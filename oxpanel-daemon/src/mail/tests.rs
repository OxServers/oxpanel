//! Email workflows against the fake OS: the exact commands they run, the
//! files they render, every refusal of the contract, suspension, deletion,
//! the DNS records, reconciliation and the dry run.
#![allow(clippy::too_many_lines)]

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use super::store::{MailMode, MailStore};
use super::*;
use crate::config::Config;
use crate::dns::rr::{RawRr, RrType};
use crate::error::MailCode;
use crate::host::{DriftKind, HostService};
use crate::system::{bin, FakeSystem};
use crate::tenant::TenantService;
use crate::validate::Limits as TenantLimits;
use crate::vhost::{VHostRequest, VHostService};

const PW: &str = "Correct-Horse-9";
const PW2: &str = "Another-Secret-77";

struct H {
    dir: tempfile::TempDir,
    sys: Arc<FakeSystem>,
    ctx: Ctx,
    mail: MailService,
    tenants: TenantService,
    vhosts: VHostService,
}

fn mail_config(cfg: &mut Config, dir: &std::path::Path) {
    cfg.state_dir = dir.join("state");
    cfg.home_base = dir.join("home");
    cfg.systemd_unit_dir = dir.join("systemd");
    cfg.nginx_log_dir = dir.join("log");
    cfg.php_conf_dir = dir.join("php");
    cfg.nginx_conf_dir = dir.join("nginx").join("oxpanel.d");
    cfg.nginx_include_file = dir.join("nginx").join("conf.d").join("00-oxpanel.conf");
    cfg.mail.enabled = true;
    cfg.mail.hostname = Some(Domain::parse("mail.host.test").unwrap());
    cfg.mail.password_cost = 4;
}

async fn harness_with(configure: impl FnOnce(&mut Config)) -> H {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    crate::config::sandbox_feature_paths(&mut cfg, dir.path());
    mail_config(&mut cfg, dir.path());
    for d in [
        &cfg.home_base,
        &cfg.systemd_unit_dir,
        &dir.path().join("nginx").join("conf.d"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    configure(&mut cfg);
    let sys = Arc::new(FakeSystem::new());
    if cfg.dns.enabled {
        sys.dns_follow(&cfg.dns.data_dir.join("zones"));
    }
    let ctx = Ctx::new(cfg, sys.clone(), false);
    ctx.store.init().unwrap();
    let tenants = TenantService::new(ctx.clone());
    let vhosts = VHostService::new(ctx.clone());
    for (t, site) in [("alice", "example.test"), ("bob", "bob.test")] {
        tenants
            .create(t, TenantLimits::default(), "")
            .await
            .unwrap();
        vhosts
            .configure(VHostRequest {
                domain: site.into(),
                tenant: t.into(),
                aliases: vec![format!("www.{site}")],
                ..VHostRequest::default()
            })
            .await
            .unwrap();
    }
    sys.clear_calls();
    H {
        dir,
        sys,
        mail: MailService::new(ctx.clone()),
        tenants,
        vhosts,
        ctx,
    }
}

async fn harness() -> H {
    harness_with(|_| {}).await
}

fn with_dns(cfg: &mut Config) {
    cfg.dns.enabled = true;
    cfg.dns.nameservers = vec![
        Domain::parse("ns1.example.net").unwrap(),
        Domain::parse("ns2.example.net").unwrap(),
    ];
    cfg.dns.soa_contact = "hostmaster@example.net".into();
    cfg.dns.ipv4 = Some("203.0.113.10".parse().unwrap());
    std::fs::write(&cfg.dns.suffix_list, "com\nnet\norg\ntest\n").unwrap();
}

fn code(e: &Error) -> Option<MailCode> {
    match e {
        Error::Mail { code, .. } => Some(*code),
        _ => None,
    }
}

impl H {
    fn cfg(&self) -> &MailConfig {
        &self.ctx.config.mail
    }

    fn argvs(&self, program: &'static str) -> Vec<Vec<String>> {
        self.sys
            .calls_to(program)
            .iter()
            .map(|c| {
                c.args
                    .iter()
                    .map(|a: &OsString| a.to_string_lossy().into_owned())
                    .collect()
            })
            .collect()
    }

    #[allow(clippy::unused_self)]
    fn read(&self, p: PathBuf) -> String {
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    fn map(&self, name: &str) -> String {
        self.read(self.cfg().postfix_dir.join("oxpanel").join(name))
    }

    fn dovecot(&self, name: &str) -> String {
        self.read(self.cfg().dovecot_dir.join("oxpanel").join(name))
    }

    fn home(&self, t: &str) -> PathBuf {
        self.ctx.config.home_base.join(t)
    }

    async fn domain(&self) {
        self.mail
            .set_domain("alice", "example.test", MailMode::Local, &[], "")
            .await
            .unwrap();
    }

    async fn mailbox(&self, local: &str) {
        self.mail
            .put_mailbox("alice", "example.test", local, 0, PW, true)
            .await
            .unwrap();
    }

    fn record(&self, d: &str) -> super::store::MailDomainRecord {
        MailStore::new(&self.ctx.config)
            .load(&Domain::parse(d).unwrap())
            .unwrap()
            .unwrap()
    }

    /// Every file under the sandbox, as text (for "never on disk" checks).
    fn all_text(&self) -> String {
        fn walk(p: &std::path::Path, out: &mut String) {
            let Ok(rd) = std::fs::read_dir(p) else { return };
            for e in rd.flatten() {
                let path = e.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if let Ok(t) = std::fs::read(&path) {
                    out.push_str(&String::from_utf8_lossy(&t));
                }
            }
        }
        let mut s = String::new();
        walk(self.dir.path(), &mut s);
        s
    }
}

// ---- domains, keys, certificates: exact commands ------------------------------------

#[tokio::test]
async fn setting_up_a_domain_runs_exactly_these_commands() {
    let h = harness().await;
    // The accounts' creation already rendered the servers' files (the
    // policy service's map lists every account) and made the self-signed
    // certificate: make it again to see the command.
    let ss = h.cfg().selfsigned_dir.clone();
    assert!(ss.join("selfsigned.crt").is_file() && ss.join("selfsigned.key").is_file());
    std::fs::remove_file(ss.join("selfsigned.crt")).unwrap();
    ops::ensure_selfsigned(&h.ctx, &Domain::parse("mail.host.test").unwrap())
        .await
        .unwrap();
    assert_eq!(
        h.argvs(bin::OPENSSL),
        vec![vec![
            "req".to_owned(),
            "-x509".into(),
            "-newkey".into(),
            "rsa:2048".into(),
            "-nodes".into(),
            "-days".into(),
            "3650".into(),
            "-keyout".into(),
            ss.join("selfsigned.key").display().to_string(),
            "-out".into(),
            ss.join("selfsigned.crt").display().to_string(),
            "-subj".into(),
            "/CN=mail.host.test".into(),
        ]]
    );
    h.sys.clear_calls();
    let (v, created) = h
        .mail
        .set_domain("alice", "example.test", MailMode::Local, &[], "")
        .await
        .unwrap();
    assert!(created);
    assert_eq!(v.mode, MailMode::Local);
    let rec = h.record("example.test");
    let key = rec.dkim.clone().unwrap();
    let key_path = render::dkim_key_path(h.cfg(), "example.test", &key.selector);
    assert_eq!(
        h.argvs(bin::OPENSSL),
        vec![
            vec![
                "genpkey".to_owned(),
                "-algorithm".into(),
                "RSA".into(),
                "-pkeyopt".into(),
                "rsa_keygen_bits:2048".into(),
            ],
            vec![
                "pkey".into(),
                "-in".into(),
                key_path.display().to_string(),
                "-pubout".into(),
            ],
        ]
    );
    assert!(key_path.is_file());
    assert_eq!(
        std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
        0o640,
        "the key is readable by root and the signer's group only"
    );
    assert!(v.dkim.unwrap().record.starts_with("v=DKIM1; k=rsa; p="));
    // Exactly the servers whose files changed: Postfix (the domain's maps)
    // and Rspamd (the selector map). Dovecot has no mailbox yet, the
    // policy map lists the account already.
    let units: Vec<String> = h
        .argvs(bin::SYSTEMCTL)
        .into_iter()
        .filter(|a| a.len() == 3 && a[0] == "reload-or-restart" && a[1] == "--")
        .map(|a| a[2].clone())
        .collect();
    assert_eq!(units, [ops::POSTFIX_SERVICE, ops::RSPAMD_SERVICE]);
    // Setting the same again changes nothing and reloads nothing.
    h.sys.clear_calls();
    let (_, created) = h
        .mail
        .set_domain("alice", "example.test", MailMode::Local, &[], "")
        .await
        .unwrap();
    assert!(!created);
    assert!(h.argvs(bin::OPENSSL).is_empty(), "no new key");
    assert!(
        !h.argvs(bin::SYSTEMCTL)
            .iter()
            .any(|a| a[0] == "reload-or-restart"),
        "{:?}",
        h.argvs(bin::SYSTEMCTL)
    );
}

#[tokio::test]
async fn a_mailbox_is_made_as_the_account_and_only_its_files_change() {
    let h = harness().await;
    h.domain().await;
    h.sys.clear_calls();
    let (m, created) = h
        .mail
        .put_mailbox("alice", "example.test", "info", 10 << 20, PW, true)
        .await
        .unwrap();
    assert!(created);
    assert_eq!(m.address, "info@example.test");
    let alice = h
        .ctx
        .store
        .load_tenant(&Username::parse("alice").unwrap())
        .unwrap()
        .unwrap();
    let mkdirs = h.sys.calls_to(bin::MKDIR);
    assert_eq!(mkdirs.len(), 1);
    let dir = h.home("alice").join("mail/example.test/info");
    assert_eq!(
        mkdirs[0]
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        ["-p", "-m", "0700", "--", &dir.display().to_string()]
    );
    let run_as = mkdirs[0].run_as.unwrap();
    assert_eq!((run_as.uid, run_as.gid), (alice.uid, alice.gid));
    // Only the files that changed are announced: maps (Postfix), the
    // password files (Dovecot reloaded: it forgets cached logins), the policy map.
    let units: Vec<String> = h
        .argvs(bin::SYSTEMCTL)
        .into_iter()
        .filter(|a| a[0] == "reload-or-restart")
        .map(|a| a[2].clone())
        .collect();
    assert_eq!(
        units,
        [
            ops::POSTFIX_SERVICE,
            ops::DOVECOT_SERVICE,
            ops::POLICY_SERVICE
        ]
    );
    assert!(h.argvs(bin::DOVEADM).into_iter().all(|a| a[0] == "-f"));
    // The quota is read with doveadm.
    assert!(h.argvs(bin::DOVEADM).contains(&vec![
        "-f".to_owned(),
        "tab".into(),
        "quota".into(),
        "get".into(),
        "-u".into(),
        "info@example.test".into()
    ]));
}

#[tokio::test]
async fn the_password_is_only_ever_a_hash_in_the_password_file() {
    let h = harness().await;
    h.domain().await;
    h.mailbox("info").await;
    let passwd = h.dovecot("passwd");
    assert!(
        passwd.starts_with("info@example.test:{BLF-CRYPT}$2y$04$"),
        "{passwd}"
    );
    let line = passwd.lines().next().unwrap();
    assert!(password::verify(PW, line.split_once(':').unwrap().1));
    assert!(!h.all_text().contains(PW), "the password is on disk");
    for c in h.sys.calls() {
        assert!(
            !c.display().contains(PW),
            "the password in argv: {}",
            c.display()
        );
        assert!(c
            .stdin
            .as_ref()
            .is_none_or(|s| !String::from_utf8_lossy(s).contains(PW)));
    }
    // A new password replaces the hash and ends the sessions.
    h.sys.clear_calls();
    h.mail
        .set_mailbox_password("alice", "example.test", "info", PW2)
        .await
        .unwrap();
    let line = h.dovecot("passwd");
    assert!(password::verify(
        PW2,
        line.trim().split_once(':').unwrap().1
    ));
    assert!(h
        .argvs(bin::DOVEADM)
        .contains(&vec!["kick".to_owned(), "info@example.test".into()]));
    assert!(!h.all_text().contains(PW2));
}

#[tokio::test]
async fn maps_and_password_files_are_rendered_from_the_records() {
    let h = harness().await;
    h.domain().await;
    h.mailbox("info").await;
    h.mailbox("sales").await;
    h.mail
        .put_mailbox("alice", "example.test", "off", 20 << 20, PW, false)
        .await
        .unwrap();
    h.mail
        .put_forwarder(
            "alice",
            "example.test",
            "team",
            &["a@x.org".into(), "B@Y.org".into()],
            false,
        )
        .await
        .unwrap();
    h.mail
        .put_forwarder(
            "alice",
            "example.test",
            "sales",
            &["boss@x.org".into()],
            true,
        )
        .await
        .unwrap();
    h.mail
        .set_domain("alice", "example.test", MailMode::Local, &[], "info")
        .await
        .unwrap();
    assert_eq!(
        h.map("domains"),
        format!("{}example.test OK\n", render::HEADER)
    );
    assert_eq!(
        h.map("mailboxes"),
        format!(
            "{}info@example.test example.test/info/\noff@example.test example.test/off/\nsales@example.test example.test/sales/\n",
            render::HEADER
        )
    );
    assert_eq!(
        h.map("aliases"),
        format!(
            "{}info@example.test info@example.test\noff@example.test off@example.test\nsales@example.test boss@x.org,sales@example.test\nteam@example.test a@x.org,b@y.org\n@example.test info@example.test\n",
            render::HEADER
        )
    );
    assert_eq!(
        h.map("senders"),
        format!(
            "{}info@example.test info@example.test\nsales@example.test sales@example.test\n",
            render::HEADER
        )
    );
    assert_eq!(h.map("recipient_access"), render::HEADER);
    assert_eq!(h.dovecot("deny"), "off@example.test\n");
    let alice = h
        .ctx
        .store
        .load_tenant(&Username::parse("alice").unwrap())
        .unwrap()
        .unwrap();
    let users = h.dovecot("users");
    let home = h.home("alice");
    assert!(
        users.contains(&format!(
            "off@example.test::{}:{}::{}/mail/example.test/off::userdb_quota_rule=*:storage=20971520B\n",
            alice.uid,
            alice.gid,
            home.display()
        )),
        "{users}"
    );
    assert!(
        users.contains("info@example.test::") && users.contains("userdb_quota_rule=*:storage=0\n")
    );
    // Policy map: mailboxes and the account.
    let policy: render::PolicyMap =
        serde_json::from_str(&h.read(h.cfg().state_dir.join("policy.json"))).unwrap();
    assert!(!policy.mailboxes["off@example.test"].enabled);
    assert_eq!(policy.accounts["alice"].uid, alice.uid);
    assert!(policy.accounts["alice"]
        .sender_domains
        .contains(&"www.example.test".to_owned()));
}

#[tokio::test]
async fn suspension_denies_logins_and_defers_mail_and_resuming_undoes_it() {
    let h = harness().await;
    h.domain().await;
    h.mailbox("info").await;
    h.sys.clear_calls();
    h.tenants.set_suspended("alice", true).await.unwrap();
    assert_eq!(h.dovecot("deny"), "info@example.test\n");
    assert_eq!(
        h.map("recipient_access"),
        format!(
            "{}example.test 450 4.2.1 mailbox temporarily unavailable\n",
            render::HEADER
        )
    );
    assert_eq!(
        h.map("senders"),
        render::HEADER,
        "a suspended mailbox may send as nobody"
    );
    assert!(h
        .argvs(bin::DOVEADM)
        .contains(&vec!["kick".to_owned(), "*@example.test".into()]));
    let policy: render::PolicyMap =
        serde_json::from_str(&h.read(h.cfg().state_dir.join("policy.json"))).unwrap();
    assert!(policy.accounts["alice"].suspended);
    // Changes are refused while suspended.
    let e = h
        .mail
        .put_mailbox("alice", "example.test", "new", 0, PW, true)
        .await
        .unwrap_err();
    assert_eq!(code(&e), Some(MailCode::AccountSuspended), "{e}");
    h.tenants.set_suspended("alice", false).await.unwrap();
    assert_eq!(h.dovecot("deny"), "");
    assert_eq!(h.map("recipient_access"), render::HEADER);
    assert!(h.map("senders").contains("info@example.test"));
}

// ---- refusals of the contract ----------------------------------------------------------

#[tokio::test]
async fn a_domain_must_be_a_name_the_account_holds() {
    let h = harness().await;
    let mut cases = vec![
        ("alice", "bob.test", "another account's site"),
        ("alice", "www.bob.test", "another account's site alias"),
        ("alice", "mail.host.test", "the mail host name"),
        ("alice", "unrelated.test", "a name alice does not hold"),
    ];
    // Another account's mail domain.
    h.mail
        .set_domain("bob", "bob.test", MailMode::Local, &[], "")
        .await
        .unwrap();
    cases.push(("alice", "bob.test", "another account's mail domain"));
    for (t, d, why) in cases {
        let e = h
            .mail
            .set_domain(t, d, MailMode::Local, &[], "")
            .await
            .unwrap_err();
        assert_eq!(code(&e), Some(MailCode::DomainNotOwned), "{why}: {e}");
        assert!(e.to_string().starts_with("mail_domain_not_owned: "), "{e}");
    }
    // Its own alias is fine.
    h.mail
        .set_domain("alice", "www.example.test", MailMode::Local, &[], "")
        .await
        .unwrap();
    // Requests that are invalid before anything is looked at.
    for (mode, mx, catch) in [
        (MailMode::External, vec![], ""),
        (MailMode::Local, vec!["mx.x.org".to_owned()], ""),
        (MailMode::Off, vec![], "info"),
        (MailMode::External, vec!["not a host".to_owned()], ""),
    ] {
        let e = h
            .mail
            .set_domain("alice", "example.test", mode, &mx, catch)
            .await
            .unwrap_err();
        assert!(matches!(e, Error::InvalidInput { .. }), "{e}");
    }
    assert!(MailStore::new(&h.ctx.config)
        .load(&Domain::parse("example.test").unwrap())
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn mailbox_refusals_carry_their_codes() {
    let h = harness().await;
    h.domain().await;
    // weak_password
    for weak in [
        "short",
        "1234567890",
        "aaaaaaaaaaaaaa",
        "password123",
        "info-is-great-1",
        "example-123456",
    ] {
        let e = h
            .mail
            .put_mailbox("alice", "example.test", "info", 0, weak, true)
            .await
            .unwrap_err();
        assert_eq!(code(&e), Some(MailCode::WeakPassword), "{weak}: {e}");
    }
    // A new mailbox needs a password.
    let e = h
        .mail
        .put_mailbox("alice", "example.test", "info", 0, "", true)
        .await
        .unwrap_err();
    assert!(
        matches!(
            e,
            Error::InvalidInput {
                field: "password",
                ..
            }
        ),
        "{e}"
    );
    // mailbox_limit_reached, mailbox_quota_above_limit
    h.mail
        .set_limits(
            "alice",
            Limits {
                max_mailboxes: 1,
                max_mailbox_bytes: 50 << 20,
                rate_account: 10,
                rate_mailbox: 5,
            },
        )
        .await
        .unwrap();
    for (q, why) in [(60 << 20, "above")] {
        let e = h
            .mail
            .put_mailbox("alice", "example.test", "info", q, PW, true)
            .await
            .unwrap_err();
        assert_eq!(
            code(&e),
            Some(MailCode::MailboxQuotaAboveLimit),
            "{why}: {e}"
        );
    }
    let e = h
        .mail
        .put_mailbox("alice", "example.test", "info", 1000, PW, true)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::InvalidInput { .. }), "below 1 MiB: {e}");
    h.mail
        .put_mailbox("alice", "example.test", "info", 10 << 20, PW, true)
        .await
        .unwrap();
    let e = h
        .mail
        .put_mailbox("alice", "example.test", "two", 10 << 20, PW, true)
        .await
        .unwrap_err();
    assert_eq!(code(&e), Some(MailCode::MailboxLimitReached), "{e}");
    // Updating the one there is still possible.
    let (_, created) = h
        .mail
        .put_mailbox("alice", "example.test", "info", 20 << 20, "", false)
        .await
        .unwrap();
    assert!(!created);
    // Another account's domain is not found.
    let e = h
        .mail
        .put_mailbox("bob", "example.test", "x", 0, PW, true)
        .await
        .unwrap_err();
    assert_eq!(code(&e), Some(MailCode::DomainNotFound), "{e}");
    // A domain whose mail is elsewhere takes no mailbox.
    h.mail
        .set_domain(
            "alice",
            "example.test",
            MailMode::External,
            &["mx.provider.net".into()],
            "",
        )
        .await
        .unwrap();
    let e = h
        .mail
        .put_mailbox("alice", "example.test", "info", 20 << 20, "", true)
        .await
        .unwrap_err();
    assert_eq!(code(&e), Some(MailCode::DomainNotLocal), "{e}");
}

#[tokio::test]
async fn mailboxes_and_forwarders_do_not_share_an_address_by_accident() {
    let h = harness().await;
    h.domain().await;
    h.mailbox("info").await;
    let e = h
        .mail
        .put_forwarder("alice", "example.test", "info", &["x@y.org".into()], false)
        .await
        .unwrap_err();
    assert_eq!(code(&e), Some(MailCode::AddressInUse), "{e}");
    h.mail
        .put_forwarder("alice", "example.test", "team", &["x@y.org".into()], false)
        .await
        .unwrap();
    let e = h
        .mail
        .put_mailbox("alice", "example.test", "team", 0, PW, true)
        .await
        .unwrap_err();
    assert_eq!(code(&e), Some(MailCode::AddressInUse), "{e}");
    let e = h
        .mail
        .put_forwarder("alice", "example.test", "nobox", &["x@y.org".into()], true)
        .await
        .unwrap_err();
    assert!(
        matches!(
            e,
            Error::InvalidInput {
                field: "keep_copy",
                ..
            }
        ),
        "{e}"
    );
    // A mailbox with a copy forwarded is fine.
    h.mail
        .put_forwarder("alice", "example.test", "info", &["x@y.org".into()], true)
        .await
        .unwrap();
}

#[tokio::test]
async fn forward_loops_and_too_many_destinations_are_refused() {
    let h = harness().await;
    h.domain().await;
    h.mail
        .set_domain("bob", "bob.test", MailMode::Local, &[], "")
        .await
        .unwrap();
    let e = h
        .mail
        .put_forwarder(
            "alice",
            "example.test",
            "a",
            &["a@example.test".into()],
            false,
        )
        .await
        .unwrap_err();
    assert_eq!(code(&e), Some(MailCode::ForwardLoop), "itself: {e}");
    h.mail
        .put_forwarder("alice", "example.test", "a", &["b@bob.test".into()], false)
        .await
        .unwrap();
    h.mail
        .put_forwarder("bob", "bob.test", "b", &["c@example.test".into()], false)
        .await
        .unwrap();
    let e = h
        .mail
        .put_forwarder(
            "alice",
            "example.test",
            "c",
            &["a@example.test".into()],
            false,
        )
        .await
        .unwrap_err();
    assert_eq!(code(&e), Some(MailCode::ForwardLoop), "through two: {e}");
    let many: Vec<String> = (0..=MAX_FORWARD).map(|i| format!("r{i}@x.org")).collect();
    let e = h
        .mail
        .put_forwarder("alice", "example.test", "d", &many, false)
        .await
        .unwrap_err();
    assert_eq!(code(&e), Some(MailCode::TooManyDestinations), "{e}");
    for bad in [
        "no-at-sign",
        "a@b@c",
        "x y@z.org",
        "a@-bad-.org",
        "\"q\"@x.org",
        "a@x.org\nRCPT TO:<b@c.org>",
    ] {
        let e = h
            .mail
            .put_forwarder("alice", "example.test", "e", &[bad.to_owned()], false)
            .await
            .unwrap_err();
        assert!(matches!(e, Error::InvalidInput { .. }), "{bad:?}: {e}");
    }
}

const MAX_FORWARD: usize = crate::validate::MAX_FORWARD_DESTINATIONS;

#[tokio::test]
async fn a_catch_all_must_be_a_mailbox_of_the_domain() {
    let h = harness().await;
    h.domain().await;
    for (c, why) in [
        ("nobody", "no such mailbox"),
        ("x@bob.test", "another domain"),
    ] {
        let e = h
            .mail
            .set_domain("alice", "example.test", MailMode::Local, &[], c)
            .await
            .unwrap_err();
        assert!(
            matches!(
                e,
                Error::InvalidInput {
                    field: "catch_all",
                    ..
                }
            ),
            "{why}: {e}"
        );
    }
    h.mailbox("info").await;
    let (v, _) = h
        .mail
        .set_domain(
            "alice",
            "example.test",
            MailMode::Local,
            &[],
            "info@example.test",
        )
        .await
        .unwrap();
    assert_eq!(v.catch_all, "info@example.test");
    // Deleting that mailbox drops the catch-all.
    h.mail
        .delete_mailbox("alice", "example.test", "info")
        .await
        .unwrap();
    assert!(h.record("example.test").catch_all.is_none());
    assert!(!h.map("aliases").contains("@example.test "));
}

#[tokio::test]
async fn switching_the_mode_keeps_mailboxes_but_serves_them_only_locally() {
    let h = harness().await;
    h.domain().await;
    h.mailbox("info").await;
    let (v, _) = h
        .mail
        .set_domain(
            "alice",
            "example.test",
            MailMode::External,
            &["aspmx.l.google.com".into()],
            "",
        )
        .await
        .unwrap();
    assert!(v.dkim.is_none());
    assert_eq!(v.required_records.len(), 1);
    assert_eq!(v.required_records[0].rtype, "MX");
    assert!(!h.map("domains").contains("example.test"));
    assert!(!h.dovecot("passwd").contains("info@"));
    assert_eq!(
        h.record("example.test").mailboxes.len(),
        1,
        "kept in the record"
    );
    h.mail
        .set_domain("alice", "example.test", MailMode::Off, &[], "")
        .await
        .unwrap();
    assert!(h
        .mail
        .get_domain("alice", "example.test")
        .await
        .unwrap()
        .required_records
        .is_empty());
    h.mail
        .set_domain("alice", "example.test", MailMode::Local, &[], "")
        .await
        .unwrap();
    assert!(h.dovecot("passwd").contains("info@example.test:"));
}

// ---- deletion, autoresponders, DKIM rotation -------------------------------------------

#[tokio::test]
async fn deleting_a_mailbox_removes_its_mail_as_the_account() {
    let h = harness().await;
    h.domain().await;
    h.mailbox("info").await;
    let alice = h
        .ctx
        .store
        .load_tenant(&Username::parse("alice").unwrap())
        .unwrap()
        .unwrap();
    h.sys.clear_calls();
    assert!(h
        .mail
        .delete_mailbox("alice", "example.test", "info")
        .await
        .unwrap());
    // The servers forget it at once.
    assert!(!h.dovecot("passwd").contains("info@"));
    assert!(h
        .argvs(bin::DOVEADM)
        .contains(&vec!["kick".to_owned(), "info@example.test".into()]));
    // The removal runs in the background.
    for _ in 0..100 {
        if h.record("example.test").mailboxes.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(h.record("example.test").mailboxes.is_empty());
    let rm = h.sys.calls_to(bin::RM);
    assert_eq!(rm.len(), 1);
    assert_eq!(
        rm[0]
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        [
            "-rf",
            "--one-file-system",
            "--",
            &h.home("alice")
                .join("mail/example.test/info")
                .display()
                .to_string()
        ]
    );
    let run_as = rm[0].run_as.unwrap();
    assert_eq!((run_as.uid, run_as.gid), (alice.uid, alice.gid));
    assert!(!h
        .mail
        .delete_mailbox("alice", "example.test", "info")
        .await
        .unwrap());
}

#[tokio::test]
async fn autoresponders_are_sieve_scripts_the_account_cannot_change() {
    let h = harness().await;
    h.domain().await;
    h.mailbox("info").await;
    let v = h
        .mail
        .set_autoresponder(
            "alice",
            "info@example.test",
            true,
            "Away \"now\"",
            "Back on Monday.\r\nThanks \\ bye",
            Some(1_800_000_000),
            Some(1_800_086_400),
        )
        .await
        .unwrap();
    assert!(v.enabled);
    let path = render::sieve_path(h.cfg(), "example.test", "info");
    let script = h.read(path.clone());
    assert!(script.contains("vacation :days 1 :addresses [\"info@example.test\"] :subject \"Away \\\"now\\\"\" \"Back on Monday.\nThanks \\\\ bye\";"), "{script}");
    assert!(
        script.contains(
            "currentdate :zone \"+0000\" :value \"ge\" \"iso8601\" \"2027-01-15T08:00:00Z\""
        ),
        "{script}"
    );
    assert!(
        script.contains("exists \"list-id\""),
        "no replies to lists: {script}"
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(
        h.argvs(bin::SIEVEC).last().unwrap(),
        &vec![path.display().to_string()]
    );
    // Header injection through the subject is impossible.
    let e = h
        .mail
        .set_autoresponder(
            "alice",
            "info@example.test",
            true,
            "x\r\nBcc: a@b.org",
            "body",
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            e,
            Error::InvalidInput {
                field: "subject",
                ..
            }
        ),
        "{e}"
    );
    let e = h
        .mail
        .set_autoresponder(
            "alice",
            "info@example.test",
            true,
            "s",
            "b",
            Some(10),
            Some(5),
        )
        .await
        .unwrap_err();
    assert!(matches!(e, Error::InvalidInput { .. }), "{e}");
    let e = h
        .mail
        .set_autoresponder(
            "alice",
            "info@example.test",
            true,
            "s",
            "b",
            None,
            Some(u64::MAX),
        )
        .await
        .unwrap_err();
    assert!(matches!(e, Error::InvalidInput { .. }), "{e}");
    // Off: the script goes; the text is kept.
    let v = h
        .mail
        .set_autoresponder("alice", "info@example.test", false, "", "", None, None)
        .await
        .unwrap();
    assert!(!v.enabled && v.subject.starts_with("Away"));
    assert!(!path.exists());
    assert_eq!(
        h.mail
            .get_autoresponder("alice", "info@example.test")
            .await
            .unwrap()
            .subject,
        v.subject
    );
    let e = h
        .mail
        .get_autoresponder("alice", "nobody@example.test")
        .await
        .unwrap_err();
    assert_eq!(code(&e), Some(MailCode::MailboxNotFound));
}

fn hex(s: &str) -> String {
    crate::dns::wire::hex_upper(s.as_bytes())
}

#[tokio::test]
async fn rotating_the_dkim_key_with_dns_elsewhere_waits_until_the_new_record_is_seen() {
    let h = harness().await;
    h.domain().await;
    let map = h.cfg().state_dir.join("dkim/selectors.map");
    let old = h.record("example.test").dkim.unwrap();
    // Step 1: a new key to publish; the old one keeps signing.
    let v = h
        .mail
        .rotate_dkim("alice", "example.test", false)
        .await
        .unwrap();
    let rec = h.record("example.test");
    let pending = rec.dkim_pending.clone().unwrap();
    assert_ne!(pending.selector, old.selector);
    assert_eq!(rec.dkim.as_ref().unwrap().selector, old.selector);
    assert!(rec.dkim_retired.is_empty());
    let d = v.dkim.unwrap();
    assert_eq!(d.selector, old.selector);
    let p = d.pending.unwrap();
    assert_eq!(p.selector, pending.selector);
    assert_eq!(p.published, Published::Unknown);
    let names: Vec<String> = v.required_records.iter().map(|r| r.name.clone()).collect();
    assert!(names.contains(&format!("{}._domainkey", old.selector)));
    assert!(names.contains(&format!("{}._domainkey", pending.selector)));
    assert!(render::dkim_key_path(h.cfg(), "example.test", &pending.selector).is_file());
    assert_eq!(
        h.read(map.clone()),
        format!("{}example.test {}\n", render::HEADER, old.selector)
    );
    // Step 2 before the record is published: nothing changes, it says so,
    // and no second key is made.
    let name = format!("{}._domainkey.example.test", pending.selector);
    h.sys.set_dns_resolver(&name, "TXT", "ok NOERROR 0");
    let v = h
        .mail
        .rotate_dkim("alice", "example.test", false)
        .await
        .unwrap();
    let p = v.dkim.unwrap().pending.unwrap();
    assert_eq!(
        (p.selector.as_str(), p.published),
        (pending.selector.as_str(), Published::No)
    );
    assert_eq!(
        h.record("example.test").dkim.unwrap().selector,
        old.selector
    );
    // A record with another key does not count either.
    h.sys.set_dns_resolver(
        &name,
        "TXT",
        &format!("ok NOERROR 0 txt={}", hex("v=DKIM1; k=rsa; p=AAAA")),
    );
    h.mail
        .rotate_dkim("alice", "example.test", false)
        .await
        .unwrap();
    assert_eq!(
        h.record("example.test").dkim.unwrap().selector,
        old.selector
    );
    // Once public DNS has it (spaces as some providers show them), it signs.
    let txt = records::dkim_txt(&pending.public_key).replace("; ", ";  ");
    h.sys
        .set_dns_resolver(&name, "TXT", &format!("ok NOERROR 0 txt={}", hex(&txt)));
    let v = h
        .mail
        .rotate_dkim("alice", "example.test", false)
        .await
        .unwrap();
    let rec = h.record("example.test");
    assert_eq!(rec.dkim.as_ref().unwrap().selector, pending.selector);
    assert!(rec.dkim_pending.is_none());
    assert_eq!(rec.dkim_retired.len(), 1);
    assert!(rec.dkim_retired[0].retire_at_unix.unwrap() > now_unix() + 6 * 86_400);
    let d = v.dkim.unwrap();
    assert_eq!(
        (d.selector.as_str(), d.pending),
        (pending.selector.as_str(), None)
    );
    assert_eq!(
        h.read(map.clone()),
        format!("{}example.test {}\n", render::HEADER, pending.selector)
    );
    for k in [&old, &pending] {
        assert!(render::dkim_key_path(h.cfg(), "example.test", &k.selector).is_file());
    }
}

#[tokio::test]
async fn a_forced_rotation_signs_with_the_new_key_at_once() {
    let h = harness().await;
    h.domain().await;
    let old = h.record("example.test").dkim.unwrap();
    // Forced from the start, and forced while a key is pending.
    h.mail
        .rotate_dkim("alice", "example.test", true)
        .await
        .unwrap();
    let first = h.record("example.test").dkim.unwrap();
    assert_ne!(first.selector, old.selector);
    h.mail
        .rotate_dkim("alice", "example.test", false)
        .await
        .unwrap();
    let pending = h.record("example.test").dkim_pending.unwrap();
    let v = h
        .mail
        .rotate_dkim("alice", "example.test", true)
        .await
        .unwrap();
    let rec = h.record("example.test");
    assert_eq!(rec.dkim.unwrap().selector, pending.selector);
    assert!(rec.dkim_pending.is_none() && v.dkim.unwrap().pending.is_none());
    assert_eq!(rec.dkim_retired.len(), 2);
}

#[tokio::test]
async fn with_the_zone_hosted_here_a_rotation_publishes_then_switches() {
    let h = harness_with(with_dns).await;
    h.domain().await;
    let old = h.record("example.test").dkim.unwrap();
    let v = h
        .mail
        .rotate_dkim("alice", "example.test", false)
        .await
        .unwrap();
    let rec = h.record("example.test");
    let new = rec.dkim.unwrap();
    assert_ne!(new.selector, old.selector);
    assert!(rec.dkim_pending.is_none());
    let d = v.dkim.unwrap();
    assert_eq!(
        (d.selector.as_str(), d.published, d.pending),
        (new.selector.as_str(), Published::Yes, None)
    );
    // Both keys are in the zone: the new one signs, the old one for a week.
    let dns = crate::dns::DnsService::new(h.ctx.clone());
    let zone = dns.get_zone("alice", "example.test").await.unwrap();
    for k in [&old, &new] {
        let name = format!("{}._domainkey", k.selector);
        assert!(
            zone.records
                .iter()
                .any(|r| r.origin == "mail" && r.rr.name.as_str() == name),
            "{name}"
        );
    }
}

#[tokio::test]
async fn the_mail_host_warns_about_its_reverse_name_and_a_blocked_port_25() {
    let h = harness().await;
    let host = h.cfg().hostname.clone().unwrap();
    let target = h.cfg().port25_check.clone().unwrap();
    // Nothing known yet (GetMailHost would start a check in the background).
    assert_eq!(hostcheck::cached(&h.ctx, &host), None);
    // The host's address has another reverse name; port 25 is blocked.
    h.sys
        .set_dns_resolver(host.as_str(), "A", "ok NOERROR 0 a=192.0.2.10");
    h.sys.set_dns_resolver(
        "10.2.0.192.in-addr.arpa",
        "PTR",
        "ok NOERROR 0 ptr=vps-123.provider.example",
    );
    h.sys
        .set_dns_resolver(target.as_str(), "A", "ok NOERROR 0 a=198.51.100.25");
    let c = hostcheck::refresh(&h.ctx, &host).await.unwrap();
    assert!(
        c.reverse_dns
            .as_deref()
            .unwrap()
            .contains("vps-123.provider.example"),
        "{c:?}"
    );
    assert!(c.port25.as_deref().unwrap().contains("port 25"), "{c:?}");
    let v = h.mail.host().await.unwrap();
    let kinds: Vec<WarningKind> = v.warnings.iter().map(|(k, _)| *k).collect();
    assert!(
        kinds.contains(&WarningKind::ReverseDns) && kinds.contains(&WarningKind::Port25),
        "{kinds:?}"
    );
    // The probe connected to the target's port 25, as an SMTP question.
    let probe = h.argvs(bin::SYSTEMD_RUN);
    assert!(
        probe.iter().any(|a| a
            .windows(3)
            .any(|w| w == ["--q", "198.51.100.25:25", target.as_str()])),
        "{probe:?}"
    );
    // Fixed: the right reverse name and a greeting from the target.
    h.sys.set_dns_resolver(
        "10.2.0.192.in-addr.arpa",
        "PTR",
        &format!("ok NOERROR 0 ptr={host}"),
    );
    h.sys.set_dns_resolver(
        "198.51.100.25:25",
        "SMTP",
        &format!("ok NOERROR 0 txt={}", hex("220 mx.google.com ESMTP")),
    );
    let c = hostcheck::refresh(&h.ctx, &host).await.unwrap();
    assert_eq!((c.reverse_dns, c.port25), (None, None));
    let v = h.mail.host().await.unwrap();
    assert!(!v
        .warnings
        .iter()
        .any(|(k, _)| matches!(k, WarningKind::ReverseDns | WarningKind::Port25)));
}

#[test]
fn last_logins_are_read_from_dovecots_dict_file() {
    let m = mailboxes::parse_last_logins(
        "shared/last-login/info@example.test\n1794700000\nshared/last-login/Sales@Example.test\n1794700100\nshared/other\nx\nshared/last-login/bad@example.test\nnot-a-number\n",
    );
    assert_eq!(m.get("info@example.test"), Some(&1_794_700_000));
    assert_eq!(m.get("sales@example.test"), Some(&1_794_700_100));
    assert_eq!(m.len(), 2);
    assert!(mailboxes::parse_last_logins("shared/last-login/x@y.test\n").is_empty());
}

#[tokio::test]
async fn mailboxes_list_their_last_login_when_dovecot_recorded_one() {
    let h = harness().await;
    h.domain().await;
    h.mailbox("info").await;
    h.mailbox("sales").await;
    let f = render::last_login_file(h.cfg());
    std::fs::create_dir_all(f.parent().unwrap()).unwrap();
    std::fs::write(&f, "shared/last-login/info@example.test\n1794700000\n").unwrap();
    let l = h
        .mail
        .list_mailboxes("alice", "example.test")
        .await
        .unwrap();
    let got: Vec<(&str, Option<u64>)> = l
        .iter()
        .map(|m| (m.local_part.as_str(), m.last_login_unix))
        .collect();
    assert_eq!(got, [("info", Some(1_794_700_000)), ("sales", None)]);
}

#[test]
fn dovecot_records_last_logins_only_with_its_group() {
    let host = Domain::parse("mail.host.net").unwrap();
    let cfg = MailConfig::default();
    let mut m = render::Model {
        hostname: host,
        accounts: std::collections::BTreeMap::new(),
        domains: Vec::new(),
        cert: PathBuf::from("/c"),
        key: PathBuf::from("/k"),
        uid_min: 1000,
        uid_max: 60000,
        last_login: false,
    };
    let off = render::dovecot_conf(&cfg, &m).unwrap();
    assert!(
        off.contains("mail_access_groups = \n")
            && !off.contains("last_login")
            && !off.contains("service dict")
    );
    m.last_login = true;
    let on = render::dovecot_conf(&cfg, &m).unwrap();
    for want in [
        "mail_access_groups = oxpanel-maildict\n",
        "mail_plugins = $mail_plugins imap_quota last_login\n",
        "protocol pop3 {\n  mail_plugins = $mail_plugins last_login\n}",
        "oxlastlogin = file:/var/lib/oxpanel-mail/lastlogin/last-login.dict",
        "    mode = 0660\n    group = oxpanel-maildict\n",
        "last_login_dict = proxy::oxlastlogin",
    ] {
        assert!(on.contains(want), "{want}\n{on}");
    }
    // Delivery (LMTP) is not a login.
    let lmtp = on
        .split("protocol lmtp")
        .nth(1)
        .unwrap()
        .split('}')
        .next()
        .unwrap();
    assert!(!lmtp.contains("last_login"), "{lmtp}");
}

// ---- the account's life ------------------------------------------------------------

#[tokio::test]
async fn an_account_with_mail_is_deleted_only_with_everything() {
    let h = harness().await;
    h.domain().await;
    h.mailbox("info").await;
    h.mail
        .set_autoresponder("alice", "info@example.test", true, "s", "b", None, None)
        .await
        .unwrap();
    h.vhosts.remove("example.test").await.unwrap();
    let e = h.tenants.delete("alice", true).await.unwrap_err();
    assert!(matches!(e, Error::TenantHasMailDomains(_)), "{e}");
    let key = render::dkim_key_path(
        h.cfg(),
        "example.test",
        &h.record("example.test").dkim.unwrap().selector,
    );
    {
        let _g = h.ctx.lock.lock().await;
        assert_eq!(
            remove_tenant_mail(&h.ctx, &Username::parse("alice").unwrap())
                .await
                .unwrap(),
            1
        );
    }
    assert!(!key.exists());
    assert!(!h.cfg().state_dir.join("sieve/example.test").exists());
    assert!(MailStore::new(&h.ctx.config).list().unwrap().is_empty());
    assert!(!h.dovecot("passwd").contains("info@"));
    h.tenants.delete("alice", true).await.unwrap();
}

#[tokio::test]
async fn suspending_an_account_without_mail_domains_reaches_the_policy_map() {
    // Its sites' mail is the policy service's to refuse (found on the VM:
    // the map kept an account without mail domains unsuspended).
    let h = harness().await;
    h.domain().await;
    let map = |h: &H| -> render::PolicyMap {
        serde_json::from_str(&h.read(h.cfg().state_dir.join("policy.json"))).unwrap()
    };
    h.tenants.set_suspended("bob", true).await.unwrap();
    assert!(map(&h).accounts["bob"].suspended);
    h.tenants.set_suspended("bob", false).await.unwrap();
    assert!(!map(&h).accounts["bob"].suspended);
}

#[tokio::test]
async fn a_mail_domain_without_mailboxes_goes_with_its_account() {
    let h = harness().await;
    h.domain().await;
    let key = render::dkim_key_path(
        h.cfg(),
        "example.test",
        &h.record("example.test").dkim.unwrap().selector,
    );
    h.vhosts.remove("example.test").await.unwrap();
    h.tenants.delete("alice", true).await.unwrap();
    assert!(MailStore::new(&h.ctx.config).list().unwrap().is_empty());
    assert!(!key.exists());
}

#[tokio::test]
async fn limits_and_usage() {
    let h = harness().await;
    h.domain().await;
    h.mailbox("info").await;
    assert_eq!(
        h.mail.get_limits("alice").await.unwrap(),
        Limits {
            max_mailboxes: 0,
            max_mailbox_bytes: 0,
            rate_account: 500,
            rate_mailbox: 200
        }
    );
    let l = Limits {
        max_mailboxes: 3,
        max_mailbox_bytes: 0,
        rate_account: 50,
        rate_mailbox: 0,
    };
    assert_eq!(h.mail.set_limits("alice", l).await.unwrap(), l);
    let policy: render::PolicyMap =
        serde_json::from_str(&h.read(h.cfg().state_dir.join("policy.json"))).unwrap();
    assert_eq!(
        (
            policy.accounts["alice"].rate_account,
            policy.accounts["alice"].rate_mailbox
        ),
        (50, 0)
    );
    // The counters the policy service writes.
    let usage = policy::Usage {
        hour: policy::current_hour(),
        accounts: [("alice".to_owned(), 7)].into(),
        mailboxes: std::collections::BTreeMap::new(),
    };
    std::fs::write(
        policy::usage_path(&h.cfg().state_dir),
        serde_json::to_vec(&usage).unwrap(),
    )
    .unwrap();
    h.sys.script_stdout(
        bin::DOVEADM,
        "Quota name\tType\tValue\tLimit\t%\nMailbox\tSTORAGE\t3\t-\t0\nMailbox\tMESSAGE\t2\t-\t0\n",
    );
    let u = h.mail.usage("alice").await.unwrap();
    assert_eq!(
        u,
        Usage {
            mailboxes: 1,
            bytes_used: 3072,
            sent_this_hour: 7
        }
    );
    assert_eq!(h.mail.usage("bob").await.unwrap().sent_this_hour, 0);
}

#[tokio::test]
async fn email_off_answers_mail_unavailable() {
    let h = harness_with(|c| c.mail.enabled = false).await;
    let e = h
        .mail
        .set_domain("alice", "example.test", MailMode::Local, &[], "")
        .await
        .unwrap_err();
    assert_eq!(code(&e), Some(MailCode::Unavailable));
    assert!(e.to_string().starts_with("mail_unavailable: "));
    assert!(!h.mail.host().await.unwrap().enabled);
    assert!(h.sys.calls().is_empty());
    let h = harness().await;
    h.sys.set_missing(bin::DOVECOT);
    let e = h.mail.list_domains("alice").await.unwrap_err();
    assert_eq!(code(&e), Some(MailCode::Unavailable));
}

#[tokio::test]
async fn the_queue_is_read_attributed_and_managed() {
    let h = harness().await;
    h.domain().await;
    // Postfix's tools run in transient units; what they print is read back
    // from the journal.
    let tools = |h: &H| -> Vec<Vec<String>> {
        h.argvs(bin::SYSTEMD_RUN)
            .into_iter()
            .filter(|a| a.iter().any(|x| x.starts_with("--unit=oxpanel-mailq-")))
            .map(|a| a.into_iter().skip_while(|x| x != "--").skip(3).collect())
            .collect()
    };
    h.sys.clear_calls();
    h.sys.script_stdout(
        bin::JOURNALCTL,
        r#"{"queue_name":"deferred","queue_id":"ABCDE12345","arrival_time":100,"message_size":10,"sender":"info@example.test","recipients":[{"address":"x@y.org","delay_reason":"timed out"}]}
{"queue_name":"deferred","queue_id":"FFFFF00000","arrival_time":200,"message_size":10,"sender":"wp@www.bob.test","recipients":[]}"#,
    );
    let (q, total) = h.mail.queue(0, 0).await.unwrap();
    assert_eq!(total, 2);
    assert_eq!(
        (q[0].queue_id.as_str(), q[0].tenant.as_str()),
        ("FFFFF00000", "bob")
    );
    assert_eq!(
        (q[1].tenant.as_str(), q[1].reason.as_str()),
        ("alice", "timed out")
    );
    assert_eq!(
        tools(&h),
        vec![vec![bin::POSTQUEUE.to_owned(), "-j".into()]]
    );
    let run = h.argvs(bin::SYSTEMD_RUN);
    assert_eq!(&run[0][..3], ["--wait", "--collect", "--quiet"]);
    let tail: Vec<&String> = run[0]
        .iter()
        .skip_while(|x| *x != "--")
        .skip(1)
        .take(2)
        .collect();
    assert_eq!(
        tail[1],
        crate::mail::queue::TOOL_SUBCOMMAND,
        "through the daemon's own binary"
    );
    assert!(
        h.argvs(bin::POSTQUEUE).is_empty(),
        "never run in the daemon's own unit"
    );
    h.sys.clear_calls();
    h.sys.script_stdout(
        bin::JOURNALCTL,
        r#"{"queue_id":"ABCDE12345","recipients":[]}"#,
    );
    assert!(h.mail.delete_queued("ABCDE12345").await.unwrap());
    assert_eq!(
        tools(&h),
        vec![
            vec![bin::POSTQUEUE.to_owned(), "-j".into()],
            vec![bin::POSTSUPER.to_owned(), "-d".into(), "ABCDE12345".into()]
        ]
    );
    let e = h.mail.delete_queued("ZZZZZ99999").await.unwrap_err();
    assert_eq!(code(&e), Some(MailCode::QueuedMailNotFound));
    for bad in ["", "ab", "../x", "-d ALL"] {
        assert!(matches!(
            h.mail.delete_queued(bad).await.unwrap_err(),
            Error::InvalidInput { .. }
        ));
    }
    h.sys.clear_calls();
    assert_eq!(h.mail.flush_queue().await.unwrap(), 0);
    assert_eq!(
        tools(&h),
        vec![
            vec![bin::POSTQUEUE.to_owned(), "-j".into()],
            vec![bin::POSTQUEUE.to_owned(), "-f".into()]
        ]
    );
}

// ---- DNS ---------------------------------------------------------------------------

#[tokio::test]
async fn mail_records_are_protected_records_of_the_hosted_zone() {
    let h = harness_with(with_dns).await;
    let (v, _) = h
        .mail
        .set_domain("alice", "example.test", MailMode::Local, &[], "")
        .await
        .unwrap();
    assert!(v.dns_hosted && v.required_records.is_empty());
    assert_eq!(v.dkim.unwrap().published, Published::Yes);
    let dns = crate::dns::DnsService::new(h.ctx.clone());
    let zone = dns.get_zone("alice", "example.test").await.unwrap();
    let mail: Vec<(String, &'static str)> = zone
        .records
        .iter()
        .filter(|r| r.origin == "mail")
        .map(|r| (r.rr.name.as_str().to_owned(), r.rr.data.rtype().as_str()))
        .collect();
    assert!(zone
        .records
        .iter()
        .filter(|r| r.origin == "mail")
        .all(|r| r.protected));
    for want in [
        ("@", "MX"),
        ("@", "TXT"),
        ("_dmarc", "TXT"),
        ("webmail", "CNAME"),
        ("_imaps._tcp", "SRV"),
    ] {
        assert!(
            mail.iter().any(|(n, t)| n == want.0 && *t == want.1),
            "{want:?} in {mail:?}"
        );
    }
    let raw = |name: &str, t: RrType, value: &str| RawRr {
        name: name.into(),
        rtype: Some(t),
        value: value.into(),
        priority: if t == RrType::Mx { 5 } else { 0 },
        ..RawRr::default()
    };
    for (r, why) in [
        (raw("@", RrType::Mx, "mx.evil.org"), "MX"),
        (raw("@", RrType::Txt, "v=spf1 +all"), "SPF"),
        (raw("_dmarc", RrType::Txt, "v=DMARC1; p=reject"), "DMARC"),
        (raw("autoconfig", RrType::A, "192.0.2.1"), "at a CNAME"),
    ] {
        let e = dns
            .add_record("alice", "example.test", &r)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("kept by the engine"), "{why}: {e}");
    }
    // A verification TXT at the apex is fine.
    dns.add_record(
        "alice",
        "example.test",
        &raw("@", RrType::Txt, "google-site-verification=x"),
    )
    .await
    .unwrap();
    // Switching to an external provider: only its MX stay engine-kept; a
    // record the tenant had where email now needs one makes way.
    h.mail
        .set_domain("alice", "example.test", MailMode::Off, &[], "")
        .await
        .unwrap();
    dns.add_record(
        "alice",
        "example.test",
        &raw("_dmarc", RrType::Txt, "v=DMARC1; p=reject"),
    )
    .await
    .unwrap();
    h.mail
        .set_domain("alice", "example.test", MailMode::Local, &[], "")
        .await
        .unwrap();
    let zone = dns.get_zone("alice", "example.test").await.unwrap();
    assert!(
        !zone
            .records
            .iter()
            .any(|r| !r.protected && r.rr.name.as_str() == "_dmarc"),
        "the tenant's DMARC made way"
    );
}

// ---- reconcile and dry run -------------------------------------------------------------

#[tokio::test]
async fn reconcile_reports_mail_drift_and_orphans() {
    let h = harness().await;
    h.domain().await;
    h.mailbox("info").await;
    let host = HostService::new(h.ctx.clone());
    let mail_drift = |d: Vec<crate::host::Drift>| -> Vec<(DriftKind, String)> {
        d.into_iter()
            .filter(|d| {
                matches!(
                    d.kind,
                    DriftKind::MailConfigDrift
                        | DriftKind::MailDomainDrift
                        | DriftKind::OrphanMailFile
                )
            })
            .map(|d| (d.kind, d.subject))
            .collect()
    };
    assert_eq!(mail_drift(host.reconcile().await.unwrap()), vec![]);
    let main_cf = h.cfg().postfix_dir.join("main.cf");
    std::fs::write(&main_cf, "edited by hand\n").unwrap();
    let orphan = h.cfg().state_dir.join("dkim/gone.test.ox1.key");
    std::fs::write(&orphan, "x").unwrap();
    std::fs::remove_dir(h.home("alice").join("mail/example.test/info")).unwrap();
    let d = mail_drift(host.reconcile().await.unwrap());
    assert!(
        d.contains(&(DriftKind::MailConfigDrift, main_cf.display().to_string())),
        "{d:?}"
    );
    assert!(
        d.contains(&(DriftKind::OrphanMailFile, orphan.display().to_string())),
        "{d:?}"
    );
    assert!(
        d.contains(&(DriftKind::MailDomainDrift, "info@example.test".to_owned())),
        "{d:?}"
    );
    // A start-up convergence heals what the records describe.
    std::fs::remove_file(&orphan).unwrap();
    converge(&h.ctx).await;
    let d = mail_drift(host.reconcile().await.unwrap());
    assert_eq!(d, vec![], "{d:?}");
}

#[tokio::test]
async fn everything_works_in_a_dry_run() {
    let h = harness_with(|c| c.dry_run = true).await;
    h.domain().await;
    h.mailbox("info").await;
    h.mail
        .put_forwarder("alice", "example.test", "team", &["x@y.org".into()], false)
        .await
        .unwrap();
    h.mail
        .set_autoresponder("alice", "info@example.test", true, "s", "b", None, None)
        .await
        .unwrap();
    h.mail
        .rotate_dkim("alice", "example.test", false)
        .await
        .unwrap();
    assert_eq!(
        h.mail
            .list_mailboxes("alice", "example.test")
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        h.mail
            .list_forwarders("alice", "example.test")
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(h.mail.list_domains("alice").await.unwrap().len(), 1);
    h.mail.set_limits("alice", Limits::default()).await.unwrap();
    h.mail.usage("alice").await.unwrap();
    h.mail.host().await.unwrap();
    h.mail.queue(0, 10).await.unwrap();
    h.mail.flush_queue().await.unwrap();
    assert!(h
        .mail
        .delete_mailbox("alice", "example.test", "info")
        .await
        .unwrap());
    assert!(h
        .mail
        .delete_forwarder("alice", "example.test", "team")
        .await
        .unwrap());
}

#[tokio::test]
async fn the_webmail_is_offered_with_roundcube_and_only_over_https_once_certified() {
    let h = harness().await;
    let rc = h.cfg().roundcube_index.clone();
    std::fs::create_dir_all(rc.parent().unwrap()).unwrap();
    std::fs::write(&rc, "<?php").unwrap();
    h.domain().await;
    let nginx = h.read(h.cfg().nginx_file.clone());
    assert!(
        nginx.contains("server_name webmail.example.test;"),
        "{nginx}"
    );
    assert!(
        !nginx.contains("listen 443"),
        "no HTTPS without a certificate: {nginx}"
    );
    assert!(nginx.contains("return 503;"));
    assert!(nginx.contains("server_name autoconfig.example.test;"));
    let rcconf = h.read(webmail::roundcube_conf_path(h.cfg()));
    assert!(rcconf.contains("$config['identities_level'] = 3;"));
    assert_eq!(
        h.mail.host().await.unwrap().webmail_url_pattern,
        "https://webmail.{domain}/"
    );
    // A certificate for the name switches it to HTTPS.
    let name = Domain::parse("webmail.example.test").unwrap();
    std::fs::create_dir_all(&h.ctx.config.tls_dir).unwrap();
    std::fs::write(
        crate::tls::cert_path(&h.ctx.config.mail.selfsigned_dir, &name),
        "c",
    )
    .unwrap();
    std::fs::write(
        crate::tls::key_path(&h.ctx.config.mail.selfsigned_dir, &name),
        "k",
    )
    .unwrap();
    {
        let _g = h.ctx.lock.lock().await;
        ops::apply(&h.ctx).await.unwrap();
    }
    let nginx = h.read(h.cfg().nginx_file.clone());
    assert!(nginx.contains("listen 443 ssl http2;"), "{nginx}");
    assert!(nginx.contains("return 301 https://$host$request_uri;"));
}
