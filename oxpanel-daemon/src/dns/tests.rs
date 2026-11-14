//! DNS hosting against the fake OS: zones following sites, records,
//! protection, ownership, validation by the server's checkers with rollback,
//! serials, DNSSEC, suspension, deletion and reconciliation.
#![allow(clippy::many_single_char_names)]

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use super::rr::{RawRr, RrType};
use super::*;
use crate::config::Config;
use crate::records::DnsChoice;
use crate::system::FakeSystem;
use crate::tenant::TenantService;
use crate::validate::Limits;
use crate::vhost::{VHostRequest, VHostService};

const LIST: &str = "com\nnet\norg\nuk\nco.uk\ntest\n";

struct H {
    _dir: tempfile::TempDir,
    sys: Arc<FakeSystem>,
    ctx: Ctx,
    dns: DnsService,
    vhosts: VHostService,
    tenants: TenantService,
}

fn dns_config(cfg: &mut Config) {
    cfg.dns.enabled = true;
    cfg.dns.nameservers = vec![
        Domain::parse("ns1.example.net").unwrap(),
        Domain::parse("ns2.example.net").unwrap(),
    ];
    cfg.dns.soa_contact = "hostmaster@example.net".into();
    cfg.dns.ipv4 = Some("203.0.113.10".parse().unwrap());
    cfg.dns.secondaries = vec!["127.0.0.1:853".parse().unwrap()];
}

async fn harness_with(configure: impl FnOnce(&mut Config)) -> H {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    crate::config::sandbox_feature_paths(&mut cfg, dir.path());
    cfg.state_dir = dir.path().join("state");
    cfg.home_base = dir.path().join("home");
    cfg.systemd_unit_dir = dir.path().join("systemd");
    cfg.nginx_log_dir = dir.path().join("log");
    cfg.php_conf_dir = dir.path().join("php");
    cfg.nginx_conf_dir = dir.path().join("nginx").join("oxpanel.d");
    cfg.nginx_include_file = dir
        .path()
        .join("nginx")
        .join("conf.d")
        .join("00-oxpanel.conf");
    for d in [
        &cfg.home_base,
        &cfg.systemd_unit_dir,
        &dir.path().join("nginx").join("conf.d"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(&cfg.dns.suffix_list, LIST).unwrap();
    dns_config(&mut cfg);
    configure(&mut cfg);
    let sys = Arc::new(FakeSystem::new());
    sys.dns_follow(&cfg.dns.data_dir.join("zones"));
    let ctx = Ctx::new(cfg, sys.clone(), false);
    ctx.store.init().unwrap();
    let tenants = TenantService::new(ctx.clone());
    for t in ["alice", "bob"] {
        tenants.create(t, Limits::default(), "").await.unwrap();
    }
    sys.clear_calls();
    H {
        _dir: dir,
        sys,
        dns: DnsService::new(ctx.clone()),
        vhosts: VHostService::new(ctx.clone()),
        tenants,
        ctx,
    }
}

async fn harness() -> H {
    harness_with(|_| {}).await
}

impl H {
    async fn site(&self, domain: &str, tenant: &str, aliases: &[&str]) {
        self.site_with(domain, tenant, aliases, DnsChoice::On).await;
    }

    async fn site_with(&self, domain: &str, tenant: &str, aliases: &[&str], dns: DnsChoice) {
        self.vhosts
            .configure(VHostRequest {
                domain: domain.into(),
                tenant: tenant.into(),
                aliases: aliases.iter().map(|a| (*a).to_owned()).collect(),
                dns,
                ..VHostRequest::default()
            })
            .await
            .unwrap();
    }

    fn zone_file(&self, zone: &str) -> Option<String> {
        std::fs::read_to_string(
            self.ctx
                .config
                .dns
                .data_dir
                .join("zones")
                .join(format!("{zone}.zone")),
        )
        .ok()
    }

    fn conf(&self, name: &str) -> String {
        std::fs::read_to_string(self.ctx.config.dns.conf_dir.join(name)).unwrap_or_default()
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

    fn rndc_calls(&self) -> Vec<Vec<String>> {
        self.argvs(bin::SYSTEMD_RUN)
            .into_iter()
            .filter(|a| a.iter().any(|x| x == bin::RNDC))
            .map(|a| a.into_iter().skip_while(|x| x != "-c").skip(2).collect())
            .collect()
    }

    async fn add(&self, tenant: &str, zone: &str, raw: RawRr) -> Result<(RecordView, bool, u32)> {
        self.dns.add_record(tenant, zone, &raw).await
    }
}

fn rec(name: &str, t: RrType, value: &str) -> RawRr {
    RawRr {
        name: name.into(),
        rtype: Some(t),
        value: value.into(),
        ..RawRr::default()
    }
}

#[tokio::test]
async fn a_site_gets_a_zone_for_its_registrable_domain() {
    let h = harness().await;
    h.site("shop.example.co.uk", "alice", &["www.shop.example.co.uk"])
        .await;
    let zones = h.dns.list_zones("").await.unwrap();
    assert_eq!(zones.len(), 1);
    let z = &zones[0].record;
    assert_eq!(
        (z.zone.as_str(), z.tenant.as_str(), z.automatic),
        ("example.co.uk", "alice", true)
    );
    assert_eq!(z.state, ZoneState::Ready);
    let serial = z.serial;
    assert_eq!(
        h.zone_file("example.co.uk").unwrap(),
        format!(
            "; Managed by oxpanel-daemon. Manual edits will be overwritten.
example.co.uk. 3600 IN SOA ns1.example.net. hostmaster.example.net. {serial} 7200 3600 1209600 3600
example.co.uk. 3600 IN NS ns1.example.net.
example.co.uk. 3600 IN NS ns2.example.net.
shop.example.co.uk. 3600 IN A 203.0.113.10
www.shop.example.co.uk. 3600 IN A 203.0.113.10
"
        )
    );
    // Validated with the server's own checker, on a staging copy.
    let checks = h.argvs(bin::NAMED_CHECKZONE);
    assert!(
        checks.iter().any(|a| a[..11]
            == [
                "-k",
                "fail",
                "-m",
                "fail",
                "-M",
                "fail",
                "-S",
                "fail",
                "-i",
                "local",
                "example.co.uk"
            ]
            && a[11].ends_with("/staging/example.co.uk.zone")),
        "{checks:?}"
    );
    assert!(!h.argvs(bin::NAMED_CHECKCONF).is_empty());
    // The server configuration lists it, the catalog too.
    assert!(h.conf("zones.conf").contains("zone \"example.co.uk\" {"));
    let catalog = h.zone_file(zone::CATALOG_ZONE).unwrap();
    assert!(catalog.contains("IN PTR example.co.uk.\n"), "{catalog}");
    // The fake server loaded it at the recorded serial.
    assert_eq!(h.sys.dns_served("example.co.uk"), Some(serial));
    // Key files: generated, root-only (group: the server's).
    for k in ["rndc.key", "transfer.key"] {
        let p = h.ctx.config.dns.conf_dir.join(k);
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o640,
            "{k}"
        );
        assert!(bind::key_file_is_valid(
            &std::fs::read_to_string(&p).unwrap(),
            if k == "rndc.key" {
                bind::RNDC_KEY
            } else {
                bind::TRANSFER_KEY
            }
        ));
    }
    // The site reports its zone.
    let site = h
        .ctx
        .store
        .load_vhost(&Domain::parse("shop.example.co.uk").unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(zone_of_site(&h.ctx, &site), "example.co.uk");
}

#[tokio::test]
async fn zones_follow_alias_changes_and_go_with_their_last_site() {
    let h = harness().await;
    h.site("example.com", "alice", &[]).await;
    let first = h
        .dns
        .get_zone("alice", "example.com")
        .await
        .unwrap()
        .record
        .serial;
    h.sys.clear_calls();
    h.site("example.com", "alice", &["www.example.com", "example.org"])
        .await;
    let text = h.zone_file("example.com").unwrap();
    assert!(
        text.contains("www.example.com. 3600 IN A 203.0.113.10\n"),
        "{text}"
    );
    let z = h.dns.get_zone("alice", "example.com").await.unwrap();
    assert!(zone::serial_gt(z.record.serial, first));
    // The alias in another registrable domain got its own zone.
    assert!(h.dns.get_zone("alice", "example.org").await.is_ok());
    // Only the changed zone was reloaded (the new one was loaded by reconfig,
    // the catalog reloaded so that secondaries learn about it).
    assert_eq!(
        h.rndc_calls(),
        vec![
            vec!["reload".to_owned(), zone::CATALOG_ZONE.to_owned()],
            vec!["reload".to_owned(), "example.com".to_owned()]
        ]
    );
    assert!(h
        .argvs(bin::SYSTEMCTL)
        .iter()
        .any(|a| a == &["reload", bind::SERVICE]));
    // Dropping the alias drops its records.
    h.site("example.com", "alice", &[]).await;
    assert!(!h
        .zone_file("example.com")
        .unwrap()
        .contains("www.example.com"));
    // ... and the zone that only that alias used.
    assert!(h.dns.get_zone("alice", "example.org").await.is_err());
    assert!(h.zone_file("example.org").is_none());
    // Removing the last site removes an automatic zone the tenant added nothing to.
    h.vhosts.remove("example.com").await.unwrap();
    assert!(h.dns.list_zones("").await.unwrap().is_empty());
    assert!(!h.conf("zones.conf").contains("example.com"));
}

#[tokio::test]
async fn a_zone_with_tenant_records_outlives_its_sites() {
    let h = harness().await;
    h.site("example.com", "alice", &[]).await;
    let mut mx = rec("@", RrType::Mx, "mx1.mail.example.net");
    mx.priority = 10;
    h.add("alice", "example.com", mx).await.unwrap();
    h.vhosts.remove("example.com").await.unwrap();
    let z = h.dns.get_zone("alice", "example.com").await.unwrap();
    assert!(z.sites.is_empty());
    let text = h.zone_file("example.com").unwrap();
    assert!(text.contains("example.com. 3600 IN MX 10 mx1.mail.example.net.\n"));
    assert!(!text.contains(" IN A "), "{text}");
    // Explicit deletion removes it.
    assert!(h.dns.delete_zone("alice", "example.com").await.unwrap());
    assert!(h.zone_file("example.com").is_none());
    assert!(
        !h.dns.delete_zone("alice", "example.com").await.unwrap(),
        "idempotent"
    );
}

#[tokio::test]
async fn opted_out_sites_and_a_disabled_host_get_nothing() {
    let h = harness().await;
    h.site_with("example.com", "alice", &[], DnsChoice::Off)
        .await;
    assert!(h.dns.list_zones("").await.unwrap().is_empty());
    let h = harness_with(|c| c.dns.enabled = false).await;
    h.site("example.com", "alice", &[]).await;
    assert!(h.dns.list_zones("").await.unwrap().is_empty());
    assert!(matches!(
        h.dns.create_zone("alice", "example.com").await,
        Err(Error::DnsUnavailable(_))
    ));
    assert!(h.sys.calls_to(bin::NAMED_CHECKZONE).is_empty());
}

#[tokio::test]
async fn a_missing_dns_server_is_refused_before_anything_is_created() {
    let h = harness().await;
    h.sys.set_missing(bin::NAMED);
    let e = h.dns.create_zone("alice", "example.com").await.unwrap_err();
    assert!(
        matches!(&e, Error::DnsUnavailable(m) if m.contains("dnf install bind")),
        "{e}"
    );
    assert!(ZoneStore::new(&h.ctx.config).list().unwrap().is_empty());
    assert!(!h.ctx.config.dns.conf_dir.exists());
    // Sites are still created; they get no zone.
    h.site("example.com", "alice", &[]).await;
    assert!(ZoneStore::new(&h.ctx.config).list().unwrap().is_empty());
}

#[tokio::test]
async fn tenants_cannot_reach_into_each_others_zones() {
    let h = harness().await;
    h.site("example.com", "alice", &["www.example.com"]).await;
    // Bob cannot create the zone, an overlapping one, or a public suffix.
    for (zone, why) in [
        ("example.com", "already exists"),
        ("shop.example.com", "another tenant"),
        ("co.uk", "public suffix"),
    ] {
        let e = h.dns.create_zone("bob", zone).await.unwrap_err();
        assert!(
            matches!(&e, Error::DnsConflict(m) if m.contains(why)),
            "{zone}: {e}"
        );
    }
    assert!(matches!(
        h.dns.create_zone("bob", "com").await,
        Err(Error::InvalidInput { .. })
    ));
    // Bob cannot see or touch Alice's zone: NOT_FOUND.
    assert!(matches!(
        h.dns.get_zone("bob", "example.com").await,
        Err(Error::DnsZoneNotFound(_))
    ));
    assert!(matches!(
        h.add("bob", "example.com", rec("x", RrType::A, "192.0.2.1"))
            .await,
        Err(Error::DnsZoneNotFound(_))
    ));
    assert!(!h.dns.delete_zone("bob", "example.com").await.unwrap());
    assert!(h.dns.get_zone("alice", "example.com").await.is_ok());
    // Bob's site inside Alice's zone: served, but no records from the engine.
    h.site("blog.example.com", "bob", &[]).await;
    assert!(!h.zone_file("example.com").unwrap().contains("blog"));
    assert_eq!(h.dns.list_zones("bob").await.unwrap().len(), 0);
    // Alice cannot create a zone holding a site of Bob's.
    h.site("bob.test", "bob", &[]).await;
    h.dns.delete_zone("bob", "bob.test").await.unwrap();
    let e = h.dns.create_zone("alice", "bob.test").await.unwrap_err();
    assert!(
        matches!(&e, Error::DnsConflict(m) if m.contains("another tenant")),
        "{e}"
    );
    // Nor a zone nested in her own.
    let e = h
        .dns
        .create_zone("alice", "sub.example.com")
        .await
        .unwrap_err();
    assert!(
        matches!(&e, Error::DnsConflict(m) if m.contains("add records to that zone")),
        "{e}"
    );
}

#[tokio::test]
async fn engine_records_are_protected_and_the_dns_rules_hold() {
    let h = harness().await;
    h.site("example.com", "alice", &["www.example.com"]).await;
    let refused = [
        rec("www", RrType::A, "192.0.2.1"),
        rec("www", RrType::Cname, "elsewhere.example.net"),
        rec("@", RrType::Cname, "elsewhere.example.net"),
        rec("@", RrType::Ns, "ns.elsewhere.example"),
        rec("www", RrType::Ns, "ns.elsewhere.example"),
    ];
    for r in refused {
        assert!(
            h.add("alice", "example.com", r.clone()).await.is_err(),
            "{r:?}"
        );
    }
    // CNAME exclusivity.
    h.add(
        "alice",
        "example.com",
        rec("shop", RrType::Cname, "shops.example.net"),
    )
    .await
    .unwrap();
    assert!(h
        .add("alice", "example.com", rec("shop", RrType::Txt, "x"))
        .await
        .is_err());
    // MX must not point at a CNAME in the zone.
    let mut mx = rec("@", RrType::Mx, "shop.example.com");
    mx.priority = 10;
    let e = h.add("alice", "example.com", mx).await.unwrap_err();
    assert!(e.to_string().contains("CNAME"), "{e}");
    // A delegation takes only NS at its name and glue below it.
    h.add(
        "alice",
        "example.com",
        rec("dev", RrType::Ns, "ns1.dev.example.com"),
    )
    .await
    .unwrap();
    h.add(
        "alice",
        "example.com",
        rec("ns1.dev", RrType::A, "192.0.2.53"),
    )
    .await
    .unwrap();
    assert!(h
        .add("alice", "example.com", rec("dev", RrType::Txt, "x"))
        .await
        .is_err());
    assert!(h
        .add("alice", "example.com", rec("x.dev", RrType::Txt, "x"))
        .await
        .is_err());
    // RRsets share a TTL.
    let mut a = rec("api", RrType::A, "192.0.2.1");
    a.ttl = 300;
    h.add("alice", "example.com", a).await.unwrap();
    let mut b = rec("api", RrType::A, "192.0.2.2");
    b.ttl = 600;
    assert!(h.add("alice", "example.com", b).await.is_err());
    // The protected records are visible but marked.
    let z = h.dns.get_zone("alice", "example.com").await.unwrap();
    let protected: Vec<String> = z
        .records
        .iter()
        .filter(|r| r.protected)
        .map(|r| format!("{} {}", r.rr.name.as_str(), r.rr.data.rtype().as_str()))
        .collect();
    assert_eq!(protected, ["@ NS", "@ NS", "@ A", "www A"]);
    assert!(z.records.iter().filter(|r| r.protected).all(|r| r.id == 0));
}

#[tokio::test]
async fn records_for_an_external_mail_provider() {
    let h = harness().await;
    h.site("example.com", "alice", &["www.example.com"]).await;
    let z = "example.com";
    for (pref, host) in [(10, "mx1.mail.example.net"), (20, "mx2.mail.example.net")] {
        let mut mx = rec("@", RrType::Mx, host);
        mx.priority = pref;
        h.add("alice", z, mx).await.unwrap();
    }
    let mut sub_mx = rec("lists", RrType::Mx, "mx.lists.example.net");
    sub_mx.priority = 5;
    h.add("alice", z, sub_mx).await.unwrap();
    h.add(
        "alice",
        z,
        rec(
            "@",
            RrType::Txt,
            "v=spf1 include:_spf.mail.example.net ~all",
        ),
    )
    .await
    .unwrap();
    let dkim = format!("v=DKIM1; k=rsa; p={}", "M".repeat(392));
    h.add("alice", z, rec("s1._domainkey", RrType::Txt, &dkim))
        .await
        .unwrap();
    h.add(
        "alice",
        z,
        rec(
            "s2._domainkey",
            RrType::Cname,
            "s2.domainkey.u1.mail.example.net",
        ),
    )
    .await
    .unwrap();
    h.add(
        "alice",
        z,
        rec(
            "_dmarc",
            RrType::Txt,
            "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
        ),
    )
    .await
    .unwrap();
    let mut srv = rec(
        "_autodiscover._tcp",
        RrType::Srv,
        "autodiscover.mail.example.net",
    );
    srv.port = 443;
    srv.weight = 1;
    h.add("alice", z, srv).await.unwrap();
    h.add(
        "alice",
        z,
        rec("autoconfig", RrType::Cname, "autoconfig.mail.example.net"),
    )
    .await
    .unwrap();
    let text = h.zone_file(z).unwrap();
    for line in [
        "example.com. 3600 IN MX 10 mx1.mail.example.net.\n",
        "example.com. 3600 IN MX 20 mx2.mail.example.net.\n",
        "lists.example.com. 3600 IN MX 5 mx.lists.example.net.\n",
        "example.com. 3600 IN TXT \"v=spf1 include:_spf.mail.example.net ~all\"\n",
        "s2._domainkey.example.com. 3600 IN CNAME s2.domainkey.u1.mail.example.net.\n",
        "_dmarc.example.com. 3600 IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com\"\n",
        "_autodiscover._tcp.example.com. 3600 IN SRV 0 1 443 autodiscover.mail.example.net.\n",
    ] {
        assert!(text.contains(line), "missing {line}{text}");
    }
    let dkim_line = text
        .lines()
        .find(|l| l.starts_with("s1._domainkey"))
        .unwrap();
    assert_eq!(
        dkim_line.matches('"').count(),
        4,
        "split into two quoted strings: {dkim_line}"
    );
    // A null MX is alone.
    let mut null = rec("nomail", RrType::Mx, ".");
    h.add("alice", z, null.clone()).await.unwrap();
    null.value = "mx.example.net".into();
    null.priority = 10;
    assert!(h.add("alice", z, null).await.is_err());
}

#[tokio::test]
async fn serials_increase_and_identical_requests_change_nothing() {
    let h = harness().await;
    h.site("example.com", "alice", &[]).await;
    let s0 = h
        .dns
        .get_zone("alice", "example.com")
        .await
        .unwrap()
        .record
        .serial;
    let r = rec("@", RrType::Txt, "hello");
    let (v, changed, s1) = h.add("alice", "example.com", r.clone()).await.unwrap();
    assert!(changed && zone::serial_gt(s1, s0));
    h.sys.clear_calls();
    let (v2, changed, s2) = h.add("alice", "example.com", r).await.unwrap();
    assert!(!changed);
    assert_eq!((v2.id, s2), (v.id, s1));
    assert!(h.rndc_calls().is_empty(), "nothing reloaded for a repeat");
    // A restart (a new engine on the same state) keeps the serial; a change
    // after it still increases it.
    let dns = DnsService::new(h.ctx.clone());
    converge(&h.ctx).await;
    assert_eq!(
        dns.get_zone("alice", "example.com")
            .await
            .unwrap()
            .record
            .serial,
        s1
    );
    let (_, _, s3) = dns
        .add_record("alice", "example.com", &rec("@", RrType::Txt, "again"))
        .await
        .unwrap();
    assert!(zone::serial_gt(s3, s1));
    assert_eq!(h.sys.dns_served("example.com"), Some(s3));
    // Update and remove.
    let (_, changed, s4) = dns
        .update_record(
            "alice",
            "example.com",
            v.id,
            &rec("@", RrType::Txt, "changed"),
        )
        .await
        .unwrap();
    assert!(changed && zone::serial_gt(s4, s3));
    assert!(h.zone_file("example.com").unwrap().contains("\"changed\""));
    assert!(matches!(
        dns.update_record("alice", "example.com", 999, &rec("@", RrType::Txt, "x"))
            .await,
        Err(Error::DnsRecordNotFound { .. })
    ));
    let (removed, s5) = dns
        .remove_record("alice", "example.com", v.id)
        .await
        .unwrap();
    assert!(removed && zone::serial_gt(s5, s4));
    assert!(
        !dns.remove_record("alice", "example.com", v.id)
            .await
            .unwrap()
            .0
    );
    let reset = dns.reset_zone("alice", "example.com").await.unwrap();
    assert!(reset.record.records.is_empty());
}

#[tokio::test]
async fn a_rejected_zone_is_never_activated() {
    let h = harness().await;
    h.site("example.com", "alice", &[]).await;
    let before = h.zone_file("example.com").unwrap();
    let rec_before = h.dns.get_zone("alice", "example.com").await.unwrap().record;
    h.sys.clear_calls();
    h.sys
        .script_failure(bin::NAMED_CHECKZONE, 1, "zone example.com/IN: bad things");
    let e = h
        .add("alice", "example.com", rec("x", RrType::Txt, "y"))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, Error::DnsZoneRejected(m) if m.contains("bad things")),
        "{e}"
    );
    assert_eq!(
        h.zone_file("example.com").unwrap(),
        before,
        "live file untouched"
    );
    assert_eq!(
        h.dns.get_zone("alice", "example.com").await.unwrap().record,
        rec_before,
        "record restored"
    );
    assert!(h.rndc_calls().is_empty(), "nothing reloaded");
    assert!(
        std::fs::read_dir(h.ctx.config.dns.data_dir.join("staging"))
            .unwrap()
            .next()
            .is_none(),
        "no staging leftovers"
    );
    // A rejected server configuration is restored too.
    let conf = h.conf("zones.conf");
    h.sys
        .script_failure(bin::NAMED_CHECKCONF, 1, "zones.conf:3: unknown option");
    let e = h.dns.create_zone("alice", "other.test").await.unwrap_err();
    assert!(e.to_string().contains("unknown option"), "{e}");
    assert_eq!(h.conf("zones.conf"), conf);
}

#[tokio::test]
async fn suspension_freezes_zones_that_keep_answering() {
    let h = harness().await;
    h.site("example.com", "alice", &[]).await;
    h.tenants.set_suspended("alice", true).await.unwrap();
    assert!(h.zone_file("example.com").is_some());
    assert!(h.sys.dns_served("example.com").is_some());
    let e = h
        .add("alice", "example.com", rec("x", RrType::Txt, "y"))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, Error::DnsConflict(m) if m.contains("suspended")),
        "{e}"
    );
    h.tenants.set_suspended("alice", false).await.unwrap();
    h.add("alice", "example.com", rec("x", RrType::Txt, "y"))
        .await
        .unwrap();
}

#[tokio::test]
async fn deleting_a_tenant_is_refused_while_it_has_zones() {
    let h = harness().await;
    h.dns.create_zone("alice", "example.com").await.unwrap();
    let e = h.tenants.delete("alice", true).await.unwrap_err();
    assert!(matches!(e, Error::TenantHasDnsZones(_)), "{e}");
    {
        let _g = h.ctx.lock.lock().await;
        assert_eq!(
            remove_tenant_zones(&h.ctx, &Username::parse("alice").unwrap())
                .await
                .unwrap(),
            1
        );
    }
    h.tenants.delete("alice", true).await.unwrap();
}

#[tokio::test]
async fn dnssec_on_and_safely_off() {
    let h = harness().await;
    h.site("example.com", "alice", &[]).await;
    let s0 = h
        .dns
        .get_zone("alice", "example.com")
        .await
        .unwrap()
        .record
        .serial;
    let z = h
        .dns
        .set_dnssec("alice", "example.com", true, false)
        .await
        .unwrap();
    assert_eq!(z.dnssec.state, DnssecState::Signing);
    assert!(
        zone::serial_gt(z.record.serial, s0),
        "a new serial for the signed zone"
    );
    let zones_conf = h.conf("zones.conf");
    assert!(
        zones_conf.contains("dnssec-policy \"oxpanel\";\n    inline-signing yes;"),
        "{zones_conf}"
    );
    let key_dir = h.ctx.config.dns.data_dir.join("keys").join("example.com");
    assert!(key_dir.is_dir());
    std::fs::write(
        key_dir.join("Kexample.com.+013+29363.key"),
        "example.com. 3600 IN DNSKEY 257 3 13 ojVvxeNn+jDXp4IEn3MFAEGpvWkGafaqWDICjTZhmoowSmtPAMaGnZ6u W6lcZgTCJKOfldsnn+s5IL50zkfVeA==\n",
    )
    .unwrap();
    let z = h.dns.get_zone("alice", "example.com").await.unwrap();
    assert_eq!(z.dnssec.state, DnssecState::Signed);
    assert_eq!(z.dnssec.ds, ["example.com. IN DS 29363 13 2 79D38907566B83D16997F1187109BCD309C3DCC69E31F1286F7718C945E578CA"]);
    // Off while the parent publishes the DS: refused.
    h.sys.set_dns_resolver("example.com", "DS", "ok NOERROR 0 ds=29363/13/2/79D38907566B83D16997F1187109BCD309C3DCC69E31F1286F7718C945E578CA");
    let e = h
        .dns
        .set_dnssec("alice", "example.com", false, true)
        .await
        .unwrap_err();
    assert!(
        matches!(&e, Error::DnsConflict(m) if m.contains("still publishes a DS")),
        "{e}"
    );
    let check = h.dns.check_zone("alice", "example.com").await.unwrap();
    assert!(check.ds_checked && check.ds_matches);
    // Parent unknown: refused unless forced.
    h.sys
        .set_dns_resolver("example.com", "DS", "fail no answer");
    let e = h
        .dns
        .set_dnssec("alice", "example.com", false, false)
        .await
        .unwrap_err();
    assert!(
        matches!(&e, Error::DnsConflict(m) if m.contains("repeat with force")),
        "{e}"
    );
    // No DS at the parent: off, with a serial above the signed one served.
    h.sys.set_dns_resolver("example.com", "DS", "ok NOERROR 0");
    let served = h.sys.dns_served("example.com").unwrap();
    let z = h
        .dns
        .set_dnssec("alice", "example.com", false, false)
        .await
        .unwrap();
    assert_eq!(z.dnssec.state, DnssecState::Off);
    assert!(zone::serial_gt(z.record.serial, served));
    assert!(!h.conf("zones.conf").contains("dnssec-policy"));
    assert!(!key_dir.exists(), "keys removed");
}

#[tokio::test]
async fn the_check_reports_delegation_in_plain_words() {
    let h = harness().await;
    h.dns.create_zone("alice", "example.com").await.unwrap();
    h.sys.set_dns_resolver(
        "example.com",
        "NS",
        "ok NOERROR 0 ns=ns1.example.net ns=ns2.example.net",
    );
    let c = h.dns.check_zone("alice", "example.com").await.unwrap();
    assert_eq!(c.delegation, Delegation::Delegated);
    assert_eq!(c.serials[0].status, "ok");
    assert_eq!(c.serials[1].server, "127.0.0.1:853");
    h.sys.set_dns_resolver(
        "example.com",
        "NS",
        "ok NOERROR 0 ns=ns1.other.example ns=ns2.other.example",
    );
    let c = h.dns.check_zone("alice", "example.com").await.unwrap();
    assert_eq!(c.delegation, Delegation::Elsewhere);
    assert!(
        c.guidance
            .contains("set the domain's name servers to ns1.example.net, ns2.example.net"),
        "{}",
        c.guidance
    );
    h.sys.set_dns_resolver("example.com", "NS", "ok NXDOMAIN 0");
    assert_eq!(
        h.dns
            .check_zone("alice", "example.com")
            .await
            .unwrap()
            .delegation,
        Delegation::NotFound
    );
    h.sys
        .set_dns_resolver("example.com", "NS", "fail no resolver");
    assert_eq!(
        h.dns
            .check_zone("alice", "example.com")
            .await
            .unwrap()
            .delegation,
        Delegation::Unknown
    );
    // The probe runs unprivileged, outside the daemon, with exact properties.
    let run = h
        .argvs(bin::SYSTEMD_RUN)
        .into_iter()
        .find(|a| a.iter().any(|x| x == probe::SUBCOMMAND))
        .unwrap();
    for p in [
        "--property=DynamicUser=yes",
        "--property=CapabilityBoundingSet=",
        "--property=NoNewPrivileges=yes",
        "--property=ProtectSystem=strict",
    ] {
        assert!(run.iter().any(|x| x == p), "{p}: {run:?}");
    }
    assert!(
        run.windows(5)
            .any(|w| w == ["--q", "resolver", "example.com", "NS", "1"]),
        "{run:?}"
    );
}

#[tokio::test]
async fn reconcile_sees_files_server_and_secondaries() {
    let h = harness().await;
    h.site("example.com", "alice", &[]).await;
    let _g = h.ctx.lock.lock().await;
    assert_eq!(drifts(&h.ctx).await.unwrap(), vec![]);
    let zones = h.ctx.config.dns.data_dir.join("zones");
    std::fs::write(zones.join("example.com.zone"), "edited\n").unwrap();
    std::fs::write(zones.join("stray.zone"), "x").unwrap();
    h.sys.set_dns_secondaries_lag(true);
    let kinds: Vec<DriftKind> = drifts(&h.ctx)
        .await
        .unwrap()
        .into_iter()
        .map(|d| d.kind)
        .collect();
    assert!(kinds.contains(&DriftKind::DnsZoneDrift));
    assert!(kinds.contains(&DriftKind::OrphanDnsFile));
    assert!(kinds.contains(&DriftKind::DnsSecondaryDrift));
    h.sys.set_dns_down(true);
    let kinds: Vec<DriftKind> = drifts(&h.ctx)
        .await
        .unwrap()
        .into_iter()
        .map(|d| d.kind)
        .collect();
    assert!(kinds.contains(&DriftKind::DnsServerDrift));
}

#[tokio::test]
async fn host_facts_flag_a_single_server() {
    let h = harness_with(|c| c.dns.secondaries.clear()).await;
    let f = facts(&h.ctx).await.unwrap();
    assert!(f.enabled && f.available);
    assert!(f.server_version.starts_with("BIND 9.16"));
    assert!(
        f.warnings.iter().any(|w| w.contains("no redundancy")),
        "{:?}",
        f.warnings
    );
}

/// Found by phase 80: a tenant could create the zone
/// `catalog.oxpanel.invalid`, the engine's own catalog. The server's
/// configuration then held two zone statements of that name, the checker
/// rejected it, and every later DNS change of every tenant (and every
/// cascading deletion, which removes zones) failed. Special-use domains
/// (`localhost`, reverse zones, `.invalid` …) are refused the same way.
#[tokio::test]
async fn the_catalog_and_special_use_domains_cannot_become_zones() {
    let h = harness().await;
    for zone in [
        "catalog.oxpanel.invalid",
        "oxpanel.invalid",
        "x.catalog.oxpanel.invalid",
        "example.invalid",
        "my.localhost",
        "0.0.127.in-addr.arpa",
        "2.0.192.in-addr.arpa",
        "8.b.d.0.1.0.0.2.ip6.arpa",
        "printer.local",
        "hidden.onion",
        "x.alt",
    ] {
        let e = h.dns.create_zone("alice", zone).await.unwrap_err();
        assert!(
            matches!(&e, Error::DnsConflict(m) if m.contains("special-use") || m.contains("catalog")),
            "{zone}: {e}"
        );
    }
    assert!(h.dns.list_zones("alice").await.unwrap().is_empty());
    // A site with such a name gets no zone either (and the site itself works).
    h.site("catalog.oxpanel.invalid", "alice", &["www.localhost"])
        .await;
    assert!(h.dns.list_zones("").await.unwrap().is_empty());
    // An ordinary zone still works.
    h.dns.create_zone("alice", "example.com").await.unwrap();
}

/// Found by phase 80: a zone whose creation the server's configuration
/// checker rejected kept its record and its file. Every later configuration
/// then held it, and was rejected too: no tenant could change DNS any more,
/// and cascading deletions failed. The creation is now refused whole.
#[tokio::test]
async fn a_zone_the_configuration_checker_rejects_leaves_nothing() {
    let h = harness().await;
    h.dns.create_zone("alice", "example.com").await.unwrap();
    h.sys.script_failure(
        bin::NAMED_CHECKCONF,
        1,
        "zones.conf:9: zone 'x': already exists",
    );
    let e = h.dns.create_zone("bob", "example.net").await.unwrap_err();
    assert!(matches!(&e, Error::DnsZoneRejected(_)), "{e}");
    assert!(
        h.zone_file("example.net").is_none(),
        "zone file left behind"
    );
    let zones: Vec<String> = h
        .dns
        .list_zones("")
        .await
        .unwrap()
        .into_iter()
        .map(|z| z.record.zone)
        .collect();
    assert_eq!(zones, ["example.com"], "record left behind");
    // The next change of anyone works again.
    h.dns.create_zone("bob", "example.net").await.unwrap();
    h.add("alice", "example.com", rec("x", RrType::Txt, "y"))
        .await
        .unwrap();
}

/// Found by acceptance phase 60: right after the server was started (its
/// unit is active before named's control channel listens), the first
/// `rndc reload` was refused and the record change failed with an internal
/// error. A refused command is now tried again for a few seconds.
#[tokio::test]
async fn a_reload_refused_while_the_server_starts_is_tried_again() {
    let h = harness().await;
    h.site("example.com", "alice", &[]).await;
    h.sys.clear_calls();
    // The next systemd-run (the rndc reload) is refused once.
    h.sys.script_failure(
        bin::SYSTEMD_RUN,
        1,
        "rndc: connect failed: connection refused",
    );
    h.add("alice", "example.com", rec("x", RrType::Txt, "y"))
        .await
        .unwrap();
    assert_eq!(h.rndc_calls().len(), 2, "{:?}", h.rndc_calls());
}
