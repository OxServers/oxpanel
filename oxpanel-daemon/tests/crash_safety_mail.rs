//! Crash safety of the email workflows, by `crash_safety.rs`' method: each
//! workflow is interrupted at every external command it runs (the command
//! fails, the daemon dies just before it, the daemon dies just after it),
//! then a new daemon boots on the same disk and the same (fake) operating
//! system — converging email as `main` does — and the request is repeated.
//! It must succeed and leave records and files consistent (`Reconcile`
//! reports nothing, no temporary file is left), and a further identical
//! request must keep it so.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::{Fault, World};
use oxpanel_daemon::backup::BackupService;
use oxpanel_daemon::host::HostService;
use oxpanel_daemon::lifecycle::LifecycleService;
use oxpanel_daemon::mail::store::{MailMode, MailStore};
use oxpanel_daemon::mail::MailService;
use oxpanel_daemon::records::{JobKind, JobState};
use oxpanel_daemon::tenant::TenantService;
use oxpanel_daemon::validate::{Domain, JobId, Limits, Username};
use oxpanel_daemon::vhost::{VHostRequest, VHostService};
use oxpanel_daemon::Result;

const TENANT: &str = "alice";
const DOMAIN: &str = "site.example";
const PW: &str = "Correct-Horse-9";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    SetMailDomain,
    PutMailbox,
    DeleteMailbox,
    PutForwarder,
    SetAutoresponder,
    RotateDkimKey,
    Suspend,
    Cascade,
}

const ALL: [Op; 8] = [
    Op::SetMailDomain,
    Op::PutMailbox,
    Op::DeleteMailbox,
    Op::PutForwarder,
    Op::SetAutoresponder,
    Op::RotateDkimKey,
    Op::Suspend,
    Op::Cascade,
];

#[derive(Debug, Clone)]
struct Daemon {
    ctx: oxpanel_daemon::ctx::Ctx,
    tenants: TenantService,
    vhosts: VHostService,
    host: HostService,
    mail: MailService,
    lifecycle: LifecycleService,
}

fn world(selinux: bool) -> World {
    let mut w = World::new(selinux);
    let dir = w.dir.path().join("mail");
    let m = &mut w.config.mail;
    m.enabled = true;
    m.hostname = Some(Domain::parse("mail.host.test").unwrap());
    m.password_cost = 4;
    m.postfix_dir = dir.join("postfix");
    m.dovecot_dir = dir.join("dovecot");
    m.rspamd_dir = dir.join("rspamd");
    m.state_dir = dir.join("state");
    m.webmail_dir = dir.join("webmail");
    m.webmail_data_dir = dir.join("webmail-data");
    m.nginx_file = dir.join("nginx-mail.conf");
    m.run_dir = dir.join("run");
    m.milter_dir = dir.join("milter");
    m.selfsigned_dir = dir.join("pki");
    m.roundcube_index = dir.join("roundcube/index.php");
    std::fs::create_dir_all(&w.config.backup_dir).unwrap();
    w.chaos.fake.set_track_units(true);
    w
}

async fn boot(w: &World) -> Daemon {
    let s = w.boot().await;
    let ctx = s.ctx.clone();
    oxpanel_daemon::mail::converge(&ctx).await;
    let backups = BackupService::new(ctx.clone()).with_poll_interval(Duration::from_secs(3600));
    Daemon {
        tenants: s.tenants,
        vhosts: s.vhosts,
        host: s.host,
        mail: MailService::new(ctx.clone()),
        lifecycle: LifecycleService::new(ctx.clone(), backups)
            .with_poll_interval(Duration::from_secs(3600)),
        ctx,
    }
}

async fn setup(op: Op, d: &Daemon) {
    d.tenants
        .create(TENANT, Limits::default(), "")
        .await
        .expect("tenant");
    d.vhosts
        .configure(VHostRequest {
            domain: DOMAIN.into(),
            tenant: TENANT.into(),
            ..VHostRequest::default()
        })
        .await
        .expect("site");
    if op == Op::SetMailDomain {
        return;
    }
    d.mail
        .set_domain(TENANT, DOMAIN, MailMode::Local, &[], "")
        .await
        .expect("mail domain");
    if op == Op::PutMailbox {
        return;
    }
    d.mail
        .put_mailbox(TENANT, DOMAIN, "info", 0, PW, true)
        .await
        .expect("mailbox");
}

fn record(d: &Daemon) -> Option<oxpanel_daemon::mail::store::MailDomainRecord> {
    MailStore::new(&d.ctx.config)
        .load(&Domain::parse(DOMAIN).unwrap())
        .unwrap()
}

/// Wait for the background removal of a deleted mailbox (bounded: a
/// failed removal is finished by the next start).
async fn removal_done(d: &Daemon) {
    for _ in 0..100 {
        if record(d).is_none_or(|r| !r.mailboxes.contains_key("info")) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn run(op: Op, d: &Daemon) -> Result<()> {
    match op {
        Op::SetMailDomain => d
            .mail
            .set_domain(TENANT, DOMAIN, MailMode::Local, &[], "")
            .await
            .map(|_| ()),
        Op::PutMailbox => d
            .mail
            .put_mailbox(TENANT, DOMAIN, "info", 0, PW, true)
            .await
            .map(|_| ()),
        Op::DeleteMailbox => {
            d.mail.delete_mailbox(TENANT, DOMAIN, "info").await?;
            removal_done(d).await;
            Ok(())
        }
        Op::PutForwarder => d
            .mail
            .put_forwarder(
                TENANT,
                DOMAIN,
                "team",
                &["boss@other.example".into()],
                false,
            )
            .await
            .map(|_| ()),
        Op::SetAutoresponder => d
            .mail
            .set_autoresponder(
                TENANT,
                &format!("info@{DOMAIN}"),
                true,
                "Away",
                "Back soon.",
                None,
                None,
            )
            .await
            .map(|_| ()),
        Op::RotateDkimKey => {
            // Rotate once: a repeat after a finished rotation is a no-op here.
            if record(d).is_some_and(|r| !r.dkim_retired.is_empty()) {
                return Ok(());
            }
            d.mail.rotate_dkim(TENANT, DOMAIN).await.map(|_| ())
        }
        Op::Suspend => d.tenants.set_suspended(TENANT, true).await.map(|_| ()),
        Op::Cascade => {
            drive(d).await;
            if d.lifecycle
                .delete_cascade(TENANT, TENANT, 0)
                .await?
                .is_some()
            {
                drive(d).await;
            }
            Ok(())
        }
    }
}

async fn drive(d: &Daemon) {
    for _ in 0..50 {
        let running: Vec<String> = d
            .ctx
            .store
            .list_jobs()
            .unwrap()
            .into_iter()
            .filter(|j| j.state == JobState::Running && j.kind == JobKind::DeleteTenant)
            .map(|j| j.id)
            .collect();
        if running.is_empty() {
            return;
        }
        for id in running {
            d.lifecycle
                .step(&JobId::parse(&id).unwrap())
                .await
                .expect("step");
        }
    }
    panic!("the deletion never finished");
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn verify(op: Op, w: &World, d: &Daemon, context: &str) {
    let m = &w.config.mail;
    let passwd = read(&m.dovecot_dir.join("oxpanel/passwd"));
    let domains = read(&m.postfix_dir.join("oxpanel/domains"));
    let rec = record(d);
    match op {
        Op::SetMailDomain => {
            let r = rec.expect("record");
            assert!(r.dkim.is_some(), "{context}: no DKIM key");
            assert!(
                domains.contains(&format!("{DOMAIN} OK")),
                "{context}: {domains}"
            );
        }
        Op::PutMailbox => {
            assert!(passwd.contains(&format!("info@{DOMAIN}:")), "{context}");
            assert!(
                w.config
                    .home_base
                    .join(TENANT)
                    .join(format!("mail/{DOMAIN}/info"))
                    .is_dir(),
                "{context}: no mail directory"
            );
        }
        Op::DeleteMailbox => {
            assert!(!passwd.contains("info@"), "{context}");
            assert!(
                !rec.unwrap().mailboxes.contains_key("info"),
                "{context}: still being removed"
            );
        }
        Op::PutForwarder => {
            let aliases = read(&m.postfix_dir.join("oxpanel/aliases"));
            assert!(
                aliases.contains(&format!("team@{DOMAIN} boss@other.example")),
                "{context}: {aliases}"
            );
        }
        Op::SetAutoresponder => {
            let s = m.state_dir.join(format!("sieve/{DOMAIN}/info.sieve"));
            assert!(read(&s).contains("vacation"), "{context}");
        }
        Op::RotateDkimKey => {
            let r = rec.unwrap();
            assert_eq!(r.dkim_retired.len(), 1, "{context}");
            let map = read(&m.state_dir.join("dkim/selectors.map"));
            assert!(map.contains(&r.dkim.unwrap().selector), "{context}: {map}");
        }
        Op::Suspend => {
            assert!(
                read(&m.dovecot_dir.join("oxpanel/deny")).contains("info@"),
                "{context}"
            );
            assert!(
                read(&m.postfix_dir.join("oxpanel/recipient_access")).contains(" 450 "),
                "{context}"
            );
        }
        Op::Cascade => {
            assert!(rec.is_none(), "{context}: mail record left");
            assert!(
                d.ctx
                    .store
                    .load_tenant(&Username::parse(TENANT).unwrap())
                    .unwrap()
                    .is_none(),
                "{context}: tenant left"
            );
            let keys = std::fs::read_dir(m.state_dir.join("dkim")).map_or(0, |r| {
                r.flatten()
                    .filter(|e| {
                        std::path::Path::new(&e.file_name())
                            .extension()
                            .is_some_and(|x| x.eq_ignore_ascii_case("key"))
                    })
                    .count()
            });
            assert_eq!(keys, 0, "{context}: DKIM keys left");
            assert!(!passwd.contains("info@"), "{context}");
        }
    }
}

fn assert_no_temporaries(dir: &Path, context: &str) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        assert!(
            !name.starts_with(".oxpanel-"),
            "{context}: temporary {name} in {}",
            dir.display()
        );
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            assert_no_temporaries(&e.path(), context);
        }
    }
}

async fn assert_consistent(w: &World, d: &Daemon, context: &str) {
    let drifts = d.host.reconcile().await.expect("reconcile");
    assert!(drifts.is_empty(), "{context}: reconcile found {drifts:#?}");
    assert_no_temporaries(w.dir.path(), context);
}

async fn interrupt_and_resume(op: Op, selinux: bool, fault: Fault) -> bool {
    let context = format!("{op:?} selinux={selinux} {fault:?}");
    let w = world(selinux);
    let d = boot(&w).await;
    setup(op, &d).await;
    w.chaos.arm(fault);
    let first = {
        let d = d.clone();
        tokio::spawn(async move { run(op, &d).await })
    };
    tokio::pin!(first);
    tokio::select! {
        _ = &mut first => {}
        () = w.chaos.killed() => {
            first.abort();
            let _ = first.await;
        }
    }
    let hit = w.chaos.was_hit();
    w.chaos.arm(Fault::None);
    drop(d);

    let d = boot(&w).await;
    if let Err(e) = run(op, &d).await {
        panic!("{context}: the repeated request failed: {e}");
    }
    verify(op, &w, &d, &context);
    assert_consistent(&w, &d, &context).await;
    run(op, &d).await.expect("idempotent replay");
    verify(op, &w, &d, &format!("{context} (replay)"));
    assert_consistent(&w, &d, &format!("{context} (replay)")).await;
    hit
}

async fn sweep(op: Op, selinux: bool, failures: &mut Vec<String>) -> usize {
    let mut points = 0;
    for make in [Fault::FailAt, Fault::KillBefore, Fault::KillAfter] {
        let mut k = 0;
        loop {
            match tokio::spawn(interrupt_and_resume(op, selinux, make(k))).await {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    let panic = e.into_panic();
                    let msg = panic
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                        .unwrap_or_else(|| format!("{op:?} {:?}: panicked", make(k)));
                    failures.push(msg.lines().take(12).collect::<Vec<_>>().join(" | "));
                }
            }
            k += 1;
            assert!(k < 300, "{op:?}: runaway workflow");
        }
        points += k;
    }
    points
}

#[tokio::test]
async fn email_workflows_survive_interruption_at_every_command() {
    let mut failures = Vec::new();
    let mut total = 0;
    for selinux in [false, true] {
        for op in ALL {
            let n = sweep(op, selinux, &mut failures).await;
            assert!(n > 0, "{op:?} ran no command at all");
            total += n;
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {total} interruption points left an inconsistent state:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[tokio::test]
async fn uninterrupted_email_workflows_are_consistent() {
    for op in ALL {
        let w = world(false);
        let d = boot(&w).await;
        setup(op, &d).await;
        assert_consistent(&w, &d, &format!("{op:?} after setup")).await;
        run(op, &d).await.unwrap_or_else(|e| panic!("{op:?}: {e}"));
        verify(op, &w, &d, &format!("{op:?}"));
        assert_consistent(&w, &d, &format!("{op:?}")).await;
    }
}
