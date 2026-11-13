//! Crash safety, exhaustively: every workflow is interrupted at every external
//! command it runs — once by a failing command, once by killing the daemon
//! just before the command, once by killing it just after — then the daemon
//! is restarted on the same state and the request is repeated. The repeated
//! request must succeed and leave records, files, accounts and running
//! services consistent (`Reconcile` reports nothing).
//!
//! "Killing" is exact, not simulated by an error: the workflow's future is
//! frozen inside the command and dropped, so no clean-up code runs.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use common::{assert_consistent, Fault, Services, World};
use oxpanel_daemon::records::{AppRuntime, TenantState};
use oxpanel_daemon::system::bin;
use oxpanel_daemon::validate::{Limits, Username};
use oxpanel_daemon::vhost::{AppRequest, VHostRequest};
use oxpanel_daemon::Result;

const TENANT: &str = "alice";
const SITE: &str = "site.example";
const OTHER_SITE: &str = "other.example";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    CreateTenant,
    UpdateLimits,
    ConfigureStatic,
    ConfigurePhp,
    ConfigureNode,
    ConfigurePython,
    /// PHP switched off on the tenant's only PHP site: the pool must go.
    PhpOff,
    /// The application switched off: its unit must go.
    AppOff,
    /// A static site becomes a PHP site.
    StaticToPhp,
    Suspend,
    Resume,
    RemoveStatic,
    RemovePhp,
    RemoveApp,
    DeleteTenant,
}

const ALL: [Op; 15] = [
    Op::CreateTenant,
    Op::UpdateLimits,
    Op::ConfigureStatic,
    Op::ConfigurePhp,
    Op::ConfigureNode,
    Op::ConfigurePython,
    Op::PhpOff,
    Op::AppOff,
    Op::StaticToPhp,
    Op::Suspend,
    Op::Resume,
    Op::RemoveStatic,
    Op::RemovePhp,
    Op::RemoveApp,
    Op::DeleteTenant,
];

fn limits(memory_mib: u64) -> Limits {
    Limits {
        memory_max_bytes: Some(memory_mib << 20),
        cpu_weight: Some(50),
        io_weight: None,
        tasks_max: Some(64),
        // The fake host enforces no quotas: a disk limit would be refused.
        disk_max_bytes: None,
        inodes_max: None,
        db_trash_max_bytes: None,
    }
}

fn site(domain: &str) -> VHostRequest {
    VHostRequest {
        domain: domain.into(),
        tenant: TENANT.into(),
        ..VHostRequest::default()
    }
}

fn php_site(domain: &str) -> VHostRequest {
    VHostRequest {
        php: true,
        ..site(domain)
    }
}

fn app_site(domain: &str, runtime: AppRuntime) -> VHostRequest {
    VHostRequest {
        app: Some(AppRequest {
            runtime,
            root: String::new(),
            entry: String::new(),
        }),
        ..site(domain)
    }
}

/// State the operation starts from.
async fn setup(op: Op, s: &Services) {
    if op == Op::CreateTenant {
        return;
    }
    s.tenants
        .create(TENANT, limits(128), "")
        .await
        .expect("tenant");
    let sites: Vec<VHostRequest> = match op {
        Op::PhpOff | Op::RemovePhp => vec![php_site(SITE)],
        Op::AppOff | Op::RemoveApp => vec![app_site(SITE, AppRuntime::Node)],
        Op::StaticToPhp | Op::RemoveStatic => vec![site(SITE)],
        // Suspension has to stop PHP and both kinds of application.
        Op::Suspend | Op::Resume => vec![
            php_site(SITE),
            app_site(OTHER_SITE, AppRuntime::Node),
            app_site("third.example", AppRuntime::Python),
        ],
        _ => vec![],
    };
    for r in sites {
        s.vhosts.configure(r).await.expect("site");
    }
    if op == Op::Resume {
        s.tenants
            .set_suspended(TENANT, true)
            .await
            .expect("suspend");
    }
}

/// The request under test. Repeating it must be safe.
async fn run(op: Op, s: &Services) -> Result<()> {
    match op {
        Op::CreateTenant => s
            .tenants
            .create(TENANT, limits(128), "r1")
            .await
            .map(|_| ()),
        Op::UpdateLimits => s
            .tenants
            .update_limits(TENANT, limits(256))
            .await
            .map(|_| ()),
        Op::ConfigureStatic | Op::PhpOff | Op::AppOff => {
            s.vhosts.configure(site(SITE)).await.map(|_| ())
        }
        Op::ConfigurePhp | Op::StaticToPhp => s.vhosts.configure(php_site(SITE)).await.map(|_| ()),
        Op::ConfigureNode => s
            .vhosts
            .configure(app_site(SITE, AppRuntime::Node))
            .await
            .map(|_| ()),
        Op::ConfigurePython => s
            .vhosts
            .configure(app_site(SITE, AppRuntime::Python))
            .await
            .map(|_| ()),
        Op::Suspend => s.tenants.set_suspended(TENANT, true).await.map(|_| ()),
        Op::Resume => s.tenants.set_suspended(TENANT, false).await.map(|_| ()),
        Op::RemoveStatic | Op::RemovePhp | Op::RemoveApp => s.vhosts.remove(SITE).await.map(|_| ()),
        Op::DeleteTenant => s.tenants.delete(TENANT, true).await.map(|_| ()),
    }
}

/// What the operation promised, beyond general consistency.
async fn verify(op: Op, w: &World, s: &Services, context: &str) {
    let name = Username::parse(TENANT).expect("name");
    let tenant = s.ctx.store.load_tenant(&name).expect("load tenant");
    let vhost = s
        .vhosts
        .list(None)
        .await
        .expect("list")
        .into_iter()
        .find(|v| v.domain == SITE);
    let cfg = &w.config;
    let pool_unit = cfg.systemd_unit_dir.join("oxpanel-php-alice.service");
    let pool_conf = cfg.php_conf_dir.join("alice.conf");
    let app_unit = cfg
        .systemd_unit_dir
        .join(format!("oxpanel-app-{SITE}.service"));
    let site_conf = cfg.nginx_conf_dir.join(format!("{SITE}.conf"));
    match op {
        Op::CreateTenant => {
            let t = tenant.expect("tenant record");
            assert_eq!(t.state, TenantState::Ready, "{context}");
            assert_eq!(t.owner, "r1", "{context}");
            assert_eq!(
                w.chaos.fake.calls_to(bin::USERADD).len(),
                1,
                "{context}: the account is created exactly once"
            );
        }
        Op::UpdateLimits => {
            assert_eq!(tenant.expect("tenant").limits, limits(256), "{context}");
        }
        Op::ConfigureStatic | Op::PhpOff | Op::AppOff => {
            let v = vhost.expect("site record");
            assert!(!v.php && v.app.is_none(), "{context}");
            assert!(
                !pool_unit.exists() && !pool_conf.exists(),
                "{context}: PHP pool left behind"
            );
            assert!(
                !app_unit.exists(),
                "{context}: application unit left behind"
            );
        }
        Op::ConfigurePhp | Op::StaticToPhp => {
            assert!(vhost.expect("site record").php, "{context}");
            assert!(pool_unit.is_file() && pool_conf.is_file(), "{context}");
        }
        Op::ConfigureNode | Op::ConfigurePython => {
            assert!(vhost.expect("site record").app.is_some(), "{context}");
            assert!(app_unit.is_file(), "{context}");
        }
        Op::Suspend | Op::Resume => {
            let suspended = op == Op::Suspend;
            assert_eq!(tenant.expect("tenant").suspended, suspended, "{context}");
            let conf = std::fs::read_to_string(&site_conf).expect("site config");
            assert_eq!(conf.contains("return 503;"), suspended, "{context}");
        }
        Op::RemoveStatic | Op::RemovePhp | Op::RemoveApp => {
            assert!(vhost.is_none(), "{context}: record left behind");
            assert!(!site_conf.exists(), "{context}: site config left behind");
            assert!(
                !pool_unit.exists() && !pool_conf.exists(),
                "{context}: PHP pool left behind"
            );
            assert!(
                !app_unit.exists(),
                "{context}: application unit left behind"
            );
            for kind in ["access", "error"] {
                assert!(
                    !cfg.nginx_log_dir
                        .join(format!("{SITE}.{kind}.log"))
                        .exists(),
                    "{context}: log left behind"
                );
            }
        }
        Op::DeleteTenant => {
            assert!(tenant.is_none(), "{context}: record left behind");
            assert!(
                w.chaos.fake.users().is_empty(),
                "{context}: account left behind"
            );
            assert!(
                !cfg.systemd_unit_dir
                    .join("oxpanel-tenant-alice.slice")
                    .exists(),
                "{context}: slice left behind"
            );
        }
    }
}

/// Interrupt `op` at command `k` in the given way, restart, repeat, check.
/// Returns whether command `k` existed (false = the workflow is shorter).
async fn interrupt_and_resume(op: Op, selinux: bool, fault: Fault) -> bool {
    let context = format!("{op:?} selinux={selinux} {fault:?}");
    let w = World::new(selinux);
    let s = w.boot().await;
    setup(op, &s).await;

    w.chaos.arm(fault);
    let first = {
        let s = s.clone();
        tokio::spawn(async move { run(op, &s).await })
    };
    tokio::pin!(first);
    tokio::select! {
        _ = &mut first => {}
        () = w.chaos.killed() => {
            // The daemon dies here: nothing after this point runs.
            first.abort();
            let _ = first.await;
        }
    }
    let hit = w.chaos.was_hit();
    w.chaos.arm(Fault::None);
    drop(s);

    // Restart on the same disk and the same operating system, then repeat.
    let s = w.boot().await;
    if let Err(e) = run(op, &s).await {
        panic!("{context}: the repeated request failed: {e}");
    }
    verify(op, &w, &s, &context).await;
    assert_consistent(&w, &s, &context).await;
    // And once more: a third identical request changes nothing.
    run(op, &s).await.expect("idempotent replay");
    assert_consistent(&w, &s, &format!("{context} (replay)")).await;
    hit
}

/// Every interruption point of `op`, in all three ways. Returns how many
/// points there were; failures are collected so one run reports them all.
async fn sweep(op: Op, selinux: bool, failures: &mut Vec<String>) -> usize {
    let mut points = 0;
    for make in [Fault::FailAt, Fault::KillBefore, Fault::KillAfter] {
        let mut k = 0;
        loop {
            // In its own task so a failed assertion is recorded, not fatal.
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
                    failures.push(msg.lines().next().unwrap_or_default().to_owned());
                }
            }
            k += 1;
            assert!(k < 200, "{op:?}: runaway workflow");
        }
        points += k;
    }
    points
}

async fn sweep_all(selinux: bool) {
    let mut failures = Vec::new();
    let mut total = 0;
    for op in ALL {
        let n = sweep(op, selinux, &mut failures).await;
        assert!(n > 0, "{op:?} ran no command at all");
        total += n;
    }
    assert!(
        failures.is_empty(),
        "{} of {total} interruption points left an inconsistent state:\n{}",
        failures.len(),
        failures.join("\n")
    );
    // Not a tautology: the sweep really found interruption points.
    assert!(total > 150, "only {total} interruption points exercised");
}

#[tokio::test]
async fn every_workflow_survives_interruption_at_every_command() {
    sweep_all(false).await;
}

#[tokio::test]
async fn every_workflow_survives_interruption_on_selinux_hosts() {
    sweep_all(true).await;
}

/// An uninterrupted run of every workflow is consistent too (the baseline the
/// sweeps compare against), and so is repeating it.
#[tokio::test]
async fn uninterrupted_workflows_are_consistent_and_idempotent() {
    for op in ALL {
        for selinux in [false, true] {
            let w = World::new(selinux);
            let s = w.boot().await;
            setup(op, &s).await;
            assert_consistent(&w, &s, &format!("{op:?} after setup")).await;
            run(op, &s).await.expect("run");
            verify(op, &w, &s, &format!("{op:?}")).await;
            assert_consistent(&w, &s, &format!("{op:?}")).await;
        }
    }
}
