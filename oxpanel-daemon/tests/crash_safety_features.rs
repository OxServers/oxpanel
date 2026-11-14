//! Crash safety of the multi-step workflows added after `crash_safety.rs`
//! was written: certificates and Automatic HTTPS, SFTP access and passwords,
//! disk quotas, databases and their trash, scheduled tasks, per-site PHP
//! pools, backup schedules, DNS zones, records and DNSSEC, and the job-based
//! workflows (backup, restore, database restore, file jobs, cascade
//! deletion).
//!
//! The method is `crash_safety.rs`' own: every workflow is interrupted at
//! every external command it runs — the command fails, the daemon is killed
//! just before it, the daemon is killed just after it (the workflow's future
//! is frozen inside the command and dropped: no clean-up code runs) — then a
//! new daemon boots on the same disk and the same (fake) operating system,
//! and the request is repeated. It must succeed and leave records, files,
//! accounts, database server, DNS server and running services consistent
//! (`Reconcile` reports nothing, no temporary file is left, no job is left
//! running), and a further identical request must keep it so.
//!
//! The fake OS here has MariaDB installed, DNS hosting on (the fake server
//! serves what is in the zones directory), disk quotas enforced and an ACME
//! authority: every feature takes its real code path.
//!
//! Job workflows are "repeated" the way an operator repeats them: a job the
//! interrupted daemon left running is driven to its end (as `resume_all`
//! does at start-up), and the request is made again only if the result is
//! not there yet.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::match_wildcard_for_single_variants,
    clippy::case_sensitive_file_extension_comparisons
)]

mod common;

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use common::{running_units, Fault, World};
use oxpanel_daemon::backup::BackupService;
use oxpanel_daemon::backup_schedule::{Frequency, ScheduleService};
use oxpanel_daemon::db::DbService;
use oxpanel_daemon::dns::rr::{RawRr, RrType};
use oxpanel_daemon::dns::DnsService;
use oxpanel_daemon::files::{FileService, JobRequest};
use oxpanel_daemon::host::HostService;
use oxpanel_daemon::lifecycle::LifecycleService;
use oxpanel_daemon::php_settings::RawSettings;
use oxpanel_daemon::records::{DbEngine, JobKind, JobState, OnExisting, TenantState};
use oxpanel_daemon::sftp::SftpService;
use oxpanel_daemon::system::fake_tls::{fake_certificate, fake_private_key};
use oxpanel_daemon::task::{Form, RawSchedule, RawSpec, TaskKind, TaskService};
use oxpanel_daemon::tenant::TenantService;
use oxpanel_daemon::tls::{CertificateUpload, TlsService};
use oxpanel_daemon::validate::{FileJobId, FilePath, JobId, Limits, Username};
use oxpanel_daemon::vhost::{VHostRequest, VHostService};
use oxpanel_daemon::{app, php, Error, Result};

const TENANT: &str = "alice";
const SITE: &str = "site.example";
const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGNQ8nctDOzq4yQ8Bix4hfkkqCQw0kkYzl6hc7hg7rRo alice@laptop";
const PASSWORD: &str = "correct horse battery staple";
const DB: &str = "alice_wp";
const DB_USER: &str = "alice_app";
const POLL: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    SftpAddKey,
    SftpRemoveKey,
    SftpSetPassword,
    SftpClearPassword,
    CertInstall,
    CertRemove,
    AutoHttps,
    DiskQuota,
    DbCreate,
    DbUserAndGrant,
    DbDelete,
    DbTrashRestore,
    DbTrashPurge,
    TaskPut,
    TaskDelete,
    PhpSettingsOn,
    PhpSettingsOff,
    BackupSchedule,
    DnsZoneCreate,
    DnsZoneDelete,
    DnsRecordAdd,
    DnssecOn,
    DnssecOff,
    Backup,
    Restore,
    RestoreDatabase,
    FileCopy,
    Cascade,
}

const ALL: [Op; 28] = [
    Op::SftpAddKey,
    Op::SftpRemoveKey,
    Op::SftpSetPassword,
    Op::SftpClearPassword,
    Op::CertInstall,
    Op::CertRemove,
    Op::AutoHttps,
    Op::DiskQuota,
    Op::DbCreate,
    Op::DbUserAndGrant,
    Op::DbDelete,
    Op::DbTrashRestore,
    Op::DbTrashPurge,
    Op::TaskPut,
    Op::TaskDelete,
    Op::PhpSettingsOn,
    Op::PhpSettingsOff,
    Op::BackupSchedule,
    Op::DnsZoneCreate,
    Op::DnsZoneDelete,
    Op::DnsRecordAdd,
    Op::DnssecOn,
    Op::DnssecOff,
    Op::Backup,
    Op::Restore,
    Op::RestoreDatabase,
    Op::FileCopy,
    Op::Cascade,
];

/// Every service of one daemon "process".
#[derive(Debug, Clone)]
struct Daemon {
    ctx: oxpanel_daemon::ctx::Ctx,
    tenants: TenantService,
    vhosts: VHostService,
    host: HostService,
    sftp: SftpService,
    tls: TlsService,
    db: DbService,
    tasks: TaskService,
    schedules: ScheduleService,
    dns: DnsService,
    backups: BackupService,
    files: FileService,
    lifecycle: LifecycleService,
}

/// A world with every feature available on the fake host.
fn world(selinux: bool) -> World {
    let mut w = World::new(selinux);
    let dir = w.dir.path().to_owned();
    let dns = &mut w.config.dns;
    dns.conf_dir = dir.join("named-oxpanel");
    dns.data_dir = dir.join("oxpanel-dns");
    dns.suffix_list = dir.join("public_suffix_list.dat");
    dns.enabled = true;
    dns.nameservers = vec![
        oxpanel_daemon::validate::Domain::parse("ns1.example.net").unwrap(),
        oxpanel_daemon::validate::Domain::parse("ns2.example.net").unwrap(),
    ];
    dns.soa_contact = "hostmaster@example.net".into();
    dns.ipv4 = Some(std::net::Ipv4Addr::new(203, 0, 113, 10));
    std::fs::write(&w.config.dns.suffix_list, "com\nnet\norg\n").unwrap();
    for sub in ["account", "challenges", "csr", "issued"] {
        std::fs::create_dir_all(w.config.acme_dir.join(sub)).unwrap();
    }
    std::fs::create_dir_all(dir.join("run")).unwrap();
    std::fs::create_dir_all(&w.config.backup_dir).unwrap();
    w.chaos.fake.install_mariadb();
    w.chaos
        .fake
        .dns_follow(&w.config.dns.data_dir.join("zones"));
    w.chaos
        .fake
        .dns_follow_conf(&w.config.dns.conf_dir.join("zones.conf"));
    w.chaos.fake.set_quota_enforced(true);
    w.chaos.fake.set_track_units(true);
    // The ACME client's system account (created by the package).
    w.chaos.fake.add_user(oxpanel_daemon::system::OsUser {
        name: oxpanel_daemon::acme::ACME_USER.into(),
        uid: 990,
        gid: 990,
        home: "/".into(),
        shell: "/sbin/nologin".into(),
    });
    w
}

/// The tenants' accounts on the fake host (not the system's own).
fn tenant_accounts(w: &World) -> BTreeSet<String> {
    w.chaos
        .fake
        .users()
        .into_iter()
        .map(|u| u.name)
        .filter(|n| n != oxpanel_daemon::acme::ACME_USER)
        .collect()
}

/// Start (or restart) the daemon: what `main` does before it serves, except
/// that resumed jobs are driven by the test (see `drive_running`).
async fn boot(w: &World) -> Daemon {
    let s = w.boot().await;
    let ctx = s.ctx.clone();
    oxpanel_daemon::dns::converge(&ctx).await;
    let backups = BackupService::new(ctx.clone()).with_poll_interval(POLL);
    Daemon {
        tenants: s.tenants,
        vhosts: s.vhosts,
        host: s.host,
        sftp: SftpService::new(ctx.clone()),
        tls: TlsService::new(ctx.clone()),
        db: DbService::new(ctx.clone()),
        tasks: TaskService::new(ctx.clone()),
        schedules: ScheduleService::new(ctx.clone(), backups.clone()),
        dns: DnsService::new(ctx.clone()),
        files: FileService::new(ctx.clone()).with_poll_interval(POLL),
        lifecycle: LifecycleService::new(ctx.clone(), backups.clone()).with_poll_interval(POLL),
        backups,
        ctx,
    }
}

fn php_site() -> VHostRequest {
    VHostRequest {
        domain: SITE.into(),
        tenant: TENANT.into(),
        php: true,
        ..VHostRequest::default()
    }
}

fn upload() -> CertificateUpload {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    CertificateUpload {
        domain: SITE.into(),
        chain_pem: fake_certificate("k1", "Test CA", now - 3600, now + 60 * 86400, &[SITE]),
        key_pem: fake_private_key("k1"),
    }
}

fn task() -> RawSpec {
    RawSpec {
        name: "nightly".into(),
        kind: Some(TaskKind::Php),
        script: "public_html/cron.php".into(),
        schedule: RawSchedule {
            form: Some(Form::Daily),
            hour: 3,
            ..RawSchedule::default()
        },
        ..RawSpec::default()
    }
}

fn record() -> RawRr {
    RawRr {
        name: "mail".into(),
        rtype: Some(RrType::A),
        value: "192.0.2.25".into(),
        ..RawRr::default()
    }
}

fn disk_limits() -> Limits {
    Limits {
        disk_max_bytes: Some(512 << 20),
        inodes_max: Some(10_000),
        ..Limits::default()
    }
}

/// The trash item of `DB`, if any.
fn trash_id(d: &Daemon) -> Option<String> {
    d.ctx
        .store
        .list_trash()
        .unwrap()
        .into_iter()
        .find(|t| t.name == DB)
        .map(|t| t.id)
}

fn last_backup(d: &Daemon) -> Option<String> {
    let mut b = d.ctx.store.list_backups().unwrap();
    b.retain(|b| b.tenant == TENANT);
    b.sort_by_key(|b| b.created_at_unix);
    b.last().map(|b| b.id.clone())
}

/// State the operation starts from: alice with a PHP site (and its zone).
async fn setup(op: Op, d: &Daemon) {
    d.tenants
        .create(TENANT, Limits::default(), "")
        .await
        .expect("tenant");
    d.vhosts.configure(php_site()).await.expect("site");
    let home = d.ctx.config.home_base.join(TENANT);
    std::fs::create_dir_all(home.join("public_html")).unwrap();
    std::fs::create_dir_all(home.join("copy")).unwrap();
    std::fs::write(home.join("public_html").join("index.php"), "<?php echo 1;").unwrap();
    match op {
        Op::SftpRemoveKey => {
            d.sftp.add_key(TENANT, KEY, "laptop").await.expect("key");
        }
        Op::SftpClearPassword => {
            d.sftp.set_password(TENANT, PASSWORD).await.expect("pw");
        }
        Op::CertRemove => {
            d.tls.install(upload()).await.expect("cert");
        }
        Op::DbUserAndGrant | Op::DbDelete | Op::RestoreDatabase => {
            d.db.create_database(TENANT, DB, DbEngine::Mariadb)
                .await
                .expect("db");
        }
        Op::DbTrashRestore | Op::DbTrashPurge => {
            d.db.create_database(TENANT, DB, DbEngine::Mariadb)
                .await
                .expect("db");
            d.db.delete_database(DB).await.expect("trash");
        }
        Op::TaskDelete => {
            d.tasks.put(TENANT, &task()).await.expect("task");
        }
        Op::PhpSettingsOff => {
            d.vhosts
                .set_php_settings(SITE, &php_settings())
                .await
                .expect("php settings");
        }
        Op::DnsZoneDelete => {
            d.dns
                .create_zone(TENANT, "other.example")
                .await
                .expect("zone");
        }
        Op::DnssecOff => {
            d.dns
                .set_dnssec(TENANT, SITE, true, false)
                .await
                .expect("dnssec");
        }
        Op::Cascade => {
            // One of everything the cascade has to take away.
            d.sftp.add_key(TENANT, KEY, "laptop").await.expect("key");
            d.db.create_database(TENANT, DB, DbEngine::Mariadb)
                .await
                .expect("db");
            d.db.create_user(TENANT, DB_USER, "db-password-123", DbEngine::Mariadb)
                .await
                .expect("user");
            d.db.grant(DB_USER, DB).await.expect("grant");
            d.tasks.put(TENANT, &task()).await.expect("task");
            d.dns
                .add_record(TENANT, SITE, &record())
                .await
                .expect("record");
            d.tls.install(upload()).await.expect("cert");
        }
        _ => {}
    }
    if matches!(op, Op::Restore | Op::RestoreDatabase) {
        drive(d, JobKind::Backup).await;
        assert!(last_backup(d).is_some(), "setup: no backup");
    }
}

fn php_settings() -> RawSettings {
    RawSettings {
        memory_limit_mb: 256,
        ..RawSettings::default()
    }
}

/// Step every running job until none runs (what the job drivers do).
async fn drive_running(d: &Daemon) {
    for _ in 0..50 {
        let mut busy = false;
        for job in d.ctx.store.list_jobs().unwrap() {
            if job.state != JobState::Running {
                continue;
            }
            busy = true;
            let id = JobId::parse(&job.id).unwrap();
            if job.kind == JobKind::DeleteTenant {
                d.lifecycle.step(&id).await.expect("step deletion");
            } else {
                d.backups.step(&id).await.expect("step job");
            }
        }
        for job in d.ctx.store.list_file_jobs().unwrap() {
            if job.state != JobState::Running {
                continue;
            }
            busy = true;
            d.files
                .step(&FileJobId::parse(&job.id).unwrap())
                .await
                .expect("step file job");
        }
        if !busy {
            return;
        }
    }
    panic!("jobs never finished");
}

/// Start a job of `kind` (if none is needed any more, nothing) and drive it.
async fn drive(d: &Daemon, kind: JobKind) {
    drive_running(d).await;
    let started = match kind {
        JobKind::Backup => d.backups.create(TENANT, 0, 0).await.map(|_| ()),
        JobKind::Restore => {
            let b = last_backup(d).expect("a backup to restore");
            d.backups
                .restore(TENANT, &b, OnExisting::Overwrite)
                .await
                .map(|_| ())
        }
        JobKind::RestoreDatabase => {
            let b = last_backup(d).expect("a backup to restore");
            d.backups
                .restore_database(TENANT, &b, DB, "alice_copy")
                .await
                .map(|_| ())
        }
        other => panic!("not driven here: {other:?}"),
    };
    started.expect("start job");
    drive_running(d).await;
}

fn succeeded(d: &Daemon, kind: JobKind) -> bool {
    d.ctx
        .store
        .list_jobs()
        .unwrap()
        .iter()
        .any(|j| j.kind == kind && j.tenant == TENANT && j.state == JobState::Succeeded)
}

/// The request under test. Repeating it must be safe.
async fn run(op: Op, d: &Daemon) -> Result<()> {
    match op {
        Op::SftpAddKey => d.sftp.add_key(TENANT, KEY, "laptop").await.map(|_| ()),
        Op::SftpRemoveKey => {
            let fp = d
                .sftp
                .list_keys(TENANT)
                .await?
                .first()
                .map(|k| k.fingerprint.clone());
            match fp {
                Some(fp) => d.sftp.remove_key(TENANT, &fp, false).await.map(|_| ()),
                None => Ok(()),
            }
        }
        Op::SftpSetPassword => d.sftp.set_password(TENANT, PASSWORD).await.map(|_| ()),
        Op::SftpClearPassword => d.sftp.clear_password(TENANT, false).await.map(|_| ()),
        Op::CertInstall => d.tls.install(upload()).await.map(|_| ()),
        Op::CertRemove => d.tls.remove(SITE).await.map(|_| ()),
        Op::AutoHttps => d.tls.auto_https_run(SITE).await.map(|_| ()),
        Op::DiskQuota => d
            .tenants
            .update_limits(TENANT, disk_limits())
            .await
            .map(|_| ()),
        Op::DbCreate => {
            d.db.create_database(TENANT, DB, DbEngine::Mariadb)
                .await
                .map(|_| ())
        }
        Op::DbUserAndGrant => {
            d.db.create_user(TENANT, DB_USER, "db-password-123", DbEngine::Mariadb)
                .await?;
            d.db.grant(DB_USER, DB).await.map(|_| ())
        }
        Op::DbDelete => d.db.delete_database(DB).await.map(|_| ()),
        Op::DbTrashRestore => match trash_id(d) {
            Some(t) => {
                d.db.restore_trash(TENANT, &t, "alice_back")
                    .await
                    .map(|_| ())
            }
            None => Ok(()),
        },
        Op::DbTrashPurge => match trash_id(d) {
            Some(t) => d.db.purge_trash(TENANT, &t).await.map(|_| ()),
            None => Ok(()),
        },
        Op::TaskPut => d.tasks.put(TENANT, &task()).await.map(|_| ()),
        Op::TaskDelete => d.tasks.delete(TENANT, "nightly").await.map(|_| ()),
        Op::PhpSettingsOn => d
            .vhosts
            .set_php_settings(SITE, &php_settings())
            .await
            .map(|_| ()),
        Op::PhpSettingsOff => d
            .vhosts
            .set_php_settings(SITE, &RawSettings::default())
            .await
            .map(|_| ()),
        Op::BackupSchedule => d
            .schedules
            .set(TENANT, Some(Frequency::Daily), Some(2), None)
            .await
            .map(|_| ()),
        Op::DnsZoneCreate => d.dns.create_zone(TENANT, "other.example").await.map(|_| ()),
        Op::DnsZoneDelete => d.dns.delete_zone(TENANT, "other.example").await.map(|_| ()),
        Op::DnsRecordAdd => {
            // Adding the same record twice is refused as a duplicate; the
            // repeat is "make sure it is there".
            let zone = d.dns.get_zone(TENANT, SITE).await?;
            if zone.records.iter().any(|r| r.rr.name.as_str() == "mail") {
                return Ok(());
            }
            d.dns.add_record(TENANT, SITE, &record()).await.map(|_| ())
        }
        Op::DnssecOn => d
            .dns
            .set_dnssec(TENANT, SITE, true, false)
            .await
            .map(|_| ()),
        Op::DnssecOff => d
            .dns
            .set_dnssec(TENANT, SITE, false, true)
            .await
            .map(|_| ()),
        Op::Backup => {
            drive_running(d).await;
            if !succeeded(d, JobKind::Backup) {
                drive(d, JobKind::Backup).await;
            }
            Ok(())
        }
        Op::Restore => {
            drive_running(d).await;
            if !succeeded(d, JobKind::Restore) {
                drive(d, JobKind::Restore).await;
            }
            Ok(())
        }
        Op::RestoreDatabase => {
            drive_running(d).await;
            if !succeeded(d, JobKind::RestoreDatabase)
                && d.ctx
                    .store
                    .list_databases()?
                    .iter()
                    .all(|r| r.name != "alice_copy")
            {
                drive(d, JobKind::RestoreDatabase).await;
            }
            Ok(())
        }
        Op::FileCopy => {
            drive_running(d).await;
            let dst = d.ctx.config.home_base.join(TENANT).join("copy");
            if dst.join("public_html").join("index.php").is_file() {
                return Ok(());
            }
            d.files
                .start_job(
                    TENANT,
                    JobRequest::Copy {
                        sources: vec![FilePath::parse("public_html", "sources")?],
                        destination: FilePath::parse("copy", "destination")?,
                        overwrite: true,
                    },
                )
                .await?;
            drive_running(d).await;
            Ok(())
        }
        Op::Cascade => {
            drive_running(d).await;
            if d.lifecycle
                .delete_cascade(TENANT, TENANT, 0)
                .await?
                .is_some()
            {
                drive_running(d).await;
            }
            Ok(())
        }
    }
}

/// What the operation promised, beyond general consistency.
async fn verify(op: Op, w: &World, d: &Daemon, context: &str) {
    let name = Username::parse(TENANT).unwrap();
    let tenant = d.ctx.store.load_tenant(&name).unwrap();
    let cfg = &w.config;
    let keys_file = cfg.sftp_keys_dir.join(TENANT);
    let site_conf = std::fs::read_to_string(cfg.nginx_conf_dir.join(format!("{SITE}.conf")))
        .unwrap_or_default();
    let has_trash = trash_id(d).is_some();
    let databases: BTreeSet<String> = d
        .ctx
        .store
        .list_databases()
        .unwrap()
        .into_iter()
        .map(|r| r.name)
        .collect();
    match op {
        Op::SftpAddKey => {
            assert_eq!(tenant.unwrap().sftp_keys.len(), 1, "{context}");
            let text = std::fs::read_to_string(&keys_file).expect("keys file");
            assert!(text.contains("restrict "), "{context}: {text}");
        }
        Op::SftpRemoveKey => {
            assert!(tenant.unwrap().sftp_keys.is_empty(), "{context}");
            assert!(!keys_file.exists(), "{context}: keys file left");
        }
        Op::SftpSetPassword => assert!(tenant.unwrap().sftp_password, "{context}"),
        Op::SftpClearPassword => assert!(!tenant.unwrap().sftp_password, "{context}"),
        Op::CertInstall | Op::AutoHttps => {
            assert!(
                site_conf.contains("ssl_certificate "),
                "{context}: {site_conf}"
            );
        }
        Op::CertRemove => {
            assert!(!site_conf.contains("ssl_certificate "), "{context}");
            let left: Vec<_> = std::fs::read_dir(&cfg.tls_dir)
                .map(|r| r.flatten().map(|e| e.file_name()).collect())
                .unwrap_or_default();
            assert!(
                left.is_empty(),
                "{context}: certificate files left: {left:?}"
            );
        }
        Op::DiskQuota => {
            let t = tenant.unwrap();
            assert_eq!(t.limits, disk_limits(), "{context}");
            assert_eq!(
                w.chaos.fake.quota_limits(t.uid),
                (512 << 10, 10_000),
                "{context}: the kernel's limits"
            );
        }
        Op::DbCreate | Op::DbUserAndGrant => assert!(databases.contains(DB), "{context}"),
        Op::DbDelete => {
            assert!(!databases.contains(DB), "{context}");
            assert!(has_trash, "{context}: not in the trash");
        }
        Op::DbTrashRestore => {
            assert!(databases.contains("alice_back") && !has_trash, "{context}");
        }
        Op::DbTrashPurge => assert!(!has_trash, "{context}"),
        Op::TaskPut => assert_eq!(d.tasks.list(TENANT).await.unwrap().len(), 1, "{context}"),
        Op::TaskDelete => assert!(d.tasks.list(TENANT).await.unwrap().is_empty(), "{context}"),
        Op::PhpSettingsOn | Op::PhpSettingsOff => {
            let on = op == Op::PhpSettingsOn;
            let pools = std::fs::read_dir(&cfg.php_conf_dir)
                .unwrap()
                .flatten()
                .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
                .collect::<String>();
            assert_eq!(
                pools.contains("memory_limit] = 256M"),
                on,
                "{context}: {pools}"
            );
        }
        Op::BackupSchedule => {
            let v = d.schedules.get(TENANT).await.unwrap();
            assert!(format!("{v:?}").contains("Daily"), "{context}: {v:?}");
        }
        Op::DnsZoneCreate | Op::DnsZoneDelete => {
            let exists = d
                .dns
                .list_zones(TENANT)
                .await
                .unwrap()
                .iter()
                .any(|z| z.record.zone == "other.example");
            assert_eq!(exists, op == Op::DnsZoneCreate, "{context}");
            // (The fake server loads whatever zone files exist, so only a
            // created zone can be checked against what it serves; a deleted
            // one is checked by its files, below and in Reconcile.)
            if op == Op::DnsZoneCreate {
                assert!(
                    w.chaos.fake.dns_served("other.example").is_some(),
                    "{context}: the server does not serve the new zone"
                );
            } else {
                assert!(
                    !w.config
                        .dns
                        .data_dir
                        .join("zones/other.example.zone")
                        .exists(),
                    "{context}: zone file left"
                );
            }
        }
        Op::DnsRecordAdd => {
            let zone = d.dns.get_zone(TENANT, SITE).await.unwrap();
            assert_eq!(
                zone.records
                    .iter()
                    .filter(|r| r.rr.name.as_str() == "mail")
                    .count(),
                1,
                "{context}"
            );
        }
        Op::DnssecOn | Op::DnssecOff => {
            let zone = d.dns.get_zone(TENANT, SITE).await.unwrap();
            assert_eq!(
                !format!("{:?}", zone.dnssec.state).contains("Off"),
                op == Op::DnssecOn,
                "{context}: {:?}",
                zone.dnssec
            );
        }
        Op::Backup => {
            assert!(succeeded(d, JobKind::Backup), "{context}");
            let b = last_backup(d).expect("backup record");
            assert!(
                cfg.backup_dir.join(TENANT).join(&b).is_dir(),
                "{context}: archive directory of {b}"
            );
        }
        Op::Restore => assert!(succeeded(d, JobKind::Restore), "{context}"),
        Op::RestoreDatabase => assert!(databases.contains("alice_copy"), "{context}"),
        Op::FileCopy => assert!(
            cfg.home_base
                .join(TENANT)
                .join("copy/public_html/index.php")
                .is_file(),
            "{context}: {:?}",
            d.ctx.store.list_file_jobs().unwrap()
        ),
        Op::Cascade => {
            assert!(tenant.is_none(), "{context}: record left behind");
            assert!(tenant_accounts(w).is_empty(), "{context}: account left");
            assert!(databases.is_empty(), "{context}: databases left");
            assert!(!keys_file.exists(), "{context}: keys file left");
            assert!(
                d.dns.list_zones("").await.unwrap_or_default().is_empty(),
                "{context}: zones left"
            );
            assert!(
                d.ctx.store.list_vhosts().unwrap().is_empty(),
                "{context}: sites left"
            );
        }
    }
}

/// Every temporary file the engine writes is a dot-file named
/// `.oxpanel-…`; none may survive anywhere the engine writes.
fn assert_no_temporaries(dir: &Path, context: &str) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        assert!(
            !name.starts_with(".oxpanel-"),
            "{context}: temporary file {name} left in {}",
            dir.display()
        );
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            assert_no_temporaries(&e.path(), context);
        }
    }
}

/// What `systemctl enable`/`disable` of a timer does on a real host: the
/// `timers.target.wants` link, decided by the last such call for the timer
/// (the fake OS only records the command).
fn emulate_timer_links(w: &World) {
    let wants = w.config.systemd_unit_dir.join("timers.target.wants");
    let mut last: std::collections::BTreeMap<String, bool> = std::collections::BTreeMap::new();
    for call in w
        .chaos
        .fake
        .calls_to(oxpanel_daemon::system::bin::SYSTEMCTL)
    {
        let args: Vec<String> = call
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let verb = match args.first().map(String::as_str) {
            Some("enable") => true,
            Some("disable") => false,
            _ => continue,
        };
        for unit in args.iter().filter(|a| a.ends_with(".timer")) {
            last.insert(unit.clone(), verb);
        }
    }
    for (unit, enabled) in last {
        let link = wants.join(&unit);
        if enabled && w.config.systemd_unit_dir.join(&unit).exists() {
            std::fs::create_dir_all(&wants).unwrap();
            if link.symlink_metadata().is_err() {
                std::os::unix::fs::symlink(w.config.systemd_unit_dir.join(&unit), &link).unwrap();
            }
        } else if link.symlink_metadata().is_ok() {
            std::fs::remove_file(&link).unwrap();
        }
    }
}

/// What BIND does when a zone is to be signed: it creates the zone's keys
/// in the key directory the engine made for it (the fake server does not).
fn emulate_bind_keys(w: &World) {
    let Ok(rd) = std::fs::read_dir(w.config.dns.data_dir.join("keys")) else {
        return;
    };
    for e in rd.flatten() {
        let zone = e.file_name().to_string_lossy().into_owned();
        let has_key = std::fs::read_dir(e.path()).is_ok_and(|mut r| r.next().is_some());
        if e.path().is_dir() && !has_key {
            std::fs::write(
                e.path().join(format!("K{zone}.+013+29363.key")),
                format!("{zone}. 3600 IN DNSKEY 257 3 13 ojVvxeNn+jDXp4IEn3MFAEGpvWkGafaqWDICjTZhmoowSmtPAMaGnZ6u W6lcZgTCJKOfldsnn+s5IL50zkfVeA==\n"),
            )
            .unwrap();
        }
    }
}

/// Records, files, accounts, the database and DNS servers and running
/// services agree; no job is left running; no temporary file is left.
async fn assert_consistent(w: &World, d: &Daemon, context: &str) {
    emulate_timer_links(w);
    emulate_bind_keys(w);
    let drifts = d.host.reconcile().await.expect("reconcile");
    assert!(drifts.is_empty(), "{context}: reconcile found {drifts:#?}");
    // PHP pools and applications: running exactly for active tenants' sites.
    let tenants: std::collections::BTreeMap<String, bool> = d
        .ctx
        .store
        .list_tenants()
        .unwrap()
        .into_iter()
        .map(|t| (t.username, t.state == TenantState::Ready && !t.suspended))
        .collect();
    let mut expected = BTreeSet::new();
    for v in d.ctx.store.list_vhosts().unwrap() {
        if tenants.get(&v.tenant) != Some(&true) {
            continue;
        }
        if v.php {
            expected.insert(php::unit_name(&Username::parse(&v.tenant).unwrap()));
        }
        if v.app.is_some() {
            expected.insert(app::unit_name(
                &oxpanel_daemon::validate::Domain::parse(&v.domain).unwrap(),
            ));
        }
    }
    let running: BTreeSet<String> = running_units(&w.chaos.fake)
        .into_iter()
        .filter(|u| u.starts_with("oxpanel-php-") || u.starts_with("oxpanel-app-"))
        .collect();
    assert_eq!(
        running, expected,
        "{context}: running services differ from the records"
    );
    let recorded: BTreeSet<String> = tenants.keys().cloned().collect();
    let accounts = tenant_accounts(w);
    assert_eq!(
        recorded, accounts,
        "{context}: tenant records and accounts differ"
    );
    for job in d.ctx.store.list_jobs().unwrap() {
        assert_ne!(
            job.state,
            JobState::Running,
            "{context}: job {} left running",
            job.id
        );
    }
    for job in d.ctx.store.list_file_jobs().unwrap() {
        assert_ne!(
            job.state,
            JobState::Running,
            "{context}: file job {} left running",
            job.id
        );
    }
    let cfg = &w.config;
    for dir in [
        &cfg.state_dir,
        &cfg.nginx_conf_dir,
        &cfg.systemd_unit_dir,
        &cfg.php_conf_dir,
        &cfg.tls_dir,
        &cfg.acme_dir,
        &cfg.sftp_keys_dir,
        &cfg.backup_dir,
        &cfg.dns.data_dir,
        &cfg.dns.conf_dir,
    ] {
        assert_no_temporaries(dir, context);
    }
}

/// Interrupt `op` at command `k` in the given way, restart, repeat, check.
/// Returns whether command `k` existed (false = the workflow is shorter).
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
    verify(op, &w, &d, &context).await;
    assert_consistent(&w, &d, &context).await;
    run(op, &d).await.expect("idempotent replay");
    verify(op, &w, &d, &format!("{context} (replay)")).await;
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

async fn sweep_ops(ops: &[Op], selinux: bool) {
    let mut failures = Vec::new();
    let mut total = 0;
    for &op in ops {
        let n = sweep(op, selinux, &mut failures).await;
        // The backup schedule is a record only (the engine starts backups by
        // itself): no command, hence no interruption point but the write.
        assert!(
            n > 0 || op == Op::BackupSchedule,
            "{op:?} ran no command at all"
        );
        total += n;
    }
    assert!(
        failures.is_empty(),
        "{} of {total} interruption points left an inconsistent state:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The ops in groups, so that a failure names its feature and the groups
/// run in parallel.
const SFTP_TLS_QUOTA: [Op; 8] = [
    Op::SftpAddKey,
    Op::SftpRemoveKey,
    Op::SftpSetPassword,
    Op::SftpClearPassword,
    Op::CertInstall,
    Op::CertRemove,
    Op::AutoHttps,
    Op::DiskQuota,
];
const DATABASES: [Op; 5] = [
    Op::DbCreate,
    Op::DbUserAndGrant,
    Op::DbDelete,
    Op::DbTrashRestore,
    Op::DbTrashPurge,
];
const ESSENTIALS_DNS: [Op; 10] = [
    Op::TaskPut,
    Op::TaskDelete,
    Op::PhpSettingsOn,
    Op::PhpSettingsOff,
    Op::BackupSchedule,
    Op::DnsZoneCreate,
    Op::DnsZoneDelete,
    Op::DnsRecordAdd,
    Op::DnssecOn,
    Op::DnssecOff,
];
const JOBS: [Op; 5] = [
    Op::Backup,
    Op::Restore,
    Op::RestoreDatabase,
    Op::FileCopy,
    Op::Cascade,
];

#[test]
fn the_groups_cover_every_operation() {
    let grouped: BTreeSet<String> = SFTP_TLS_QUOTA
        .iter()
        .chain(&DATABASES)
        .chain(&ESSENTIALS_DNS)
        .chain(&JOBS)
        .map(|o| format!("{o:?}"))
        .collect();
    let all: BTreeSet<String> = ALL.iter().map(|o| format!("{o:?}")).collect();
    assert_eq!(grouped, all);
}

#[tokio::test]
async fn sftp_certificates_and_quotas_survive_interruption_at_every_command() {
    for selinux in [false, true] {
        sweep_ops(&SFTP_TLS_QUOTA, selinux).await;
    }
}

#[tokio::test]
async fn databases_and_the_trash_survive_interruption_at_every_command() {
    for selinux in [false, true] {
        sweep_ops(&DATABASES, selinux).await;
    }
}

#[tokio::test]
async fn tasks_php_settings_schedules_and_dns_survive_interruption_at_every_command() {
    for selinux in [false, true] {
        sweep_ops(&ESSENTIALS_DNS, selinux).await;
    }
}

#[tokio::test]
async fn jobs_survive_interruption_at_every_command() {
    for selinux in [false, true] {
        sweep_ops(&JOBS, selinux).await;
    }
}

/// The baseline: every workflow uninterrupted is consistent and verified.
#[tokio::test]
async fn uninterrupted_feature_workflows_are_consistent() {
    for op in ALL {
        for selinux in [false, true] {
            let w = world(selinux);
            let d = boot(&w).await;
            setup(op, &d).await;
            assert_consistent(&w, &d, &format!("{op:?} after setup")).await;
            run(op, &d).await.unwrap_or_else(|e| panic!("{op:?}: {e}"));
            verify(op, &w, &d, &format!("{op:?}")).await;
            assert_consistent(&w, &d, &format!("{op:?}")).await;
        }
    }
}

// Keep `Error` in use for readers grepping the error type of `run`.
const _: Option<Error> = None;
