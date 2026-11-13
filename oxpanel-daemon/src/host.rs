//! Host-level read-only operations: engine/host information and
//! reconciliation of the records against the operating system.
//!
//! Reconciliation never repairs anything. It reports where reality differs
//! from what the records say OxPanel owns, so an operator (or the panel) can
//! decide: most findings are healed by repeating the original request, and
//! orphans are deliberately left alone ("own it or leave it").

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::app;
use crate::backup;
use crate::config::Config;
use crate::ctx::Ctx;
use crate::error::Result;
use crate::fsutil;
use crate::php::{self, PoolFiles};
use crate::records::{BackupRecord, BackupState, JobState, TenantRecord, TenantState, VHostRecord};
use crate::system::{bin, HostStats};
use crate::systemd::{self, TenantUnits};
use crate::validate::{BackupId, Domain, Username};
use crate::vhost;

/// What kind of difference a [`Drift`] describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DriftKind {
    TenantIncomplete,
    TenantAccountMissing,
    TenantAccountMismatch,
    TenantHomeInvalid,
    TenantUnitDrift,
    VHostTenantMissing,
    VHostConfigDrift,
    OrphanNginxConfig,
    OrphanSliceUnit,
    PhpPoolDrift,
    OrphanPhpPool,
    AppUnitDrift,
    OrphanAppUnit,
    BackupArchiveMissing,
    BackupArchiveModified,
    OrphanBackupArchive,
    BackupIncomplete,
}

/// One difference between a record and the operating system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drift {
    pub kind: DriftKind,
    /// Tenant name, domain or file path.
    pub subject: String,
    pub detail: String,
}

impl Drift {
    fn new(kind: DriftKind, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            kind,
            subject: subject.into(),
            detail: detail.into(),
        }
    }
}

/// Which optional runtimes are installed on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Runtimes {
    pub php: bool,
    pub node: bool,
    pub python: bool,
}

/// Engine and host facts for the panel's overview.
#[derive(Debug, Clone, PartialEq)]
pub struct HostInfo {
    pub selinux: bool,
    pub dry_run: bool,
    pub tenant_count: u32,
    pub vhost_count: u32,
    pub uid_min: u32,
    pub uid_max: u32,
    pub runtimes: Runtimes,
    /// Installed Node.js version; empty if none.
    pub node_version: String,
    pub stats: HostStats,
    /// Size and free space of the file system holding backups (0 if the
    /// backup directory does not exist yet).
    pub backup_disk_total_bytes: u64,
    pub backup_disk_free_bytes: u64,
    /// Backups kept per tenant.
    pub backup_keep: u32,
}

#[derive(Debug, Clone)]
pub struct HostService {
    ctx: Ctx,
}

impl HostService {
    pub fn new(ctx: Ctx) -> Self {
        Self { ctx }
    }

    pub async fn info(&self) -> Result<HostInfo> {
        let cfg = &self.ctx.config;
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        let node_version = app::node_version(&self.ctx).await?.unwrap_or_default();
        let node_usable =
            app::major_of(&node_version).is_some_and(|major| major >= app::MIN_NODE_MAJOR);
        let backup_disk = self
            .ctx
            .sys
            .host_stats(&cfg.backup_dir)
            .await
            .unwrap_or_default();
        Ok(HostInfo {
            backup_disk_total_bytes: backup_disk.disk_total_bytes,
            backup_disk_free_bytes: backup_disk.disk_free_bytes,
            backup_keep: cfg.backup_keep,
            selinux: self.ctx.selinux,
            dry_run: cfg.dry_run,
            tenant_count: count(self.ctx.store.list_tenants()?.len()),
            vhost_count: count(self.ctx.store.list_vhosts()?.len()),
            uid_min: cfg.uid_min,
            uid_max: cfg.uid_max,
            runtimes: Runtimes {
                php: self.ctx.sys.is_installed(bin::PHP_FPM).await,
                node: node_usable,
                python: self.ctx.sys.is_installed(bin::PYTHON3).await,
            },
            node_version,
            stats: self.ctx.sys.host_stats(&cfg.home_base).await?,
        })
    }

    /// Compare every record with the OS. Holds the mutation lock so a
    /// workflow in flight is never reported as drift.
    pub async fn reconcile(&self) -> Result<Vec<Drift>> {
        let _guard = self.ctx.lock.lock().await;
        let cfg = &self.ctx.config;
        let tenants = self.ctx.store.list_tenants()?;
        let vhosts = self.ctx.store.list_vhosts()?;
        let mut out = Vec::new();

        for t in &tenants {
            self.check_tenant(t, &mut out).await?;
        }
        let by_name: BTreeMap<&str, &TenantRecord> =
            tenants.iter().map(|t| (t.username.as_str(), t)).collect();
        for v in &vhosts {
            check_vhost(cfg, v, by_name.get(v.tenant.as_str()).copied(), &mut out)?;
        }

        let known_confs: BTreeSet<&Path> = vhosts.iter().map(|v| v.config_path.as_path()).collect();
        for path in fsutil::list_files_with_suffix(&cfg.nginx_conf_dir, ".conf")? {
            if !known_confs.contains(path.as_path()) {
                out.push(Drift::new(
                    DriftKind::OrphanNginxConfig,
                    path.to_string_lossy(),
                    "no virtual-host record refers to this file",
                ));
            }
        }
        let known_slices: BTreeSet<PathBuf> = tenants
            .iter()
            .map(|t| cfg.systemd_unit_dir.join(&t.slice_unit))
            .collect();
        for path in fsutil::list_files_with_suffix(&cfg.systemd_unit_dir, ".slice")? {
            let ours = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("oxpanel-tenant-"));
            if ours && !known_slices.contains(&path) {
                out.push(Drift::new(
                    DriftKind::OrphanSliceUnit,
                    path.to_string_lossy(),
                    "no tenant record refers to this unit",
                ));
            }
        }
        check_php_pools(cfg, &tenants, &vhosts, &mut out)?;
        check_apps(cfg, self.ctx.selinux, &by_name, &vhosts, &mut out)?;
        check_backups(&self.ctx, &mut out)?;
        Ok(out)
    }

    async fn check_tenant(&self, t: &TenantRecord, out: &mut Vec<Drift>) -> Result<()> {
        let subject = t.username.as_str();
        if t.state != TenantState::Ready {
            let what = match t.state {
                TenantState::Deleting => "deletion was interrupted; repeat DeleteTenant",
                _ => "provisioning was interrupted; repeat CreateTenant",
            };
            out.push(Drift::new(DriftKind::TenantIncomplete, subject, what));
            return Ok(());
        }
        match self.ctx.sys.user_by_name(subject).await? {
            None => {
                out.push(Drift::new(
                    DriftKind::TenantAccountMissing,
                    subject,
                    "the POSIX account no longer exists",
                ));
                return Ok(());
            }
            Some(u) if (u.uid, u.gid, u.home.as_path()) != (t.uid, t.gid, t.home.as_path()) => {
                out.push(Drift::new(
                    DriftKind::TenantAccountMismatch,
                    subject,
                    format!(
                        "account is uid={} gid={} home={}, record says uid={} gid={} home={}",
                        u.uid,
                        u.gid,
                        u.home.display(),
                        t.uid,
                        t.gid,
                        t.home.display()
                    ),
                ));
            }
            Some(_) => {}
        }
        if let Some(problem) = self
            .ctx
            .sys
            .inspect_private_dir(&t.home, t.uid, t.gid)
            .await?
        {
            out.push(Drift::new(
                DriftKind::TenantHomeInvalid,
                subject,
                format!("{}: {problem}", t.home.display()),
            ));
        }
        let name = Username::parse(&t.username)?;
        let units = TenantUnits::for_tenant(&self.ctx.config.systemd_unit_dir, &name, t.uid);
        for (path, expected) in [
            (
                &units.slice_unit,
                systemd::render_slice_unit(&name, &t.limits),
            ),
            (
                &units.user_slice_dropin,
                systemd::render_user_slice_dropin(&name, &t.limits),
            ),
        ] {
            if let Some(problem) = compare_file(path, &expected)? {
                out.push(Drift::new(
                    DriftKind::TenantUnitDrift,
                    subject,
                    format!("{} {problem}", path.display()),
                ));
            }
        }
        Ok(())
    }
}

fn check_vhost(
    cfg: &Config,
    v: &VHostRecord,
    tenant: Option<&TenantRecord>,
    out: &mut Vec<Drift>,
) -> Result<()> {
    let Some(tenant) = tenant else {
        out.push(Drift::new(
            DriftKind::VHostTenantMissing,
            v.domain.as_str(),
            format!("tenant '{}' has no record", v.tenant),
        ));
        return Ok(());
    };
    let expected = vhost::render_vhost(cfg, tenant, v)?;
    if let Some(problem) = compare_file(&v.config_path, &expected)? {
        out.push(Drift::new(
            DriftKind::VHostConfigDrift,
            v.domain.as_str(),
            format!("{} {problem}", v.config_path.display()),
        ));
    }
    Ok(())
}

/// PHP-FPM pools: one per ready tenant with a PHP-enabled virtual host.
fn check_php_pools(
    cfg: &Config,
    tenants: &[TenantRecord],
    vhosts: &[VHostRecord],
    out: &mut Vec<Drift>,
) -> Result<()> {
    let mut known_pool_files: BTreeSet<PathBuf> = BTreeSet::new();
    for t in tenants.iter().filter(|t| {
        t.state == TenantState::Ready && vhosts.iter().any(|v| v.php && v.tenant == t.username)
    }) {
        let name = Username::parse(&t.username)?;
        let files = PoolFiles::for_tenant(&cfg.php_conf_dir, &cfg.systemd_unit_dir, &name);
        for (path, expected) in [
            (&files.conf, php::render_pool_conf(t, &name, &cfg.web_user)?),
            (&files.unit, php::render_unit(t, &name, &files.conf)?),
        ] {
            if let Some(problem) = compare_file(path, &expected)? {
                out.push(Drift::new(
                    DriftKind::PhpPoolDrift,
                    t.username.as_str(),
                    format!("{} {problem}", path.display()),
                ));
            }
        }
        known_pool_files.insert(files.conf);
        known_pool_files.insert(files.unit);
    }

    let mut pool_files = fsutil::list_files_with_suffix(&cfg.php_conf_dir, ".conf")?;
    pool_files.extend(
        fsutil::list_files_with_suffix(&cfg.systemd_unit_dir, ".service")?
            .into_iter()
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("oxpanel-php-"))
            }),
    );
    for path in pool_files {
        if !known_pool_files.contains(&path) {
            out.push(Drift::new(
                DriftKind::OrphanPhpPool,
                path.to_string_lossy(),
                "no PHP-enabled virtual host accounts for this file",
            ));
        }
    }
    Ok(())
}

/// Applications: one unit per virtual host that runs one.
fn check_apps(
    cfg: &Config,
    selinux: bool,
    by_name: &BTreeMap<&str, &TenantRecord>,
    vhosts: &[VHostRecord],
    out: &mut Vec<Drift>,
) -> Result<()> {
    let mut known_app_units: BTreeSet<PathBuf> = BTreeSet::new();
    for v in vhosts.iter().filter(|v| v.app.is_some()) {
        let (Some(t), Some(a)) = (by_name.get(v.tenant.as_str()), v.app.as_ref()) else {
            continue; // already reported as a virtual host without a tenant
        };
        let domain = Domain::parse(&v.domain)?;
        let path = app::unit_path(&cfg.systemd_unit_dir, &domain);
        let expected = app::render_unit(t, &domain, a, &cfg.web_user, selinux)?;
        if let Some(problem) = compare_file(&path, &expected)? {
            out.push(Drift::new(
                DriftKind::AppUnitDrift,
                v.domain.as_str(),
                format!("{} {problem}", path.display()),
            ));
        }
        known_app_units.insert(path);
    }
    for path in fsutil::list_files_with_suffix(&cfg.systemd_unit_dir, ".service")? {
        let ours = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("oxpanel-app-"));
        if ours && !known_app_units.contains(&path) {
            out.push(Drift::new(
                DriftKind::OrphanAppUnit,
                path.to_string_lossy(),
                "no virtual host accounts for this unit",
            ));
        }
    }

    Ok(())
}

/// Backups: every record has its directory, manifest and members (at their
/// recorded sizes — checksums are verified when a backup is restored, not on
/// every reconciliation), and every directory in the store has a record.
fn check_backups(ctx: &Ctx, out: &mut Vec<Drift>) -> Result<()> {
    let backup_dir = &ctx.config.backup_dir;
    let backups = ctx.store.list_backups()?;
    let jobs = ctx.store.list_jobs()?;
    let in_flight: BTreeSet<&str> = jobs
        .iter()
        .filter(|j| j.state == JobState::Running)
        .map(|j| j.backup_id.as_str())
        .collect();
    let mut known: BTreeSet<PathBuf> = BTreeSet::new();
    for b in &backups {
        let dir = backup::backup_path(
            backup_dir,
            &Username::parse_field(&b.tenant, "tenant")?,
            &BackupId::parse(&b.id)?,
        );
        known.insert(dir.clone());
        if b.state != BackupState::Ready {
            if !in_flight.contains(b.id.as_str()) {
                out.push(Drift::new(
                    DriftKind::BackupIncomplete,
                    b.id.as_str(),
                    format!(
                        "backup of tenant '{}' was never completed and no job is writing it; delete it",
                        b.tenant
                    ),
                ));
            }
            continue;
        }
        check_backup_files(b, &dir, out)?;
    }
    for j in jobs.iter().filter(|j| j.state == JobState::Running) {
        if !backups.iter().any(|b| b.id == j.backup_id) {
            out.push(Drift::new(
                DriftKind::BackupIncomplete,
                j.id.as_str(),
                format!(
                    "job is recorded as running for tenant '{}' but backup {} has no record",
                    j.tenant, j.backup_id
                ),
            ));
        }
    }
    for tenant in fsutil::list_dirs(backup_dir)? {
        let tenant_dir = backup_dir.join(&tenant);
        for id in fsutil::list_dirs(&tenant_dir)? {
            let dir = tenant_dir.join(&id);
            if !known.contains(&dir) {
                out.push(Drift::new(
                    DriftKind::OrphanBackupArchive,
                    dir.to_string_lossy(),
                    "no backup record refers to this directory",
                ));
            }
        }
    }
    Ok(())
}

/// The files of one sealed backup against its record.
fn check_backup_files(b: &BackupRecord, dir: &Path, out: &mut Vec<Drift>) -> Result<()> {
    let subject = b.id.as_str();
    if !dir.is_dir() {
        out.push(Drift::new(
            DriftKind::BackupArchiveMissing,
            subject,
            format!("{} is missing", dir.display()),
        ));
        return Ok(());
    }
    let manifest = dir.join(backup::MANIFEST);
    match fsutil::read_optional(&manifest)? {
        None => out.push(Drift::new(
            DriftKind::BackupArchiveMissing,
            subject,
            format!("{} is missing", manifest.display()),
        )),
        Some(bytes) if bytes != backup::render_manifest(b)? => out.push(Drift::new(
            DriftKind::BackupArchiveModified,
            subject,
            format!("{} differs from the record", manifest.display()),
        )),
        Some(_) => {}
    }
    for m in &b.members {
        let path = dir.join(&m.name);
        match std::fs::symlink_metadata(&path) {
            Ok(md) if md.is_file() && md.len() == m.size_bytes => {}
            Ok(md) => out.push(Drift::new(
                DriftKind::BackupArchiveModified,
                subject,
                format!(
                    "{} is {} bytes, the record says {}",
                    path.display(),
                    md.len(),
                    m.size_bytes
                ),
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => out.push(Drift::new(
                DriftKind::BackupArchiveMissing,
                subject,
                format!("{} is missing", path.display()),
            )),
            Err(e) => return Err(crate::Error::io("lstat", &path, e)),
        }
    }
    Ok(())
}

/// `None` when the file holds exactly `expected`.
fn compare_file(path: &Path, expected: &str) -> Result<Option<&'static str>> {
    Ok(match fsutil::read_optional(path)? {
        None => Some("is missing"),
        Some(bytes) if bytes != expected.as_bytes() => Some("differs from the record"),
        Some(_) => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::system::{bin, FakeSystem, System as _};
    use crate::tenant::TenantService;
    use crate::validate::Limits;
    use crate::vhost::{VHostRequest, VHostService};
    use crate::Error;
    use std::sync::Arc;

    struct Harness {
        _dir: tempfile::TempDir,
        sys: Arc<FakeSystem>,
        ctx: Ctx,
        tenants: TenantService,
        vhosts: VHostService,
        host: HostService,
    }

    /// Two tenants, one site each, everything consistent.
    async fn harness() -> Harness {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let mut cfg = Config::default();
        cfg.state_dir = dir.path().join("state");
        cfg.home_base = dir.path().join("home");
        cfg.backup_dir = dir.path().join("backups");
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
            std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("{e}"));
        }
        let sys = Arc::new(FakeSystem::new());
        let ctx = Ctx::new(cfg, sys.clone(), false);
        ctx.store.init().unwrap_or_else(|e| panic!("{e}"));
        let h = Harness {
            _dir: dir,
            sys,
            tenants: TenantService::new(ctx.clone()),
            vhosts: VHostService::new(ctx.clone()),
            host: HostService::new(ctx.clone()),
            ctx,
        };
        let limits = Limits {
            cpu_weight: Some(50),
            ..Limits::default()
        };
        for (tenant, domain) in [("alice", "example.com"), ("foo-bar", "example.net")] {
            h.tenants
                .create(tenant, limits, "")
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            h.vhosts
                .configure(VHostRequest {
                    domain: domain.into(),
                    tenant: tenant.into(),
                    ..VHostRequest::default()
                })
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        }
        h.sys.clear_calls();
        h
    }

    fn kinds(d: &[Drift]) -> Vec<(DriftKind, &str)> {
        d.iter().map(|d| (d.kind, d.subject.as_str())).collect()
    }

    #[tokio::test]
    async fn a_consistent_host_has_no_drift_and_reconcile_runs_nothing() -> Result<()> {
        let h = harness().await;
        assert_eq!(h.host.reconcile().await?, vec![]);
        h.tenants.set_suspended("alice", true).await?;
        h.sys.clear_calls();
        assert_eq!(h.host.reconcile().await?, vec![], "suspension is not drift");
        assert!(h.sys.calls().is_empty(), "reconcile is read-only");
        Ok(())
    }

    #[tokio::test]
    async fn reports_account_unit_and_config_drift() -> Result<()> {
        let h = harness().await;
        let cfg = &h.ctx.config;
        // alice: unit edited by hand, site config removed.
        let slice = cfg.systemd_unit_dir.join("oxpanel-tenant-alice.slice");
        std::fs::write(&slice, "[Slice]\nCPUWeight=9999\n")
            .map_err(|e| Error::io("write", &slice, e))?;
        let conf = cfg.nginx_conf_dir.join("example.com.conf");
        std::fs::remove_file(&conf).map_err(|e| Error::io("unlink", &conf, e))?;
        // foo-bar: account deleted behind the daemon's back.
        h.sys
            .run_ok(
                crate::system::CommandSpec::new(bin::USERDEL, cfg.command_timeout).arg("foo-bar"),
            )
            .await?;
        let drifts = h.host.reconcile().await?;
        assert_eq!(
            kinds(&drifts),
            vec![
                (DriftKind::TenantUnitDrift, "alice"),
                (DriftKind::TenantAccountMissing, "foo-bar"),
                (DriftKind::VHostConfigDrift, "example.com"),
            ]
        );
        assert!(drifts
            .first()
            .is_some_and(|d| d.detail.ends_with("differs from the record")));
        assert!(drifts
            .get(2)
            .is_some_and(|d| d.detail.ends_with("is missing")));
        // Repeating the original request heals what it can.
        h.vhosts
            .configure(VHostRequest {
                domain: "example.com".into(),
                tenant: "alice".into(),
                ..VHostRequest::default()
            })
            .await?;
        h.tenants
            .update_limits(
                "alice",
                Limits {
                    cpu_weight: Some(50),
                    ..Limits::default()
                },
            )
            .await?;
        assert_eq!(
            kinds(&h.host.reconcile().await?),
            vec![(DriftKind::TenantAccountMissing, "foo-bar")]
        );
        Ok(())
    }

    #[tokio::test]
    async fn reports_home_incomplete_tenants_and_orphans() -> Result<()> {
        let h = harness().await;
        let cfg = &h.ctx.config;
        let home = cfg.home_base.join("alice");
        std::fs::remove_dir_all(&home).map_err(|e| Error::io("rm", &home, e))?;
        // Interrupted provisioning.
        h.sys.script_failure(bin::SYSTEMCTL, 1, "dbus down");
        assert!(h
            .tenants
            .create("carol", Limits::default(), "")
            .await
            .is_err());
        // Files nobody recorded; foreign files are not ours to report.
        let stray_conf = cfg.nginx_conf_dir.join("stray.example.conf");
        let stray_slice = cfg.systemd_unit_dir.join("oxpanel-tenant-ghost.slice");
        for p in [
            &stray_conf,
            &stray_slice,
            &cfg.systemd_unit_dir.join("machine.slice"),
            &cfg.nginx_conf_dir.join("README"),
        ] {
            std::fs::write(p, "x").map_err(|e| Error::io("write", p, e))?;
        }
        // A site whose tenant record vanished.
        let orphan_site = crate::records::VHostRecord {
            version: 1,
            domain: "lost.example".into(),
            tenant: "nobody".into(),
            document_root: "public_html".into(),
            aliases: vec![],
            config_path: cfg.nginx_conf_dir.join("lost.example.conf"),
            created_at_unix: 0,
            php: false,
            app: None,
        };
        h.ctx.store.save_vhost(&orphan_site)?;

        let drifts = h.host.reconcile().await?;
        let stray_conf = stray_conf.to_string_lossy().into_owned();
        let stray_slice = stray_slice.to_string_lossy().into_owned();
        assert_eq!(
            kinds(&drifts),
            vec![
                (DriftKind::TenantHomeInvalid, "alice"),
                (DriftKind::TenantIncomplete, "carol"),
                (DriftKind::VHostTenantMissing, "lost.example"),
                (DriftKind::OrphanNginxConfig, stray_conf.as_str()),
                (DriftKind::OrphanSliceUnit, stray_slice.as_str()),
            ]
        );
        assert!(
            std::path::Path::new(&stray_conf).exists(),
            "orphans are reported, never removed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn info_counts_records_and_reports_host_stats() -> Result<()> {
        let h = harness().await;
        let i = h.host.info().await?;
        assert_eq!((i.tenant_count, i.vhost_count), (2, 2));
        assert_eq!((i.uid_min, i.uid_max), (20_000, 29_999));
        assert!(!i.selinux && !i.dry_run);
        assert_eq!(i.stats.memory_total_bytes, 8 << 30);
        assert!(i.stats.disk_free_bytes <= i.stats.disk_total_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn reports_php_pool_drift_and_orphans() -> Result<()> {
        let h = harness().await;
        let cfg = &h.ctx.config;
        h.vhosts
            .configure(VHostRequest {
                domain: "example.com".into(),
                tenant: "alice".into(),
                php: true,
                ..VHostRequest::default()
            })
            .await?;
        assert_eq!(
            h.host.reconcile().await?,
            vec![],
            "a healthy pool is not drift"
        );
        assert!(h.host.info().await?.runtimes.php);

        let conf = cfg.php_conf_dir.join("alice.conf");
        std::fs::write(&conf, "[alice]\nuser = root\n")
            .map_err(|e| Error::io("write", &conf, e))?;
        let stray_conf = cfg.php_conf_dir.join("ghost.conf");
        let stray_unit = cfg.systemd_unit_dir.join("oxpanel-php-ghost.service");
        for p in [
            &stray_conf,
            &stray_unit,
            &cfg.systemd_unit_dir.join("sshd.service"),
        ] {
            std::fs::write(p, "x").map_err(|e| Error::io("write", p, e))?;
        }
        let drifts = h.host.reconcile().await?;
        let (stray_conf, stray_unit) = (
            stray_conf.to_string_lossy().into_owned(),
            stray_unit.to_string_lossy().into_owned(),
        );
        assert_eq!(
            kinds(&drifts),
            vec![
                (DriftKind::PhpPoolDrift, "alice"),
                (DriftKind::OrphanPhpPool, stray_conf.as_str()),
                (DriftKind::OrphanPhpPool, stray_unit.as_str()),
            ]
        );
        // Repeating the request rewrites the pool.
        h.vhosts
            .configure(VHostRequest {
                domain: "example.com".into(),
                tenant: "alice".into(),
                php: true,
                ..VHostRequest::default()
            })
            .await?;
        assert_eq!(
            h.host.reconcile().await?.len(),
            2,
            "only the orphans remain"
        );
        h.sys.set_missing(bin::PHP_FPM);
        assert!(!h.host.info().await?.runtimes.php);
        Ok(())
    }

    #[tokio::test]
    async fn reports_app_unit_drift_and_orphans() -> Result<()> {
        use crate::records::AppRuntime;
        use crate::vhost::AppRequest;
        let h = harness().await;
        let cfg = &h.ctx.config;
        let request = || VHostRequest {
            domain: "example.com".into(),
            tenant: "alice".into(),
            app: Some(AppRequest {
                runtime: AppRuntime::Node,
                root: String::new(),
                entry: String::new(),
            }),
            ..VHostRequest::default()
        };
        h.vhosts.configure(request()).await?;
        assert_eq!(
            h.host.reconcile().await?,
            vec![],
            "a healthy application is not drift"
        );
        let info = h.host.info().await?;
        assert!(info.runtimes.node && info.runtimes.python);

        let unit = cfg.systemd_unit_dir.join("oxpanel-app-example.com.service");
        let mut edited = std::fs::read_to_string(&unit).map_err(|e| Error::io("read", &unit, e))?;
        edited = edited.replace("User=alice", "User=root");
        std::fs::write(&unit, edited).map_err(|e| Error::io("write", &unit, e))?;
        let stray = cfg
            .systemd_unit_dir
            .join("oxpanel-app-ghost.example.service");
        std::fs::write(&stray, "x").map_err(|e| Error::io("write", &stray, e))?;
        let stray = stray.to_string_lossy().into_owned();
        assert_eq!(
            kinds(&h.host.reconcile().await?),
            vec![
                (DriftKind::AppUnitDrift, "example.com"),
                (DriftKind::OrphanAppUnit, stray.as_str()),
            ]
        );
        h.vhosts.configure(request()).await?;
        assert_eq!(
            kinds(&h.host.reconcile().await?),
            vec![(DriftKind::OrphanAppUnit, stray.as_str())],
            "repeating the request rewrites the unit"
        );
        Ok(())
    }

    #[tokio::test]
    async fn reports_backup_drift_and_orphans() -> Result<()> {
        use crate::backup::BackupService;
        use crate::validate::JobId;
        let h = harness().await;
        let cfg = &h.ctx.config;
        let backups = BackupService::new(h.ctx.clone())
            .with_poll_interval(std::time::Duration::from_secs(3600));
        let (job, _) = backups.create("alice").await?;
        assert_eq!(
            h.host.reconcile().await?,
            vec![],
            "a backup in flight is not drift"
        );
        assert!(backups.step(&JobId::parse(&job.id)?).await?);
        assert_eq!(
            h.host.reconcile().await?,
            vec![],
            "a sealed backup is not drift"
        );
        let info = h.host.info().await?;
        assert_eq!(info.backup_keep, 7);
        assert!(info.backup_disk_free_bytes > 0);

        // The archive grew behind the daemon's back; a member disappeared.
        let dir = cfg.backup_dir.join("alice").join(&job.backup_id);
        let archive = dir.join("home.tar.gz");
        let mut grown = std::fs::read(&archive).map_err(|e| Error::io("read", &archive, e))?;
        grown.extend_from_slice(b"appended");
        std::fs::write(&archive, grown).map_err(|e| Error::io("write", &archive, e))?;
        let records = dir.join("records.json");
        std::fs::remove_file(&records).map_err(|e| Error::io("rm", &records, e))?;
        // A backup whose job record vanished while it was being written.
        let (lost, _) = backups.create("foo-bar").await?;
        h.ctx.store.delete_job(&JobId::parse(&lost.id)?)?;
        // Directories nobody recorded.
        let stray_a = cfg.backup_dir.join("alice").join("b0000000000001");
        let stray_b = cfg.backup_dir.join("ghost").join("b0000000000002");
        for d in [&stray_a, &stray_b] {
            std::fs::create_dir_all(d).map_err(|e| Error::io("mkdir", d, e))?;
        }
        let (stray_a, stray_b) = (
            stray_a.to_string_lossy().into_owned(),
            stray_b.to_string_lossy().into_owned(),
        );
        let drifts = h.host.reconcile().await?;
        assert_eq!(
            kinds(&drifts),
            vec![
                (DriftKind::BackupArchiveModified, job.backup_id.as_str()),
                (DriftKind::BackupArchiveMissing, job.backup_id.as_str()),
                (DriftKind::BackupIncomplete, lost.backup_id.as_str()),
                (DriftKind::OrphanBackupArchive, stray_a.as_str()),
                (DriftKind::OrphanBackupArchive, stray_b.as_str()),
            ]
        );
        // Deleting through the API heals what belongs to records; orphans
        // are reported, never removed.
        assert!(backups.delete("alice", &job.backup_id).await?);
        assert!(backups.delete("foo-bar", &lost.backup_id).await?);
        assert_eq!(
            kinds(&h.host.reconcile().await?),
            vec![
                (DriftKind::OrphanBackupArchive, stray_a.as_str()),
                (DriftKind::OrphanBackupArchive, stray_b.as_str()),
            ]
        );
        assert!(std::path::Path::new(&stray_a).is_dir());
        Ok(())
    }

    #[tokio::test]
    async fn info_reports_node_version_and_usability() -> Result<()> {
        let h = harness().await;
        let i = h.host.info().await?;
        assert!(i.runtimes.node);
        assert_eq!(i.node_version, "22.11.0");
        h.sys.set_node_version("v16.20.2");
        let i = h.host.info().await?;
        assert!(!i.runtimes.node, "installed but too old is not available");
        assert_eq!(i.node_version, "16.20.2");
        h.sys.set_missing(bin::NODE);
        let i = h.host.info().await?;
        assert!(!i.runtimes.node);
        assert_eq!(i.node_version, "");
        Ok(())
    }
}
