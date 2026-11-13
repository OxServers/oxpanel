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
    TlsCertificateDrift,
    OrphanTlsFile,
    OrphanAutoHttpsState,
    SftpAccessDrift,
    OrphanSftpAccess,
    SshdConfigDrift,
    DiskQuotaDrift,
    DatabaseMissing,
    DatabaseUserMissing,
    DatabasePrivilegeDrift,
    OrphanDatabaseObject,
    BackupArchiveMissing,
    BackupArchiveModified,
    OrphanBackupArchive,
    BackupIncomplete,
    DatabaseTrashDrift,
    OrphanDatabaseTrash,
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
    pub(crate) fn new(
        kind: DriftKind,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
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

/// What the host offers for HTTPS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSupport {
    /// OpenSSL is installed: certificates can be installed.
    pub available: bool,
    /// The ACME client and its directories are in place.
    pub acme: bool,
    pub acme_directory_url: String,
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
    /// Days a deleted database stays in the trash.
    pub db_trash_days: u32,
    /// Per database engine: availability, version, databases and users.
    pub databases: Vec<crate::db::EngineFacts>,
    pub tls: TlsSupport,
    pub facilities: Facilities,
}

/// What tenants can be given on this host beyond web hosting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facilities {
    /// sshd is installed and confines tenants (see [`crate::sftp`]).
    pub sftp: bool,
    /// Tenants may be given SFTP passwords (`OXPANEL_SFTP_PASSWORDS`).
    pub sftp_passwords: bool,
    /// Disk limits are enforced by the kernel (see [`crate::quota`]).
    pub disk_quota: bool,
    /// What was found about quotas, and what to do if they are unavailable.
    pub disk_quota_detail: String,
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
        let quota = crate::quota::availability(&self.ctx).await?;
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
            db_trash_days: cfg.db_trash_days,
            selinux: self.ctx.selinux,
            dry_run: cfg.dry_run,
            tenant_count: count(self.ctx.store.count_tenants()?),
            vhost_count: count(self.ctx.store.count_vhosts()?),
            uid_min: cfg.uid_min,
            uid_max: cfg.uid_max,
            runtimes: Runtimes {
                php: self.ctx.sys.is_installed(bin::PHP_FPM).await,
                node: node_usable,
                python: self.ctx.sys.is_installed(bin::PYTHON3).await,
            },
            node_version,
            stats: self.ctx.sys.host_stats(&cfg.home_base).await?,
            tls: TlsSupport {
                available: self.ctx.sys.is_installed(bin::OPENSSL).await,
                acme: crate::acme::unavailable_reason(&self.ctx).await?.is_none(),
                acme_directory_url: cfg.acme_directory_url.clone(),
            },
            facilities: Facilities {
                sftp: crate::sftp::is_available(&self.ctx).await?,
                sftp_passwords: cfg.sftp_passwords == crate::config::SftpPasswords::Allowed,
                disk_quota: quota.available,
                disk_quota_detail: quota.detail,
            },
            databases: crate::db::facts(&self.ctx).await?,
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
        check_tls(cfg, &vhosts, &mut out)?;
        check_sftp(&self.ctx, &tenants, &mut out).await?;
        check_quotas(&self.ctx, &tenants, &mut out).await?;
        out.extend(crate::db::drifts(&self.ctx, &tenants).await?);
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

/// Certificates: the chain file must be what the record holds, the key must
/// exist and be closed to everyone but root, and nothing else may live in
/// the certificate directory. (Whether the key still belongs to the
/// certificate is not checked here: that needs OpenSSL, and reconciliation
/// runs nothing.)
fn check_tls(cfg: &Config, vhosts: &[VHostRecord], out: &mut Vec<Drift>) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mut known: BTreeSet<PathBuf> = BTreeSet::new();
    for v in vhosts {
        let domain = Domain::parse(&v.domain)?;
        // The key of a certificate request in flight (or one that was interrupted).
        known.insert(crate::tls::pending_key_path(&cfg.tls_dir, &domain));
        let Some(tls) = &v.tls else {
            continue;
        };
        let cert = crate::tls::cert_path(&cfg.tls_dir, &domain);
        let key = crate::tls::key_path(&cfg.tls_dir, &domain);
        if let Some(problem) = compare_file(&cert, &tls.chain_pem)? {
            out.push(Drift::new(
                DriftKind::TlsCertificateDrift,
                v.domain.as_str(),
                format!("{} {problem}", cert.display()),
            ));
        }
        let key_problem = match std::fs::symlink_metadata(&key) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some("is missing"),
            Err(e) => return Err(crate::Error::io("lstat", &key, e)),
            Ok(md) if !md.is_file() => Some("is not a regular file"),
            // The daemon's own uid: root in production.
            Ok(md) if md.mode() & 0o077 != 0 || md.uid() != nix::unistd::geteuid().as_raw() => {
                Some("is not a root-only file (expected mode 0600, owner root)")
            }
            Ok(_) => None,
        };
        if let Some(problem) = key_problem {
            out.push(Drift::new(
                DriftKind::TlsCertificateDrift,
                v.domain.as_str(),
                format!("{} {problem}", key.display()),
            ));
        }
        known.insert(cert);
        known.insert(key);
    }
    let sites: BTreeSet<PathBuf> = vhosts
        .iter()
        .filter_map(|v| Domain::parse(&v.domain).ok())
        .map(|d| crate::auto_https::state_path(cfg, &d))
        .collect();
    for path in crate::auto_https::state_files(cfg)? {
        if !sites.contains(&path) {
            out.push(Drift::new(
                DriftKind::OrphanAutoHttpsState,
                path.to_string_lossy(),
                "Automatic HTTPS state of a virtual host that does not exist",
            ));
        }
    }
    for path in fsutil::list_files_with_suffix(&cfg.tls_dir, "")? {
        if !known.contains(&path) {
            out.push(Drift::new(
                DriftKind::OrphanTlsFile,
                path.to_string_lossy(),
                "no virtual host accounts for this file",
            ));
        }
    }
    Ok(())
}

/// SFTP: the sshd drop-in, every tenant's membership of the tenant group,
/// the keys file and mount unit of every tenant with keys, and anything in
/// OxPanel's SFTP locations that no tenant accounts for. File checks only:
/// whether a mount is currently active is not looked at.
async fn check_sftp(ctx: &Ctx, tenants: &[TenantRecord], out: &mut Vec<Drift>) -> Result<()> {
    use crate::sftp::{self, SftpPaths};
    let cfg = &ctx.config;
    if ctx.sys.is_installed(bin::SSHD).await {
        let path = &cfg.sshd_dropin_file;
        if let Some(problem) = compare_file(path, &sftp::render_sshd_dropin(cfg)?)? {
            out.push(Drift::new(
                DriftKind::SshdConfigDrift,
                path.to_string_lossy(),
                format!("{problem}; tenants are not confined to SFTP until the daemon restarts or a key is added"),
            ));
        }
    }
    let group = ctx.sys.group_by_name(&cfg.tenant_group).await?;
    let mut known: BTreeSet<PathBuf> = BTreeSet::new();
    for t in tenants.iter().filter(|t| t.state == TenantState::Ready) {
        let subject = t.username.as_str();
        // A missing account is reported as such already.
        let exists = ctx.sys.user_by_name(subject).await?.is_some();
        let member = match group {
            Some(gid) => ctx.sys.groups_of(subject, t.gid).await?.contains(&gid),
            None => false,
        };
        if exists && !member {
            out.push(Drift::new(
                DriftKind::SftpAccessDrift,
                subject,
                format!("the account is not in group '{}'", cfg.tenant_group),
            ));
        }
        if exists {
            check_password(ctx, t, out).await?;
        }
        if !sftp::has_access(t) {
            continue;
        }
        let paths = SftpPaths::for_tenant(cfg, t)?;
        let mut expected = vec![(&paths.mount_unit, Some(sftp::render_mount_unit(t, &paths)?))];
        // While suspended (or without keys) there must be no keys file at all.
        let keys = (!t.suspended && !t.sftp_keys.is_empty())
            .then(|| sftp::render_keys_file(t))
            .transpose()?;
        expected.push((&paths.keys_file, keys));
        for (path, contents) in expected {
            let problem = match contents {
                Some(c) => compare_file(path, &c)?,
                None => path
                    .exists()
                    .then_some("exists although the tenant is suspended or has no keys"),
            };
            if let Some(problem) = problem {
                out.push(Drift::new(
                    DriftKind::SftpAccessDrift,
                    subject,
                    format!("{} {problem}", path.display()),
                ));
            }
        }
        known.insert(paths.keys_file.clone());
        known.insert(paths.mount_unit.clone());
        known.insert(paths.chroot.clone());
    }
    let mut ours: Vec<PathBuf> = Vec::new();
    for dir in [&cfg.sftp_keys_dir, &cfg.sftp_chroot_dir()] {
        ours.extend(fsutil::list_entry_names(dir)?.iter().map(|n| dir.join(n)));
    }
    let chroot_units = systemd::mount_unit_name(&cfg.sftp_chroot_dir())?;
    let prefix = format!("{}-", chroot_units.trim_end_matches(".mount"));
    ours.extend(
        fsutil::list_files_with_suffix(&cfg.systemd_unit_dir, ".mount")?
            .into_iter()
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(&prefix))
            }),
    );
    for path in ours {
        if !known.contains(&path) {
            out.push(Drift::new(
                DriftKind::OrphanSftpAccess,
                path.to_string_lossy(),
                "no tenant with SFTP access accounts for this (a mount kept for sessions that were open when the last credential was removed goes at the daemon's next start)",
            ));
        }
    }
    Ok(())
}

/// The password side of SFTP access: membership of the password group and
/// the state of the shadow entry must match the record. Looks only at what
/// kind of entry it is, never at the hash.
async fn check_password(ctx: &Ctx, t: &TenantRecord, out: &mut Vec<Drift>) -> Result<()> {
    use crate::system::PasswordState;
    let cfg = &ctx.config;
    let subject = t.username.as_str();
    if let Some(gid) = ctx.sys.group_by_name(&cfg.sftp_password_group).await? {
        let member = ctx.sys.groups_of(subject, t.gid).await?.contains(&gid);
        if member != t.sftp_password {
            let detail = if member {
                format!("the account is in group '{}' (password login) but the record has no SFTP password", cfg.sftp_password_group)
            } else {
                format!(
                    "the record has an SFTP password but the account is not in group '{}'",
                    cfg.sftp_password_group
                )
            };
            out.push(Drift::new(DriftKind::SftpAccessDrift, subject, detail));
        }
    }
    let state = ctx.sys.password_state(subject).await?;
    let expected = match (t.sftp_password, t.suspended) {
        (false, _) => PasswordState::NoPassword,
        (true, false) => PasswordState::Usable,
        (true, true) => PasswordState::Locked,
    };
    if state != expected && state != PasswordState::Missing {
        let found = match state {
            PasswordState::Empty => "an EMPTY password (any password logs in)",
            PasswordState::Usable => "a usable password",
            PasswordState::Locked => "a locked password",
            PasswordState::NoPassword | PasswordState::Missing => "no password",
        };
        let wanted = match expected {
            PasswordState::Usable => "a usable SFTP password",
            PasswordState::Locked => "a locked SFTP password (suspended)",
            _ => "no SFTP password",
        };
        let fix = if t.sftp_password && state == PasswordState::NoPassword {
            "set the password again"
        } else {
            "repeat SetSftpPassword or ClearSftpPassword, or restart the daemon"
        };
        out.push(Drift::new(
            DriftKind::SftpAccessDrift,
            subject,
            format!("the account has {found}, the record says {wanted} ({fix})"),
        ));
    }
    if t.sftp_password && cfg.sftp_passwords == crate::config::SftpPasswords::Forbidden {
        out.push(Drift::new(
            DriftKind::SftpAccessDrift,
            subject,
            "the record has an SFTP password, but this host forbids them (OXPANEL_SFTP_PASSWORDS=false) so sshd does not accept it; ClearSftpPassword",
        ));
    }
    Ok(())
}

/// Disk quotas: the kernel's limits for every ready tenant equal the record
/// (including "none"), and a recorded limit is still enforceable at all.
async fn check_quotas(ctx: &Ctx, tenants: &[TenantRecord], out: &mut Vec<Drift>) -> Result<()> {
    use crate::quota;
    let ready = || tenants.iter().filter(|t| t.state == TenantState::Ready);
    let Some(table) = quota::report_all(ctx).await? else {
        let detail = quota::availability(ctx).await?.detail;
        for t in ready().filter(|t| t.limits.has_disk_quota()) {
            out.push(Drift::new(
                DriftKind::DiskQuotaDrift,
                t.username.as_str(),
                format!("the record has a disk limit, but it is not enforced: {detail}"),
            ));
        }
        return Ok(());
    };
    for t in ready() {
        let row = table.get(&t.uid).copied().unwrap_or_default();
        let (bytes, inodes) = quota::expected_limits(&t.limits);
        if (row.limit_bytes, row.inodes_limit) != (bytes, inodes) {
            out.push(Drift::new(
                DriftKind::DiskQuotaDrift,
                t.username.as_str(),
                format!(
                    "the kernel limits uid {} to {} bytes / {} inodes, the record says {bytes} / {inodes} (0 = none); repeat UpdateTenantLimits",
                    t.uid, row.limit_bytes, row.inodes_limit
                ),
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
    // A tenant deletion without a final backup names no backup.
    for j in jobs
        .iter()
        .filter(|j| j.state == JobState::Running && !j.backup_id.is_empty())
    {
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
        crate::config::sandbox_feature_paths(&mut cfg, dir.path());
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
        cfg.sftp_keys_dir = dir.path().join("sftp-keys");
        cfg.sshd_dropin_file = dir.path().join("sshd_config.d").join("60-oxpanel.conf");
        cfg.socket_path = dir.path().join("run").join("oxpanel.sock");
        for d in [
            &cfg.home_base,
            &cfg.systemd_unit_dir,
            &dir.path().join("nginx").join("conf.d"),
            &dir.path().join("sshd_config.d"),
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
        // As the daemon does at start.
        crate::sftp::converge_all(&h.ctx)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
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

    /// An account that exists but is not the one the record describes (here:
    /// a different home) is reported, not repaired.
    #[tokio::test]
    async fn reports_an_account_that_no_longer_matches_its_record() -> Result<()> {
        let h = harness().await;
        let cfg = &h.ctx.config;
        let mut rec = h
            .ctx
            .store
            .load_tenant(&Username::parse("alice")?)?
            .ok_or_else(|| Error::Internal("no record".into()))?;
        rec.home = cfg.home_base.join("somewhere-else");
        h.ctx.store.save_tenant(&rec)?;
        let drifts = h.host.reconcile().await?;
        let found: Vec<_> = drifts
            .iter()
            .filter(|d| d.kind == DriftKind::TenantAccountMismatch)
            .collect();
        assert_eq!(found.len(), 1, "{drifts:?}");
        assert!(found
            .first()
            .is_some_and(|d| d.subject == "alice" && d.detail.contains("somewhere-else")));
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
            redirect_https: false,
            hsts: false,
            tls: None,
            auto_https: crate::records::AutoHttpsChoice::On,
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
        let (job, _) = backups.create("alice", 0, 0).await?;
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
        let (lost, _) = backups.create("foo-bar", 0, 0).await?;
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

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGNQ8nctDOzq4yQ8Bix4hfkkqCQw0kkYzl6hc7hg7rRo";

    #[tokio::test]
    async fn reports_sftp_drift_and_orphans() -> Result<()> {
        use crate::sftp::{SftpPaths, SftpService};
        let h = harness().await;
        let cfg = &h.ctx.config;
        let sftp = SftpService::new(h.ctx.clone());
        sftp.add_key("alice", KEY, "").await?;
        assert_eq!(
            h.host.reconcile().await?,
            vec![],
            "fresh access is not drift"
        );
        assert!(h.host.info().await?.facilities.sftp);
        h.tenants.set_suspended("alice", true).await?;
        assert_eq!(
            h.host.reconcile().await?,
            vec![],
            "suspended: no keys file, no drift"
        );
        h.tenants.set_suspended("alice", false).await?;

        let alice = h.tenants.get("alice").await?;
        let paths = SftpPaths::for_tenant(cfg, &alice)?;
        std::fs::write(&paths.keys_file, "ssh-ed25519 AAAA intruder\n")
            .map_err(|e| Error::io("write", &paths.keys_file, e))?;
        std::fs::remove_file(&paths.mount_unit)
            .map_err(|e| Error::io("unlink", &paths.mount_unit, e))?;
        std::fs::write(&cfg.sshd_dropin_file, "# edited\n")
            .map_err(|e| Error::io("write", &cfg.sshd_dropin_file, e))?;
        let stray_keys = cfg.sftp_keys_dir.join("ghost");
        std::fs::write(&stray_keys, "x").map_err(|e| Error::io("write", &stray_keys, e))?;
        let stray_unit = cfg.systemd_unit_dir.join(crate::systemd::mount_unit_name(
            &cfg.sftp_chroot_dir()
                .join("ghost")
                .join("home")
                .join("ghost"),
        )?);
        std::fs::write(&stray_unit, "x").map_err(|e| Error::io("write", &stray_unit, e))?;
        // Not ours: another mount unit on the host.
        let foreign = cfg.systemd_unit_dir.join("srv-data.mount");
        std::fs::write(&foreign, "x").map_err(|e| Error::io("write", &foreign, e))?;
        h.sys
            .run_ok(
                crate::system::CommandSpec::new(bin::GPASSWD, cfg.command_timeout).args([
                    "--delete",
                    "foo-bar",
                    "oxpanel-tenants",
                ]),
            )
            .await?;
        h.sys.clear_calls();
        let dropin = cfg.sshd_dropin_file.to_string_lossy().into_owned();
        let (stray_keys, stray_unit) = (
            stray_keys.to_string_lossy().into_owned(),
            stray_unit.to_string_lossy().into_owned(),
        );
        assert_eq!(
            kinds(&h.host.reconcile().await?),
            vec![
                (DriftKind::SshdConfigDrift, dropin.as_str()),
                (DriftKind::SftpAccessDrift, "alice"),
                (DriftKind::SftpAccessDrift, "alice"),
                (DriftKind::SftpAccessDrift, "foo-bar"),
                (DriftKind::OrphanSftpAccess, stray_keys.as_str()),
                (DriftKind::OrphanSftpAccess, stray_unit.as_str()),
            ]
        );
        assert!(h.sys.calls().is_empty(), "reconcile is read-only");
        assert!(!h.host.info().await?.facilities.sftp, "edited drop-in");
        // Repeating the request (or a restart) heals all but the orphans.
        sftp.add_key("alice", KEY, "").await?;
        crate::sftp::converge_all(&h.ctx).await?;
        assert_eq!(
            h.host.reconcile().await?.len(),
            2,
            "only the orphans remain"
        );
        Ok(())
    }

    #[tokio::test]
    async fn reports_disk_quota_drift() -> Result<()> {
        let h = harness().await;
        let disk = Limits::default()
            .with_disk(10 << 20, 0)
            .unwrap_or_else(|e| panic!("{e}"));
        h.sys.set_quota_enforced(true);
        let i = h.host.info().await?.facilities;
        assert!(i.disk_quota, "{}", i.disk_quota_detail);
        h.tenants.update_limits("alice", disk).await?;
        assert_eq!(h.host.reconcile().await?, vec![]);
        // Changed behind the daemon's back; a uid with a limit it should not have.
        h.sys.set_quota_limits(20_000, 1, 0);
        h.sys.set_quota_limits(20_001, 5, 5);
        assert_eq!(
            kinds(&h.host.reconcile().await?),
            vec![
                (DriftKind::DiskQuotaDrift, "alice"),
                (DriftKind::DiskQuotaDrift, "foo-bar"),
            ]
        );
        // The host stops enforcing quotas (e.g. booted without the option).
        h.sys.set_quota_enforced(false);
        let i = h.host.info().await?.facilities;
        assert!(!i.disk_quota && i.disk_quota_detail.contains("uquota"));
        let drifts = h.host.reconcile().await?;
        assert_eq!(kinds(&drifts), vec![(DriftKind::DiskQuotaDrift, "alice")]);
        assert!(drifts
            .first()
            .is_some_and(|d| d.detail.contains("not enforced")));
        Ok(())
    }

    #[tokio::test]
    async fn reports_password_drift_both_ways() -> Result<()> {
        use crate::sftp::SftpService;
        let h = harness().await;
        let sftp = SftpService::new(h.ctx.clone());
        sftp.set_password("alice", "correct horse battery").await?;
        assert_eq!(
            h.host.reconcile().await?,
            vec![],
            "a set password is not drift"
        );
        h.tenants.set_suspended("alice", true).await?;
        assert_eq!(
            h.host.reconcile().await?,
            vec![],
            "nor a locked one while suspended"
        );
        h.tenants.set_suspended("alice", false).await?;
        // alice's password disappears; foo-bar (none recorded) gets one, and
        // a place in the password group.
        h.sys.set_shadow_field("alice", "!!");
        h.sys.set_shadow_field("foo-bar", "$6$x$y");
        h.sys
            .run_ok(
                crate::system::CommandSpec::new(bin::GPASSWD, h.ctx.config.command_timeout).args([
                    "--add",
                    "foo-bar",
                    "oxpanel-sftp-password",
                ]),
            )
            .await?;
        h.sys.clear_calls();
        let drifts = h.host.reconcile().await?;
        assert_eq!(
            kinds(&drifts),
            vec![
                (DriftKind::SftpAccessDrift, "alice"),
                (DriftKind::SftpAccessDrift, "foo-bar"),
                (DriftKind::SftpAccessDrift, "foo-bar"),
            ]
        );
        assert!(drifts
            .iter()
            .any(|d| d.detail.contains("set the password again")));
        assert!(h.sys.calls().is_empty(), "reconcile is read-only");
        // An empty password field is always drift.
        h.sys.set_shadow_field("alice", "");
        assert!(h
            .host
            .reconcile()
            .await?
            .iter()
            .any(|d| d.subject == "alice" && d.detail.contains("EMPTY")));
        // A restart repairs what it can without a plaintext: foo-bar loses the
        // stray password and membership; alice's empty field is disabled.
        crate::sftp::converge_all(&h.ctx).await?;
        assert_eq!(
            h.sys.password_state("foo-bar").await?,
            crate::system::PasswordState::NoPassword
        );
        assert_eq!(
            h.sys.password_state("alice").await?,
            crate::system::PasswordState::NoPassword
        );
        assert_eq!(
            kinds(&h.host.reconcile().await?),
            vec![(DriftKind::SftpAccessDrift, "alice")],
            "only the lost password remains: it must be set again"
        );
        Ok(())
    }
}
