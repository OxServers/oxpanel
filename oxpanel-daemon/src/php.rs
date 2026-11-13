//! Per-tenant PHP-FPM pools.
//!
//! A tenant that enables PHP on at least one virtual host gets its own
//! PHP-FPM instance — its own master process, not a pool inside a shared
//! root-owned master:
//!
//! - the whole instance runs **as the tenant** (`User=`), so no PHP code and
//!   no FPM master ever holds root or another tenant's identity;
//! - it lives in the tenant's slice, so the tenant's memory, CPU and task
//!   limits bound PHP exactly as they bound everything else;
//! - the unit is sandboxed (`ProtectSystem=strict`, private `/tmp`, empty
//!   capability set, `NoNewPrivileges`) and may write only the tenant's home;
//! - Nginx reaches it through a UNIX socket whose ACL names the web-server
//!   account; other tenants cannot connect;
//! - `open_basedir` confines scripts to the home, and sessions and uploads go
//!   to the unit's private `/tmp`.
//!
//! The pool exists exactly as long as the tenant has a PHP-enabled virtual
//! host. Both files are rendered from the records and nothing else.

use std::path::{Path, PathBuf};

use tracing::info;

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::nginx::safe_path_str;
use crate::php_settings::PhpSettings;
use crate::records::{TenantRecord, VHostRecord};
use crate::system::{bin, CommandSpec};
use crate::systemd;
use crate::validate::{Domain, Username};

const HEADER_UNIT: &str = "# Managed by oxpanel-daemon. Manual edits will be overwritten.\n";
const HEADER_CONF: &str = "; Managed by oxpanel-daemon. Manual edits will be overwritten.\n";
const FILE_MODE: u32 = 0o644;
const DIR_MODE: u32 = 0o755;
/// systemd `RuntimeDirectory=` parent (below `/run`); one sub-directory per tenant.
const RUNTIME_SUBDIR: &str = "oxpanel-php";
/// Upper bound of concurrent PHP workers per tenant. The tenant's `TasksMax`
/// and `MemoryMax` remain the hard limits.
const MAX_CHILDREN: u32 = 8;

/// `oxpanel-php-<escaped name>.service`
pub fn unit_name(name: &Username) -> String {
    format!(
        "oxpanel-php-{}.service",
        systemd::escape_unit_component(name.as_str())
    )
}

/// The socket Nginx passes PHP requests to.
pub fn socket_path(name: &Username) -> PathBuf {
    PathBuf::from(format!("/run/{RUNTIME_SUBDIR}/{name}/php.sock"))
}

/// Paths of the two files that make up a tenant's pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolFiles {
    pub conf: PathBuf,
    pub unit: PathBuf,
}

impl PoolFiles {
    pub fn for_tenant(conf_dir: &Path, unit_dir: &Path, name: &Username) -> Self {
        Self {
            conf: conf_dir.join(format!("{name}.conf")),
            unit: unit_dir.join(unit_name(name)),
        }
    }
}

/// The socket of a site's own pool (a site with PHP settings, see
/// [`render_pool_conf_with_sites`]).
pub fn site_socket_path(name: &Username, domain: &Domain) -> PathBuf {
    PathBuf::from(format!("/run/{RUNTIME_SUBDIR}/{name}/{domain}.sock"))
}

/// A site that gets a pool of its own, with its effective settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SitePool {
    pub domain: Domain,
    pub settings: PhpSettings,
}

/// The sites of `tenant` that get a pool of their own: PHP on and settings
/// set. `pending` stands in for the stored record of its domain (a change
/// not saved yet), and is added if it has none. Settings are clamped to the
/// tenant's caps (see [`crate::php_settings::effective`]).
pub fn site_pools(
    cfg: &crate::config::Config,
    tenant: &TenantRecord,
    vhosts: &[VHostRecord],
    pending: Option<&VHostRecord>,
) -> Result<Vec<SitePool>> {
    let caps = tenant.php_limits.resolve(&cfg.essentials.php_max);
    let mut sites: Vec<&VHostRecord> = vhosts
        .iter()
        .filter(|v| v.tenant == tenant.username)
        .filter(|v| pending.is_none_or(|p| p.domain != v.domain))
        .collect();
    sites.extend(pending.filter(|p| p.tenant == tenant.username));
    let mut out: Vec<SitePool> = sites
        .into_iter()
        .filter(|v| v.php && !v.php_settings.is_empty())
        .map(|v| {
            Ok(SitePool {
                domain: Domain::parse(&v.domain)?,
                settings: crate::php_settings::effective(&v.php_settings, &caps),
            })
        })
        .collect::<Result<_>>()?;
    out.sort_by(|a, b| a.domain.as_str().cmp(b.domain.as_str()));
    Ok(out)
}

/// The FPM configuration with a pool for every site in `sites` after the
/// tenant's default pool. Each site pool repeats the default pool's
/// hardening and adds the site's settings; it has its own socket, so a
/// setting of one site never applies to another. Without sites this is
/// exactly [`render_pool_conf`].
pub fn render_pool_conf_with_sites(
    tenant: &TenantRecord,
    name: &Username,
    web_user: &str,
    sites: &[SitePool],
) -> Result<String> {
    use std::fmt::Write as _;
    let home = safe_path_str(&tenant.home)?;
    let mut out = render_pool_conf(tenant, name, web_user)?;
    for site in sites {
        let sock = site_socket_path(name, &site.domain);
        let display_errors = if site.settings.display_errors {
            "on"
        } else {
            "off"
        };
        let _ = write!(
            out,
            "\n; Site {domain}: its own pool, for its own PHP settings (SetPhpSettings).\n{}{}",
            pool_section(
                site.domain.as_str(),
                safe_path_str(&sock)?,
                web_user,
                home,
                display_errors
            ),
            crate::php_settings::pool_lines(&site.settings)?,
            domain = site.domain,
        );
    }
    Ok(out)
}

/// The FPM configuration: one `[global]` section and one pool.
pub fn render_pool_conf(tenant: &TenantRecord, name: &Username, web_user: &str) -> Result<String> {
    let home = safe_path_str(&tenant.home)?;
    let sock = socket_path(name);
    let sock = safe_path_str(&sock)?;
    Ok(format!(
        "{HEADER_CONF}[global]
daemonize = no
; The journal: stderr of a systemd service is a socket, which FPM cannot open as a file.
error_log = syslog
syslog.ident = oxpanel-php-{name}
log_level = notice

{}",
        pool_section(name.as_str(), sock, web_user, home, "off")
    ))
}

/// One pool: its socket, process manager and the hardening every pool of
/// OxPanel carries. `section` and the paths are validated names.
fn pool_section(
    section: &str,
    sock: &str,
    web_user: &str,
    home: &str,
    display_errors: &str,
) -> String {
    format!(
        "[{section}]
listen = {sock}
; Only the web server may connect; other tenants cannot.
listen.acl_users = {web_user}
pm = ondemand
pm.max_children = {MAX_CHILDREN}
pm.process_idle_timeout = 60s
pm.max_requests = 500
catch_workers_output = yes
decorate_workers_output = no
clear_env = yes
security.limit_extensions = .php
php_admin_value[open_basedir] = {home}/:/tmp/:/usr/share/php/:/usr/share/pear/
; The unit has a private /tmp, so these are per tenant.
php_admin_value[upload_tmp_dir] = /tmp
php_admin_value[session.save_path] = /tmp
php_admin_value[sys_temp_dir] = /tmp
php_admin_flag[log_errors] = on
php_admin_flag[display_errors] = {display_errors}
php_admin_flag[allow_url_include] = off
"
    )
}

/// The service unit that runs the tenant's FPM instance.
pub fn render_unit(tenant: &TenantRecord, name: &Username, conf: &Path) -> Result<String> {
    let home = safe_path_str(&tenant.home)?;
    let conf = safe_path_str(conf)?;
    // Derived from the validated name, not copied from the record: a record
    // is a file, and its `slice_unit` string would otherwise reach the unit
    // unchecked (a line break in it would add a directive).
    let slice = systemd::slice_unit_name(name);
    let php_fpm = bin::PHP_FPM;
    Ok(format!(
        "{HEADER_UNIT}[Unit]
Description=OxPanel PHP-FPM for tenant {name}
Documentation=https://github.com/OxServers/oxpanel
After=network.target

[Service]
Type=notify
User={name}
Group={name}
Slice={slice}
ExecStart={php_fpm} --nodaemonize --fpm-config {conf}
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
RestartSec=2s
RuntimeDirectory={RUNTIME_SUBDIR}/{name}
RuntimeDirectoryMode=0711
UMask=0022

# The instance already runs unprivileged as the tenant; this narrows it further.
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ReadWritePaths={home}
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
"
    ))
}

fn systemctl(ctx: &Ctx) -> CommandSpec {
    CommandSpec::new(bin::SYSTEMCTL, ctx.config.command_timeout)
}

/// Write the pool's files and make sure the instance runs (unless the tenant
/// is suspended). Idempotent; a changed file restarts the instance.
/// The caller holds the mutation lock. Returns whether a file changed.
pub async fn ensure_pool(
    ctx: &Ctx,
    tenant: &TenantRecord,
    pending: Option<&VHostRecord>,
) -> Result<bool> {
    if !ctx.sys.is_installed(bin::PHP_FPM).await {
        return Err(Error::PhpUnavailable);
    }
    let cfg = &ctx.config;
    let name = Username::parse(&tenant.username)?;
    let files = PoolFiles::for_tenant(&cfg.php_conf_dir, &cfg.systemd_unit_dir, &name);
    let unit = unit_name(&name);
    fsutil::ensure_dir(&cfg.php_conf_dir, DIR_MODE)?;
    let sites = site_pools(cfg, tenant, &ctx.store.list_vhosts()?, pending)?;
    let conf_changed = fsutil::write_atomic(
        &files.conf,
        render_pool_conf_with_sites(tenant, &name, &cfg.web_user, &sites)?.as_bytes(),
        FILE_MODE,
    )?;
    let unit_changed = fsutil::write_atomic(
        &files.unit,
        render_unit(tenant, &name, &files.conf)?.as_bytes(),
        FILE_MODE,
    )?;
    if unit_changed {
        systemd::daemon_reload(ctx.sys.as_ref(), cfg.command_timeout).await?;
    }
    if tenant.suspended {
        return Ok(conf_changed || unit_changed);
    }
    if conf_changed || unit_changed {
        // `restart` also starts a stopped unit, and picks up either file.
        ctx.sys
            .run_ok(systemctl(ctx).args(["enable", "--"]).arg(&unit))
            .await?;
        ctx.sys
            .run_ok(systemctl(ctx).args(["restart", "--"]).arg(&unit))
            .await?;
        info!(tenant = %name, unit, "php-fpm pool (re)started");
    } else {
        ctx.sys
            .run_ok(systemctl(ctx).args(["enable", "--now", "--"]).arg(&unit))
            .await?;
    }
    Ok(conf_changed || unit_changed)
}

/// Stop the instance and remove its files. Returns whether anything existed.
pub async fn remove_pool(ctx: &Ctx, tenant: &TenantRecord) -> Result<bool> {
    let cfg = &ctx.config;
    let name = Username::parse(&tenant.username)?;
    let files = PoolFiles::for_tenant(&cfg.php_conf_dir, &cfg.systemd_unit_dir, &name);
    let had_unit = files.unit.exists();
    if had_unit {
        ctx.sys
            .run_ok(
                systemctl(ctx)
                    .args(["disable", "--now", "--"])
                    .arg(unit_name(&name)),
            )
            .await?;
    }
    let removed_unit = fsutil::remove_if_exists(&files.unit)?;
    let removed_conf = fsutil::remove_if_exists(&files.conf)?;
    if removed_unit {
        systemd::daemon_reload(ctx.sys.as_ref(), cfg.command_timeout).await?;
    }
    if removed_unit || removed_conf {
        info!(tenant = %name, "php-fpm pool removed");
    }
    Ok(removed_unit || removed_conf)
}

/// Start or stop an existing pool when its tenant is resumed or suspended.
/// `disable` as well as stop: a suspended tenant's PHP must not come back
/// after a reboot. A tenant without a pool is left alone.
pub async fn set_running(ctx: &Ctx, tenant: &TenantRecord, running: bool) -> Result<()> {
    let cfg = &ctx.config;
    let name = Username::parse(&tenant.username)?;
    let files = PoolFiles::for_tenant(&cfg.php_conf_dir, &cfg.systemd_unit_dir, &name);
    if !files.unit.exists() {
        return Ok(());
    }
    let verb = if running { "enable" } else { "disable" };
    ctx.sys
        .run_ok(
            systemctl(ctx)
                .args([verb, "--now", "--"])
                .arg(unit_name(&name)),
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{TenantState, RECORD_VERSION};

    fn tenant(name: &str) -> (TenantRecord, Username) {
        let n = Username::parse(name).unwrap_or_else(|e| panic!("{e}"));
        (
            TenantRecord {
                version: RECORD_VERSION,
                username: name.into(),
                uid: 20000,
                gid: 20000,
                home: PathBuf::from(format!("/home/{name}")),
                limits: crate::validate::Limits::default(),
                slice_unit: systemd::slice_unit_name(&n),
                created_at_unix: 0,
                state: TenantState::Ready,
                owner: String::new(),
                suspended: false,
                sftp_keys: Vec::new(),
                sftp_password: false,
                php_limits: crate::php_settings::PhpLimits::default(),
            },
            n,
        )
    }

    #[test]
    fn pool_conf_confines_php_to_the_tenant() -> Result<()> {
        let (t, n) = tenant("foo-bar");
        let c = render_pool_conf(&t, &n, "nginx")?;
        assert!(c.starts_with(HEADER_CONF));
        assert!(c.contains("\n[foo-bar]\nlisten = /run/oxpanel-php/foo-bar/php.sock\n"));
        assert!(c.contains("\nlisten.acl_users = nginx\n"));
        assert!(c.contains("php_admin_value[open_basedir] = /home/foo-bar/:/tmp/:"));
        assert!(c.contains("php_admin_value[session.save_path] = /tmp\n"));
        assert!(c.contains("security.limit_extensions = .php\n"));
        assert!(c.contains("clear_env = yes\n"));
        assert!(
            !c.contains("user ="),
            "the instance already runs as the tenant"
        );
        assert!(!c.contains("listen = 127"), "never a TCP listener");
        Ok(())
    }

    #[test]
    fn unit_runs_as_the_tenant_in_its_slice_without_privileges() -> Result<()> {
        let (t, n) = tenant("foo-bar");
        let u = render_unit(&t, &n, Path::new("/etc/oxpanel-php/foo-bar.conf"))?;
        assert_eq!(unit_name(&n), "oxpanel-php-foo\\x2dbar.service");
        for line in [
            "User=foo-bar",
            "Group=foo-bar",
            "Slice=oxpanel-tenant-foo\\x2dbar.slice",
            "ExecStart=/usr/sbin/php-fpm --nodaemonize --fpm-config /etc/oxpanel-php/foo-bar.conf",
            "RuntimeDirectory=oxpanel-php/foo-bar",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "PrivateTmp=yes",
            "ProtectSystem=strict",
            "ReadWritePaths=/home/foo-bar",
        ] {
            assert!(u.lines().any(|l| l == line), "missing line: {line}");
        }
        assert!(!u.contains("User=root"));
        Ok(())
    }

    #[test]
    fn a_site_with_settings_gets_its_own_hardened_pool() -> Result<()> {
        let (t, n) = tenant("alice");
        let plain = render_pool_conf(&t, &n, "nginx")?;
        assert_eq!(
            render_pool_conf_with_sites(&t, &n, "nginx", &[])?,
            plain,
            "a tenant without settings keeps exactly its configuration"
        );
        let site = SitePool {
            domain: Domain::parse("shop.example.com")?,
            settings: PhpSettings {
                memory_limit_mb: Some(256),
                display_errors: true,
                ..PhpSettings::default()
            },
        };
        let c = render_pool_conf_with_sites(&t, &n, "nginx", &[site])?;
        assert!(
            c.starts_with(&plain),
            "the default pool comes first, unchanged"
        );
        let tail = &c[plain.len()..];
        assert_eq!(
            tail,
            "
; Site shop.example.com: its own pool, for its own PHP settings (SetPhpSettings).
[shop.example.com]
listen = /run/oxpanel-php/alice/shop.example.com.sock
; Only the web server may connect; other tenants cannot.
listen.acl_users = nginx
pm = ondemand
pm.max_children = 8
pm.process_idle_timeout = 60s
pm.max_requests = 500
catch_workers_output = yes
decorate_workers_output = no
clear_env = yes
security.limit_extensions = .php
php_admin_value[open_basedir] = /home/alice/:/tmp/:/usr/share/php/:/usr/share/pear/
; The unit has a private /tmp, so these are per tenant.
php_admin_value[upload_tmp_dir] = /tmp
php_admin_value[session.save_path] = /tmp
php_admin_value[sys_temp_dir] = /tmp
php_admin_flag[log_errors] = on
php_admin_flag[display_errors] = on
php_admin_flag[allow_url_include] = off
php_value[memory_limit] = 256M
"
        );
        assert_eq!(
            site_socket_path(&n, &Domain::parse("shop.example.com")?),
            PathBuf::from("/run/oxpanel-php/alice/shop.example.com.sock")
        );
        Ok(())
    }

    #[test]
    fn site_pools_follow_pending_changes_and_the_tenants_caps() -> Result<()> {
        let (mut t, _) = tenant("alice");
        t.php_limits.memory_limit_mb = 128;
        let cfg = crate::config::Config::default();
        let vhost = |domain: &str, php: bool, mb: Option<u32>| VHostRecord {
            version: 1,
            domain: domain.into(),
            tenant: "alice".into(),
            document_root: "public_html".into(),
            aliases: vec![],
            config_path: PathBuf::from("/x"),
            created_at_unix: 0,
            php,
            app: None,
            redirect_https: false,
            hsts: false,
            tls: None,
            auto_https: crate::records::AutoHttpsChoice::On,
            php_settings: PhpSettings {
                memory_limit_mb: mb,
                ..PhpSettings::default()
            },
        };
        let stored = vec![
            vhost("b.example", true, Some(512)),
            vhost("a.example", true, None),
            vhost("c.example", false, Some(64)),
        ];
        let sites = site_pools(&cfg, &t, &stored, None)?;
        assert_eq!(sites.len(), 1, "PHP on and settings set");
        assert_eq!(sites.first().map(|s| s.domain.as_str()), Some("b.example"));
        assert_eq!(
            sites.first().and_then(|s| s.settings.memory_limit_mb),
            Some(128),
            "clamped to the cap"
        );
        // A pending change replaces the stored record of its domain.
        let pending = vhost("b.example", true, None);
        assert!(site_pools(&cfg, &t, &stored, Some(&pending))?.is_empty());
        let new = vhost("d.example", true, Some(64));
        assert_eq!(site_pools(&cfg, &t, &stored, Some(&new))?.len(), 2);
        Ok(())
    }

    #[test]
    fn rendering_refuses_paths_that_could_inject_directives() {
        let (mut t, n) = tenant("alice");
        t.home = PathBuf::from("/home/alice\nUser=root");
        assert!(render_pool_conf(&t, &n, "nginx").is_err());
        assert!(render_unit(&t, &n, Path::new("/etc/oxpanel-php/alice.conf")).is_err());
    }
}
