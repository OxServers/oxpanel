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
use crate::records::TenantRecord;
use crate::system::{bin, CommandSpec};
use crate::systemd;
use crate::validate::Username;

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

[{name}]
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
php_admin_flag[display_errors] = off
php_admin_flag[allow_url_include] = off
"
    ))
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
pub async fn ensure_pool(ctx: &Ctx, tenant: &TenantRecord) -> Result<bool> {
    if !ctx.sys.is_installed(bin::PHP_FPM).await {
        return Err(Error::PhpUnavailable);
    }
    let cfg = &ctx.config;
    let name = Username::parse(&tenant.username)?;
    let files = PoolFiles::for_tenant(&cfg.php_conf_dir, &cfg.systemd_unit_dir, &name);
    let unit = unit_name(&name);
    fsutil::ensure_dir(&cfg.php_conf_dir, DIR_MODE)?;
    let conf_changed = fsutil::write_atomic(
        &files.conf,
        render_pool_conf(tenant, &name, &cfg.web_user)?.as_bytes(),
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
    fn rendering_refuses_paths_that_could_inject_directives() {
        let (mut t, n) = tenant("alice");
        t.home = PathBuf::from("/home/alice\nUser=root");
        assert!(render_pool_conf(&t, &n, "nginx").is_err());
        assert!(render_unit(&t, &n, Path::new("/etc/oxpanel-php/alice.conf")).is_err());
    }
}
