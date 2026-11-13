//! Node.js and Python applications behind virtual hosts.
//!
//! A virtual host may run one long-lived application. Like PHP, it never
//! shares a process or an identity with anything else:
//!
//! - each application is its own systemd service running **as the tenant**,
//!   inside the tenant's slice, so the tenant's limits bound it;
//! - the unit is sandboxed exactly like a PHP instance and may write only the
//!   tenant's home;
//! - the application listens on a UNIX socket in a runtime directory only the
//!   tenant and the web server can enter — there is no TCP port another tenant
//!   could connect to, and nothing to allocate;
//! - the application directory is *not* granted to the web server, so source
//!   code and configuration are never served as files;
//! - a Python application gets its own virtualenv, so its packages are its own.
//!
//! The application learns its socket from `PORT` (which Node's
//! `server.listen(process.env.PORT)` accepts as it is) and `OXPANEL_SOCKET`.
//!
//! Dependencies are installed by running `npm`/`pip` as the tenant in a
//! transient unit: the daemon itself has no network, and must not have one.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tracing::info;

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::nginx::safe_path_str;
use crate::records::{AppRecord, AppRuntime, TenantRecord, VHostRecord};
use crate::system::{bin, CommandSpec};
use crate::systemd;
use crate::validate::{Domain, RelPath, Username};

const HEADER: &str = "# Managed by oxpanel-daemon. Manual edits will be overwritten.\n";
const FILE_MODE: u32 = 0o644;
/// systemd `RuntimeDirectory=` parent (below `/run`); one sub-directory per virtual host.
const RUNTIME_SUBDIR: &str = "oxpanel-app";
/// Upper bound for one dependency installation (the gRPC deadline is 300 s).
const INSTALL_TIMEOUT: Duration = Duration::from_secs(270);
/// What the transient unit is told; a little under ours so systemd ends it first.
const INSTALL_RUNTIME_MAX_SEC: u32 = 240;
/// Lines of application output returned by [`read_log`].
const LOG_LINES: &str = "200";

/// Domain applications run in on SELinux hosts, and the policy module that defines it.
const SELINUX_APP_CONTEXT: &str = "system_u:system_r:oxpanel_app_t:s0";
const SELINUX_MODULE: &str = "oxpanel";

/// Oldest Node.js major version OxPanel runs applications on.
pub const MIN_NODE_MAJOR: u32 = 22;

/// The installed Node.js version (`22.11.0`), or `None` if Node.js is not
/// installed or does not report a version.
pub async fn node_version(ctx: &Ctx) -> Result<Option<String>> {
    if !ctx.sys.is_installed(bin::NODE).await {
        return Ok(None);
    }
    let out = ctx
        .sys
        .run(CommandSpec::new(bin::NODE, ctx.config.command_timeout).arg("--version"))
        .await?;
    let text = out.stdout_lossy();
    let version = text.trim().trim_start_matches('v');
    Ok((out.success() && !version.is_empty()).then(|| version.to_owned()))
}

/// Major component of a version string such as `22.11.0`.
pub fn major_of(version: &str) -> Option<u32> {
    version.split('.').next()?.parse().ok()
}

/// `oxpanel-app-<escaped domain>.service`
pub fn unit_name(domain: &Domain) -> String {
    format!(
        "oxpanel-app-{}.service",
        systemd::escape_unit_component(domain.as_str())
    )
}

/// The directory systemd creates for the application's socket.
pub fn runtime_dir(domain: &Domain) -> PathBuf {
    PathBuf::from(format!("/run/{RUNTIME_SUBDIR}/{domain}"))
}

/// The socket Nginx passes requests to.
pub fn socket_path(domain: &Domain) -> PathBuf {
    runtime_dir(domain).join("app.sock")
}

pub fn unit_path(unit_dir: &Path, domain: &Domain) -> PathBuf {
    unit_dir.join(unit_name(domain))
}

/// Absolute application directory.
pub fn app_root(tenant: &TenantRecord, app: &AppRecord) -> PathBuf {
    tenant.home.join(&app.root)
}

/// The interpreter the unit executes.
fn interpreter(runtime: AppRuntime, root: &Path) -> PathBuf {
    match runtime {
        AppRuntime::Node => PathBuf::from(bin::NODE),
        AppRuntime::Python => root.join(".venv/bin/python"),
    }
}

/// What systemd itself executes in front of the interpreter.
///
/// A virtualenv's `python` is a symlink inside the tenant's home. Under
/// SELinux, systemd may not read symlinks there, so it executes `env` (a
/// system binary), and `env` — by then running as the tenant, in the
/// application's own domain — executes the virtualenv's interpreter.
fn launcher(runtime: AppRuntime) -> &'static str {
    match runtime {
        AppRuntime::Node => "",
        AppRuntime::Python => "/usr/bin/env ",
    }
}

/// The program that must be installed on the host for `runtime`.
pub fn required_program(runtime: AppRuntime) -> &'static str {
    match runtime {
        AppRuntime::Node => bin::NODE,
        AppRuntime::Python => bin::PYTHON3,
    }
}

/// The service unit that runs the application.
pub fn render_unit(
    tenant: &TenantRecord,
    domain: &Domain,
    app: &AppRecord,
    web_user: &str,
    selinux: bool,
) -> Result<String> {
    let name = Username::parse(&tenant.username)?;
    // Re-validated: these strings come from a record and end up in a unit file.
    RelPath::parse_field(&app.root, "app.root")?;
    RelPath::parse_field(&app.entry, "app.entry")?;
    let home = safe_path_str(&tenant.home)?;
    let root = app_root(tenant, app);
    let entry = root.join(&app.entry);
    let interpreter = interpreter(app.runtime, &root);
    let (root, entry, interpreter) = (
        safe_path_str(&root)?,
        safe_path_str(&entry)?,
        safe_path_str(&interpreter)?,
    );
    let run_dir = runtime_dir(domain);
    let run_dir = safe_path_str(&run_dir)?;
    let sock = socket_path(domain);
    let sock = safe_path_str(&sock)?;
    let slice = &tenant.slice_unit;
    let runtime = app.runtime.as_str();
    let setfacl = bin::SETFACL;
    let launcher = launcher(app.runtime);
    // On SELinux hosts the application runs in its own domain, the only one
    // the web server may connect to (packaging/selinux/oxpanel.cil).
    let selinux_context = if selinux {
        format!("SELinuxContext={SELINUX_APP_CONTEXT}\n")
    } else {
        String::new()
    };
    Ok(format!(
        "{HEADER}[Unit]
Description=OxPanel {runtime} application for {domain} (tenant {name})
Documentation=https://github.com/OxServers/oxpanel
After=network.target

[Service]
Type=simple
User={name}
Group={name}
Slice={slice}
{selinux_context}WorkingDirectory={root}
Environment=PORT={sock}
Environment=OXPANEL_SOCKET={sock}
Environment=HOME={home}
Environment=NODE_ENV=production
Environment=PYTHONUNBUFFERED=1
# As root (+): let the web server enter the socket directory and connect to
# sockets created in it. Everyone else stays out (the directory is 0750).
ExecStartPre=+{setfacl} -m u:{web_user}:--x,d:u:{web_user}:rw- {run_dir}
ExecStart={launcher}{interpreter} {entry}
Restart=on-failure
RestartSec=3s
RuntimeDirectory={RUNTIME_SUBDIR}/{domain}
RuntimeDirectoryMode=0750
# Group bits must stay on: the kernel applies the umask to a socket's mode
# even under a default ACL, and those bits are the ACL mask that decides
# whether the web server's entry is effective. Nothing is opened to others.
UMask=0007

# The application already runs unprivileged as the tenant; this narrows it further.
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

fn parts(vhost: &VHostRecord) -> Result<(Domain, &AppRecord)> {
    let app = vhost
        .app
        .as_ref()
        .ok_or_else(|| Error::NoApp(vhost.domain.clone()))?;
    Ok((Domain::parse(&vhost.domain)?, app))
}

/// Everything the host must provide before an application of `runtime` can
/// be enabled. Read-only, so a request that cannot succeed is refused before
/// it has created anything.
pub async fn preflight(ctx: &Ctx, runtime: AppRuntime) -> Result<()> {
    let timeout = ctx.config.command_timeout;
    if !ctx.sys.is_installed(required_program(runtime)).await {
        return Err(Error::RuntimeUnavailable(match runtime {
            AppRuntime::Node => "Node.js (nodejs)",
            AppRuntime::Python => "Python (python3)",
        }));
    }
    if runtime == AppRuntime::Node {
        let found = node_version(ctx).await?.unwrap_or_default();
        if major_of(&found).is_none_or(|major| major < MIN_NODE_MAJOR) {
            return Err(Error::RuntimeTooOld {
                runtime: "Node.js",
                found,
                minimum: MIN_NODE_MAJOR,
            });
        }
    }
    if ctx.selinux {
        // Without the module the unit could not start in its domain and the
        // web server could not reach it: refuse with something actionable.
        let modules = ctx
            .sys
            .run_ok(CommandSpec::new(bin::SEMODULE, timeout).arg("--list-modules"))
            .await?;
        if !modules
            .stdout_lossy()
            .lines()
            .any(|l| l.trim() == SELINUX_MODULE)
        {
            return Err(Error::AppPolicyMissing);
        }
    }
    Ok(())
}

/// Create the application directory (as the tenant), a virtualenv for Python,
/// write the unit and make sure the application runs (unless the tenant is
/// suspended). Idempotent; a changed unit restarts the application.
/// The caller holds the mutation lock. Returns whether the unit changed.
pub async fn ensure_app(ctx: &Ctx, tenant: &TenantRecord, vhost: &VHostRecord) -> Result<bool> {
    let (domain, app) = parts(vhost)?;
    let cfg = &ctx.config;
    let timeout = cfg.command_timeout;
    preflight(ctx, app.runtime).await?;
    let root = app_root(tenant, app);
    ctx.sys
        .run_ok(
            CommandSpec::new(bin::MKDIR, timeout)
                .args(["-p", "--"])
                .arg(&root)
                .as_user(tenant.uid, tenant.gid),
        )
        .await?;
    ctx.sys.verify_owned_dir(&root, tenant.uid).await?;
    ensure_venv(ctx, tenant, app).await?;
    let unit = unit_name(&domain);
    let changed = fsutil::write_atomic(
        &unit_path(&cfg.systemd_unit_dir, &domain),
        render_unit(tenant, &domain, app, &cfg.web_user, ctx.selinux)?.as_bytes(),
        FILE_MODE,
    )?;
    if changed {
        systemd::daemon_reload(ctx.sys.as_ref(), timeout).await?;
    }
    if tenant.suspended {
        return Ok(changed);
    }
    if changed {
        ctx.sys
            .run_ok(systemctl(ctx).args(["enable", "--"]).arg(&unit))
            .await?;
        ctx.sys
            .run_ok(systemctl(ctx).args(["restart", "--"]).arg(&unit))
            .await?;
        info!(%domain, tenant = %tenant.username, runtime = app.runtime.as_str(), unit, "application (re)started");
    } else {
        ctx.sys
            .run_ok(systemctl(ctx).args(["enable", "--now", "--"]).arg(&unit))
            .await?;
    }
    Ok(changed)
}

/// A Python application's virtualenv (`<root>/.venv`), created if it is
/// missing — after `ConfigureVirtualHost`, and after a restore (backups
/// leave virtualenvs out). Nothing for other runtimes.
pub async fn ensure_venv(ctx: &Ctx, tenant: &TenantRecord, app: &AppRecord) -> Result<()> {
    let root = app_root(tenant, app);
    if app.runtime == AppRuntime::Python && !root.join(".venv/bin/python").exists() {
        // Created by the tenant, for the tenant: needs no network and no root.
        ctx.sys
            .run_ok(
                CommandSpec::new(bin::PYTHON3, ctx.config.command_timeout)
                    .args(["-m", "venv", "--"])
                    .arg(root.join(".venv"))
                    .as_user(tenant.uid, tenant.gid),
            )
            .await?;
    }
    Ok(())
}

/// The file `InstallAppDependencies` installs from: `package.json` or
/// `requirements.txt`, relative to the application directory.
pub fn dependency_manifest(runtime: AppRuntime) -> &'static str {
    match runtime {
        AppRuntime::Node => "package.json",
        AppRuntime::Python => "requirements.txt",
    }
}

/// Stop the application and remove its unit. The application directory is the
/// tenant's data and is left alone. Returns whether a unit existed.
pub async fn remove_app(ctx: &Ctx, domain: &Domain) -> Result<bool> {
    let cfg = &ctx.config;
    let path = unit_path(&cfg.systemd_unit_dir, domain);
    if !path.exists() {
        return Ok(false);
    }
    ctx.sys
        .run_ok(
            systemctl(ctx)
                .args(["disable", "--now", "--"])
                .arg(unit_name(domain)),
        )
        .await?;
    fsutil::remove_if_exists(&path)?;
    systemd::daemon_reload(ctx.sys.as_ref(), cfg.command_timeout).await?;
    info!(%domain, "application removed");
    Ok(true)
}

/// Start or stop every application of a tenant (resume / suspend).
/// `disable` as well as stop, so a reboot does not revive a suspended tenant.
pub async fn set_running_all(ctx: &Ctx, tenant: &TenantRecord, running: bool) -> Result<()> {
    let verb = if running { "enable" } else { "disable" };
    for v in ctx
        .store
        .list_vhosts()?
        .iter()
        .filter(|v| v.tenant == tenant.username && v.app.is_some())
    {
        let domain = Domain::parse(&v.domain)?;
        if unit_path(&ctx.config.systemd_unit_dir, &domain).exists() {
            ctx.sys
                .run_ok(
                    systemctl(ctx)
                        .args([verb, "--now", "--"])
                        .arg(unit_name(&domain)),
                )
                .await?;
        }
    }
    Ok(())
}

/// Restart the application, clearing a start-limit left by earlier crashes.
pub async fn restart(ctx: &Ctx, vhost: &VHostRecord) -> Result<()> {
    let (domain, _) = parts(vhost)?;
    let unit = unit_name(&domain);
    ctx.sys
        .run_ok(systemctl(ctx).args(["reset-failed", "--"]).arg(&unit))
        .await?;
    ctx.sys
        .run_ok(systemctl(ctx).args(["restart", "--"]).arg(&unit))
        .await?;
    Ok(())
}

/// Install the application's dependencies (see [`run_installer`]), then
/// restart it if that succeeded and the tenant is not suspended.
pub async fn install_dependencies(
    ctx: &Ctx,
    tenant: &TenantRecord,
    vhost: &VHostRecord,
) -> Result<(bool, String)> {
    let (succeeded, output) = run_installer(ctx, tenant, vhost).await?;
    if succeeded && !tenant.suspended {
        restart(ctx, vhost).await?;
    }
    Ok((succeeded, output))
}

/// Install the application's dependencies as the tenant. Runs in a transient
/// unit (the daemon has no network), sandboxed like the application itself and
/// inside the tenant's slice. Returns whether the installer succeeded and the
/// end of its output; a failing installer is a result, not an error.
pub async fn run_installer(
    ctx: &Ctx,
    tenant: &TenantRecord,
    vhost: &VHostRecord,
) -> Result<(bool, String)> {
    let (domain, app) = parts(vhost)?;
    let root = app_root(tenant, app);
    let home = safe_path_str(&tenant.home)?;
    let root_str = safe_path_str(&root)?;
    let unit = format!(
        "oxpanel-appdeps-{}",
        systemd::escape_unit_component(domain.as_str())
    );
    let started_at = crate::records::now_unix();
    // No `--pipe`: under SELinux, systemd (init_t) may not write to a pipe
    // created by this service, and drops the request. The installer's output
    // goes to the journal instead and is read back from there.
    let mut cmd = CommandSpec::new(bin::SYSTEMD_RUN, INSTALL_TIMEOUT)
        .args(["--wait", "--collect", "--quiet"])
        .arg(format!("--unit={unit}"));
    for property in [
        format!("User={}", tenant.username),
        format!("Group={}", tenant.username),
        format!("Slice={}", tenant.slice_unit),
        format!("WorkingDirectory={root_str}"),
        format!("Environment=HOME={home}"),
        format!("ReadWritePaths={home}"),
        format!("RuntimeMaxSec={INSTALL_RUNTIME_MAX_SEC}"),
        "NoNewPrivileges=yes".to_owned(),
        "CapabilityBoundingSet=".to_owned(),
        "PrivateTmp=yes".to_owned(),
        "PrivateDevices=yes".to_owned(),
        "ProtectSystem=strict".to_owned(),
        "ProtectKernelTunables=yes".to_owned(),
        "ProtectKernelModules=yes".to_owned(),
        "ProtectControlGroups=yes".to_owned(),
        "RestrictSUIDSGID=yes".to_owned(),
    ] {
        cmd = cmd.arg("--property").arg(property);
    }
    cmd = cmd.arg("--");
    cmd = match app.runtime {
        AppRuntime::Node => {
            cmd.args([bin::NPM, "install", "--omit=dev", "--no-audit", "--no-fund"])
        }
        AppRuntime::Python => cmd.arg(bin::ENV).arg(root.join(".venv/bin/python")).args([
            "-m",
            "pip",
            "install",
            "--no-input",
            "--disable-pip-version-check",
            "--requirement",
            "requirements.txt",
        ]),
    };
    let out = ctx.sys.run(cmd).await?;
    let succeeded = out.success();
    info!(%domain, tenant = %tenant.username, succeeded, "dependency installation finished");
    let journal = ctx
        .sys
        .run(
            CommandSpec::new(bin::JOURNALCTL, ctx.config.command_timeout)
                .args(["--no-pager", "--output=cat", "--lines"])
                .arg(LOG_LINES)
                .arg("--since")
                .arg(format!("@{started_at}"))
                .arg("--unit")
                .arg(format!("{unit}.service")),
        )
        .await?;
    // What the installer printed, then anything systemd-run itself said
    // (for example that an installation for this site is already running).
    let mut output = journal.stdout_lossy();
    let own = out.combined_lossy();
    if !own.is_empty() {
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
        output.push_str(&own);
    }
    Ok((succeeded, output))
}

/// The most recent output of the application, from the journal.
pub async fn read_log(ctx: &Ctx, vhost: &VHostRecord) -> Result<String> {
    let (domain, _) = parts(vhost)?;
    let out = ctx
        .sys
        .run_ok(
            CommandSpec::new(bin::JOURNALCTL, ctx.config.command_timeout)
                .args(["--no-pager", "--output=short-iso", "--lines"])
                .arg(LOG_LINES)
                .arg("--unit")
                .arg(unit_name(&domain)),
        )
        .await?;
    Ok(out.stdout_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{TenantState, RECORD_VERSION};

    fn tenant(name: &str) -> TenantRecord {
        let n = Username::parse(name).unwrap_or_else(|e| panic!("{e}"));
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
        }
    }

    fn app(runtime: AppRuntime, root: &str, entry: &str) -> AppRecord {
        AppRecord {
            runtime,
            root: root.into(),
            entry: entry.into(),
        }
    }

    fn domain(s: &str) -> Domain {
        Domain::parse(s).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn node_unit_runs_as_the_tenant_on_a_private_socket() -> Result<()> {
        let d = domain("my-app.example.com");
        let u = render_unit(
            &tenant("foo-bar"),
            &d,
            &app(AppRuntime::Node, "apps/shop", "server.js"),
            "nginx",
            false,
        )?;
        assert!(
            !u.contains("SELinuxContext"),
            "no SELinux directive on hosts without SELinux"
        );
        let with_selinux = render_unit(
            &tenant("foo-bar"),
            &d,
            &app(AppRuntime::Node, "apps/shop", "server.js"),
            "nginx",
            true,
        )?;
        assert!(with_selinux
            .lines()
            .any(|l| l == "SELinuxContext=system_u:system_r:oxpanel_app_t:s0"));
        assert_eq!(unit_name(&d), "oxpanel-app-my\\x2dapp.example.com.service");
        for line in [
            "User=foo-bar",
            "Group=foo-bar",
            "Slice=oxpanel-tenant-foo\\x2dbar.slice",
            "WorkingDirectory=/home/foo-bar/apps/shop",
            "Environment=PORT=/run/oxpanel-app/my-app.example.com/app.sock",
            "Environment=OXPANEL_SOCKET=/run/oxpanel-app/my-app.example.com/app.sock",
            "ExecStartPre=+/usr/bin/setfacl -m u:nginx:--x,d:u:nginx:rw- /run/oxpanel-app/my-app.example.com",
            "ExecStart=/usr/bin/node /home/foo-bar/apps/shop/server.js",
            "RuntimeDirectory=oxpanel-app/my-app.example.com",
            "RuntimeDirectoryMode=0750",
            "UMask=0007",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "ProtectSystem=strict",
            "ReadWritePaths=/home/foo-bar",
        ] {
            assert!(u.lines().any(|l| l == line), "missing line: {line}\n{u}");
        }
        assert!(!u.contains("User=root"));
        assert_eq!(
            u.matches("ExecStart").count(),
            2,
            "one ExecStartPre and one ExecStart"
        );
        Ok(())
    }

    #[test]
    fn python_unit_uses_the_apps_own_virtualenv() -> Result<()> {
        let u = render_unit(
            &tenant("alice"),
            &domain("api.example.com"),
            &app(AppRuntime::Python, "apps/api", "src/main.py"),
            "nginx",
            false,
        )?;
        assert!(u.lines().any(|l| l
            == "ExecStart=/usr/bin/env /home/alice/apps/api/.venv/bin/python /home/alice/apps/api/src/main.py"));
        assert!(u.contains("Environment=PYTHONUNBUFFERED=1\n"));
        Ok(())
    }

    #[test]
    fn rendering_refuses_values_that_could_inject_unit_directives() {
        let d = domain("example.com");
        for (root, entry) in [
            ("apps/x\nUser=root", "app.js"),
            ("apps/x", "app.js\nExecStart=/bin/sh"),
            ("apps/x", "app.js --inspect=0.0.0.0"),
            ("../../etc", "app.js"),
            ("apps/x", "../../../usr/bin/id"),
            ("/etc", "app.js"),
        ] {
            assert!(
                render_unit(
                    &tenant("alice"),
                    &d,
                    &app(AppRuntime::Node, root, entry),
                    "nginx",
                    false
                )
                .is_err(),
                "{root:?} {entry:?}"
            );
        }
        let mut t = tenant("alice");
        t.home = PathBuf::from("/home/alice ExecStartPre=+/bin/sh");
        assert!(render_unit(
            &t,
            &d,
            &app(AppRuntime::Node, "apps/x", "app.js"),
            "nginx",
            true
        )
        .is_err());
    }
}
