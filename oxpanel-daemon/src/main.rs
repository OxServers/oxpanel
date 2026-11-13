//! `oxpanel-daemon` entry point: configuration, preflight checks, socket
//! setup, and the gRPC server lifecycle.

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use nix::sys::stat::{umask, Mode};
use nix::unistd::{chown, Gid, Uid};
use tokio::net::UnixListener;
use tonic::transport::Server;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use oxpanel_daemon::auth::{self, PeerPolicy};
use oxpanel_daemon::config::Config;
use oxpanel_daemon::ctx::Ctx;
use oxpanel_daemon::server::Engine;
use oxpanel_daemon::system::{bin, CommandSpec, FakeSystem, OsUser, RealSystem, System};
use oxpanel_daemon::{fsutil, nginx, quota, sftp, vhost};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const USAGE: &str = "\
oxpanel-daemon — OxPanel system engine

USAGE:
    oxpanel-daemon [--dry-run] [--check-config]
    oxpanel-daemon --help | --version

FLAGS:
    --dry-run       Use an in-memory fake OS (no root needed). Point OXPANEL_STATE_DIR,
                    OXPANEL_HOME_BASE, OXPANEL_SYSTEMD_UNIT_DIR, OXPANEL_NGINX_CONF_DIR,
                    OXPANEL_NGINX_INCLUDE_FILE and OXPANEL_SOCKET_PATH at a writable directory.
    --check-config  Validate configuration and preflight requirements, then exit.

Configuration is read from OXPANEL_* environment variables; see
packaging/daemon.env for the full list and defaults.
";

/// Sysexits-style codes so systemd logs say why we stopped.
enum Fatal {
    Config(String),
    Perm(String),
    Unavailable(String),
    Runtime(String),
}

impl Fatal {
    fn code(&self) -> u8 {
        match self {
            Self::Config(_) => 78,
            Self::Perm(_) => 77,
            Self::Unavailable(_) => 69,
            Self::Runtime(_) => 1,
        }
    }
    fn message(&self) -> &str {
        match self {
            Self::Config(m) | Self::Perm(m) | Self::Unavailable(m) | Self::Runtime(m) => m,
        }
    }
}

struct Cli {
    dry_run: bool,
    check_config: bool,
}

fn parse_cli() -> Result<Option<Cli>, Fatal> {
    let mut cli = Cli {
        dry_run: false,
        check_config: false,
    };
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--dry-run" => cli.dry_run = true,
            "--check-config" => cli.check_config = true,
            "--help" | "-h" => {
                // The one place stdout is appropriate: the user asked for text.
                #[allow(clippy::print_stdout)]
                {
                    print!("{USAGE}");
                }
                return Ok(None);
            }
            "--version" | "-V" => {
                #[allow(clippy::print_stdout)]
                {
                    println!("oxpanel-daemon {VERSION}");
                }
                return Ok(None);
            }
            other => {
                return Err(Fatal::Config(format!(
                    "unknown argument '{other}'; see --help"
                )))
            }
        }
    }
    Ok(Some(cli))
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("OXPANEL_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    // Under systemd the journal supplies timestamps and ANSI is noise.
    let under_systemd = std::env::var_os("INVOCATION_ID").is_some();
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr);
    if under_systemd {
        builder.with_ansi(false).without_time().init();
    } else {
        builder.init();
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match parse_cli() {
        Ok(Some(cli)) => cli,
        Ok(None) => return ExitCode::SUCCESS,
        Err(f) => {
            init_tracing();
            error!("{}", f.message());
            return ExitCode::from(f.code());
        }
    };
    init_tracing();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(f) => {
            error!("{}", f.message());
            ExitCode::from(f.code())
        }
    }
}

async fn run(cli: Cli) -> Result<(), Fatal> {
    let mut config = Config::from_env().map_err(|e| Fatal::Config(e.to_string()))?;
    if cli.dry_run {
        config.dry_run = true;
    }
    info!(version = VERSION, dry_run = config.dry_run, socket = %config.socket_path.display(), "starting oxpanel-daemon");

    let sys = make_system(&mut config)?;

    let selinux = preflight(&config, sys.as_ref()).await?;
    let socket_gid = match &config.socket_group {
        Some(g) => Some(
            sys.group_by_name(g)
                .await
                .map_err(|e| Fatal::Runtime(e.to_string()))?
                .ok_or_else(|| {
                    Fatal::Config(format!("OXPANEL_SOCKET_GROUP '{g}' does not exist"))
                })?,
        ),
        None => None,
    };
    let policy = Arc::new(PeerPolicy::from_config(&config, socket_gid));
    if policy.only_root() {
        warn!(
            "no OXPANEL_ALLOWED_UIDS/GIDS or socket group configured: only root can call the API"
        );
    }

    let ctx = Ctx::new(config, sys, selinux);
    ctx.store
        .init()
        .map_err(|e| Fatal::Runtime(format!("state directory: {e}")))?;
    nginx::ensure_include(
        ctx.sys.as_ref(),
        &ctx.config.nginx_conf_dir,
        &ctx.config.nginx_include_file,
        ctx.config.nginx_default_server,
        ctx.config.command_timeout,
    )
    .await
    .map_err(|e| Fatal::Runtime(format!("nginx include: {e}")))?;

    if !cli.check_config {
        converge_at_start(&ctx).await;
    }

    if cli.check_config {
        info!("configuration and preflight checks passed");
        return Ok(());
    }

    let listener = bind_socket(&ctx.config.socket_path, socket_gid)?;
    let incoming = auth::gate(listener, policy, ctx.sys.clone());
    let engine = Engine::new(ctx.clone());

    let shutdown = async {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "cannot install SIGTERM handler");
                    std::future::pending::<()>().await;
                    return;
                }
            };
        tokio::select! {
            _ = term.recv() => info!("SIGTERM received; shutting down"),
            r = tokio::signal::ctrl_c() => match r {
                Ok(()) => info!("SIGINT received; shutting down"),
                Err(e) => error!(error = %e, "ctrl_c handler failed"),
            },
        }
    };

    if let Err(e) = sd_notify::notify(&[sd_notify::NotifyState::Ready]) {
        warn!(error = %e, "sd_notify READY failed");
    }
    info!(socket = %ctx.config.socket_path.display(), "listening");

    let served = Server::builder()
        .timeout(Duration::from_secs(300))
        .concurrency_limit_per_connection(16)
        .max_concurrent_streams(16)
        .http2_keepalive_interval(Some(Duration::from_secs(30)))
        .http2_keepalive_timeout(Some(Duration::from_secs(10)))
        .add_service(engine.into_service())
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await;

    let _ = sd_notify::notify(&[sd_notify::NotifyState::Stopping]);
    let _ = std::fs::remove_file(&ctx.config.socket_path);
    served.map_err(|e| Fatal::Runtime(format!("server: {e}")))?;
    info!("stopped");
    Ok(())
}

/// The real OS, or the in-memory fake for `--dry-run`.
/// Bring what the records describe up to date with this version of the
/// daemon. Failures are logged and left to `Reconcile`; they never stop it.
async fn converge_at_start(ctx: &Ctx) {
    // Files written by an older version are re-rendered from the records.
    match vhost::converge_all(ctx).await {
        Ok(0) => {}
        Ok(n) => info!(tenants = n, "virtual-host configuration brought up to date"),
        Err(e) => {
            warn!(error = %e, "could not bring virtual-host configuration up to date; see `oxpanel-ctl host reconcile`");
        }
    }
    // SFTP: the sshd drop-in confines every tenant account, also those
    // without keys, so it is installed whenever sshd is.
    match sftp::converge_all(ctx).await {
        Ok(n) => info!(tenants_with_sftp = n, "sftp access converged"),
        Err(e) => {
            warn!(error = %e, "could not converge SFTP access; see `oxpanel-ctl host reconcile`");
        }
    }
    match quota::availability(ctx).await {
        Ok(a) => info!(available = a.available, detail = %a.detail, "disk quotas"),
        Err(e) => warn!(error = %e, "could not determine disk-quota support"),
    }
}

fn make_system(config: &mut Config) -> Result<Arc<dyn System>, Fatal> {
    if config.dry_run {
        let fake = FakeSystem::new();
        fake.add_user(OsUser {
            name: config.web_user.clone(),
            uid: 991,
            gid: 991,
            home: "/var/lib/nginx".into(),
            shell: bin::NOLOGIN.into(),
        });
        if let Some(g) = &config.socket_group {
            fake.add_group(g, 990);
        }
        // Let the developer running the daemon talk to it.
        config.allowed_uids.insert(nix::unistd::geteuid().as_raw());
        warn!("DRY RUN: no accounts, files under /etc or services will be touched");
        return Ok(Arc::new(fake));
    }
    if !nix::unistd::geteuid().is_root() {
        return Err(Fatal::Perm(
            "must run as root (it manages accounts, cgroups and nginx)".into(),
        ));
    }
    Ok(Arc::new(RealSystem::new()))
}

/// Verify the host has what the daemon needs. Returns whether SELinux is enabled.
async fn preflight(config: &Config, sys: &dyn System) -> Result<bool, Fatal> {
    if config.dry_run {
        return Ok(false);
    }
    for b in [
        bin::USERADD,
        bin::USERDEL,
        bin::NGINX,
        bin::SYSTEMCTL,
        bin::SETPRIV,
        bin::SETFACL,
        bin::MKDIR,
        bin::DU,
        bin::GPASSWD,
    ] {
        if !is_executable(Path::new(b)) {
            return Err(Fatal::Unavailable(format!(
                "required program {b} is missing"
            )));
        }
    }
    let selinux = if is_executable(Path::new(bin::SELINUXENABLED)) {
        let out = sys
            .run(CommandSpec::new(
                bin::SELINUXENABLED,
                config.command_timeout,
            ))
            .await
            .map_err(|e| Fatal::Runtime(e.to_string()))?;
        out.success()
    } else {
        false
    };
    if selinux {
        for b in [bin::RESTORECON, bin::SEMANAGE, bin::GETSEBOOL] {
            if !is_executable(Path::new(b)) {
                return Err(Fatal::Unavailable(format!(
                    "SELinux is enabled but {b} is missing (install policycoreutils-python-utils libselinux-utils)"
                )));
            }
        }
        // Document roots live under tenant homes. httpd_t may only traverse
        // user_home_dir_t with httpd_enable_homedirs, and intermediate tenant
        // directories such as ~/www carry httpd_user_content_t, readable only
        // with httpd_read_user_content. The RPM %post and the handbook set both
        // persistently; we refuse to run half-working.
        for boolean in ["httpd_enable_homedirs", "httpd_read_user_content"] {
            let out = sys
                .run(CommandSpec::new(bin::GETSEBOOL, config.command_timeout).arg(boolean))
                .await
                .map_err(|e| Fatal::Runtime(e.to_string()))?;
            if !out.stdout_lossy().contains("--> on") {
                return Err(Fatal::Config(format!(
                    "SELinux boolean {boolean} is off: web sites under /home cannot be served. Run: setsebool -P {boolean} on"
                )));
            }
        }
    }
    if selinux {
        // Not fatal: static sites and read-only PHP work without it.
        let out = sys
            .run(CommandSpec::new(bin::GETSEBOOL, config.command_timeout).arg("httpd_unified"))
            .await
            .map_err(|e| Fatal::Runtime(e.to_string()))?;
        if !out.stdout_lossy().contains("--> on") {
            warn!("SELinux boolean httpd_unified is off: PHP sites cannot write to their own files (uploads, caches). Run: setsebool -P httpd_unified on");
        }
    }
    info!(selinux, "preflight");
    let Some(web) = sys
        .user_by_name(&config.web_user)
        .await
        .map_err(|e| Fatal::Runtime(e.to_string()))?
    else {
        return Err(Fatal::Config(format!(
            "OXPANEL_WEB_USER '{}' does not exist",
            config.web_user
        )));
    };
    // The web user receives ACL grants on every document root: it must never
    // be root or a tenant.
    if sys
        .group_by_name(&config.tenant_group)
        .await
        .map_err(|e| Fatal::Runtime(e.to_string()))?
        .is_none()
    {
        return Err(Fatal::Config(format!(
            "OXPANEL_TENANT_GROUP '{}' does not exist (the package creates it with systemd-sysusers)",
            config.tenant_group
        )));
    }
    if web.uid == 0 {
        return Err(Fatal::Config("OXPANEL_WEB_USER must not be root".into()));
    }
    if (config.uid_min..=config.uid_max).contains(&web.uid) {
        return Err(Fatal::Config(format!(
            "OXPANEL_WEB_USER '{}' (uid {}) is inside the tenant uid range {}..={}",
            config.web_user, web.uid, config.uid_min, config.uid_max
        )));
    }
    Ok(selinux)
}

fn is_executable(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Create the listening socket with restrictive permissions from the first
/// instant: umask guarantees the mode at `bind(2)` time, then ownership is fixed.
fn bind_socket(path: &Path, group_gid: Option<u32>) -> Result<UnixListener, Fatal> {
    if let Some(parent) = path.parent() {
        fsutil::ensure_dir(parent, 0o755)
            .map_err(|e| Fatal::Runtime(format!("socket directory: {e}")))?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_socket() => {
            std::fs::remove_file(path)
                .map_err(|e| Fatal::Runtime(format!("remove stale socket: {e}")))?;
        }
        Ok(_) => {
            return Err(Fatal::Config(format!(
                "{} exists and is not a socket",
                path.display()
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Fatal::Runtime(format!("stat {}: {e}", path.display()))),
    }
    let mode = if group_gid.is_some() { 0o660 } else { 0o600 };
    let old = umask(Mode::from_bits_truncate(0o777 & !mode));
    let bound = UnixListener::bind(path);
    umask(old);
    let listener = bound.map_err(|e| Fatal::Runtime(format!("bind {}: {e}", path.display())))?;
    if let Some(gid) = group_gid {
        chown(path, Some(Uid::from_raw(0)), Some(Gid::from_raw(gid)))
            .or_else(|e| {
                if nix::unistd::geteuid().is_root() {
                    Err(e)
                } else {
                    Ok(())
                }
            })
            .map_err(|e| Fatal::Runtime(format!("chown socket: {e}")))?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| Fatal::Runtime(format!("chmod socket: {e}")))?;
    Ok(listener)
}
