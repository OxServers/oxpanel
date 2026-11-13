//! `oxpanel-ctl` — talk to `oxpanel-daemon` over its UNIX socket.
//!
//! Exit status: 0 on success, 1 on an API error (message on stderr),
//! 2 on usage errors, 3 when `host reconcile` found drift, 4 when
//! `vhost install-deps` ran and the installer failed.
// A CLI's whole job is to print.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::codegen::http::Uri;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

use oxpanel_proto::v1 as pb;

/// Print a line to stdout; a closed pipe (`oxpanel-ctl … | head`) ends the
/// program quietly instead of panicking with "Broken pipe".
fn emit(line: &str) {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    if let Err(e) = writeln!(out, "{line}") {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
    }
}

macro_rules! say {
    ($($arg:tt)*) => { emit(&format!($($arg)*)) };
}
use oxpanel_proto::v1::ox_panel_engine_client::OxPanelEngineClient;

#[derive(Parser, Debug)]
#[command(name = "oxpanel-ctl", version, about = "Administer an OxPanel engine")]
struct Cli {
    /// Path of the daemon socket.
    #[arg(
        long,
        env = "OXPANEL_SOCKET_PATH",
        default_value = "/run/oxpanel/oxpanel.sock"
    )]
    socket: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Tenant accounts.
    #[command(subcommand)]
    Tenant(TenantCmd),
    /// Nginx virtual hosts.
    #[command(subcommand)]
    Vhost(VhostCmd),
    /// The engine and the host it runs on.
    #[command(subcommand)]
    Host(HostCmd),
    /// SFTP access of tenants (SSH public keys).
    #[command(subcommand)]
    Sftp(SftpCmd),
}

#[derive(Subcommand, Debug)]
enum SftpCmd {
    /// Let a public key log in over SFTP as the tenant (idempotent).
    AddKey {
        username: String,
        /// The key line, e.g. "ssh-ed25519 AAAA… comment".
        #[arg(
            long,
            conflicts_with = "key_file",
            required_unless_present = "key_file"
        )]
        key: Option<String>,
        /// Read the key line from a file (e.g. ~/.ssh/id_ed25519.pub).
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// Name for the key; default: the key's own comment.
        #[arg(long, default_value = "")]
        label: String,
    },
    /// Remove a key by its fingerprint (SHA256:…); ends running sessions.
    RemoveKey {
        username: String,
        fingerprint: String,
    },
    /// The tenant's keys.
    ListKeys { username: String },
}

#[derive(Subcommand, Debug)]
enum HostCmd {
    /// Engine version, capacity and host load.
    Info,
    /// Compare records with the operating system (read-only).
    /// Exits with status 3 when differences are found.
    Reconcile,
}

#[derive(Subcommand, Debug)]
enum TenantCmd {
    /// Create a tenant (idempotent).
    Create {
        username: String,
        /// Owner label from the panel (e.g. a reseller id).
        #[arg(long, default_value = "")]
        owner: String,
        #[command(flatten)]
        limits: LimitArgs,
    },
    Get {
        username: String,
    },
    List {
        /// Only tenants with this owner label.
        #[arg(long, default_value = "")]
        owner: String,
    },
    /// Replace the tenant's resource limits (all of them; omitted = default).
    SetLimits {
        username: String,
        #[command(flatten)]
        limits: LimitArgs,
    },
    /// Replace the owner label; an empty label clears it.
    SetOwner {
        username: String,
        owner: String,
    },
    /// Make every site of the tenant answer 503 until resumed.
    Suspend {
        username: String,
    },
    Resume {
        username: String,
    },
    /// Current memory, CPU, task and disk consumption.
    Usage {
        username: String,
    },
    /// Delete a tenant OxPanel created.
    Delete {
        username: String,
        /// Also remove the home directory.
        #[arg(long)]
        remove_home: bool,
    },
}

#[derive(Args, Debug, Default)]
struct LimitArgs {
    /// systemd MemoryMax, e.g. 512M, 2G or bytes. 0 = unlimited.
    #[arg(long, value_parser = parse_size, default_value = "0")]
    memory: u64,
    /// systemd CPUWeight 1..=10000 (0 = default).
    #[arg(long, default_value_t = 0)]
    cpu_weight: u32,
    /// systemd IOWeight 1..=10000 (0 = default).
    #[arg(long, default_value_t = 0)]
    io_weight: u32,
    /// systemd TasksMax (0 = default).
    #[arg(long, default_value_t = 0)]
    tasks_max: u32,
    /// Disk space (kernel quota), e.g. 5G. 0 = unlimited.
    #[arg(long, value_parser = parse_size, default_value = "0")]
    disk: u64,
    /// Number of files and directories (kernel quota). 0 = unlimited.
    #[arg(long, default_value_t = 0)]
    inodes: u64,
}

#[derive(Subcommand, Debug)]
enum VhostCmd {
    /// Create or update a virtual host (idempotent).
    Set {
        domain: String,
        #[arg(long)]
        tenant: String,
        /// Document root relative to the tenant home (default public_html).
        #[arg(long, default_value = "")]
        root: String,
        /// Additional server names (repeatable).
        #[arg(long = "alias")]
        aliases: Vec<String>,
        /// Run *.php through the tenant's own PHP-FPM pool.
        #[arg(long)]
        php: bool,
        /// Run an application behind the site: node or python.
        #[arg(long, value_enum)]
        app: Option<AppKind>,
        /// Application directory relative to the tenant home (default apps/<domain>).
        #[arg(long, default_value = "", requires = "app")]
        app_root: String,
        /// Program to run, relative to the application directory (default app.js / app.py).
        #[arg(long, default_value = "", requires = "app")]
        app_entry: String,
    },
    /// Restart the site's application (after putting new code in place).
    RestartApp {
        domain: String,
    },
    /// Install the application's dependencies as the tenant
    /// (npm install / pip install -r requirements.txt), then restart it.
    /// Exits with status 4 when the installer fails.
    InstallDeps {
        domain: String,
    },
    /// Print the end of a site's access log (or error log).
    Log {
        domain: String,
        /// The error log instead of the access log.
        #[arg(long)]
        error: bool,
        /// The application's own output instead (stdout and stderr).
        #[arg(long, conflicts_with = "error")]
        app: bool,
        /// How much of the end of the log to fetch (default 32K, at most 128K).
        #[arg(long, value_parser = parse_size, default_value = "0")]
        bytes: u64,
    },
    Remove {
        domain: String,
    },
    List {
        #[arg(long, default_value = "")]
        tenant: String,
    },
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
enum AppKind {
    Node,
    Python,
}

/// Exit status of `vhost install-deps` when the installer failed.
const EXIT_INSTALL_FAILED: u8 = 4;

fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('k' | 'K') => (&s[..s.len() - 1], 1u64 << 10),
        Some('m' | 'M') => (&s[..s.len() - 1], 1u64 << 20),
        Some('g' | 'G') => (&s[..s.len() - 1], 1u64 << 30),
        Some('t' | 'T') => (&s[..s.len() - 1], 1u64 << 40),
        _ => (s, 1),
    };
    let n: u64 = num.parse().map_err(|_| format!("'{s}' is not a size"))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("'{s}' is too large"))
}

async fn connect(socket: PathBuf) -> Result<OxPanelEngineClient<Channel>, tonic::transport::Error> {
    let channel = Endpoint::try_from("http://oxpanel.local")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = socket.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await?;
    Ok(OxPanelEngineClient::new(channel))
}

impl From<LimitArgs> for pb::ResourceLimits {
    fn from(l: LimitArgs) -> Self {
        Self {
            memory_max_bytes: l.memory,
            cpu_weight: l.cpu_weight,
            io_weight: l.io_weight,
            tasks_max: l.tasks_max,
            disk_max_bytes: l.disk,
            inodes_max: l.inodes,
        }
    }
}

fn print_update(r: &pb::UpdateTenantResponse) {
    say!("changed={}", r.changed);
    if let Some(t) = &r.tenant {
        print_tenant(t);
    }
}

/// Exit status of `host reconcile` when drift was found.
const EXIT_DRIFT: u8 = 3;

fn print_tenant(t: &pb::Tenant) {
    let l = t.limits.unwrap_or_default();
    let state = pb::TenantState::try_from(t.state).map_or("unknown", |s| s.as_str_name());
    say!(
        "tenant={} owner={} uid={} gid={} home={} state={} suspended={} slice={} memory_max={} cpu_weight={} io_weight={} tasks_max={} disk_max={} inodes_max={} sftp_keys={} created_at={}",
        t.username,
        if t.owner.is_empty() { "-" } else { t.owner.as_str() },
        t.uid,
        t.gid,
        t.home,
        state,
        t.suspended,
        t.slice_unit,
        l.memory_max_bytes,
        l.cpu_weight,
        l.io_weight,
        l.tasks_max,
        l.disk_max_bytes,
        l.inodes_max,
        t.sftp_key_count,
        t.created_at.as_ref().map_or(0, |ts| ts.seconds),
    );
}

fn print_vhost(v: &pb::VirtualHost) {
    say!(
        "domain={} tenant={} document_root={} aliases={} php={} app={} config={}",
        v.domain,
        v.tenant,
        v.document_root,
        if v.aliases.is_empty() {
            "-".to_owned()
        } else {
            v.aliases.join(",")
        },
        v.php,
        v.app.as_ref().map_or_else(
            || "-".to_owned(),
            |a| {
                let runtime = match pb::AppRuntime::try_from(a.runtime) {
                    Ok(pb::AppRuntime::Node) => "node",
                    Ok(pb::AppRuntime::Python) => "python",
                    _ => "unknown",
                };
                format!("{runtime}:{}:{}", a.root, a.entry)
            }
        ),
        v.config_path
    );
}

async fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut c = connect(cli.socket).await?;
    Ok(match cli.cmd {
        Cmd::Tenant(cmd) => run_tenant(&mut c, cmd).await?,
        Cmd::Vhost(cmd) => run_vhost(&mut c, cmd).await?,
        Cmd::Host(cmd) => run_host(&mut c, cmd).await?,
        Cmd::Sftp(cmd) => run_sftp(&mut c, cmd).await?,
    })
}

async fn run_tenant(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: TenantCmd,
) -> Result<ExitCode, tonic::Status> {
    match cmd {
        TenantCmd::Create {
            username,
            owner,
            limits,
        } => {
            let r = c
                .create_tenant(pb::CreateTenantRequest {
                    username,
                    owner,
                    limits: Some(limits.into()),
                })
                .await?
                .into_inner();
            say!("created={}", r.created);
            if let Some(t) = &r.tenant {
                print_tenant(t);
            }
        }
        TenantCmd::Get { username } => {
            print_tenant(
                &c.get_tenant(pb::GetTenantRequest { username })
                    .await?
                    .into_inner(),
            );
        }
        TenantCmd::List { owner } => {
            for t in &c
                .list_tenants(pb::ListTenantsRequest { owner })
                .await?
                .into_inner()
                .tenants
            {
                print_tenant(t);
            }
        }
        TenantCmd::SetLimits { username, limits } => {
            print_update(
                &c.update_tenant_limits(pb::UpdateTenantLimitsRequest {
                    username,
                    limits: Some(limits.into()),
                })
                .await?
                .into_inner(),
            );
        }
        TenantCmd::SetOwner { username, owner } => {
            print_update(
                &c.update_tenant_owner(pb::UpdateTenantOwnerRequest { username, owner })
                    .await?
                    .into_inner(),
            );
        }
        TenantCmd::Suspend { username } => {
            print_update(
                &c.suspend_tenant(pb::SuspendTenantRequest { username })
                    .await?
                    .into_inner(),
            );
        }
        TenantCmd::Resume { username } => {
            print_update(
                &c.resume_tenant(pb::ResumeTenantRequest { username })
                    .await?
                    .into_inner(),
            );
        }
        TenantCmd::Usage { username } => {
            let u = c
                .get_tenant_usage(pb::GetTenantUsageRequest { username })
                .await?
                .into_inner();
            say!(
                "tenant={} memory_current={} cpu_usage_nsec={} tasks_current={} disk_usage={} measured_at={}",
                u.username,
                u.memory_current_bytes,
                u.cpu_usage_nsec,
                u.tasks_current,
                u.disk_usage_bytes,
                u.measured_at.as_ref().map_or(0, |ts| ts.seconds),
            );
        }
        TenantCmd::Delete {
            username,
            remove_home,
        } => {
            let r = c
                .delete_tenant(pb::DeleteTenantRequest {
                    username,
                    remove_home,
                })
                .await?
                .into_inner();
            say!("deleted={}", r.deleted);
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn vhost_log(
    c: &mut OxPanelEngineClient<Channel>,
    domain: String,
    error: bool,
    app: bool,
    bytes: u64,
) -> Result<(), tonic::Status> {
    let kind = if app {
        pb::LogKind::App
    } else if error {
        pb::LogKind::Error
    } else {
        pb::LogKind::Access
    };
    let r = c
        .read_virtual_host_log(pb::ReadVirtualHostLogRequest {
            domain,
            kind: kind.into(),
            max_bytes: u32::try_from(bytes).unwrap_or(u32::MAX),
        })
        .await?
        .into_inner();
    if r.truncated {
        eprintln!("(showing the end of the log only)");
    }
    for line in r.text.lines() {
        say!("{line}");
    }
    Ok(())
}

async fn run_vhost(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: VhostCmd,
) -> Result<ExitCode, tonic::Status> {
    match cmd {
        VhostCmd::Set {
            domain,
            tenant,
            root,
            aliases,
            php,
            app,
            app_root,
            app_entry,
        } => {
            let r = c
                .configure_virtual_host(pb::ConfigureVirtualHostRequest {
                    domain,
                    tenant,
                    document_root: root,
                    aliases,
                    php,
                    app: app.map(|kind| pb::App {
                        runtime: match kind {
                            AppKind::Node => pb::AppRuntime::Node,
                            AppKind::Python => pb::AppRuntime::Python,
                        }
                        .into(),
                        root: app_root,
                        entry: app_entry,
                    }),
                })
                .await?
                .into_inner();
            say!("changed={}", r.created);
            if let Some(v) = &r.vhost {
                print_vhost(v);
            }
        }
        VhostCmd::RestartApp { domain } => {
            c.restart_app(pb::RestartAppRequest { domain }).await?;
            say!("restarted=true");
        }
        VhostCmd::InstallDeps { domain } => {
            let r = c
                .install_app_dependencies(pb::InstallAppDependenciesRequest { domain })
                .await?
                .into_inner();
            for line in r.output.lines() {
                say!("{line}");
            }
            say!("succeeded={}", r.succeeded);
            if !r.succeeded {
                return Ok(ExitCode::from(EXIT_INSTALL_FAILED));
            }
        }
        VhostCmd::Log {
            domain,
            error,
            app,
            bytes,
        } => vhost_log(c, domain, error, app, bytes).await?,
        VhostCmd::Remove { domain } => {
            let r = c
                .remove_virtual_host(pb::RemoveVirtualHostRequest { domain })
                .await?
                .into_inner();
            say!("removed={}", r.removed);
        }
        VhostCmd::List { tenant } => {
            for v in &c
                .list_virtual_hosts(pb::ListVirtualHostsRequest { tenant })
                .await?
                .into_inner()
                .vhosts
            {
                print_vhost(v);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn run_host(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: HostCmd,
) -> Result<ExitCode, tonic::Status> {
    match cmd {
        HostCmd::Info => {
            let i = c
                .get_host_info(pb::GetHostInfoRequest {})
                .await?
                .into_inner();
            say!(
                "version={} selinux={} php={} node={} node_version={} python={} sftp={} disk_quota={} dry_run={} tenants={} vhosts={} uid_range={}-{} load={:.2},{:.2},{:.2} memory_total={} memory_free={} home_disk_total={} home_disk_free={} uptime={}",
                i.daemon_version,
                i.selinux_enabled,
                i.php_available,
                i.node_available,
                if i.node_version.is_empty() {
                    "-"
                } else {
                    i.node_version.as_str()
                },
                i.python_available,
                i.sftp_available,
                i.disk_quota_available,
                i.dry_run,
                i.tenant_count,
                i.vhost_count,
                i.uid_min,
                i.uid_max,
                i.load_1m,
                i.load_5m,
                i.load_15m,
                i.memory_total_bytes,
                i.memory_free_bytes,
                i.home_disk_total_bytes,
                i.home_disk_free_bytes,
                i.uptime_seconds,
            );
            say!("disk_quota_detail={}", i.disk_quota_detail);
        }
        HostCmd::Reconcile => {
            let r = c.reconcile(pb::ReconcileRequest {}).await?.into_inner();
            say!("drifts={}", r.drifts.len());
            for d in &r.drifts {
                let kind = pb::DriftKind::try_from(d.kind).map_or("unknown", |k| k.as_str_name());
                say!("kind={} subject={} detail={}", kind, d.subject, d.detail);
            }
            if !r.drifts.is_empty() {
                return Ok(ExitCode::from(EXIT_DRIFT));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn print_sftp_key(k: &pb::SftpKey) {
    say!(
        "fingerprint={} type={} label={} added_at={}",
        k.fingerprint,
        k.key_type,
        if k.label.is_empty() {
            "-"
        } else {
            k.label.as_str()
        },
        k.added_at.as_ref().map_or(0, |ts| ts.seconds),
    );
}

async fn run_sftp(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: SftpCmd,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match cmd {
        SftpCmd::AddKey {
            username,
            key,
            key_file,
            label,
        } => {
            let public_key = match (key, key_file) {
                (Some(k), _) => k,
                (None, Some(path)) => std::fs::read_to_string(&path)
                    .map_err(|e| format!("{}: {e}", path.display()))?,
                (None, None) => return Err("--key or --key-file is required".into()),
            };
            let r = c
                .add_sftp_key(pb::AddSftpKeyRequest {
                    username,
                    public_key,
                    label,
                })
                .await?
                .into_inner();
            say!("changed={}", r.changed);
            if let Some(k) = &r.key {
                print_sftp_key(k);
            }
        }
        SftpCmd::RemoveKey {
            username,
            fingerprint,
        } => {
            let r = c
                .remove_sftp_key(pb::RemoveSftpKeyRequest {
                    username,
                    fingerprint,
                })
                .await?
                .into_inner();
            say!("removed=true remaining={}", r.remaining);
        }
        SftpCmd::ListKeys { username } => {
            for k in &c
                .list_sftp_keys(pb::ListSftpKeysRequest { username })
                .await?
                .into_inner()
                .keys
            {
                print_sftp_key(k);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            // gRPC errors carry a code + message; print both compactly.
            match e.downcast_ref::<tonic::Status>() {
                Some(s) => eprintln!("error: {:?}: {}", s.code(), s.message()),
                None => eprintln!("error: {e}"),
            }
            ExitCode::FAILURE
        }
    }
}
