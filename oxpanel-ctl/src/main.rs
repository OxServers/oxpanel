//! `oxpanel-ctl` — talk to `oxpanel-daemon` over its UNIX socket.
//!
//! Exit status: 0 on success, 1 on an API error (message on stderr),
//! 2 on usage errors, 3 when `host reconcile` found drift, 4 when
//! `vhost install-deps` ran and the installer failed, or when `cert request`
//! / `cert renew` ran and no certificate was issued; 5 when a backup or
//! restore waited for with `--wait` failed.
//!
//! Database and SFTP passwords are read from standard input, never from arguments.
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

mod essentials;

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
    /// Per-tenant backups and restores (run as jobs).
    #[command(subcommand)]
    Backup(BackupCmd),
    /// Databases and database users of tenants (MariaDB).
    #[command(subcommand)]
    Db(DbCmd),
    /// HTTPS certificates of virtual hosts.
    #[command(subcommand)]
    Cert(CertCmd),
    /// SFTP access of tenants (SSH public keys).
    #[command(subcommand)]
    Sftp(SftpCmd),
    /// Scheduled tasks (cron jobs) of tenants.
    #[command(subcommand)]
    Task(essentials::TaskCmd),
    /// PHP settings of sites, and a tenant's caps on them.
    #[command(subcommand)]
    Php(essentials::PhpCmd),
    /// Backups the engine starts by itself (off, daily, weekly).
    #[command(subcommand)]
    BackupSchedule(essentials::ScheduleCmd),
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
    /// Remove a key by its fingerprint (SHA256:…). Running sessions continue
    /// unless --end-sessions is given.
    RemoveKey {
        username: String,
        fingerprint: String,
        /// Also end the tenant's running SFTP sessions.
        #[arg(long)]
        end_sessions: bool,
    },
    /// Set or replace the tenant's SFTP password, read from standard input
    /// (one line; never pass it as an argument).
    SetPassword { username: String },
    /// Remove the tenant's SFTP password. Running sessions continue unless
    /// --end-sessions is given.
    ClearPassword {
        username: String,
        /// Also end the tenant's running SFTP sessions.
        #[arg(long)]
        end_sessions: bool,
    },
    /// The tenant's keys.
    ListKeys { username: String },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum DbEngineArg {
    Mariadb,
}

impl From<DbEngineArg> for i32 {
    fn from(e: DbEngineArg) -> Self {
        match e {
            DbEngineArg::Mariadb => pb::DatabaseEngine::Mariadb.into(),
        }
    }
}

fn engine_name(raw: i32) -> &'static str {
    match pb::DatabaseEngine::try_from(raw) {
        Ok(pb::DatabaseEngine::Mariadb) => "mariadb",
        Ok(pb::DatabaseEngine::Unspecified) | Err(_) => "unknown",
    }
}

#[derive(Subcommand, Debug)]
enum DbCmd {
    /// Create a database (idempotent). The name is <tenant>_<suffix>.
    Create {
        name: String,
        #[arg(long)]
        tenant: String,
        #[arg(long, value_enum, default_value_t = DbEngineArg::Mariadb)]
        engine: DbEngineArg,
    },
    /// List databases with their size.
    List {
        #[arg(long, default_value = "")]
        tenant: String,
    },
    /// Move a database to its tenant's trash (the name is free at once; it
    /// is purged automatically after the host's trash period).
    Delete {
        name: String,
    },
    /// The tenant's deleted databases, oldest first.
    TrashList {
        tenant: String,
    },
    /// Bring a deleted database back under a NEW name of the same tenant.
    /// It gets no grants.
    TrashRestore {
        tenant: String,
        trash_id: String,
        new_name: String,
    },
    /// Purge one deleted database, or all of the tenant's (no id).
    TrashPurge {
        tenant: String,
        trash_id: Option<String>,
    },
    /// Create a database user. The password is read from standard input
    /// (one line), never from the command line.
    UserCreate {
        name: String,
        #[arg(long)]
        tenant: String,
        #[arg(long, value_enum, default_value_t = DbEngineArg::Mariadb)]
        engine: DbEngineArg,
    },
    UserList {
        #[arg(long, default_value = "")]
        tenant: String,
    },
    /// Replace a user's password, read from standard input (one line).
    UserPasswd {
        name: String,
    },
    UserDelete {
        name: String,
    },
    /// Let a user work in a database of the same tenant.
    Grant {
        user: String,
        database: String,
    },
    Revoke {
        user: String,
        database: String,
    },
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
        /// Delete it with everything it has (sites, databases, SFTP access,
        /// backups that are not retained, the home); needs --confirm.
        #[arg(long)]
        cascade: bool,
        /// With --cascade: the tenant's name again.
        #[arg(long)]
        confirm: Option<String>,
        /// With --cascade: take a final backup first and keep it this many
        /// days (1-366); nothing is deleted unless it completes.
        #[arg(long, default_value_t = 0, requires = "cascade")]
        final_backup_days: u32,
        /// With --cascade: wait for the job; exits with status 5 if it failed.
        #[arg(long, requires = "cascade")]
        wait: bool,
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
    /// Most the database trash may hold, e.g. 1G. 0 = the disk limit.
    #[arg(long, value_parser = parse_size, default_value = "0")]
    db_trash: u64,
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
        /// Redirect plain HTTP to HTTPS (takes effect once a certificate is installed).
        #[arg(long)]
        redirect_https: bool,
        /// Send Strict-Transport-Security over HTTPS. Browsers remember it for a
        /// year: enable only once HTTPS is there to stay.
        #[arg(long)]
        hsts: bool,
        /// Exclude the site from Automatic HTTPS (which otherwise gets it a
        /// certificate by itself when switched on for the host).
        #[arg(long)]
        no_auto_https: bool,
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

#[derive(Subcommand, Debug)]
enum CertCmd {
    /// Install a certificate chain and its private key ("bring your own").
    /// The key is read from a file and sent in the request body.
    Install {
        domain: String,
        /// PEM file: the certificate first, then its intermediates.
        #[arg(long)]
        chain: PathBuf,
        /// PEM file with the unencrypted private key.
        #[arg(long)]
        key: PathBuf,
    },
    /// Remove the certificate; the site is served over HTTP only again.
    Remove { domain: String },
    /// Obtain (or renew now) a certificate from the ACME authority.
    /// Exits with status 4 when none was issued.
    Request { domain: String },
    /// Renew every ACME certificate that is due.
    /// Exits with status 4 when a renewal failed.
    Renew,
    /// Show a virtual host's certificate.
    Show { domain: String },
    /// Automatic HTTPS: certificates for every site without asking.
    #[command(subcommand)]
    Auto(AutoCmd),
}

#[derive(Subcommand, Debug)]
enum AutoCmd {
    /// Run it now: for one site (ignoring back-off) or for every site.
    /// Exits with status 4 when a site is left without a certificate.
    Run { domain: Option<String> },
    /// What it has done and will do, per site.
    Status { domain: Option<String> },
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
            db_trash_max_bytes: l.db_trash,
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
        "tenant={} owner={} uid={} gid={} home={} state={} suspended={} slice={} memory_max={} cpu_weight={} io_weight={} tasks_max={} disk_max={} inodes_max={} sftp_keys={} sftp_password={} created_at={}",
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
        t.sftp_password,
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
        Cmd::Cert(cmd) => run_cert(&mut c, cmd).await?,
        Cmd::Sftp(cmd) => run_sftp(&mut c, cmd).await?,
        Cmd::Db(cmd) => run_db(&mut c, cmd).await?,
        Cmd::Backup(cmd) => run_backup(&mut c, cmd).await?,
        Cmd::Task(cmd) => essentials::run_task(&mut c, cmd).await?,
        Cmd::Php(cmd) => essentials::run_php(&mut c, cmd).await?,
        Cmd::BackupSchedule(cmd) => essentials::run_schedule(&mut c, cmd).await?,
    })
}

/// One line from standard input, without its line ending. A password given
/// as an argument would be visible to every user of the host in `ps`.
fn read_password() -> Result<String, tonic::Status> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| tonic::Status::invalid_argument(format!("reading the password: {e}")))?;
    let password = line.trim_end_matches(['\n', '\r']);
    if password.is_empty() {
        return Err(tonic::Status::invalid_argument(
            "no password on standard input (e.g. `oxpanel-ctl db user-create … < password-file`)",
        ));
    }
    Ok(password.to_owned())
}

fn print_db_user(u: &pb::DatabaseUser) {
    say!(
        "user={} tenant={} engine={} databases={} max_connections={} created_at={}",
        u.name,
        u.tenant,
        engine_name(u.engine),
        if u.databases.is_empty() {
            "-".to_owned()
        } else {
            u.databases.join(",")
        },
        u.max_connections,
        u.created_at.as_ref().map_or(0, |ts| ts.seconds),
    );
}

fn print_database(d: &pb::Database) {
    say!(
        "database={} tenant={} engine={} size={} created_at={}",
        d.name,
        d.tenant,
        engine_name(d.engine),
        d.size_bytes,
        d.created_at.as_ref().map_or(0, |ts| ts.seconds),
    );
}

async fn run_db(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: DbCmd,
) -> Result<ExitCode, tonic::Status> {
    match cmd {
        DbCmd::Create {
            name,
            tenant,
            engine,
        } => {
            let r = c
                .create_database(pb::CreateDatabaseRequest {
                    tenant,
                    name,
                    engine: engine.into(),
                })
                .await?
                .into_inner();
            say!("created={}", r.created);
            if let Some(d) = &r.database {
                print_database(d);
            }
        }
        DbCmd::List { tenant } => {
            for d in &c
                .list_databases(pb::ListDatabasesRequest { tenant })
                .await?
                .into_inner()
                .databases
            {
                print_database(d);
            }
        }
        DbCmd::Delete { name } => {
            let r = c
                .delete_database(pb::DeleteDatabaseRequest { name })
                .await?
                .into_inner();
            if r.trash_id.is_empty() {
                say!("deleted={}", r.deleted);
            } else {
                say!(
                    "deleted={} trash_id={} purge_at={}",
                    r.deleted,
                    r.trash_id,
                    r.purge_at.as_ref().map_or(0, |ts| ts.seconds)
                );
            }
        }
        DbCmd::TrashList { .. } | DbCmd::TrashRestore { .. } | DbCmd::TrashPurge { .. } => {
            run_db_trash(c, cmd).await?;
        }
        DbCmd::UserCreate {
            name,
            tenant,
            engine,
        } => {
            let password = read_password()?;
            let r = c
                .create_database_user(pb::CreateDatabaseUserRequest {
                    tenant,
                    name,
                    password,
                    engine: engine.into(),
                })
                .await?
                .into_inner();
            say!("created={}", r.created);
            if let Some(u) = &r.user {
                print_db_user(u);
            }
        }
        DbCmd::UserList { tenant } => {
            for u in &c
                .list_database_users(pb::ListDatabaseUsersRequest { tenant })
                .await?
                .into_inner()
                .users
            {
                print_db_user(u);
            }
        }
        DbCmd::UserPasswd { name } => {
            let password = read_password()?;
            c.set_database_user_password(pb::SetDatabaseUserPasswordRequest { name, password })
                .await?;
            say!("changed=true");
        }
        DbCmd::UserDelete { name } => {
            let r = c
                .delete_database_user(pb::DeleteDatabaseUserRequest { name })
                .await?
                .into_inner();
            say!("deleted={}", r.deleted);
        }
        DbCmd::Grant { .. } | DbCmd::Revoke { .. } => run_db_access(c, cmd).await?,
    }
    Ok(ExitCode::SUCCESS)
}

fn print_issue(i: &pb::DatabaseObjectIssue) {
    say!(
        "not-recreated kind={} name={} reason={}",
        i.kind,
        i.name,
        i.reason
    );
}

/// `db trash-list`, `db trash-restore` and `db trash-purge`.
async fn run_db_trash(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: DbCmd,
) -> Result<(), tonic::Status> {
    match cmd {
        DbCmd::TrashList { tenant } => {
            let r = c
                .list_database_trash(pb::ListDatabaseTrashRequest { tenant })
                .await?
                .into_inner();
            for t in &r.databases {
                say!(
                    "{} {} size={} deleted_at={} purge_at={} objects={}",
                    t.id,
                    t.name,
                    t.size_bytes,
                    t.deleted_at.as_ref().map_or(0, |ts| ts.seconds),
                    t.purge_at.as_ref().map_or(0, |ts| ts.seconds),
                    t.object_count
                );
            }
            say!("total={} cap={}", r.total_bytes, r.cap_bytes);
        }
        DbCmd::TrashRestore {
            tenant,
            trash_id,
            new_name,
        } => {
            let r = c
                .restore_database_trash(pb::RestoreDatabaseTrashRequest {
                    tenant,
                    trash_id,
                    new_name,
                })
                .await?
                .into_inner();
            say!(
                "restored={}",
                r.database.as_ref().map_or("-", |d| d.name.as_str())
            );
            for i in &r.object_issues {
                print_issue(i);
            }
        }
        DbCmd::TrashPurge { tenant, trash_id } => {
            let r = c
                .purge_database_trash(pb::PurgeDatabaseTrashRequest {
                    tenant,
                    trash_id: trash_id.unwrap_or_default(),
                })
                .await?
                .into_inner();
            say!("purged={}", r.purged);
        }
        _ => {}
    }
    Ok(())
}

/// `db grant` and `db revoke`.
async fn run_db_access(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: DbCmd,
) -> Result<(), tonic::Status> {
    let (changed, user) = match cmd {
        DbCmd::Grant { user, database } => {
            let r = c
                .grant_database_access(pb::GrantDatabaseAccessRequest { user, database })
                .await?
                .into_inner();
            (r.changed, r.user)
        }
        DbCmd::Revoke { user, database } => {
            let r = c
                .revoke_database_access(pb::RevokeDatabaseAccessRequest { user, database })
                .await?
                .into_inner();
            (r.changed, r.user)
        }
        _ => return Ok(()),
    };
    say!("changed={changed}");
    if let Some(u) = &user {
        print_db_user(u);
    }
    Ok(())
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
        cmd @ TenantCmd::Delete { .. } => return delete_tenant(c, cmd).await,
    }
    Ok(ExitCode::SUCCESS)
}

/// `tenant delete`, with or without `--cascade`.
async fn delete_tenant(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: TenantCmd,
) -> Result<ExitCode, tonic::Status> {
    let TenantCmd::Delete {
        username,
        remove_home,
        cascade,
        confirm,
        final_backup_days,
        wait,
    } = cmd
    else {
        return Ok(ExitCode::SUCCESS);
    };
    let r = c
        .delete_tenant(pb::DeleteTenantRequest {
            username,
            remove_home,
            cascade,
            confirm_username: confirm.unwrap_or_default(),
            final_backup_retain_days: final_backup_days,
        })
        .await?
        .into_inner();
    if !cascade {
        say!("deleted={}", r.deleted);
    } else if let Some(job) = r.job {
        say!("started={}", r.started);
        return follow_job(c, job, wait).await;
    } else {
        say!("deleted=false");
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
            redirect_https,
            hsts,
            no_auto_https,
        } => {
            let r = c
                .configure_virtual_host(pb::ConfigureVirtualHostRequest {
                    redirect_https,
                    hsts,
                    auto_https_opt_out: no_auto_https,
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

/// One line about a virtual host's certificate (`certificate=-` when none).
fn print_certificate(v: &pb::VirtualHost) {
    let Some(c) = &v.certificate else {
        say!(
            "domain={} certificate=- auto_https={}",
            v.domain,
            if v.auto_https_opt_out { "off" } else { "on" }
        );
        return;
    };
    let not_before = c.not_before.as_ref().map_or(0, |t| t.seconds);
    let not_after = c.not_after.as_ref().map_or(0, |t| t.seconds);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let source = match pb::CertificateSource::try_from(c.source) {
        Ok(pb::CertificateSource::Uploaded) => "uploaded",
        Ok(pb::CertificateSource::Acme) => "acme",
        _ => "unknown",
    };
    let list = |names: &[String]| {
        if names.is_empty() {
            "-".to_owned()
        } else {
            names.join(",")
        }
    };
    say!(
        "domain={} certificate=present source={} not_before={} not_after={} expires_in_days={} names={} uncovered={} redirect_https={} hsts={} auto_https={} issuer={}",
        v.domain,
        source,
        not_before,
        not_after,
        not_after.saturating_sub(now).div_euclid(86_400),
        list(&c.names),
        list(&c.uncovered_names),
        v.redirect_https,
        v.hsts,
        if v.auto_https_opt_out { "off" } else { "on" },
        c.issuer,
    );
}

/// One line per site, then one indented line per skipped name.
fn print_auto_https(s: &pb::AutoHttpsStatus) {
    let state = pb::AutoHttpsState::try_from(s.state).map_or("unknown", |k| {
        k.as_str_name().trim_start_matches("AUTO_HTTPS_STATE_")
    });
    let list = |names: &[String]| {
        if names.is_empty() {
            "-".to_owned()
        } else {
            names.join(",")
        }
    };
    let when = |t: Option<i64>| t.map_or_else(|| "-".to_owned(), |t| t.to_string());
    say!(
        "domain={} auto_https={} covered={} pending={} skipped={} last_attempt={} next_attempt={} last_error={}",
        s.domain,
        state.to_ascii_lowercase(),
        list(&s.covered_names),
        list(&s.pending_names),
        list(&s.skipped.iter().map(|k| k.name.clone()).collect::<Vec<_>>()),
        when(s.last_attempt.as_ref().map(|t| t.seconds)),
        when(s.next_attempt.as_ref().map(|t| t.seconds)),
        if s.last_error.is_empty() { "-" } else { s.last_error.as_str() },
    );
    for k in &s.skipped {
        say!(
            "  skipped name={} failures={} next_attempt={} reason={}",
            k.name,
            k.failures,
            when(k.next_attempt.as_ref().map(|t| t.seconds)),
            k.reason
        );
    }
}

/// `cert auto run|status`.
async fn run_cert_auto(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: AutoCmd,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match cmd {
        AutoCmd::Run { domain } => {
            let r = c
                .run_auto_https(pb::RunAutoHttpsRequest {
                    domain: domain.unwrap_or_default(),
                })
                .await?
                .into_inner();
            let mut failed = false;
            for s in &r.sites {
                print_auto_https(s);
                failed |= s.state == i32::from(pb::AutoHttpsState::Failed);
            }
            if failed {
                return Ok(ExitCode::from(EXIT_INSTALL_FAILED));
            }
        }
        AutoCmd::Status { domain } => {
            for s in &c
                .get_auto_https_status(pb::GetAutoHttpsStatusRequest {
                    domain: domain.unwrap_or_default(),
                })
                .await?
                .into_inner()
                .sites
            {
                print_auto_https(s);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn run_cert(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: CertCmd,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match cmd {
        CertCmd::Install { domain, chain, key } => {
            let certificate_chain_pem = std::fs::read_to_string(&chain)
                .map_err(|e| format!("cannot read {}: {e}", chain.display()))?;
            let private_key_pem = std::fs::read_to_string(&key)
                .map_err(|e| format!("cannot read {}: {e}", key.display()))?;
            let r = c
                .install_certificate(pb::InstallCertificateRequest {
                    domain,
                    certificate_chain_pem,
                    private_key_pem,
                })
                .await?
                .into_inner();
            say!("changed={}", r.changed);
            if let Some(v) = &r.vhost {
                print_certificate(v);
            }
        }
        CertCmd::Remove { domain } => {
            let r = c
                .remove_certificate(pb::RemoveCertificateRequest { domain })
                .await?
                .into_inner();
            say!("removed={}", r.removed);
        }
        CertCmd::Request { domain } => {
            let r = c
                .request_certificate(pb::RequestCertificateRequest { domain })
                .await?
                .into_inner();
            for line in r.output.lines() {
                say!("{line}");
            }
            say!("succeeded={}", r.succeeded);
            if let Some(v) = &r.vhost {
                print_certificate(v);
            }
            if !r.succeeded {
                return Ok(ExitCode::from(EXIT_INSTALL_FAILED));
            }
        }
        CertCmd::Renew => {
            let r = c
                .renew_certificates(pb::RenewCertificatesRequest {})
                .await?
                .into_inner();
            say!("renewals={}", r.renewals.len());
            let mut failed = false;
            for n in &r.renewals {
                say!("domain={} succeeded={}", n.domain, n.succeeded);
                if !n.succeeded {
                    failed = true;
                    for line in n.output.lines() {
                        say!("  {line}");
                    }
                }
            }
            if failed {
                return Ok(ExitCode::from(EXIT_INSTALL_FAILED));
            }
        }
        CertCmd::Auto(cmd) => return run_cert_auto(c, cmd).await,
        CertCmd::Show { domain } => {
            let vhosts = c
                .list_virtual_hosts(pb::ListVirtualHostsRequest {
                    tenant: String::new(),
                })
                .await?
                .into_inner()
                .vhosts;
            let v = vhosts
                .iter()
                .find(|v| v.domain == domain)
                .ok_or_else(|| tonic::Status::not_found(format!("no virtual host {domain}")))?;
            print_certificate(v);
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
                "version={} selinux={} php={} node={} node_version={} python={} sftp={} sftp_passwords={} disk_quota={} dry_run={} tenants={} vhosts={} uid_range={}-{} load={:.2},{:.2},{:.2} memory_total={} memory_free={} home_disk_total={} home_disk_free={} uptime={} backup_disk_total={} backup_disk_free={} backup_keep={} db_trash_days={} tls={} acme={} acme_directory={} auto_https={}",
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
                i.sftp_passwords_allowed,
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
                i.backup_disk_total_bytes,
                i.backup_disk_free_bytes,
                i.backup_keep,
                i.database_trash_days,
                // Last on the line: scripts match `auto_https=…$`.
                i.tls_available,
                i.acme_available,
                i.acme_directory_url,
                i.auto_https_enabled,
            );
            say!("disk_quota_detail={}", i.disk_quota_detail);
            essentials::print_host_info(&i);
            // One line per database engine.
            for e in &i.database_engines {
                say!(
                    "database_engine={} available={} version={} databases={} database_users={}",
                    engine_name(e.engine),
                    e.available,
                    if e.version.is_empty() {
                        "-"
                    } else {
                        e.version.as_str()
                    },
                    e.database_count,
                    e.database_user_count,
                );
            }
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
            end_sessions,
        } => {
            let r = c
                .remove_sftp_key(pb::RemoveSftpKeyRequest {
                    username,
                    fingerprint,
                    end_sessions,
                })
                .await?
                .into_inner();
            say!("removed=true remaining={}", r.remaining);
        }
        SftpCmd::SetPassword { username } => {
            let mut input = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)
                .map_err(|e| format!("reading the password from stdin: {e}"))?;
            // One line: its terminating newline is not part of the password.
            let line = input.strip_suffix('\n').unwrap_or(&input);
            let password = line.strip_suffix('\r').unwrap_or(line).to_owned();
            let r = c
                .set_sftp_password(pb::SetSftpPasswordRequest { username, password })
                .await?
                .into_inner();
            say!("password=set");
            if let Some(t) = &r.tenant {
                print_tenant(t);
            }
        }
        SftpCmd::ClearPassword {
            username,
            end_sessions,
        } => {
            let r = c
                .clear_sftp_password(pb::ClearSftpPasswordRequest {
                    username,
                    end_sessions,
                })
                .await?
                .into_inner();
            say!("cleared={}", r.cleared);
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

#[derive(Subcommand, Debug)]
enum BackupCmd {
    /// Start a backup of a tenant; prints the job.
    Create {
        tenant: String,
        /// Keep this backup for 1-12 months whatever the retention count
        /// says, also after the tenant is deleted (e.g. a final backup).
        #[arg(long, default_value_t = 0)]
        retain_months: u32,
        /// The same in days, 1-366 (not together with --retain-months).
        #[arg(long, default_value_t = 0)]
        retain_days: u32,
        /// Wait for the job to finish; exits with status 5 if it failed.
        #[arg(long)]
        wait: bool,
    },
    /// Keep a complete backup for 1-12 months or 1-366 days from now (also
    /// after the tenant is deleted); then the engine removes it.
    Retain {
        tenant: String,
        backup_id: String,
        #[arg(long, default_value_t = 0)]
        months: u32,
        #[arg(long, default_value_t = 0)]
        days: u32,
    },
    /// Restore one database of one of the tenant's backups under a NEW name
    /// of the tenant; prints the job.
    RestoreDb {
        tenant: String,
        backup_id: String,
        database: String,
        new_name: String,
        /// Wait for the job to finish; exits with status 5 if it failed.
        #[arg(long)]
        wait: bool,
    },
    /// Restore one database of a retained backup of a DELETED tenant into an
    /// existing tenant, under a new name of that tenant.
    RestoreRetainedDb {
        backup_id: String,
        /// The deleted tenant the backup was taken from.
        #[arg(long)]
        from: String,
        /// The existing tenant that receives the database.
        #[arg(long)]
        to: String,
        database: String,
        new_name: String,
        /// Wait for the job to finish; exits with status 5 if it failed.
        #[arg(long)]
        wait: bool,
    },
    /// Every retained backup, including those of deleted tenants.
    ListRetained,
    /// Restore a retained backup of a DELETED tenant into an existing tenant.
    RestoreRetained {
        backup_id: String,
        /// The deleted tenant the backup was taken from.
        #[arg(long)]
        from: String,
        /// The existing tenant that receives the files.
        #[arg(long)]
        to: String,
        #[command(flatten)]
        existing: ExistingArg,
        /// Wait for the job to finish; exits with status 5 if it failed.
        #[arg(long)]
        wait: bool,
    },
    /// The tenant's backups, oldest first.
    List { tenant: String },
    /// Delete one of the tenant's backups.
    Delete {
        tenant: String,
        backup_id: String,
        /// The backup is a retained backup of the deleted tenant `tenant`.
        #[arg(long)]
        tenant_deleted: bool,
    },
    /// Restore the tenant's home from one of its own backups; prints the job.
    /// One of --overwrite / --keep-existing is required.
    Restore {
        tenant: String,
        backup_id: String,
        #[command(flatten)]
        existing: ExistingArg,
        /// Wait for the job to finish; exits with status 5 if it failed.
        #[arg(long)]
        wait: bool,
    },
    /// State of a backup or restore job.
    Job {
        job_id: String,
        /// Wait for the job to finish; exits with status 5 if it failed.
        #[arg(long)]
        wait: bool,
    },
}

/// What a restore does with files that already exist: a required choice.
#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
struct ExistingArg {
    /// Files in the backup replace existing ones.
    #[arg(long)]
    overwrite: bool,
    /// Existing files are left untouched; only missing ones are restored.
    #[arg(long)]
    keep_existing: bool,
}

impl ExistingArg {
    fn value(&self) -> i32 {
        if self.keep_existing {
            pb::OnExisting::Keep.into()
        } else {
            pb::OnExisting::Overwrite.into()
        }
    }
}

/// Exit status of `backup … --wait` when the job failed.
const EXIT_JOB_FAILED: u8 = 5;

fn print_job(j: &pb::Job) {
    let kind = pb::JobKind::try_from(j.kind).map_or("unknown", |k| k.as_str_name());
    let state = pb::JobState::try_from(j.state).map_or("unknown", |s| s.as_str_name());
    say!(
        "job={} kind={} tenant={} backup={} state={} started_at={} finished_at={} message={}",
        j.id,
        kind,
        j.tenant,
        j.backup_id,
        state,
        j.started_at.as_ref().map_or(0, |ts| ts.seconds),
        j.finished_at.as_ref().map_or(0, |ts| ts.seconds),
        if j.message.is_empty() {
            "-"
        } else {
            j.message.as_str()
        },
    );
    for (key, value) in [
        ("database", &j.database),
        ("new_name", &j.new_name),
        ("phase", &j.phase),
    ] {
        if !value.is_empty() {
            say!("{key}={value}");
        }
    }
    for i in &j.object_issues {
        print_issue(i);
    }
}

fn print_backup(b: &pb::Backup) {
    let state = pb::BackupState::try_from(b.state).map_or("unknown", |s| s.as_str_name());
    let members: Vec<String> = b
        .members
        .iter()
        .map(|m| format!("{}:{}:{}", m.kind, m.name, m.size_bytes))
        .collect();
    say!(
        "backup={} tenant={}{} state={} created_at={} retain_until={} size={} domains={} members={} excluded={}",
        b.id,
        b.tenant,
        if b.tenant_deleted { " tenant_deleted=true" } else { "" },
        state,
        b.created_at.as_ref().map_or(0, |ts| ts.seconds),
        b.retain_until.as_ref().map_or(0, |ts| ts.seconds),
        b.size_bytes,
        if b.domains.is_empty() {
            "-".to_owned()
        } else {
            b.domains.join(",")
        },
        if members.is_empty() {
            "-".to_owned()
        } else {
            members.join(",")
        },
        b.excluded_count,
    );
    for d in &b.databases {
        say!(
            "  database {} size={} dump={} objects={}",
            d.name,
            d.size_bytes,
            d.dump_member,
            d.objects_member
        );
    }
}

/// Print the job; with `wait`, poll it until it has ended, then print its
/// output and the final state.
async fn follow_job(
    c: &mut OxPanelEngineClient<Channel>,
    mut job: pb::Job,
    wait: bool,
) -> Result<ExitCode, tonic::Status> {
    let running = |j: &pb::Job| j.state == i32::from(pb::JobState::Running);
    if wait {
        while running(&job) {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            job = c
                .get_job(pb::GetJobRequest {
                    job_id: job.id.clone(),
                })
                .await?
                .into_inner();
        }
    }
    for line in job.output.lines() {
        say!("{line}");
    }
    if job.kind == i32::from(pb::JobKind::Restore) && !running(&job) {
        say!(
            "restored_entries={} skipped_entries={}",
            job.restored_entries,
            job.skipped_entries
        );
        for site in &job.sites {
            say!(
                "site={} dependencies_ok={} detail={}",
                site.domain,
                site.succeeded,
                site.detail
            );
        }
    }
    print_job(&job);
    if job.state == i32::from(pb::JobState::Failed) {
        return Ok(ExitCode::from(EXIT_JOB_FAILED));
    }
    Ok(ExitCode::SUCCESS)
}

/// Print whether a job was started, then follow it like `follow_job`.
async fn follow_start(
    c: &mut OxPanelEngineClient<Channel>,
    r: pb::StartJobResponse,
    wait: bool,
) -> Result<ExitCode, tonic::Status> {
    say!("started={}", r.started);
    match r.job {
        Some(job) => follow_job(c, job, wait).await,
        None => Err(tonic::Status::internal("no job in the response")),
    }
}

/// The operator's commands for retained backups.
async fn run_retained(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: BackupCmd,
) -> Result<ExitCode, tonic::Status> {
    match cmd {
        BackupCmd::Retain {
            tenant,
            backup_id,
            months,
            days,
        } => {
            let b = c
                .retain_backup(pb::RetainBackupRequest {
                    tenant,
                    backup_id,
                    retain_months: months,
                    retain_days: days,
                })
                .await?
                .into_inner();
            print_backup(&b);
        }
        BackupCmd::ListRetained => {
            for b in &c
                .list_retained_backups(pb::ListRetainedBackupsRequest {})
                .await?
                .into_inner()
                .backups
            {
                print_backup(b);
            }
        }
        BackupCmd::RestoreRetained {
            backup_id,
            from,
            to,
            existing,
            wait,
        } => {
            let r = c
                .restore_retained_backup(pb::RestoreRetainedBackupRequest {
                    backup_id,
                    source_tenant: from,
                    target_tenant: to,
                    on_existing: existing.value(),
                })
                .await?
                .into_inner();
            return follow_start(c, r, wait).await;
        }
        BackupCmd::RestoreRetainedDb {
            backup_id,
            from,
            to,
            database,
            new_name,
            wait,
        } => {
            let r = c
                .restore_retained_backup_database(pb::RestoreRetainedBackupDatabaseRequest {
                    backup_id,
                    source_tenant: from,
                    target_tenant: to,
                    database,
                    new_name,
                })
                .await?
                .into_inner();
            return follow_start(c, r, wait).await;
        }
        _ => {}
    }
    Ok(ExitCode::SUCCESS)
}

async fn run_backup(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: BackupCmd,
) -> Result<ExitCode, tonic::Status> {
    match cmd {
        BackupCmd::Create {
            tenant,
            retain_months,
            retain_days,
            wait,
        } => {
            let r = c
                .create_backup(pb::CreateBackupRequest {
                    tenant,
                    retain_months,
                    retain_days,
                })
                .await?
                .into_inner();
            return follow_start(c, r, wait).await;
        }
        BackupCmd::Restore {
            tenant,
            backup_id,
            existing,
            wait,
        } => {
            let r = c
                .restore_backup(pb::RestoreBackupRequest {
                    tenant,
                    backup_id,
                    on_existing: existing.value(),
                })
                .await?
                .into_inner();
            return follow_start(c, r, wait).await;
        }
        BackupCmd::RestoreDb {
            tenant,
            backup_id,
            database,
            new_name,
            wait,
        } => {
            let r = c
                .restore_backup_database(pb::RestoreBackupDatabaseRequest {
                    tenant,
                    backup_id,
                    database,
                    new_name,
                })
                .await?
                .into_inner();
            return follow_start(c, r, wait).await;
        }
        BackupCmd::Job { job_id, wait } => {
            let job = c.get_job(pb::GetJobRequest { job_id }).await?.into_inner();
            return follow_job(c, job, wait).await;
        }
        BackupCmd::List { tenant } => {
            for b in &c
                .list_backups(pb::ListBackupsRequest { tenant })
                .await?
                .into_inner()
                .backups
            {
                print_backup(b);
            }
        }
        cmd @ (BackupCmd::Retain { .. }
        | BackupCmd::ListRetained
        | BackupCmd::RestoreRetained { .. }
        | BackupCmd::RestoreRetainedDb { .. }) => return run_retained(c, cmd).await,
        BackupCmd::Delete {
            tenant,
            backup_id,
            tenant_deleted,
        } => {
            let r = c
                .delete_backup(pb::DeleteBackupRequest {
                    tenant,
                    backup_id,
                    tenant_deleted,
                })
                .await?
                .into_inner();
            say!("deleted={}", r.deleted);
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
