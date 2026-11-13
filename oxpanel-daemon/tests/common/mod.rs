//! Shared harness for the integration tests: a sandboxed configuration, a
//! fault-injecting [`System`], an in-process daemon on a real UNIX socket, and
//! a raw HTTP/2 client that can send what no well-behaved gRPC client would.
#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::field_reassign_with_default,
    clippy::missing_panics_doc,
    unreachable_pub
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;
use tonic::codegen::http::Uri;
use tonic::transport::{Channel, Endpoint, Server};
use tower::service_fn;

use oxpanel_daemon::auth::{self, PeerPolicy, Scope};
use oxpanel_daemon::config::Config;
use oxpanel_daemon::ctx::Ctx;
use oxpanel_daemon::host::HostService;
use oxpanel_daemon::records::TenantState;
use oxpanel_daemon::server::Engine;
use oxpanel_daemon::system::{
    bin, CommandOutput, CommandSpec, FakeSystem, HostStats, OsUser, PasswordState, QuotaState,
    System,
};
use oxpanel_daemon::tenant::TenantService;
use oxpanel_daemon::vhost::VHostService;
use oxpanel_daemon::{app, nginx, php, vhost, Result};
use oxpanel_proto::v1::ox_panel_engine_client::OxPanelEngineClient;

/// What the fault-injecting system does to the `n`-th external command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    None,
    /// The command is not executed and reports exit status 1.
    FailAt(usize),
    /// The daemon "dies" just before the command would have run.
    KillBefore(usize),
    /// The command runs to completion; the daemon "dies" before seeing the result.
    KillAfter(usize),
}

/// A [`System`] that forwards to a [`FakeSystem`] and can delay, fail or
/// freeze (= the process was killed there) a chosen command.
#[derive(Debug)]
pub struct Chaos {
    pub fake: Arc<FakeSystem>,
    counter: AtomicUsize,
    fault: Mutex<Fault>,
    hit: AtomicBool,
    reached: Notify,
    delays: Mutex<Vec<(&'static str, Duration)>>,
}

impl Chaos {
    pub fn new() -> Self {
        Self {
            fake: Arc::new(FakeSystem::new()),
            counter: AtomicUsize::new(0),
            fault: Mutex::new(Fault::None),
            hit: AtomicBool::new(false),
            reached: Notify::new(),
            delays: Mutex::new(Vec::new()),
        }
    }

    /// Arm a fault; command numbering restarts at 0.
    pub fn arm(&self, fault: Fault) {
        *self.fault.lock().unwrap() = fault;
        self.counter.store(0, Ordering::SeqCst);
        self.hit.store(false, Ordering::SeqCst);
    }

    /// Whether the armed fault was reached.
    pub fn was_hit(&self) -> bool {
        self.hit.load(Ordering::SeqCst)
    }

    /// Resolves once a `Kill*` fault froze the workflow.
    pub async fn killed(&self) {
        self.reached.notified().await;
    }

    /// Make every invocation of `program` take at least `delay`.
    pub fn delay(&self, program: &'static str, delay: Duration) {
        self.delays.lock().unwrap().push((program, delay));
    }
}

#[tonic::async_trait]
impl System for Chaos {
    async fn run(&self, spec: CommandSpec) -> Result<CommandOutput> {
        let idx = self.counter.fetch_add(1, Ordering::SeqCst);
        let delay = self
            .delays
            .lock()
            .unwrap()
            .iter()
            .find(|(p, _)| *p == spec.program)
            .map(|(_, d)| *d);
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        let fault = *self.fault.lock().unwrap();
        match fault {
            Fault::FailAt(k) if k == idx => {
                self.hit.store(true, Ordering::SeqCst);
                Ok(CommandOutput {
                    program: spec.program,
                    code: Some(1),
                    stdout: Vec::new(),
                    stderr: b"injected failure".to_vec(),
                })
            }
            Fault::KillBefore(k) if k == idx => {
                self.hit.store(true, Ordering::SeqCst);
                self.reached.notify_one();
                std::future::pending().await
            }
            Fault::KillAfter(k) if k == idx => {
                let _ = self.fake.run(spec).await;
                self.hit.store(true, Ordering::SeqCst);
                self.reached.notify_one();
                std::future::pending().await
            }
            _ => self.fake.run(spec).await,
        }
    }

    async fn user_by_name(&self, name: &str) -> Result<Option<OsUser>> {
        self.fake.user_by_name(name).await
    }
    async fn user_by_uid(&self, uid: u32) -> Result<Option<OsUser>> {
        self.fake.user_by_uid(uid).await
    }
    async fn group_by_name(&self, name: &str) -> Result<Option<u32>> {
        self.fake.group_by_name(name).await
    }
    async fn groups_of(&self, name: &str, primary_gid: u32) -> Result<Vec<u32>> {
        self.fake.groups_of(name, primary_gid).await
    }
    async fn ensure_private_dir(&self, path: &Path, uid: u32, gid: u32) -> Result<()> {
        self.fake.ensure_private_dir(path, uid, gid).await
    }
    async fn verify_owned_dir(&self, path: &Path, uid: u32) -> Result<()> {
        self.fake.verify_owned_dir(path, uid).await
    }
    async fn inspect_private_dir(&self, path: &Path, uid: u32, gid: u32) -> Result<Option<String>> {
        self.fake.inspect_private_dir(path, uid, gid).await
    }
    async fn is_installed(&self, program: &'static str) -> bool {
        self.fake.is_installed(program).await
    }
    async fn host_stats(&self, path: &Path) -> Result<HostStats> {
        self.fake.host_stats(path).await
    }
    async fn quota_state(&self, path: &Path) -> Result<QuotaState> {
        self.fake.quota_state(path).await
    }
    async fn password_state(&self, user: &str) -> Result<PasswordState> {
        self.fake.password_state(user).await
    }
}

/// A configuration whose every path lives in a fresh temporary directory.
pub fn sandbox_config(dir: &Path) -> Config {
    let mut cfg = Config::default();
    cfg.state_dir = dir.join("state");
    cfg.home_base = dir.join("home");
    cfg.systemd_unit_dir = dir.join("systemd");
    cfg.nginx_log_dir = dir.join("log");
    cfg.php_conf_dir = dir.join("php");
    cfg.nginx_conf_dir = dir.join("nginx").join("oxpanel.d");
    cfg.nginx_include_file = dir.join("nginx").join("conf.d").join("00-oxpanel.conf");
    cfg.socket_path = dir.join("oxpanel.sock");
    // The feature streams' own locations (defaults under /etc and /var/lib).
    cfg.tls_dir = dir.join("pki");
    cfg.acme_dir = dir.join("acme");
    cfg.sftp_keys_dir = dir.join("sftp-keys");
    cfg.sshd_dropin_file = dir.join("sshd_config.d").join("60-oxpanel.conf");
    cfg.backup_dir = dir.join("backups");
    for d in [
        &cfg.home_base,
        &cfg.systemd_unit_dir,
        &dir.join("nginx").join("conf.d"),
        &dir.join("sshd_config.d"),
    ] {
        std::fs::create_dir_all(d).expect("mkdir");
    }
    cfg
}

/// The three services of one daemon "process".
#[derive(Debug, Clone)]
pub struct Services {
    pub ctx: Ctx,
    pub tenants: TenantService,
    pub vhosts: VHostService,
    pub host: HostService,
}

/// The persistent world a daemon lives in: its directories and the (fake)
/// operating system. [`World::boot`] is a daemon start; calling it again is a
/// restart on the same state.
#[derive(Debug)]
pub struct World {
    pub dir: tempfile::TempDir,
    pub config: Config,
    pub chaos: Arc<Chaos>,
    pub selinux: bool,
}

impl World {
    pub fn new(selinux: bool) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = sandbox_config(dir.path());
        Self {
            dir,
            config,
            chaos: Arc::new(Chaos::new()),
            selinux,
        }
    }

    /// Start (or restart) the daemon: what `main` does before it serves.
    pub async fn boot(&self) -> Services {
        let ctx = Ctx::new(self.config.clone(), self.chaos.clone(), self.selinux);
        ctx.store.init().expect("store init");
        nginx::ensure_include(
            ctx.sys.as_ref(),
            &ctx.config.nginx_conf_dir,
            &ctx.config.nginx_include_file,
            ctx.config.nginx_default_server,
            ctx.config.command_timeout,
        )
        .await
        .expect("nginx include");
        // main() only logs a failure here; so do we.
        let _ = vhost::converge_all(&ctx).await;
        let _ = oxpanel_daemon::sftp::converge_all(&ctx).await;
        Services {
            tenants: TenantService::new(ctx.clone()),
            vhosts: VHostService::new(ctx.clone()),
            host: HostService::new(ctx.clone()),
            ctx,
        }
    }
}

fn argv(c: &CommandSpec) -> Vec<String> {
    c.args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

/// Units the fake systemd would be running, derived from the complete
/// history of `systemctl` calls (`restart`, `enable --now`, `disable --now`).
pub fn running_units(fake: &FakeSystem) -> BTreeSet<String> {
    let mut running = BTreeSet::new();
    for call in fake.calls_to(bin::SYSTEMCTL) {
        let args = argv(&call);
        let Some(unit) = args.last().filter(|u| u.ends_with(".service")).cloned() else {
            continue;
        };
        if unit == "nginx.service" {
            continue;
        }
        let now = args.iter().any(|a| a == "--now");
        match (args.first().map(String::as_str), now) {
            (Some("restart" | "start"), _) | (Some("enable"), true) => {
                running.insert(unit);
            }
            (Some("stop"), _) | (Some("disable"), true) => {
                running.remove(&unit);
            }
            _ => {}
        }
    }
    running
}

/// Units that should be running according to the records: the PHP instance of
/// every active tenant with a PHP site, and every application of an active tenant.
pub fn expected_units(s: &Services) -> BTreeSet<String> {
    let tenants: BTreeMap<String, bool> = s
        .ctx
        .store
        .list_tenants()
        .expect("list tenants")
        .into_iter()
        .map(|t| (t.username, t.state == TenantState::Ready && !t.suspended))
        .collect();
    let mut out = BTreeSet::new();
    for v in s.ctx.store.list_vhosts().expect("list vhosts") {
        if tenants.get(&v.tenant) != Some(&true) {
            continue;
        }
        if v.php {
            let name = oxpanel_daemon::validate::Username::parse(&v.tenant).expect("tenant name");
            out.insert(php::unit_name(&name));
        }
        if v.app.is_some() {
            let domain = oxpanel_daemon::validate::Domain::parse(&v.domain).expect("domain");
            out.insert(app::unit_name(&domain));
        }
    }
    out
}

/// The invariant every test ends on: records, files, accounts and running
/// services agree, and nothing is left over in OxPanel's directories.
pub async fn assert_consistent(w: &World, s: &Services, context: &str) {
    let drifts = s.host.reconcile().await.expect("reconcile");
    assert!(drifts.is_empty(), "{context}: reconcile found {drifts:#?}");
    assert_eq!(
        running_units(&w.chaos.fake),
        expected_units(s),
        "{context}: running services differ from what the records call for"
    );
    let recorded: BTreeSet<String> = s
        .ctx
        .store
        .list_tenants()
        .expect("list tenants")
        .into_iter()
        .map(|t| t.username)
        .collect();
    let accounts: BTreeSet<String> = w.chaos.fake.users().into_iter().map(|u| u.name).collect();
    assert_eq!(
        recorded, accounts,
        "{context}: tenant records and accounts differ"
    );
    for dir in [
        &w.config.tenants_dir(),
        &w.config.vhosts_dir(),
        &w.config.nginx_conf_dir,
        &w.config.systemd_unit_dir,
        &w.config.php_conf_dir,
    ] {
        let Ok(rd) = std::fs::read_dir(dir) else {
            continue;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            assert!(
                !name.starts_with(".oxpanel-"),
                "{context}: temporary file {name} left in {}",
                dir.display()
            );
        }
    }
}

// ---------------------------------------------------------------- gRPC server

#[derive(Debug)]
pub struct TestServer {
    pub world: World,
    pub services: Services,
    pub socket: PathBuf,
}

impl TestServer {
    pub fn fake(&self) -> &FakeSystem {
        &self.world.chaos.fake
    }
}

pub fn my_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

pub fn allow_me() -> PeerPolicy {
    PeerPolicy::new([my_uid()].into_iter().collect(), BTreeSet::new(), false)
}

pub fn allow_nobody() -> PeerPolicy {
    PeerPolicy::new(BTreeSet::new(), BTreeSet::new(), false)
}

/// A real tonic server on a UNIX socket behind the real peer gate, with the
/// same transport limits as `main`. `scopes`: `None` = the caller is
/// unrestricted, `Some(set)` = the caller is confined to exactly that set.
pub async fn serve(policy: PeerPolicy, scopes: Option<&[Scope]>) -> TestServer {
    let mut world = World::new(false);
    if let Some(scopes) = scopes {
        world
            .config
            .peer_scopes
            .insert(my_uid(), scopes.iter().copied().collect());
    }
    let services = world.boot().await;
    world.chaos.fake.clear_calls();
    let socket = world.config.socket_path.clone();
    let listener = UnixListener::bind(&socket).expect("bind");
    let incoming = auth::gate(listener, Arc::new(policy), services.ctx.sys.clone());
    let engine = Engine::new(services.ctx.clone());
    tokio::spawn(async move {
        Server::builder()
            .timeout(Duration::from_secs(300))
            .concurrency_limit_per_connection(16)
            .max_concurrent_streams(16)
            .add_service(engine.into_service())
            .serve_with_incoming(incoming)
            .await
            .expect("serve");
    });
    TestServer {
        world,
        services,
        socket,
    }
}

pub async fn connect(
    socket: &Path,
) -> std::result::Result<OxPanelEngineClient<Channel>, tonic::transport::Error> {
    let path = socket.to_owned();
    let channel = Endpoint::try_from("http://oxpanel.local")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await?;
    Ok(OxPanelEngineClient::new(channel))
}

// ---------------------------------------------------------------- raw client

/// What came back from a hand-made HTTP/2 request.
#[derive(Debug, Clone)]
pub struct RawReply {
    pub http_status: u16,
    /// `grpc-status`, from the trailers or (trailers-only reply) the headers.
    pub grpc_status: Option<i32>,
    pub grpc_message: String,
    pub body: Bytes,
}

/// One length-prefixed gRPC message.
pub fn frame(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 5);
    out.push(0);
    out.extend_from_slice(&u32::try_from(message.len()).expect("length").to_be_bytes());
    out.extend_from_slice(message);
    out
}

/// POST `body` (sent exactly as given) to `/oxpanel.v1.OxPanelEngine/<method>`.
/// `Err` means the transport failed (the peer was cut off, the stream reset).
pub async fn raw_call(
    socket: &Path,
    method: &str,
    body: Vec<u8>,
) -> std::result::Result<RawReply, String> {
    raw_request(
        socket,
        &format!("/oxpanel.v1.OxPanelEngine/{method}"),
        "application/grpc",
        body,
    )
    .await
}

pub async fn raw_request(
    socket: &Path,
    path: &str,
    content_type: &str,
    body: Vec<u8>,
) -> std::result::Result<RawReply, String> {
    let stream = UnixStream::connect(socket)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|e| format!("handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("http://oxpanel.local{path}"))
        .header("content-type", content_type)
        .header("te", "trailers")
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| format!("request: {e}"))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| format!("send: {e}"))?;
    let http_status = resp.status().as_u16();
    let header = |h: &hyper::HeaderMap, k: &str| {
        h.get(k)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned)
    };
    let mut grpc_status = header(resp.headers(), "grpc-status");
    let mut grpc_message = header(resp.headers(), "grpc-message");
    let collected = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("body: {e}"))?;
    if let Some(t) = collected.trailers() {
        grpc_status = header(t, "grpc-status").or(grpc_status);
        grpc_message = header(t, "grpc-message").or(grpc_message);
    }
    Ok(RawReply {
        http_status,
        grpc_status: grpc_status.and_then(|s| s.parse().ok()),
        grpc_message: grpc_message.unwrap_or_default(),
        body: collected.to_bytes(),
    })
}

/// Every `rpc` declared in the service definition, in declaration order.
pub fn rpcs_in_proto() -> Vec<String> {
    let proto = include_str!("../../../proto/oxpanel/v1/panel.proto");
    proto
        .lines()
        .filter_map(|l| {
            let l = l.trim_start();
            let rest = l.strip_prefix("rpc ")?;
            Some(rest.split('(').next()?.trim().to_owned())
        })
        .collect()
}
