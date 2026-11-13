//! `make bench` — how fast is the engine, and how does it degrade with scale?
//!
//! Runs the real daemon code (records on disk, rendering, the gRPC server on
//! a UNIX socket behind the peer gate) against the in-memory fake operating
//! system, so the numbers are the *engine's own* cost: what remains when
//! `useradd`, `nginx -t` and `systemctl` take no time. The cost of those
//! tools on a real host is measured separately by acceptance phase 90.
//!
//! ```text
//! make bench                         # 1,000 and 10,000 tenants, 5,000 virtual hosts
//! make bench ARGS="--tenants 500 --vhosts 1000 --seconds 2"
//! OXPANEL_BENCH_DIR=/dev/shm make bench   # state on tmpfs: isolates CPU cost from fsync
//! ```
//!
//! Output is Markdown, ready for `docs/PERFORMANCE.md`.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::field_reassign_with_default,
    clippy::too_many_lines
)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper_util::rt::TokioIo;
use tokio::net::{UnixListener, UnixStream};
use tonic::codegen::http::Uri;
use tonic::transport::{Channel, Endpoint, Server};
use tower::service_fn;

use oxpanel_daemon::auth::{self, PeerPolicy};
use oxpanel_daemon::config::Config;
use oxpanel_daemon::ctx::Ctx;
use oxpanel_daemon::server::Engine;
use oxpanel_daemon::system::FakeSystem;
use oxpanel_proto::v1 as pb;
use oxpanel_proto::v1::ox_panel_engine_client::OxPanelEngineClient;

type Client = OxPanelEngineClient<Channel>;
type BoxError = Box<dyn std::error::Error + Send + Sync>;

struct Args {
    tenants: Vec<usize>,
    vhosts: usize,
    seconds: u64,
}

fn parse_args() -> Result<Args, BoxError> {
    let mut args = Args {
        tenants: vec![1_000, 10_000],
        vhosts: 5_000,
        seconds: 5,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--tenants" => {
                args.tenants = value()?
                    .split(',')
                    .map(str::parse)
                    .collect::<Result<_, _>>()?;
            }
            "--vhosts" => args.vhosts = value()?.parse()?,
            "--seconds" => args.seconds = value()?.parse()?,
            "--help" | "-h" => {
                println!("usage: oxpanel-bench [--tenants N[,N…]] [--vhosts N] [--seconds N]");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    Ok(args)
}

struct Daemon {
    _dir: tempfile::TempDir,
    socket: PathBuf,
    sys: Arc<FakeSystem>,
    state_dir: PathBuf,
}

async fn start(uid_max: u32) -> Result<Daemon, BoxError> {
    let dir = match std::env::var_os("OXPANEL_BENCH_DIR") {
        Some(base) => tempfile::tempdir_in(base)?,
        None => tempfile::tempdir()?,
    };
    let p = dir.path();
    let mut cfg = Config::default();
    cfg.state_dir = p.join("state");
    cfg.home_base = p.join("home");
    cfg.systemd_unit_dir = p.join("systemd");
    cfg.nginx_log_dir = p.join("log");
    cfg.php_conf_dir = p.join("php");
    cfg.nginx_conf_dir = p.join("nginx").join("oxpanel.d");
    cfg.nginx_include_file = p.join("nginx").join("conf.d").join("00-oxpanel.conf");
    cfg.socket_path = p.join("oxpanel.sock");
    cfg.tls_dir = p.join("pki");
    cfg.acme_dir = p.join("acme");
    cfg.sftp_keys_dir = p.join("sftp-keys");
    cfg.sshd_dropin_file = p.join("sshd_config.d").join("60-oxpanel.conf");
    cfg.uid_max = uid_max;
    for d in [
        &cfg.home_base,
        &cfg.systemd_unit_dir,
        &p.join("nginx").join("conf.d"),
    ] {
        std::fs::create_dir_all(d)?;
    }
    let sys = Arc::new(FakeSystem::new());
    let ctx = Ctx::new(cfg.clone(), sys.clone(), false);
    ctx.store.init()?;
    let listener = UnixListener::bind(&cfg.socket_path)?;
    let me = nix::unistd::geteuid().as_raw();
    let policy = PeerPolicy::new(
        [me].into_iter().collect(),
        std::iter::empty().collect(),
        false,
    );
    let incoming = auth::gate(listener, Arc::new(policy), ctx.sys.clone());
    let engine = Engine::new(ctx);
    tokio::spawn(async move {
        // Same transport limits as the daemon's main().
        let _ = Server::builder()
            .timeout(Duration::from_secs(300))
            .concurrency_limit_per_connection(16)
            .max_concurrent_streams(16)
            .add_service(engine.into_service())
            .serve_with_incoming(incoming)
            .await;
    });
    Ok(Daemon {
        socket: cfg.socket_path.clone(),
        state_dir: cfg.state_dir.clone(),
        _dir: dir,
        sys,
    })
}

async fn connect(socket: &Path) -> Result<Client, BoxError> {
    let path = socket.to_owned();
    let channel = Endpoint::try_from("http://oxpanel.local")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await?;
    // Listings of 10,000 tenants are larger than the client's 4 MiB default.
    Ok(OxPanelEngineClient::new(channel).max_decoding_message_size(64 << 20))
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn tenant_name(i: usize) -> String {
    format!("t{i:06}")
}

/// Create tenants `from..to`; returns the mean milliseconds per tenant.
async fn create_tenants(c: &mut Client, from: usize, to: usize) -> Result<f64, BoxError> {
    let t0 = Instant::now();
    for i in from..to {
        c.create_tenant(pb::CreateTenantRequest {
            username: tenant_name(i),
            owner: format!("r{}", i % 20),
            limits: Some(pb::ResourceLimits {
                memory_max_bytes: 256 << 20,
                cpu_weight: 100,
                io_weight: 0,
                tasks_max: 128,
                disk_max_bytes: 0,
                inodes_max: 0,
            }),
        })
        .await?;
    }
    Ok(ms(t0.elapsed()) / (to - from).max(1) as f64)
}

/// Configure virtual hosts `from..to`, spread over `tenants` tenants; one in
/// ten uses PHP, one in ten an application.
async fn create_vhosts(
    c: &mut Client,
    from: usize,
    to: usize,
    tenants: usize,
) -> Result<f64, BoxError> {
    let t0 = Instant::now();
    for i in from..to {
        c.configure_virtual_host(pb::ConfigureVirtualHostRequest {
            domain: format!("site{i:06}.example"),
            tenant: tenant_name(i % tenants),
            aliases: vec![format!("www.site{i:06}.example")],
            php: i % 10 == 1,
            app: (i % 10 == 2).then(|| pb::App {
                runtime: pb::AppRuntime::Node.into(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await?;
    }
    Ok(ms(t0.elapsed()) / (to - from).max(1) as f64)
}

/// Median of `n` timed runs of `f`, in milliseconds.
async fn median<F, Fut>(n: usize, mut f: F) -> Result<f64, BoxError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), BoxError>>,
{
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = Instant::now();
        f().await?;
        samples.push(ms(t0.elapsed()));
    }
    samples.sort_by(f64::total_cmp);
    Ok(samples.get(samples.len() / 2).copied().unwrap_or_default())
}

#[derive(Clone, Copy)]
enum Read {
    GetTenant,
    ListTenants,
    ListVHostsOfTenant,
    HostInfo,
}

impl Read {
    fn name(self) -> &'static str {
        match self {
            Self::GetTenant => "GetTenant",
            Self::ListTenants => "ListTenants (all)",
            Self::ListVHostsOfTenant => "ListVirtualHosts (one tenant)",
            Self::HostInfo => "GetHostInfo",
        }
    }
}

/// `clients` connections issue `rpc` back to back for `secs` seconds.
/// Returns (requests per second, p50, p95, p99) with latencies in ms.
async fn read_load(
    socket: &Path,
    rpc: Read,
    clients: usize,
    tenants: usize,
    secs: u64,
) -> Result<(f64, f64, f64, f64), BoxError> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut tasks = Vec::new();
    for k in 0..clients {
        let mut c = connect(socket).await?;
        tasks.push(tokio::spawn(async move {
            let mut lat = Vec::new();
            let mut i = k;
            while Instant::now() < deadline {
                let name = tenant_name(i % tenants);
                i = i.wrapping_add(7919);
                let t0 = Instant::now();
                let ok = match rpc {
                    Read::GetTenant => c
                        .get_tenant(pb::GetTenantRequest { username: name })
                        .await
                        .is_ok(),
                    Read::ListTenants => c
                        .list_tenants(pb::ListTenantsRequest::default())
                        .await
                        .is_ok(),
                    Read::ListVHostsOfTenant => c
                        .list_virtual_hosts(pb::ListVirtualHostsRequest { tenant: name })
                        .await
                        .is_ok(),
                    Read::HostInfo => c.get_host_info(pb::GetHostInfoRequest {}).await.is_ok(),
                };
                if !ok {
                    return Err("read RPC failed under load");
                }
                lat.push(ms(t0.elapsed()));
            }
            Ok(lat)
        }));
    }
    let started = Instant::now();
    let mut all = Vec::new();
    for t in tasks {
        all.extend(t.await??);
    }
    let elapsed = started.elapsed().as_secs_f64().max(secs as f64);
    all.sort_by(f64::total_cmp);
    let pct = |p: f64| {
        let idx = ((all.len() as f64 * p) as usize).min(all.len().saturating_sub(1));
        all.get(idx).copied().unwrap_or_default()
    };
    Ok((all.len() as f64 / elapsed, pct(0.50), pct(0.95), pct(0.99)))
}

fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("VmRSS:"))
                .and_then(|v| v.split_whitespace().next()?.parse().ok())
        })
        .unwrap_or(0)
}

fn machine() -> String {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let model = cpuinfo
        .lines()
        .find_map(|l| l.strip_prefix("model name"))
        .map_or_else(
            || "unknown CPU".to_owned(),
            |v| v.trim_start_matches([' ', '\t', ':']).to_owned(),
        );
    let cores = std::thread::available_parallelism().map_or(0, std::num::NonZero::get);
    let mem_kib: u64 = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("MemTotal:"))
                .and_then(|v| v.split_whitespace().next()?.parse().ok())
        })
        .unwrap_or(0);
    format!("{model}, {cores} logical CPUs, {} GiB RAM", mem_kib >> 20)
}

async fn scale_run(tenants: usize, vhosts: usize, secs: u64) -> Result<(), BoxError> {
    let d = start(20_000 + u32::try_from(tenants)? + 10).await?;
    let mut c = connect(&d.socket).await?;
    println!("\n### {tenants} tenants, {vhosts} virtual hosts\n");

    // Provisioning, in ten slices, so degradation with scale is visible.
    eprintln!("[bench] creating {tenants} tenants");
    let t0 = Instant::now();
    let slice = (tenants / 10).max(1);
    let mut tenant_ms = Vec::new();
    for s in 0..10 {
        let (from, to) = (s * slice, ((s + 1) * slice).min(tenants));
        if from >= to {
            break;
        }
        tenant_ms.push((to, create_tenants(&mut c, from, to).await?));
        d.sys.clear_calls();
    }
    let tenants_total = t0.elapsed();
    eprintln!("[bench] configuring {vhosts} virtual hosts");
    let t0 = Instant::now();
    let slice = (vhosts / 10).max(1);
    let mut vhost_ms = Vec::new();
    for s in 0..10 {
        let (from, to) = (s * slice, ((s + 1) * slice).min(vhosts));
        if from >= to {
            break;
        }
        vhost_ms.push((to, create_vhosts(&mut c, from, to, tenants).await?));
        d.sys.clear_calls();
    }
    let vhosts_total = t0.elapsed();

    println!("| Provisioning | first tenth | middle | last tenth | total | throughput |");
    println!("|---|---|---|---|---|---|");
    for (what, series, total, n) in [
        ("CreateTenant", &tenant_ms, tenants_total, tenants),
        ("ConfigureVirtualHost", &vhost_ms, vhosts_total, vhosts),
    ] {
        let at = |i: usize| series.get(i).map_or(0.0, |(_, v)| *v);
        println!(
            "| {what} | {:.2} ms each | {:.2} ms | {:.2} ms | {:.1} s | {:.0}/s |",
            at(0),
            at(series.len() / 2),
            at(series.len().saturating_sub(1)),
            total.as_secs_f64(),
            n as f64 / total.as_secs_f64().max(1e-9),
        );
    }

    // Single operations at full scale.
    eprintln!("[bench] single operations at full scale");
    let mid = tenant_name(tenants / 2);
    let mut rows: Vec<(&str, f64)> = Vec::new();
    macro_rules! timed {
        ($label:expr, $n:expr, $call:expr) => {{
            let v = median($n, || {
                let c = c.clone();
                let mid = mid.clone();
                async move {
                    $call(c, mid).await?;
                    Ok(())
                }
            })
            .await?;
            rows.push(($label, v));
        }};
    }
    timed!("GetTenant", 200, |mut c: Client, mid: String| async move {
        c.get_tenant(pb::GetTenantRequest { username: mid })
            .await
            .map(|_| ())
    });
    timed!(
        "ListTenants (all)",
        7,
        |mut c: Client, _m: String| async move {
            c.list_tenants(pb::ListTenantsRequest::default())
                .await
                .map(|_| ())
        }
    );
    timed!(
        "ListTenants (one owner of 20)",
        7,
        |mut c: Client, _m: String| async move {
            c.list_tenants(pb::ListTenantsRequest { owner: "r3".into() })
                .await
                .map(|_| ())
        }
    );
    timed!(
        "ListVirtualHosts (all)",
        7,
        |mut c: Client, _m: String| async move {
            c.list_virtual_hosts(pb::ListVirtualHostsRequest::default())
                .await
                .map(|_| ())
        }
    );
    timed!(
        "ListVirtualHosts (one tenant)",
        7,
        |mut c: Client, mid: String| async move {
            c.list_virtual_hosts(pb::ListVirtualHostsRequest { tenant: mid })
                .await
                .map(|_| ())
        }
    );
    timed!(
        "GetTenantUsage",
        50,
        |mut c: Client, mid: String| async move {
            c.get_tenant_usage(pb::GetTenantUsageRequest { username: mid })
                .await
                .map(|_| ())
        }
    );
    timed!("GetHostInfo", 7, |mut c: Client, _m: String| async move {
        c.get_host_info(pb::GetHostInfoRequest {}).await.map(|_| ())
    });
    timed!("Reconcile", 3, |mut c: Client, _m: String| async move {
        c.reconcile(pb::ReconcileRequest {}).await.map(|_| ())
    });
    timed!(
        "UpdateTenantLimits (no change)",
        20,
        |mut c: Client, mid: String| async move {
            c.update_tenant_limits(pb::UpdateTenantLimitsRequest {
                username: mid,
                limits: Some(pb::ResourceLimits {
                    memory_max_bytes: 256 << 20,
                    cpu_weight: 100,
                    io_weight: 0,
                    tasks_max: 128,
                    disk_max_bytes: 0,
                    inodes_max: 0,
                }),
            })
            .await
            .map(|_| ())
        }
    );
    timed!(
        "ConfigureVirtualHost (replay, no change)",
        7,
        |mut c: Client, _m: String| async move {
            c.configure_virtual_host(pb::ConfigureVirtualHostRequest {
                domain: "site000000.example".into(),
                tenant: tenant_name(0),
                aliases: vec!["www.site000000.example".into()],
                ..Default::default()
            })
            .await
            .map(|_| ())
        }
    );
    // Suspend + resume of one tenant (both re-render its sites).
    let t0 = Instant::now();
    for _ in 0..3 {
        c.suspend_tenant(pb::SuspendTenantRequest {
            username: mid.clone(),
        })
        .await?;
        c.resume_tenant(pb::ResumeTenantRequest {
            username: mid.clone(),
        })
        .await?;
    }
    rows.push(("SuspendTenant + ResumeTenant", ms(t0.elapsed()) / 3.0));
    // One more tenant and site on top of everything, then remove them again.
    let t0 = Instant::now();
    create_tenants(&mut c, tenants, tenants + 1).await?;
    rows.push(("CreateTenant (one more)", ms(t0.elapsed())));
    let extra = tenant_name(tenants);
    let t0 = Instant::now();
    c.configure_virtual_host(pb::ConfigureVirtualHostRequest {
        domain: "extra.example".into(),
        tenant: extra.clone(),
        ..Default::default()
    })
    .await?;
    rows.push(("ConfigureVirtualHost (one more)", ms(t0.elapsed())));
    let t0 = Instant::now();
    c.remove_virtual_host(pb::RemoveVirtualHostRequest {
        domain: "extra.example".into(),
    })
    .await?;
    rows.push(("RemoveVirtualHost", ms(t0.elapsed())));
    let t0 = Instant::now();
    c.delete_tenant(pb::DeleteTenantRequest {
        username: extra,
        remove_home: true,
    })
    .await?;
    rows.push(("DeleteTenant", ms(t0.elapsed())));

    println!("\n| Single request at this scale | time |");
    println!("|---|---|");
    for (label, v) in &rows {
        println!("| {label} | {v:.2} ms |");
    }

    // Read RPCs under concurrency.
    eprintln!("[bench] read RPCs under concurrency");
    println!("\n| Read RPC | clients | requests/s | p50 | p95 | p99 |");
    println!("|---|---|---|---|---|---|");
    for rpc in [
        Read::GetTenant,
        Read::ListVHostsOfTenant,
        Read::HostInfo,
        Read::ListTenants,
    ] {
        for clients in [1usize, 8, 64] {
            let (rps, p50, p95, p99) = read_load(&d.socket, rpc, clients, tenants, secs).await?;
            println!(
                "| {} | {clients} | {rps:.0} | {p50:.2} ms | {p95:.2} ms | {p99:.2} ms |",
                rpc.name()
            );
        }
    }

    // Reads while a writer is busy: the mutation lock must not stall them.
    let writer = {
        let mut w = connect(&d.socket).await?;
        let mid = mid.clone();
        tokio::spawn(async move {
            let until = Instant::now() + Duration::from_secs(secs);
            let mut n = 0u32;
            while Instant::now() < until {
                let mem = (256 + u64::from(n % 2)) << 20;
                if w.update_tenant_limits(pb::UpdateTenantLimitsRequest {
                    username: mid.clone(),
                    limits: Some(pb::ResourceLimits {
                        memory_max_bytes: mem,
                        cpu_weight: 100,
                        io_weight: 0,
                        tasks_max: 128,
                        disk_max_bytes: 0,
                        inodes_max: 0,
                    }),
                })
                .await
                .is_err()
                {
                    break;
                }
                n += 1;
            }
            n
        })
    };
    let (rps, p50, p95, p99) = read_load(&d.socket, Read::GetTenant, 8, tenants, secs).await?;
    let writes = writer.await?;
    println!(
        "| GetTenant while a writer runs ({:.0} updates/s) | 8 | {rps:.0} | {p50:.2} ms | {p95:.2} ms | {p99:.2} ms |",
        f64::from(writes) / secs as f64
    );

    let records = du(&d.state_dir);
    println!(
        "\nBenchmark process RSS at this scale: {} MiB (server and clients; the fake OS keeps accounts in memory). Records on disk: {} KiB.",
        rss_kib() >> 10,
        records >> 10
    );
    Ok(())
}

fn du(dir: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .map(|e| match e.metadata() {
            Ok(m) if m.is_dir() => du(&e.path()),
            Ok(m) => m.len(),
            Err(_) => 0,
        })
        .sum()
}

async fn run() -> Result<(), BoxError> {
    let args = parse_args()?;
    let where_ = std::env::var("OXPANEL_BENCH_DIR")
        .unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().into_owned());
    println!("## Engine benchmark (fake operating system)\n");
    println!("- Machine: {}", machine());
    println!("- State directory: `{where_}`");
    println!(
        "- Build: {}",
        if cfg!(debug_assertions) {
            "debug (numbers are not representative; use `make bench`)"
        } else {
            "release"
        }
    );
    for tenants in &args.tenants {
        scale_run(*tenants, args.vhosts, args.seconds).await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("oxpanel-bench: {e}");
            ExitCode::FAILURE
        }
    }
}
