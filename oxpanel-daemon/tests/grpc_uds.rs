//! End-to-end: real tonic server on a UNIX socket, real peer-credential gate,
//! real gRPC client — with the operating system faked.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::field_reassign_with_default,
    clippy::too_many_lines
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hyper_util::rt::TokioIo;
use tokio::net::{UnixListener, UnixStream};
use tonic::codegen::http::Uri;
use tonic::transport::{Channel, Endpoint, Server};
use tonic::Code;
use tower::service_fn;

use oxpanel_daemon::auth::{self, PeerPolicy};
use oxpanel_daemon::config::Config;
use oxpanel_daemon::ctx::Ctx;
use oxpanel_daemon::server::Engine;
use oxpanel_daemon::system::FakeSystem;
use oxpanel_proto::v1 as pb;
use oxpanel_proto::v1::ox_panel_engine_client::OxPanelEngineClient;

struct TestServer {
    _dir: tempfile::TempDir,
    socket: PathBuf,
    sys: Arc<FakeSystem>,
    config: Config,
}

async fn start(policy: PeerPolicy) -> TestServer {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = Config::default();
    cfg.state_dir = dir.path().join("state");
    cfg.home_base = dir.path().join("home");
    cfg.systemd_unit_dir = dir.path().join("systemd");
    cfg.nginx_conf_dir = dir.path().join("nginx").join("oxpanel.d");
    cfg.nginx_include_file = dir
        .path()
        .join("nginx")
        .join("conf.d")
        .join("00-oxpanel.conf");
    cfg.socket_path = dir.path().join("oxpanel.sock");
    for d in [
        &cfg.home_base,
        &cfg.systemd_unit_dir,
        &dir.path().join("nginx").join("conf.d"),
    ] {
        std::fs::create_dir_all(d).expect("mkdir");
    }
    let sys = Arc::new(FakeSystem::new());
    let ctx = Ctx::new(cfg.clone(), sys.clone(), false);
    ctx.store.init().expect("store init");
    let listener = UnixListener::bind(&cfg.socket_path).expect("bind");
    let incoming = auth::gate(listener, Arc::new(policy), ctx.sys.clone());
    let engine = Engine::new(ctx);
    tokio::spawn(async move {
        Server::builder()
            .add_service(engine.into_service())
            .serve_with_incoming(incoming)
            .await
            .expect("serve");
    });
    TestServer {
        socket: cfg.socket_path.clone(),
        _dir: dir,
        sys,
        config: cfg,
    }
}

async fn connect(socket: &Path) -> Result<OxPanelEngineClient<Channel>, tonic::transport::Error> {
    let path = socket.to_owned();
    let channel = Endpoint::try_from("http://oxpanel.local")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await?;
    Ok(OxPanelEngineClient::new(channel))
}

fn allow_me() -> PeerPolicy {
    let me = nix::unistd::geteuid().as_raw();
    PeerPolicy::new([me].into_iter().collect(), BTreeSet::new(), false)
}

#[tokio::test]
async fn full_tenant_and_vhost_lifecycle_over_uds() {
    let srv = start(allow_me()).await;
    let mut client = connect(&srv.socket).await.expect("connect");

    // Create
    let resp = client
        .create_tenant(pb::CreateTenantRequest {
            username: "alice".into(),
            owner: "reseller1".into(),
            limits: Some(pb::ResourceLimits {
                memory_max_bytes: 512 * 1024 * 1024,
                cpu_weight: 200,
                io_weight: 0,
                tasks_max: 100,
            }),
        })
        .await
        .expect("create")
        .into_inner();
    assert!(resp.created);
    let t = resp.tenant.expect("tenant");
    assert_eq!(t.username, "alice");
    assert_eq!(t.uid, 20000);
    assert_eq!(t.state, i32::from(pb::TenantState::Ready));
    assert_eq!(t.slice_unit, "oxpanel-tenant-alice.slice");
    assert!(t.created_at.is_some_and(|ts| ts.seconds > 1_600_000_000));
    assert_eq!(t.limits.as_ref().map(|l| l.cpu_weight), Some(200));
    assert_eq!(t.owner, "reseller1");

    // Idempotent replay
    let again = client
        .create_tenant(pb::CreateTenantRequest {
            username: "alice".into(),
            owner: "reseller1".into(),
            limits: Some(pb::ResourceLimits {
                memory_max_bytes: 512 * 1024 * 1024,
                cpu_weight: 200,
                io_weight: 0,
                tasks_max: 100,
            }),
        })
        .await
        .expect("replay")
        .into_inner();
    assert!(!again.created);

    // Drift is AlreadyExists
    let drift = client
        .create_tenant(pb::CreateTenantRequest {
            username: "alice".into(),
            owner: "reseller1".into(),
            limits: None,
        })
        .await
        .expect_err("drift must fail");
    assert_eq!(drift.code(), Code::AlreadyExists);

    // Get / List
    let got = client
        .get_tenant(pb::GetTenantRequest {
            username: "alice".into(),
        })
        .await
        .expect("get")
        .into_inner();
    assert_eq!(got.uid, 20000);
    let list = client
        .list_tenants(pb::ListTenantsRequest::default())
        .await
        .expect("list")
        .into_inner();
    assert_eq!(list.tenants.len(), 1);
    let mine = client
        .list_tenants(pb::ListTenantsRequest {
            owner: "reseller1".into(),
        })
        .await
        .expect("list mine")
        .into_inner();
    assert_eq!(mine.tenants.len(), 1);
    let none = client
        .list_tenants(pb::ListTenantsRequest {
            owner: "other".into(),
        })
        .await
        .expect("list none")
        .into_inner();
    assert!(none.tenants.is_empty());

    // VHost
    let vh = client
        .configure_virtual_host(pb::ConfigureVirtualHostRequest {
            domain: "example.com".into(),
            tenant: "alice".into(),
            document_root: String::new(),
            aliases: vec!["www.example.com".into()],
        })
        .await
        .expect("vhost")
        .into_inner();
    assert!(vh.created);
    let v = vh.vhost.expect("vhost body");
    assert_eq!(v.document_root, "public_html");
    assert!(PathBuf::from(&v.config_path).starts_with(&srv.config.nginx_conf_dir));
    assert!(srv
        .config
        .home_base
        .join("alice")
        .join("public_html")
        .is_dir());
    let vlist = client
        .list_virtual_hosts(pb::ListVirtualHostsRequest {
            tenant: "alice".into(),
        })
        .await
        .expect("vlist")
        .into_inner();
    assert_eq!(vlist.vhosts.len(), 1);

    // Tenant with vhosts cannot be deleted
    let blocked = client
        .delete_tenant(pb::DeleteTenantRequest {
            username: "alice".into(),
            remove_home: true,
        })
        .await
        .expect_err("must be blocked");
    assert_eq!(blocked.code(), Code::FailedPrecondition);

    // Remove vhost, then tenant
    assert!(
        client
            .remove_virtual_host(pb::RemoveVirtualHostRequest {
                domain: "example.com".into()
            })
            .await
            .expect("rm")
            .into_inner()
            .removed
    );
    assert!(
        !client
            .remove_virtual_host(pb::RemoveVirtualHostRequest {
                domain: "example.com".into()
            })
            .await
            .expect("rm2")
            .into_inner()
            .removed
    );
    assert!(
        client
            .delete_tenant(pb::DeleteTenantRequest {
                username: "alice".into(),
                remove_home: true
            })
            .await
            .expect("del")
            .into_inner()
            .deleted
    );
    let nf = client
        .get_tenant(pb::GetTenantRequest {
            username: "alice".into(),
        })
        .await
        .expect_err("gone");
    assert_eq!(nf.code(), Code::NotFound);
    assert!(srv.sys.users().is_empty());
}

#[tokio::test]
async fn validation_errors_surface_as_invalid_argument_with_message() {
    let srv = start(allow_me()).await;
    let mut client = connect(&srv.socket).await.expect("connect");
    for bad in ["root", "Alice", "a;b", "../etc", ""] {
        let e = client
            .create_tenant(pb::CreateTenantRequest {
                username: bad.into(),
                owner: String::new(),
                limits: None,
            })
            .await
            .expect_err("must fail");
        assert_eq!(e.code(), Code::InvalidArgument, "{bad}");
        assert!(
            e.message().starts_with("invalid username"),
            "{bad}: {}",
            e.message()
        );
    }
    let e = client
        .create_tenant(pb::CreateTenantRequest {
            username: "carol".into(),
            owner: String::new(),
            limits: Some(pb::ResourceLimits {
                memory_max_bytes: 1,
                cpu_weight: 0,
                io_weight: 0,
                tasks_max: 0,
            }),
        })
        .await
        .expect_err("tiny memory limit");
    assert_eq!(e.code(), Code::InvalidArgument);
    let e = client
        .configure_virtual_host(pb::ConfigureVirtualHostRequest {
            domain: "not a domain".into(),
            tenant: "carol".into(),
            document_root: String::new(),
            aliases: vec![],
        })
        .await
        .expect_err("bad domain");
    assert_eq!(e.code(), Code::InvalidArgument);
    assert!(
        srv.sys.calls().is_empty(),
        "invalid requests never reach the OS"
    );
}

#[tokio::test]
async fn internal_failures_are_redacted() {
    let srv = start(allow_me()).await;
    let mut client = connect(&srv.socket).await.expect("connect");
    srv.sys.script_failure(
        oxpanel_daemon::system::bin::USERADD,
        1,
        "useradd: cannot lock /etc/passwd; try again later.",
    );
    let e = client
        .create_tenant(pb::CreateTenantRequest {
            username: "dave".into(),
            owner: String::new(),
            limits: None,
        })
        .await
        .expect_err("useradd failed");
    assert_eq!(e.code(), Code::Internal);
    assert!(!e.message().contains("passwd"), "{}", e.message());
}

#[tokio::test]
async fn unauthorised_peer_is_cut_off_before_grpc() {
    // Nobody is allowed, not even root.
    let srv = start(PeerPolicy::new(BTreeSet::new(), BTreeSet::new(), false)).await;
    // The connect may succeed at the socket level; the request must not.
    let result = match connect(&srv.socket).await {
        Ok(mut client) => client
            .list_tenants(pb::ListTenantsRequest::default())
            .await
            .map(|_| ()),
        Err(_) => Err(tonic::Status::unavailable(
            "connection refused during handshake",
        )),
    };
    assert!(result.is_err(), "unauthorised peer must not be served");
    assert!(srv.sys.calls().is_empty());
}
