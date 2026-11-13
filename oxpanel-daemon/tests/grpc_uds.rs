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

use oxpanel_daemon::auth::{self, PeerPolicy, Scope};
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

const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGNQ8nctDOzq4yQ8Bix4hfkkqCQw0kkYzl6hc7hg7rRo";
const FINGERPRINT: &str = "SHA256:d61vVJ9GcopAzh14aZ3bTeCz+981/iT/jSIxXFS8pjQ";

async fn start(policy: PeerPolicy) -> TestServer {
    start_scoped(policy, &[]).await
}

/// Like [`start`], with the calling uid confined to `scopes` (empty = unrestricted).
async fn start_scoped(policy: PeerPolicy, scopes: &[Scope]) -> TestServer {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = Config::default();
    cfg.state_dir = dir.path().join("state");
    cfg.home_base = dir.path().join("home");
    cfg.systemd_unit_dir = dir.path().join("systemd");
    cfg.nginx_log_dir = dir.path().join("log");
    cfg.php_conf_dir = dir.path().join("php");
    cfg.nginx_conf_dir = dir.path().join("nginx").join("oxpanel.d");
    cfg.nginx_include_file = dir
        .path()
        .join("nginx")
        .join("conf.d")
        .join("00-oxpanel.conf");
    cfg.socket_path = dir.path().join("oxpanel.sock");
    cfg.sftp_keys_dir = dir.path().join("sftp-keys");
    cfg.sshd_dropin_file = dir.path().join("sshd_config.d").join("60-oxpanel.conf");
    if !scopes.is_empty() {
        cfg.peer_scopes.insert(
            nix::unistd::geteuid().as_raw(),
            scopes.iter().copied().collect(),
        );
    }
    for d in [
        &cfg.home_base,
        &cfg.systemd_unit_dir,
        &dir.path().join("nginx").join("conf.d"),
        &dir.path().join("sshd_config.d"),
    ] {
        std::fs::create_dir_all(d).expect("mkdir");
    }
    let sys = Arc::new(FakeSystem::new());
    let ctx = Ctx::new(cfg.clone(), sys.clone(), false);
    ctx.store.init().expect("store init");
    // As the daemon does at start: install the sshd drop-in.
    oxpanel_daemon::sftp::converge_all(&ctx)
        .await
        .expect("sftp converge");
    sys.clear_calls();
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
                ..pb::ResourceLimits::default()
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
                ..pb::ResourceLimits::default()
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
            php: false,
            app: None,
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
                ..pb::ResourceLimits::default()
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
            php: false,
            app: None,
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

#[tokio::test]
async fn management_rpcs_over_uds() {
    let srv = start(allow_me()).await;
    let mut client = connect(&srv.socket).await.expect("connect");
    client
        .create_tenant(pb::CreateTenantRequest {
            username: "alice".into(),
            owner: "r1".into(),
            limits: None,
        })
        .await
        .expect("create");
    client
        .configure_virtual_host(pb::ConfigureVirtualHostRequest {
            domain: "example.com".into(),
            tenant: "alice".into(),
            document_root: String::new(),
            aliases: vec![],
            php: false,
            app: None,
        })
        .await
        .expect("vhost");

    // Limits
    let new_limits = pb::ResourceLimits {
        memory_max_bytes: 256 << 20,
        cpu_weight: 50,
        io_weight: 0,
        tasks_max: 0,
        ..pb::ResourceLimits::default()
    };
    let r = client
        .update_tenant_limits(pb::UpdateTenantLimitsRequest {
            username: "alice".into(),
            limits: Some(new_limits),
        })
        .await
        .expect("limits")
        .into_inner();
    assert!(r.changed);
    assert_eq!(r.tenant.and_then(|t| t.limits), Some(new_limits));
    let bad = client
        .update_tenant_limits(pb::UpdateTenantLimitsRequest {
            username: "alice".into(),
            limits: Some(pb::ResourceLimits {
                cpu_weight: 10_001,
                ..pb::ResourceLimits::default()
            }),
        })
        .await
        .expect_err("weight out of range");
    assert_eq!(bad.code(), Code::InvalidArgument);

    // Owner
    let r = client
        .update_tenant_owner(pb::UpdateTenantOwnerRequest {
            username: "alice".into(),
            owner: "r2".into(),
        })
        .await
        .expect("owner")
        .into_inner();
    assert!(r.changed);
    assert_eq!(r.tenant.map(|t| t.owner).as_deref(), Some("r2"));

    // Suspend / resume
    let conf = srv.config.nginx_conf_dir.join("example.com.conf");
    let r = client
        .suspend_tenant(pb::SuspendTenantRequest {
            username: "alice".into(),
        })
        .await
        .expect("suspend")
        .into_inner();
    assert!(r.changed && r.tenant.is_some_and(|t| t.suspended));
    assert!(std::fs::read_to_string(&conf)
        .expect("conf")
        .contains("return 503;"));
    assert!(
        client
            .get_tenant(pb::GetTenantRequest {
                username: "alice".into()
            })
            .await
            .expect("get")
            .into_inner()
            .suspended
    );
    let r = client
        .resume_tenant(pb::ResumeTenantRequest {
            username: "alice".into(),
        })
        .await
        .expect("resume")
        .into_inner();
    assert!(r.changed && r.tenant.is_some_and(|t| !t.suspended));
    assert!(!std::fs::read_to_string(&conf)
        .expect("conf")
        .contains("503"));

    // Usage, host info, reconcile
    let u = client
        .get_tenant_usage(pb::GetTenantUsageRequest {
            username: "alice".into(),
        })
        .await
        .expect("usage")
        .into_inner();
    assert_eq!(u.username, "alice");
    assert_eq!(
        (u.memory_current_bytes, u.disk_usage_bytes),
        (1_048_576, 8192)
    );
    assert!(u.measured_at.is_some());
    let i = client
        .get_host_info(pb::GetHostInfoRequest {})
        .await
        .expect("info")
        .into_inner();
    assert_eq!(i.daemon_version, env!("CARGO_PKG_VERSION"));
    assert_eq!((i.tenant_count, i.vhost_count), (1, 1));
    assert!(i.memory_total_bytes > 0);
    let rec = client
        .reconcile(pb::ReconcileRequest {})
        .await
        .expect("reconcile")
        .into_inner();
    assert!(rec.drifts.is_empty(), "{:?}", rec.drifts);
    std::fs::remove_file(&conf).expect("rm conf");
    let rec = client
        .reconcile(pb::ReconcileRequest {})
        .await
        .expect("reconcile")
        .into_inner();
    assert_eq!(rec.drifts.len(), 1);
    let d = rec.drifts.first().expect("one drift");
    assert_eq!(d.kind, i32::from(pb::DriftKind::VhostConfigDrift));
    assert_eq!(d.subject, "example.com");

    // SFTP keys
    let added = client
        .add_sftp_key(pb::AddSftpKeyRequest {
            username: "alice".into(),
            public_key: format!("{KEY} alice@laptop"),
            label: String::new(),
        })
        .await
        .expect("add key")
        .into_inner();
    assert!(added.changed);
    let key = added.key.expect("key");
    assert_eq!(key.fingerprint, FINGERPRINT);
    assert_eq!(
        (key.label.as_str(), key.public_key.as_str()),
        ("alice@laptop", KEY)
    );
    let tenant = client
        .get_tenant(pb::GetTenantRequest {
            username: "alice".into(),
        })
        .await
        .expect("get")
        .into_inner();
    assert_eq!(tenant.sftp_key_count, 1);
    let listed = client
        .list_sftp_keys(pb::ListSftpKeysRequest {
            username: "alice".into(),
        })
        .await
        .expect("list keys")
        .into_inner()
        .keys;
    assert_eq!(listed, vec![key]);
    let bad = client
        .add_sftp_key(pb::AddSftpKeyRequest {
            username: "alice".into(),
            public_key: format!("command=\"/bin/sh\" {KEY}"),
            label: String::new(),
        })
        .await
        .expect_err("options are refused");
    assert_eq!(bad.code(), Code::InvalidArgument);
    let removed = client
        .remove_sftp_key(pb::RemoveSftpKeyRequest {
            username: "alice".into(),
            fingerprint: FINGERPRINT.into(),
        })
        .await
        .expect("remove key")
        .into_inner();
    assert_eq!(removed.remaining, 0);
    let gone = client
        .remove_sftp_key(pb::RemoveSftpKeyRequest {
            username: "alice".into(),
            fingerprint: FINGERPRINT.into(),
        })
        .await
        .expect_err("already removed");
    assert_eq!(gone.code(), Code::NotFound);

    // Disk limits on a host without quotas are refused, with what to do.
    let refused = client
        .update_tenant_limits(pb::UpdateTenantLimitsRequest {
            username: "alice".into(),
            limits: Some(pb::ResourceLimits {
                disk_max_bytes: 1 << 30,
                ..pb::ResourceLimits::default()
            }),
        })
        .await
        .expect_err("no quotas here");
    assert_eq!(refused.code(), Code::FailedPrecondition);
    assert!(
        refused.message().contains("uquota"),
        "{}",
        refused.message()
    );

    // Unknown tenants
    let nf = client
        .suspend_tenant(pb::SuspendTenantRequest {
            username: "ghost".into(),
        })
        .await
        .expect_err("no such tenant");
    assert_eq!(nf.code(), Code::NotFound);
}

#[tokio::test]
async fn a_scoped_peer_can_only_call_its_scopes() {
    let srv = start_scoped(allow_me(), &[Scope::Read, Scope::VHost]).await;
    let mut client = connect(&srv.socket).await.expect("connect");

    // Reads are allowed.
    client
        .list_tenants(pb::ListTenantsRequest::default())
        .await
        .expect("list");
    client
        .get_host_info(pb::GetHostInfoRequest {})
        .await
        .expect("info");
    client
        .reconcile(pb::ReconcileRequest {})
        .await
        .expect("reconcile");

    // (Host information asks the installed Node.js for its version.)
    srv.sys.clear_calls();

    // Every tenant-changing RPC is refused before validation or any OS call.
    let denied = [
        client
            .create_tenant(pb::CreateTenantRequest {
                username: "alice".into(),
                owner: String::new(),
                limits: None,
            })
            .await
            .map(|_| ()),
        client
            .update_tenant_limits(pb::UpdateTenantLimitsRequest {
                username: "alice".into(),
                limits: None,
            })
            .await
            .map(|_| ()),
        client
            .update_tenant_owner(pb::UpdateTenantOwnerRequest {
                username: "alice".into(),
                owner: "x".into(),
            })
            .await
            .map(|_| ()),
        client
            .suspend_tenant(pb::SuspendTenantRequest {
                username: "alice".into(),
            })
            .await
            .map(|_| ()),
        client
            .resume_tenant(pb::ResumeTenantRequest {
                username: "alice".into(),
            })
            .await
            .map(|_| ()),
        client
            .delete_tenant(pb::DeleteTenantRequest {
                username: "alice".into(),
                remove_home: true,
            })
            .await
            .map(|_| ()),
        client
            .add_sftp_key(pb::AddSftpKeyRequest {
                username: "alice".into(),
                public_key: KEY.into(),
                label: String::new(),
            })
            .await
            .map(|_| ()),
        client
            .remove_sftp_key(pb::RemoveSftpKeyRequest {
                username: "alice".into(),
                fingerprint: FINGERPRINT.into(),
            })
            .await
            .map(|_| ()),
    ];
    for (i, r) in denied.into_iter().enumerate() {
        let e = r.expect_err("must be denied");
        assert_eq!(e.code(), Code::PermissionDenied, "rpc #{i}");
        assert!(e.message().contains("scope"), "{}", e.message());
    }
    assert!(
        srv.sys.calls().is_empty(),
        "denied requests never reach the OS"
    );

    // The vhost scope is honoured: the call gets past the gate (and then
    // fails on the missing tenant, not on permissions).
    let e = client
        .configure_virtual_host(pb::ConfigureVirtualHostRequest {
            domain: "example.com".into(),
            tenant: "alice".into(),
            document_root: String::new(),
            aliases: vec![],
            php: false,
            app: None,
        })
        .await
        .expect_err("no tenant");
    assert_eq!(e.code(), Code::NotFound);
}
