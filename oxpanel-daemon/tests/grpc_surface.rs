//! The gRPC surface under hostile and concurrent use, over a real UNIX socket
//! and the real peer gate:
//!
//! - every RPC in the service definition has a scope decision, is refused
//!   without that scope and for unauthorised peers;
//! - malformed, truncated, oversized and random requests are refused without
//!   touching the operating system, and never take the server down;
//! - many clients mutating at once neither deadlock nor lose an update, and
//!   leave records and the (fake) operating system consistent;
//! - a long dependency installation blocks nobody, and cannot bring a
//!   suspended tenant's application back.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use proptest::prelude::*;
use proptest::strategy::ValueTree as _;
use proptest::test_runner::TestRunner;
use prost::Message as _;
use tonic::Code;

use common::{
    allow_me, allow_nobody, assert_consistent, connect, frame, raw_call, raw_request,
    rpcs_in_proto, running_units, serve,
};
use oxpanel_daemon::auth::Scope;
use oxpanel_daemon::server::MAX_REQUEST_BYTES;
use oxpanel_daemon::system::bin;
use oxpanel_proto::v1 as pb;

const PERMISSION_DENIED: i32 = 7;

/// The scope decision for every RPC. A new RPC in `panel.proto` without an
/// entry here fails `every_rpc_has_a_scope_decision`.
fn scope_table() -> BTreeMap<&'static str, Scope> {
    [
        ("CreateTenant", Scope::Tenant),
        ("GetTenant", Scope::Read),
        ("ListTenants", Scope::Read),
        ("DeleteTenant", Scope::Delete),
        ("ConfigureVirtualHost", Scope::VHost),
        ("RemoveVirtualHost", Scope::VHost),
        ("ListVirtualHosts", Scope::Read),
        ("RestartApp", Scope::VHost),
        ("InstallAppDependencies", Scope::VHost),
        ("ReadVirtualHostLog", Scope::Read),
        ("UpdateTenantLimits", Scope::Tenant),
        ("UpdateTenantOwner", Scope::Tenant),
        ("SuspendTenant", Scope::Tenant),
        ("ResumeTenant", Scope::Tenant),
        ("GetTenantUsage", Scope::Read),
        ("GetHostInfo", Scope::Read),
        ("Reconcile", Scope::Read),
        // HTTPS (tls stream)
        ("InstallCertificate", Scope::VHost),
        ("RemoveCertificate", Scope::VHost),
        ("RequestCertificate", Scope::VHost),
        ("RenewCertificates", Scope::VHost),
        ("RunAutoHttps", Scope::VHost),
        ("GetAutoHttpsStatus", Scope::Read),
        // SFTP (sftp stream; customers manage their own access)
        ("AddSftpKey", Scope::VHost),
        ("RemoveSftpKey", Scope::VHost),
        ("ListSftpKeys", Scope::Read),
        ("SetSftpPassword", Scope::VHost),
        ("ClearSftpPassword", Scope::VHost),
        // Databases (db stream; managing a site's database is site management)
        ("CreateDatabase", Scope::VHost),
        ("ListDatabases", Scope::Read),
        ("DeleteDatabase", Scope::VHost),
        ("CreateDatabaseUser", Scope::VHost),
        ("ListDatabaseUsers", Scope::Read),
        ("SetDatabaseUserPassword", Scope::VHost),
        ("DeleteDatabaseUser", Scope::VHost),
        ("GrantDatabaseAccess", Scope::VHost),
        ("RevokeDatabaseAccess", Scope::VHost),
        // Backups (backup stream; restoring a retained backup of a deleted
        // tenant and deleting a backup need the strongest scope)
        ("CreateBackup", Scope::Tenant),
        ("ListBackups", Scope::Read),
        ("DeleteBackup", Scope::Delete),
        ("RestoreBackup", Scope::Tenant),
        ("GetJob", Scope::Read),
        ("RetainBackup", Scope::Tenant),
        ("ListRetainedBackups", Scope::Read),
        ("RestoreRetainedBackup", Scope::Delete),
        // Lifecycle: the database trash is the customer's (like deleting a
        // database); restoring a database from a backup is like restoring
        // files; from a deleted tenant's retained backup, the strongest scope.
        ("ListDatabaseTrash", Scope::Read),
        ("RestoreDatabaseTrash", Scope::VHost),
        ("PurgeDatabaseTrash", Scope::VHost),
        ("RestoreBackupDatabase", Scope::Tenant),
        ("RestoreRetainedBackupDatabase", Scope::Delete),
        // File manager (files stream): listing is `read`; content holds
        // secrets, so reading it needs the customer's write scope, like
        // every change.
        ("ListFiles", Scope::Read),
        ("StatFile", Scope::Read),
        ("ReadFile", Scope::VHost),
        ("WriteFile", Scope::VHost),
        ("StartUpload", Scope::VHost),
        ("UploadChunk", Scope::VHost),
        ("FinishUpload", Scope::VHost),
        ("AbortUpload", Scope::VHost),
        ("MakeDirectory", Scope::VHost),
        ("MoveFile", Scope::VHost),
        ("SetFileAccess", Scope::VHost),
        ("SearchFiles", Scope::Read),
        ("GetDirectorySize", Scope::Read),
        ("CopyFiles", Scope::VHost),
        ("DeleteFiles", Scope::VHost),
        ("CompressFiles", Scope::VHost),
        ("ExtractArchive", Scope::VHost),
        ("GetFileJob", Scope::Read),
        ("ListFileJobs", Scope::Read),
        // Essentials: a customer manages its own scheduled tasks and PHP
        // settings (the customer tier's write scope); a plan's PHP caps and
        // the backup schedule are the operator's, like CreateBackup.
        ("PutScheduledTask", Scope::VHost),
        ("DeleteScheduledTask", Scope::VHost),
        ("ListScheduledTasks", Scope::Read),
        ("RunScheduledTask", Scope::VHost),
        ("ReadScheduledTaskLog", Scope::Read),
        ("SetPhpSettings", Scope::VHost),
        ("SetTenantPhpLimits", Scope::Tenant),
        ("SetBackupSchedule", Scope::Tenant),
        ("GetBackupSchedule", Scope::Read),
        // DNS hosting (dns stream; a customer edits its own zones, as it
        // manages its own databases)
        ("CreateDnsZone", Scope::VHost),
        ("ListDnsZones", Scope::Read),
        ("GetDnsZone", Scope::Read),
        ("DeleteDnsZone", Scope::VHost),
        ("AddDnsRecord", Scope::VHost),
        ("UpdateDnsRecord", Scope::VHost),
        ("RemoveDnsRecord", Scope::VHost),
        ("ResetDnsZone", Scope::VHost),
        ("CheckDnsZone", Scope::Read),
        ("SetDnssec", Scope::VHost),
    ]
    .into_iter()
    .collect()
}

#[test]
fn every_rpc_has_a_scope_decision() {
    let rpcs = rpcs_in_proto();
    assert!(rpcs.len() >= 17, "service definition not parsed: {rpcs:?}");
    let table = scope_table();
    for rpc in &rpcs {
        assert!(
            table.contains_key(rpc.as_str()),
            "RPC {rpc} is in panel.proto but has no scope decision in tests/grpc_surface.rs: \
             decide which of read/vhost/tenant/delete it needs, call `authorise` first thing \
             in its handler, and add it to scope_table()"
        );
    }
    for rpc in table.keys() {
        assert!(
            rpcs.iter().any(|r| r == rpc),
            "{rpc} is in scope_table() but no longer in panel.proto"
        );
    }
}

/// For each scope: a peer holding every scope *except* it is refused by all
/// RPCs that need it (before validation and before any OS call), and a peer
/// holding *only* it gets past the gate of exactly those RPCs.
#[tokio::test]
async fn every_rpc_is_refused_without_its_scope_and_passes_with_it() {
    let table = scope_table();
    for scope in Scope::ALL {
        let others: Vec<Scope> = Scope::ALL.into_iter().filter(|s| *s != scope).collect();
        let without = serve(allow_me(), Some(&others)).await;
        let only = serve(allow_me(), Some(&[scope])).await;
        for rpc in rpcs_in_proto() {
            let needs = table.get(rpc.as_str()).copied().expect("scope decision");
            let denied = raw_call(&without.socket, &rpc, frame(&[]))
                .await
                .expect("transport");
            let granted = raw_call(&only.socket, &rpc, frame(&[]))
                .await
                .expect("transport");
            if needs == scope {
                assert_eq!(
                    denied.grpc_status,
                    Some(PERMISSION_DENIED),
                    "{rpc} without scope '{}': {denied:?}",
                    scope.as_str()
                );
                assert!(
                    denied.grpc_message.contains("scope"),
                    "{rpc}: {}",
                    denied.grpc_message
                );
                // An empty request is either served (lists, host info) or
                // fails validation: both prove the gate was passed.
                assert!(
                    matches!(granted.grpc_status, Some(0 | 3)),
                    "{rpc} with only scope '{}': {granted:?}",
                    scope.as_str()
                );
            } else {
                assert_ne!(
                    denied.grpc_status,
                    Some(PERMISSION_DENIED),
                    "{rpc} needs '{}', not '{}'",
                    needs.as_str(),
                    scope.as_str()
                );
                assert_eq!(
                    granted.grpc_status,
                    Some(PERMISSION_DENIED),
                    "{rpc} must not be callable with only scope '{}'",
                    scope.as_str()
                );
            }
        }
        // Nothing a refused request asked for reached the OS. (The server
        // without `read` can run no read RPC, the only ones that call out.)
        if scope == Scope::Read {
            assert!(
                without.fake().calls().is_empty(),
                "{:?}",
                without.fake().calls()
            );
        }
    }
}

#[tokio::test]
async fn every_rpc_is_refused_for_an_unauthorised_peer() {
    let srv = serve(allow_nobody(), None).await;
    for rpc in rpcs_in_proto() {
        let reply = raw_call(&srv.socket, &rpc, frame(&[])).await;
        assert!(
            reply.is_err(),
            "{rpc}: an unauthorised peer got an HTTP/2 answer: {reply:?}"
        );
    }
    assert!(srv.fake().calls().is_empty());
    assert!(srv
        .services
        .ctx
        .store
        .list_tenants()
        .expect("list")
        .is_empty());
}

fn create(username: &str) -> pb::CreateTenantRequest {
    pb::CreateTenantRequest {
        username: username.into(),
        owner: String::new(),
        limits: None,
    }
}

/// The server answers a well-formed request (used after every abuse).
async fn assert_alive(srv: &common::TestServer) {
    let ok = raw_call(&srv.socket, "ListTenants", frame(&[]))
        .await
        .expect("the server stopped answering");
    assert_eq!(ok.grpc_status, Some(0), "{ok:?}");
}

#[tokio::test]
async fn malformed_requests_are_refused_without_side_effects() {
    let srv = serve(allow_me(), None).await;
    let valid = create("alice").encode_to_vec();

    // Field 1 (a string) sent as a varint.
    let wrong_wire_type = vec![0x08, 0x01];
    // Field 1 with a length that runs past the end of the message.
    let length_overrun = vec![0x0a, 0x7f, b'a', b'b'];
    // Field 1 holding bytes that are not UTF-8.
    let invalid_utf8 = vec![0x0a, 0x03, 0xff, 0xfe, 0xfd];
    // A varint that never ends.
    let endless_varint = vec![0x08; 1]
        .into_iter()
        .chain([0xff; 12])
        .collect::<Vec<u8>>();

    let mut truncated = frame(&valid);
    truncated.truncate(truncated.len() - 3);
    let mut header_only = frame(&valid);
    header_only.truncate(5);
    let mut compressed_flag = frame(&valid);
    compressed_flag[0] = 1;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("wrong wire type", frame(&wrong_wire_type)),
        ("length overrun", frame(&length_overrun)),
        ("invalid UTF-8", frame(&invalid_utf8)),
        ("endless varint", frame(&endless_varint)),
        ("truncated frame", truncated),
        ("frame header only", header_only),
        ("no frame at all", Vec::new()),
        ("three stray bytes", vec![0, 0, 0]),
        ("compressed flag without an encoding", compressed_flag),
        (
            "length prefix far larger than the body",
            vec![0, 0x7f, 0xff, 0xff, 0xff, 1, 2, 3],
        ),
    ];
    for (what, body) in cases {
        let reply = raw_call(&srv.socket, "CreateTenant", body).await;
        match reply {
            // The stream was reset: also a refusal.
            Err(_) => {}
            Ok(r) => assert!(
                r.grpc_status.is_some_and(|s| s != 0),
                "{what}: expected a refusal, got {r:?}"
            ),
        }
        assert!(
            srv.fake().calls().is_empty(),
            "{what}: reached the OS: {:?}",
            srv.fake().calls()
        );
        assert!(
            srv.services
                .ctx
                .store
                .list_tenants()
                .expect("list")
                .is_empty(),
            "{what}: created a tenant"
        );
        assert_alive(&srv).await;
    }

    // Not gRPC at all.
    let r = raw_request(
        &srv.socket,
        "/oxpanel.v1.OxPanelEngine/CreateTenant",
        "application/json",
        b"{}".to_vec(),
    )
    .await
    .expect("transport");
    assert_ne!(r.grpc_status, Some(0), "{r:?}");
    let r = raw_request(
        &srv.socket,
        "/oxpanel.v1.OxPanelEngine/NoSuchMethod",
        "application/grpc",
        frame(&[]),
    )
    .await
    .expect("transport");
    assert_eq!(
        r.grpc_status,
        Some(12),
        "unknown method is UNIMPLEMENTED: {r:?}"
    );
    let r = raw_request(
        &srv.socket,
        "/some.other.Service/CreateTenant",
        "application/grpc",
        frame(&valid),
    )
    .await
    .expect("transport");
    assert_eq!(r.grpc_status, Some(12), "{r:?}");
    assert!(srv.fake().calls().is_empty());
    assert_alive(&srv).await;

    // Two messages in a unary call. The transport library serves the first
    // and never reads the second: nothing is smuggled past validation, and
    // the second request has no effect whatsoever.
    let mut two_messages = frame(&valid);
    two_messages.extend(frame(&create("root").encode_to_vec()));
    two_messages.extend(frame(&create("bob").encode_to_vec()));
    let _ = raw_call(&srv.socket, "CreateTenant", two_messages).await;
    let names: Vec<String> = srv
        .services
        .ctx
        .store
        .list_tenants()
        .expect("list")
        .into_iter()
        .map(|t| t.username)
        .collect();
    assert!(
        names.is_empty() || names == ["alice"],
        "a second message in a unary call was acted on: {names:?}"
    );
    assert_consistent(&srv.world, &srv.services, "two messages").await;
}

#[tokio::test]
async fn oversized_requests_are_refused_before_decoding() {
    let srv = serve(allow_me(), None).await;
    // A syntactically valid request that is simply too big: 300 KiB of aliases.
    let big = pb::ConfigureVirtualHostRequest {
        domain: "example.com".into(),
        tenant: "alice".into(),
        aliases: (0..20_000).map(|i| format!("a{i}.example.com")).collect(),
        ..Default::default()
    }
    .encode_to_vec();
    assert!(big.len() > MAX_REQUEST_BYTES);
    let r = raw_call(&srv.socket, "ConfigureVirtualHost", frame(&big)).await;
    match r {
        Err(_) => {}
        Ok(r) => assert!(
            matches!(r.grpc_status, Some(8 | 11)),
            "expected RESOURCE_EXHAUSTED/OUT_OF_RANGE, got {r:?}"
        ),
    }
    // A length prefix that announces 1 GiB (nothing is allocated for it).
    let mut huge = vec![0u8];
    huge.extend_from_slice(&(1u32 << 30).to_be_bytes());
    huge.extend_from_slice(&[0u8; 64]);
    let r = raw_call(&srv.socket, "CreateTenant", huge).await;
    if let Ok(r) = r {
        assert!(r.grpc_status.is_some_and(|s| s != 0), "{r:?}");
    }
    // Just under the limit is decoded, and then refused by validation.
    let fits = pb::ConfigureVirtualHostRequest {
        domain: "example.com".into(),
        tenant: "alice".into(),
        aliases: (0..10_000).map(|i| format!("a{i}.example.com")).collect(),
        ..Default::default()
    }
    .encode_to_vec();
    assert!(fits.len() < MAX_REQUEST_BYTES);
    let r = raw_call(&srv.socket, "ConfigureVirtualHost", frame(&fits))
        .await
        .expect("transport");
    assert_eq!(r.grpc_status, Some(3), "too many aliases: {r:?}");
    assert!(srv.fake().calls().is_empty());
    assert_alive(&srv).await;
}

#[tokio::test]
async fn unknown_fields_are_ignored_and_change_nothing() {
    let srv = serve(allow_me(), None).await;
    let mut body = create("alice").encode_to_vec();
    // Field 999, varint 1 — and field 1000, a length-delimited blob.
    body.extend_from_slice(&[0xb8, 0x3e, 0x01]);
    body.extend_from_slice(&[0xc2, 0x3e, 0x04, b'e', b'v', b'i', b'l']);
    let r = raw_call(&srv.socket, "CreateTenant", frame(&body))
        .await
        .expect("transport");
    assert_eq!(r.grpc_status, Some(0), "{r:?}");
    let reply = pb::CreateTenantResponse::decode(&r.body[5..]).expect("decode");
    let t = reply.tenant.expect("tenant");
    assert_eq!((t.username.as_str(), t.uid), ("alice", 20000));
    // The same request without the extra fields is the identical tenant.
    let mut client = connect(&srv.socket).await.expect("connect");
    let again = client
        .create_tenant(create("alice"))
        .await
        .expect("replay")
        .into_inner();
    assert!(
        !again.created,
        "the unknown fields were not part of the spec"
    );
    // A field given twice: the last value wins, as protobuf specifies; it is
    // validated like any other value.
    let mut twice = create("carol").encode_to_vec();
    twice.extend_from_slice(&create("root").encode_to_vec());
    let r = raw_call(&srv.socket, "CreateTenant", frame(&twice))
        .await
        .expect("transport");
    assert_eq!(r.grpc_status, Some(3), "'root' is reserved: {r:?}");
    assert_consistent(&srv.world, &srv.services, "unknown fields").await;
}

static PANICS: AtomicUsize = AtomicUsize::new(0);

/// Random bytes, random valid-looking messages with hostile strings, against
/// every RPC. Whatever happens, no handler may panic, the state must stay
/// consistent, and the server must keep answering.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn random_requests_never_panic_or_corrupt_state() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        PANICS.fetch_add(1, Ordering::SeqCst);
        previous(info);
    }));
    let srv = serve(allow_me(), None).await;
    let rpcs = rpcs_in_proto();
    let mut runner = TestRunner::deterministic();
    let bytes = proptest::collection::vec(any::<u8>(), 0..600);
    // Strings a hostile panel would try: metacharacters, traversal, control
    // characters, very long values, plus plausible names.
    let hostile = prop_oneof![
        "[a-z][a-z0-9_-]{2,12}",
        "[a-z0-9-]{1,10}(\\.[a-z0-9-]{1,10}){1,3}",
        ".{0,40}",
        "(\\.\\./){1,6}etc/(passwd|shadow)",
        "[a-z]{1,5}[;{}$\"'`\\\\\n\r\t\0 ][a-z]{1,5}",
        "/[a-z/]{1,30}",
        "[a-z]{300,400}",
    ];
    for i in 0..400 {
        let rpc = rpcs.get(i % rpcs.len()).expect("rpc");
        let raw = bytes.new_tree(&mut runner).expect("tree").current();
        let _ = raw_call(&srv.socket, rpc, frame(&raw)).await;
        let mut s = || hostile.new_tree(&mut runner).expect("tree").current();
        let body = match i % 6 {
            0 => pb::CreateTenantRequest {
                username: s(),
                owner: s(),
                limits: Some(pb::ResourceLimits {
                    memory_max_bytes: u64::MAX - (i as u64),
                    cpu_weight: u32::MAX,
                    io_weight: i as u32,
                    tasks_max: u32::MAX,
                    disk_max_bytes: u64::MAX - (i as u64),
                    inodes_max: i as u64,
                    ..Default::default()
                }),
            }
            .encode_to_vec(),
            1 => pb::ConfigureVirtualHostRequest {
                domain: s(),
                tenant: s(),
                document_root: s(),
                aliases: vec![s(), s()],
                php: i % 2 == 0,
                app: Some(pb::App {
                    runtime: i32::try_from(i % 5).unwrap_or(0) - 1,
                    root: s(),
                    entry: s(),
                }),
                redirect_https: i % 3 == 0,
                hsts: i % 2 == 1,
                auto_https_opt_out: i % 4 == 0,
                dns_opt_out: i % 5 == 0,
            }
            .encode_to_vec(),
            2 => pb::ReadVirtualHostLogRequest {
                domain: s(),
                kind: i32::try_from(i % 7).unwrap_or(0) - 2,
                max_bytes: u32::MAX,
            }
            .encode_to_vec(),
            3 => pb::DeleteTenantRequest {
                username: s(),
                remove_home: true,
                ..Default::default()
            }
            .encode_to_vec(),
            4 => pb::UpdateTenantOwnerRequest {
                username: s(),
                owner: s(),
            }
            .encode_to_vec(),
            _ => pb::RemoveVirtualHostRequest { domain: s() }.encode_to_vec(),
        };
        let _ = raw_call(&srv.socket, rpc, frame(&body)).await;
    }
    assert_eq!(
        PANICS.load(Ordering::SeqCst),
        0,
        "a request handler panicked"
    );
    assert_alive(&srv).await;
    assert_consistent(&srv.world, &srv.services, "after random requests").await;
    // Whatever was created went through validation: every account name the
    // fake OS saw is a valid tenant name, and nothing ran outside the sandbox.
    for call in srv.fake().calls() {
        for arg in &call.args {
            let arg = arg.to_string_lossy();
            assert!(
                !arg.contains("..") && !arg.contains('\n') && !arg.contains(';'),
                "hostile argument reached the OS: {} {arg:?}",
                call.program
            );
        }
    }
}

#[tokio::test]
async fn idle_and_abusive_connections_do_not_starve_other_clients() {
    use tokio::io::AsyncWriteExt as _;
    let srv = serve(allow_me(), None).await;
    let mut idle = Vec::new();
    for i in 0..200 {
        let mut c = tokio::net::UnixStream::connect(&srv.socket)
            .await
            .expect("connect");
        match i % 3 {
            // Says nothing.
            0 => {}
            // Speaks HTTP/1.
            1 => {
                let _ = c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
            }
            // Starts an HTTP/2 preface and stops half-way.
            _ => {
                let _ = c.write_all(b"PRI * HTTP/2.0\r\n\r\nSM").await;
            }
        }
        idle.push(c);
    }
    let started = Instant::now();
    assert_alive(&srv).await;
    let mut client = connect(&srv.socket).await.expect("connect");
    client.create_tenant(create("alice")).await.expect("create");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "requests were delayed by idle connections: {:?}",
        started.elapsed()
    );
    drop(idle);
    assert_consistent(&srv.world, &srv.services, "idle connections").await;
}

fn limits(memory_mib: u64) -> Option<pb::ResourceLimits> {
    Some(pb::ResourceLimits {
        memory_max_bytes: memory_mib << 20,
        cpu_weight: 0,
        io_weight: 0,
        tasks_max: 0,
        disk_max_bytes: 0,
        inodes_max: 0,
        ..Default::default()
    })
}

fn vhost(domain: &str, tenant: &str, kind: usize) -> pb::ConfigureVirtualHostRequest {
    pb::ConfigureVirtualHostRequest {
        domain: domain.into(),
        tenant: tenant.into(),
        php: kind == 1,
        app: match kind {
            2 => Some(pb::App {
                runtime: pb::AppRuntime::Node.into(),
                ..Default::default()
            }),
            3 => Some(pb::App {
                runtime: pb::AppRuntime::Python.into(),
                ..Default::default()
            }),
            _ => None,
        },
        ..Default::default()
    }
}

/// Eight clients create, configure, suspend, resume, remove and delete at
/// once, fight over one tenant name and one domain, while two readers list
/// and reconcile. No deadlock; the fights have exactly one winner; no reader
/// ever sees a half-done workflow; the end state is consistent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_clients_neither_deadlock_nor_corrupt_state() {
    const WORKERS: usize = 8;
    const ROUNDS: usize = 6;
    let srv = Arc::new(serve(allow_me(), None).await);
    let shared_created = Arc::new(AtomicUsize::new(0));
    let contested_won = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let mut readers = Vec::new();
    for _ in 0..2 {
        let (srv, done) = (srv.clone(), done.clone());
        readers.push(tokio::spawn(async move {
            let mut c = connect(&srv.socket).await.expect("connect");
            let mut n = 0u32;
            while !done.load(Ordering::SeqCst) {
                c.list_tenants(pb::ListTenantsRequest::default())
                    .await
                    .expect("list tenants");
                c.list_virtual_hosts(pb::ListVirtualHostsRequest::default())
                    .await
                    .expect("list vhosts");
                c.get_host_info(pb::GetHostInfoRequest {})
                    .await
                    .expect("info");
                let drifts = c
                    .reconcile(pb::ReconcileRequest {})
                    .await
                    .expect("reconcile")
                    .into_inner()
                    .drifts;
                assert!(
                    drifts.is_empty(),
                    "a reader saw a workflow half done: {drifts:?}"
                );
                n += 1;
            }
            n
        }));
    }

    let mut workers = Vec::new();
    for w in 0..WORKERS {
        let (srv, shared_created, contested_won) =
            (srv.clone(), shared_created.clone(), contested_won.clone());
        workers.push(tokio::spawn(async move {
            let mut c = connect(&srv.socket).await.expect("connect");
            // Everyone creates the same tenant with the same specification.
            let r = c
                .create_tenant(pb::CreateTenantRequest {
                    username: "shared".into(),
                    owner: "team".into(),
                    limits: limits(64),
                })
                .await
                .expect("shared tenant")
                .into_inner();
            if r.created {
                shared_created.fetch_add(1, Ordering::SeqCst);
            }
            for round in 0..ROUNDS {
                let tenant = format!("wk{w}x{round}");
                let domain = format!("s{w}-{round}.example");
                c.create_tenant(pb::CreateTenantRequest {
                    username: tenant.clone(),
                    owner: String::new(),
                    limits: limits(64),
                })
                .await
                .expect("create");
                // Everyone wants the same domain for a different tenant.
                match c
                    .configure_virtual_host(vhost("contested.example", &tenant, 0))
                    .await
                {
                    Ok(_) => {
                        contested_won.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(e) => assert_eq!(e.code(), Code::FailedPrecondition, "{e}"),
                }
                c.configure_virtual_host(vhost(&domain, &tenant, (w + round) % 4))
                    .await
                    .expect("configure");
                c.configure_virtual_host(vhost(
                    &format!("sh{w}-{round}.example"),
                    "shared",
                    round % 4,
                ))
                .await
                .expect("configure on the shared tenant");
                c.update_tenant_limits(pb::UpdateTenantLimitsRequest {
                    username: tenant.clone(),
                    limits: limits(128),
                })
                .await
                .expect("limits");
                c.suspend_tenant(pb::SuspendTenantRequest {
                    username: tenant.clone(),
                })
                .await
                .expect("suspend");
                if round % 3 != 0 {
                    c.resume_tenant(pb::ResumeTenantRequest {
                        username: tenant.clone(),
                    })
                    .await
                    .expect("resume");
                }
                if round % 2 == 0 {
                    c.remove_virtual_host(pb::RemoveVirtualHostRequest {
                        domain: domain.clone(),
                    })
                    .await
                    .expect("remove");
                    let _ = c
                        .remove_virtual_host(pb::RemoveVirtualHostRequest {
                            domain: "contested.example".into(),
                        })
                        .await;
                    // Refused while the tenant still owns the contested site
                    // (if another worker re-took it meanwhile, it is not ours).
                    let _ = c
                        .delete_tenant(pb::DeleteTenantRequest {
                            username: tenant,
                            remove_home: true,
                            ..Default::default()
                        })
                        .await;
                }
            }
        }));
    }
    let all = async {
        for w in workers {
            w.await.expect("worker");
        }
        done.store(true, Ordering::SeqCst);
        let mut reads = 0;
        for r in readers {
            reads += r.await.expect("reader");
        }
        reads
    };
    let reads = tokio::time::timeout(Duration::from_secs(120), all)
        .await
        .expect("deadlock: the clients did not finish within 120 s");
    assert!(reads > 0);
    assert_eq!(
        shared_created.load(Ordering::SeqCst),
        1,
        "exactly one client created the shared tenant"
    );
    assert!(contested_won.load(Ordering::SeqCst) >= 1);
    let owners = srv
        .services
        .ctx
        .store
        .list_vhosts()
        .expect("list")
        .into_iter()
        .filter(|v| v.domain == "contested.example")
        .count();
    assert!(owners <= 1, "a domain has one owner at most");
    let shared_sites = srv
        .services
        .vhosts
        .list(Some("shared"))
        .await
        .expect("list")
        .len();
    assert_eq!(shared_sites, WORKERS * ROUNDS, "no configure was lost");
    assert_consistent(&srv.world, &srv.services, "after the concurrent run").await;
}

/// Two different fields of the same record, changed by two clients at the
/// same instant, both survive — every round.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_updates_of_one_tenant_are_not_lost() {
    let srv = serve(allow_me(), None).await;
    let mut a = connect(&srv.socket).await.expect("connect");
    let mut b = connect(&srv.socket).await.expect("connect");
    let mut c = connect(&srv.socket).await.expect("connect");
    a.create_tenant(create("alice")).await.expect("create");
    a.configure_virtual_host(vhost("example.com", "alice", 1))
        .await
        .expect("site");
    for round in 1..=40u64 {
        let owner = format!("owner{round}");
        let (r1, r2, r3) = tokio::join!(
            a.update_tenant_owner(pb::UpdateTenantOwnerRequest {
                username: "alice".into(),
                owner: owner.clone(),
            }),
            b.update_tenant_limits(pb::UpdateTenantLimitsRequest {
                username: "alice".into(),
                limits: limits(64 + round),
            }),
            async {
                if round % 2 == 0 {
                    c.suspend_tenant(pb::SuspendTenantRequest {
                        username: "alice".into(),
                    })
                    .await
                } else {
                    c.resume_tenant(pb::ResumeTenantRequest {
                        username: "alice".into(),
                    })
                    .await
                }
            }
        );
        r1.expect("owner");
        r2.expect("limits");
        r3.expect("suspension");
        let t = a
            .get_tenant(pb::GetTenantRequest {
                username: "alice".into(),
            })
            .await
            .expect("get")
            .into_inner();
        assert_eq!(t.owner, owner, "round {round}: the owner update was lost");
        assert_eq!(
            t.limits.map(|l| l.memory_max_bytes),
            Some((64 + round) << 20),
            "round {round}: the limits update was lost"
        );
        assert_eq!(t.suspended, round % 2 == 0, "round {round}");
    }
    assert_consistent(&srv.world, &srv.services, "after concurrent updates").await;
}

/// `InstallAppDependencies` may run for minutes. It must not hold the
/// mutation lock: other tenants are provisioned while it runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_running_dependency_installation_blocks_nobody() {
    let srv = serve(allow_me(), None).await;
    let mut c = connect(&srv.socket).await.expect("connect");
    c.create_tenant(create("alice")).await.expect("create");
    c.configure_virtual_host(vhost("app.example", "alice", 2))
        .await
        .expect("app");
    srv.world
        .chaos
        .delay(bin::SYSTEMD_RUN, Duration::from_millis(1500));

    let mut installer = connect(&srv.socket).await.expect("connect");
    let started = Instant::now();
    let install = tokio::spawn(async move {
        installer
            .install_app_dependencies(pb::InstallAppDependenciesRequest {
                domain: "app.example".into(),
            })
            .await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !install.is_finished(),
        "the installation should still be running"
    );
    c.create_tenant(create("bob"))
        .await
        .expect("create during install");
    c.configure_virtual_host(vhost("bob.example", "bob", 1))
        .await
        .expect("configure during install");
    c.reconcile(pb::ReconcileRequest {})
        .await
        .expect("reconcile during install");
    let others = started.elapsed();
    assert!(
        !install.is_finished(),
        "other requests waited for the installation"
    );
    assert!(others < Duration::from_millis(1400), "{others:?}");
    let r = install.await.expect("join").expect("install").into_inner();
    assert!(r.succeeded);
    assert_consistent(&srv.world, &srv.services, "after the installation").await;
}

/// Suspension while an installation is running: when the installer finishes
/// it must not restart the application of the (now suspended) tenant, and
/// removal of the site meanwhile must not make it fail or resurrect anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_installation_cannot_revive_a_suspended_or_removed_application() {
    for removed in [false, true] {
        let srv = serve(allow_me(), None).await;
        let mut c = connect(&srv.socket).await.expect("connect");
        c.create_tenant(create("alice")).await.expect("create");
        c.configure_virtual_host(vhost("app.example", "alice", 2))
            .await
            .expect("app");
        srv.world
            .chaos
            .delay(bin::SYSTEMD_RUN, Duration::from_millis(800));
        let mut installer = connect(&srv.socket).await.expect("connect");
        let install = tokio::spawn(async move {
            installer
                .install_app_dependencies(pb::InstallAppDependenciesRequest {
                    domain: "app.example".into(),
                })
                .await
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        if removed {
            c.remove_virtual_host(pb::RemoveVirtualHostRequest {
                domain: "app.example".into(),
            })
            .await
            .expect("remove during install");
        } else {
            c.suspend_tenant(pb::SuspendTenantRequest {
                username: "alice".into(),
            })
            .await
            .expect("suspend during install");
        }
        assert!(!install.is_finished());
        let r = install.await.expect("join").expect("install").into_inner();
        assert!(r.succeeded, "the installer itself succeeded");
        assert!(
            running_units(srv.fake()).is_empty(),
            "removed={removed}: the application runs again: {:?}",
            running_units(srv.fake())
        );
        assert_consistent(&srv.world, &srv.services, "installation vs suspension").await;
    }
}
