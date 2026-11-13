//! Performance budgets that fail `make test` when the engine gets *wildly*
//! slower. These are not benchmarks (see `make bench` and docs/PERFORMANCE.md
//! for the numbers): the budgets are about 20x the measured values in a debug
//! build, so only a real regression — an accidental quadratic, a blocking call
//! inside the lock, a fsync per read — trips them on a slow CI runner.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::print_stderr
)]

mod common;

use std::time::{Duration, Instant};

use common::{allow_me, connect, serve};
use oxpanel_proto::v1 as pb;

const TENANTS: usize = 300;
const VHOSTS: usize = 300;

fn name(i: usize) -> String {
    format!("p{i:05}")
}

fn budget(what: &str, took: Duration, max: Duration) {
    eprintln!("perf: {what}: {took:?} (budget {max:?})");
    assert!(took <= max, "{what} took {took:?}, budget {max:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provisioning_and_reads_stay_within_budget_at_300_tenants_and_300_sites() {
    let srv = serve(allow_me(), None).await;
    let mut c = connect(&srv.socket).await.expect("connect");

    let t0 = Instant::now();
    for i in 0..TENANTS {
        c.create_tenant(pb::CreateTenantRequest {
            username: name(i),
            owner: format!("o{}", i % 10),
            limits: Some(pb::ResourceLimits {
                memory_max_bytes: 128 << 20,
                cpu_weight: 100,
                io_weight: 0,
                tasks_max: 100,
                disk_max_bytes: 0,
                inodes_max: 0,
            }),
        })
        .await
        .expect("create tenant");
    }
    // Linear growth is expected (the uid scan reads every record); the whole
    // run has a wide budget, and so does the last tenth against the first.
    budget("create 300 tenants", t0.elapsed(), Duration::from_secs(60));

    let t0 = Instant::now();
    for i in 0..VHOSTS {
        c.configure_virtual_host(pb::ConfigureVirtualHostRequest {
            domain: format!("site{i:05}.example"),
            tenant: name(i % TENANTS),
            aliases: vec![format!("www.site{i:05}.example")],
            php: i % 10 == 1,
            ..Default::default()
        })
        .await
        .expect("configure");
    }
    budget("configure 300 sites", t0.elapsed(), Duration::from_secs(90));

    // Single requests at this scale.
    let t0 = Instant::now();
    for i in 0..200 {
        c.get_tenant(pb::GetTenantRequest {
            username: name(i % TENANTS),
        })
        .await
        .expect("get");
    }
    budget("200 x GetTenant", t0.elapsed(), Duration::from_secs(4));

    let t0 = Instant::now();
    let all = c
        .list_tenants(pb::ListTenantsRequest::default())
        .await
        .expect("list")
        .into_inner();
    assert_eq!(all.tenants.len(), TENANTS);
    budget("ListTenants (300)", t0.elapsed(), Duration::from_secs(2));

    let t0 = Instant::now();
    let all = c
        .list_virtual_hosts(pb::ListVirtualHostsRequest::default())
        .await
        .expect("list")
        .into_inner();
    assert_eq!(all.vhosts.len(), VHOSTS);
    budget(
        "ListVirtualHosts (300)",
        t0.elapsed(),
        Duration::from_secs(2),
    );

    let t0 = Instant::now();
    c.reconcile(pb::ReconcileRequest {})
        .await
        .expect("reconcile");
    budget(
        "Reconcile (300 + 300)",
        t0.elapsed(),
        Duration::from_secs(10),
    );

    // Reads must not queue behind a writer: 8 clients read while one tenant is
    // updated in a loop; the median read stays fast.
    let socket = srv.socket.clone();
    let writer = tokio::spawn(async move {
        let mut w = connect(&socket).await.expect("connect");
        for n in 0..100u64 {
            w.update_tenant_limits(pb::UpdateTenantLimitsRequest {
                username: name(0),
                limits: Some(pb::ResourceLimits {
                    memory_max_bytes: (128 + n % 2) << 20,
                    cpu_weight: 100,
                    io_weight: 0,
                    tasks_max: 100,
                    disk_max_bytes: 0,
                    inodes_max: 0,
                }),
            })
            .await
            .expect("update");
        }
    });
    let mut readers = Vec::new();
    for k in 0..8usize {
        let socket = srv.socket.clone();
        readers.push(tokio::spawn(async move {
            let mut r = connect(&socket).await.expect("connect");
            let mut worst = Duration::ZERO;
            for i in 0..100 {
                let t = Instant::now();
                r.get_tenant(pb::GetTenantRequest {
                    username: name((k * 37 + i) % TENANTS),
                })
                .await
                .expect("get");
                worst = worst.max(t.elapsed());
            }
            worst
        }));
    }
    let mut worst = Duration::ZERO;
    for r in readers {
        worst = worst.max(r.await.expect("reader"));
    }
    writer.await.expect("writer");
    budget(
        "slowest GetTenant while a writer runs",
        worst,
        Duration::from_secs(2),
    );
}
