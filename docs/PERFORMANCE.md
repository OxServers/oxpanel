# OxPanel engine — performance

Two kinds of numbers, from two tools, because they answer different questions.

| Tool | What it measures | Runs |
|---|---|---|
| `make bench` (`oxpanel-bench`) | The engine's **own** cost: record files, rendering, locking, gRPC, against the in-memory fake OS (`useradd`, `nginx -t`, `systemctl` take no time). Release build. | by hand and nightly in CI; **never** in `make check` |
| acceptance phase 90 | What provisioning costs on a **real** host: real `useradd`, `nginx -t`, `systemctl`, `semanage`, SELinux enforcing. | `make acceptance` |
| `tests/perf_budget.rs` | Budgets about 20x the measured values, in a debug build: a quadratic mistake fails `make test`; noise does not. | every `make test` |

Reproduce: `make bench ARGS="--tenants 1000,10000 --vhosts 5000 --seconds 3"`;
`OXPANEL_BENCH_DIR=/dev/shm` puts the state on tmpfs (CPU cost without file-system latency).

## Machines

* **Bench**: 11th Gen Intel Core i7-1185G7 @ 3.00 GHz, 8 logical CPUs, 30 GiB RAM, state in
  `/tmp` (tmpfs), AlmaLinux 9 container (rustc 1.98.1, `--release`, `lto = "thin"`).
  **The machine was shared with other test runs** (load average 4 to 5 on 8 CPUs for the whole
  measurement) so every figure is an upper bound; an earlier run of the same code at lower load
  was up to 1.6x faster. Treat the *shape* (what grows, by how much) as the result, not the third digit.
* **Real host**: AlmaLinux 9.x cloud image under QEMU/KVM, 2 vCPU, 2 GiB RAM, virtio disk, SELinux
  enforcing, the RPM built from the tested commit, on the same workstation (also shared).

## What scales how

The record store is one JSON file per tenant and per virtual host. Three request kinds
read **every** record of a kind; everything else touches one file:

| Request | Reads | Why |
|---|---|---|
| `CreateTenant` | all tenants | uid allocation (lowest free id) |
| `ConfigureVirtualHost` | all virtual hosts | every server name must be unique across the host |
| `ListTenants`, `ListVirtualHosts`, `Reconcile`, start-up convergence | all | by definition |
| `GetTenant`, `UpdateTenantLimits`, `RemoveVirtualHost`, `SuspendTenant`/`ResumeTenant` (one tenant's sites), `GetTenantUsage` | one record (suspend: all sites, to find the tenant's) | |
| `GetHostInfo` | directory entry counts only (since this work: it parsed every record before) | |

So provisioning cost per request is **linear in the number of objects**, and the cost of
provisioning N objects is quadratic. The numbers below say where that stops being acceptable.

## Results: engine against the fake OS

### 1,000 tenants, 5,000 virtual hosts

| Provisioning | first tenth | middle | last tenth | total | throughput |
|---|---|---|---|---|---|
| CreateTenant | 2.07 ms each | 11.0 ms | 10.5 ms | 8.1 s | 123/s |
| ConfigureVirtualHost | 2.66 ms each | 25.4 ms | 32.3 ms | 107.9 s | 46/s |

| Single request at full scale | time |
|---|---|
| GetTenant | 0.07 ms |
| ListTenants (all 1,000) | 9.9 ms |
| ListVirtualHosts (all 5,000) | 39.6 ms |
| ListVirtualHosts (one tenant) | 32.1 ms (scans all) |
| GetHostInfo | 2.4 ms (was 30.3 ms before the fix) |
| Reconcile | 109 ms |
| UpdateTenantLimits (no change) | 0.11 ms |
| ConfigureVirtualHost (replay, no change) | 31.2 ms |
| Suspend + Resume of one tenant | 127 ms |
| CreateTenant (one more) | 7.6 ms |
| RemoveVirtualHost | 0.2 ms |
| DeleteTenant | 33.8 ms |

| Read RPC under concurrency | clients | requests/s | p50 | p95 | p99 |
|---|---|---|---|---|---|
| GetTenant | 1 / 8 / 64 | 15,149 / 40,379 / 54,810 | 0.06 / 0.16 / 1.09 ms | 0.09 / 0.40 / 1.90 ms | 0.11 / 0.61 / 2.95 ms |
| ListVirtualHosts (one tenant) | 1 / 8 / 64 | 30 / 82 / 88 | 32 / 95 / 393 ms | 41 / 117 / 715 ms | 47 / 150 / 834 ms |
| ListTenants (all) | 1 / 8 / 64 | 49 / 168 / 157 | 20 / 43 / 295 ms | 24 / 87 / 588 ms | 27 / 133 / 699 ms |
| GetHostInfo | 1 / 8 / 64 | 194 / 286 / 312 | 5.1 / 25.8 / 169 ms | 6.1 / 53 / 333 ms | 8.0 / 70 / 449 ms |
| GetTenant while a writer updates 576 times/s | 8 | 12,075 | 0.44 ms | 1.60 ms | 4.88 ms |

Reads do **not** queue behind writers: with a writer holding the mutation lock continuously,
`GetTenant` p99 stays under 5 ms. Process size at this scale: 37 MiB (including the benchmark's own clients).

### 10,000 tenants, 5,000 virtual hosts

| Provisioning | first tenth | middle | last tenth | total | throughput |
|---|---|---|---|---|---|
| CreateTenant | 10.0 ms each | 39.3 ms | 102 ms | 411.7 s | 24/s |
| ConfigureVirtualHost | 1.7 ms each | 17.6 ms | 31.9 ms | 87.3 s | 57/s |

(`ConfigureVirtualHost` depends on the number of *sites*, not tenants: it costs the same as in the 1,000-tenant table.)

| Single request at full scale | time |
|---|---|
| GetTenant | 0.10 ms |
| ListTenants (all 10,000) | 97.7 ms |
| ListTenants (one owner of 20) | 75.0 ms (scans all) |
| ListVirtualHosts (all 5,000) | 41.9 ms |
| GetHostInfo | 9.5 ms (277 ms before the fix) |
| Reconcile (10,000 + 5,000) | 453 ms |
| ConfigureVirtualHost (replay, no change) | 34.8 ms |
| Suspend + Resume of one tenant | 130 ms |
| CreateTenant (one more) | 65.8 ms |
| DeleteTenant | 28.7 ms |

| Read RPC under concurrency | clients | requests/s | p50 | p95 | p99 |
|---|---|---|---|---|---|
| GetTenant | 1 / 8 / 64 | 14,593 / 36,085 / 48,697 | 0.07 / 0.18 / 1.22 ms | 0.10 / 0.44 / 2.25 ms | 0.12 / 0.68 / 3.11 ms |
| ListVirtualHosts (one tenant) | 1 / 8 / 64 | 21 / 50 / 52 | 43 / 144 / 522 ms | 63 / 281 / 920 ms | 70 / 296 / 1,021 ms |
| ListTenants (all) | 1 / 8 / 64 | 7 / 27 / 36 | 136 / 308 / 1,211 ms | 158 / 458 / 1,966 ms | 162 / 501 / 2,026 ms |
| GetHostInfo | 1 / 8 / 64 | 65 / 289 / 217 | 13 / 26 / 218 ms | 21 / 45 / 610 ms | 21 / 51 / 684 ms |
| GetTenant while a writer updates 1,585 times/s | 8 | 28,090 | 0.24 ms | 0.59 ms | 1.07 ms |

Process size: 82 MiB (including the benchmark's own clients); records on disk: 5.2 MiB.
(An earlier run of the same code, before `GetHostInfo` was fixed and at lower machine load,
measured `CreateTenant` 5.2 / 32.8 / 123.6 ms; the figures move by a third with load.)


## Results: a real host (acceptance phase 90)

100 tenants, each with one static site, created one after the other through `oxpanel-ctl`
on the real host (final acceptance run; an earlier run on the same VM measured the same within 10 %):

| Step | Measured |
|---|---|
| `CreateTenant` (real `useradd`, home, slice units, `daemon-reload`, `restorecon`) | median 142 ms for the first ten, 175 ms for the last ten; 201 ms at its worst |
| `ConfigureVirtualHost` (docroot as the tenant, ACLs, `semanage fcontext`, `restorecon`, Nginx file, `nginx -t`, reload) | median 505 ms first ten, 629 ms last ten; most of it is the external tools (`semanage` is a Python program started per call; the split was not timed separately) |
| One tenant plus one site | 0.7 s each: 100 pairs in 69 s |
| Nginx `reload` | 18 ms at 1 site, 27 ms at 100 |
| `nginx -t` | 5 ms at 1 site, 10 ms at 100 |
| `ListTenants` / `ListVirtualHosts` at 100 (wall time including starting `oxpanel-ctl`) | 5 ms / 4 ms |
| `Reconcile` at 100 tenants and 100 sites | 12 ms |
| `GetHostInfo` (wall, incl. `oxpanel-ctl`; it runs `node --version`) | 31 ms |
| `SuspendTenant` / `ResumeTenant` (one site) | 36 ms / 34 ms |
| Daemon restart until it answers, 100 tenants and sites | 4 ms |
| Daemon resident memory | 9.4 MB at start, 9.5 MB at 100 sites, 6.0 MB after teardown |

Reading: the engine's own share of a provisioning request is a few milliseconds; the rest is the
tools it drives (`useradd`, `semanage`, `restorecon`, `setfacl`, `nginx -t`, `systemctl`). The
growth from the first to the last ten sites (about 1.2x) is the linear scan plus the Nginx reload and
validation cost growing with the number of server blocks, and is far inside the 5x budget. Nginx reload
cost is small enough that the daemon reloading on every change (it does) is not a problem at 100 sites;
at several thousand sites `nginx -t` (it parses every file) will dominate; that was not measured on the VM
(2 GiB of RAM) and is an open question: see the bench's tenants-and-sites tables for the engine side only.


## Budgets

Explicit, wide, and enforced where cheap.

| Quantity | Budget | Measured | Enforced by |
|---|---|---|---|
| `GetTenant`, 200 sequential, 300 tenants (debug build) | 4 s | 0.7 s | `perf_budget.rs` (`make test`) |
| `CreateTenant` x 300 (debug) | 60 s | 4.3 s | `perf_budget.rs` |
| `ConfigureVirtualHost` x 300 (debug) | 90 s | 3.5 s | `perf_budget.rs` |
| `ListTenants` / `ListVirtualHosts` at 300 (debug) | 2 s | 25 ms / 19 ms | `perf_budget.rs` |
| `Reconcile` at 300 + 300 (debug) | 10 s | 92 ms | `perf_budget.rs` |
| Slowest `GetTenant` while a writer runs (debug) | 2 s | 129 ms | `perf_budget.rs` |
| One tenant plus one site on a real host | 1.5 s (about 2x measured) | 0.7 s | phase 90 |
| Provisioning time per request grows at most 5x from the first to the last tenth (real host) | 5x | flat | phase 90 |
| Daemon resident memory | 100 MB | 9.5 MB at 100 sites | phase 90 |
| Any mutating request, up to 1,000 tenants and 5,000 sites (design point) | 100 ms | 2.7 to 33 ms (loaded machine) | `make bench` (read by a person) |
| Dashboard reads (`GetHostInfo`, `GetTenant`), same scale | 10 ms | 2.4 ms, 0.07 ms | `make bench` |

The two lines marked "by a person" are not gates: `make bench` is too long and too machine-dependent for CI.
The nightly CI `bench` job uploads its output so a regression is visible as a changed table.

## Where it stops being acceptable

* **Up to about 1,000 tenants and 5,000 sites per host** every operation is under 100 ms in the engine
  itself; a real host's `useradd`, `nginx -t` and `semanage` cost far more than the engine does
  (see the real-host table: the engine's share is a few percent). File-per-record is fine here.
* **At 10,000 tenants** creating a tenant costs 66 to 102 ms (10 ms at the start) in the engine, and a full listing
  98 ms for one client and 1.2 s at the median when 64 clients ask at once; nothing fails, but a panel that lists everything on every page view, or provisions
  thousands of accounts in a loop, will feel it. These are the limits of file-per-record, not bugs:
  the fix is an in-memory index built at start-up and kept current under the mutation lock, which
  turns the three linear scans into hash lookups.
* **Not fixed in this work, and why.** The index is a change to the records module that every other stream
  (TLS, SFTP, databases, backups) is also editing, and it needs an answer to "what if someone edits a record
  while the daemon runs" that the owner should decide (re-read on `Reconcile`? watch the directory?).
  What was cheap and safe was fixed: `GetHostInfo` no longer parses records (12x faster at 1,000/5,000).
* Blocking file I/O runs on the async runtime's worker threads (the stores are synchronous). Under 64
  concurrent full listings at 10,000 tenants every worker is busy, and unrelated reads queue behind them;
  it takes a client that asks for the whole list repeatedly to see it. Moving the scans to
  `spawn_blocking` is a small change; it was left because it does not change the numbers above for a single client.
