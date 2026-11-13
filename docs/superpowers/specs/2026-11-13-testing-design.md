# Testing programme B/C/D: security, performance, traceability, QA (M5) — design

Date: 2026-11-13. Status: implemented on branch `m5-testing`, on top of commit `d38bae2`.

## Goal

Prove the engine as it stands (tenants, virtual hosts, PHP, Node.js and Python
applications, per-site logs, management RPCs, scopes) is secure, robust and fast
enough, with tests that stay in the repository and run in CI. Tests, tooling
and documents are added; production code changes only to fix a defect a test
found, each with the test that found it.

## Decisions

**Property tests, not a fuzzing set-up.** Every validator and renderer is
covered by `proptest` properties that run inside `make test` in about a second
(`oxpanel-daemon/tests/properties.rs`, `src/proptests.rs` for crate-private
parsers). A coverage-guided fuzz target (`cargo-fuzz`) needs a nightly
toolchain and a sanitizer runtime that the container image does not have, and a
target nobody runs finds nothing. The properties assert what the types promise
(an accepted path never contains `..`; an accepted domain contains nothing that
could end an Nginx directive; a rendered unit or configuration is its template
with the validated inputs and nothing else), plus that no input panics.
*Rejected:* `cargo-fuzz` now; adding it later needs only a `fuzz/` directory and
reuses the same property bodies.

**The gRPC surface is tested through a real server.** `tests/common` boots the
daemon library in-process on a UNIX socket behind the real peer gate, with the
real transport limits, and a raw HTTP/2 client that can send frames no
well-behaved client would (truncated, oversized, a compression flag with no
codec, random protobuf). The list of RPCs is read from `panel.proto` at test
time, and a table of scope decisions must name every one: **a new RPC without
a scope decision fails the build.** Each RPC is then called by an unauthorised
peer, by a peer holding every scope but its own, and by a peer holding exactly
its own.

**Crash safety is exhaustive, not sampled.** A fault-injecting `System` wraps
the fake OS. For each of fifteen operations (create tenant, update limits,
configure static/PHP/Node.js/Python sites, PHP off, app off, static to PHP,
suspend, resume, remove static/PHP/app site, delete tenant) and for every
external command the operation runs, the test interrupts it three ways: the
command fails, the daemon is killed just before it, the daemon is killed just
after it (the workflow's future is frozen inside the command and dropped, so no
clean-up code runs). A new daemon is then booted on the same disk, the request
is repeated, and it must succeed and leave records, files, accounts and
running units in agreement (`assert_consistent`, which includes a clean
`Reconcile`). Also run with the SELinux code paths enabled. This is stronger
than acceptance phase 50's one hand-picked kill and is cheap because the fake
OS is in memory.

**Attacks run on the real host, from inside the tenant's code.** Phase 80
(`tests-acceptance/phases/80-attacks.sh`) installs a probe battery in the
attacker's own PHP, Node.js and Python code and reads back, per probe,
"OPEN" or "BLOCKED" against an expectation. Each read or write is tried twice:
with the language's own API and through a child process (`cat`, `touch`), so
that PHP's `open_basedir` cannot hide a hole in the operating-system layer.
Probes with an expectation of "open" (the tenant's own files) prove the harness
can succeed at all. Heavier attacks (memory, fork, `/tmp`, detached children,
links the daemon trips over, header smuggling) are separate sections.
Classification of SELinux denials is in the phase header and in
`docs/SECURITY.md`.
*Rejected:* a generic exploit framework; testing from outside through the web
server only (it cannot make the daemon walk a planted link).

**Benchmarks run the real daemon against the fake OS.** `make bench`
(`oxpanel-bench`, a workspace member that `make check` builds and lints but
never runs) measures what is the engine's own: record I/O, rendering, locking,
gRPC. What `useradd`, `nginx -t` and `semanage` cost on a real host is measured
by acceptance phase 90 on the VM. Cheap budgets live in
`tests/perf_budget.rs` (about 20x the measured value) so a quadratic mistake
fails `make test` on a slow runner, but normal noise does not.

**Traceability is a text file and a shell script.** `docs/traceability.map`
names, for every row of `docs/FEATURES.md`, the tests that prove it;
`scripts/traceability.sh` (part of `make check` and CI) fails on a row with no
test, a mapping for a row that no longer exists, and a reference to a test
or check that no longer exists. Pure bash and `grep`: it needs no toolchain and
runs in a second. The cost is that a stream adding a FEATURES row must add its
mapping in the same change: that is the point.

**Coverage with `cargo-llvm-cov`, gated at a floor below the measurement.**
Measured in the container; the floor in `scripts/coverage.sh` is a few points
under the measured value, so it catches a suite that stops running rather than
punishing a point. `system/real.rs` (the process runner that needs root and a
real host) and the `main.rs` entry point are excluded and are covered by the
integration and acceptance suites instead; the exclusion is stated in the
script and in `docs/COVERAGE.md`.

## Defects the work found

Listed with severity in the final report and in the commit messages; each has
a regression test next to the code.

## Not included

* Fuzzing with a sanitizer (see above).
* A load test of nginx itself or of tenant applications.
* Testing of TLS, SFTP, databases and backups (other streams).
* Network egress filtering of tenant code, disk quotas: the attacks that
  depend on them are recorded as known gaps in `docs/SECURITY.md`, not tested
  for success.
* Disk-full and out-of-memory behaviour *of the daemon*: manual QA plan step 8.2.
