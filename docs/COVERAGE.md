# Coverage

`make coverage` (`scripts/coverage.sh`, `cargo-llvm-cov` in the dev container) measures line
coverage of `oxpanel-daemon` from every test that `cargo test` runs (unit, property, gRPC,
crash-safety, performance-budget). CI runs it as its own job and fails under the floor in the
script. `COVERAGE_HTML=1 make coverage` writes an HTML report to `target/llvm-cov/html`.

Measured at the commit this file was added (library code only, fake OS):

| | lines | regions | functions |
|---|---|---|---|
| `oxpanel-daemon` | **96.3 %** (6,366 lines, 239 missed) | 90.5 % | 84.3 % |

Lowest files: `ctx.rs` 62 % (a constructor and accessors), `fsutil.rs` 84 % (the I/O-error
branches of directory helpers), `system/fake.rs` 92 %, `auth.rs` 92 %. `validate.rs` and `error.rs`
are 100 %, `vhost.rs` 97 %, `server.rs` 98 %, `host.rs` 97 %. Error paths that mattered and were
uncovered are now tested: resolving supplementary groups from the account database
(`auth::tests::supplementary_groups_come_from_the_account_database`), an account that no longer
matches its record (`host::tests::reports_an_account_that_no_longer_matches_its_record`), and the
internal-to-wire mapping of every drift kind
(`server::tests::every_drift_kind_maps_to_the_protobuf_kind_of_the_same_name`). The "17 functions have
mismatched data" warning `cargo-llvm-cov` prints is harmless (generic instantiations merged).

**Not measured, on purpose:** `system/real.rs` (the runner that executes real programs: it needs
root and a real host, so the container-integration and acceptance suites cover it, and a line
count from unit tests would be meaningless), `main.rs` (entry point: start-up, preflight, signal
handling; covered by integration and acceptance), generated code, `oxpanel-ctl`, tests themselves.

**The floor** (`COVERAGE_FLOOR`, default 90) sits five points below the measurement: it catches a
test suite that stops running, not the loss of a line. Coverage is not evidence of correctness:
the properties in `tests/properties.rs` and the exhaustive interruption test in
`tests/crash_safety.rs` say more about the engine than the percentage does.
