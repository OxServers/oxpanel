# oxpanel-daemon — rules for working on this crate

Target: AlmaLinux 9, SELinux enforcing, systemd, Nginx. Runs as root under a
hardened unit. Build and test only inside the target-OS container (`make test`,
`make integration`); the host has no toolchain and is not the target.

## Security invariants (enforced; do not weaken)

1. **No shell.** Never `sh -c`, never `Command::new("sh")`. Every external
   program is an absolute path in `system::bin`, invoked with an argv array.
   The only place that spawns processes is `system/real.rs`.
2. **Validate before anything.** Every API field goes through a newtype in
   `validate.rs` (allow-list, never deny-list). Values that were not validated
   do not reach `system`, the file system, systemd or Nginx.
3. **Tenant work runs as the tenant.** Use `CommandSpec::as_user` (setpriv with
   cleared groups, empty bounding set, no_new_privs). Root only does what
   root must: useradd/userdel, ACLs, unit files, nginx test/reload, labels.
4. **Own it or leave it.** Modify or delete only what a record in
   `/var/lib/oxpanel` says OxPanel created. Never adopt existing accounts.
5. **Atomic, explicit, symlink-safe file writes** via `fsutil` only.
6. **Fail closed.** No peer credentials → no service. Unknown state → error.
7. **No panics in production paths.** `unwrap`/`expect`/`panic` are denied by
   clippy; map every fault to `error::Error` and let `server.rs` redact it.
8. **`#![forbid(unsafe_code)]`** — if something needs `unsafe`, it needs a
   dependency that already audits it (nix), not our own code.
9. **Idempotent and resumable.** Every RPC may be retried after a crash; write
   the record before side effects that depend on it and drive by `state`.
10. **The unit file is part of the code.** Any new external tool or path needs
    a matching `ReadWritePaths`/capability/syscall review in
    `packaging/systemd/oxpanel-daemon.service`, verified by `make integration`.

## Patterns

- tokio multi-thread runtime; tonic 0.14 (`tonic-prost`), codegen via protox (no protoc).
- `System` trait: `RealSystem` in production, `FakeSystem` in tests. Tests assert
  on exact argv vectors — treat a changed argv as a security-relevant change.
- One `tokio::Mutex` serialises all mutations (passwd, nginx, systemd are not transactional).
- Logging via `tracing` to stderr → journald. Never `println!` in the daemon.
- Errors: `thiserror` enum → `tonic::Status` in `error.rs`; client-caused errors
  keep their message, internal ones are redacted.

## Definition of done for a change

`make check` green (fmt, clippy pedantic -D warnings, tests, cargo-deny) and
`make integration` green. If the change touches provisioning, add both a
`FakeSystem` test asserting the argv and an assertion in
`tests-integration/run-inside.sh`.
