# Integration of the M2 streams (testing, tls, sftp, db, backups) — design

Date: 2026-11-13. Status: branch `m2-integration`, from `d38bae2`.

## What

The five finished branches merged into one, in this order, each with a real
merge commit followed by a commit that fixes what the merge broke:
`m5-testing`, `m2b-tls`, `m2c-sftp-quotas`, `m2d-databases`, `m2e-backups`.
The individual design records stay authoritative for their features; this
record covers only what the combination needed.

## Order of a tenant's lifecycle across features

`TenantService::set_suspended` and `TenantService::delete` are the only
places where every feature meets. The order (asserted end to end by
`tenant::tests::one_tenant_with_every_feature_through_suspend_resume_and_delete`):

- **Suspend:** the sites answer 503 (Nginx re-rendered and reloaded), then
  the tenant's processes stop (PHP-FPM, applications), then its access is
  cut: SFTP (keys file removed, password hash locked, the tenant's
  `user-<uid>.slice` stopped so open sessions end), and last the database
  accounts (`ACCOUNT LOCK` and `KILL USER`), when nothing of the tenant's
  is running that could reconnect. Automatic HTTPS skips suspended
  tenants; backups and restores of a suspended tenant remain possible
  (operator actions) and leave its services stopped.
- **Resume:** the exact reverse: access (database accounts unlocked, SFTP
  keys file and password restored — an sshd that cannot take them right
  now is logged and reported by `Reconcile`, never blocks the resume),
  then processes (PHP, applications, which may connect to their database
  as they start), then the sites; finally Automatic HTTPS catches up on
  the tenant's sites.
- **Delete:** every refusal runs before anything is written or destroyed,
  reading records only: virtual hosts, databases or database users,
  backups that are not retained, a running backup or restore job. Then the
  record goes to `deleting`, retained backups are detached from the name,
  SFTP access is removed (sessions ended, chroot mount gone — before the
  home may be removed), the uid's disk quota is cleared, `userdel`, the
  slice units, the job history, the record.

A failed resume after access was restored leaves the record suspended with
access already given back; repeating the request completes it (the intent
was to resume). A failed suspend leaves the sites at 503 and the record
unsuspended; repeating completes it. Both as every other RPC.

## Decisions taken while merging

- **One way to feed a command's standard input.** The sftp stream
  (`Option<Secret>`, written before reading the output) and the db stream
  (`Option<Vec<u8>>` plus `secret_input`, written concurrently with
  reading, inside the timeout, stderr withheld from the journal for secret
  input) had each added a `stdin` field to `CommandSpec`. The db design is
  kept; `Secret`/`stdin_secret` remain as a wrapper that marks input
  secret. Effect on SFTP: `chpasswd`'s stderr is now also kept out of the
  journal when it fails.
- **Dependency installation never restarts by itself.** m5-testing moved
  the restart after `InstallAppDependencies` under the mutation lock, from
  the records as they are then; the backups stream had added a wrapper
  that restarted from a stale record without the lock. The wrapper is
  gone; restores start applications with the tenant's other services.
- **`chpasswd` runs in `passwd_t`.** With `NoNewPrivileges=yes` the stock
  transition of the daemon's `chpasswd` into `passwd_t` was denied (an AVC
  per password change, found in acceptance once m5-testing's corrected AVC
  counter was combined with SFTP passwords). `oxpanel.cil` allows exactly
  that `nnp_transition`.
- **Test harnesses are hermetic.** `config::sandbox_feature_paths` (tests
  only) moves the TLS, ACME, SFTP, sshd drop-in, scratch and backup
  locations into the test's directory; harnesses that reconcile run the
  SFTP start-up convergence like `main()` does. Before, combined features
  made unit tests read (and could make them write) the container's
  `/etc/ssh`, `/etc/pki` and `/var/lib/oxpanel-backups`.
- **Integration container and systemd credentials.** The integration
  container runs with `CAP_SYS_ADMIN` (SFTP bind mounts). There, systemd
  252 mounts a unit's credentials on ramfs inside the user namespace,
  unreadable for the unit's `User=` — so the ACME client cannot read the
  External Account Binding. `run-inside.sh` probes exactly that and, only
  where credentials cannot work, asserts the client's "cannot read the EAB
  credential" instead of the issuance; the acceptance VM always runs the
  full check (and passed it).

## Not covered by the merged engine's tests

- The crash-safety test (`tests/crash_safety.rs`) and the property tests
  were written before HTTPS, SFTP, databases and backups and interrupt only
  the base workflows; the feature workflows have their own resumability
  unit tests but are not part of the exhaustive interruption matrix.
- Acceptance phase 80 (attacks) predates the four feature streams and is
  unchanged: it does not attack SFTP (chroot escape, forwarding — covered by
  the integration suite instead), the certificate files or the ACME client,
  MariaDB (cross-tenant SQL — covered by the integration suite), or the
  backup worker (hostile archives — covered by the integration suite).
- Database dumps in backups, the database trash, cascade deletion of a
  customer: out of scope.
