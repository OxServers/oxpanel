# Integration of the M3 streams (lifecycle, files, installer) — design

Date: 2026-11-14. Status: branch `m3-integration`, from `m2-integration`
(`43f8b69`).

## What

Three finished branches merged into one, in this order, each with a real
merge commit followed by commits that fix what the merge broke:
`m3-lifecycle` (`f177362`), `m3-files` (`e977547`), `m3-installer`
(`8e8071f`). The individual design records stay authoritative for their
features; this record covers only what the combination needed. It extends
`2026-11-13-integration-design.md` (the M2 integration), whose method and
lifecycle order it follows.

- `m3-lifecycle` merged without conflicts; `make check` and `make
  integration` passed on the merge commit as it was.
- `m3-files` conflicted only where both sides added at the same place
  (proto service block and messages, records store, server handlers and
  converters, error mapping, start-up job resumption, scope table,
  `run-inside.sh` sections, traceability rows, docs). Both sides were kept,
  lifecycle first. No field, enum value, RPC or message was renumbered or
  duplicated: the file manager adds only new messages and RPCs (its jobs
  are `FileJob`, not new `JobKind` values), lifecycle adds `ResourceLimits`
  7, `HostInfo` 35, `DriftKind` 30–31, `JobKind` 3–4, `Job` 14–17, and new
  messages. Every new RPC (5 lifecycle, 19 file manager) has a scope
  decision in `tests/grpc_surface.rs`.
- `m3-installer` conflicted in one paragraph of FEATURES.

## Order of a tenant's lifecycle across features

`TenantService::set_suspended`, `TenantService::delete` and
`TenantService::remove_everything` (the cascade) are where every feature
meets. The order (asserted end to end by
`tenant::tests::one_tenant_with_every_feature_through_suspend_resume_and_delete`,
which now also carries a database in the trash, a running file job and an
upload in progress, and by
`lifecycle::tests::a_cascade_waits_for_file_jobs_and_takes_the_file_managers_state_along`):

- **Suspend:** the sites answer 503 (Nginx re-rendered and reloaded); then
  a running file-manager job is stopped (its unit stopped, recorded as
  failed "stopped because the tenant was suspended"; a file being written
  stays under its temporary name) and the files become read-only; then the
  tenant's processes stop (PHP-FPM, applications); then its access is cut:
  SFTP (keys file removed, password hash locked, sessions ended), and last
  the database accounts (`ACCOUNT LOCK`, `KILL USER`). The database trash
  has no grants and is untouched. Automatic HTTPS skips suspended tenants;
  backups, restores and trash restores remain possible (operator actions).
- **Resume:** the exact reverse: database accounts, SFTP, then PHP and
  applications, then the sites; the files are writable again (a stopped
  file job is not restarted); Automatic HTTPS catches up.
- **Delete (refusing, the default):** every refusal runs before anything
  is written or destroyed, reading records only: virtual hosts, databases,
  database users or trash, a running file job, backups that are not
  retained, a running backup, restore or deletion job. Then the record goes
  to `deleting`, retained backups are detached, SFTP access is removed, the
  disk quota cleared, `userdel`, slice units, job history (backup and
  file-manager), upload records, the record.
- **Delete with `cascade` (a job):** refused before anything is written
  while a backup, restore or file job of the tenant runs (the operator
  waits, or suspends the tenant, which stops a file job). While it runs, no
  other backup or restore job starts and the file manager changes nothing
  of the tenant's (reads stay possible: the final backup is still being
  taken). Optional final backup; then: record `deleting`, retained backups
  detached, a file job found running stopped (only after a crash can there
  be one), PHP and applications stopped, every site removed, SFTP access,
  database users, databases and trash dropped, backups that are not
  retained removed, then the account with its home (partial uploads go
  with it), slice units, backup and file-manager job history, upload
  records, the record. Each step is idempotent and driven by records; the
  job resumes at start-up.

## Decisions taken while merging

- **Two job stores stay separate.** Backups, restores, database restores
  and the cascade are `Job`s (`GetJob`, `/var/lib/oxpanel/jobs`, at most 4
  running on the host, one per tenant); file-manager jobs are `FileJob`s
  (`GetFileJob`/`ListFileJobs`, `/var/lib/oxpanel/file-jobs`, at most 8 on
  the host, one per tenant). Both are resumed at start-up. They meet only
  where it matters: the cascade refuses while a file job runs, the file
  manager refuses changes while a cascade runs, both deletions wait for
  both kinds, suspension stops file jobs but not backups. File jobs and
  backup/restore jobs of the same tenant may still run at the same time,
  as the files design decided (a backup of a live site is consistent only
  to the second anyway); a restore with `overwrite` racing a file job
  changes only that tenant's own files.
- **Cascade and file jobs: refuse, not stop.** A whole-customer deletion
  could have stopped a running file job instead. It refuses, like for a
  backup job, so that the cascade never cuts off work the operator may not
  know is running, and so that a final backup never captures a half-copied
  tree. Suspending the tenant is the documented way to stop a file job
  first. The stop inside the removal is only the backstop after a crash.
- **File-manager changes during a cascade: refused.** The tenant is still
  `ready` while its final backup is taken; changes then would be missing
  from the backup and race the removal. Refused with
  `FAILED_PRECONDITION` ("job … is still running for tenant …"). Synchronous
  operations do not take the mutation lock, so a change that was accepted
  a moment before the cascade started can still finish; it cannot
  resurrect the home: the worker opens the home by path and never creates
  it, `userdel` refuses an account with running processes (the driver
  retries), and a removed home cannot be reopened.
- **`rust-version` 1.85 → 1.88.** `zip` 9 needs 1.88; `tonic` 0.14 and
  `proptest` declared 1.88 already, so 1.85 was wrong before this merge.
  Clippy's MSRV-dependent `manual_is_multiple_of` then applies (two sites
  changed). The tested toolchain stays pinned by `rust-toolchain.toml`
  (1.98.1); the RPM spec's comment states the minimum.
- **Installer and acceptance.** Phases 12 and 95 deleted a database and
  then the tenant; with the trash, the refusing deletion refuses, so both
  would have failed. Phase 95 purges the trash; phase 12 deletes the
  upgraded tenant with the cascade and also checks the file manager and
  the trash on it. Phase 95 keeps a trashed database and a file-job history
  across uninstall and reinstall. `install.sh --uninstall` names what the
  new features leave (job records, the database trash). No new package is
  required: `mariadb-dump` comes with MariaDB, the file manager's worker is
  the daemon binary, and the new state directories (`db-trash`,
  `file-jobs`, `uploads`) are created by the daemon under
  `/var/lib/oxpanel`. `daemon.env` gained the missing
  `OXPANEL_DB_TRASH_DAYS`.

## Phase 80, "the operator can remove the raced site …"

FLAKE-FINDINGS

## Not covered by the merged engine's tests

- The crash-safety matrix (`tests/crash_safety.rs`) still interrupts only
  the base workflows; the trash, the cascade and the file manager have
  their own resumability tests.
- Phase 80 does not attack the file manager or the trash; the file
  manager's attacks (links out of the home, traversal, hostile archives,
  bombs, names) are covered by `files_tests` and the integration suite.
- A file job and a backup restore of the same tenant at the same time are
  allowed and not tested together.
