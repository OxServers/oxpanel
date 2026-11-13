# Integration of the M3 streams (lifecycle, files, installer, essentials) — design

Date: 2026-11-14. Status: branch `m3-integration`, from `m2-integration`
(`43f8b69`).

## What

Four finished branches merged into one, in this order, each with a real
merge commit followed by commits that fix what the merge broke:
`m3-lifecycle` (`f177362`), `m3-files` (`e977547`), `m3-installer`
(`8e8071f`), `m3-essentials` (`f7a0a6d`, itself based on `m3-lifecycle`).
The individual design records stay authoritative for their features; this
record covers only what the combination needed. It extends
`2026-11-13-integration-design.md` (the M2 integration), whose method and
lifecycle order it follows. `m3-dns` is not part of it.

- `m3-lifecycle` merged without conflicts; `make check` and `make
  integration` passed on the merge commit as it was.
- `m3-files` and `m3-essentials` conflicted only where both sides added at
  the same place (proto service block and messages, records store, server
  handlers and converters, error mapping, config, start-up, scope table,
  `run-inside.sh` sections, traceability rows, docs, the Containerfile).
  Both sides were kept, in merge order.
- `m3-installer` conflicted in one paragraph of FEATURES.

### API numbering

No field, enum value, RPC or message is duplicated or renumbered (checked
mechanically on the merged `panel.proto`: 179 messages and enums, 78 RPCs).
Lifecycle added `ResourceLimits` 7, `HostInfo` 35, `DriftKind` 30–31,
`JobKind` 3–4, `Job` 14–17; essentials added `Tenant` 13, `VirtualHost`
12–13, `HostInfo` 36–42, `DriftKind` 32–34; the file manager added only new
messages and RPCs (its jobs are `FileJob`, not `JobKind` values), and the
installer nothing. So essentials' numbers, chosen on its lifecycle base,
did not collide and nothing was renumbered. Every new RPC (5 lifecycle, 19
file manager, 9 essentials) has a scope decision in
`tests/grpc_surface.rs`.

## Order of a tenant's lifecycle across features

`TenantService::set_suspended`, `TenantService::delete` and
`TenantService::remove_everything` (the cascade) are where every feature
meets. The order is asserted end to end by
`tenant::tests::one_tenant_with_every_feature_through_suspend_resume_and_delete`
(which now also carries a database in the trash, a running file job, an
upload in progress, a scheduled task, PHP settings with their own pool, and
a backup schedule) and by the lifecycle tests (cascade with every feature;
`a_cascade_waits_for_file_jobs_and_takes_the_file_managers_state_along`):

- **Suspend:** the sites answer 503 (Nginx re-rendered and reloaded); a
  running file-manager job is stopped (recorded as failed "stopped because
  the tenant was suspended"; a file being written stays under its
  temporary name) and the files become read-only; PHP-FPM stops (with the
  site pools inside it); applications stop; scheduled-task timers are
  disabled and a running task is stopped; SFTP (keys file removed,
  password hash locked, sessions ended); last the database accounts
  (`ACCOUNT LOCK`, `KILL USER`). The trash has no grants and is untouched;
  scheduled backups keep running (essentials' decision); Automatic HTTPS
  skips suspended tenants.
- **Resume:** the exact reverse: database accounts, SFTP, PHP-FPM,
  applications, task timers of enabled tasks, then the sites; the files
  are writable again (a stopped file job is not restarted); Automatic
  HTTPS catches up.
- **Delete (refusing, the default):** every refusal runs before anything is
  written, reading records only: virtual hosts, databases, database users
  or trash, a running file job, backups that are not retained, a running
  backup, restore or deletion job. Then the record goes to `deleting`,
  retained backups are detached, scheduled tasks are removed (they are
  configuration; `userdel` would refuse while one runs), SFTP access, the
  disk quota, `userdel`, slice units, backup and file-manager job history,
  upload records, the backup schedule, the record.
- **Delete with `cascade` (a job):** refused before anything is written
  while a backup, restore or file job of the tenant runs (the operator
  waits, or suspends the tenant, which stops a file job). While it runs no
  other backup or restore job starts and the file manager changes nothing
  of the tenant's (reads stay possible). Optional final backup; then:
  record `deleting`, retained backups detached, a file job found running
  stopped (only after a crash can there be one), PHP and applications
  stopped, scheduled tasks removed, every site removed (with its
  certificate, Automatic HTTPS state, logs, PHP pools — the tenant's and
  the sites' own — and application unit), SFTP access, database users,
  databases and trash dropped, backups that are not retained removed, the
  account with its home (partial uploads go with it), slice units, job
  histories, upload records, the backup schedule, the record. Each step is
  idempotent and record-driven; the job resumes at start-up.

## Decisions taken while merging

- **Two job stores stay separate.** Backups, restores, database restores
  and the cascade (and scheduled backups, which use the same `create_job`)
  are `Job`s (`GetJob`, `/var/lib/oxpanel/jobs`, at most 4 running on the
  host, one per tenant); file-manager jobs are `FileJob`s
  (`GetFileJob`/`ListFileJobs`, `/var/lib/oxpanel/file-jobs`, at most 8 on
  the host, one per tenant). Both are resumed at start-up. They meet where
  it matters: the cascade refuses while a file job runs, the file manager
  refuses changes while a cascade runs, both deletions wait for both kinds,
  suspension stops file jobs but not backups. A file job and a backup or
  restore of the same tenant may still run at the same time, as the files
  design decided (a restore racing a file job changes only that tenant's
  own files).
- **Cascade and file jobs: refuse, not stop.** Like for a backup job, so
  that the cascade never cuts off work the operator may not know about and
  a final backup never captures a half-copied tree. Suspending the tenant
  is the documented way to stop a file job first; the stop inside the
  removal is only the backstop after a crash.
- **File-manager changes during a cascade: refused** (`FAILED_PRECONDITION`,
  "job … is still running for tenant …"); the tenant is still `ready`
  while its final backup is taken. Synchronous operations do not take the
  mutation lock, so a change accepted a moment before the cascade started
  can still finish; it cannot resurrect the home: the worker opens the home
  by path and never creates it, `userdel` refuses an account with running
  processes (the driver retries), and a removed home cannot be reopened.
- **Scheduled tasks and the file manager.** A task names a script inside
  the home; the file manager does not protect it (only the home, document
  and application roots and the directories leading to them are
  protected). Deleting or moving a task's script through the file manager
  is the customer's choice; the task then fails visibly, as it does when
  the script is removed over SFTP.
- **`TZ=UTC` for every external command** (essentials). Checked against the
  other streams: the file manager reports times as UNIX seconds, backups
  and lifecycle read journals with `--since @<seconds>`, `mariadb-dump`
  writes `TIME_ZONE='+00:00'` itself and the replay sets the time zone of
  events explicitly; applications, PHP-FPM and tasks are systemd units and
  do not inherit the daemon's environment. Nothing depended on local time.
- **`rust-version` 1.85 → 1.88.** `zip` 9 needs 1.88; `tonic` 0.14 and
  `proptest` declared 1.88 already, so 1.85 was wrong before. Clippy's
  MSRV-dependent `manual_is_multiple_of` then applies (two sites changed).
  The tested toolchain stays pinned by `rust-toolchain.toml` (1.98.1).
- **Installer, packaging and acceptance.** Phases 12 and 95 deleted a
  database and then the tenant; with the trash the refusing deletion
  refuses, so both would have failed. Phase 95 purges the trash; phase 12
  deletes the upgraded tenant with the cascade and checks the file
  manager, the trash and a scheduled task on it. Phase 95 keeps a trashed
  database and a file-job history across uninstall and reinstall.
  `install.sh` installs `php-cli` in its PHP stage (scheduled PHP tasks;
  the RPM recommends it) and `--uninstall` names what the new features
  leave (job records, the trash, task units that keep firing, scheduled
  backups that pause). `daemon.env` gained the missing
  `OXPANEL_DB_TRASH_DAYS`. No other package is required: `mariadb-dump`
  comes with MariaDB, the file manager's worker is the daemon binary, and
  the new state directories (`db-trash`, `file-jobs`, `uploads`, `tasks`,
  `backup-schedules`) are created by the daemon under `/var/lib/oxpanel`.

## Phase 80, "the operator can remove the raced site …"

The check failed once each in two earlier acceptance runs and passed on
rerun. Section 4c was looped on a kept VM (2 vCPU, SELinux enforcing):

1. **The flake was the test.** Of 40 configurations raced against the
   tenant flipping the document root between a directory, a link to
   `/var/lib/oxpanel` and nothing, 0 to 6 complete (30 rounds: mean 3.2;
   in a second experiment 3 of 15 rounds had none). A configuration that
   loses the race is refused whole and leaves no record and no
   configuration, which is correct. When all 40 lost, `race.test` never
   existed, and `RemoveVirtualHost` rightly answered `removed=false`; the
   check read that as a failure. It asserted that at least one raced
   configuration wins, which the engine does not promise.
2. **Found doing so, a real defect.** Removing a site *while* the tenant
   flips its document root failed with an internal error in 12 of 15
   attempts (it worked when repeated after the race stopped). The guard
   "skip `restorecon` when the document root is missing", added for an
   earlier phase-80 finding, is a check-then-act: the path exists when
   looked at and is gone or a link when `restorecon -RF` walks it, which
   exits 255. A tenant running such a loop could keep its site — and
   itself, also through the cascade — from ever being removed. The relabel
   after the labelling rule is deleted is now best effort (logged); the
   Nginx file, the `semanage fcontext` rule and the record are handled as
   before. Deterministic unit test:
   `vhost::tests::a_site_can_be_removed_while_the_tenant_flips_its_document_root`.

The guarantee the section now asserts, deterministically: a raced
configuration either completes or is refused whole (never acts outside the
home; the record and the configuration exist together or not at all); an
existing site can be removed while the race goes on and leaves nothing (no
record, no configuration, no labelling rule); nothing outside the home
changes. The site to be raced is created before the race starts, a second,
new site is raced 20 times and must be all-or-nothing, and the removal of
the first runs while the tenant is still flipping the path.

## Not covered by the merged engine's tests

- The crash-safety matrix (`tests/crash_safety.rs`) still interrupts only
  the base workflows; the trash, the cascade, the file manager and the
  essentials have their own resumability tests.
- Phase 80 does not attack the file manager, the trash or scheduled tasks;
  their attacks are covered by `files_tests`, the task property and unit
  tests, and the integration suite.
- A file job and a backup restore of the same tenant at the same time are
  allowed and not tested together.
