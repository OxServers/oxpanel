# Per-tenant backup and restore (M2e) — design

Date: 2026-11-13. Status: implemented on branch `m2e-backups`.

## Goal

Back up a tenant's files and the engine's records about it, list, delete and
restore those backups through the API — local to the host, safe against a
hostile tenant and a hostile archive, and robust against the daemon being
killed or the host restarted half-way.

## API

`CreateBackup(tenant)` and `RestoreBackup(tenant, backup_id)` return a `Job`
at once (`StartJobResponse{job, started}`); `GetJob(job_id)` reports
`RUNNING / SUCCEEDED / FAILED` with a one-line `message` and the end of the
worker's `output`. `ListBackups(tenant)` returns id, time, size, state
(`CREATING`/`READY`), members (name, kind, size, SHA-256) and the tenant's
domains at the time; `DeleteBackup(tenant, backup_id)`.

- A repeated `CreateBackup` while a backup of the tenant runs returns that job
  (`started=false`); a repeated identical restore likewise. Any other job for
  a tenant with one in flight is `FAILED_PRECONDITION`: **one job per tenant**.
  At most 4 jobs run on the host at once (`RESOURCE_EXHAUSTED` beyond).
- Scopes: create and restore need `tenant`, delete needs `delete`, list and
  job status need `read`. No new scope.
- Ids are `b<unix millis>` and `j<unix millis>` (allow-listed newtypes
  `BackupId`/`JobId`; they become file and unit names). Backups sort by time.
- `HostInfo` 32–34: backup file-system size and free space, `backup_keep`.
- `oxpanel-ctl backup create|list|delete|restore|job`, with `--wait` (exit 5
  if the job failed).

## Jobs

A real site takes longer than the 300-second RPC deadline, and the work must
not die with the daemon, so it runs in a **transient systemd unit**
(`oxpanel-job-<job id>.service`, `systemd-run`) that executes the daemon's own
binary in worker mode: `oxpanel-daemon worker backup|restore <uid> …`
(`src/worker.rs`, strict argument parser, never accepts uid/gid 0). The unit:

- runs in the tenant's slice (charged to its memory/CPU/IO limits), `Nice=19`,
  `CPUSchedulingPolicy=batch`, IO class best-effort priority 7,
  `RuntimeMaxSec=OXPANEL_BACKUP_TIMEOUT_SECS` (default 6 h);
- is sandboxed: `ProtectSystem=strict` with exactly one writable path (the
  backup's own directory for a backup, the tenant's home for a restore),
  `PrivateNetwork/Tmp/Devices`, `NoNewPrivileges`, `RestrictSUIDSGID`,
  `MemoryDenyWriteExecute`, and **`CapabilityBoundingSet=CAP_SETUID CAP_SETGID
  CAP_SETPCAP`**: the worker is root only so that it can drop to the tenant;
  without `CAP_DAC_OVERRIDE` it cannot open a tenant's files itself;
- has `RemainAfterExit=yes`, so its result stays visible until the daemon has
  collected it, and then `stop`/`reset-failed` lets systemd forget it.

`systemd-run` is called **without** `--no-block`: it returns once the unit has
started, so the daemon's first look can never mistake a still-queued
("inactive") unit for one that has vanished. No `--pipe` (see the SELinux
lessons); the worker's stderr — including `tar`'s warnings about skipped
files — goes to the journal and the last 40 lines are copied into the job.

The daemon only watches: the job record (`/var/lib/oxpanel/jobs/<id>.json`,
written before the unit is started) is polled every 2 s with `systemctl
show`. When the unit has ended the daemon concludes the job under the
mutation lock. At start-up `resume_all` re-attaches to every job recorded as
running — so a daemon killed mid-backup picks the job up again, and a job
whose unit vanished (host rebooted) is concluded from what is on disk.

### What makes a backup "complete" (never a half-written archive that looks valid)

1. The worker writes `home.tar.gz` (`O_CREAT|O_EXCL|O_NOFOLLOW`, 0600),
   hashing as it copies, `fsync`s it, and only then writes
   `home.tar.gz.result.json` (size + SHA-256) atomically. The result file is
   the worker's statement that the member is complete.
2. The daemon seals the backup: for every member with a result file it checks
   the on-disk size, then writes `manifest.json` atomically (the commit point),
   removes the result files, and marks the record `READY`.
3. Anything else — unit failed, timed out, killed, OOM, vanished without a
   result file, sizes disagree — removes the backup directory and record; the
   job is `FAILED` with a reason. A record in `CREATING` without a running job
   is reported by `Reconcile`.

## Archive format (format 1) and the hook for further data sources

`<backup_dir>/<tenant>/<backup id>/` holds *members* plus `manifest.json`
(`{format, id, tenant, created_at_unix, engine_version, members:[{name, kind,
size_bytes, sha256}]}`). Today:

- `home.tar.gz`, kind `home` — the home as a gzip'd GNU tar;
- `records.json`, kind `records` — the engine's `TenantRecord` and every
  `VHostRecord` of the tenant, so the backup describes itself.

**Hook for database dumps (not implemented):** `BackupService::seal`
(`src/backup.rs`) picks up *every* file in the backup directory that has a
`<member>.result.json` next to it (`worker::MemberResult{kind, size_bytes,
sha256}`), whatever its kind. A new data source therefore only has to write
its member (e.g. `db-<name>.sql.gz`, kind `mariadb`) and its result file into
the backup directory before the job's unit exits — concretely, an extra step
in `worker::backup` (or an extra `Task` variant run by the same unit) that
streams `mariadb-dump`, run as the tenant, through `copy_hashed` exactly like
the home. Manifest, record, listing, checksum verification, deletion,
retention and `Reconcile` need no change, and the format stays `1`. Restore
selects members by kind (`kind == "home"` today), so a backup with a member
kind it does not know still restores the home; restoring a dump would be a
new `Task::Restore…` variant. Clients must tolerate unknown kinds (stated in
the proto).

**Compression: gzip.** `gzip` and `tar` are in every AlmaLinux 9 install
(the RPM now `Requires:` both, and `CreateBackup` refuses with
`FAILED_PRECONDITION` if either is missing). Alternatives: `xz` (base, but
5–10× slower — a backup at nice 19 already takes long), `zstd` (faster and
better, `tar --zstd` works, but the `zstd` binary is not installed by default
and an operator's rescue system may lack it), `pigz` (not in BaseOS). Gzip is
the archive any tool can open.

**Included and excluded.** The whole home, except `./.cache` and `./.npm`
(package-manager download caches, regenerated on demand). Virtualenvs and
`node_modules` are **included**: a backup that needs the network and
today's package versions to turn back into a working site is not a backup of
that site, and both are typically small next to user content. Not recorded:
ACLs, xattrs, SELinux labels (`--no-acls --no-selinux --no-xattrs`) — the
engine re-creates the ones it manages after a restore; set-uid/gid bits are
stripped at creation (`--mode=u-s,g-s`).

## Security of the archive path

**Reading** (`worker::tar_create`): `tar` runs **as the tenant** through
`setpriv` (cleared groups, empty bounding set, `no_new_privs`), with
`--one-file-system --sparse --numeric-owner --hard-dereference
--ignore-failed-read`, and nothing that dereferences. Consequences:

- symlinks (to `/etc/shadow`, into other homes) are stored as symlinks; their
  targets are never read;
- a hard link root planted to `/etc/shadow`, a root-owned 0600 file, another
  tenant's file: the tenant cannot open them, so `tar` reports and skips them
  (`--ignore-failed-read`); nobody reads them *for* the tenant;
- FIFOs and device nodes are recorded as such, never opened (no hang, no
  device read); sockets are skipped;
- sparse files cost what they occupy (`--sparse`, SEEK_HOLE); a directory
  bomb or endless file is bounded by the archive size cap, the tenant's
  cgroup and `RuntimeMaxSec`; names with newlines are stored verbatim.

The archiver gets a **pipe**, never a descriptor of the archive: the root
worker reads the pipe, counts it against `max_bytes` (free space minus the
reserve, measured at request time) and writes the root-only file. Nothing
running as the tenant can write, grow, truncate or reopen an archive.

**Storage**: `/var/lib/oxpanel-backups` (`OXPANEL_BACKUP_DIR`), `root:root
0700` (tmpfiles.d and the daemon both ensure it); every directory 0700, every
file 0600. Configuration refuses a backup directory inside the home base.
The tenant cannot list or read it (integration-tested).

**Bounds**: `CreateBackup` measures the home **as the tenant** (`du
--one-file-system`, up to 240 s) and refuses with `RESOURCE_EXHAUSTED`
unless `free ≥ usage + OXPANEL_BACKUP_MIN_FREE_BYTES` (default 1 GiB); the
archive can never grow into the reserve. Retention keeps the newest
`OXPANEL_BACKUP_KEEP` (default 7) ready backups per tenant, applied when a
backup completes. Job history is capped at 20 per tenant.

**Restoring** (`worker::tar_extract`): the worker first reads the whole
archive and verifies size and SHA-256 against the record (a corrupted or
truncated archive is refused before `tar` sees a byte), then hands it to
`tar --extract --no-same-owner --same-permissions --no-acls --no-selinux
--no-xattrs -C <home>` running **as the tenant**. The guarantees come from
layers, not from tar's options alone:

| Hostile member | Stopped by |
|---|---|
| absolute path `/etc/x` | GNU tar strips the leading `/` (lands in the home); the unit makes `/etc` read-only anyway |
| `../` path | GNU tar strips leading `../` and skips names containing `..` |
| symlink to `/etc` or `/home/bob`, then a file through it | tar extracts such symlinks as placeholders until the end (never writes through them); the tenant has no write access to either; read-only file system outside the home |
| hard link to `/etc/shadow` | target is stripped to a relative name; `fs.protected_hardlinks`; `/etc` read-only |
| set-uid / set-gid file | `RestrictSUIDSGID=yes` (seccomp refuses the mode) and the bits were stripped at creation |
| device node | the tenant has no `CAP_MKNOD`; `PrivateDevices` |
| member owned by root | `--no-same-owner`, and the tenant cannot `chown` |

Each row is tested with a crafted archive in `run-inside.sh` (on the real VM
too). `tar` then exits non-zero and the job is `FAILED` ("refused or failed
to restore some members; the others were restored").

**Cross-tenant**: a backup is looked up *for the requesting tenant*;
someone else's id is `NOT_FOUND` (restore and delete). The record also keeps
the uid it was taken from; a restore into an account with a different uid
(tenant deleted and recreated) is refused.

## Restore semantics

- **Merge over the home**: files in the backup replace current ones; files
  created since stay. Rejected: *replace* (deleting a live site's newer data
  on the say-so of one request is the worse failure, and needs root-side
  recursive deletion inside a tenant home); *side directory* (safe but the
  site does not come back, which is the point of a restore — a panel can
  offer "restore to folder" later).
- The tenant's PHP-FPM instance and applications are **stopped** for the
  duration (`systemctl disable --now`, so a reboot mid-restore does not
  revive them on half-restored files) and started again at the end — also
  when the restore failed. A suspended tenant's services stay stopped.
- Afterwards, whatever the outcome: the home is made private again
  (`ensure_private_dir`), relabelled (`restorecon -R`), and every document
  root gets what `ConfigureVirtualHost` gives it (`VHostService::
  restore_web_access`: exists, `u:nginx` traverse/read ACLs including the
  default ACL, SELinux web-content label). This is needed because `tar`
  restoring a directory's mode resets its ACL mask. The site is served
  without manual steps (tested for a static and a PHP site).
- Records (virtual hosts, limits) are **not** restored: `records.json` is
  information for the operator/panel. Restoring configuration is a panel
  decision (domains may have moved to another tenant since).

## Tenant lifecycle

`DeleteTenant` is **refused** while the tenant has backups or a job in
flight (`FAILED_PRECONDITION`, "still has backups; delete them first").
Backups are found by tenant name, so a later tenant of the same name would
inherit them; deleting them silently would destroy the only copy of a
customer's data as a side effect. The panel deletes backups explicitly (or
keeps the tenant until its retention period ends). The job history of a
deleted tenant is dropped. Suspended tenants can be backed up and restored by
the operator.

`Reconcile` reports `BACKUP_ARCHIVE_MISSING` (directory, manifest or member
gone), `BACKUP_ARCHIVE_MODIFIED` (member size or manifest differs from the
record — checksums are verified at restore, not on every reconcile, which
would read every archive), `ORPHAN_BACKUP_ARCHIVE` (a directory without a
record; reported, never removed) and `BACKUP_INCOMPLETE` (a `CREATING` record
without a running job, or a running job without a backup record).

## SELinux

The job unit runs `/usr/sbin/oxpanel-daemon` (`bin_t`) from `init_t`, i.e.
in `unconfined_service_t`, like the daemon and the dependency installer;
the store is `var_lib_t` under `/var/lib`. No policy change was needed
(acceptance: zero AVC denials).

## Not included

Scheduling (left to the panel: call `CreateBackup` on its own timetable;
retention is the engine's), off-host copies, encryption, incremental
backups, database dumps (hook above), restoring a single file or into a side
directory, restoring records, per-tenant quotas on backup space (the global
reserve and retention bound it).

## Known limitations

- While a restore runs, a `ConfigureVirtualHost` with PHP or a `ResumeTenant`
  for the same tenant would start its PHP/applications early; the end of the
  restore starts them again either way. The panel should not do that.
- A device node root planted in a home is archived as a node; restoring it as
  the tenant fails, so that restore reports `FAILED` (the rest is restored).
- Measuring a very large home (`du`) is limited to 240 s inside the request.
