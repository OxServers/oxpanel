# File manager (M3, files stream) — design

Date: 2026-11-14. Status: implemented on branch `m3-files`.

## Goal

A customer manages the files in its own home through the panel — browse,
read, upload, download, edit, organise, compress, extract — without SFTP and
without a shell. The panel calls the engine on the customer's behalf; the
engine must make it impossible for any call to touch anything outside that
tenant's home, whatever paths, names or archive contents it is given. This is
the most attack-exposed surface of the engine: tenant-controlled trees, names
and archives, processed at the request of a root daemon.

## Model: the kernel is the guarantee

The daemon never opens a tenant's file. Every operation is done by a
**worker running as the tenant** — this binary in a worker mode — so the
kernel refuses everything the tenant could not do itself over SFTP: another
tenant's home (0700), a root-owned file, a hard link root planted to someone
else's private file, a device. Our own checks come on top, never instead.

Two layers stop a request from leaving the home:

1. **Identity.** The worker has the tenant's uid and gid, no supplementary
   groups, an empty capability bounding set and `no_new_privs`. Quick
   operations: `systemd-run --scope --slice=<tenant slice>` → `setpriv
   --reuid --regid --clear-groups --bounding-set=-all --inh-caps=-all
   --no-new-privs` → `oxpanel-daemon files`. Jobs: a transient service with
   `User=`/`Group=` the tenant and `CapabilityBoundingSet=` empty. The worker
   itself refuses to start as root (exit 77) and refuses a home it does not
   own.
2. **Confined resolution.** Every path is resolved by the worker with
   `openat2(home_fd, path, RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS |
   RESOLVE_NO_XDEV)`. An absolute symlink, a `..` that would climb out, a
   `/proc` magic link or a mount point inside the home makes the resolution
   fail (`EXDEV`/`ELOOP` → `FAILED_PRECONDITION`, "leads outside the home")
   instead of being followed. This matters because layer 1 alone would let a
   link `x -> /etc/passwd` (world-readable) be read; with it, nothing outside
   the home is ever read or written through a link. Symlinks *inside* the
   home work as the customer expects.

Tree walks (copy, delete, compress, search, size) go from descriptor to
descriptor: each child is opened relative to its parent's descriptor with
`O_NOFOLLOW` and `RESOLVE_NO_SYMLINKS`, never by a path string, so a
directory swapped for a symlink half-way cannot redirect a walk, symlinks
inside a tree are never descended into (copied and archived as links,
removed as links), and trees deeper than `PATH_MAX` are handled (up to 256
levels; deeper is refused rather than running out of descriptors).

### Why our own worker and not coreutils/tar/unzip

| Concern | Driving `cp`/`rm`/`tar`/`unzip` with argv | Our worker |
|---|---|---|
| Option injection (`-rf`, `--checkpoint-action=…`) | needs `--` everywhere, per tool, forever | names never reach an argv: the request is JSON on stdin and names go to `*at` syscalls |
| Newlines/control characters in names | output parsing breaks (`ls`, `find -print`) | names are bytes in, JSON (escaped) out |
| Locale/encoding of names | tool- and `LC_ALL`-dependent | bytes; non-UTF-8 names listed lossily and flagged |
| TOCTOU between check and use | tools re-resolve paths string by string | one `openat2` per request path, then descriptors |
| Symlinks out of the home | each tool's own `-P`/`--no-dereference` semantics | `RESOLVE_BENEATH` for request paths, `RESOLVE_NO_SYMLINKS` in walks |
| FIFOs, devices (blocking opens) | `cat` blocks on a FIFO | type checked through `O_PATH` first; opens use `O_NONBLOCK` and are compared with the probe |
| Sparse files | `cp --sparse=auto` heuristics; `unzip` fills | `SEEK_DATA`/`SEEK_HOLE` copy; size from `st_blocks` |
| Hard links | tools follow them like any file | the kernel decides (the worker is the tenant) |
| Archive bombs | `unzip` has partial bomb detection, `tar` none | ratio, total-bytes and entry-count caps enforced while streaming |
| Archive path tricks | GNU tar strips; unzip warns, behaviour varies by version | rebuilt component by component; refused, never "fixed" |

The archive formats are parsed by pure-Rust crates (`zip` 9 with deflate
only, `tar`, `flate2` with miniz_oxide): no C, no other compression methods
(bzip2, lzma, zstd, encrypted entries are reported and skipped), all within
`cargo deny`.

## API (`panel.proto`, files section; `oxpanel-ctl files …`)

Synchronous: `ListFiles` (one directory, paged: directories first, then by
name; at most 1000 per page), `StatFile`, `ReadFile` (≤ 1 MiB per call, with
offset; size and mtime returned for change detection), `WriteFile` (≤ 192 KiB,
atomic, for the editor), `StartUpload`/`UploadChunk`/`FinishUpload`/
`AbortUpload` (any size up to the limit, 192 KiB chunks), `MakeDirectory`
(optionally with parents), `MoveFile` (rename within the home),
`SetFileAccess`, `SearchFiles`, `GetDirectorySize`.

Jobs: `CopyFiles`, `DeleteFiles`, `CompressFiles` (zip or tar.gz),
`ExtractArchive` (zip, tar, tar.gz — recognised by content, not name),
`GetFileJob`, `ListFileJobs`.

Every path is relative to the home (`""`/`"."` is the home), validated by
`validate::FilePath`: no leading `/`, no empty, `.` or `..` component, no
NUL, at most 3072 bytes, 64 components, 255 bytes per name (property-tested
in `tests/properties.rs`). A name the engine *creates* must pass
`check_new_name`: visible characters and inner spaces only — no control
characters (newline, tab, escape, DEL, C1), no other whitespace, no
invisible or bidirectional formatting characters (`U+202E` makes
`invoice‮fdp.exe` look like a PDF), no leading/trailing space. Existing names
may contain anything but NUL, so a name made over SFTP with a newline can
still be listed, renamed and deleted. A leading `-` is allowed: it is only
ever a syscall argument.

Uploads and writes are atomic: content goes to a temporary name in the
target's directory — a dot-file, which Nginx never serves — created
`O_EXCL|O_NOFOLLOW` with its final mode (so the kernel applies the
directory's default ACL exactly as for SFTP; a `chmod` afterwards would set
the ACL's "other" entry from the mode and make the file differ from one the
tenant uploads over SFTP — found by the integration test), then `fsync`, the
replaced file's mode if one is replaced, `renameat2` (with
`RENAME_NOREPLACE` unless `overwrite`). An upload's partial file is
`.oxpanel-upload-<id>` next to the target; chunks must be sent in order (a
repeated chunk truncates and rewrites, so a retry after a timeout is safe);
`FinishUpload` checks the size and, optionally, the SHA-256. A chunk refused
for the quota or the size limit removes the partial file and ends the upload
(no partial file is left); uploads not finished within 24 hours are removed
by the engine (hourly sweep, as the tenant). At most 8 uploads in progress
per tenant.

### Scopes

- `read`: `ListFiles`, `StatFile`, `SearchFiles`, `GetDirectorySize`,
  `GetFileJob`, `ListFileJobs` — like listing sites.
- `vhost` (the customer tier's write scope): **`ReadFile`** and every change.
  File *content* is more sensitive than metadata — `wp-config.php` holds a
  database password, `.env` API keys. A read-only peer (monitoring,
  dashboards) has no business reading it; the customer panel holds `vhost`
  anyway. Rejected: a new `content` scope (the brief allows no new scopes).
- `delete` is not used: deleting one's own files is everyday site management
  (the customer tier has no `delete`), unlike deleting a tenant or a backup.

### Suspended tenants: read-only

Owner decision taken here (reversible): a suspended tenant's files can be
listed, read, searched and sized, but nothing can be changed
(`FAILED_PRECONDITION`, "suspended; its files can be read but not
changed"), and a running file job is stopped at suspension (its unit is
stopped; a file being written is left under its temporary name, never as a
truncated target; the job is recorded as failed "stopped because the tenant
was suspended"). Reasons: suspension stops the tenant from *doing* things
(serving, running code, SFTP); reading preserves evidence for an abuse
investigation without letting anyone tamper, and lets the customer or
operator take the data away. Rejected: refusing everything (the operator
then needs SFTP or root to look at a suspended site's files); full access
(a suspended account could keep changing its site).

### The engine's own directories

Protected from deletion, moving and access changes: the home itself, every
document root and application root of the tenant's sites, and every
directory between the home and one of them (`FAILED_PRECONDITION`). Deleting
`public_html` breaks the site and its ACLs; `chmod 0700` on a directory on
the way removes the web server's traverse right. Their *content* is the
customer's. Protection is by inode, so an alias (`ln -s . x` then
`x/public_html`) does not get around it. This is a guard against accidents
through the panel, not a security boundary: the tenant can do the same over
SFTP, and nothing here could hurt anyone but itself. A Python application's
`.venv` is deliberately not protected (it is rebuilt by
`InstallAppDependencies` and left out of backups). SFTP chroot material and
everything else the engine keeps lives outside the home.

### Modes and the ACL scheme

`vhost.rs::grant_web_access` gives the web server `u:nginx:--x` on the home
and every directory down to a document root, and `u:nginx:r-x` plus the same
as a *default* ACL on the root. On a file or directory with an ACL the group
permission bits *are* the ACL mask, which can only narrow named entries.
Hence:

- **web readable** = files 0644 (0755 if the owner may execute), directories
  0755: mask `r--`/`r-x`, so the web server reads through its ACL entry;
- **private** = files 0600 (0700), directories 0700: mask `---`, so the
  entry is ineffective; Nginx answers 403 (tested);
- **explicit mode**: 0 to 0775. Never set-uid, set-gid or sticky (refused
  at validation, masked again in the worker), never world-writable. Group
  write is allowed: the group is the tenant's private group, and as the
  mask it cannot widen the web server's `r-x`.

No mode change can grant the web server more than the engine's entries, and
none can touch the home or the protected directories. New files are created
0644 and directories 0755, as SFTP creates them with its default umask 022;
under a document root the inherited default ACL (whose "other" entry is
empty) makes them 0640 and 0750, exactly as for an SFTP upload; a file
replaced by an upload or an editor save keeps its mode. Ownership is the
tenant's by construction; under a document root the default ACL is inherited
exactly as for a file the tenant creates itself (the integration test
compares `getfacl` of both); the SELinux label is the type-transition
default for the path, the same as for a tenant-created file (compared with
`matchpathcon` on the VM). Content is never cached: every read is a fresh
`pread` by a fresh worker.

## Jobs

`CopyFiles`, `DeleteFiles`, `CompressFiles` and `ExtractArchive` run in a
transient service `oxpanel-files-<job id>` like backups: the record
(`/var/lib/oxpanel/file-jobs/<id>.json`) and the request
(`<id>.request`, root 0600) are written first; `systemd-run` starts the unit
with `User=`/`Group=` the tenant, `Slice=` its slice, `StandardInput=file:`
the request (opened by systemd before it drops privileges, so the request
stays root-only on disk and file names never appear in an argv or in
`systemctl show`), `Nice=10`, best-effort I/O priority 6,
`RuntimeMaxSec=OXPANEL_FILES_JOB_TIMEOUT_SECS` (default 2 h), `MemoryMax=1G`,
`TasksMax=16`, no capabilities, `NoNewPrivileges`, `ProtectSystem=strict`
with only the home writable, private network, `/tmp` and devices,
`RestrictSUIDSGID`, `ProtectProc=invisible`, and the rest of the backup
unit's hardening. The worker prints the entries it left out or could not
handle (escaped, at most 20) and, last, `oxpanel-files-result {json}`; a
file name cannot forge that line (names are escaped, so none starts a line).

The daemon polls the unit (`systemctl show`), and when it has ended reads
the result line from the journal and concludes the job; `resume_all` picks
running jobs up after a restart (tested by killing the daemon mid-job on the
real host). Each job-starting call waits up to 2 s, so small jobs return
finished and the panel needs no polling for them. **One job per tenant at a
time** (`FAILED_PRECONDITION`), at most 8 file jobs on the host
(`RESOURCE_EXHAUSTED`), 50 finished jobs remembered per tenant. File jobs
are independent of backup jobs (a backup of a live site is consistent only
to the second anyway). `DeleteTenant` is refused while a file job runs;
deleting a tenant drops its job history and upload records.

Copies merge into existing directories, replace existing files only with
`overwrite` (otherwise skipped and counted), keep holes, modes (minus
set-uid/set-gid/sticky/world-write) and modification times, copy symlinks
as symlinks and hard links as separate files, and leave out FIFOs, sockets
and devices. A directory is never copied into itself (directories created by
the copy and the destination are never sources). Deletion removes links,
never their targets; a directory the tenant closed to itself (0500, 0000) is
opened up again to empty it.

## Archives are hostile

| Hostile entry | What happens |
|---|---|
| absolute name `/etc/x` | skipped ("absolute path") — not stripped |
| `../x`, `a/../../x` | skipped ("contains '..'") |
| symlink `l -> /etc` or `-> ../../other`, then `l/x` | the link is skipped; `l/x` creates a plain directory `l` inside the destination |
| a symlink *already* in the destination leading out | parents are opened with `RESOLVE_NO_SYMLINKS`: the entry is skipped, nothing is written through it |
| hard link to `/etc/shadow`, `../other/secret` | skipped; a hard link to a file extracted earlier becomes a copy of it |
| device node, FIFO, socket | skipped |
| set-uid/set-gid/sticky, world-writable | files `mode & 0755 | 0600`, directories `mode & 0755 | 0700` |
| owner root | ignored: the worker is the tenant |
| control/invisible characters, non-UTF-8 names | skipped |
| zip/tar/gz bomb | stopped when the content written exceeds `extract_max_ratio` × the archive's size (default 200, at least 1 MiB) or `job_max_bytes` (default 8 GiB); the entry being written is discarded |
| millions of entries | refused beyond `extract_max_entries` (default 100 000), for zip before anything is written |
| encrypted or exotic compression | skipped with the reason |

Existing files are kept (skipped) unless `overwrite`; directories are merged.
A refused or interrupted entry never leaves a partial file (temporary name +
rename). An extraction stopped by a limit or the quota leaves the entries
already extracted (reported) — it does not roll back. Compression stores
symlinks as symlinks (never their target), leaves out special files and the
archive being written, reads at most `job_max_bytes` (a 1 TiB sparse file is
refused, not read), and does not deliver an archive with entries it could
not read (job `FAILED`, no archive).

## Limits and defaults

| Setting | Default | What it bounds |
|---|---|---|
| `ReadFile` length | 1 MiB | one response |
| `WriteFile` / `UploadChunk` data | 192 KiB | one request (the daemon decodes ≤ 256 KiB) |
| `OXPANEL_FILES_UPLOAD_MAX_BYTES` | 4 GiB | one upload |
| `OXPANEL_FILES_JOB_MAX_BYTES` | 8 GiB | content one job copies, archives or extracts |
| `OXPANEL_FILES_EXTRACT_MAX_RATIO` | 200 | extracted size / archive size |
| `OXPANEL_FILES_EXTRACT_MAX_ENTRIES` | 100 000 | entries per archive |
| `OXPANEL_FILES_LIST_MAX_ENTRIES` | 100 000 | names read from one directory (beyond: `truncated`) |
| `OXPANEL_FILES_WALK_MAX_ENTRIES` | 200 000 | entries a search or size visits (beyond: `truncated`) |
| walk time | 30 s | a search or size |
| `OXPANEL_FILES_JOB_TIMEOUT_SECS` | 7200 | one job (`RuntimeMaxSec`) |
| listing page | 1000 (default 500) | one response |
| search results | 1000 (default 200) | one response |
| selection | 1000 paths | one job |
| uploads in progress | 8 per tenant, 24 h | partial files |
| jobs | 1 per tenant, 8 per host | concurrency |
| worker memory | 256 MiB (scope), 1 GiB (job) | on top of the tenant's slice |

The tenant's slice (memory, CPU, I/O weight, tasks) and disk quota apply to
every worker; the quota is the backstop, never the control.

## Secrets and logs

File content travels on the worker's standard input/output only, marked as
secret input (never in `Debug`, never in a log line; the worker's stderr is
not logged when it fails). The daemon logs the RPC, the tenant and the path
(escaped), never content. Error messages name only the path the caller gave,
relative to the home — never an absolute path, so never another tenant's.

## Not included

Trash/undo for deleted files, versioning, sharing links, thumbnails and
previews, browsing inside an archive without extracting it, recursive mode
changes, changing owners, extended attributes and ACL editing, symlink
creation through the API, `rar`/`7z`/`bzip2`/`xz`, resumable uploads across
24 hours, conflict detection on editor save (the panel can compare `modified`
from `ReadFile`/`StatFile`), addressing an entry whose name is not UTF-8 on
its own (it is listed, sized, copied, archived and deleted with its
directory), per-tenant job queues (one at a time is enforced, not queued),
and drift kinds in `Reconcile` (the file manager writes no configuration; a
job record left `running` is concluded when the daemon starts).

## Known limitations

- Copies and extractions do not `fsync` each file (only uploads and editor
  saves do); after a power loss a just-copied file may be empty, never a
  half-written target.
- Moving across file systems inside a home (a mount point) is refused;
  copy instead.
- A protected directory is protected by its inode at the time of the
  request; it is a guard against accidents, as said above.
