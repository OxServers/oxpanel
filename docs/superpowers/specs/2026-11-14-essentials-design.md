# Essentials: scheduled tasks, PHP settings per site, scheduled backups — design

Date: 2026-11-14. Status: implemented on branch `m3-essentials` (from
`m3-lifecycle`, f177362).

Three small features a hosting customer expects on day one. Everything here
was decided in this stream and can be reversed; the decisions the owner is
most likely to want to change are collected at the end.

## 1. Scheduled tasks ("cron jobs")

### Shape

A task belongs to a tenant and has a name (`[a-z0-9-]`, 1–32, unique per
tenant). It is stored as a record (`/var/lib/oxpanel/tasks/<tenant>.<name>.json`)
and rendered into two files under `/etc/systemd/system`:

- `oxpanel-task-<tenant>-<name>.service` — `Type=oneshot`, `User=`/`Group=`
  the tenant, `Slice=` the tenant's slice, the same sandbox as an application
  unit (`NoNewPrivileges`, empty capability set, `ProtectSystem=strict` with
  only the home writable, private `/tmp` and devices, `ProtectKernel*`,
  `RestrictNamespaces`, `RestrictSUIDSGID`, …), `InaccessiblePaths=-/run/oxpanel`
  (the engine socket is closed to tenants by its mode already; this makes it
  invisible), on SELinux hosts `SELinuxContext=` the application domain
  `oxpanel_app_t`, and `TimeoutStartSec=` the task's time limit.
- `oxpanel-task-<tenant>-<name>.timer` — `OnCalendar=`, `RandomizedDelaySec=`
  with `FixedRandomDelay=yes`, `AccuracySec=1s`, `Persistent=false`, enabled
  into `timers.target` while the task is on and the tenant is not suspended.

Both components are systemd-escaped (`-` → `\x2d`), so the single `-` between
tenant and task name is unambiguous: tenant `a-b` task `c` and tenant `a` task
`b-c` get different units.

**Why timers and not a crontab.** A crontab line is interpreted by a shell
(`/bin/sh -c`), which is exactly what the engine never lets tenant text near;
cron runs the job in the crond's cgroup, not the tenant's slice, so limits and
usage would not apply; it has no time limit, no overlap protection and no
per-job state. A timer + oneshot unit gives all of that from systemd itself:
the unit is in the tenant's slice (limits, `GetTenantUsage`), `TimeoutStartSec`
kills the whole control group at the limit (children included: nothing
outlives it), a oneshot unit that is still activating is not started a second
time (a timer that fires while the task runs merges into the running start
job — no overlap), output goes to the journal, and `systemctl show` gives the
last start, exit and status. The files are rendered from the records, so
`Reconcile` can compare them byte for byte, and they survive a reboot.

**Missed runs are not caught up** (`Persistent=false`), as with cron: after a
reboot, hundreds of tasks would otherwise all fire at once.

### What a task may run — the security decision

The engine's "no shell" rule is about root never interpreting tenant input.
A command run as the tenant in the tenant's sandbox is the same trust level as
the tenant's own application. Even so, a **free command line was rejected**:
the line would have to go into `ExecStart=`, whose syntax (quoting, `;`, `%`
specifiers, `$` variable expansion, `-@:+!` prefixes) is a small language of
its own, and a mistake in escaping it is a mistake in a root-written unit
file. A structured form leaves nothing to interpret:

| Kind | Executed (argv) |
|---|---|
| `PHP` | `/usr/bin/php -f <home>/<script> -- <args…>` |
| `NODE` | `/usr/bin/node <home>/<script> <args…>` |
| `PYTHON` | `/usr/bin/python3 <home>/<script> <args…>`, or with a virtualenv `/usr/bin/env <home>/<venv>/bin/python <home>/<script> <args…>` (systemd cannot exec a path under a home on SELinux hosts; `env` is a system binary, as for applications) |
| `URL` | `/usr/bin/curl --silent --show-error --fail --max-time <limit> --proto =http,https --max-redirs 0 --user-agent OxPanel-task --resolve <host>:80:127.0.0.1 --resolve <host>:443:127.0.0.1 --output /dev/null --write-out "HTTP %{http_code} …" -- <url>` |

- The interpreter is always an absolute system path chosen by the engine.
- `script` and `virtualenv` are relative paths inside the home (`RelPath`:
  no `..`, no leading `/`, only `A-Za-z0-9._-/`), so they contain nothing that
  is special in a unit file.
- `args` (at most 16, each at most 256 bytes) may contain printable ASCII
  except `" ' \ $ %` and the backtick; every word is written double-quoted. So
  no argument can end the line, close the quotes, expand a specifier or a
  variable, or add a directive. A property test parses every rendered
  `ExecStart=` back with systemd's rules and gets the argv back; the
  integration test reads `ExecStart` from systemd for injection attempts.
- A `URL` task may only name a host that is one of the tenant's own server
  names (domain or alias) at the time it is saved, over `http`/`https`,
  without user info or port, with an allow-listed path/query (`%` only as a
  `%XX` escape, no `$`); `--resolve` pins it to this host's loopback, so the
  engine is never a tool to fetch arbitrary URLs and the request never leaves
  the machine. `%` is written `%%` in the unit (systemd specifier escape).
- A task whose script (or virtualenv) is missing still runs and fails visibly:
  the interpreter's "could not open" error is in the output and the exit
  status is reported. The engine does not check that the script exists when
  the task is saved (the customer may upload it afterwards).
- `php-cli` is an optional package: a PHP task is refused with
  `FAILED_PRECONDITION` when `/usr/bin/php` is missing (`GetHostInfo.php_cli_available`),
  like Node.js and Python for applications. A runtime removed later makes the
  task fail visibly (exit status 203).

### Schedule

Not a calendar expression from the caller: a structured schedule whose fields
are integers, mapped onto `OnCalendar=` by the engine. The rendered text is
built only from digits and fixed tokens, so it is safe by construction:

| Form | Fields | `OnCalendar=` |
|---|---|---|
| `EVERY_MINUTES` | `interval` ∈ {1,2,3,4,5,6,10,12,15,20,30} and ≥ the host minimum | `*-*-* *:00/N:00` |
| `EVERY_HOURS` | `interval` ∈ {1,2,3,4,6,8,12}, `minute` | `*-*-* 00/N:MM:00` |
| `DAILY` | `hour`, `minute` | `*-*-* HH:MM:00` |
| `WEEKLY` | `weekday` (0 = Sunday), `hour`, `minute` | `Sun *-*-* HH:MM:00` |
| `MONTHLY` | `day_of_month` 1–28, `hour`, `minute` | `*-*-DD HH:MM:00` |

Intervals divide 60 or 24 evenly, so "every N" is exactly every N. Wall-clock
forms take an optional IANA time zone (`Europe/Berlin`; default `UTC`),
validated by its characters and by existing under `/usr/share/zoneinfo`, and
appended to the expression (systemd ≥ 235).

- **Minimum interval**: `OXPANEL_TASK_MIN_INTERVAL_MINUTES` (default 5).
- **Per-tenant limit**: `OXPANEL_TASK_MAX_PER_TENANT` (default 20).
- **Time limit**: per task 10 s … `OXPANEL_TASK_MAX_TIMEOUT_SECS` (default
  3600), default 300 s.
- **Spreading**: `RandomizedDelaySec` = min(period, 15 min) − 1 s for the
  "every" forms and 15 min for the wall-clock forms, with `FixedRandomDelay=yes`
  (systemd ≥ 247): every task gets a stable, per-unit offset, so "every hour"
  stays exactly hourly for each task, but a thousand of them do not start in
  the same second. `AccuracySec=1s` keeps systemd from coalescing them again.

### API and state

`PutScheduledTask` (create or replace, idempotent; `vhost` scope),
`DeleteScheduledTask` (`vhost`), `RunScheduledTask` ("run now",
`systemctl start --no-block`, `vhost`; refused while suspended),
`ListScheduledTasks` and `ReadScheduledTaskLog` (`read`). `enabled` is part
of the specification.

Finding (systemd 252, AlmaLinux 9): `systemctl show --timestamp=unix` prints
the `ExecMain*Timestamp` properties as `@<seconds>`, but ignores the option
for a timer's `NextElapseUSecRealtime`, which it always prints as local
time with a zone abbreviation (`Sat 2026-11-14 01:47:00 PKT`). The daemon
therefore runs every external command with `TZ=UTC` (only the way tools
print times changes) and parses the `… UTC` form; any other form is
reported as "unknown" rather than guessed. Status comes from systemd (`systemctl show
--timestamp=unix`): running, last start and finish, result (`success`,
`exit-code`, `timeout`, `signal`), exit status, next elapse. These are
systemd's in-memory facts: they survive a daemon reload but not a reboot
(the output stays in the journal). Output: the end of the unit's journal,
like application logs.

### Lifecycle

- Suspension: after applications, every timer is disabled and stopped and
  every running task is stopped; tasks saved while suspended are born
  disabled. Resume: the timers of enabled tasks are enabled again.
- Deleting a tenant (plain or cascade) **removes** its tasks (stopped, unit
  files and records deleted) before the account goes: task definitions are
  configuration, not data, and `userdel` would refuse while a task process
  runs.
- `Reconcile`: `TASK_UNIT_DRIFT` (a unit file missing or not what the record
  renders) and `ORPHAN_TASK_UNIT` (an `oxpanel-task-*` unit without a record).

### SELinux

Tasks run in `oxpanel_app_t`, the domain applications already use; it may
execute the `bin_t` interpreters (`php`, `node`, `python3`, `env`, `curl`)
and read and write the tenant's files. No new policy rule is needed.

## 2. PHP settings per site

### Allow-list

| Setting | Values | Applied as |
|---|---|---|
| `memory_limit` | 16 … max MiB (default max 1024) | `php_value` |
| `upload_max_filesize` | 1 … max MiB (default max 256) | `php_value` |
| `post_max_size` | 1 … max MiB (default max 256), ≥ `upload_max_filesize`; if only the upload size is given, upload + 1 MiB | `php_value` |
| `max_execution_time` | 1 … max s (default max 300) | `php_value` |
| `max_input_time` | 1 … max s (default max 300) | `php_value` |
| `max_input_vars` | 100 … max (default max 10000) | `php_value` |
| `display_errors` | on/off (default off) | `php_admin_flag` |
| `date.timezone` | IANA zone, checked against `/usr/share/zoneinfo` | `php_value` |

Values are typed integers/booleans in the API and rendered by the engine
(`256M`, `120`), so nothing a caller sends reaches the configuration as text,
except a time zone, which is allow-listed character by character and must
exist. There is no way to name any other setting: the API has no free-form
key. The pool's hardening (`open_basedir`, `allow_url_include`, `upload_tmp_dir`,
`session.save_path`, …) is not reachable.

### Where they are applied: a pool per site, inside the tenant's FPM

Three places were considered:

1. **`fastcgi_param PHP_VALUE` in the site's Nginx block** — rejected. FPM
   applies `PHP_VALUE` to the *master* value of the worker that handles the
   request (`fpm_php_apply_defines_ex`, stage `ACTIVATE`), and the change
   stays in that worker for every later request. One tenant's sites share one
   pool, so site A's `memory_limit` would leak into site B served by the same
   worker. (Same trust level, so not a security problem, but wrong.)
2. **The tenant's pool** — one value per tenant, not per site.
3. **A pool per site with settings, inside the tenant's own FPM instance** —
   chosen. The instance (one master, running as the tenant, in its slice)
   keeps its default pool `[<tenant>]` for sites without settings; a site with
   settings gets a pool `[<domain>]` with its own socket
   (`/run/oxpanel-php/<tenant>/<domain>.sock`), the same hardening as the
   default pool, and its settings as `php_value`. The site's Nginx block passes
   to that socket. Nothing leaks between sites; idle pools cost nothing
   (`pm = ondemand`, at most 8 workers each; the tenant's `TasksMax` and
   `MemoryMax` remain the hard limits).

**Byte-identical defaults.** A tenant whose sites set nothing gets exactly the
pool configuration and server blocks it had before (asserted by unit tests).

`php_value`, not `php_admin_value`: a script may still change the settings
that PHP lets it change (`ini_set('memory_limit', …)`, `set_time_limit()`),
as it can on any PHP host — the API sets the defaults the application runs
with, not a security boundary. The real ceiling for memory is the tenant's
cgroup (`MemoryMax`), and for time the tenant's CPU weight; both are said so
in the handbook. `display_errors` stays an admin flag (it is already one in
the pool). On Linux, `max_execution_time` counts CPU time of the script, not
time spent waiting (sleep, database, network) — PHP's own rule.

### Nginx follows

Only when a setting is used:

- `client_max_body_size <post_max_size>m;` at server level (Nginx's default is
  1 MiB — without this, a larger `upload_max_filesize` would do nothing);
- `fastcgi_read_timeout` = max(60, `max_execution_time` + 30) s and
  `fastcgi_send_timeout` = max(60, `max_input_time` + 30) s in the PHP
  location (Nginx's default is 60 s — a longer execution time would end in a
  504 while the script still runs).

### Maxima: host and plan

Host maxima: `OXPANEL_PHP_MAX_MEMORY_MB`, `OXPANEL_PHP_MAX_UPLOAD_MB` (upload
and post), `OXPANEL_PHP_MAX_EXECUTION_SECS`, `OXPANEL_PHP_MAX_INPUT_TIME_SECS`,
`OXPANEL_PHP_MAX_INPUT_VARS`. Per tenant (a plan): `SetTenantPhpLimits`
(`tenant` scope) stores lower caps on the tenant record (0 = the host
maximum); each must lie within the host's bounds. `SetPhpSettings` refuses a
value above the tenant's cap. If a cap is lowered later, sites keep their
requested values in the record but are **rendered clamped** to the cap, so a
plan downgrade takes effect at once without rewriting customers' choices;
`VirtualHost.php_settings_effective` shows what applies. Changing the host
maxima takes effect at the next daemon start (start-up convergence re-renders).

### API

`SetPhpSettings(domain, settings)` (`vhost` scope: the customer tier may tune
its own sites) replaces the site's settings (an empty message clears them);
refused for a site without PHP (`FAILED_PRECONDITION`). Settings are kept on
the virtual-host record; `ConfigureVirtualHost` keeps them, as it keeps the
certificate. `VirtualHost.php_settings` / `php_settings_effective`,
`Tenant.php_limits`, `GetHostInfo.php_limits` for reads.

`Reconcile`: the pool file now includes the site pools, so an edited one is
the existing `PHP_POOL_DRIFT`; Nginx blocks are the existing
`VHOST_CONFIG_DRIFT`.

## 3. Scheduled backups

### Held in the engine

One record per tenant that has a schedule or has been seen by the scheduler,
`/var/lib/oxpanel/backup-schedules/<tenant>.json`: the tenant's choice
(`off`, `daily`, `weekly`, or none = follow the host default), the hour and
weekday if the caller chose them, and the scheduler's state (last slot
handled, last job, last result and message). A loop in the daemon (every
`OXPANEL_BACKUP_SCHEDULE_CHECK_SECS`, default 300, and at start-up) starts
what is due with the same `create_job` as `CreateBackup`, so a scheduled
backup is subject to everything a manual one is: one job per tenant, at most 4
jobs on the host, the free-space check and reserve, the exclusion rules,
database dumps, the time limit, retention. Backups run whether or not the
panel is up.

### When

All times are UTC (the engine has no time-zone database of its own; a
host's backup window is an operator setting, not a customer one).

- **Minute**: always assigned by the engine from a stable hash of the tenant
  name (FNV-1a), so tenants spread over the hour.
- **Hour**: chosen by the caller, or assigned from the hash within the host's
  window `OXPANEL_BACKUP_WINDOW` (default `01-05`, inclusive).
- **Weekday** (weekly): chosen, or assigned from the hash.

The scheduler computes the most recent slot ≤ now. It is due when that slot
is later than the last slot handled. **Catch-up once**: after the host was off
for three days, the most recent slot is the only one that is due — one backup,
not three. Setting or changing a schedule, and the first time the scheduler
sees a tenant on the host default, marks the current slot as handled, so the
first run is the next slot (no stampede on upgrade).

### Results

- Started: last result `running` with the job id; on a later round the job's
  outcome is copied (`succeeded` / `failed` with the job's message).
- Refused before starting (no space, MariaDB unavailable, …): `failed` with
  the reason; the slot is handled, the next slot runs normally — a failure
  never stops future runs.
- The host's job cap is reached, or another job of the tenant (a restore) is
  running: `deferred`, and the slot stays due, so it is retried at the next
  round. A manual backup already running counts as this slot's backup.
- `GetBackupSchedule` shows the effective schedule, where it comes from, the
  next run, the last run, job, result and message.

### Decisions

- **Same keep-count as manual backups.** Separate counts would make "how many
  backups do I have" two numbers, and a long series of scheduled backups would
  still be the newest anyway; a backup worth keeping is marked retained
  (`RetainBackup`), which exempts it from the count.
- **Suspended tenants keep their scheduled backups.** Suspension is often a
  dispute about payment; the data should be protected until the account is
  deleted. The operator can switch a tenant's schedule off.
- **Host switch and default**: `OXPANEL_BACKUP_SCHEDULES=true` (the loop runs)
  and `OXPANEL_BACKUP_SCHEDULE_DEFAULT=off` (what tenants without a choice
  get). With the switch off, schedules are kept but nothing runs. The
  default is `off`, not `daily`, so that upgrading a host does not start
  filling its backup disk on its own, and so that test tenants on the
  acceptance VM never get a backup the tests did not ask for (a run crossing
  a tenant's assigned hour would otherwise race the checks). The handbook
  recommends `daily` for production hosts; it is one line in `daemon.env`.
- **Scope**: `SetBackupSchedule` needs the `tenant` scope, like `CreateBackup`;
  `GetBackupSchedule` needs `read`.
- Deleting a tenant removes its schedule record.

`Reconcile`: `ORPHAN_BACKUP_SCHEDULE` (a schedule record for a tenant that
does not exist).

## Testing

- Unit tests (fake OS): exact argv of every `systemctl` call, exact rendered
  service and timer units, pool files with site pools, server blocks with and
  without settings (byte-identical without), clamping, scheduler slot
  arithmetic, catch-up once, deferral, failure recording.
- Property tests: every accepted schedule renders to an expression of the
  allowed alphabet and round-trips; every accepted argument list survives
  `ExecStart=` quoting (parsed back with systemd's rules); arbitrary strings
  are either refused or rendered harmlessly; every accepted PHP settings set
  renders to lines of the allowed form; the backup slot is ≤ now, within one
  period, and stable.
- Integration (container) and acceptance (VM, SELinux enforcing, phase 20):
  a PHP, a Node.js and a Python task really run as the tenant, on schedule
  and with "run now"; output readable; time limit kills a sleeping task;
  cannot read another tenant's home or reach the engine socket; counted in
  the tenant's slice; injection attempts in every field refused; suspension,
  resume, deletion. Each PHP setting observed through `ini_get` in a real
  request; an upload larger than the old limit succeeds; a CPU-bound script
  is cut at `max_execution_time`; out-of-bounds values refused; caps clamp.
  Scheduled backups: the "due" logic is exercised for real by rewinding the
  record's last handled slot while the daemon is stopped (simulating three
  days of downtime) with a 5-second check interval: exactly one backup runs
  (catch-up once) and is recorded; a failing one (free-space reserve set
  impossibly high) is recorded as failed and the next run is still scheduled.

## Not included

- Per-task environment variables, a free command line, shell features
  (pipes, redirection) — a task can be a script that does these.
- E-mailing task output (no mail system yet).
- Catching up missed task runs after downtime.
- Last-run state of tasks across reboots (systemd keeps it in memory; the
  output stays in the journal).
- Other PHP settings (`opcache.*`, `session.*`, extensions), per-site PHP
  versions.
- Backup schedules other than daily/weekly, more than one per day, separate
  keep-counts, time zones other than UTC, off-host targets.
