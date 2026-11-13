# OxPanel engine — feature list (v0.1.0)

This is what `oxpanel-daemon` **does today**, as verified by the test suites
(`make test`, `make integration`). Anything not listed here is not implemented;
see "Not yet included" at the end so nobody assumes otherwise.

## Tenant accounts

| Feature | Detail |
|---|---|
| Create tenant | Dedicated POSIX user **and** primary group with the same numeric id (when free), allocated from a reserved uid range (default `20000–29999`, lowest free id), login shell `/sbin/nologin`, password locked, GECOS `OxPanel tenant`. |
| Private home | `<home_base>/<username>` (default `/home/<username>`), mode `0700`, owned by the tenant. Mode and ownership are re-verified and repaired on every provisioning pass. |
| Resource limits (cgroups v2) | Per-tenant systemd slice `oxpanel-tenant-<name>.slice` carrying `MemoryMax` (plus `MemorySwapMax=0`), `CPUWeight`, `IOWeight`, `TasksMax`; a `user-<uid>.slice.d/50-oxpanel.conf` drop-in applies the same limits to any future login session. Written as unit files and applied with `systemctl daemon-reload` — the daemon never writes `/sys/fs/cgroup`. |
| Safe unit naming | Tenant names are systemd-escaped (`foo-bar` → `oxpanel-tenant-foo\x2dbar.slice`) so one tenant's slice can never be nested under another's. |
| Owner label | Optional opaque `owner` string (e.g. a reseller id) stored on the tenant and usable as a filter in `ListTenants`. The engine never interprets it. |
| Get / list | `GetTenant`, `ListTenants` (optionally filtered by owner). |
| Delete tenant | `userdel`, optionally with `--remove` (home directory), removes the slice unit and drop-in. Refused while the tenant still owns virtual hosts. |
| SELinux | On SELinux-enabled hosts the home is relabelled with `restorecon -R` after creation. |
| Idempotent | Repeating `CreateTenant` with an identical specification returns the existing tenant (`created=false`); a different specification is refused (`ALREADY_EXISTS`). |
| Resumable | The tenant record is written **before** `useradd`; if the daemon crashes at any point, the next identical request resumes the remaining steps. Records carry a state: `provisioning`, `ready`, `deleting`. |
| Never adopts foreign accounts | A user or group that exists but was not created by OxPanel is refused (`FAILED_PRECONDITION`), and can never be deleted through the API. |
| Update limits | `UpdateTenantLimits` replaces the tenant's limits (a complete set, not a patch): both unit files are rewritten and applied with `daemon-reload`, so the new values are live immediately. Repeating the call completes an interrupted attempt. |
| Update owner | `UpdateTenantOwner` replaces or clears the owner label (e.g. moving a customer to another reseller). Touches no OS state. |
| Suspend / resume | `SuspendTenant` re-renders every virtual host of the tenant to answer `503` with `Retry-After` and no document root, validates once and reloads; all files are restored if Nginx rejects the result. Files, limits and the account are untouched; sites added while suspended are born suspended. `ResumeTenant` reverses it. |
| Usage | `GetTenantUsage`: current memory, total CPU time and task count from systemd (tenant slice + login-session slice), and disk space allocated under the home (`du`, one file system, no symlink following). |
| Reserved names | `root`, `nginx`, `apache`, `oxpanel*`, `systemd-*`, `wheel`, `sudo`, … are rejected before anything touches the OS. |

## Virtual hosts (Nginx)

| Feature | Detail |
|---|---|
| Configure | One server block per domain: `listen 80` / `listen [::]:80`, `server_name <domain> <aliases…>`, `root <home>/<document_root>`, `index index.html index.htm`, `try_files`. |
| Per-site logs | Every virtual host writes its own `<domain>.access.log` and `<domain>.error.log` under `/var/log/nginx/oxpanel` (closed to tenants), rotated daily for 14 days by the shipped logrotate rule and removed with the site. `ReadVirtualHostLog` returns the end of either log (whole lines, 32 KiB by default, at most 128 KiB) so the panel can show it without shell access. |
| PHP source is never served | On a virtual host without PHP, `*.php` answers 404 instead of handing out the script as a download. |
| Start-up convergence | At start the daemon re-renders every virtual host from its record, so files written by an older version pick up the current template (validated and rolled back like any other change). |
| Aliases | Up to 50 additional server names per virtual host. Every server name is unique across the whole host; a name owned by another tenant is refused. |
| Document root | Relative to the tenant home (default `public_html`), **created as the tenant** (privileges fully dropped via `setpriv`), then verified to be a real directory owned by the tenant. |
| Web-server access without opening the home | POSIX ACLs give the web user (`nginx`) traverse (`--x`) on the path and read (`r-x`) on the document root, plus a default ACL so new files inherit it. The home stays closed to everyone else (`group::---`, `other::---`). ACLs are set with `--physical`, so a planted symlink is skipped. |
| Hardened server block | `disable_symlinks if_not_owner` (symlinks to files the tenant does not own are refused), dot-files (`/.env`, `/.git`) answered with 404, `autoindex off`, `server_tokens off`. |
| Validate → activate → roll back | Config written atomically (`tempfile` + `rename` + `fsync`), checked with `nginx -t`; only then `systemctl reload-or-restart nginx`. If validation fails the previous file (or its absence) is restored and the error text is returned. |
| Catch-all default server | On first use the daemon installs `/etc/nginx/conf.d/00-oxpanel.conf` with an `include` of its directory **and** a `default_server` that closes the connection (`return 444`), so unknown host names and bare-IP requests never reach a tenant's site. Validated with `nginx -t`; rolled back if the host already defines a default server (configurable). |
| SELinux | On SELinux-enabled hosts the document root is made label-equivalent to `/usr/share/nginx/html` (`semanage fcontext -e`, so the tree is `httpd_sys_content_t` even though the policy's own `file_contexts.homedirs` would label `~/public_html` differently; a plain rule is overridden), committed without a kernel policy reload, then `restorecon -RF` (the policy creates `~/public_html` as the *customizable* `httpd_user_content_t`, which plain `restorecon` refuses to change); removed again when the last virtual host using that root is removed. Requires the `httpd_enable_homedirs` and `httpd_read_user_content` booleans, which the RPM sets and the daemon checks at start-up. |
| Remove / list | `RemoveVirtualHost` (config removed, validated, reloaded), `ListVirtualHosts` (optionally per tenant). |
| Idempotent | Re-sending an identical configuration changes nothing and reports `created=false`. |

## PHP (per-tenant PHP-FPM)

| Feature | Detail |
|---|---|
| Opt-in per virtual host | `ConfigureVirtualHost` with `php=true`. Refused with `FAILED_PRECONDITION` if `php-fpm` is not installed; `GetHostInfo.php_available` tells the panel in advance. |
| One FPM instance per tenant, running as the tenant | Not a pool inside a shared root-owned master: the whole instance (master and workers) runs under the tenant's uid through its own systemd unit `oxpanel-php-<name>.service`. No PHP process ever runs as root or as another tenant. |
| Inside the tenant's limits | The unit lives in the tenant's slice, so `MemoryMax`, `CPUWeight`, `IOWeight` and `TasksMax` bound PHP, and `GetTenantUsage` reports it. At most 8 workers, started on demand and stopped when idle. |
| Sandboxed unit | `NoNewPrivileges`, empty capability set, `ProtectSystem=strict` with only the tenant's home writable, private `/tmp` (sessions and uploads are per tenant), `PrivateDevices`, `ProtectKernel*`, `RestrictNamespaces`. |
| Socket only the web server can reach | UNIX socket `/run/oxpanel-php/<name>/php.sock` with an ACL naming the web-server account. Other tenants cannot connect; there is no TCP listener. |
| Confined scripts | `open_basedir` limits file access to the tenant's home and `/tmp`; `allow_url_include` and `display_errors` are off; only `.php` is executed. |
| Safe Nginx hand-off | `try_files $uri =404` before `fastcgi_pass` (a script that does not exist is never passed on, which closes the `image.jpg/x.php` path-info trick), `SCRIPT_FILENAME` built from `$realpath_root`, dot-directories excluded, `X-Powered-By` hidden. Unknown paths fall back to `/index.php` (front controllers such as WordPress work without rewrite rules). |
| Lifecycle | The instance is created with the tenant's first PHP-enabled virtual host and removed with the last one. It is enabled, so it returns after a reboot. Suspending the tenant stops and disables it (after the sites answer 503); resuming starts it before the sites return. |
| SELinux | Works enforcing with zero denials. PHP runs in the web-server domain; the RPM sets `httpd_unified` so a tenant's PHP can write the tenant's own files (uploads, caches). Without the boolean PHP is read-only and the daemon logs a warning at start. |
| Reconciliation | A missing or edited pool configuration or unit is reported as `PHP_POOL_DRIFT`, stray ones as `ORPHAN_PHP_POOL`. |

## Node.js and Python applications

| Feature | Detail |
|---|---|
| Opt-in per virtual host | `ConfigureVirtualHost` with `app { runtime: NODE | PYTHON, root, entry }` (defaults: `apps/<domain>`, `app.js` / `app.py`). Cannot be combined with `php`. Refused with `FAILED_PRECONDITION` if the runtime is not installed, or if Node.js is older than **22** (the minimum supported); `GetHostInfo` reports `node_available`, `node_version` and `python_available`. |
| One service per application, running as the tenant | `oxpanel-app-<domain>.service`: `User=<tenant>`, in the tenant's slice (so the tenant's limits bound it and `GetTenantUsage` counts it), sandboxed like PHP (`NoNewPrivileges`, empty capability set, `ProtectSystem=strict` with only the tenant's home writable, private `/tmp`). Restarted automatically if it crashes; enabled, so it returns after a reboot. |
| No TCP ports | The application listens on a UNIX socket whose path it receives in `PORT` and `OXPANEL_SOCKET` (`server.listen(process.env.PORT)` works unchanged in Node.js). The socket directory is `0750` with an ACL for the web server only: other tenants can neither enter it nor connect, and there are no ports to allocate or collide. |
| Source is never web-readable | The application directory gets no web-server ACL and must not be the document root or inside it. Nginx serves files that exist in the document root itself (static assets) and proxies everything else, including WebSocket upgrades, to the application; `X-Forwarded-For`/`-Proto` and `Host` are passed on, `X-Powered-By` is hidden. |
| Python virtualenv | Every Python application gets its own virtualenv (`<root>/.venv`), created as the tenant. The application runs with that interpreter, so its packages are its own. |
| Dependencies | `InstallAppDependencies` runs `npm install --omit=dev` or `pip install -r requirements.txt` (into the virtualenv) as the tenant, in a sandboxed transient unit inside the tenant's slice with a 4-minute limit, returns the installer's output, and restarts the application on success. A failing installer is a result, not an error. |
| Restart and output | `RestartApp` (after new code is in place; also clears a crash loop). `ReadVirtualHostLog` with kind `APP` returns the application's recent stdout/stderr from the journal. |
| Lifecycle | The unit is removed when the application is switched off or the virtual host is removed; the code stays (it is the tenant's data). Suspension stops and disables every application of the tenant after the sites answer 503; resume starts them before the sites return. |
| SELinux | Works enforcing with zero denials. Applications run in their own domain, `oxpanel_app_t` (a small CIL module shipped with the package), so the web server is allowed to connect to application sockets and to nothing else; socket directories are labelled `httpd_var_run_t`. If the module is missing, enabling an application is refused with the command that installs it. |
| Reconciliation | An edited or missing application unit is `APP_UNIT_DRIFT`, a stray one `ORPHAN_APP_UNIT`. |

## Backups and restores

| Feature | Detail |
|---|---|
| Jobs | `CreateBackup` and `RestoreBackup` return a job at once; `GetJob` reports `RUNNING`, `SUCCEEDED` or `FAILED` with a message and the end of the worker's output. The work runs in a transient systemd unit (`oxpanel-job-<id>.service`), so it is not bound by the 300 s request limit and survives a restart or crash of the daemon, which re-attaches to running jobs at start. One job per tenant, at most 4 on the host. |
| Contents | The tenant's home as a gzip'd tar (`home.tar.gz`) and the engine's records of the tenant and its virtual hosts (`records.json`), listed in a `manifest.json` with size and SHA-256 of each member. Further members (database dumps) can be added without changing the format. |
| Left out, and said so | `node_modules` at any depth, Python virtualenvs (any directory with a `pyvenv.cfg`, and every Python application's `.venv`), and the `.cache`/`.npm` download caches. A scan as the tenant lists what was left out in the record, the manifest and `ListBackups` (`excluded`, `excluded_count`, `exclude_rules`), and the free-space estimate does not count it. |
| Read as the tenant | `tar` runs with the tenant's uid (never root), stores symlinks as symlinks, skips what the tenant cannot read, records FIFOs and device nodes without opening them, handles sparse files, stays on one file system. It writes into a pipe; only a root worker without `CAP_DAC_OVERRIDE` writes the archive file. |
| Charged to the tenant | The job runs in the tenant's slice at the lowest CPU and I/O priority, sandboxed (`ProtectSystem=strict` with one writable path, no network), with a time limit (6 h by default). |
| Root-only storage, bounded | `/var/lib/oxpanel-backups/<tenant>/<id>/`, directories `0700`, files `0600`; tenants cannot list or read it. A backup is refused unless the home fits with a reserve to spare (1 GiB by default), and the archive may not grow into it. The newest 7 complete backups per tenant are kept (configurable). |
| Never half-written | A backup is listed `READY` only after the worker has written and synced the archive and the daemon has written the manifest; a failed, killed or interrupted backup leaves nothing behind. |
| Integrity | Size and SHA-256 are verified in full before a restore starts; a damaged or truncated archive is refused and nothing is restored. |
| Restore as the tenant | Into the home, with a required choice for files that already exist: `OVERWRITE` (replaced, never written through) or `KEEP` (left untouched, only missing files restored); there is no default. Newer files always stay; the job reports how many entries were restored and how many were kept. Extracted by `tar` running as the tenant in a sandbox where only the home is writable: absolute paths, `..`, writes through symlinks, hard links out of the home, set-uid/set-gid files and device nodes are all refused, and every file belongs to the tenant. PHP and applications are stopped during the restore; afterwards the home is made private again, relabelled, and every document root gets its web-server ACLs and SELinux label back, so the site is served without manual steps. Every application gets its virtualenv recreated and its dependencies reinstalled (as `InstallAppDependencies` does) before it starts; the result per site is in the job, and a failed installation does not fail the restore of the files. |
| Tenant isolation | A backup is only found for the tenant it belongs to (and the uid it was taken from): restoring or deleting another tenant's backup is `NOT_FOUND`. |
| Lifecycle | Suspended tenants can be backed up and restored (their services stay stopped). `DeleteTenant` is refused while the tenant has a running job or backups that are not retained. |
| Retained backups | A backup can be kept for 1–12 months (`CreateBackup.retain_months` or `RetainBackup`): exempt from the per-tenant count, kept after `DeleteTenant`, then removed automatically (checked at start-up and hourly). Backups of a deleted tenant are invisible to a later tenant of the same name; the operator lists them (`ListRetainedBackups`), deletes them early, or restores one into an existing tenant with `RestoreRetainedBackup` (backup id + former tenant + target, `delete` scope). |
| Reconciliation | `BACKUP_ARCHIVE_MISSING`, `BACKUP_ARCHIVE_MODIFIED` (size or manifest differs from the record), `ORPHAN_BACKUP_ARCHIVE`, `BACKUP_INCOMPLETE`. |
| Scheduling | Left to the panel (call `CreateBackup` on its own timetable); retention is enforced by the engine. |

## API, transport and authentication

| Feature | Detail |
|---|---|
| gRPC over a UNIX socket only | `/run/oxpanel/oxpanel.sock`, `root:oxpanel 0660`. There is no TCP listener and no TLS — nothing to expose. |
| Kernel-verified peers | Every connection is authenticated with `SO_PEERCRED`. Allowed: uid 0 (configurable), uids in `OXPANEL_ALLOWED_UIDS`, and accounts whose primary or supplementary group (from the account database) is in `OXPANEL_ALLOWED_GIDS` or is the socket group. Unauthorised peers are closed **before** any HTTP/2 is parsed. |
| Fail-closed interceptor | A request without verified peer information is refused with `PERMISSION_DENIED`. |
| Strict input validation | Allow-list newtypes for user names (`^[a-z][a-z0-9_-]{2,31}$`), domains (lower-case ASCII / punycode labels, no wildcards, no IPs), document roots (no `..`, no metacharacters), owner labels, and limits (memory ≥ 16 MiB or unlimited, weights 1–10000). Invalid input never reaches the OS. |
| Precise error codes | `INVALID_ARGUMENT`, `ALREADY_EXISTS`, `NOT_FOUND`, `FAILED_PRECONDITION`, `RESOURCE_EXHAUSTED`, `PERMISSION_DENIED`, `DEADLINE_EXCEEDED`, `INTERNAL`. Internal failures are redacted for the client and logged in full to the journal. |
| Limits | Requests capped at 256 KiB, 16 concurrent streams per connection, 300 s per request, HTTP/2 keep-alive. |
| Per-peer scopes | `OXPANEL_PEER_SCOPES=uid:scope+scope,…` confines an authenticated peer to `read`, `vhost`, `tenant` and/or `delete` RPCs; anything else is refused with `PERMISSION_DENIED` before validation or any OS call. Unlisted peers keep full access. A customer-facing service account limited to `read+vhost` can never reach `DeleteTenant`. |
| Serialised mutations | One global lock: exactly one tenant/vhost mutation runs at a time (the account database, Nginx and systemd are not transactional). |

## Operations

| Feature | Detail |
|---|---|
| `oxpanel-ctl` | Command-line client: `tenant create|get|list|set-limits|set-owner|suspend|resume|usage|delete`, `vhost set|log|restart-app|install-deps|remove|list`, `host info|reconcile`, `backup create|list|delete|restore|job|retain|list-retained|restore-retained` (restores require `--overwrite` or `--keep-existing`; `--wait`), human-readable sizes (`512M`, `2G`). |
| Host information | `GetHostInfo`: engine version, SELinux and dry-run state, tenant and virtual-host counts, the tenant uid range (capacity), load averages, memory, uptime, and size/free space of the file system holding tenant homes. |
| Reconciliation | `Reconcile` compares every record with the operating system and reports differences: interrupted tenants, missing or mismatched accounts, invalid homes, edited or missing unit files, missing or edited Nginx files, virtual hosts without a tenant, and orphan files in OxPanel's own directories. Strictly read-only — most findings are healed by repeating the original request. `oxpanel-ctl host reconcile` exits `3` when drift is found. |
| Configuration | Environment variables `OXPANEL_*` (from `/etc/oxpanel/daemon.env`); every value has a production default. `--check-config` validates configuration and host prerequisites without starting. |
| Preflight | Refuses to start without root, without the required tools (`useradd`, `userdel`, `nginx`, `systemctl`, `setpriv`, `setfacl`, `mkdir`, `du`, and on SELinux hosts `restorecon`, `semanage`), if the socket group does not exist, or if the web user is root / a tenant. |
| systemd integration | `Type=notify` readiness, clean shutdown on `SIGTERM`/`SIGINT` (socket removed), logs via `tracing` to the journal, `RuntimeDirectory`/`StateDirectory` managed by systemd. |
| Hardened unit | `ProtectSystem=strict` with an explicit `ReadWritePaths` list, `PrivateNetwork` + `IPAddressDeny=any`, `NoNewPrivileges`, `PrivateDevices`, `ProtectKernel*`, `RestrictNamespaces`, `MemoryDenyWriteExecute`, capability deny-list, seccomp allow-list. |
| Packaging | RPM spec (`packaging/oxpanel-daemon.spec`), `sysusers.d` (creates the `oxpanel` group), `tmpfiles.d`, environment file. |
| Dry-run mode | `--dry-run` runs the full daemon against an in-memory fake OS as an unprivileged user — for developing the panel without root. |
| Records | Everything the daemon owns is recorded in `/var/lib/oxpanel/{tenants,vhosts,backups,jobs}/*.json` (root-only). A corrupt record blocks operations on that one object only. |

## Engineering guarantees

- Rust, `#![forbid(unsafe_code)]`, clippy pedantic with warnings as errors, no `unwrap`/`expect`/`panic` in production paths.
- No shell anywhere: every external program is an absolute path with an argv array; the only module that spawns processes is `system/real.rs`.
- Tests: 136 unit tests (exact argv assertions against a fake OS), 6 end-to-end gRPC tests over a real UNIX socket, a 364-check root integration suite in an AlmaLinux 9 systemd container, and `make acceptance`: ≈480 checks on a real AlmaLinux 9 VM with SELinux enforcing (install from git or RPM, SELinux labels and zero AVC denials, sandbox namespaces, restart/kill/resume, reboot, soak). `cargo-deny` for advisories/licences/bans.
- Builds without a system `protoc` (pure-Rust `protox`) and without a host toolchain (everything runs in the AlmaLinux 9 container).

## Not yet included

To be explicit, v0.1.0 does **not** provide: TLS/ACME certificates, a choice of PHP version or per-tenant PHP settings (the host's `php-fpm` package is used as installed), a choice of Node.js/Python version per application (the host's packages are used; Node.js must be 22 or newer), other runtimes, custom start commands or environment variables for applications, a confining SELinux policy for applications, DNS, mail, databases, FTP/SFTP/SSH access for tenants, disk quotas, off-host or encrypted backups, automatic repair of drift found by `Reconcile`, a confined SELinux domain for the daemon itself, or historical metrics. These are on the roadmap in `oxpanel-daemon/PROJECT_DETAILS.md`.
