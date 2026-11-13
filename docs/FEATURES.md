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

## HTTPS (certificates)

| Feature | Detail |
|---|---|
| Bring your own certificate | `InstallCertificate` takes the chain and the unencrypted private key (RSA or EC) in the request body. OpenSSL confirms the key belongs to the certificate; the daemon checks the validity period and that the certificate covers the domain (wildcards cover one label). Aliases it does not cover are reported (`uncovered_names`), not refused. Anything that fails is refused with the reason before a file is touched. `RemoveCertificate` makes the site HTTP-only again. |
| Automatic certificates (ACME, HTTP-01) | `RequestCertificate` obtains a certificate for the domain and all aliases from Let's Encrypt (or any ACME directory set in `OXPANEL_ACME_DIRECTORY_URL`, e.g. staging or a private CA). Renewed automatically 30 days before expiry (checked 5 minutes after start and every 12 hours; `RenewCertificates` does it now). A refusal by the authority is a result with its reason, not an error; the site keeps its previous certificate. |
| Automatic HTTPS | On by default (host-wide `OXPANEL_AUTO_HTTPS`, per site `auto_https_opt_out`): every site gets a certificate by itself a few seconds after it is created or its names change, and a sweep every 15 minutes retries failures. Before the authority is asked, the ACME client checks from outside the daemon that each name resolves and that every address it resolves to serves a probe file under the challenge path; names that fail are left out (the rest is still issued if the domain passes) and back off 1 h, 6 h, then daily — state kept across restarts. At most two checks/orders at once, one per site. A valid uploaded certificate is never touched; an expired one is replaced unless the site opted out. Suspended tenants are skipped and catch up on resume. `GetAutoHttpsStatus` / `oxpanel-ctl cert auto status`: covered / pending / partial / failed / uploaded / suspended / disabled, covered and skipped names with reasons, last and next attempt, last error; `RunAutoHttps` / `cert auto run [domain]` runs it now. |
| Any ACME authority | Let's Encrypt by default; any RFC 8555 directory via `OXPANEL_ACME_DIRECTORY_URL` (staging, ZeroSSL, Google Trust Services, private CAs). External Account Binding (required by ZeroSSL and Google) from a root-only file (`OXPANEL_ACME_EAB_FILE`), handed to the client as a systemd credential: never an argument, never logged, never returned. |
| The daemon stays offline | The daemon keeps `PrivateNetwork=yes`. OxPanel's own ACME client, `oxpanel-acme`, runs in a transient unit as the unprivileged account `oxpanel-acme` (no capabilities, read-only system, no homes, writable only its account, challenge and output directories). The daemon generates the key and the signing request itself; the client only ever sees the request, never a private key, and what it delivers is validated like an upload. |
| Private keys | One root-only file per site in `/etc/pki/oxpanel` (`0700`/`0600`). Never logged, never on a command line, never in a record or response. Stored PEM is rebuilt from the validated blocks, never the bytes sent. |
| Nginx | `listen 443 ssl http2` on IPv4 and IPv6 serving exactly the same site (PHP gets `HTTPS=on`, applications `X-Forwarded-Proto: https`); TLS 1.2 + 1.3, ECDHE AEAD suites only, shared session cache, no session tickets, no OCSP stapling. Per-site `redirect_https` (301, ACME challenges still answered on port 80) and `hsts` (one year, off by default). A 443 catch-all rejects the handshake for unknown names and for clients without SNI, so no tenant's certificate is ever shown for a name it does not own. |
| Status | `VirtualHost.certificate`: source (uploaded/ACME), issuer, not-before/not-after, names, uncovered names, install time — for expiry warnings in the panel. `GetHostInfo` reports `tls_available`, `acme_available` and the ACME directory. |
| Lifecycle | Reconfiguring a site keeps its certificate; removing the site removes certificate, key and any ACME leftovers. A suspended site answers 503 on both ports with its own certificate, does not redirect and answers no ACME challenges; certificates cannot be requested for it and renewals wait until it is resumed. |
| SELinux | Works enforcing: keys and certificates are `cert_t` (under `/etc/pki`), the challenge directory is `httpd_sys_content_t` via the shipped module; nothing else of the ACME client's directories is readable by the web server. |
| Reconciliation | A certificate file that differs from the record, or a missing or non-root-only key, is `TLS_CERTIFICATE_DRIFT`; a stray file in the certificate directory is `ORPHAN_TLS_FILE`; Automatic HTTPS state of a site that does not exist is `ORPHAN_AUTO_HTTPS_STATE`. |

Port 443 (and 80, for HTTP-01) must be opened in the firewall by the operator; OxPanel does not manage it.

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
| `oxpanel-ctl` | Command-line client: `tenant create|get|list|set-limits|set-owner|suspend|resume|usage|delete`, `vhost set|log|restart-app|install-deps|remove|list`, `cert install|remove|request|renew|show|auto run|auto status`, `host info|reconcile`, human-readable sizes (`512M`, `2G`). |
| Host information | `GetHostInfo`: engine version, SELinux and dry-run state, tenant and virtual-host counts, the tenant uid range (capacity), load averages, memory, uptime, and size/free space of the file system holding tenant homes. |
| Reconciliation | `Reconcile` compares every record with the operating system and reports differences: interrupted tenants, missing or mismatched accounts, invalid homes, edited or missing unit files, missing or edited Nginx files, virtual hosts without a tenant, and orphan files in OxPanel's own directories. Strictly read-only — most findings are healed by repeating the original request. `oxpanel-ctl host reconcile` exits `3` when drift is found. |
| Configuration | Environment variables `OXPANEL_*` (from `/etc/oxpanel/daemon.env`); every value has a production default. `--check-config` validates configuration and host prerequisites without starting. |
| Preflight | Refuses to start without root, without the required tools (`useradd`, `userdel`, `nginx`, `systemctl`, `setpriv`, `setfacl`, `mkdir`, `du`, and on SELinux hosts `restorecon`, `semanage`), if the socket group does not exist, or if the web user is root / a tenant. |
| systemd integration | `Type=notify` readiness, clean shutdown on `SIGTERM`/`SIGINT` (socket removed), logs via `tracing` to the journal, `RuntimeDirectory`/`StateDirectory` managed by systemd. |
| Hardened unit | `ProtectSystem=strict` with an explicit `ReadWritePaths` list, `PrivateNetwork` + `IPAddressDeny=any`, `NoNewPrivileges`, `PrivateDevices`, `ProtectKernel*`, `RestrictNamespaces`, `MemoryDenyWriteExecute`, capability deny-list, seccomp allow-list. |
| Packaging | RPM spec (`packaging/oxpanel-daemon.spec`), `sysusers.d` (creates the `oxpanel` group), `tmpfiles.d`, environment file. |
| Dry-run mode | `--dry-run` runs the full daemon against an in-memory fake OS as an unprivileged user — for developing the panel without root. |
| Records | Everything the daemon owns is recorded in `/var/lib/oxpanel/{tenants,vhosts}/*.json` (root-only). A corrupt record blocks operations on that one object only. |

## Engineering guarantees

- Rust, `#![forbid(unsafe_code)]`, clippy pedantic with warnings as errors, no `unwrap`/`expect`/`panic` in production paths.
- No shell anywhere: every external program is an absolute path with an argv array; the only module that spawns processes is `system/real.rs`.
- Tests: 130 unit tests of the daemon (exact argv assertions against a fake OS) and 9 of the ACME client, 8 end-to-end gRPC tests over a real UNIX socket, a 327-check root integration suite in an AlmaLinux 9 systemd container (including HTTPS with OpenSSL-made certificates, and ACME, Automatic HTTPS and External Account Binding end to end against a local Pebble test CA), and `make acceptance`: ≈483 checks on a real AlmaLinux 9 VM with SELinux enforcing (install from git or RPM, SELinux labels and zero AVC denials, sandbox namespaces, restart/kill/resume, reboot, soak). `cargo-deny` for advisories/licences/bans.
- Builds without a system `protoc` (pure-Rust `protox`) and without a host toolchain (everything runs in the AlmaLinux 9 container).

## Not yet included

To be explicit, v0.1.0 does **not** provide: ACME DNS-01 or wildcard certificates from ACME, OCSP stapling, a choice of PHP version or per-tenant PHP settings (the host's `php-fpm` package is used as installed), a choice of Node.js/Python version per application (the host's packages are used; Node.js must be 22 or newer), other runtimes, custom start commands or environment variables for applications, a confining SELinux policy for applications, DNS, mail, databases, FTP/SFTP/SSH access for tenants, disk quotas, backups, automatic repair of drift found by `Reconcile`, a confined SELinux domain for the daemon itself, or historical metrics. These are on the roadmap in `oxpanel-daemon/PROJECT_DETAILS.md`.
