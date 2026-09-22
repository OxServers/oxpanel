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
| Reserved names | `root`, `nginx`, `apache`, `oxpanel*`, `systemd-*`, `wheel`, `sudo`, … are rejected before anything touches the OS. |

## Virtual hosts (Nginx)

| Feature | Detail |
|---|---|
| Configure | One server block per domain: `listen 80` / `listen [::]:80`, `server_name <domain> <aliases…>`, `root <home>/<document_root>`, `index index.html index.htm`, `try_files`. |
| Aliases | Up to 50 additional server names per virtual host. Every server name is unique across the whole host; a name owned by another tenant is refused. |
| Document root | Relative to the tenant home (default `public_html`), **created as the tenant** (privileges fully dropped via `setpriv`), then verified to be a real directory owned by the tenant. |
| Web-server access without opening the home | POSIX ACLs give the web user (`nginx`) traverse (`--x`) on the path and read (`r-x`) on the document root, plus a default ACL so new files inherit it. The home stays closed to everyone else (`group::---`, `other::---`). ACLs are set with `--physical`, so a planted symlink is skipped. |
| Hardened server block | `disable_symlinks if_not_owner` (symlinks to files the tenant does not own are refused), dot-files (`/.env`, `/.git`) answered with 404, `autoindex off`, `server_tokens off`. |
| Validate → activate → roll back | Config written atomically (`tempfile` + `rename` + `fsync`), checked with `nginx -t`; only then `systemctl reload-or-restart nginx`. If validation fails the previous file (or its absence) is restored and the error text is returned. |
| Catch-all default server | On first use the daemon installs `/etc/nginx/conf.d/00-oxpanel.conf` with an `include` of its directory **and** a `default_server` that closes the connection (`return 444`), so unknown host names and bare-IP requests never reach a tenant's site. Validated with `nginx -t`; rolled back if the host already defines a default server (configurable). |
| SELinux | On SELinux-enabled hosts the document root is made label-equivalent to `/usr/share/nginx/html` (`semanage fcontext -e`, so the tree is `httpd_sys_content_t` even though the policy's own `file_contexts.homedirs` would label `~/public_html` differently; a plain rule is overridden), committed without a kernel policy reload, then `restorecon -RF` (the policy creates `~/public_html` as the *customizable* `httpd_user_content_t`, which plain `restorecon` refuses to change); removed again when the last virtual host using that root is removed. Requires the `httpd_enable_homedirs` and `httpd_read_user_content` booleans, which the RPM sets and the daemon checks at start-up. |
| Remove / list | `RemoveVirtualHost` (config removed, validated, reloaded), `ListVirtualHosts` (optionally per tenant). |
| Idempotent | Re-sending an identical configuration changes nothing and reports `created=false`. |

## API, transport and authentication

| Feature | Detail |
|---|---|
| gRPC over a UNIX socket only | `/run/oxpanel/oxpanel.sock`, `root:oxpanel 0660`. There is no TCP listener and no TLS — nothing to expose. |
| Kernel-verified peers | Every connection is authenticated with `SO_PEERCRED`. Allowed: uid 0 (configurable), uids in `OXPANEL_ALLOWED_UIDS`, and accounts whose primary or supplementary group (from the account database) is in `OXPANEL_ALLOWED_GIDS` or is the socket group. Unauthorised peers are closed **before** any HTTP/2 is parsed. |
| Fail-closed interceptor | A request without verified peer information is refused with `PERMISSION_DENIED`. |
| Strict input validation | Allow-list newtypes for user names (`^[a-z][a-z0-9_-]{2,31}$`), domains (lower-case ASCII / punycode labels, no wildcards, no IPs), document roots (no `..`, no metacharacters), owner labels, and limits (memory ≥ 16 MiB or unlimited, weights 1–10000). Invalid input never reaches the OS. |
| Precise error codes | `INVALID_ARGUMENT`, `ALREADY_EXISTS`, `NOT_FOUND`, `FAILED_PRECONDITION`, `RESOURCE_EXHAUSTED`, `PERMISSION_DENIED`, `DEADLINE_EXCEEDED`, `INTERNAL`. Internal failures are redacted for the client and logged in full to the journal. |
| Limits | Requests capped at 256 KiB, 16 concurrent streams per connection, 300 s per request, HTTP/2 keep-alive. |
| Serialised mutations | One global lock: exactly one tenant/vhost mutation runs at a time (the account database, Nginx and systemd are not transactional). |

## Operations

| Feature | Detail |
|---|---|
| `oxpanel-ctl` | Command-line client: `tenant create|get|list|delete`, `vhost set|remove|list`, human-readable sizes (`512M`, `2G`). |
| Configuration | Environment variables `OXPANEL_*` (from `/etc/oxpanel/daemon.env`); every value has a production default. `--check-config` validates configuration and host prerequisites without starting. |
| Preflight | Refuses to start without root, without the required tools (`useradd`, `userdel`, `nginx`, `systemctl`, `setpriv`, `setfacl`, `mkdir`, and on SELinux hosts `restorecon`, `semanage`), if the socket group does not exist, or if the web user is root / a tenant. |
| systemd integration | `Type=notify` readiness, clean shutdown on `SIGTERM`/`SIGINT` (socket removed), logs via `tracing` to the journal, `RuntimeDirectory`/`StateDirectory` managed by systemd. |
| Hardened unit | `ProtectSystem=strict` with an explicit `ReadWritePaths` list, `PrivateNetwork` + `IPAddressDeny=any`, `NoNewPrivileges`, `PrivateDevices`, `ProtectKernel*`, `RestrictNamespaces`, `MemoryDenyWriteExecute`, capability deny-list, seccomp allow-list. |
| Packaging | RPM spec (`packaging/oxpanel-daemon.spec`), `sysusers.d` (creates the `oxpanel` group), `tmpfiles.d`, environment file. |
| Dry-run mode | `--dry-run` runs the full daemon against an in-memory fake OS as an unprivileged user — for developing the panel without root. |
| Records | Everything the daemon owns is recorded in `/var/lib/oxpanel/{tenants,vhosts}/*.json` (root-only). A corrupt record blocks operations on that one object only. |

## Engineering guarantees

- Rust, `#![forbid(unsafe_code)]`, clippy pedantic with warnings as errors, no `unwrap`/`expect`/`panic` in production paths.
- No shell anywhere: every external program is an absolute path with an argv array; the only module that spawns processes is `system/real.rs`.
- Tests: 63 unit tests (exact argv assertions against a fake OS), 4 end-to-end gRPC tests over a real UNIX socket, an 80-check root integration suite in an AlmaLinux 9 systemd container, and `make acceptance`: ≈200 checks on a real AlmaLinux 9 VM with SELinux enforcing (install from git or RPM, SELinux labels and zero AVC denials, sandbox namespaces, restart/kill/resume, reboot, soak). `cargo-deny` for advisories/licences/bans.
- Builds without a system `protoc` (pure-Rust `protox`) and without a host toolchain (everything runs in the AlmaLinux 9 container).

## Not yet included

To be explicit, v0.1.0 does **not** provide: TLS/ACME certificates, PHP-FPM or any application runtime (Nginx serves static files only), DNS, mail, databases, FTP/SFTP/SSH access for tenants, disk quotas, backups, per-vhost access logs, update RPCs (`UpdateTenantLimits`, owner transfer), reconciliation of records against the OS, a confined SELinux domain for the daemon itself, per-peer API scopes, or metrics. These are on the roadmap in `oxpanel-daemon/PROJECT_DETAILS.md`.
