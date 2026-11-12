# oxpanel-daemon

The open-source system engine of OxPanel: a root-privileged daemon for
AlmaLinux 9 that provisions isolated hosting tenants and manages Nginx
virtual hosts, exposed over gRPC on a UNIX socket authenticated by kernel peer
credentials.

For operators: [feature list](../docs/FEATURES.md) and the [handbook](../docs/HANDBOOK.md) (installation, configuration, access control, CLI, API, troubleshooting).

## What it does

| RPC | Effect on the system |
|---|---|
| `CreateTenant` | `useradd` (dedicated uid/gid from a reserved range, `/sbin/nologin`, home `0700`), a systemd slice `oxpanel-tenant-<name>.slice` carrying `MemoryMax`/`CPUWeight`/`IOWeight`/`TasksMax`, a `user-<uid>.slice.d` drop-in for login sessions, `restorecon` on SELinux hosts. Accepts an opaque `owner` label (e.g. a reseller id) that the engine stores and filters on but never interprets |
| `GetTenant` / `ListTenants` | read the daemon's records; `ListTenants` can filter by `owner` |
| `DeleteTenant` | `userdel [--remove]`, unit cleanup — refused while the tenant owns virtual hosts, and always refused for accounts OxPanel did not create |
| `ConfigureVirtualHost` | document root created *as the tenant*; POSIX ACLs (`--physical`) grant the web user traverse + read; on SELinux hosts a persistent `semanage fcontext` rule + `restorecon`; server block written atomically, validated with `nginx -t`, activated with `systemctl reload-or-restart nginx`, rolled back on failure. On first use the daemon also installs a catch-all `default_server` (`return 444`) so unknown host names and bare-IP requests never land on a tenant |
| `RemoveVirtualHost` / `ListVirtualHosts` | inverse / read |

Every mutation is idempotent and resumable (records carry a state), and the
daemon never touches an account, unit or config file it has no record for.

## Security model

- **Transport:** UNIX socket only (`/run/oxpanel/oxpanel.sock`, `root:oxpanel 0660`). No TCP, ever.
- **Authentication:** `SO_PEERCRED`. A connection is accepted only if the peer uid is allow-listed, or its effective/supplementary gid is (the `oxpanel` group by default), or it is root. Unauthorised peers are closed *before* any HTTP/2 byte is parsed. Every request additionally fails closed if peer info is missing.
- **Input:** allow-list validation of every field (`validate.rs`): user names `^[a-z][a-z0-9_-]{2,31}$` minus a reserved list, ASCII A-label domains, relative document roots with no `..`/metacharacters, bounded limits. Invalid input never reaches the OS.
- **Execution:** no shell anywhere. Every external program is an absolute path with an argv array (`system/`). Anything run on a tenant's behalf goes through `setpriv --reuid --regid --clear-groups --bounding-set=-all --inh-caps=-all --no-new-privs`.
- **Ownership:** the daemon only modifies what its own records say it created. The record is written *before* `useradd`, so a crash can never leave an account the daemon refuses to recognise; interrupted work resumes on the next identical request.
- **Tenant isolation in systemd:** `-` is a hierarchy separator in slice names, so tenant names are escaped (`foo-bar` → `oxpanel-tenant-foo\x2dbar.slice`); no tenant's slice is ever a child of another's. Verified with `systemctl show -p Slice` on the real OS.
- **Web user sanity:** `OXPANEL_WEB_USER` (the account that receives ACL grants on every document root) must exist, must not be root, and must not be inside the tenant uid range — checked at startup.
- **Files:** atomic writes (`tempfile` + `rename` + `fsync`), explicit modes, symlink refusal.
- **Symlink attacks:** ACLs are set with `--physical`, the document root must be a real directory owned by the tenant, and the server block carries `disable_symlinks if_not_owner`. Verified on the real OS: a tenant symlink to `/etc/shadow` is answered with 404.
- **No accidental default site:** the include stanza carries a `default_server` that closes the connection (`return 444`), validated with `nginx -t` at startup and rolled back if the host already defines one (`OXPANEL_NGINX_DEFAULT_SERVER=false` to opt out).
- **Errors:** client-caused failures return precise gRPC codes; internal failures are redacted to the client and logged to the journal.
- **Process:** `#![forbid(unsafe_code)]`, clippy pedantic with `unwrap`/`expect`/`panic` denied in production paths, `cargo-deny` for advisories/licences/bans.
- **Deployment:** the systemd unit (`packaging/systemd/`) runs as root but with `ProtectSystem=strict`, `PrivateNetwork`, `IPAddressDeny=any`, `NoNewPrivileges`, a capability deny-list, a seccomp allow-list and more. Verified end-to-end by `make integration`.

Known limits (v1): the daemon runs unconfined under SELinux (as `unconfined_service_t`)
— a confined `oxpanel_t` domain is roadmap; the capability set is a deny-list,
not yet an allow-list; per-tenant PHP-FPM pools / TLS are not implemented.

## Layout

```
proto/oxpanel/v1/panel.proto   API contract (shared with the Go panel)
oxpanel-proto/                 codegen crate (protox + tonic-prost-build; no protoc needed)
oxpanel-daemon/src/
  main.rs       CLI, preflight, socket setup (umask-safe bind, chown), server lifecycle, sd_notify
  config.rs     OXPANEL_* environment -> Config
  validate.rs   Username / Domain / RelPath / Limits newtypes
  auth.rs       PeerPolicy, SO_PEERCRED gate, AuthedStream
  server.rs     gRPC <-> workflows
  tenant.rs     CreateTenant / Get / List / Delete
  vhost.rs      ConfigureVirtualHost / Remove / List
  nginx.rs      server-block rendering, test -> reload -> rollback
  systemd.rs    slice units and drop-ins
  records.rs    /var/lib/oxpanel state (what we own)
  fsutil.rs     atomic writes, dir creation, symlink checks
  system/       the only module that execs or looks up accounts: RealSystem, FakeSystem
oxpanel-daemon/tests/grpc_uds.rs   real server + real client over a UNIX socket, fake OS
oxpanel-ctl/                   admin CLI
packaging/                     systemd unit, env file, sysusers, tmpfiles, RPM spec
tests-integration/             AlmaLinux 9 image + in-container assertions
scripts/                       dev.sh (run cargo in the image), integration-test.sh
```

## Build & test

```sh
make image          # build localhost/oxpanel-dev:alma9 (rustup 1.98.1, gcc, nginx, systemd, cargo-deny)
make test           # 80 unit tests + 6 gRPC end-to-end tests (fake OS, no root)
make clippy         # pedantic, warnings are errors
make deny           # RustSec advisories, licences, banned crates
make integration    # boots systemd in the container, installs from packaging/, drives the
                    # daemon with oxpanel-ctl and asserts on accounts, ACLs, nginx responses
make rpm            # RPM from the working tree → dist/rpms/
make acceptance     # real AlmaLinux 9 VM under KVM, SELinux enforcing: install from git like a
                    # user (or INSTALL=rpm), then SELinux / sandbox / restart / reboot / soak phases
```

What `make integration` proves on AlmaLinux 9 (all 79 assertions must pass): the daemon starts
through its hardened unit (`Type=notify`), socket is `root:oxpanel 0660`, real `useradd` with a
`0700` home and locked password, systemd loads the tenant slice and reports `MemoryMax`, replays
are idempotent, foreign accounts are never adopted, the document root is tenant-owned with the
ACL model (`group::---`, `other::---`, another account cannot traverse), Nginx serves the tenant's
page and its alias, dot-files and tenant symlinks to `/etc/shadow` are 404, unknown hosts and the
bare IP get the connection closed, an unauthorised tenant peer is refused while a service account
in the `oxpanel` group is served (and faked process groups are not), teardown removes everything,
and the journal has no errors. The RPM spec is also built and test-installed in the same image.

## Verification status (honest ledger)

| Claim | How it is verified |
|---|---|
| Input validation, argv construction, idempotency, rollback, redaction | unit tests with `FakeSystem` asserting exact argv vectors |
| Peer-credential gate, fail-closed interceptor, gRPC codes | `tests/grpc_uds.rs` over a real UNIX socket |
| Real `useradd`/`userdel`, home modes, ACL model, slice loading and limits, Nginx serving/refusing, catch-all default server, group-based peer auth, hardened unit starts and runs the daemon | `make integration` in a systemd container of the target OS |
| RPM spec builds, installs, creates the `oxpanel` group and config dir | built and test-installed in the same image |
| Dependency advisories / licences / bans | `cargo deny check` |
| `PrivateNetwork=`, `ProtectHostname=` in the unit | **not** verifiable in a rootless container (systemd reports "ignoring"); needs a real host |
| SELinux paths (`semanage fcontext`, `restorecon`), and whether the unit's seccomp/`MemoryDenyWriteExecute` lets `semanage` (Python) run | **not** verified — the container has no SELinux; test on a real AlmaLinux 9 host before shipping |
| Independent adversarial review | the multi-agent audit was blocked by an account spend limit; an inline review found and fixed the slice-hierarchy, orphan-account and web-user issues. The real-host rig then found five more (SELinux mount-on, `/var/log/nginx`, homedir labelling, ACL-mask repair, CLI `EPIPE`) — see `docs/superpowers/specs/2026-09-22-acceptance-rig-design.md` |

**Reload semantics:** `ConfigureVirtualHost` returns after `nginx -t` succeeded and the reload was
requested; Nginx swaps workers asynchronously, so a request in the following few milliseconds may
still hit an old worker. Clients that need a confirmed switch should poll the site.

`scripts/dev.sh <cmd>` runs any command inside the image with the source
mounted and cargo caches in named volumes.

## Run

Production is via the RPM / systemd unit. For development without root:

```sh
export OXPANEL_DRY_RUN=1 OXPANEL_STATE_DIR=$PWD/tmp/state OXPANEL_HOME_BASE=$PWD/tmp/home \
       OXPANEL_SYSTEMD_UNIT_DIR=$PWD/tmp/systemd OXPANEL_NGINX_CONF_DIR=$PWD/tmp/nginx/oxpanel.d \
       OXPANEL_NGINX_INCLUDE_FILE=$PWD/tmp/nginx/conf.d/00-oxpanel.conf \
       OXPANEL_SOCKET_PATH=$PWD/tmp/oxpanel.sock OXPANEL_SOCKET_GROUP=
oxpanel-daemon --dry-run &
oxpanel-ctl --socket $PWD/tmp/oxpanel.sock tenant create alice --memory 512M
```

Configuration reference: [`packaging/daemon.env`](../packaging/daemon.env).
