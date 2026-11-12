# OxPanel engine handbook

Installation, configuration and operation of `oxpanel-daemon` v0.1.0 on
AlmaLinux 9. Every command in this handbook has been run as written; where a
step is only verifiable on a real host (SELinux, `PrivateNetwork`) that is said.

Contents

1. [How it fits together](#1-how-it-fits-together)
2. [Requirements](#2-requirements)
3. [Installation](#3-installation)
4. [Configuration](#4-configuration)
5. [Access control](#5-access-control)
6. [Using `oxpanel-ctl`](#6-using-oxpanel-ctl)
7. [Using the gRPC API from the panel](#7-using-the-grpc-api-from-the-panel)
8. [What the engine puts on disk](#8-what-the-engine-puts-on-disk)
9. [Day-2 operations](#9-day-2-operations)
10. [Troubleshooting](#10-troubleshooting)
11. [Development and testing](#11-development-and-testing)
12. [Upgrading and uninstalling](#12-upgrading-and-uninstalling)
13. [Security notes for operators](#13-security-notes-for-operators)

---

## 1. How it fits together

```
 panel-api (Go, proprietary)        oxpanel-ctl (admin CLI)
   runs as a member of group           runs as root or a member
   `oxpanel`                           of group `oxpanel`
            └──────────────┬──────────────┘
                           │ gRPC over /run/oxpanel/oxpanel.sock
                           │ peer identity = SO_PEERCRED
                 ┌─────────▼──────────┐
                 │   oxpanel-daemon   │  root, hardened systemd unit
                 └──┬───────┬───────┬─┘
      useradd/ACLs  │       │ units │  nginx -t / reload
                    ▼       ▼       ▼
             /home/<t>   systemd   /etc/nginx/oxpanel.d/<domain>.conf
             0700        slices    /etc/nginx/conf.d/00-oxpanel.conf
```

The engine owns three things and nothing else: tenant accounts (plus their
homes and systemd slices), the files in `/etc/nginx/oxpanel.d/` (plus one
include file in `conf.d`), and its own records in `/var/lib/oxpanel/`. It will
not touch an account, unit or Nginx file it has no record for.

## 2. Requirements

| | |
|---|---|
| OS | AlmaLinux 9 (RHEL 9 family). Other systemd + Nginx distributions are untested. |
| Init | systemd (cgroups v2, the default on EL9). |
| Web server | `nginx` from AppStream, with the stock `/etc/nginx/nginx.conf` (it must `include /etc/nginx/conf.d/*.conf;`, which the stock file does). |
| Tools | `shadow-utils` (useradd/userdel), `util-linux` (setpriv), `acl` (setfacl), `coreutils` (mkdir, du), `policycoreutils` (restorecon); on SELinux-enabled hosts also `policycoreutils-python-utils` (semanage) and `libselinux-utils` (selinuxenabled). The RPM pulls all of these in. |
| SELinux | Enforcing is supported and is the target; the daemon detects it at start-up and labels tenant content accordingly. The booleans `httpd_enable_homedirs` and `httpd_read_user_content` must be on (the RPM sets them; the source install block sets them), because document roots live under tenant homes. |
| Network | None. The API is a local UNIX socket; the daemon has no network access at all under its unit. |
| Ports | Nginx on 80 (v0.1.0 does not manage TLS). |

## 3. Installation

### 3.1 From the RPM (recommended)

Build the package once on any AlmaLinux 9 machine (or in the project's
container image) and install it on the hosting nodes.

**Build the RPM**

```sh
# build host: AlmaLinux 9 with a Rust toolchain
sudo dnf install -y rpm-build systemd-rpm-macros gcc git
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal   # toolchain pinned by rust-toolchain.toml
source ~/.cargo/env

git clone https://github.com/OxServers/oxpanel.git && cd oxpanel
mkdir -p ~/rpmbuild/{SOURCES,SPECS}
git archive --prefix=oxpanel-0.1.0/ -o ~/rpmbuild/SOURCES/oxpanel-daemon-0.1.0.tar.gz HEAD
cp packaging/oxpanel-daemon.spec ~/rpmbuild/SPECS/
rpmbuild -bb ~/rpmbuild/SPECS/oxpanel-daemon.spec
ls ~/rpmbuild/RPMS/x86_64/          # oxpanel-daemon-0.1.0-1.el9.x86_64.rpm (+ debuginfo)
```

**Install on a hosting node**

```sh
sudo dnf install ./oxpanel-daemon-0.1.0-1.el9.x86_64.rpm   # pulls nginx, acl, policycoreutils-python-utils, …
sudo systemctl enable --now nginx
sudo systemctl enable --now oxpanel-daemon
```

The package installs:

| Path | Purpose |
|---|---|
| `/usr/sbin/oxpanel-daemon` | the engine |
| `/usr/bin/oxpanel-ctl` | admin CLI |
| `/usr/lib/systemd/system/oxpanel-daemon.service` | hardened unit |
| `/usr/lib/sysusers.d/oxpanel.conf` | creates the `oxpanel` group |
| `/usr/lib/tmpfiles.d/oxpanel.conf` | `/etc/oxpanel` (`root:oxpanel 0750`) |
| `/etc/oxpanel/daemon.env` | configuration (`%config(noreplace)`, `0640`) |

### 3.2 From source, on the target host

```sh
sudo dnf install -y gcc git nginx shadow-utils util-linux acl policycoreutils policycoreutils-python-utils libselinux-utils logrotate php-fpm nodejs npm
# SELinux: sites live under tenant homes, so the web server must be allowed to traverse and read them.
if sudo selinuxenabled; then sudo setsebool -P httpd_enable_homedirs=on httpd_read_user_content=on httpd_unified=on; fi
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal && source ~/.cargo/env

git clone https://github.com/OxServers/oxpanel.git && cd oxpanel
cargo build --release --locked -p oxpanel-daemon -p oxpanel-ctl

sudo install -m0755 target/release/oxpanel-daemon /usr/sbin/oxpanel-daemon
sudo install -m0755 target/release/oxpanel-ctl    /usr/bin/oxpanel-ctl
sudo install -Dm0644 packaging/systemd/oxpanel-daemon.service /etc/systemd/system/oxpanel-daemon.service
sudo install -Dm0644 packaging/sysusers.d/oxpanel.conf        /usr/lib/sysusers.d/oxpanel.conf
sudo install -Dm0644 packaging/tmpfiles.d/oxpanel.conf        /usr/lib/tmpfiles.d/oxpanel.conf
sudo install -Dm0640 packaging/daemon.env                     /etc/oxpanel/daemon.env
sudo install -Dm0644 packaging/logrotate.d/oxpanel            /etc/logrotate.d/oxpanel
sudo install -Dm0644 packaging/selinux/oxpanel.cil            /usr/share/oxpanel/selinux/oxpanel.cil
# SELinux: the domain tenant applications (Node.js, Python) run in.
if sudo selinuxenabled; then sudo semodule -i /usr/share/oxpanel/selinux/oxpanel.cil; fi
sudo systemd-sysusers && sudo systemd-tmpfiles --create oxpanel.conf
sudo systemctl daemon-reload
sudo systemctl enable --now nginx oxpanel-daemon
```

This is exactly the sequence the integration test performs
(`tests-integration/run-inside.sh`).

### 3.3 Building without a toolchain on the workstation

The repository ships a container image of the target OS. On any machine with
podman:

```sh
make image      # builds localhost/oxpanel-dev:alma9 (rustup, gcc, nginx, systemd, cargo-deny)
make release    # cargo build --release inside the image
```

The binaries land in the named volume `oxpanel-target`; copy them out with

```sh
podman run --rm --security-opt label=disable -v oxpanel-target:/t:ro -v "$PWD:/out" \
  localhost/oxpanel-dev:alma9 cp /t/release/oxpanel-daemon /t/release/oxpanel-ctl /out/
```

They are built against AlmaLinux 9's glibc and run on any AlmaLinux 9 host.

### 3.4 Verify the installation

```sh
sudo oxpanel-daemon --check-config          # validates config + host prerequisites, exits 0
systemctl status oxpanel-daemon             # active (running), "listening socket=/run/oxpanel/oxpanel.sock"
ls -l /run/oxpanel/oxpanel.sock             # srw-rw---- root oxpanel
sudo oxpanel-ctl tenant list                # empty on a fresh host, exit 0
journalctl -u oxpanel-daemon -n 20          # "preflight selinux=true|false", "listening"
```

## 4. Configuration

All configuration is read from the environment at start-up; the unit loads
`/etc/oxpanel/daemon.env`. Every value has a default, so an empty file is
valid. After editing: `sudo systemctl restart oxpanel-daemon`.

| Variable | Default | Meaning |
|---|---|---|
| `OXPANEL_SOCKET_PATH` | `/run/oxpanel/oxpanel.sock` | Listening socket. Its directory is created by systemd (`RuntimeDirectory=oxpanel`). |
| `OXPANEL_SOCKET_GROUP` | `oxpanel` | Group owning the socket (mode `0660`) and implicitly allowed to call the API. Empty = socket is root-only (`0600`). Must exist. |
| `OXPANEL_ALLOWED_UIDS` | *(empty)* | Comma-separated numeric uids allowed to call the API. |
| `OXPANEL_ALLOWED_GIDS` | *(empty)* | Comma-separated numeric gids allowed (primary or supplementary group of the peer's account). The socket group is always included. |
| `OXPANEL_ALLOW_ROOT_PEER` | `true` | Whether uid 0 may call the API regardless of the lists. |
| `OXPANEL_PEER_SCOPES` | *(empty)* | Confine peers to parts of the API: `uid:scope+scope,uid:scope`. Scopes: `read`, `vhost`, `tenant`, `delete`, `all`. See §5. |
| `OXPANEL_UID_MIN` / `OXPANEL_UID_MAX` | `20000` / `29999` | Inclusive uid range for tenants (lowest free id is used). `UID_MIN` must be ≥ 1000. |
| `OXPANEL_HOME_BASE` | `/home` | Tenant homes are `<base>/<username>`. |
| `OXPANEL_STATE_DIR` | `/var/lib/oxpanel` | Records. Created by systemd (`StateDirectory=oxpanel`, `0700`). |
| `OXPANEL_NGINX_CONF_DIR` | `/etc/nginx/oxpanel.d` | One `<domain>.conf` per virtual host. |
| `OXPANEL_NGINX_INCLUDE_FILE` | `/etc/nginx/conf.d/00-oxpanel.conf` | Include stanza (+ catch-all server). Must not be inside the conf dir. |
| `OXPANEL_NGINX_DEFAULT_SERVER` | `true` | Install the catch-all `default_server` (`return 444`). Set `false` only if the host already defines its own default server. |
| `OXPANEL_SYSTEMD_UNIT_DIR` | `/etc/systemd/system` | Where tenant slice units and drop-ins are written. |
| `OXPANEL_NGINX_LOG_DIR` | `/var/log/nginx/oxpanel` | Per-site `<domain>.access.log` / `<domain>.error.log`. If you change it, change `/etc/logrotate.d/oxpanel` too. |
| `OXPANEL_PHP_CONF_DIR` | `/etc/oxpanel-php` | One PHP-FPM configuration per tenant that uses PHP. World-readable (each tenant's FPM reads its own); holds no secrets. |
| `OXPANEL_WEB_USER` | `nginx` | Account the web-server workers run as; receives ACL grants on document roots. Must exist, must not be root, must not be inside the tenant uid range. |
| `OXPANEL_COMMAND_TIMEOUT_SECS` | `60` | Upper bound for any single external command (`useradd`, `nginx -t`, …). |
| `OXPANEL_LOG` | `info` | `tracing` filter: `info`, `debug`, `oxpanel_daemon=trace`, … |
| `OXPANEL_DRY_RUN` | `false` | Use the in-memory fake OS (development only — see §11). |

Rules enforced at start-up (`--check-config` reports them):

- every path must be absolute, below `/`, without `.`/`..` components, and use
  only `A-Z a-z 0-9 / . _ -` (paths are interpolated into Nginx directives and
  SELinux regular expressions);
- `OXPANEL_NGINX_INCLUDE_FILE` may not live inside `OXPANEL_NGINX_CONF_DIR`;
- `OXPANEL_UID_MIN` ≥ 1000 and ≤ `OXPANEL_UID_MAX`.

Example `/etc/oxpanel/daemon.env` for a node whose panel API runs as user
`panelapi` and whose homes live on a dedicated volume:

```sh
OXPANEL_HOME_BASE=/srv/homes
OXPANEL_UID_MIN=30000
OXPANEL_UID_MAX=39999
OXPANEL_LOG=info
# panelapi is in group oxpanel; nothing else needed for access.
```

## 5. Access control

Who may call the API is decided by the **kernel-reported identity of the
connecting process** (`SO_PEERCRED`), checked against:

1. uid 0, if `OXPANEL_ALLOW_ROOT_PEER=true` (default);
2. `OXPANEL_ALLOWED_UIDS`;
3. the peer's effective gid, or any group of the peer's **account** in the
   account database, matching `OXPANEL_ALLOWED_GIDS` or the socket group.

Point 3 means membership is decided by `/etc/group` (or SSSD), not by the
groups a process happens to carry. A process that merely set supplementary
group `oxpanel` on itself is refused; an account that is a member of `oxpanel`
is accepted even from a process that dropped the group.

**Set up the panel's service account**

```sh
sudo useradd -r -G oxpanel -s /sbin/nologin panelapi
# run the Go panel-api as `panelapi`; it can now open /run/oxpanel/oxpanel.sock
```

**Give an administrator the CLI**

```sh
sudo usermod -aG oxpanel alice     # alice re-logs in, then: oxpanel-ctl tenant list
```

Unauthorised connections are closed before any protocol data is read and are
logged as `rejected connection reason="uid=… gid=… is not in the allow-list"`.

Tenants themselves must never be in the `oxpanel` group.

**Confining a peer to part of the API (scopes)**

Authentication decides *who* may connect; `OXPANEL_PEER_SCOPES` decides *what*
a connected peer may call. A uid that is listed may call only the RPCs in its
scopes; a uid that is not listed (including root) may call everything.

| Scope | RPCs |
|---|---|
| `read` | `GetTenant`, `ListTenants`, `ListVirtualHosts`, `GetTenantUsage`, `GetHostInfo`, `Reconcile` |
| `vhost` | `ConfigureVirtualHost`, `RemoveVirtualHost` |
| `tenant` | `CreateTenant`, `UpdateTenantLimits`, `UpdateTenantOwner`, `SuspendTenant`, `ResumeTenant` |
| `delete` | `DeleteTenant` |

```sh
# The customer-facing tier runs as its own account and can never create,
# resize, suspend or delete a tenant, even if it is fully compromised.
sudo useradd -r -G oxpanel -s /sbin/nologin panelweb
echo "OXPANEL_PEER_SCOPES=$(id -u panelweb):read+vhost" | sudo tee -a /etc/oxpanel/daemon.env
sudo systemctl restart oxpanel-daemon
```

A refused call returns `PERMISSION_DENIED` ("this peer is not permitted to call
DeleteTenant (scope 'delete' required)") and is logged with the peer's uid and
pid. It is refused before input validation and before anything touches the OS.
Scopes limit RPC classes, not objects: which tenant a customer may touch is
still the panel API's decision.

## 6. Using `oxpanel-ctl`

```
oxpanel-ctl [--socket PATH] <command>        # --socket defaults to $OXPANEL_SOCKET_PATH or /run/oxpanel/oxpanel.sock

tenant create <username> [--owner LABEL] [--memory SIZE] [--cpu-weight N] [--io-weight N] [--tasks-max N]
tenant get    <username>
tenant list   [--owner LABEL]
tenant set-limits <username> [--memory SIZE] [--cpu-weight N] [--io-weight N] [--tasks-max N]
tenant set-owner  <username> <LABEL|''>
tenant suspend <username>
tenant resume  <username>
tenant usage   <username>
tenant delete <username> [--remove-home]

host info
host reconcile

vhost set     <domain> --tenant <username> [--root RELATIVE_PATH] [--alias DOMAIN]... [--php]
              [--app node|python [--app-root RELATIVE_PATH] [--app-entry FILE]]
vhost log     <domain> [--error | --app] [--bytes SIZE]
vhost restart-app  <domain>
vhost install-deps <domain>
vhost remove  <domain>
vhost list    [--tenant <username>]
```

Sizes accept `k`, `m`, `g`, `t` suffixes (binary units) or plain bytes.
Exit status: `0` success, `1` API error (message on stderr, e.g.
`error: FailedPrecondition: nginx rejected the configuration: …`), `2` usage,
`3` when `host reconcile` found differences, `4` when `vhost install-deps` ran
and the installer failed.

**Examples**

```sh
# A tenant with 512 MiB, a quarter of a CPU's weight and at most 200 tasks
sudo oxpanel-ctl tenant create acme --owner reseller-north --memory 512M --cpu-weight 25 --tasks-max 200
# created=true
# tenant=acme owner=reseller-north uid=20000 gid=20000 home=/home/acme state=TENANT_STATE_READY slice=oxpanel-tenant-acme.slice memory_max=536870912 cpu_weight=25 io_weight=0 tasks_max=200 created_at=1788600162

# Running it again is a no-op
sudo oxpanel-ctl tenant create acme --owner reseller-north --memory 512M --cpu-weight 25 --tasks-max 200
# created=false ...

# A site with an alias; the document root /home/acme/public_html is created for the tenant
sudo oxpanel-ctl vhost set acme.example --tenant acme --alias www.acme.example
# changed=true
# domain=acme.example tenant=acme document_root=public_html aliases=www.acme.example config=/etc/nginx/oxpanel.d/acme.example.conf

# A second site in a sub-directory
sudo oxpanel-ctl vhost set shop.acme.example --tenant acme --root sites/shop

# Everything a reseller owns
sudo oxpanel-ctl tenant list --owner reseller-north

# Resize: set-limits replaces ALL limits, so repeat the ones you want to keep
sudo oxpanel-ctl tenant set-limits acme --memory 1G --cpu-weight 25 --tasks-max 200
# changed=true ...

# Non-payment: every site of the tenant answers 503 until resumed; files are untouched
sudo oxpanel-ctl tenant suspend acme
sudo oxpanel-ctl tenant resume acme

# Move the customer to another reseller
sudo oxpanel-ctl tenant set-owner acme reseller-south

# What is it using right now?
sudo oxpanel-ctl tenant usage acme
# tenant=acme memory_current=0 cpu_usage_nsec=0 tasks_current=0 disk_usage=28672 measured_at=1794571200

# The host, and whether the records still match it
sudo oxpanel-ctl host info
sudo oxpanel-ctl host reconcile        # drifts=0

# A PHP site: the tenant gets its own PHP-FPM, running as the tenant inside its limits
sudo oxpanel-ctl vhost set blog.acme.example --tenant acme --root blog --php
systemctl status oxpanel-php-acme.service
# Switch PHP off again (the pool is removed when no site of the tenant uses it)
sudo oxpanel-ctl vhost set blog.acme.example --tenant acme --root blog

# A Node.js application. It must listen on the socket path it gets in PORT:
#   require('http').createServer(handler).listen(process.env.PORT)
sudo oxpanel-ctl vhost set app.acme.example --tenant acme --app node
#   code goes to /home/acme/apps/app.acme.example/ (entry: app.js), as the tenant
sudo oxpanel-ctl vhost install-deps app.acme.example      # npm install --omit=dev, as the tenant
sudo oxpanel-ctl vhost restart-app  app.acme.example      # after putting new code in place
sudo oxpanel-ctl vhost log app.acme.example --app         # what the application printed

# A Python application in its own virtualenv; static files from apps/api/public
sudo oxpanel-ctl vhost set api.acme.example --tenant acme --app python \
     --app-root apps/api --app-entry main.py --root apps/api/public
sudo oxpanel-ctl vhost install-deps api.acme.example      # pip install -r requirements.txt

# The end of a site's access log, or its error log
sudo oxpanel-ctl vhost log acme.example
sudo oxpanel-ctl vhost log acme.example --error --bytes 64K

# Tear down (order matters: vhosts first)
sudo oxpanel-ctl vhost remove shop.acme.example
sudo oxpanel-ctl vhost remove acme.example
sudo oxpanel-ctl tenant delete acme --remove-home
```

Limits: `--memory` is `0` (unlimited) or ≥ 16 MiB; `--cpu-weight` and
`--io-weight` are `0` (systemd default, 100) or 1–10000; `--tasks-max` is `0`
(default) or ≥ 1. Names: user names `^[a-z][a-z0-9_-]{2,31}$` (reserved system
names refused); domains lower-case ASCII labels (punycode `xn--` allowed, no
wildcards, no IP literals); `--root` is relative, with components made of
`A-Z a-z 0-9 . _ -` only; `--owner` is `^[a-z0-9][a-z0-9_.-]{0,63}$`.

**Uploading content:** tenants have no login in v0.1.0. Put files in place as
the tenant so ownership stays correct, e.g.
`sudo setpriv --reuid=acme --regid=acme --clear-groups -- cp -r site/. /home/acme/public_html/`.
Files inherit the default ACL, so Nginx can read them without further steps.

## 7. Using the gRPC API from the panel

The contract is `proto/oxpanel/v1/panel.proto` (package `oxpanel.v1`, service
`OxPanelEngine`). Generate a Go client with the standard tooling:

```sh
protoc -I proto --go_out=. --go-grpc_out=. proto/oxpanel/v1/panel.proto
```

Connect over the socket (no TLS; identity is the process's uid/gid):

```go
conn, err := grpc.NewClient("unix:///run/oxpanel/oxpanel.sock",
    grpc.WithTransportCredentials(insecure.NewCredentials()))
client := oxpanelv1.NewOxPanelEngineClient(conn)

resp, err := client.CreateTenant(ctx, &oxpanelv1.CreateTenantRequest{
    Username: "acme", Owner: "reseller-north",
    Limits: &oxpanelv1.ResourceLimits{MemoryMaxBytes: 512 << 20, CpuWeight: 25},
})
```

**Semantics to build on**

| RPC | Idempotency | Notable errors |
|---|---|---|
| `CreateTenant` | identical spec → `created=false`; different spec → `ALREADY_EXISTS`; interrupted → resumed | `INVALID_ARGUMENT` (validation), `FAILED_PRECONDITION` (name belongs to an unmanaged account, or tenant is being deleted), `RESOURCE_EXHAUSTED` (uid range full) |
| `GetTenant` / `ListTenants` | read-only | `NOT_FOUND` |
| `DeleteTenant` | `deleted=false` if absent | `FAILED_PRECONDITION` (still owns virtual hosts, or unmanaged account) |
| `ConfigureVirtualHost` | identical config → `created=false` | `NOT_FOUND` (tenant), `FAILED_PRECONDITION` (name owned by another tenant; tenant not ready; `php=true` but PHP is not installed; **`nginx -t` rejected the result — message contains the nginx output**) |
| `RemoveVirtualHost` | `removed=false` if absent | `FAILED_PRECONDITION` (config invalid after removal — operator attention) |
| `UpdateTenantLimits` | same limits → `changed=false` (unit files are still re-applied, completing an interrupted attempt) | `NOT_FOUND`, `FAILED_PRECONDITION` (tenant not ready), `INVALID_ARGUMENT`. The limits are a full replacement, not a patch |
| `UpdateTenantOwner` | same owner → `changed=false` | `NOT_FOUND`, `FAILED_PRECONDITION`, `INVALID_ARGUMENT` |
| `SuspendTenant` / `ResumeTenant` | already in that state → `changed=false` | `NOT_FOUND`, `FAILED_PRECONDITION` (tenant not ready; `nginx -t` rejected — all files restored, state unchanged) |
| `GetTenantUsage` / `GetHostInfo` | read-only measurements | `NOT_FOUND`; usage runs `du` on the home, so cache it in the panel rather than polling per page view |
| `RestartApp` | restarts every time | `NOT_FOUND`, `FAILED_PRECONDITION` (the site runs no application; tenant suspended) |
| `InstallAppDependencies` | re-runs the installer; **not** under the mutation lock (it can take minutes), other RPCs proceed meanwhile | returns `succeeded=false` plus the installer output when npm/pip fails — show it to the site owner. `FAILED_PRECONDITION` as for `RestartApp`. Allow up to 5 minutes |
| `ReadVirtualHostLog` | read-only; at most 128 KiB of whole lines from the end of the current file | `NOT_FOUND` (no such site). Log lines contain visitor IP addresses: show a site's log only to its owner |
| `Reconcile` | read-only; waits for the mutation lock | — (an empty `drifts` list means records and OS agree) |
| any | | `PERMISSION_DENIED` (peer not allowed, or its scopes do not cover the RPC — §5), `DEADLINE_EXCEEDED` (a system command hit `OXPANEL_COMMAND_TIMEOUT_SECS`), `INTERNAL` (redacted; see the journal) |

Guidance for the three panels (root / reseller / customer): the engine is
role-agnostic and authorises the *panel process*, not end users. Enforce in the
panel that a customer only reaches `ConfigureVirtualHost`/`RemoveVirtualHost`
for their own tenant, and a reseller only tenants carrying their `owner`
label; do not forward raw `nginx -t` text to customers.

**Reload timing:** `ConfigureVirtualHost` returns after `nginx -t` succeeded
and the reload was *requested*. Nginx replaces workers asynchronously, so a
request in the next few milliseconds may still hit an old worker. If the panel
needs to confirm a site is live, poll it.

## 8. What the engine puts on disk

| Path | Owner / mode | Content |
|---|---|---|
| `/var/lib/oxpanel/tenants/<username>.json` | `root 0600` | tenant record: uid, gid, home, limits, slice unit, owner, `state` (`provisioning` / `ready` / `deleting`), created time |
| `/var/lib/oxpanel/vhosts/<domain>.json` | `root 0600` | vhost record: tenant, document root, aliases, config path |
| `/home/<username>` | `<t>:<t> 0700` + ACL `user:nginx:--x` | tenant home (`stat` shows `0710` because the ACL mask occupies the group bits; the real group/other entries are `---`) |
| `/home/<username>/<document_root>` | `<t>:<t>` + ACL `user:nginx:r-x`, default ACL | web content |
| `/etc/systemd/system/oxpanel-tenant-<name>.slice` | `root 0644` | tenant slice with limits (`-` in names escaped as `\x2d`) |
| `/etc/systemd/system/user-<uid>.slice.d/50-oxpanel.conf` | `root 0644` | the same limits for login sessions |
| `/etc/nginx/conf.d/00-oxpanel.conf` | `root 0644` | `include /etc/nginx/oxpanel.d/*.conf;` + catch-all default server |
| `/etc/nginx/oxpanel.d/<domain>.conf` | `root 0644` | the server block |
| `/var/log/nginx/oxpanel/<domain>.{access,error}.log` | directory `root 0750` | per-site logs; rotated by `/etc/logrotate.d/oxpanel`, removed with the site |
| `/etc/oxpanel-php/<username>.conf` | `root 0644` | PHP-FPM configuration of a tenant with a PHP-enabled site |
| `/etc/systemd/system/oxpanel-php-<name>.service` | `root 0644` | that tenant's PHP-FPM unit (`User=<tenant>`, in the tenant slice) |
| `/run/oxpanel-php/<username>/php.sock` | `<t>:<t>` + ACL `user:nginx:rw-` | socket Nginx passes PHP requests to |
| `/home/<username>/<app root>` | `<t>:<t>`, no web-server ACL | application code (default `apps/<domain>`); Python apps also `.venv/` |
| `/etc/systemd/system/oxpanel-app-<domain>.service` | `root 0644` | the application's unit (`User=<tenant>`, in the tenant slice) |
| `/run/oxpanel-app/<domain>/app.sock` | directory `<t>:<t> 0750` + ACL `user:nginx:--x` | socket Nginx proxies to; created by the application |
| `/usr/share/oxpanel/selinux/oxpanel.cil` | `root 0644` | SELinux module: the `oxpanel_app_t` domain and the socket-directory label |
| `/run/oxpanel/oxpanel.sock` | `root:oxpanel 0660` | API socket |
| SELinux hosts | | `semanage fcontext` equivalence `<docroot> = /usr/share/nginx/html` (labels the tree `httpd_sys_content_t`; a plain rule would be overridden by `file_contexts.homedirs`) |

Records are the source of truth for *what OxPanel owns*. Back up
`/var/lib/oxpanel` together with `/home` and `/etc/nginx/oxpanel.d`.

## 9. Day-2 operations

**Logs**

```sh
journalctl -u oxpanel-daemon -f                 # every request logs rpc, peer uid/pid, arguments, outcome
OXPANEL_LOG=debug                                # in daemon.env: also logs every executed command line
```

**Health**

```sh
systemctl is-active oxpanel-daemon && sudo oxpanel-ctl tenant list >/dev/null && echo OK
```

**Inspect a tenant's limits as systemd sees them**

```sh
systemctl show -p MemoryMax,CPUWeight,TasksMax oxpanel-tenant-acme.slice
```

**Adjusting limits** — `oxpanel-ctl tenant set-limits` (`UpdateTenantLimits`).
The limits given replace the old set entirely and are live as soon as the call
returns. Afterwards a `CreateTenant` replay must carry the *new* limits to be
treated as idempotent. Never edit the unit files by hand: the next change
overwrites them, and `host reconcile` reports the edit as drift.

**Suspending a tenant** — `tenant suspend` / `tenant resume`. Suspension is a
web-serving state: sites answer `503` with `Retry-After: 3600`. The account,
files and limits are unchanged, and `tenant get` shows `suspended=true`.

**PHP** — needs the `php-fpm` package (the RPM recommends it; `host info` shows
`php=true`). OxPanel uses the PHP version the host has installed; to change it,
switch the AppStream module (`dnf module switch-to php:8.3`) and restart the
pools (`systemctl restart 'oxpanel-php-*'`). Install extensions with dnf
(`php-mysqlnd`, `php-gd`, …) and restart the pools the same way. A tenant's PHP
errors go to the journal: `journalctl -u oxpanel-php-<name>`.

The `php-fpm` package also ships a *shared* pool (`php-fpm.service`, running as
`apache`) and makes Nginx start it. OxPanel never uses it — every tenant has
its own instance — so on a hosting node switch it off:
`sudo systemctl mask --now php-fpm.service`.

**Node.js and Python applications** — need `nodejs` and `npm` (the RPM
recommends them; Python 3 is part of the system); `host info` shows
`node=true python=true`. AlmaLinux 9 installs Node.js 16 by default, which is
past its end of life: pick a current stream before installing
(`sudo dnf module enable nodejs:22 && sudo dnf install nodejs npm`). After
changing the Node.js or Python version, restart the applications
(`systemctl restart 'oxpanel-app-*'`).

What an application must do: **listen on the UNIX socket path in `PORT`**
(also in `OXPANEL_SOCKET`). It cannot listen on a TCP port for visitors;
that is what keeps tenants from reaching each other's applications.

```js
// Node.js (Express: app.listen(process.env.PORT) is the same thing)
require('http').createServer((req, res) => res.end('hello')).listen(process.env.PORT);
```
```python
# Python with gunicorn installed through requirements.txt — main.py:
import os, sys
os.execv(os.path.join(sys.prefix, 'bin', 'gunicorn'),
         ['gunicorn', '--bind', 'unix:' + os.environ['PORT'], 'myapp.wsgi:application'])
```

The application runs with `NODE_ENV=production`, the application directory as
its working directory, the tenant's home as `HOME`, and a private `/tmp`. If a
site answers **502**, the application is not listening: `vhost log <domain>
--app` shows why (a crash loop stops after five quick failures;
`vhost restart-app` starts it again). Until tenants have file access
(SFTP is the next milestone), put code in place as the tenant, as for static
content.

**Checking for drift** — `oxpanel-ctl host reconcile` compares every record
with the accounts, homes, unit files and Nginx files, and prints one line per
difference (`kind=… subject=… detail=…`); exit status `3` means drift, so it
drops straight into a cron job or monitoring check. It never repairs anything.
What to do with each finding:

| Kind | Meaning | Fix |
|---|---|---|
| `TENANT_INCOMPLETE` | A create or delete was interrupted. | Repeat the same `tenant create` / `tenant delete`. |
| `TENANT_ACCOUNT_MISSING` / `_MISMATCH` | The account was removed or changed outside OxPanel. | See "Recovering a stuck tenant" below. |
| `TENANT_HOME_INVALID` | Home missing, not a directory, wrong owner, or open to others. | Restore it; `chown`/`chmod 0700`. |
| `TENANT_UNIT_DRIFT` | A slice unit or drop-in was edited or removed. | `tenant set-limits` with the recorded limits rewrites both. |
| `VHOST_CONFIG_DRIFT` | A site's Nginx file was edited or removed. | Repeat `vhost set` for the domain. |
| `VHOST_TENANT_MISSING` | A site record names a tenant without a record. | `vhost remove` the domain. |
| `PHP_POOL_DRIFT` | A tenant's PHP-FPM configuration or unit was edited or removed. | Repeat `vhost set … --php` for one of the tenant's PHP sites. |
| `APP_UNIT_DRIFT` | An application's unit was edited or removed. | Repeat `vhost set … --app …` for the site. |
| `ORPHAN_APP_UNIT` | An application unit no site accounts for. | Inspect and remove by hand. |
| `ORPHAN_PHP_POOL` | A PHP-FPM file no PHP-enabled site accounts for. | Inspect and remove by hand. |
| `ORPHAN_NGINX_CONFIG` / `ORPHAN_SLICE_UNIT` | A file in OxPanel's directories that no record accounts for. | Inspect and remove by hand; OxPanel will not touch what it did not record. |

**Recovering a stuck tenant** — a record in `provisioning` or `deleting`
resumes on the next identical `CreateTenant`/`DeleteTenant`. A record whose
account has vanished is reported as `INTERNAL` with
"record … exists but the account is gone; manual repair needed": either
recreate the account by hand (`useradd --uid <uid> …`) and re-run, or delete
the record file and clean up units/vhost files yourself.

**Corrupt record** — logged as `corrupt record skipped; repair or remove it`.
Listing continues without it; operations on that one object fail until the
file is fixed or removed.

**Changing the socket group or allowed peers** — edit `daemon.env`, restart.
Existing connections are closed on restart; the panel should reconnect.

**Restarting Nginx by hand** is safe; the daemon re-validates the whole
configuration with `nginx -t` on every change.

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `oxpanel-daemon` exits with status **78** | Configuration error — the message names the variable. Run `oxpanel-daemon --check-config`. |
| exits with **77** `must run as root` | Started outside the unit as a normal user. Use `systemctl start`, or `--dry-run` for development. |
| exits with **69** `required program … is missing` / `SELinux is enforcing but /usr/sbin/semanage is missing` | Install the listed package (`policycoreutils-python-utils` provides `semanage`). |
| `OXPANEL_SOCKET_GROUP 'oxpanel' does not exist` | `sudo systemd-sysusers` (the RPM does this), or create the group. |
| `OXPANEL_WEB_USER 'nginx' does not exist` / `is inside the tenant uid range` / `must not be root` | Install nginx, or point `OXPANEL_WEB_USER` at the real worker account. |
| exits with **78** `SELinux boolean … is off` | `sudo setsebool -P httpd_enable_homedirs=on httpd_read_user_content=on` (the RPM does this in `%post`). Without them `httpd_t` cannot traverse `/home/<tenant>` and every site returns 403. |
| PHP site works but cannot write (uploads fail, "Permission denied") | SELinux boolean `httpd_unified` is off (the daemon warns at start): `sudo setsebool -P httpd_unified on`. |
| `FailedPrecondition: PHP is not installed on this host` | `sudo dnf install php-fpm`; no daemon restart needed. |
| App site answers 502 | The application is not listening on `$PORT`: `oxpanel-ctl vhost log <domain> --app`, then `vhost restart-app`. |
| `FailedPrecondition: the OxPanel SELinux module is not installed` | `sudo semodule -i /usr/share/oxpanel/selinux/oxpanel.cil` (the RPM does this in `%post`). |
| `FailedPrecondition: Node.js (nodejs) is not installed on this host` | `sudo dnf install nodejs npm`; no daemon restart needed. |
| PHP site answers 502 | The tenant's pool is not running: `systemctl status oxpanel-php-<name>`, `journalctl -u oxpanel-php-<name>`. Usually the tenant hit its `MemoryMax`/`TasksMax`. |
| `Failed at step NAMESPACE` / `status=226/NAMESPACE` in the journal | A `ReadWritePaths=` entry points at a directory systemd may not mount on under SELinux (security file types such as `semanage_store_t`). The shipped unit lists parents (`/var/lib`) for this reason; if you customised the unit, revert to that pattern. |
| Start-up fails with `nginx include: nginx rejected the configuration: … duplicate default server` | The host already has a `default_server`. Set `OXPANEL_NGINX_DEFAULT_SERVER=false` (then unknown hosts go to *that* server). |
| Client gets `transport error` / connection closed immediately | Peer not allowed. Check `journalctl -u oxpanel-daemon` for `rejected connection`; add the account to group `oxpanel` (or `OXPANEL_ALLOWED_UIDS`). Remember: account membership, not process groups. |
| `PermissionDenied` on every RPC | Same as above, or the request bypassed the gate (only possible with a custom transport). |
| `FailedPrecondition: user 'x' exists but is not managed by OxPanel` | The name is an existing local account or group. Pick another name; the daemon never adopts accounts. |
| `AlreadyExists: tenant 'x' already exists with a different specification` | Replay with the same limits/owner, or delete and recreate. |
| `FailedPrecondition: tenant 'x' still owns virtual hosts` | Remove the vhosts first. |
| `FailedPrecondition: nginx rejected the configuration: …` | The generated block conflicted with something in the host's Nginx config (the message is `nginx -t`'s output). Nothing was activated; the previous file was restored. |
| `ResourceExhausted: no free UID in range` | Raise `OXPANEL_UID_MAX` or free ids. |
| `DeadlineExceeded` | A tool hung longer than `OXPANEL_COMMAND_TIMEOUT_SECS` (SSSD/NSS lookups are the usual suspect). |
| `Internal` | Details are in the journal only, by design. |
| Site returns 403/404 right after `vhost set` | Reload race (worker swap) — retry after a moment. Persisting 403 with SELinux: check `ausearch -m avc -ts recent`; the docroot should be `httpd_sys_content_t`. |
| `curl http://<ip>/` closes the connection | Intended: the catch-all `default_server` returns 444 for hosts no tenant owns. |
| `stat /home/<t>` shows `0710` | Expected with the ACL; `getfacl` shows `group::---` and `other::---`. |

## 11. Development and testing

```sh
make image         # AlmaLinux 9 dev/test image (one-time)
make check         # rustfmt --check, clippy pedantic -D warnings, tests, cargo-deny
make test          # 104 unit + 6 gRPC end-to-end tests (fake OS, no root)
make integration   # boots systemd in a container, installs from packaging/, runs 223 assertions
make rpm           # build the RPM from the working tree into dist/rpms/
make acceptance    # REAL AlmaLinux 9 VM (KVM, SELinux enforcing): install like a user, run all phases
./scripts/dev.sh cargo <anything>   # run cargo inside the image
```

### Real-host acceptance (`make acceptance`)

The container suite cannot exercise SELinux, the unit's network/hostname
namespaces, a reboot, or the RPM's dependency resolution. `make acceptance`
boots a fresh **AlmaLinux 9 virtual machine** under KVM from the official cloud
image — qemu runs inside a podman container, so nothing is installed on your
workstation; you only need `/dev/kvm` to be readable — and drives it over SSH.

| Variable | Default | Effect |
|---|---|---|
| `INSTALL=git` | *(default)* | The VM runs this handbook's §3.2 "From source" block **verbatim** (cloned from GitHub), then the §3.4 verification block. This is the "user installing from git" test; it exercises what is on the remote, not your working tree. |
| `INSTALL=rpm` | | Builds the RPM from your working tree and `dnf install`s it in the VM. Fast path for uncommitted changes and for the packaging. |
| `GIT_REF=<branch or sha>` | current branch | Which commit the git install checks out. CI passes the pushed SHA. |
| `PHASES="10 20 30 40 50 60 70"` | all | Subset of phases (below). |
| `KEEP=1` | | Leave the VM running afterwards; the report prints the `ssh` line (`make acceptance-destroy` removes it). |
| `SOAK_N=20` | | Cycles for the soak phase. |
| `CONTINUE=1` | | Run remaining phases after a failure. |
| `TARGET=user@host` | | Use a machine you provide instead of a VM (`TARGET_KEY=path` for the key). Phases 60/70 reboot it and create accounts, so this needs `I_UNDERSTAND=1`. |

Phases: **10** install (`dnf install` of the RPM or the handbook's source install; services start; `--check-config`) ·
**20** the 79-check integration suite on the real host ·
**30** SELinux: enforcing, docroot labels, `semanage` rule lifecycle, site serves, **zero AVC denials** ·
**40** sandbox: private network/UTS/mount namespaces, seccomp, capability bounding set, read-only `/usr` ·
**50** `systemctl restart`, `SIGKILL` + auto-restart, a record forced back to `provisioning` is resumed with exactly one `useradd` ·
**60** reboot with two tenants and two sites; everything must come back ·
**70** soak: N create/destroy cycles, then nothing may be left behind.

Results land in `dist/acceptance/<UTC stamp>/` (`latest` symlink): `report.md`
with a per-phase table and failure context, `phases/*.log`, the VM's journals,
`audit.log`, nginx logs, generated configs and records, and the serial console.
Exit status 0 means every check passed. A full run takes roughly 8 minutes in
RPM mode and 15–20 in git mode (it compiles the daemon inside the VM).

In CI the `acceptance` job runs on every push to `main`, nightly, and on demand,
installing from git at the pushed commit and uploading the run directory as an
artifact.

**Dry-run mode** runs the real daemon and CLI without root against an
in-memory OS, so the panel can be developed on a laptop:

```sh
T=$HOME/ox; mkdir -p $T/nginx/conf.d $T/home $T/systemd
export OXPANEL_DRY_RUN=1 OXPANEL_STATE_DIR=$T/state OXPANEL_HOME_BASE=$T/home \
       OXPANEL_SYSTEMD_UNIT_DIR=$T/systemd OXPANEL_NGINX_CONF_DIR=$T/nginx/oxpanel.d \
       OXPANEL_NGINX_INCLUDE_FILE=$T/nginx/conf.d/00-oxpanel.conf \
       OXPANEL_SOCKET_PATH=$T/oxpanel.sock OXPANEL_SOCKET_GROUP=
oxpanel-daemon --dry-run &
oxpanel-ctl --socket $T/oxpanel.sock tenant create alice --memory 512M
```

In dry-run the daemon allows its own uid as a peer, writes real files under the
configured directories (records, unit files, Nginx configs) and fakes
`useradd`, `nginx -t`, `systemctl` and friends.

Project rules for contributors are in `oxpanel-daemon/CLAUDE.md`; the
architecture in `oxpanel-daemon/PROJECT_DETAILS.md`.

## 12. Upgrading and uninstalling

**Upgrade:** install the new RPM (`dnf upgrade ./oxpanel-daemon-*.rpm`); the
unit restarts automatically, records are versioned (`version` field) and older
records load with defaults for new fields.

**Uninstall the engine, keep the tenants:**

```sh
sudo systemctl disable --now oxpanel-daemon
sudo dnf remove oxpanel-daemon
# left in place on purpose: /var/lib/oxpanel, /home/<tenants>, /etc/systemd/system/oxpanel-tenant-*.slice,
# /etc/nginx/oxpanel.d, /etc/nginx/conf.d/00-oxpanel.conf, the accounts themselves, /etc/oxpanel/daemon.env
```

**Remove everything:** delete every virtual host and tenant through the API
first (`vhost remove`, `tenant delete --remove-home`) — that is the only path
that cleans up accounts, ACLs, SELinux rules and units consistently — then
uninstall and remove `/var/lib/oxpanel`, `/etc/nginx/oxpanel.d`,
`/etc/nginx/conf.d/00-oxpanel.conf`, `/etc/oxpanel`, and the `oxpanel` group.

## 13. Security notes for operators

- The daemon is root; its blast radius is bounded by the unit
  (`packaging/systemd/oxpanel-daemon.service`). Do not "fix" a problem by
  loosening `ReadWritePaths`, capabilities or the syscall filter without
  understanding which tool needs it — the file documents each entry.
- Membership in the `oxpanel` group is equivalent to root-level control of
  tenants. Grant it to service accounts and administrators only, never to
  tenants.
- Keep `/etc/oxpanel/daemon.env` root-readable (`0640`, as installed).
- Two unit directives cannot be verified in the container-based integration
  test: `PrivateNetwork=` and `ProtectHostname=`. They are standard systemd
  features and expected to work on a real host, but confirm with
  `systemctl status oxpanel-daemon` (no "ignoring" warnings) after the first
  production start.
- The SELinux path (`semanage fcontext`, `restorecon`) is likewise only
  exercised on a real enforcing host; test one tenant and one site there
  before rolling out.
- Report security issues privately to the maintainers, not in public issues.
