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
| Network | None for the daemon: the API is a local UNIX socket and the daemon has no network access at all under its unit. Only the ACME client (`oxpanel-acme`, run in a transient unit) connects out, to the certificate authority over HTTPS. |
| Ports | Nginx on 80, and on 443 for sites with a certificate. OxPanel does not manage the firewall: open both (`sudo firewall-cmd --permanent --add-service=http --add-service=https && sudo firewall-cmd --reload`). ACME HTTP-01 validation needs port 80 reachable from the internet. |
| SFTP (optional) | `openssh-server` with the stock `/etc/ssh/sshd_config`, which includes `/etc/ssh/sshd_config.d/*.conf` (the AlmaLinux default). OxPanel adds one drop-in there and never edits `sshd_config`. Without sshd, `host info` shows `sftp=false` and adding a key is refused. |
| Disk quotas (optional) | Tenant homes on **XFS mounted with user quotas** (`uquota`), and `xfsprogs`. This is a mount option the operator sets once (§9.1); without it `host info` shows `disk_quota=false` and a disk limit is refused with the change to make. |
| Databases (optional) | `mariadb-server` 10.4 or newer (AlmaLinux 9 ships 10.5) and, for PHP sites, `php-mysqlnd`. Not installed by the RPM: see §3.5. Without them the database RPCs refuse cleanly. |

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
| `/usr/libexec/oxpanel/oxpanel-acme` | ACME client, started by the daemon in a transient unit as `oxpanel-acme` |

### 3.2 From source, on the target host

```sh
sudo dnf module enable -y nodejs:22        # Node.js applications need version 22 or newer
sudo dnf install -y gcc git nginx shadow-utils util-linux acl policycoreutils policycoreutils-python-utils libselinux-utils logrotate tar gzip openssl ca-certificates php-fpm nodejs npm
# SELinux: sites live under tenant homes, so the web server must be allowed to traverse and read them.
if sudo selinuxenabled; then sudo setsebool -P httpd_enable_homedirs=on httpd_read_user_content=on httpd_unified=on; fi
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal && source ~/.cargo/env

git clone https://github.com/OxServers/oxpanel.git && cd oxpanel
cargo build --release --locked -p oxpanel-daemon -p oxpanel-ctl -p oxpanel-acme

sudo install -m0755 target/release/oxpanel-daemon /usr/sbin/oxpanel-daemon
sudo install -m0755 target/release/oxpanel-ctl    /usr/bin/oxpanel-ctl
sudo install -Dm0755 target/release/oxpanel-acme  /usr/libexec/oxpanel/oxpanel-acme
sudo install -Dm0644 packaging/systemd/oxpanel-daemon.service /etc/systemd/system/oxpanel-daemon.service
sudo install -Dm0644 packaging/sysusers.d/oxpanel.conf        /usr/lib/sysusers.d/oxpanel.conf
sudo install -Dm0644 packaging/tmpfiles.d/oxpanel.conf        /usr/lib/tmpfiles.d/oxpanel.conf
sudo install -Dm0640 packaging/daemon.env                     /etc/oxpanel/daemon.env
sudo install -Dm0644 packaging/logrotate.d/oxpanel            /etc/logrotate.d/oxpanel
sudo install -Dm0644 packaging/selinux/oxpanel.cil            /usr/share/oxpanel/selinux/oxpanel.cil
# SELinux: the domain tenant applications (Node.js, Python) run in, and the label of the ACME challenge directory.
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

### 3.5 Tenant databases (optional): MariaDB

Tenants can have MariaDB databases once a MariaDB server runs on the host.
The daemon talks to it as `root` over the local UNIX socket (root
authenticates through `unix_socket`, the AlmaLinux default, so there is no
administrative password to store). A fresh MariaDB gives every local user an
anonymous account and a shared `test` database; remove them, and keep the
server off the network — tenant database users can only connect locally
anyway (`'user'@'localhost'`), and with `skip-networking` there is no TCP
listener at all (applications connect to `localhost`, i.e. the socket, not
to `127.0.0.1`):

```sh
sudo dnf install -y mariadb-server php-mysqlnd
sudo systemctl enable --now mariadb
# What mysql_secure_installation does, without the prompts: no anonymous
# accounts, no `test` database open to everyone.
sudo mariadb --no-defaults --user=root <<'SQL'
DELETE FROM mysql.global_priv WHERE User='';
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;
SQL
printf '[mysqld]\nskip-networking\n' | sudo tee /etc/my.cnf.d/oxpanel-local.cnf >/dev/null
sudo systemctl restart mariadb
sudo oxpanel-ctl host info | grep '^database_engine='   # database_engine=mariadb available=true version=10.5…
```

PHP-FPM instances that were already running load `php-mysqlnd` the next time
they start (`systemctl restart 'oxpanel-php-*'`). Nothing in OxPanel has to be
restarted: availability is checked on every request. If the server stops,
database requests fail with `FAILED_PRECONDITION` and `host reconcile` reports
it; sites keep running.

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
| `OXPANEL_TENANT_GROUP` | `oxpanel-tenants` | Group every tenant is put in; OxPanel's sshd drop-in confines its members to chrooted SFTP. Created by the package; must exist. |
| `OXPANEL_SFTP_PASSWORD_GROUP` | `oxpanel-sftp-password` | Group of the tenants with an SFTP password (the only ones offered password login). Created by the package; must exist. |
| `OXPANEL_SFTP_PASSWORDS` | `true` | Whether tenants may be given SFTP passwords (opt-in per tenant). `false` = keys only (§9). |
| `OXPANEL_SSHD_DROPIN_FILE` | `/etc/ssh/sshd_config.d/60-oxpanel.conf` | The sshd drop-in OxPanel owns; its directory must be included by `sshd_config`. |
| `OXPANEL_SFTP_KEYS_DIR` | `/etc/oxpanel-sftp` | Per-tenant SFTP keys files (root-owned). |
| `OXPANEL_BACKUP_DIR` | `/var/lib/oxpanel-backups` | Backup store: `<dir>/<tenant>/<backup id>/`, root-only. Must not be inside `OXPANEL_HOME_BASE` and must be writable under the unit's `ReadWritePaths` (anything below `/var/lib` is). |
| `OXPANEL_BACKUP_KEEP` | `7` | Complete backups kept per tenant (1–365); older ones are removed when a new one completes. |
| `OXPANEL_BACKUP_MIN_FREE_BYTES` | `1073741824` | Space that must stay free on the backup file system: a backup that could eat into it is refused, and no archive may grow into it. |
| `OXPANEL_BACKUP_TIMEOUT_SECS` | `21600` | Upper bound for one backup or restore job (≥ 60). |
| `OXPANEL_COMMAND_TIMEOUT_SECS` | `60` | Upper bound for any single external command (`useradd`, `nginx -t`, …). |
| `OXPANEL_TLS_DIR` | `/etc/pki/oxpanel` | Certificates and private keys of sites (root `0700`). |
| `OXPANEL_ACME_DIR` | `/var/lib/oxpanel-acme` | Working directories shared with the ACME client. Created by `tmpfiles.d/oxpanel.conf` and labelled by the SELinux module: change those too if you move it. Must not overlap `OXPANEL_TLS_DIR`. |
| `OXPANEL_ACME_DIRECTORY_URL` | Let's Encrypt production | ACME directory, `https://` only (staging: `https://acme-staging-v02.api.letsencrypt.org/directory`). |
| `OXPANEL_ACME_CA_FILE` | *(system trust store)* | PEM bundle the ACME client trusts for the authority's HTTPS (private/test CA). Must be readable by `oxpanel-acme` and outside `/home` and `/root`. |
| `OXPANEL_ACME_EMAIL` | *(none)* | Contact address registered with the ACME account. |
| `OXPANEL_ACME_EAB_FILE` | *(none)* | External Account Binding for authorities that require it: a root-owned `0600` file with `kid=…` and `hmac_key=…` lines. Passed to the client as a systemd credential. |
| `OXPANEL_AUTO_HTTPS` | `true` | Automatic HTTPS: every site gets a certificate by itself (§6). `false` switches it off for the whole host; single sites opt out with `vhost set --no-auto-https`. |
| `OXPANEL_ACME_RENEW_DAYS` | `30` | Renew ACME certificates this many days (1–60) before expiry; checked 5 minutes after start and every 12 hours. |
| `OXPANEL_LOG` | `info` | `tracing` filter: `info`, `debug`, `oxpanel_daemon=trace`, … |
| `OXPANEL_DRY_RUN` | `false` | Use the in-memory fake OS (development only — see §11). |

Rules enforced at start-up (`--check-config` reports them):

- every path must be absolute, below `/`, without `.`/`..` components, and use
  only `A-Z a-z 0-9 / . _ -` (paths are interpolated into Nginx directives and
  SELinux regular expressions);
- `OXPANEL_NGINX_INCLUDE_FILE` may not live inside `OXPANEL_NGINX_CONF_DIR`;
- `OXPANEL_UID_MIN` ≥ 1000 and ≤ `OXPANEL_UID_MAX`;
- `OXPANEL_BACKUP_DIR` may not live inside `OXPANEL_HOME_BASE`.

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
| `read` | `GetTenant`, `ListTenants`, `ListVirtualHosts`, `ReadVirtualHostLog`, `GetTenantUsage`, `GetHostInfo`, `Reconcile`, `GetAutoHttpsStatus`, `ListSftpKeys`, `ListDatabases`, `ListDatabaseUsers`, `ListBackups`, `GetJob`, `ListRetainedBackups` |
| `vhost` | `ConfigureVirtualHost`, `RemoveVirtualHost`, `RestartApp`, `InstallAppDependencies`, `InstallCertificate`, `RemoveCertificate`, `RequestCertificate`, `RenewCertificates`, `RunAutoHttps`, `AddSftpKey`, `RemoveSftpKey`, `SetSftpPassword`, `ClearSftpPassword`, `CreateDatabase`, `DeleteDatabase`, `CreateDatabaseUser`, `SetDatabaseUserPassword`, `DeleteDatabaseUser`, `GrantDatabaseAccess`, `RevokeDatabaseAccess` (customers manage their own sites, certificates, SFTP access and databases) |
| `tenant` | `CreateTenant`, `UpdateTenantLimits`, `UpdateTenantOwner`, `SuspendTenant`, `ResumeTenant`, `CreateBackup`, `RestoreBackup`, `RetainBackup` |
| `delete` | `DeleteTenant`, `DeleteBackup`, `RestoreRetainedBackup` (a retained backup of a deleted tenant is reached only with this scope) |

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

db create     <tenant>_<suffix> --tenant <username> [--engine mariadb]
db list       [--tenant <username>]
db delete     <name>
db user-create <tenant>_<suffix> --tenant <username> [--engine mariadb]   # password: one line on stdin
db user-list  [--tenant <username>]
db user-passwd <name>                                                     # password: one line on stdin
db user-delete <name>
db grant      <user> <database>
db revoke     <user> <database>
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

# HTTPS with your own certificate (chain: certificate first, then intermediates;
# the key unencrypted). Refused if the key does not match, the certificate has
# expired or does not cover the domain; aliases it does not cover are listed.
sudo oxpanel-ctl cert install acme.example --chain acme.example.chain.pem --key acme.example.key
# domain=acme.example certificate=present source=uploaded ... names=acme.example,www.acme.example uncovered=- ...

# Or from Let's Encrypt (HTTP-01: every name must point at this host, port 80 open).
# Renewed automatically 30 days before expiry; `cert renew` does it now.
sudo oxpanel-ctl cert request acme.example
sudo oxpanel-ctl cert show acme.example

# Automatic HTTPS (on by default) does what other panels call automatic SSL:
# a few seconds after a site is created or gets a new alias, the engine checks
# that each name points here and asks the authority for a certificate covering
# the names that do. Nothing to call; but you can look and nudge:
sudo oxpanel-ctl cert auto status acme.example
# domain=acme.example auto_https=partial covered=acme.example,www.acme.example pending=- skipped=old.acme.example ...
#   skipped name=old.acme.example failures=1 next_attempt=1794560000 reason=the name does not resolve
sudo oxpanel-ctl cert auto run acme.example     # now, ignoring back-off (without a domain: every site)
sudo oxpanel-ctl vhost set acme.example --tenant acme --no-auto-https   # this site: hands off

# Redirect HTTP to HTTPS; HSTS (browsers remember it for a year — only when HTTPS is there to stay)
sudo oxpanel-ctl vhost set acme.example --tenant acme --alias www.acme.example --redirect-https --hsts
sudo oxpanel-ctl cert remove acme.example     # back to HTTP only (redirect and HSTS stop with it)

# SFTP: give the tenant a key (its id_*.pub line). It can then `sftp acme@host`
# — SFTP only, no shell, no forwarding, inside its own home (/home/acme)
sudo oxpanel-ctl sftp add-key acme --key-file acme_laptop.pub --label laptop
# changed=true
# fingerprint=SHA256:… type=ssh-ed25519 label=laptop added_at=1794571200
sudo oxpanel-ctl sftp list-keys acme
sudo oxpanel-ctl sftp remove-key acme SHA256:…    # no new logins with it; sessions continue
sudo oxpanel-ctl sftp remove-key acme SHA256:… --end-sessions   # …and end the tenant's sessions
# Or a password (opt-in per tenant), read from stdin — never as an argument
sudo oxpanel-ctl sftp set-password acme < acme.pw   # password=set
sudo oxpanel-ctl sftp clear-password acme [--end-sessions]

# A disk limit (needs quotas on the host, §9.1): 5 GiB and 200 000 files
sudo oxpanel-ctl tenant set-limits acme --memory 1G --cpu-weight 25 --tasks-max 200 --disk 5G --inodes 200000

# The end of a site's access log, or its error log
sudo oxpanel-ctl vhost log acme.example
sudo oxpanel-ctl vhost log acme.example --error --bytes 64K

# A database for the shop and a user for it (§3.5 first). Names start with
# "<tenant>_"; the password is read from standard input, never an argument.
sudo oxpanel-ctl db create acme_shop --tenant acme
printf '%s\n' "$SHOP_DB_PASSWORD" | sudo oxpanel-ctl db user-create acme_shopapp --tenant acme
sudo oxpanel-ctl db grant acme_shopapp acme_shop
sudo oxpanel-ctl db list --tenant acme        # database=acme_shop tenant=acme engine=mariadb size=…
#   in the application: host "localhost", user "acme_shopapp", database "acme_shop"

# Back up the tenant (home + the engine's records), waiting for the job;
# without --wait it prints the job id at once (`backup job <id>` to look again)
sudo oxpanel-ctl backup create acme --wait
# job=j1794571200123 kind=JOB_KIND_BACKUP tenant=acme backup=b1794571200123 state=JOB_STATE_SUCCEEDED ...
sudo oxpanel-ctl backup list acme
# backup=b1794571200123 tenant=acme state=BACKUP_STATE_READY created_at=1794571200 size=48213 domains=acme.example,shop.acme.example members=home:home.tar.gz:47101,records:records.json:1112
# Put the files back. You must choose what happens to files that exist now:
# --overwrite replaces them, --keep-existing leaves them and restores only
# what is missing. PHP/apps stop meanwhile; apps get their virtualenv and
# dependencies reinstalled (backups leave node_modules and virtualenvs out).
# --wait exits 5 if the job failed.
sudo oxpanel-ctl backup restore acme b1794571200123 --keep-existing --wait
# restored_entries=12 skipped_entries=40
# site=app.acme.example dependencies_ok=true detail=dependencies reinstalled from package.json
sudo oxpanel-ctl backup delete acme b1794571200123

# Closing a customer's account: a final backup kept for 6 months after the
# deletion (then removed automatically); other backups must go first
sudo oxpanel-ctl backup create acme --retain-months 6 --wait
sudo oxpanel-ctl backup list-retained
# backup=b1794571300456 tenant=acme state=BACKUP_STATE_READY created_at=... retain_until=1810349000 ...
# After the deletion it is listed with tenant_deleted=true; a new tenant named
# acme never sees it. The customer came back as acme2: restore it there
sudo oxpanel-ctl backup restore-retained b1794571300456 --from acme --to acme2 --overwrite --wait
# ...or drop it early
sudo oxpanel-ctl backup delete acme b1794571300456 --tenant-deleted

# The file manager: everything runs AS THE TENANT, beneath its home (a symlink
# out of the home is never followed). Paths are relative to the home.
sudo oxpanel-ctl files ls acme public_html
# dir 0755 4096 1794571500 css
# file 0644 5120 1794571400 index.php
# link 0777 11 1794571400 pw -> /etc/passwd (outside-home)
# total=3 truncated=false
sudo oxpanel-ctl files cat acme public_html/index.php        # 1 MiB per request, any size
echo '<?php phpinfo();' | sudo oxpanel-ctl files write acme public_html/info.php   # editor save, ≤ 192 KiB
sudo oxpanel-ctl files put acme ./site.zip site.zip          # chunked upload, SHA-256 checked
sudo oxpanel-ctl files get acme public_html/index.php ./index.php
sudo oxpanel-ctl files mkdir acme public_html/img --parents
sudo oxpanel-ctl files mv acme public_html/info.php public_html/old/info.php
sudo oxpanel-ctl files chmod acme public_html/.env --private  # 0600: the web server cannot read it
sudo oxpanel-ctl files chmod acme public_html/old --web       # 0755
sudo oxpanel-ctl files find acme "" config                     # names containing "config"
sudo oxpanel-ctl files du acme public_html
# Long operations are jobs (one per tenant); --wait follows them (exit 5 if FAILED)
sudo oxpanel-ctl files extract acme site.zip public_html --wait
# ...skipped '../../etc/cron.d/x': its name contains '..'
# job=f1794571600123 kind=FILE_JOB_KIND_EXTRACT tenant=acme state=JOB_STATE_SUCCEEDED entries=212 bytes=4022113 skipped=1 ...
sudo oxpanel-ctl files compress acme "" backup-site.tar.gz public_html --format tar-gz --wait
sudo oxpanel-ctl files cp acme public_html/old public_html/img --wait
sudo oxpanel-ctl files rm acme public_html/old backup-site.tar.gz --wait
sudo oxpanel-ctl files jobs acme

# Tear down (order matters: vhosts and databases first; backups that are not
# retained block deleting the tenant)
sudo oxpanel-ctl db user-delete acme_shopapp
sudo oxpanel-ctl db delete acme_shop          # drops the database and everything in it
sudo oxpanel-ctl vhost remove shop.acme.example
sudo oxpanel-ctl vhost remove acme.example
for id in $(sudo oxpanel-ctl backup list acme | sed -n 's/^backup=\([^ ]*\).*/\1/p'); do sudo oxpanel-ctl backup delete acme "$id"; done
sudo oxpanel-ctl tenant delete acme --remove-home
```

Limits: `--memory` is `0` (unlimited) or ≥ 16 MiB; `--cpu-weight` and
`--io-weight` are `0` (systemd default, 100) or 1–10000; `--tasks-max` is `0`
(default) or ≥ 1; `--disk` is `0` (unlimited) or ≥ 1 MiB and `--inodes` `0` or
≥ 100 (both kernel quotas, refused on a host without them). Names: user names `^[a-z][a-z0-9_-]{2,31}$` (reserved system
names refused); domains lower-case ASCII labels (punycode `xn--` allowed, no
wildcards, no IP literals); `--root` is relative, with components made of
`A-Z a-z 0-9 . _ -` only; `--owner` is `^[a-z0-9][a-z0-9_.-]{0,63}$`.
File-manager paths are relative to the home (no leading `/`, no `.` or `..`,
at most 3072 bytes and 64 components); names it creates must be visible text
(no newline, control or invisible characters, no leading or trailing space).
Its bounds are set with `OXPANEL_FILES_UPLOAD_MAX_BYTES` (4 GiB),
`OXPANEL_FILES_JOB_MAX_BYTES` (8 GiB), `OXPANEL_FILES_EXTRACT_MAX_RATIO`
(200), `OXPANEL_FILES_EXTRACT_MAX_ENTRIES` (100000),
`OXPANEL_FILES_LIST_MAX_ENTRIES` (100000), `OXPANEL_FILES_WALK_MAX_ENTRIES`
(200000) and `OXPANEL_FILES_JOB_TIMEOUT_SECS` (7200); see
`docs/superpowers/specs/2026-11-14-files-design.md`.
Database and database-user names are `<tenant>_<suffix>` with a suffix of 1–24
characters `a-z 0-9` (so `acme_shop_wp` belongs to tenant `acme_shop`, never to
`acme`); passwords are 8–128 characters without control characters.

**Uploading content:** give the tenant an SFTP key (`sftp add-key`); the
tenant (or its developer) uploads with any SFTP client and lands in its home,
`/home/<tenant>`. Files uploaded that way belong to the tenant and inherit the
default ACL and SELinux label, so Nginx serves them and PHP and applications
can use them without further steps. As root, put files in place as the tenant
so ownership stays correct, e.g.
`sudo setpriv --reuid=acme --regid=acme --clear-groups -- cp -r site/. /home/acme/public_html/`.

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
| `CreateDatabase` / `CreateDatabaseUser` | existing → `created=false` (a user's password is **not** changed by a repeat; use `SetDatabaseUserPassword`); interrupted → completed | `INVALID_ARGUMENT` (name not `<tenant>_<suffix>`, password length), `FAILED_PRECONDITION` (MariaDB not installed/running; the name exists on the server but OxPanel did not create it; a hand-written grant pattern would expose the new database), `RESOURCE_EXHAUSTED` (per-tenant cap), `NOT_FOUND` (tenant) |
| `SetDatabaseUserPassword` | sets it every time; re-creates an account that disappeared, with its grants | `NOT_FOUND` (no such user), `FAILED_PRECONDITION` |
| `DeleteDatabase` / `DeleteDatabaseUser` | `deleted=false` if OxPanel has no such object (it never drops one it did not create) | `FAILED_PRECONDITION` (MariaDB unavailable) |
| `GrantDatabaseAccess` / `RevokeDatabaseAccess` | already so → `changed=false`; a grant is re-applied every time (heals a hand-made revoke) | `INVALID_ARGUMENT` (user and database of different tenants), `NOT_FOUND` |
| `ListDatabases` / `ListDatabaseUsers` | read-only; sizes are `0` while MariaDB is down | — |
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
| `/etc/pki/oxpanel/<domain>.crt`, `.key` | directory `root 0700`; key `0600` | a site's certificate chain (also kept in its record) and private key (only here) |
| `/var/lib/oxpanel-acme/{account,challenges,issued}` | `oxpanel-acme` | the ACME client's account key (`0700`), HTTP-01 tokens (served by Nginx; SELinux `httpd_sys_content_t`), issued chains |
| `/var/lib/oxpanel-acme/csr` | `root 0755` | signing requests the daemon hands to the client (public) |
| `/etc/ssh/sshd_config.d/60-oxpanel.conf` | `root 0600` | `Match Group oxpanel-tenants`: SFTP only, chroot, keys from `/etc/oxpanel-sftp`, no forwarding; applies to tenants only |
| `/etc/oxpanel-sftp/<username>` | `root 0640` + ACL `user:<t>:r--`, directory `0711` | the tenant's SFTP keys (each line `restrict …`); absent while suspended |
| `/var/lib/oxpanel/sftp/<username>/` | `root 0755` | SFTP chroot; contains only `home/<username>`, the tenant's home bind-mounted |
| `/etc/systemd/system/var-lib-oxpanel-sftp-<name>-home-<name>.mount` | `root 0644` | that bind mount (enabled, so it returns after a reboot) |
| group `oxpanel-tenants` | | every tenant account is a member; grants no file access |
| group `oxpanel-sftp-password` | | tenants with an SFTP password; the password itself only as the hash in `/etc/shadow` (the record has a flag) |
| XFS user quota of the tenant's uid | | the disk and inode limit (`xfs_quota -x -c 'report -u -n -b -i' /`) |
| `/var/lib/oxpanel/databases/<name>.json` | `root 0600` | database record: tenant, engine, `state`, created time |
| `/var/lib/oxpanel/db-users/<name>.json` | `root 0600` | database-user record: tenant, engine, connection limit, granted databases, `state`. **No password and no hash** |
| MariaDB | | databases `<tenant>_<suffix>` (utf8mb4) and accounts `'<tenant>_<suffix>'@'localhost'`; data lives in `/var/lib/mysql`, which OxPanel's backups of `/var/lib/oxpanel` do not include |
| `/var/lib/oxpanel/backups/<id>.json`, `/var/lib/oxpanel/jobs/<id>.json` | `root 0600` | backup records (members, sizes, SHA-256) and backup/restore job records |
| `/var/lib/oxpanel-backups/<tenant>/<id>/` | `root 0700`, files `0600` | one backup: `home.tar.gz`, `records.json`, `manifest.json` (written last; a directory without it is not a backup) |
| `oxpanel-job-<id>.service` | transient | a running backup or restore (in the tenant's slice); gone once the daemon has recorded its result |
| SELinux hosts | | `semanage fcontext` equivalence `<docroot> = /usr/share/nginx/html` (labels the tree `httpd_sys_content_t`; a plain rule would be overridden by `file_contexts.homedirs`) |

Records are the source of truth for *what OxPanel owns*. Back up
`/var/lib/oxpanel` together with `/home` and `/etc/nginx/oxpanel.d`. The
engine's own per-tenant backups (§9) live on the same host: copy
`/var/lib/oxpanel-backups` off the host if they are to survive losing it.

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
`node=true node_version=22.x python=true`. **Node.js 22 is the minimum.**
AlmaLinux 9 installs Node.js 16 by default, which is past its end of life, so
enable a current stream first
(`sudo dnf module enable nodejs:22 && sudo dnf install nodejs npm`; on a host
that already has an older one: `sudo dnf module switch-to nodejs:22`). With an
older version installed, `host info` shows `node=false` with the version found,
and enabling a Node.js application is refused. After
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
`vhost restart-app` starts it again). Tenants upload code over SFTP (or you
put it in place as the tenant, as for static content).

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
| `SFTP_ACCESS_DRIFT` | A tenant's SFTP keys file or mount unit was edited or removed, a keys file exists while it is suspended, or the account left the `oxpanel-tenants` group. | Repeat `sftp add-key` with one of its keys (or restart the daemon). |
| `ORPHAN_SFTP_ACCESS` | A keys file, mount unit or chroot directory no tenant with keys accounts for. | Inspect and remove by hand (`systemctl disable --now` the mount unit first). |
| `SSHD_CONFIG_DRIFT` | `/etc/ssh/sshd_config.d/60-oxpanel.conf` was edited or removed: tenants may not be confined. | Restart the daemon (it rewrites and validates the file). |
| `DISK_QUOTA_DRIFT` | The kernel's quota for a tenant differs from its recorded limit, or the host no longer enforces quotas. | Repeat `tenant set-limits` with the recorded limits; for the second case see §9.1. |
| `ORPHAN_NGINX_CONFIG` / `ORPHAN_SLICE_UNIT` | A file in OxPanel's directories that no record accounts for. | Inspect and remove by hand; OxPanel will not touch what it did not record. |
| `DATABASE_MISSING` | A recorded database is gone from the server, its record is half-created/half-deleted, or MariaDB cannot be asked at all (subject `mariadb`). | Repeat `db create` (re-creates it **empty**) or `db delete`; start MariaDB. |
| `DATABASE_USER_MISSING` | A recorded database user is gone from the server, or its record is interrupted. | `db user-passwd` re-creates the account with its recorded grants; or repeat `db user-create` / `db user-delete`. |
| `DATABASE_PRIVILEGE_DRIFT` | A database user holds more or less than its record says (a global privilege, a grant on another database, `GRANT OPTION`, an edited connection limit, a lock that does not match the tenant's suspension), or an account OxPanel does not manage can reach a managed database. | Remove what was added by hand (`REVOKE …`); `db revoke` + `db grant` restores OxPanel's own grant. |
| `ORPHAN_DATABASE_OBJECT` | A database or account on the server carries a tenant's prefix (`<tenant>_`) but has no record. | Inspect and remove by hand; OxPanel will not adopt or drop it. |
| `BACKUP_ARCHIVE_MISSING` / `_MODIFIED` | A backup's directory, manifest or member is gone, or a member's size (or the manifest) no longer matches the record. Such a backup cannot be trusted; a restore from it is refused by the checksum. | `backup delete` it. |
| `BACKUP_INCOMPLETE` | A backup record that was never completed and has no running job (or a job without a backup record). | `backup delete` the backup id. |
| `ORPHAN_BACKUP_ARCHIVE` | A directory under the backup store that no record accounts for. | Inspect and remove by hand. |

**Backups** — `backup create` starts a job in a transient unit
(`oxpanel-job-<id>.service`, in the tenant's slice, lowest CPU/IO priority)
and returns; the daemon may be restarted meanwhile and picks the job up
again. `tar` runs as the tenant, so files the tenant cannot read (planted by
root, belonging to someone else) are skipped and named in the job's output.
A backup is refused (`RESOURCE_EXHAUSTED`) when the home would not fit with
`OXPANEL_BACKUP_MIN_FREE_BYTES` to spare; at most 4 jobs run on the host and
one per tenant. Only the newest `OXPANEL_BACKUP_KEEP` backups of a tenant are
kept. Scheduling is the panel's job (or cron:
`oxpanel-ctl backup create <tenant>`). A tenant with backups cannot be
deleted until they are deleted or *retained* (`backup retain <tenant> <id>
--months 1..12`, or `backup create --retain-months N`): retained backups
outlive the tenant, are hidden from any later tenant of the same name, and
are removed by the daemon when their date passes (at start-up and hourly).
`backup list-retained`, `backup delete … --tenant-deleted` and `backup
restore-retained <id> --from <deleted tenant> --to <tenant>` (needs the
`delete` scope) are the operator's tools for them.
Backups leave out `node_modules`, Python virtualenvs (any directory holding
a `pyvenv.cfg`, and each Python application's `.venv`) and the `.cache` /
`.npm` caches; `backup list` shows how many directories were left out
(`excluded=`), and the manifest names them. A restore needs an explicit
`--overwrite` or `--keep-existing`; newer files always stay. It stops the
tenant's PHP and applications while it runs, then restores the home's
privacy, SELinux labels and the web server's ACLs, recreates each Python
application's virtualenv and reinstalls every application's dependencies
(like `vhost install-deps`, so the package registry must be reachable unless
dependencies are local), and starts them again. A failed reinstallation is
reported per site (`dependencies_ok=false`) without failing the restore;
fix the cause and run `vhost install-deps`. A
`FAILED` restore of an engine-made backup usually means a member could not be
written as the tenant (e.g. a device node root once put in the home); the
other files were restored — see `backup job <id>`.

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

**Choosing the certificate authority.** Set it in `/etc/oxpanel/daemon.env`
and `systemctl restart oxpanel-daemon`; `oxpanel-ctl host info` shows
`acme_directory=`. Each directory gets its own ACME account automatically.

```sh
# Let's Encrypt (the default; nothing to set)
#OXPANEL_ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory

# Let's Encrypt staging, for trying things out (certificates are not trusted by browsers)
OXPANEL_ACME_DIRECTORY_URL=https://acme-staging-v02.api.letsencrypt.org/directory

# A provider that requires External Account Binding, e.g. ZeroSSL
# (Google Trust Services: https://dv.acme-v02.api.pki.goog/directory). The provider's
# dashboard gives an "EAB KID" and an "EAB HMAC key":
OXPANEL_ACME_DIRECTORY_URL=https://acme.zerossl.com/v2/DV90
OXPANEL_ACME_EAB_FILE=/etc/oxpanel/acme-eab
OXPANEL_ACME_EMAIL=hostmaster@example.com
```

```sh
sudo install -m 0600 -o root -g root /dev/null /etc/oxpanel/acme-eab
printf 'kid=%s\nhmac_key=%s\n' '<EAB KID>' '<EAB HMAC key>' | sudo tee /etc/oxpanel/acme-eab >/dev/null
```

The daemon refuses an EAB file that is not owned by root or that group or
others can read. The key is given to the ACME client as a systemd credential
(only that unit can read it) and never appears on a command line, in a log or
in an API response. (Typing it into `printf` puts it in your shell history;
paste it into an editor instead if that matters.)

**SFTP access** — every tenant account is in the group `oxpanel-tenants`, and
the daemon keeps `/etc/ssh/sshd_config.d/60-oxpanel.conf` in place whenever
sshd is installed (validated with `sshd -t` before sshd is reloaded; rolled
back if sshd rejects it). For members of that group sshd allows nothing but
SFTP, chrooted into a directory that contains only the tenant's own home, with
keys only OxPanel can change — also for tenants that have no key, so a
compromised site cannot give itself a login by writing
`~/.ssh/authorized_keys`. Root and every other account are not affected.
Check what sshd will do for an account:
`sshd -T -C user=acme,host=x,addr=127.0.0.1 | grep -E 'forcecommand|chroot|passwordauth'`.
Suspending a tenant withdraws its keys file, locks its password hash and ends
its running sessions; `tenant resume` restores them. Removing a key or the
password stops new logins with it; running sessions continue unless
`--end-sessions` is given.

**SFTP passwords** — opt-in per tenant (`sftp set-password`, read from stdin),
allowed by default; `OXPANEL_SFTP_PASSWORDS=false` in `daemon.env` forbids them
host-wide (restart the daemon: the password block leaves the sshd drop-in, so
existing passwords stop working at once; `host reconcile` lists the tenants
that still have one recorded; `sftp clear-password` removes them). Tenants
with a password are in the group `oxpanel-sftp-password`; only that group is
offered password authentication, with the same confinement as keys. The
password exists only as the hash in `/etc/shadow`.

*Brute force.* OpenSSH 9.9 on AlmaLinux 9.8 already refuses an address for a
while after failed logins (`PerSourcePenalties`, default
`authfail:5 … max:600 min:15`), limits unauthenticated connections
(`MaxStartups 10:30:100`) and closes a login after `LoginGraceTime 120`.
OxPanel's drop-in sets `MaxAuthTries 3` for tenants (stock: 6). Everything
global stays yours; for longer, cross-address bans install fail2ban and enable
its `sshd` jail (`dnf install fail2ban-server`, then `[sshd] enabled = true` in
`/etc/fail2ban/jail.d/sshd.local`). `pam_faillock` (`authselect
enable-feature with-faillock`) also works but locks every account after
failures, your own included. Watch `journalctl -u sshd` for
"Failed password for <tenant>".

### 9.1 Disk quotas: preparing the host

Disk limits are XFS user quotas on the file system that holds `/home`. XFS
decides at mount time whether quotas are enforced, so this is a one-time host
change that OxPanel does not make for you. On the AlmaLinux default layout
`/home` is on the root file system, which needs a kernel argument:

```sh
findmnt -no FSTYPE,OPTIONS -T /home     # xfs …,usrquota → already done
dnf -y install xfsprogs
grubby --update-kernel=ALL --args=rootflags=uquota
```

Then reboot. With `/home` on its own XFS file system instead, add `uquota` to
its options in `/etc/fstab` and remount it (`umount /home && mount /home`,
with nothing using it) or reboot. Afterwards `findmnt -T /home` shows
`usrquota`, and `oxpanel-ctl host info` shows `disk_quota=true` (its
`disk_quota_detail=` line says what was found either way). The limit counts
everything the tenant's uid owns on that file system, and a write beyond it
fails with "Disk quota exceeded". `tenant usage` then reports the quota
system's figure instead of walking the home. If the option is ever lost, the
kernel stops enforcing the limits and `host reconcile` reports every tenant
with a disk limit (`DISK_QUOTA_DRIFT`).

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
| `FailedPrecondition: Node.js (nodejs) is not installed on this host` | `sudo dnf module enable nodejs:22 && sudo dnf install nodejs npm`; no daemon restart needed. |
| `FailedPrecondition: Node.js 16.x is installed, but version 22 or newer is required` | `sudo dnf module switch-to nodejs:22`, then `systemctl restart 'oxpanel-app-*'`. |
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
| `FailedPrecondition: OpenSSL is not installed` | `sudo dnf install openssl` (the RPM requires it). |
| `FailedPrecondition: ACME is not available on this host: …` | The message names what is missing: the client binary, the `oxpanel-acme` account (`systemd-sysusers`) or a directory under `/var/lib/oxpanel-acme` (`systemd-tmpfiles --create oxpanel.conf`). `oxpanel-ctl host info` shows `acme=true` once it is in place. |
| **Why did my site not get a certificate?** | `oxpanel-ctl cert auto status <domain>` says it in plain words. `disabled`: Automatic HTTPS is off for the host (`host info` shows `auto_https=false`) or the site opted out. `suspended`: the tenant is suspended; it catches up on resume. `uploaded`: the site has a valid uploaded certificate, which is never replaced (only an expired one is). `skipped name=… reason=the name does not resolve`: DNS has no record for that name (yet). `…cannot connect to port 80` / `answered "HTTP/1.1 …"` / `serves something else than this server's probe`: the name points at another server, port 80 is closed in the firewall, or something in front (a CDN, a proxy) does not pass `/.well-known/acme-challenge/` through. `the certificate authority refused: …`: the authority's own reason (e.g. a rate limit). Each failing name waits 1 h, 6 h, then 24 h before the next try; fix the cause and run `oxpanel-ctl cert auto run <domain>` to try at once. `certificates cannot be requested on this host`: see the `ACME is not available` row. |
| `cert request` prints `succeeded=false` | The certificate authority's reason follows the client's output, e.g. DNS of a name does not point here, port 80 is closed, or a rate limit. Try `OXPANEL_ACME_DIRECTORY_URL=https://acme-staging-v02.api.letsencrypt.org/directory` while experimenting. A request sent in the same instant as the `vhost set` that created the site can lose the race with Nginx's reload (`connection` error, EOF): repeat it. The site keeps whatever certificate it had. |
| `InvalidArgument: certificate rejected: …` | The message says which check failed (key does not belong, expired, not valid for the domain, encrypted key). Nothing was changed. |
| `openssl s_client -servername <unknown>` fails the handshake | Intended: the 443 catch-all rejects names no site with a certificate owns, so no tenant's certificate is ever shown for them. |
| `curl http://<ip>/` closes the connection | Intended: the catch-all `default_server` returns 444 for hosts no tenant owns. |
| `stat /home/<t>` shows `0710` | Expected with the ACL; `getfacl` shows `group::---` and `other::---`. |
| `FailedPrecondition: disk quotas are not available: …` | The file system holding `/home` does not enforce user quotas; the message says what to change (§9.1). |
| `FailedPrecondition: SFTP is not available on this host: …` | sshd is missing, rejected the drop-in, or would not apply it (e.g. `sshd_config` has no `Include /etc/ssh/sshd_config.d/*.conf`); the message says which. |
| SFTP login fails with "Permission denied (publickey)" | Wrong key, tenant suspended (no keys file), or the key was removed. `journalctl -u sshd` shows sshd's reason. |
| SFTP connection is closed before authentication | OpenSSH 9.8+ (AlmaLinux 9.8 ships 9.9) briefly blocks an address after repeated failed logins (`PerSourcePenalties`); it lifts by itself. This applies to the host's whole sshd, not only tenants. |

## 11. Development and testing

```sh
make image         # AlmaLinux 9 dev/test image (one-time)
make check         # rustfmt --check, clippy pedantic -D warnings, tests, cargo-deny, feature traceability
make test          # 288 tests (fake OS, no root): unit, property, gRPC surface, crash safety, perf budgets
make traceability  # every row of docs/FEATURES.md maps to tests that exist (docs/traceability.map)
make coverage      # line coverage of the daemon (cargo-llvm-cov; run `make image` once first)
make bench         # engine benchmark against the fake OS (docs/PERFORMANCE.md); never part of `make check`
make integration   # boots systemd in a container, installs from packaging/, runs 681 assertions
                   # (HTTPS/ACME against a local Pebble downloaded at test time; OXPANEL_IT_SKIP_ACME=1 skips it)
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
| `PHASES="10 15 20 30 40 50 60 70 80 90"` | all | Subset of phases (below). |
| `KEEP=1` | | Leave the VM running afterwards; the report prints the `ssh` line (`make acceptance-destroy` removes it). |
| `SOAK_N=20` | | Cycles for the soak phase. |
| `CONTINUE=1` | | Run remaining phases after a failure. |
| `TARGET=user@host` | | Use a machine you provide instead of a VM (`TARGET_KEY=path` for the key). Phases 15/60/70/80/90 reboot it, create accounts and attack them, so this needs `I_UNDERSTAND=1`. |

Phases: **10** install (`dnf install` of the RPM or the handbook's source install; MariaDB set up as in §3.5; services start; `--check-config`) ·
**15** host preparation for disk quotas: runs §9.1's block, reboots, checks the quota option is on ·
**20** the 703-check integration suite on the real host (`tests-integration/run-inside.sh`: everything above plus HTTPS and ACME against a local test CA, SFTP, quotas, databases and backups) ·
**30** SELinux: enforcing, docroot labels, `semanage` rule lifecycle, site serves, **zero AVC denials** ·
**40** sandbox: private network/UTS/mount namespaces, seccomp, capability bounding set, read-only `/usr` ·
**50** `systemctl restart`, `SIGKILL` + auto-restart, a record forced back to `provisioning` is resumed with exactly one `useradd` ·
**60** reboot with two tenants and two sites; everything must come back ·
**70** soak: N create/destroy cycles, then nothing may be left behind ·
**80** attacks: from inside a tenant's own PHP, Node.js and Python code, and from the network, try to read
other tenants and the engine, escape through planted links, exhaust memory, tasks and `/tmp`, outlive
suspension or deletion, smuggle requests; every attempt must fail (`docs/SECURITY.md`) ·
**90** performance on the real host: 100 tenants with a site each, time per step and its growth, Nginx reload time, daemon memory
(`docs/PERFORMANCE.md`).

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
       OXPANEL_BACKUP_DIR=$T/backups \
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
records load with defaults for new fields. Backup and restore jobs that are
running keep running in their own units and are picked up by the new daemon.

**Uninstall the engine, keep the tenants:**

```sh
sudo systemctl disable --now oxpanel-daemon
sudo dnf remove oxpanel-daemon
# left in place on purpose: /var/lib/oxpanel, /home/<tenants>, /etc/systemd/system/oxpanel-tenant-*.slice,
# /etc/nginx/oxpanel.d, /etc/nginx/conf.d/00-oxpanel.conf, the accounts themselves, /etc/oxpanel/daemon.env,
# the backups in /var/lib/oxpanel-backups
```

**Remove everything:** delete every virtual host and tenant through the API
first (`backup delete`, `vhost remove`, `tenant delete --remove-home`) — that is the only path
that cleans up accounts, ACLs, SELinux rules and units consistently — then
uninstall and remove `/var/lib/oxpanel`, `/var/lib/oxpanel-backups`, `/etc/nginx/oxpanel.d`,
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
- Private keys of sites live only in `/etc/pki/oxpanel` (root `0700`). They are
  never logged, never returned by the API and never on a command line; the
  ACME client runs as `oxpanel-acme` and cannot read them (it only ever sees
  signing requests). Back up `/etc/pki/oxpanel` with `/var/lib/oxpanel`.
- Never add an administrator or service account to the `oxpanel-tenants`
  group: sshd confines its members to chrooted SFTP with OxPanel's keys.
- Two unit directives cannot be verified in the container-based integration
  test: `PrivateNetwork=` and `ProtectHostname=`. They are standard systemd
  features and expected to work on a real host, but confirm with
  `systemctl status oxpanel-daemon` (no "ignoring" warnings) after the first
  production start.
- The SELinux path (`semanage fcontext`, `restorecon`) is likewise only
  exercised on a real enforcing host; test one tenant and one site there
  before rolling out.
- Databases: the daemon only ever sends SQL on the `mariadb` client's
  standard input, never as an argument, and only a password *hash* (what
  MariaDB stores for `mysql_native_password`), never the password. The hash
  is still a secret (it can be attacked offline): it appears in MariaDB's
  general and binary logs if you enable them, like any `ALTER USER`. Keep
  those logs root-only. Do not give tenants `root` or any account with
  `CREATE USER`/`GRANT OPTION` — OxPanel's isolation between tenants rests on
  the grants it writes.
- Report security issues privately to the maintainers, not in public issues.
