# OxPanel engine handbook

Installation, configuration and operation of `oxpanel-daemon` v0.2.0 on
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
| Databases (optional) | `mariadb-server` 10.4 or newer (AlmaLinux 9 ships 10.5) and, for PHP sites, `php-mysqlnd`. Not installed by the RPM: the installer does it (§3.0), or see §3.5. Without them the database RPCs refuse cleanly. |

## 3. Installation

### 3.0 The installer (recommended)

On a fresh AlmaLinux 9 host (x86_64, SELinux enforcing recommended) one command
does everything §3.1 to §3.5 and §9.1 describe by hand. The release is a directory
(`make dist` builds it; see §11): the engine RPM, `install.sh`, this handbook and a
`SHA256SUMS` file.

```sh
cd oxpanel-0.2.0-release                 # the directory with install.sh and the RPM
sha256sum -c SHA256SUMS                  # catches a damaged copy (it is not a signature)
sudo ./install.sh                        # interactive: asks the few questions it has
sudo ./install.sh --yes                  # unattended, with the safe defaults
sudo ./install.sh --help                 # every option
```

The script is plain bash: read it before you run it as root. It downloads nothing
by itself. The engine RPM is taken from the command line, else from beside the
script; a dnf repository can be configured in the script (`OXPANEL_REPO_BASEURL`
and `OXPANEL_REPO_GPGKEY`, empty until a release repository exists) or given with
`--repo-url`.

**Stages.** Each is announced, logged to `/var/log/oxpanel-install.log` and says
whether it changed anything. The manual equivalent is in the section named.

| Stage | What it does | By hand |
|---|---|---|
| preflight | root, AlmaLinux 9, x86_64, SELinux mode, 2 GiB free on `/var`; stops if Apache `httpd` is enabled/running or something other than Nginx owns port 80 (`--force` overrides); notes an existing Nginx `default_server` and turns the engine's own off | §2 |
| nodejs | enables the `nodejs:22` module stream, installs `nodejs` and `npm` (an older Node.js already installed is left alone unless `--switch-nodejs`) | §3.2 |
| engine | `dnf install` of the RPM (an upgrade if one is installed; never a downgrade), plus `openssh-server` and `xfsprogs` | §3.1 |
| selinux | the booleans `httpd_enable_homedirs`, `httpd_read_user_content`, `httpd_unified`; loads the `oxpanel` policy module | §3.2 |
| nginx | `nginx -t`, then enable and start | §3.1 |
| mariadb | installs `mariadb-server`, starts it, removes anonymous accounts and the `test` database, writes `/etc/my.cnf.d/oxpanel-local.cnf` (`skip-networking`), restarts; checks there is no listener on 3306. **An already-installed MariaDB is left exactly as it is** (`--harden-existing-mariadb` to harden it) | §3.5 |
| php | `php-fpm`, `php-cli` (scheduled PHP tasks) and `php-mysqlnd`; masks the shared `php-fpm.service` unless it is running (then it warns; `--mask-php-fpm`) | §9 (PHP) |
| panel | optional hook, see below | §5 |
| daemon | enable and start `oxpanel-daemon`; waits for the socket | §3.1 |
| firewall | only if `firewalld` is running: opens `http` and `https` in the default zone, permanent and runtime. A firewall is never stopped or disabled; other firewalls are yours | §2 |
| fail2ban | optional, see below | §9 |
| quota | optional, see below | §9.1 |
| verify | `oxpanel-daemon --check-config`, `oxpanel-ctl host info`, `oxpanel-ctl host reconcile` | §3.4 |

**Idempotent and resumable.** Run it twice and the second run changes nothing and
says so (`RESULT: ok changes=0 …`). If a stage fails (no network, a broken Nginx
configuration) fix the cause and run the same command again: finished stages find
nothing to do and the run resumes at the failure. The outcome of the last run is in
`/var/lib/oxpanel-installer/status` (`result=`, `changes=`, `warnings=`,
`reboot_required=`).

**Questions and unattended use.** Interactive runs ask the questions below. Every
one can be answered on the command line or in an answers file (`--answers FILE`,
lines `key=value`, `#` comments; the keys are `fail2ban`, `epel`, `quota`, `reboot`,
`mariadb`, `php`, `nodejs`, `ignore_ip`, `home_base`, `panel_rpm`, `panel_account`,
`panel_scopes`, `harden_existing_mariadb`, `mask_php_fpm`, `switch_nodejs`; options on
the command line win). `--yes` (or running without a terminal) asks nothing and
takes the safe defaults: **no EPEL, no fail2ban, no change of the boot
configuration, no reboot**, nothing destructive.

```sh
sudo ./install.sh --yes --fail2ban --enable-epel --quota --reboot
printf 'fail2ban=yes\nepel=yes\nquota=yes\nreboot=no\nignore_ip=203.0.113.5\n' > answers
sudo ./install.sh --yes --answers answers
```

**Login banning with fail2ban (optional).** Guards tenants' SFTP passwords and
every other SSH login against guessing. fail2ban is not in AlmaLinux's own
repositories but in **EPEL** (Extra Packages for Enterprise Linux), a community
repository run by the Fedora project. Enabling it adds a package source dnf will
use from then on, for packages Red Hat and AlmaLinux do not vouch for; OxPanel
installs only `fail2ban-server` (and its firewall and SELinux companions) from it,
but the repository stays enabled so fail2ban receives updates
(`dnf config-manager --set-disabled epel` turns it off again). The installer
therefore asks, and without `--enable-epel` (or `epel=yes`) it refuses to install
fail2ban rather than assume. The jail it writes
(`/etc/fail2ban/jail.d/50-oxpanel-sshd.local`, template
`/usr/share/oxpanel/fail2ban/oxpanel-sshd.local`) reads sshd's messages from the
**journal** (no log file, so nothing to label for SELinux), bans an address for an
hour (longer for repeat offenders, up to a week) after 5 failed logins in 10
minutes, and uses firewalld's rich rules when firewalld is running, nftables
otherwise.

*It must never ban you.* The jail's `ignoreip` always contains loopback and the
address of the session that runs the installer (read from sshd's environment of the
installer's process tree; the installer warns if it cannot tell). Add every other
address you administer the host from with `--ignore-ip 203.0.113.5,198.51.100.0/24`
(or edit the `ignoreip =` line in the jail file and `systemctl reload fail2ban`). An
address on the list is never banned, so keep it short. To lift a ban: `fail2ban-client
set sshd unbanip ADDRESS`; to look: `fail2ban-client status sshd`.

**Disk quotas and the reboot (optional).** Per-customer disk limits need XFS user
quotas on the file system that holds the homes (§9.1). XFS turns them on only at
mount time, so the installer must change the boot configuration and a reboot is
unavoidable. It detects which case applies: on the default layout (`/home` on the
root file system) it runs `grubby --update-kernel=ALL --args=rootflags=uquota`; when
the homes are on a file system of their own it adds `uquota` to that file system's
`/etc/fstab` line (a copy is kept as `/etc/fstab.oxpanel-installer.bak`). Nothing is
reformatted or lost. With `--reboot` the installer finishes everything else first
and then reboots; otherwise it prints exactly what remains and records
`reboot_required=yes`:

```
What remains: a reboot, so that disk quotas take effect. Everything else is installed and running.
  1. reboot when it suits you:   sudo systemctl reboot
  2. afterwards run again:       sudo ./install.sh --quota
```

After the reboot run the same command again: it notices that quotas are active,
confirms `disk_quota=true` through the engine and finishes. On a host whose homes
are not on XFS it says so and changes nothing.

**Installing the panel (optional hook).** The panel is a separate product. If you
have its RPM: `sudo ./install.sh --panel-rpm oxpanel-panel-X.rpm`. The installer
installs it and makes sure the `panelapi` account exists and is a member of group
`oxpanel` (§5; the panel's own package normally creates it, the installer repairs or
creates it otherwise). `--panel-account` does only the account. The panel needs all
engine scopes, so none are set; for a deployment that wants fewer,
`--panel-scopes read+vhost` writes `OXPANEL_PEER_SCOPES=<panelapi uid>:read+vhost`
in the installer's block of `/etc/oxpanel/daemon.env` (§5). That block, between the
`# BEGIN oxpanel-installer` and `# END oxpanel-installer` lines, is the only part of
the file the installer writes.

**Upgrading** is the same command with a newer RPM beside the script:
`sudo ./install.sh --yes`. Tenants, sites, limits and records survive (§12).
**Uninstalling:** `sudo ./install.sh --uninstall` (§12).

The sections below are the same steps by hand, and the reference for what the
installer does.

### 3.1 From the RPM

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
git archive --prefix=oxpanel-0.2.0/ -o ~/rpmbuild/SOURCES/oxpanel-daemon-0.2.0.tar.gz HEAD
cp packaging/oxpanel-daemon.spec ~/rpmbuild/SPECS/
rpmbuild -bb ~/rpmbuild/SPECS/oxpanel-daemon.spec
ls ~/rpmbuild/RPMS/x86_64/          # oxpanel-daemon-0.2.0-1.el9.x86_64.rpm (+ debuginfo)
```

**Install on a hosting node**

```sh
sudo dnf install ./oxpanel-daemon-0.2.0-1.el9.x86_64.rpm   # pulls nginx, acl, policycoreutils-python-utils, …
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
sudo dnf install -y gcc git nginx shadow-utils util-linux acl policycoreutils policycoreutils-python-utils libselinux-utils logrotate tar gzip openssl ca-certificates php-fpm php-cli nodejs npm
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
| `OXPANEL_DB_TRASH_DAYS` | `30` | Days a deleted database stays in its tenant's trash before it is purged (1–366); checked at start-up and hourly. |
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
| `OXPANEL_TASK_MAX_PER_TENANT` | `20` | Most scheduled tasks one tenant may have (0–1000; 0 = none). |
| `OXPANEL_TASK_MIN_INTERVAL_MINUTES` | `5` | Shortest "every N minutes" interval a task may have (1–1440). |
| `OXPANEL_TASK_MAX_TIMEOUT_SECS` | `3600` | Longest time limit a task may be given (10–86400; a task's own default is 300). |
| `OXPANEL_PHP_MAX_MEMORY_MB` | `1024` | Highest `memory_limit` a site may set (MiB). The tenant's `MemoryMax` is the real ceiling either way. |
| `OXPANEL_PHP_MAX_UPLOAD_MB` | `256` | Highest `upload_max_filesize` and `post_max_size` (MiB). |
| `OXPANEL_PHP_MAX_EXECUTION_SECS` / `OXPANEL_PHP_MAX_INPUT_TIME_SECS` | `300` / `300` | Highest `max_execution_time` / `max_input_time`. |
| `OXPANEL_PHP_MAX_INPUT_VARS` | `10000` | Highest `max_input_vars`. Lowering any maximum takes effect at the next daemon start (sites are re-rendered clamped). |
| `OXPANEL_BACKUP_SCHEDULES` | `true` | Whether the engine starts scheduled backups at all. `false` keeps every schedule but runs none. |
| `OXPANEL_BACKUP_SCHEDULE_DEFAULT` | `off` | Schedule of tenants that have none of their own: `off`, `daily` or `weekly`. **`daily` is recommended for production** (§9). |
| `OXPANEL_BACKUP_WINDOW` | `01-05` | UTC hours (inclusive) in which the engine places backups whose hour nobody chose. |
| `OXPANEL_BACKUP_SCHEDULE_CHECK_SECS` | `300` | How often the scheduler looks for due backups (5–3600); it also looks at start-up. |
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

# Deleting a database moves it to the tenant's trash (no dump, instant): its
# grants are revoked, the sessions of its users end, the name is free at once.
# It is purged after 30 days (OXPANEL_DB_TRASH_DAYS); the trash does not count
# against the disk limit but is capped (--db-trash, default = the disk limit)
sudo oxpanel-ctl db delete acme_shop          # deleted=true trash_id=t1794571200999 purge_at=1797163200
sudo oxpanel-ctl db trash-list acme
# t1794571200999 acme_shop size=16384 deleted_at=1794571200 purge_at=1797163200 objects=3
# total=16384 cap=5368709120
# Bring it back — always under a NEW name (refused if it exists), with no
# grants: grant it again. Views, triggers, routines and events come back; one
# that cannot be re-created is printed with its reason (and its definition is
# in the API response)
sudo oxpanel-ctl db trash-restore acme t1794571200999 acme_shop2
# restored=acme_shop2
sudo oxpanel-ctl db grant acme_shopapp acme_shop2
# Or empty the trash early: one item, or all of them
sudo oxpanel-ctl db trash-purge acme t1794571200999
sudo oxpanel-ctl db trash-purge acme

# Back up the tenant (home, the engine's records and every database), waiting for the job;
# without --wait it prints the job id at once (`backup job <id>` to look again)
sudo oxpanel-ctl backup create acme --wait
# job=j1794571200123 kind=JOB_KIND_BACKUP tenant=acme backup=b1794571200123 state=JOB_STATE_SUCCEEDED ...
sudo oxpanel-ctl backup list acme
# backup=b1794571200123 tenant=acme state=BACKUP_STATE_READY created_at=1794571200 size=52371 domains=acme.example,shop.acme.example members=db-acme_shop.objects.json:…,db-acme_shop.sql.gz:…,home:home.tar.gz:47101,records:records.json:1112
#   database acme_shop size=16384 dump=db-acme_shop.sql.gz objects=db-acme_shop.objects.json
# Put the files back. You must choose what happens to files that exist now:
# --overwrite replaces them, --keep-existing leaves them and restores only
# what is missing. PHP/apps stop meanwhile; apps get their virtualenv and
# dependencies reinstalled (backups leave node_modules and virtualenvs out).
# --wait exits 5 if the job failed.
sudo oxpanel-ctl backup restore acme b1794571200123 --keep-existing --wait
# restored_entries=12 skipped_entries=40
# site=app.acme.example dependencies_ok=true detail=dependencies reinstalled from package.json
# A database comes back separately from the files, always into a NEW name
# (never over an existing database), without grants
sudo oxpanel-ctl backup restore-db acme b1794571200123 acme_shop acme_shopold --wait
sudo oxpanel-ctl backup delete acme b1794571200123

# Back the tenant up every night by itself (the engine does it, also while the
# panel is down): at 03:MM UTC, the minute chosen by the engine to spread tenants.
# Without --hour the engine picks an hour in OXPANEL_BACKUP_WINDOW.
sudo oxpanel-ctl backup-schedule set acme daily --hour 3
# tenant=acme frequency=daily host_default=false at=03:17UTC weekday=thu(assigned) next_run=1794649020 last_run=0 last_job=- last_result=none enabled_on_host=true
sudo oxpanel-ctl backup-schedule set acme weekly --weekday sun   # or off, or default (the host's)
sudo oxpanel-ctl backup-schedule show acme                       # next run, last result and why

# Scheduled tasks (cron jobs): a script of the tenant's, run as the tenant in its
# limits and sandbox, with a time limit (default 300 s), never twice at once.
# Schedules: "every 15m", "every 2h at :30", "hourly at :05", "daily 03:30",
# "weekly sun 03:30", "monthly 1 03:30" (--tz Europe/Berlin; default UTC).
sudo oxpanel-ctl task set acme wp-cron --url https://acme.example/wp-cron.php --schedule 'every 15m'
sudo oxpanel-ctl task set acme report --php scripts/report.php --arg --full --schedule 'daily 03:30' --tz Europe/Berlin --timeout 600
sudo oxpanel-ctl task set acme sync --python apps/api/sync.py --venv apps/api/.venv --schedule 'every 2h at :10'
sudo oxpanel-ctl task list acme     # last start/end, result (success, exit-code, timeout…), exit status, next run
sudo oxpanel-ctl task run acme report && sudo oxpanel-ctl task log acme report
sudo oxpanel-ctl task delete acme sync

# PHP settings of one site (only these exist; no options = PHP's defaults again).
# The site gets its own PHP pool; Nginx's upload size and timeouts follow.
sudo oxpanel-ctl php set acme.example --memory-limit 256M --upload-max 64M --max-execution-time 120 --timezone Europe/Berlin
# A plan's caps for the tenant (0 / absent = the host maximum)
sudo oxpanel-ctl php limits acme --memory-limit 512M --upload-max 128M

# A final backup kept for 6 months (or --retain-days 1-366) after the
# deletion, then removed automatically
sudo oxpanel-ctl backup create acme --retain-months 6 --wait
sudo oxpanel-ctl backup list-retained
# backup=b1794571300456 tenant=acme state=BACKUP_STATE_READY created_at=... retain_until=1810349000 ...
# After the deletion it is listed with tenant_deleted=true; a new tenant named
# acme never sees it. The customer came back as acme2: restore it there
sudo oxpanel-ctl backup restore-retained b1794571300456 --from acme --to acme2 --overwrite --wait
sudo oxpanel-ctl backup restore-retained-db b1794571300456 --from acme --to acme2 acme_shop acme2_shop --wait
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

# Closing a customer's account in one go: sites, certificates, PHP and
# applications, SFTP access, databases, users and the database trash (dropped
# at once), backups that are not retained, the account and its home. The name
# must be given twice; with --final-backup-days a backup of files and
# databases is taken first and kept that long (1-366 days) — nothing is
# deleted unless it completes. A job: --wait follows it (exit 5 if it failed);
# if the daemon stops meanwhile it continues at start-up, and repeating the
# command completes a deletion that stopped half-way.
sudo oxpanel-ctl tenant delete acme --cascade --confirm acme --final-backup-days 90 --wait

# Without --cascade, deleting a tenant is refused while it still has sites,
# databases, users, trash, backups that are not retained, or a running backup,
# restore or file job:
sudo oxpanel-ctl db user-delete acme_shopapp
sudo oxpanel-ctl db delete acme_shop          # to the trash
sudo oxpanel-ctl db trash-purge acme          # and gone
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
| `/var/lib/oxpanel/tasks/<tenant>.<name>.json` | `root 0600` | scheduled task record: what it runs, schedule, time zone, time limit, on/off |
| `/etc/systemd/system/oxpanel-task-<tenant>-<name>.{service,timer}` | `root 0644` | the task's oneshot service (`User=<tenant>`, in the tenant slice) and its timer (enabled into `timers.target`) |
| `/var/lib/oxpanel/backup-schedules/<tenant>.json` | `root 0600` | a tenant's backup schedule and the scheduler's state (last slot, run, job, result) |
| `/run/oxpanel-php/<username>/<domain>.sock` | `<t>:<t>` + ACL `user:nginx:rw-` | the own pool of a site with PHP settings (the pool section is in the tenant's `/etc/oxpanel-php/<username>.conf`) |
| SELinux hosts | | `semanage fcontext` equivalence `<docroot> = /usr/share/nginx/html` (labels the tree `httpd_sys_content_t`; a plain rule would be overridden by `file_contexts.homedirs`) |
| `/var/lib/oxpanel/dns-zones/<zone>.json` | `root 0600` | DNS zone record: tenant, serial, the tenant's records, DNSSEC on/off |
| `/etc/named/oxpanel/` | `root:named 0750`, files `0640` | OxPanel's BIND configuration (`named.conf`, `zones.conf`, `rndc.conf`) and keys (`rndc.key`, `transfer.key` — secrets) |
| `/var/lib/oxpanel-dns/{zones,keys,data}` | `root:named 0750`; keys `named 0700` | zone files (and the server's signed copies), DNSSEC keys (private halves `named 0600`), the server's working directory; SELinux `named_cache_t` |

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

**Scheduled backups** — the engine starts them itself (`backup-schedule
set`), daily or weekly at a UTC hour and an engine-chosen minute, also while
the panel is down; tenants without their own choice follow
`OXPANEL_BACKUP_SCHEDULE_DEFAULT`, which is `off` as shipped — set it to
`daily` on a production host. They are ordinary backups: the same limits
(one job per tenant, 4 on the host, the free-space reserve) and the same
keep-count, so a series of nightly backups replaces itself; `backup retain`
the one to keep longer. Suspended tenants are backed up too. After the host
was off, the most recent missed slot runs once at start-up. `backup-schedule
show` tells the last result: `failed` with the reason (the next night runs
anyway), `deferred` when the job limit was reached (tried again every check).

**Scheduled tasks** — `task set` writes a oneshot service and a timer per
task (`oxpanel-task-<tenant>-<name>.{service,timer}`); `systemctl
list-timers 'oxpanel-task-*'` shows them all. A task runs as the tenant in its
slice (it counts against the tenant's memory and task limits), in the same
sandbox and SELinux domain as an application, and is killed with everything
it started at its time limit. PHP tasks need `php-cli` (the RPM recommends
it; `host info` shows `php_cli=true`) and use the CLI's `php.ini` — the
per-site PHP settings below apply to the web, not to tasks. Missed runs (the
host was off) are not caught up. Last-run facts come from systemd and start
empty after a reboot; the output stays in the journal (`task log`).

**PHP settings per site** — `php set` changes `memory_limit`,
`upload_max_filesize`, `post_max_size`, `max_execution_time`,
`max_input_time`, `max_input_vars`, `display_errors` and `date.timezone`
for one site, within the host maxima (`OXPANEL_PHP_MAX_*`) and the tenant's
caps (`php limits`). The site gets a pool of its own inside the tenant's FPM
instance, so one site's settings never reach another. They are the defaults
a script starts with, not a security boundary: a script may raise
`memory_limit` with `ini_set` as on any PHP host, and the tenant's
`MemoryMax` is the real limit. `max_execution_time` counts CPU time: a script
waiting on a database or the network is not cut by it (Nginx's FastCGI timeout,
execution time + 30 s, still applies).

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
| `TASK_UNIT_DRIFT` | A scheduled task's service or timer was edited or removed, its timer is enabled although the task is off or the tenant suspended (or the reverse), or a task record names a tenant that does not exist. | Repeat `task set` with the task's settings (or `task delete`). |
| `ORPHAN_TASK_UNIT` | An `oxpanel-task-*` unit that no task record accounts for. | Inspect; `systemctl disable --now` and remove by hand. |
| `ORPHAN_BACKUP_SCHEDULE` | A backup schedule record for a tenant that no longer exists. | Remove `/var/lib/oxpanel/backup-schedules/<tenant>.json`. |

**Backups** — `backup create` starts a job in a transient unit
(`oxpanel-job-<id>.service`, in the tenant's slice, lowest CPU/IO priority)
and returns; the daemon may be restarted meanwhile and picks the job up
again. `tar` runs as the tenant, so files the tenant cannot read (planted by
root, belonging to someone else) are skipped and named in the job's output.
A backup is refused (`RESOURCE_EXHAUSTED`) when the home would not fit with
`OXPANEL_BACKUP_MIN_FREE_BYTES` to spare; at most 4 jobs run on the host and
one per tenant. Only the newest `OXPANEL_BACKUP_KEEP` backups of a tenant are
kept. A tenant with backups cannot be
deleted until they are deleted or *retained* (`backup retain <tenant> <id>
--months 1..12`, or `backup create --retain-months N`): retained backups
outlive the tenant, are hidden from any later tenant of the same name, and
are removed by the daemon when their date passes (at start-up and hourly).
`backup list-retained`, `backup delete … --tenant-deleted` and `backup
restore-retained <id> --from <deleted tenant> --to <tenant>` (needs the
`delete` scope) are the operator's tools for them (`--retain-days 1..366` and
`--days` work as well as months).
Every database of the tenant is in the backup: `mariadb-dump
--single-transaction` (tables, data, views) as root over the socket, inside
the job's sandbox and priorities, plus the triggers, routines and events as
JSON captured by the daemon. A failed dump fails the whole backup. With
databases recorded and MariaDB down, `backup create` is refused. A database
is restored on its own, into a new name only: `backup restore-db <tenant>
<id> <database> <new name>` (or `restore-retained-db` for a deleted tenant's
retained backup). The restored database has no grants. Stored objects are
re-created one by one through the hardened client; one whose definer is not
one of the tenant's users is dropped and listed in the job (`not-recreated`).
Do not feed these dumps to `mariadb` by hand as root unless you trust every
routine in them: see §13.
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
global stays yours; for longer, cross-address bans use fail2ban, which the
installer offers (§3.0: `install.sh --fail2ban --enable-epel`; EPEL is where
fail2ban lives, so enabling it is your decision). Its jail,
`/etc/fail2ban/jail.d/50-oxpanel-sshd.local`, reads the journal (`backend =
systemd`), bans after 5 failures in 10 minutes for an hour, growing to a week, and
lists in `ignoreip` loopback, the installing session's address and whatever you
add: put every address you administer from there, or a typo can lock you out
(`fail2ban-client set sshd unbanip ADDRESS` lifts a ban). By hand: install EPEL
and `fail2ban-server`, copy `/usr/share/oxpanel/fail2ban/oxpanel-sshd.local` to
that path and replace its `@…@` placeholders. `pam_faillock` (`authselect
enable-feature with-faillock`) also works but locks every account after
failures, your own included. Watch `journalctl -u sshd` for
"Failed password for <tenant>".

### 9.1 Disk quotas: preparing the host

Disk limits are XFS user quotas on the file system that holds `/home`. XFS
decides at mount time whether quotas are enforced, so this is a one-time host
change that the installer makes only when asked (`--quota`, §3.0) and the daemon never makes. By hand, on the AlmaLinux default layout
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

### 9.2 DNS hosting: this host as the name server of its customers' domains

With DNS hosting on, the host answers authoritatively for its tenants'
domains: every site gets a zone by itself (for its registrable domain:
`shop.example.co.uk` → `example.co.uk`) with address records pointing at
this host, and customers add their own records (mail, verification, …)
through the panel. The server is BIND, which OxPanel runs as its own
service, `oxpanel-dns.service`, with its own configuration in
`/etc/named/oxpanel` and `/var/lib/oxpanel-dns`; the distribution's
`/etc/named.conf` and `named.service` are not used (leave `named.service`
disabled: both want port 53).

**What you need.** Two name-server host names under a domain you control,
e.g. `ns1.example.net` and `ns2.example.net`; this host's public address(es);
port 53 open for TCP *and* UDP; ideally a second server as secondary (below).

```sh
# The RPM recommends these; install them if they are missing.
sudo dnf -y install bind bind-utils publicsuffix-list
sudo tee -a /etc/oxpanel/daemon.env >/dev/null <<'EOF'
OXPANEL_DNS=true
OXPANEL_DNS_NAMESERVERS=ns1.example.net,ns2.example.net
OXPANEL_DNS_SOA_CONTACT=hostmaster@example.net
# The PUBLIC addresses: behind NAT, not the interface's private address.
OXPANEL_DNS_IPV4=203.0.113.10
OXPANEL_DNS_IPV6=2001:db8::10
EOF
sudo oxpanel-daemon --check-config && sudo systemctl restart oxpanel-daemon
oxpanel-ctl host info | grep ^dns          # dns=true dns_available=true dns_server_running=true …
sudo firewall-cmd --permanent --add-service=dns && sudo firewall-cmd --reload   # 53/tcp and 53/udp
```

At start the daemon writes the server's configuration, generates its keys,
creates zones for the sites that exist, and starts `oxpanel-dns.service`.
`dns_warning=` lines in `host info` tell you what is missing (one name
server only, no secondary, a stock `named.service` running).

**At the registrar of `example.net`** (the domain of the name servers):
register `ns1.example.net` and `ns2.example.net` as *host records* with
**glue** — `ns1` → `203.0.113.10` (this host), `ns2` → the secondary's
address (or this host's again, see below). Inside the zone of `example.net`
the same names need address records: if `example.net` is hosted here,
`oxpanel-ctl dns zone-create example.net --tenant <operator tenant>` and
`dns record-add example.net --tenant … --name ns1 --type a --value 203.0.113.10`
(and `ns2`). **At the registrar of each customer domain**, its name servers
are set to `ns1.example.net` and `ns2.example.net` — nothing else, no glue.
`oxpanel-ctl dns zone-check <zone> --tenant <t>` then reports
`delegation=DELEGATED`; anything else comes with what to change.

**One server as ns1 and ns2.** Both names may point at this host. That
works — resolvers get their answers — but there is no redundancy: when the
host is down, the domains do not resolve at all, including their mail.
Some registrars refuse two names on one address. `host info` flags it.

**A secondary name server** (any BIND, Knot or PowerDNS server; it need not
be an OxPanel host). Zones reach it by NOTIFY and zone transfer signed with
the TSIG key OxPanel generated, and it learns which zones exist from
OxPanel's catalog zone, so it is configured once. On the primary:

```sh
echo 'OXPANEL_DNS_SECONDARIES=198.51.100.20' | sudo tee -a /etc/oxpanel/daemon.env
sudo systemctl restart oxpanel-daemon
# Copy the key to the secondary over a secure channel (it is a secret: root:named 0640):
sudo scp /etc/named/oxpanel/transfer.key root@198.51.100.20:/etc/named/oxpanel-transfer.key
# The secondary transfers over TCP 53 from this host: allow it if the firewall restricts 53.
```

On a BIND secondary (`/etc/named.conf`, AlmaLinux paths; it must listen
publicly and allow queries — `listen-on port 53 { any; }; allow-query { any; };
recursion no;`):

```
include "/etc/named/oxpanel-transfer.key";      // root:named 0640
server 203.0.113.10 { keys { "oxpanel-transfer"; }; };
options {
    // … your options, plus:
    catalog-zones {
        zone "catalog.oxpanel.invalid"
            default-masters { 203.0.113.10 key "oxpanel-transfer"; }
            zone-directory "/var/named/slaves";
    };
};
zone "catalog.oxpanel.invalid" {
    type slave;
    file "/var/named/slaves/oxpanel-catalog.db";
    masters { 203.0.113.10 key "oxpanel-transfer"; };
};
```

Every zone created on the primary appears on the secondary within seconds,
deleted ones go, and signed zones are served signed. A secondary without
catalog support needs a `zone` statement per zone (`oxpanel-ctl dns
zone-list`). `host reconcile` reports a secondary serving an older serial
(`DNS_SECONDARY_DRIFT`); `dns zone-check` shows each server's serial. To
rotate the key: remove `/etc/named/oxpanel/transfer.key`, restart the daemon
(it makes a new one), copy it to every secondary again.

**Zones and records** (what the panel does through the API):

```sh
oxpanel-ctl dns zone-list --tenant acme
oxpanel-ctl dns zone-show acme.example --tenant acme     # every record; the engine's are protected=true
oxpanel-ctl dns record-add acme.example --tenant acme --name blog --type cname --value acme.blogs.example.net
oxpanel-ctl dns record-add acme.example --tenant acme --name @ --type caa --caa-tag issue --value letsencrypt.org
oxpanel-ctl dns record-update acme.example 7 --tenant acme --name blog --type cname --value new.blogs.example.net
oxpanel-ctl dns record-remove acme.example 7 --tenant acme
oxpanel-ctl dns zone-reset acme.example --tenant acme    # only the engine's records remain
oxpanel-ctl vhost set other.example --tenant acme --no-dns   # this domain's DNS stays elsewhere
```

Names are relative to the zone (`@`, `www`, `_dmarc`); host names absolute.
The engine keeps the SOA, the apex NS records and the address records of
the tenant's sites; they cannot be overwritten (to point a site's name at a
CDN, opt the site out with `--no-dns` or drop that name from the site). A
zone created for a site goes with its last site, unless the customer added
records to it: those keep working (its mail, say) until the zone is
deleted (`dns zone-delete`). A suspended tenant's zones keep answering,
unchanged (its sites answer 503); they can be changed again after resume.
`tenant delete` is refused while the tenant has zones.

**Worked example: mail at an external provider.** OxPanel does not host
mail (yet), so no mail records are created by default. For a provider that
gives these values:

```sh
Z="--tenant acme acme.example"
# Mail servers, by priority
oxpanel-ctl dns record-add $Z --name @ --type mx --priority 10 --value mx1.mailhost.example
oxpanel-ctl dns record-add $Z --name @ --type mx --priority 20 --value mx2.mailhost.example
# SPF (one TXT at the apex; long values are split into 255-byte strings by the engine)
oxpanel-ctl dns record-add $Z --name @ --type txt --value "v=spf1 include:_spf.mailhost.example ~all"
# DKIM: either the key as TXT (save the provider's "v=DKIM1; k=rsa; p=…" in a file) …
oxpanel-ctl dns record-add $Z --name s1._domainkey --type txt --value-file dkim-s1.txt
# … or, if the provider hosts the key, a CNAME
oxpanel-ctl dns record-add $Z --name s2._domainkey --type cname --value s2.domainkey.u123.mailhost.example
# DMARC
oxpanel-ctl dns record-add $Z --name _dmarc --type txt --value "v=DMARC1; p=quarantine; rua=mailto:dmarc@acme.example"
# Domain verification and autodiscovery, if the provider asks for them
oxpanel-ctl dns record-add $Z --name @ --type txt --value "mailhost-verification=4f1c2a"
oxpanel-ctl dns record-add $Z --name _autodiscover._tcp --type srv --priority 0 --weight 1 --port 443 --value autodiscover.mailhost.example
# A domain that sends no mail at all: a null MX
# oxpanel-ctl dns record-add $Z --name @ --type mx --priority 0 --value .
dig +short MX acme.example @203.0.113.10       # check
```

An MX must name a host with an address, never a CNAME; an MX pointing at a
name inside the zone needs that name's A/AAAA record first (the server's
checker refuses it otherwise, with its reason).

**DNSSEC.** Per zone; BIND generates the key, signs, and keeps the
signatures fresh by itself (ECDSA P-256, NSEC3):

```sh
oxpanel-ctl dns dnssec acme.example on --tenant acme
oxpanel-ctl dns zone-show acme.example --tenant acme | grep -E 'dnssec=|^ds=|^dnskey='
# dnssec=signed … ds=acme.example. IN DS 29363 13 2 79D3…   ← give this to the registrar
oxpanel-ctl dns zone-check acme.example --tenant acme      # ds_at_parent=1 ds_matches=true once published
```

The key is kept for as long as the zone is signed (no automatic rollover),
so the DS at the registrar never has to change. **Switching off — in this
order:** remove the DS at the registrar; wait until it has expired from
resolvers' caches (its TTL; one to two days to be safe); then
`dns dnssec <zone> off`. The engine refuses while the parent still
publishes the DS (the domain would stop resolving for every validating
resolver), and refuses without `--force` when it cannot check. Switching on
again creates a new key: a new DS for the registrar.

**Switching DNS hosting off** (`OXPANEL_DNS=false`) stops creating and
changing zones but deletes nothing: the server keeps serving the zones that
exist, and tenants owning zones cannot be deleted. Delete the zones first
(`dns zone-list`, then `dns zone-delete <zone> --tenant <t>`, which works
while BIND is installed), then `systemctl disable --now oxpanel-dns`.

**Backups.** Zones are engine records (`/var/lib/oxpanel/dns-zones`), not
tenant files, so tenant backups do not contain them; back up
`/var/lib/oxpanel` (with the rest of the engine's state) and
`/var/lib/oxpanel-dns/keys` (signing keys: a signed zone restored without
them is signed with a new key, i.e. a new DS at the registrar).

**My domain does not resolve — checklist.**

1. `oxpanel-ctl dns zone-check <zone> --tenant <t>`: `delegation=` and the
   `guidance=` line. `ELSEWHERE`/`PARTIAL`: fix the name servers at the
   registrar (changes take up to the parent's TTL, often hours).
   `NOT_FOUND`: the domain is not registered (or misspelt).
2. `dig @<this host's public address> <zone> SOA` from *another* network:
   no answer → port 53 TCP/UDP closed (`firewall-cmd --list-services`,
   cloud security groups) or `oxpanel-dns` not running
   (`systemctl status oxpanel-dns`, `journalctl -u oxpanel-dns`).
3. `REFUSED` for the zone: it does not exist here (`dns zone-list`) or the
   site opted out (`vhost list` shows `dns_zone=opted-out`); a site inside
   another tenant's zone gets no records (`dns_zone=-`).
4. `SERVFAIL` from public resolvers but answers from this host: a DS at the
   registrar that does not match the zone's key (DNSSEC was switched off or
   on again): `dns zone-check` shows `ds_matches=false`; put the current DS
   at the registrar or remove it.
5. The name servers' own names do not resolve: glue missing at the
   registrar of their domain, or no A record for `ns1`/`ns2` in that zone.
6. `host reconcile`: a zone the server does not serve, a secondary behind.

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
| `FailedPrecondition: DNS hosting is not available on this host: …` | The message names what is missing: `OXPANEL_DNS=true` and its settings (§9.2), `dnf install bind`, or `dnf install publicsuffix-list`. |
| A customer's domain does not resolve | See the checklist at the end of §9.2 (`oxpanel-ctl dns zone-check` first). |
| `InvalidArgument: the DNS server rejected the zone: …` | BIND's own checker refused the change (its words follow, e.g. an MX pointing at a name of the zone without an address); nothing was changed or reloaded. |
| `FailedPrecondition: the parent zone still publishes a DS record …` | DNSSEC can only be switched off after the DS is removed at the registrar and has expired from caches (§9.2). |
| SFTP connection is closed before authentication | OpenSSH 9.8+ (AlmaLinux 9.8 ships 9.9) briefly blocks an address after repeated failed logins (`PerSourcePenalties`); it lifts by itself. This applies to the host's whole sshd, not only tenants. |

## 11. Development and testing

```sh
make image         # AlmaLinux 9 dev/test image (one-time)
make check         # rustfmt --check, clippy pedantic -D warnings, tests, cargo-deny, feature traceability, shellcheck of install.sh
make test          # 288 tests (fake OS, no root): unit, property, gRPC surface, crash safety, perf budgets
make traceability  # every row of docs/FEATURES.md maps to tests that exist (docs/traceability.map)
make coverage      # line coverage of the daemon (cargo-llvm-cov; run `make image` once first)
make bench         # engine benchmark against the fake OS (docs/PERFORMANCE.md); never part of `make check`
make integration   # boots systemd in a container, installs from packaging/, runs 681 assertions
                   # (HTTPS/ACME against a local Pebble downloaded at test time; OXPANEL_IT_SKIP_ACME=1 skips it)
make rpm           # build the engine RPM (with oxpanel-acme) from the working tree into dist/rpms/
make rpmlint       # rpm -qpR and rpmlint of that RPM
make dist          # dist/release/: RPM + install.sh + HANDBOOK.md + SHA256SUMS (no tag, no signing, no upload)
make rpm-old       # RPM of an older commit (OLD_REF=d38bae2) for the upgrade acceptance run
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
| `INSTALL=installer` | | Builds the release (`make dist`), copies `dist/release` into the VM, installs firewalld (a host that has a firewall) and runs `install.sh --yes --quota --no-reboot --fail2ban --enable-epel`; asserts the second run changes nothing; phase 15 reboots and runs the installer again. Default phases add 16 (fail2ban) and 95 (uninstall). |
| `INSTALL=upgrade` | | Installs the 0.1.0 RPM (built from `OLD_REF`, default `d38bae2`, by `make rpm-old`) by hand, creates tenants and sites, then upgrades with the release's `install.sh` (phase 12). Default phases `10 12 20 30`. |
| `GIT_REF=<branch or sha>` | current branch | Which commit the git install checks out. CI passes the pushed SHA. |
| `PHASES="10 15 20 30 40 50 60 70 80 90"` | all | Subset of phases (below). |
| `KEEP=1` | | Leave the VM running afterwards; the report prints the `ssh` line (`make acceptance-destroy` removes it). |
| `SOAK_N=20` | | Cycles for the soak phase. |
| `CONTINUE=1` | | Run remaining phases after a failure. |
| `TARGET=user@host` | | Use a machine you provide instead of a VM (`TARGET_KEY=path` for the key). Phases 15/60/70/80/90 reboot it, create accounts and attack them, so this needs `I_UNDERSTAND=1`. |

Phases: **10** install (`dnf install` of the RPM or the handbook's source install; MariaDB set up as in §3.5; services start; `--check-config`) ·
**12** (upgrade mode) upgrade 0.1.0 to the current release with `install.sh`: tenants, sites and limits survive, and the new features (SFTP, databases and their trash, backups, the file manager, deleting the tenant in one step) work on the pre-existing tenant ·
**15** host preparation for disk quotas: runs §9.1's block (in installer mode the installer already did it, and is run again after the reboot), reboots, checks the quota option is on ·
**16** (installer mode) fail2ban: wrong SFTP passwords from one address of a network namespace get it banned, a correct login from another address works, an address on the ignore list is never banned, no AVC denials ·
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
(`docs/PERFORMANCE.md`) ·
**95** (installer mode) `install.sh --uninstall` keeps a tenant's account, home, database, database trash, backup, file-manager job history and site, and installing again finds the tenant with all of them.

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

**Upgrade:** put the new RPM beside `install.sh` and run `sudo ./install.sh --yes`
(§3.0), or install the RPM by hand (`dnf upgrade ./oxpanel-daemon-*.rpm`). The
acceptance rig proves the first path for 0.1.0 to 0.2.0 (`INSTALL=upgrade`: tenants
with a static, a PHP and a Node.js site made with the old engine keep their
accounts, limits and sites, `host reconcile` is clean, and the new features work on
them). The unit restarts automatically and the daemon re-renders its configuration
when it starts, records are versioned (`version` field) and older
records load with defaults for new fields. Backup, restore and file-manager jobs
that are running keep running in their own units and are picked up by the new
daemon; a customer deletion (cascade) that was running continues where it stopped.

**Uninstall the engine, keep the tenants:** `sudo ./install.sh --uninstall` (asks first;
`--yes` to skip the question). It removes the engine package (and the panel package, if
installed) and what the installer itself added (the fail2ban jail file, the repository
file), and **never** touches customers' accounts, homes, databases or backups. It prints
what it left, in short: tenant accounts and homes, `/var/lib/oxpanel` (so installing again
finds every tenant, and the records of jobs in progress, which a reinstalled engine concludes
or continues), MariaDB with its data and its hardening file (and the deleted databases in the
trash, which only the engine purges), `/var/lib/oxpanel-backups`,
`/etc/pki/oxpanel`, the Nginx files of the sites (they keep being served), the sshd drop-in
and the SFTP keys, per-tenant slices, PHP and application units (still running, no longer
manageable; Node.js and Python applications need the OxPanel SELinux module that the
package removal takes out, so they stop until you install again), and all other packages
and firewall rules. By hand:

```sh
sudo systemctl disable --now oxpanel-daemon
sudo dnf remove oxpanel-daemon
# left in place on purpose: /var/lib/oxpanel, /home/<tenants>, /etc/systemd/system/oxpanel-tenant-*.slice,
# /etc/nginx/oxpanel.d, /etc/nginx/conf.d/00-oxpanel.conf, the accounts themselves, /etc/oxpanel/daemon.env,
# the backups in /var/lib/oxpanel-backups
```

**Remove everything:** delete every tenant through the API first (`tenant delete NAME
--cascade --confirm NAME --wait` removes a tenant with its sites, databases, trash, backups
that are not retained and home in one job) — that is the only path
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
- Restoring tenant SQL as root is dangerous. A tenant can write a stored
  routine or trigger whose body makes the `mariadb` client split it
  differently from the server (a `--` followed by a control character is a
  comment to the server, not to the client; `\g` in it sends a statement).
  Replayed by `mariadb-dump --routines | mariadb` as root — the usual
  migration recipe — that runs SQL of the tenant's choosing as root
  (demonstrated on MariaDB 10.5). OxPanel's own dumps leave triggers, routines
  and events out of the SQL and re-creates them safely; if you move databases
  by hand, load dumps with `mariadb --binary-mode --sandbox` and without
  `--routines`/`--triggers`/`--events`, or as an account that holds only the
  target database.
- Report security issues privately to the maintainers, not in public issues.
