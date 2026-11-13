# Installer and release packaging: design record

Date: 2026-11-13. Stream: `m3-installer`. Base: `m2-integration`.

## What and why

Installing OxPanel meant following HANDBOOK section 3 by hand, and every feature
stream had added its own steps (Node.js module stream, SELinux booleans and
module, MariaDB hardening, masking the shared PHP-FPM pool, the quota boot
argument). `install.sh` turns that into one command on a fresh AlmaLinux 9 host,
and the engine gets a releasable package set (`make dist`).

## The installer

One bash script (`set -euo pipefail`, shellcheck-clean, no downloads of its
own). It runs a **preflight**, then asks every question it has up front, then
runs **stages**, each logged to `/var/log/oxpanel-install.log` and announced on
the terminal: `nodejs`, `engine`, `selinux`, `nginx`, `mariadb`, `php`, `panel`,
`daemon`, `firewall`, `fail2ban`, `quota`, `verify`.

### Idempotent and resumable

Stages never consult a "done" record. Each one looks at the host (is the module
stream enabled, is the boolean on, is the SQL already applied, does the file
already have exactly this content) and acts only on the difference. Running the
script twice therefore changes nothing the second time, and after a failed
stage the same command resumes: finished stages find nothing to do, the failed
one tries again. Each stage that changes something prints `changed: ...`; the
run ends with `RESULT: ok changes=N warnings=W reboot_required=yes|no` and the
same in `/var/lib/oxpanel-installer/status`. The acceptance rig asserts
`changes=0` on a second run.

A stage runs in a subshell with `set -e`; what one stage tells another (the
daemon must restart, a reboot is needed) goes through flag files.

### Where the RPM comes from

Command line (`--rpm FILE` or a bare argument), else `oxpanel-daemon-*.rpm`
beside the script (newest by version), else a dnf repository. The repository
URL and its GPG key URL are two variables at the top of the script,
`OXPANEL_REPO_BASEURL` and `OXPANEL_REPO_GPGKEY`, **left empty on purpose**: no
URL has been decided or published. When set (or `--repo-url`), the script writes
`/etc/yum.repos.d/oxpanel.repo` with `gpgcheck=1`; it refuses a repository
without a key. A local RPM is checked against `SHA256SUMS` beside it when there
is one (that file protects against damage, not against tampering; it is not a
signature, and the script says so). It never installs an older RPM over a newer
one.

### Questions and the unattended rule

Questions: fail2ban, EPEL (only if fail2ban was chosen and EPEL is absent),
addresses that must never be banned, disk quotas (only if the home file system is
XFS without quotas), automatic reboot (only if quotas were chosen). Each can be
answered by flag (`--fail2ban`, `--enable-epel`, `--ignore-ip`, `--quota`,
`--reboot` and their `--no-` forms) or by an answers file (`key=value`, parsed,
never sourced; flags win). `--yes` (or no terminal) asks nothing and the defaults
are all "no": no EPEL, no fail2ban, no boot change, no reboot. Asking for fail2ban
without allowing EPEL when EPEL is absent stops the run **before** any change.

### Decisions about existing things (the "never destroy" rule)

- An existing **MariaDB** is left exactly as it is (no anonymous-account or
  test-database cleanup, no `skip-networking`, which could break an application)
  unless `--harden-existing-mariadb`. A MariaDB that the installer installed
  itself is recognised by a marker file and hardened on every run.
- A **running shared `php-fpm.service`** is not masked (something may use it):
  warning, and `--mask-php-fpm` to do it. A fresh install masks it, as the handbook
  says.
- An older **Node.js** is not replaced unless `--switch-nodejs`.
- A **default_server** already defined in the Nginx configuration makes the
  installer set `OXPANEL_NGINX_DEFAULT_SERVER=false` (as `daemon.env` documents)
  inside a marked block in `daemon.env`; the block is the only part of that file
  the installer ever writes.
- **firewalld** is touched only if it is running, only to open `http` and `https`
  in the default zone (permanent and runtime). It is never stopped or disabled;
  another firewall is left alone with a message.
- **httpd** enabled/running, or something else on port 80: stop, unless `--force`.

### fail2ban

fail2ban is in EPEL, not in the base repositories. The question explains what
EPEL is (a Fedora-run community repository, not vouched for by AlmaLinux, which
stays enabled afterwards so fail2ban gets updates) and what it costs; the answer
is never assumed. The jail (`packaging/fail2ban/oxpanel-sshd.local`, shipped in
the RPM under `/usr/share/oxpanel/fail2ban/`, installed by the script to
`/etc/fail2ban/jail.d/50-oxpanel-sshd.local` with placeholders filled in):

- `backend = systemd` with `journalmatch = _SYSTEMD_UNIT=sshd.service + _COMM=sshd`:
  the journal is the source, nothing reads `/var/log/secure`, so no file-label
  problems under SELinux enforcing (fail2ban's own policy domain reads the
  journal; the rig checks for denials).
- `maxretry = 5`, `findtime = 10m`, `bantime = 1h` growing (`bantime.increment`) to
  a week. Five, because OxPanel's drop-in already limits a connection to three
  password tries and sshd's own `PerSourcePenalties` slows an address down first;
  the jail adds the memory sshd lacks across connections and restarts.
- The jail name is `sshd` (what the handbook told operators to enable), so
  `fail2ban-client status sshd` is what operators expect.
- Ban action: `firewallcmd-rich-rules` when firewalld is running, otherwise
  `nftables-multiport`. The packages installed are `fail2ban-server`, the matching
  action package, and `fail2ban-selinux` on SELinux hosts, not the `fail2ban`
  meta-package (which pulls a mail server).
- **Never bans the operator:** `ignoreip` always has loopback and the address of
  the session that runs the installer (found from `SSH_CONNECTION` of the process
  or its ancestors, because sudo drops it, with `who -m` as fallback), plus
  `--ignore-ip`. If the address cannot be determined, a warning says so. An
  address on the list is never banned, so the list is the operator's to keep short;
  documented in the jail file and the handbook.

Tested on the VM through a network namespace and a veth pair, so the traffic is
not loopback and the ban rule really applies: wrong SFTP passwords from one
address get it banned (firewall rich rule present, even the right password is
then refused), a right password from another address works, an address on the
ignore list fails six times and is not banned.

### Disk quotas and the reboot

XFS enforces user quotas only if mounted with `usrquota`, so the setting is a boot
change. The stage finds the file system holding the home base (`--home-base`, else
`OXPANEL_HOME_BASE`, else `/home`), and:

- not XFS: says disk limits are unavailable here, changes nothing;
- already `usrquota`: "active", done;
- on `/`: `grubby --update-kernel=ALL --args=rootflags=uquota` (merging with an
  existing `rootflags=` rather than adding a second one);
- on a file system of its own: `uquota` is added to its `/etc/fstab` line (a copy
  `/etc/fstab.oxpanel-installer.bak` is kept; if there is no fstab line, it stops
  and tells the operator what to add).

Either way a reboot is needed; the installer finishes everything else first. With
`--reboot` it then reboots; otherwise it prints exactly what remains (reboot, then
run the same command again) and records `reboot_required=yes`. After the reboot,
the second run sees `usrquota`, reports "user quotas are active", and verifies
`disk_quota=true` through the engine. A kernel argument that is set but not yet
booted is recognised as "waiting for a reboot" even without `--quota`.
There is no live `mount -o remount`: XFS cannot turn quotas on that way.

### Uninstall

`--uninstall` asks (or needs `--yes`; with no terminal and no `--yes` it does
nothing), removes the panel package if present, the engine package (RPM `%postun`
takes the SELinux module out) and the installer's own additions (the fail2ban jail
file, the repository file), and prints what it left: tenant accounts and homes,
`/var/lib/oxpanel` (so a reinstall resumes from the records), databases and the
hardening file, backups, certificates and keys, the Nginx files of the sites, the
sshd drop-in and SFTP keys, running per-tenant units, the installed packages
(Nginx, MariaDB, PHP-FPM, Node.js, fail2ban, EPEL) and firewall rules. Leaving the
site files is deliberate: removing them would take every customer's site offline,
which is more than "uninstall the engine". One consequence is spelled out in the
output: Node.js/Python applications need the SELinux module, which the package
removal takes out, so they stop working until a reinstall.

### Panel hook

The panel is a separate, proprietary product. `--panel-rpm FILE` installs it (name
must start with `oxpanel-panel`, checksum checked like the engine's) and makes
sure the `panelapi` account exists in the group `oxpanel` (the panel's own
sysusers file normally creates it; the installer repairs or creates it otherwise).
`--panel-account` does only that. `--panel-scopes read+vhost` writes
`OXPANEL_PEER_SCOPES=<uid of panelapi>:read+vhost` in the installer's block of
`daemon.env`; the default is no scopes, because the panel's README says it needs
all four. If the operator already has an `OXPANEL_PEER_SCOPES` line the installer
does not add a second, and says what to add by hand. Tested here without the panel
RPM: the account part, and the scope line.

## Release packaging

- Version 0.2.0 in `Cargo.toml`/`Cargo.lock`, the RPM spec (with a changelog entry
  summarising `docs/FEATURES.md`), `INSTALLER_VERSION`, FEATURES and the handbook.
  `scripts/make-dist.sh` refuses a release where the three versions differ.
- `make rpm` builds the engine RPM; `oxpanel-acme` is already part of it
  (`/usr/libexec/oxpanel/oxpanel-acme`). The spec also ships the fail2ban jail
  template. `make rpmlint` prints `rpm -qpR` and `rpmlint`.
- `make dist` collects the RPM (not the debuginfo/debugsource packages),
  `install.sh`, the handbook, the licence, a short `README.txt` and `SHA256SUMS`
  in `dist/release/`. Nothing is tagged, signed or uploaded.

## Acceptance

`INSTALL=installer make acceptance`: build the release, fresh VM, install
firewalld (a host with a firewall), run `install.sh --yes --quota --no-reboot
--fail2ban --enable-epel`, check the second run changes nothing, let phase 15
reboot and run the installer again, then all the existing phases, plus phase 16
(fail2ban) and phase 95 (uninstall, keep data, reinstall). `INSTALL=upgrade make
acceptance`: install the 0.1.0 RPM built from `d38bae2` by hand, create tenants
with a static, a PHP and a Node.js site, run the release's `install.sh`, and check
that everything survives and the new features work on the old tenant (phase 12).
`INSTALL=rpm` and `INSTALL=git` are unchanged.

## Alternatives rejected

- *A `curl | sh` bootstrap.* Not wanted; the installer downloads nothing itself.
- *State markers per stage.* A marker can lie about a host changed by hand; looking
  at the host cannot.
- *Python or Rust installer.* Bash is what an operator can read before running it
  as root, and the dependencies are `dnf`, `systemctl` and `grubby`.
- *Hardening an existing MariaDB by default.* Destructive for someone else's
  applications; opt-in.
- *fail2ban's `[sshd]` jail with the stock log-file backend.* Needs
  `/var/log/secure` (rsyslog) and its labels; the journal needs neither.
- *Reboot by default with `--yes`.* Never without being told.

## Not included

Fetching a release (no URL exists), RPM signing, other distributions, aarch64,
installing a panel without its RPM, an interactive TUI, rolling back a failed
upgrade, shipping the installer inside the RPM. The fstab variant of the quota
change is exercised on a loopback XFS image, not on a machine that really has a
separate `/home` at boot.
