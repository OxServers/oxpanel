# SFTP access and disk quotas (M2c) — design

Date: 2026-11-13. Status: implemented on branch `m2c-sftp-quotas`. Revised the same day after
three owner decisions: SFTP passwords are offered (opt-in per tenant),
customers manage their own SFTP access (`vhost` scope), and removing a
credential ends sessions only when asked.

## Goal

Tenants can manage their own files, and the space they use is limited.
Before this, tenant accounts had no way in at all (shell `/sbin/nologin`,
locked password) and nothing bounded their disk use.

## Part 1 — SFTP

### Confinement: one sshd drop-in for a group

The daemon owns `/etc/ssh/sshd_config.d/60-oxpanel.conf` (mode 0600) and
never touches `sshd_config` itself. The drop-in is a single `Match Group
oxpanel-tenants` block followed by `Match all`:

- `AuthorizedKeysFile /etc/oxpanel-sftp/%u` — keys live outside the home.
- `AuthenticationMethods publickey`, `PasswordAuthentication no`,
  `KbdInteractiveAuthentication no`.
- `ChrootDirectory /var/lib/oxpanel/sftp/%u`, `ForceCommand internal-sftp`.
- `DisableForwarding yes` plus the individual `Allow*Forwarding no`,
  `X11Forwarding no`, `PermitTunnel no`, `PermitTTY no`, `PermitUserRC no`.

Every key line in the keys file additionally carries `restrict`, so even an
sshd that ignored the drop-in would grant the key no forwarding and no
terminal.

The drop-in is written atomically, checked with `sshd -t` and only then is
sshd asked to `try-reload-or-restart`; if `sshd -t` fails the previous file
(or its absence) is restored, exactly like `nginx::install_config`. Before a
key is accepted the daemon additionally asks sshd what it would really do
(`sshd -T -C user=<tenant>,…`) and refuses unless the answer is forced
`internal-sftp`, a chroot and a keys file outside the home — this catches a
host whose `sshd_config` does not include the drop-in directory or overrides
the block. The host's own accounts are not affected (checked in the
integration suite with `sshd -T -C user=root`), and the acceptance rig, which
drives the VM over root SSH, would stop working if they were.

The group `oxpanel-tenants` is created by `sysusers.d` and **every** tenant is
put in it with `gpasswd --add` at creation (and at start-up, for tenants
created before this version). The drop-in is installed whenever sshd is
present, not only once a tenant gets a key. This closes a hole that existed
before SFTP: any process of a tenant (a compromised PHP site) could write
`~/.ssh/authorized_keys` and use the host's sshd for port forwarding —
`nologin` does not stop `ssh -N -L`. Now no tenant has a usable
`~/.ssh/authorized_keys`, keys or not. The group grants no file access
anywhere.

### Chroot layout: a root-owned directory with the home bind-mounted in

sshd requires the chroot directory and every component above it to be
root-owned and not group/other-writable. Tenant homes are owned by the tenant,
0700, with ACLs for the web server — and must stay so (PHP, applications,
`disable_symlinks if_not_owner`, the ownership model).

Chosen: per tenant a root-owned directory `/var/lib/oxpanel/sftp/<t>` (0755)
containing `home/<t>` — the home's own absolute path — onto which the real
home is **bind-mounted** by a systemd mount unit
(`var-lib-oxpanel-sftp-<t>-home-<t>.mount`, enabled, `RequiresMountsFor=`
the home). A bind mount is the same inodes, so ownership, ACLs, default ACLs
and SELinux labels of everything uploaded are exactly what they would be for
a file the tenant created any other way: Nginx serves uploads, PHP and
applications read and write them, and their files can be managed over SFTP
without any extra step. Paths look the same inside and outside
(`/home/<t>/public_html`). The mount returns after a reboot because the unit
is enabled; it is created with the first key and removed with the last.
systemd (not the daemon, whose unit forbids mounting) performs the mount.

Rejected:

- *Make the home root-owned with a writable subdirectory* (the classic
  "chroot to `/home/%u`, files in `/home/%u/files`"). Changes the layout of
  every existing tenant, the document-root paths, PHP's `open_basedir` and
  the application units, and the "tenant owns its home" invariant.
- *`ChrootDirectory /home`*. Every component is root-owned already, but a
  tenant could list `/home` and learn every other tenant's name.
- *No chroot*. File permissions alone keep other tenants' homes closed, but
  the tenant could read every world-readable file of the host.
- *A separate SFTP server* (SFTPGo, ProFTPD mod_sftp). Another network
  daemon to install, harden, label and keep in step with the accounts.
- *Bind mounts in `/etc/fstab`*. That file belongs to the operator.

Order matters when access is removed: keys file first (no new logins), then
the tenant's sessions are ended (a session whose working directory is inside
the mount would keep it busy), then the mount is stopped and the empty
directories are removed with `rmdir` — never recursively, so nothing inside a
still-mounted home can ever be deleted through it. The mount unit sets
`LazyUnmount=yes`, so a file still held open in there (by root, or by a session
on a host without logind) cannot make the removal fail; logins are impossible
by then. The `rmdir` runs through `systemd-run` in the host's mount
namespace: a daemon started while a home was mounted holds a copy of that
mount in its own namespace (found by the integration suite after a daemon
restart), which makes the directory busy from inside; an `rmdir` in the host
namespace succeeds and the kernel detaches the stale copy.

### Keys

`AddSftpKey`, `RemoveSftpKey`, `ListSftpKeys`. A key is accepted only as one
`id_*.pub` line, with no options in front: Ed25519, ECDSA (P-256/384/521),
RSA of 2048–16384 bits (the modulus is read from the key), and the FIDO
variants of Ed25519 and ECDSA-P256; DSA is refused. The base64 blob is
decoded and checked field by field against its declared type and re-encoded
canonically; the fingerprint is OpenSSH's `SHA256:` form. At most 20 keys per
tenant. Keys are stored in the tenant record and re-validated whenever they
are written, so a hand-edited record cannot inject a line into the keys file.

The keys file `/etc/oxpanel-sftp/<t>` is `root:root 0640` with an ACL entry
`user:<t>:r--` (sshd reads it with the tenant's uid); the directory is 0711,
so a tenant can read its own file and neither list nor read the others.

### Removing a credential: sessions continue unless asked

(Owner decision.) `RemoveSftpKey` and `ClearSftpPassword` take
`end_sessions` (default false). Without it, the credential cannot start a new
session and running sessions continue; with it, **all** running sessions of
the tenant end (sshd offers no way to tell from outside which credential a
session used). If the last credential goes while a session is still open
(the tenant's `user-<uid>.slice` is active), the chroot mount is left in place
for that session — nobody new can log in — and removed at the daemon's next
start once the session has ended; until then `Reconcile` lists it as
`ORPHAN_SFTP_ACCESS`. Suspension and deletion always end sessions.

### Passwords: offered, opt-in per tenant

(Owner decision; the first version offered keys only.) `SetSftpPassword` /
`ClearSftpPassword`. A tenant has no password until one is set, and it can be
cleared again.

- **Same confinement as keys.** A tenant with a password is also a member of
  a second group, `oxpanel-sftp-password`. The drop-in's first `Match` block
  is for that group and repeats the whole confinement (chroot,
  `internal-sftp`, no forwarding, no TTY) adding only
  `AuthenticationMethods publickey password` and `PasswordAuthentication yes`;
  the tenant block keeps `publickey` only. sshd takes the first value of each
  directive, so password tenants get the password methods and identical
  confinement, and tenants without a password are not even asked for one.
- **Never in argv, logs or records.** The password arrives in the request
  body, is validated (12–256 characters, no control characters — a newline
  would start a second `chpasswd` line; further policy is the panel's) by a
  type whose `Debug` is redacted, and is written to `chpasswd` on **stdin**
  (`CommandSpec::stdin_secret`; never in `display()` or debug logs). Only the
  system hash (`ENCRYPT_METHOD` of `login.defs`, SHA-512 on AlmaLinux 9)
  exists afterwards; the record holds `sftp_password: true`; nothing returns
  it. It is not zeroed in memory after use (Rust strings; no extra
  dependency).
- **No window.** Setting: `chpasswd` first, then (if suspended) `usermod
  --lock`, and only then the group membership that lets sshd ask for a
  password; a suspended tenant is taken out of the group before `chpasswd`.
  Clearing: out of the group first, then the field is set back to `!!` (what
  `useradd` leaves) with `chpasswd -e`, also on stdin.
- **Suspension without the plaintext.** `usermod --lock` prefixes the hash
  with `!`; resumption `usermod --unlock` restores the same hash. Deletion:
  `userdel` removes the shadow entry and group memberships.
- **Sandbox and SELinux.** `chpasswd` and `usermod` write `/etc/shadow`,
  `/etc/gshadow` and their lock files under `/etc`, which the unit's
  `ReadWritePaths=/etc` already allows (as for `useradd`); the daemon reads
  `/etc/shadow` itself to classify the field for Reconcile (never returning
  or logging the hash). No new SELinux rule was needed: the acceptance VM
  ran it enforcing with zero denials.
- **Host-wide switch** `OXPANEL_SFTP_PASSWORDS` (reported as
  `HostInfo.sftp_passwords_allowed`). **Default: allowed**, because the
  owner asked for passwords to be offered and they are opt-in per tenant:
  nothing changes on a host until the panel sets one, and tenants without a
  password are never offered password authentication. Set it to `false` on
  hosts that want keys only: setting a password is refused, the password
  block is left out of the drop-in (so existing passwords stop working at
  once), and `Reconcile` reports every tenant whose record still has one.

**Brute force.** What sshd on AlmaLinux 9.8 (OpenSSH 9.9) already does:
`MaxAuthTries 6` per connection, `MaxStartups 10:30:100` (unauthenticated
connections dropped at random beyond 10, all beyond 100), `LoginGraceTime
120`, and `PerSourcePenalties` (new in 9.8, on by default: an address that
fails authentication is refused for a while — `authfail` 5 s, growing, at
most 600 s, enforced once it reaches 15 s). `pam_faillock` is not enabled by
the default authselect profile. OxPanel's drop-in sets `MaxAuthTries 3` for
both tenant blocks (the directive is allowed in `Match`; `MaxStartups`,
`LoginGraceTime` and `PerSourcePenalties` are global and stay the
operator's). Left to the operator, documented in the handbook: fail2ban (its
`sshd` jail) for longer bans across addresses, or `authselect enable-feature
with-faillock` (which would also lock out the operator's own accounts after
failures — a host decision, not OxPanel's).

### Suspension and deletion

Suspension removes the keys file (the record keeps the keys), locks the
password hash, and ends running sessions by stopping `user-<uid>.slice` — every login session of the tenant
lands there through `pam_systemd`, which is also why the existing
`user-<uid>.slice.d/50-oxpanel.conf` drop-in applies the tenant's limits to
SFTP sessions (verified on the VM: the session process's cgroup is under
`user-<uid>.slice`). Suspension needs nothing from sshd, so a broken sshd
cannot block it. Resumption writes the keys file again; if that fails (sshd
broken at that moment) the sites still come back, the failure is logged and
`Reconcile` reports the missing keys file (a password stays locked until
access is restored). Deletion removes keys file, sessions, mount, unit and
chroot before `userdel`, which removes the password.

This relies on systemd-logind, as every AlmaLinux host has it. Without logind
(the integration container) sessions are not in a user slice and are not
ended by suspension; new logins are refused all the same.

### Reconcile

`SFTP_ACCESS_DRIFT` (keys file or mount unit missing or different from the
record, a keys file present while suspended, an account not in the tenant
group; and for passwords: the password-group membership or the kind of
shadow entry — usable, locked, none, or **empty** — not what the record and
the suspension state say, in either direction, or a recorded password on a
host that forbids them), `ORPHAN_SFTP_ACCESS` (keys files, mount units, chroot directories no
tenant accounts for), `SSHD_CONFIG_DRIFT` (the drop-in missing or edited
while sshd is installed). Whether a mount is currently active is not checked
(Reconcile stays free of commands).

## Part 2 — disk quotas

### What the kernel enforces

An **XFS user quota** on the file system that holds the homes: everything the
tenant's uid owns there counts, whoever wrote it (SFTP, PHP, an application),
and a write beyond the limit fails with `EDQUOT`. Soft and hard limits are
equal (no grace period). `ResourceLimits` gains `disk_max_bytes` (0 or
≥ 1 MiB, rounded down to KiB) and `inodes_max` (0 or ≥ 100), set at creation
and through `UpdateTenantLimits` like every other limit. The kernel's limits
are set for every tenant, including "none", so a uid given to a new tenant
never inherits an old one's limit; deletion clears them. A limit counts as set
only when the report that follows the `limit` command shows it (`xfs_quota`
exits 0 for most failures).

`GetTenantUsage.disk_usage_bytes` comes from the quota report when quotas are
enforced (no tree walk), from `du` otherwise. Note the difference: the quota
figure counts the uid's files anywhere on that file system (for example
PHP's private `/tmp` on a single-file-system host), `du` only the home.

`xfs_quota` needs the block device, which the daemon's sandbox
(`PrivateDevices=yes`) deliberately hides. It therefore runs in a transient
unit (`systemd-run --wait`), like the dependency installers, with its output
in a root-only file under `/run/oxpanel/scratch` that the daemon reads back.

### What OxPanel requires from the host, and what it does itself

XFS decides at mount time whether quotas are enforced; for the root file
system that means the kernel argument `rootflags=uquota` and a reboot, for a
separate `/home` the `uquota` mount option in `/etc/fstab`. The daemon never
remounts anything or edits `/etc/fstab` or the boot loader. It reads the mount
table and reports what it sees in `GetHostInfo` (`disk_quota_available`,
`disk_quota_detail`); a request that carries a disk limit on a host that does
not enforce quotas is refused with `FAILED_PRECONDITION` and the exact
change to make, before anything is created or recorded. Limits without a disk
part work everywhere. If a host stops enforcing quotas later (booted without
the option), `Reconcile` reports every tenant whose record has a disk limit
(`DISK_QUOTA_DRIFT`), as it does when the kernel's limits differ from the
records. The handbook (§9) has the preparation, and the acceptance rig
performs it from the handbook's block (phase 15) before the integration
suite, so a tenant really hits `EDQUOT` on the real VM.

Rejected: XFS **project** quotas (limit a directory tree rather than an
owner). They would also catch files a tenant does not own inside its home,
but need a project id per home, `/etc/projects` bookkeeping, inheritance
flags on every directory and the `pquota` option; ownership is already the
unit of isolation here. **ext4** quotas need `quotacheck` and the quota
tools and are not the AlmaLinux default; they can be added behind the same
check.

## API numbers used

`ResourceLimits` 5–6, `Tenant` 11 (`sftp_key_count`) and 12
(`sftp_password`), `HostInfo` 24–27, `DriftKind` 18–21, five new RPCs and
their messages at the end, `RemoveSftpKeyRequest.end_sessions` 3.

Scopes (owner decision): customers manage their own SFTP access, so
`AddSftpKey`, `RemoveSftpKey`, `SetSftpPassword` and `ClearSftpPassword`
need the `vhost` scope and `ListSftpKeys` `read`. Scopes are per RPC class,
not per object: a peer with `vhost` can manage the SFTP access of any
tenant, exactly as it can configure any tenant's virtual hosts; confining it
to its own tenant is the panel's job (as for virtual hosts).

## Not included

Per-key session termination; password policy beyond length (the panel's);
zeroing passwords in memory; SFTP-specific logging/auditing
(`internal-sftp -l`); a read-only mode; FTP/FTPS; SSH shell access of any
kind; ext4 or project quotas; inode usage in `GetTenantUsage`; quota grace
periods and warnings.

## Verification

132 unit tests and 6 gRPC end-to-end tests (fake OS, exact argv), the root
integration suite in the systemd container (SFTP end to end with a real sshd;
quotas only as the refusal path, the container has no XFS), and
`INSTALL=rpm make acceptance` on AlmaLinux 9.8 with SELinux enforcing: all
phases pass with zero AVC denials, including real `sftp` logins with keys,
uploads served by Nginx and used by PHP, the refused shell and forwards, the
chroot showing nothing but the home, suspension ending a live session that
ran in the tenant's `user-<uid>.slice`, key removal, deletion, a write and an
SFTP upload failing on the quota, an inode limit, and SFTP access and a disk
limit surviving a reboot.

One finding from the VM: OpenSSH 9.9 (`PerSourcePenalties`) briefly drops
connections from an address after repeated failed logins; the test suite
retries positive logins and requires refusals to be "Permission denied".
