# SFTP access and disk quotas (M2c) — design

Date: 2026-11-13. Status: implemented on branch `m2c-sftp-quotas`.

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
by then.

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

Removing a key ends **all** running sessions of the tenant, not only those of
that key (sshd offers no way to tell them apart from outside).

### Passwords: not offered

Key authentication only. Passwords would need brute-force protection
(fail2ban or similar), a way to deliver them that keeps them out of argv and
logs (`chpasswd` on stdin), and they are what gets reused and phished. The
panel can generate a key pair for customers who have none. If passwords are
wanted later, the drop-in's `AuthenticationMethods` is the single switch and
the account already has a (locked) password field.

### Suspension and deletion

Suspension removes the keys file (the record keeps the keys) and ends running
sessions by stopping `user-<uid>.slice` — every login session of the tenant
lands there through `pam_systemd`, which is also why the existing
`user-<uid>.slice.d/50-oxpanel.conf` drop-in applies the tenant's limits to
SFTP sessions (verified on the VM: the session process's cgroup is under
`user-<uid>.slice`). Suspension needs nothing from sshd, so a broken sshd
cannot block it. Resumption writes the keys file again; if that fails (sshd
broken at that moment) the sites still come back, the failure is logged and
`Reconcile` reports the missing keys file. Deletion removes keys file,
sessions, mount, unit and chroot before `userdel`.

This relies on systemd-logind, as every AlmaLinux host has it. Without logind
(the integration container) sessions are not in a user slice and are not
ended by suspension; new logins are refused all the same.

### Reconcile

`SFTP_ACCESS_DRIFT` (keys file or mount unit missing or different from the
record, a keys file present while suspended, an account not in the tenant
group), `ORPHAN_SFTP_ACCESS` (keys files, mount units, chroot directories no
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

`ResourceLimits` 5–6, `Tenant.sftp_key_count` 11, `HostInfo` 24–26 (27 free),
`DriftKind` 18–21, three new RPCs and their messages at the end. Key
management requires the `tenant` scope (`ListSftpKeys`: `read`): a customer
tier confined to `read+vhost` cannot give anyone a login.

## Not included

Passwords; per-key session termination; SFTP-specific logging/auditing
(`internal-sftp -l`); a read-only mode; FTP/FTPS; SSH shell access of any
kind; ext4 or project quotas; inode usage in `GetTenantUsage`; quota grace
periods and warnings.
