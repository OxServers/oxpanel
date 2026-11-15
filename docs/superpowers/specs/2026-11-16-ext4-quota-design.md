# Disk limits on ext4 homes — design note (not implemented)

Date: 2026-11-16. Status: **assessed, not implemented** in engine 0.3.2.
Written in the usability release (item 8) because real hosts — the owner's
test VPS among them — have their homes on ext4, where `GetHostInfo` reports
`disk_quota=false` and every tenant disk limit is refused.

## Verdict: not a contained change

Today `quota.rs` is XFS only: availability is "the home file system is `xfs`
and mounted with `uquota`", limits are set and read with `xfs_quota -x -c …
<device>` in a transient unit, and the installer's quota stage knows only the
XFS boot setting (`rootflags=uquota` / `uquota` in fstab). ext4 differs at every
one of those points:

| Point | XFS (today) | ext4 (needed) |
|---|---|---|
| Accounting switched on | mount option `uquota`; for `/` only at boot (`rootflags=`) | either the `quota` file-system feature (`tune2fs -O quota`, **only on an unmounted file system**) or classic quota files `aquota.user` created by `quotacheck`; enforcement by mount option `usrquota` plus `quotaon` |
| Tool | `xfs_quota` (xfsprogs, always installed) | `setquota`, `repquota`, `quotacheck`, `quotaon` (package `quota`, not installed by default) |
| Units / output | KiB blocks; `report -u -n -N -b -i` | KiB blocks for `setquota`; `repquota` output has its own columns (grace columns, `+-` flags) |
| Boot | the kernel argument decides | `systemd-quotacheck.service` and `quotaon.service` run at boot for fstab lines with `usrquota` |
| SELinux | nothing new | quota files are `quota_db_t`; `quotacheck`/`quotaon` are `quota_exec_t` and transition to `quota_t`; behaviour from a transient unit started by the daemon is unproven |
| Proof | phase 15 (root XFS, reboot) and phase 17 (XFS loop file) | a new acceptance disk: an ext4 file system for homes on the VM |

That is a second backend in the engine, a second path in the installer, a new
package, new SELinux questions only the VM can answer, and a new acceptance
phase. It does not fit a usability release whose other items must stay small
and proven; it is planned here so it can be its own stream.

## Approach

### Accounting: classic journalled quota files, not the `quota` feature

The `quota` feature (hidden quota inodes, always consistent) is the better
mechanism, but enabling it needs `tune2fs -O quota` on an **unmounted** file
system. For `/` that means a rescue boot — not something an installer can do
on a customer's VPS. Classic journalled quota files work on a mounted file
system, need no reboot, and are what every ext4 hosting panel uses:

- fstab options: `usrjquota=aquota.user,jqfmt=vfsv1` (journalled: consistent
  after a crash, no `quotacheck` at every boot). Where the operator already
  enabled the `quota` feature (`tune2fs -l` lists `quota` in its features), only
  `usrquota` is added and no quota file is created; the engine accepts both.
- Switched on without a reboot: `mount -o remount <mountpoint>` (fstab is read),
  `quotacheck -cum <mountpoint>` (creates and fills `aquota.user` from the
  current usage; `-m`: without remounting read-only), `quotaon -u <mountpoint>`.
  Unlike XFS, the root file system needs neither `rootflags=` nor a reboot.
- At boot, systemd's generator sees `usrjquota` in fstab and runs
  `systemd-quotacheck.service` (only when needed) and `quotaon.service`.

### Engine: a backend per file system type

`quota.rs` gets a `QuotaBackend` (enum, not a trait object — two variants)
chosen by `availability()`:

- **Availability (ext4).** From `/proc/self/mountinfo` as today: `fs_type ==
  "ext4"` and the super options contain `usrquota` or `usrjquota=…`, and the
  kernel reports quotas *on* — read with `quotaon -p -u <mountpoint>` (exit 0
  and "is on") run like `xfs_quota`, outside the sandbox. A mounted-with-option
  but not-switched-on file system is reported as such ("run `quotaon -u /`, or
  the installer's quota stage"), never as available. `setquota` missing →
  "install the package `quota`".
- **Setting a limit** (argv, in a transient unit as `xfs_quota` is today,
  because `quotactl()` needs the block device and the daemon has
  `PrivateDevices=yes`):
  `systemd-run --wait --collect --quiet --property=StandardOutput=truncate:<scratch> -- /usr/sbin/setquota -u <uid> <blocks> <blocks> <inodes> <inodes> <mountpoint>`
  (soft = hard, as on XFS; `0 0 0 0` clears, so a reused uid never inherits).
  The uid is numeric (never a name: `-n` semantics are implicit with a number
  in `setquota`). Followed, as on XFS, by a report for the uid; the limit counts
  as set only when the report shows it.
- **Reading usage**: `/usr/sbin/repquota -u -n -p -O csv <mountpoint>` (quota
  4.06 on AlmaLinux 9 has `-O csv`: no column guessing; `-n`: numeric uids;
  `-p`: grace as seconds). Parsed into the same `QuotaRow`. If `-O csv` turns
  out to be unavailable, the plain format is parsed with a test copied from a
  real host, as was done for `xfs_quota`.
- `bin::SETQUOTA`, `bin::REPQUOTA`, `bin::QUOTAON` (absolute paths) and
  FakeSystem tests asserting each argv, the parse of a real `repquota` output,
  and "a limit the kernel does not show is an error".
- Nothing else changes: `require_available`, `apply`, `clear`, `usage`,
  `report_all` and Reconcile's quota drift keep their signatures; the backend
  is an argument.

The unit needs nothing new for the tools themselves (they run outside the
sandbox), but the scratch output files and `systemd-run` are already allowed.

### Installer: the quota stage learns ext4

`check_quota_offer` and `stage_quota` branch on the home file system type:

1. `dnf -y install quota` (AppStream; no EPEL).
2. fstab: add `usrjquota=aquota.user,jqfmt=vfsv1` to the line of the home
   file system (root or its own), with the same backup and awk edit as the XFS
   `uquota` path; refuse (with the reason) when there is no fstab line (a
   systemd `.mount` unit) — the operator does it by hand, HANDBOOK 9.1.
3. `mount -o remount <mountpoint>`, `quotacheck -cum <mountpoint>`,
   `restorecon <mountpoint>/aquota.user` (it must be `quota_db_t`),
   `quotaon -u <mountpoint>`.
4. `oxpanel-ctl host info` must then say `disk_quota=true`; no reboot is
   required, so `reboot_required=no` on ext4.
5. `--uninstall` keeps the fstab option and the quota file (customers' data
   path; the operator decides), and lists them as kept.

## Risks

- **SELinux.** `quotacheck`/`quotaon` from a transient unit started by the
  daemon (`init_t` → `quota_t` transition?), `quota_db_t` on `aquota.user`,
  and `setquota`/`repquota` reading the device: unproven until the VM runs it
  enforcing. Mitigation: the installer (unconfined, root) does `quotacheck` and
  `quotaon`; the engine only runs `setquota`, `repquota` and `quotaon -p`. Any
  rule needed goes into `oxpanel.cil`, narrowly, with a comment.
- **`quotacheck` on a busy file system** counts while files change; usage may
  be slightly off until the next `quotacheck`. Journalled quotas stay correct
  from then on. Done once, at installation.
- **Hosts that already use quotas** (another panel, old files): an existing
  `aquota.user` is not recreated (`quotacheck -cum` refuses to overwrite? —
  verify; if it does overwrite, the installer refuses and explains instead).
  "Own it or leave it": limits of uids that are not tenants are never touched;
  the engine only sets limits of uids it created.
- **Grace periods.** Soft = hard means no grace; the default grace of the file
  system is irrelevant and is not changed.
- **Mixed hosts.** `OXPANEL_HOME_BASE` on XFS and ext4 at once is not possible
  (one home base); a later change of the home file system type changes the
  backend at the next start, which is correct.

## Tests

- Unit (FakeSystem): availability for ext4 with/without the option, with the
  option but quotas off, with the tool missing; exact argv of `setquota`,
  `repquota`, `quotaon -p`; parsing of real `repquota -O csv` output (and
  plain, if needed); a limit the report does not show is an error; clearing on
  a reused uid.
- Integration (container): the container's file system is overlay — the ext4
  path is shown unavailable with the right reason (no enforcement possible
  there, as today for XFS).
- **Acceptance: a new phase `17b-quota-ext4.sh`**: a 512 MiB file
  (`/var/et.img`), `mkfs.ext4`, mounted at `/mnt/et` through an fstab line,
  daemon switched to `OXPANEL_HOME_BASE=/mnt/et` (as phase 17 does for the XFS
  loop file), `install.sh --yes --quota --home-base /mnt/et --only quota`;
  then: `disk_quota=true` without a reboot; a tenant with a 20 MiB limit cannot
  write a 25 MiB file (`EDQUOT`) over SFTP or as the tenant; usage reported by
  `GetTenantUsage` matches `du`; clearing the limit works; a second installer
  run changes nothing; `aquota.user` is `quota_db_t`; **zero AVC denials**;
  teardown restores the daemon's home base and removes the loop file. A reboot
  phase variant (fstab line survives, `quotaon.service` switches quotas on at
  boot) can reuse phase 60's reboot.
- The real test VPS (ext4 root) is the final proof, done by the owner.

## Estimate

About a week of one stream: engine backend and tests 2–3 days, installer 1 day,
acceptance phase and SELinux on the VM 1–2 days, docs (HANDBOOK 9.1, FEATURES,
traceability) half a day.

## Not included (even then)

Group quotas, project quotas, per-directory limits, quotas for databases
(MariaDB data lives outside the homes), Btrfs or other file systems.
