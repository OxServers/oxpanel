# Engine management milestone (M1) — design

Date: 2026-11-13. Status: implemented on branch `m1-engine-management`.

## Why

The engine could create and delete tenants and virtual hosts, but a panel also
has to *run* them: resize a plan, move a customer between resellers, suspend
for non-payment, show usage and host capacity, and notice when the host no
longer matches its records. It also had one trust level: any authorised peer
could call `DeleteTenant`. This milestone closes those gaps so the panel API
(M3) has a complete management surface to build on.

## What was added

| RPC | Scope | Behaviour |
|---|---|---|
| `UpdateTenantLimits` | tenant | Full replacement of limits. Record first, then both unit files + `daemon-reload`; a retry re-applies the files even when the record already matches. |
| `UpdateTenantOwner` | tenant | Record-only. Empty clears. |
| `SuspendTenant` / `ResumeTenant` | tenant | Re-render all of the tenant's vhosts (503, `Retry-After`, no `root`), one `nginx -t`, one reload, roll back every file on rejection. Record saved *after* activation; while the flag differs the retry forces a reload even if the files are already on disk. |
| `GetTenantUsage` | read | `systemctl show` on the tenant slice and `user-<uid>.slice` (summed) + `du --summarize --one-file-system --block-size=1`. |
| `GetHostInfo` | read | Version, SELinux, counts, uid range, load/memory/uptime via `sysinfo(2)`, home file system via `statvfs`. |
| `Reconcile` | read | Read-only drift report under the mutation lock; nine drift kinds. |

`Tenant.suspended` (field 10) and the record field `suspended` default to
false, so existing records and clients keep working.

Per-peer scopes: `OXPANEL_PEER_SCOPES=uid:scope+scope,…` with scopes `read`,
`vhost`, `tenant`, `delete`, `all`. Listed uids are confined; unlisted uids are
unrestricted (backwards compatible). Checked in `server.rs` before validation.

## Decisions

- **Suspension is a web-serving state only.** Tenants have no processes or
  logins yet. When M2 adds PHP-FPM and SFTP, suspension must also stop the
  tenant slice and refuse logins.
- **Host figures come from syscalls, not `/proc`.** The unit runs with
  `ProcSubset=pid`, so `/proc/loadavg` and `/proc/meminfo` are not visible;
  weakening the sandbox for a dashboard number was rejected.
- **Reconcile reports, never repairs.** Repair would mean deciding to delete or
  overwrite things the daemon cannot prove it owns. Most findings are healed by
  repeating the original request; a repair mode is a later, separate design.
- **Scopes are per RPC class and per uid, not per object or owner.** Object
  level authorisation stays in the panel API, which is the only component that
  knows users. Per-owner confinement can be added without breaking the format.
- **One definition of "what should be on disk"**: `vhost::render_vhost` is
  used by suspension and by reconciliation, so they cannot disagree.
- **New external program:** `/usr/bin/du` (coreutils, already a dependency).
  No new `ReadWritePaths`, capabilities or syscalls were needed.

## Verification

`make check`, `make integration` (132 checks) and `INSTALL=rpm make acceptance`
on AlmaLinux 9 with SELinux enforcing.
