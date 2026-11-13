# OxPanel — Architecture & Engineering Specification

## 1. Overview

OxPanel is a hosting control panel for enterprise Linux, designed as a
memory-safe, least-privilege alternative to legacy panels. It is delivered
open-core:

- **`oxpanel-daemon`** (open source, this repository): the root-privileged system
  engine. Owns accounts, homes, cgroups-v2 limits (via systemd), Nginx virtual
  hosts and SELinux labelling. Exposes a small gRPC API on a local UNIX socket.
- **`oxpanel-proto`** (open source): the API contract, `oxpanel.v1`, consumed by
  every client including the proprietary panel.
- **panel-api & UI** (proprietary, separate repository): React front end and Go
  API. Holds all commercial logic. Talks to the daemon over the socket as the
  `oxpanel` group member it is installed as.

## 2. Stack

| Layer | Choice |
|---|---|
| Language | Rust 2021, `#![forbid(unsafe_code)]`, clippy pedantic |
| Async runtime | tokio (multi-thread) |
| API | gRPC / HTTP2 via tonic 0.14 + prost 0.14; schema compiled by protox |
| OS interop | `nix` for account lookups, fds and modes; `tokio::process` for tools |
| Errors / logs | `thiserror`, `tracing` → journald, `sd_notify` |
| Target OS | AlmaLinux 9 minimal, SELinux enforcing, systemd 252, nginx 1.20 |
| Build/test env | podman container of the target OS (`tests-integration/Containerfile`) |

## 3. Topology

```
 ┌────────────────────────────────────────────────┐
 │  Proprietary panel (React UI + Go API)         │  runs as a member of group `oxpanel`
 └───────────────────────┬────────────────────────┘
                         │ gRPC over /run/oxpanel/oxpanel.sock
                         │ authenticated by SO_PEERCRED (uid / gid allow-list)
 ┌───────────────────────▼────────────────────────┐
 │  oxpanel-daemon (root, hardened systemd unit)  │
 │   validate ─► workflows ─► System trait        │
 │   records in /var/lib/oxpanel = what we own    │
 └──┬──────────────┬───────────────┬──────────────┘
    │ useradd/del  │ unit files +  │ nginx -t / reload
    │ ACLs         │ daemon-reload │ oxpanel.d/<domain>.conf
    ▼              ▼               ▼
 POSIX accounts  systemd slices   Nginx                 (+ semanage/restorecon on SELinux hosts)
 /home/<t> 0700  cgroups v2 limits
```

## 4. Multi-tenant isolation

- **Identity:** one POSIX user + primary group per tenant, uid from a reserved
  range (default 20000–29999), shell `/sbin/nologin`, password locked.
- **Files:** home `0700` owned by the tenant. The web server gets *only* what
  ACLs grant: traverse (`--x`) on the path, read (`r-x`) on the document root,
  inherited by new files through a default ACL. Other tenants get nothing.
- **Privilege degradation:** anything done on a tenant's behalf (creating the
  document root) runs as the tenant via `setpriv` with all capabilities and
  supplementary groups dropped and `no_new_privs`.
- **Resources:** `oxpanel-tenant-<name>.slice` (for future tenant services such
  as PHP-FPM pools) and a `user-<uid>.slice` drop-in (for any login session)
  carry `MemoryMax`, `MemorySwapMax=0`, `CPUWeight`, `IOWeight`, `TasksMax`.
  Tenant names are systemd-escaped in unit names (`-` → `\x2d`) so slices never
  nest. The daemon never writes `/sys/fs/cgroup`; systemd is the single writer.
- **Web serving:** server blocks are generated, never hand-edited; `disable_symlinks
  if_not_owner`, dot-files denied, `autoindex off`, `server_tokens off`.
- **File access:** SFTP only (no shell, no forwarding), through one sshd
  drop-in OxPanel owns that applies to the group `oxpanel-tenants` (every
  tenant). Keys live in root-owned files outside the home; the tenant is
  chrooted into a root-owned directory holding only its home, bind-mounted by
  a systemd mount unit. See `src/sftp.rs` and the M2c design record.
- **Disk:** XFS user quotas per tenant uid (`src/quota.rs`), when the host
  mounts the homes' file system with `uquota`; refused, never ignored, when not.
- **SELinux:** document roots get a persistent `httpd_sys_content_t` file-context
  rule and `restorecon`; homes are relabelled after creation.

## 5. Privilege model of the daemon itself

The daemon needs root for every operation it exists to perform, so it does not
drop root globally. Instead the blast radius is bounded by the systemd unit:
`ProtectSystem=strict` with an explicit `ReadWritePaths` list, `PrivateNetwork`
+ `IPAddressDeny=any`, `NoNewPrivileges`, `PrivateDevices`, `ProtectKernel*`,
`RestrictNamespaces`, `MemoryDenyWriteExecute`, a capability deny-list and a
seccomp allow-list. The `System` trait is the seam along which the privileged
operations can later move into a separate minimal helper process without
changing the workflows.

## 6. State and idempotency

`/var/lib/oxpanel/{tenants,vhosts}/<name>.json` (root-only). A record claiming
the name and uid is written *before* the irreversible step (`useradd`) with
`state = provisioning`, synced to the account afterwards, then set to `ready`;
deletion marks `deleting` first. Records carry an opaque `owner` label for the
panel's reseller model.
Repeating a request replays it safely: identical spec → `created=false`,
different spec → `ALREADY_EXISTS`, interrupted → resumed.

## 7. Repository layout

```
Cargo.toml                      workspace (lints, profiles)
proto/oxpanel/v1/panel.proto    API contract
oxpanel-proto/                  generated types
oxpanel-daemon/                 the engine (src/, tests/, CLAUDE.md, README.md)
oxpanel-ctl/                    admin CLI
packaging/                      systemd unit, daemon.env, sysusers.d, tmpfiles.d, RPM spec
tests-integration/              Containerfile (AlmaLinux 9) + run-inside.sh assertions
scripts/                        dev.sh, integration-test.sh
.github/workflows/ci.yml        check + integration
deny.toml                       cargo-deny policy
```

## 8. Panels and the engine (root / reseller / customer)

The proprietary layer will expose three panels (root administrator, reseller, customer). The engine stays
role-agnostic: all three reach it through the single `panelapi` service
account, and authorisation (a customer may only touch their own virtual hosts,
a reseller only tenants with their `owner` label, root everything) is enforced
in the Go API. Aggregate reseller quotas are business logic and belong there;
per-tenant hard limits are enforced here. The customer-facing tier should run
under its own service account confined with `OXPANEL_PEER_SCOPES`
(`auth::ScopePolicy`: uid → allowed RPC classes), so a compromise of the
customer web tier can never reach `DeleteTenant`. Scopes are per RPC class,
not per object; per-owner confinement is a possible later refinement.

## 9. Roadmap

1. ~~Per-peer scopes; `UpdateTenantLimits` / `UpdateTenantOwner`; suspend/resume; usage; host info; `Reconcile`~~ — done (management milestone).
2. Confined SELinux domain (`oxpanel_t`) and a capability *allow*-list for the unit; a confining policy for `oxpanel_app_t` (today it only labels applications so the web server can be allowed to reach exactly them).
3. ~~Per-tenant PHP-FPM in the tenant slice; per-vhost logs~~ — done (hosting milestone 2a). Node.js and Python applications likewise (one sandboxed service per site, UNIX socket, own SELinux domain). Next: runtime version choice, per-tenant PHP settings, application environment variables.
4. ~~TLS for virtual hosts (ACME)~~ — done (M2b): uploaded and ACME (HTTP-01) certificates; the ACME client `oxpanel-acme` runs unprivileged outside the daemon. Next: DNS-01 / wildcard certificates. SFTP access and disk quotas: done (M2c).
5. Repair mode for `Reconcile` (today it reports only).
6. Split privileged helper behind the `System` trait.
