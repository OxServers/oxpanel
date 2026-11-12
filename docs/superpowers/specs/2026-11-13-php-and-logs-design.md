# PHP-FPM per tenant and per-site logs (M2a) — design

Date: 2026-11-13. Status: implemented on branch `m2a-php-logs`.

## Goal

Make the engine host real sites: PHP applications, with logs the owner can
read, without giving up any of the isolation the static-only engine has.

## PHP

**One FPM instance per tenant, running as the tenant** (`oxpanel-php-<name>.service`,
`User=<tenant>`, `Slice=<tenant slice>`), rather than one root-owned master
with a pool per tenant. Reasons:

- no PHP-related process runs as root, so an FPM or PHP bug is contained to one
  tenant's uid by the kernel, not by FPM's own privilege dropping;
- the tenant's cgroup limits apply to PHP with no extra work, and usage
  accounting comes for free;
- a tenant's PHP can be stopped, restarted or removed without touching anyone
  else's.

Cost: one idle master process (about 6 MB) per PHP-using tenant. Workers are
`pm = ondemand`, so idle tenants cost nothing more.

The instance exists exactly while the tenant has a virtual host with
`php = true`; both files (`/etc/oxpanel-php/<name>.conf`, the unit) are
rendered only from the records, so `Reconcile` can verify them.

Nginx reaches the instance over `/run/oxpanel-php/<name>/php.sock`. FPM sets an
ACL for the web-server account on the socket (`listen.acl_users`), which an
unprivileged owner may do; no other account can connect.

Ordering rules: the pool is started before Nginx is pointed at it; on suspend
the sites go 503 before PHP stops; on resume PHP starts before the sites
return. A suspended tenant's unit is disabled so a reboot does not revive it.

**SELinux.** FPM runs in `httpd_t` (the binary is `httpd_exec_t`). Reading the
document root, the socket and the private `/tmp` work with the stock policy.
Writing the document root does not: it is labelled `httpd_sys_content_t`
through the path equivalence chosen in v0.1.0. Options considered:

1. `httpd_unified` boolean (chosen): one persistent switch, set by the RPM.
   Nginx gains the same SELinux permission, but its DAC access is `r-x` through
   the ACL, so it still cannot write.
2. Label PHP document roots `httpd_sys_rw_content_t`: needs a second
   equivalence source that is rw recursively; none exists in the stock policy,
   and a custom module is the "confined domain" roadmap item.

The daemon warns at start if the boolean is off; it is not fatal because
static and read-only PHP sites work without it.

**Not included:** choosing a PHP version per tenant, per-tenant `php.ini`
values, and worker-count tuning. The host's `php-fpm` package is used as is.

## Logs

Each server block gets `access_log` and `error_log` under
`/var/log/nginx/oxpanel` (root `0750`; tenants cannot list or read it).
`ReadVirtualHostLog` returns the tail of the live file so the panel can show
logs without tenant shell access. Rotation is a shipped logrotate rule;
rotated files of removed sites age out through the `tmpfiles.d` entry.

Because the template changed for every site, the daemon now re-renders all
virtual hosts from their records at start (`vhost::converge_all`), validated
and rolled back like any other change. Upgrades therefore need no manual step.

## Hardening found on the way

A site without PHP used to serve `*.php` as a download. It now answers 404:
script source routinely contains database passwords, and switching PHP off (or
a host without PHP) must not publish it.

## Verification

91 unit tests, 6 gRPC end-to-end tests, 172 integration checks, and
`INSTALL=rpm make acceptance` on AlmaLinux 9.8 with SELinux enforcing: all
phases pass with zero AVC denials, including a PHP site that survives a reboot.
