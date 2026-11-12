# Node.js and Python applications (M2a, second part) — design

Date: 2026-11-13. Status: implemented on branch `m2a2-node-python`.

## Goal

Host long-running Node.js and Python applications with the same isolation as
PHP: nothing shared between tenants, everything inside the tenant's limits.

## Model

One systemd service per virtual host that runs an application
(`oxpanel-app-<domain>.service`), `User=<tenant>`, `Slice=<tenant slice>`,
sandboxed like the PHP unit. Per site rather than per tenant (unlike PHP)
because an application *is* a process: two sites are two programs.

**UNIX socket, not a TCP port.** The application gets a socket path in `PORT`
/ `OXPANEL_SOCKET` and Nginx proxies to it. Considered and rejected: a loopback
TCP port per application. Any local process — every other tenant's PHP or
application — can connect to a loopback port, bypassing Nginx; ports must be
allocated, recorded and kept from colliding. A socket in a `0750` directory
with an ACL for the web server needs none of that. The cost is a contract:
the application must listen on what `PORT` says. Node accepts a path there as
it is; Python servers take `unix:` bind addresses.

Socket permissions: systemd creates the runtime directory; `ExecStartPre=+setfacl`
(as root) grants the web server `--x` on it and a default ACL `rw-` for sockets
created inside. The unit's `UMask=0007` matters: the kernel applies the umask
to a socket's mode even under a default ACL, and the group bits are the ACL
mask — with `0022` the web server's entry was ineffective (found by the
integration suite).

**Source stays private.** The application directory gets no web-server ACL and
may not be the document root or inside it. The document root (which may be a
`public/` directory inside the application) is served by Nginx directly;
`try_files $uri @app` sends everything else to the application.

**Python virtualenv.** Always, per application, created by the tenant
(`python3 -m venv`, no network needed). The unit runs
`/usr/bin/env <root>/.venv/bin/python <entry>`: the virtualenv interpreter is
a symlink in the tenant's home, which systemd may not read under SELinux, so
systemd executes `env` and `env` — already the tenant, already in the
application domain — executes the interpreter.

**Dependencies.** The daemon has no network on purpose, so `npm`/`pip` run in a
transient unit started with `systemd-run`: as the tenant, in the tenant's
slice, sandboxed, at most 4 minutes. Output is read back from the journal, not
through pipes — under SELinux, systemd may not write to a pipe created by the
daemon and silently drops the request (found on the acceptance VM). The RPC is
not under the mutation lock: it touches only the tenant's files and may take
minutes.

## SELinux

Two things are denied by the stock policy: the web server writing to a socket
labelled `var_run_t`, and the web server connecting to a process in
`unconfined_service_t`. Options:

1. Allow `httpd_t` to connect to every unconfined service — a host-wide hole.
2. A TCP loopback upstream plus `httpd_can_network_connect` — gives up the
   socket isolation and lets PHP reach any local port.
3. (chosen) A small CIL module, `packaging/selinux/oxpanel.cil`: a domain
   `oxpanel_app_t` for applications (entered through `SELinuxContext=` in the
   unit), `httpd_t` may connect to that domain only, and
   `/run/oxpanel-app(/.*)?` is `httpd_var_run_t`. CIL needs no compiler, so
   the source install can load it too.

`oxpanel_app_t` carries the attributes an ordinary program needs and omits the
dangerous ones of the stock unconfined service domain (loading policy or
kernel modules, changing booleans or enforcement, raw storage). It is therefore
narrower than what applications would otherwise run in, but it is not a
confining policy; confinement comes from the tenant uid, the unit sandbox and
the cgroup. A confining policy is on the roadmap.

On SELinux hosts the daemon checks that the module is loaded before enabling an
application and refuses with the install command otherwise.

## Not included

Runtime version choice per application, custom start commands, environment
variables and secrets, health checks/status in the API, zero-downtime restarts.

## Verification

104 unit tests, 6 gRPC end-to-end tests, the root integration suite, and
`INSTALL=rpm make acceptance` on AlmaLinux 9.8 with SELinux enforcing: all
phases pass with zero AVC denials, including a Node.js application that
survives a reboot.
