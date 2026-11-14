# The whole product on a real host: panel packaging, serving and acceptance

Date: 2026-11-14 · Branch: `m4-product` (engine, from `m3-integration`) and
`packaging` (console repository, from `ui`).

## What

Until now the panel (API + web interface, the proprietary "console") had only run
on a developer machine against `oxpanel-daemon --dry-run`. This stream makes engine,
panel API and web interface install and run together on AlmaLinux 9 with SELinux
enforcing, and proves it on the acceptance VM:

1. **`oxpanel-panel` RPM** (console repository: `packaging/oxpanel-panel.spec`,
   `make rpm`): `panel-api`, the built web interface, a hardened systemd unit,
   sysusers/tmpfiles, an environment file, Nginx templates, a small CIL policy
   module and `oxpanel-panel-setup` (put on/off Nginx, certificates, first
   administrator, status).
2. **Serving**: HTTPS on a port of its own (8443) by default; a host name of its own
   on 443 as the alternative; a self-signed certificate at install.
3. **Installer** (`install.sh`): installs a bundled or named panel RPM, a new stage
   `panelweb` (HTTPS, service, first administrator, health check over HTTPS), the
   panel's firewall port, uninstall that keeps the panel's database unless
   `--purge-panel`. `make dist PANEL_RPM=…` assembles a bundle with the panel.
4. **Acceptance mode `INSTALL=product`** with phase 25: the deployed service, its
   transport, the whole product driven through the panel's HTTPS API as a browser
   does (`tests-acceptance/phases/product/drive.py`), and what tenant code can reach
   of the panel. Phases 60 and 95 check the panel after a reboot and across an
   uninstall/reinstall when it is installed.

## Decisions and why

**The panel listens on a UNIX socket, not on loopback TCP.** Tenants' PHP and
applications run on the same host and can connect to, and *bind*, any loopback port
above 1024. With TCP, the proxy secret stops a tenant from *calling* the panel
directly, but nothing stops a tenant's process from taking the port while the panel
restarts (every package upgrade) and then receiving everything Nginx forwards:
administrators' passwords, session cookies and the proxy secret itself. A socket in
`/run/oxpanel-panel` (`panelapi:nginx 2750`, socket `0660`) cannot be reached or taken
over by a tenant. This needed the only source change in the console
(`PANEL_LISTEN_UNIX`, ~50 lines and a test); TCP remains supported.
*Rejected:* a privileged port (the panel would need `CAP_NET_BIND_SERVICE`; tenants
could still connect); systemd socket activation (keeps the port across restarts, but
not before the first start at boot, and tenants can still connect).

**Its own SELinux domain, `oxpanel_panel_t`, shipped by the panel package.** Nginx
(`httpd_t`) may not connect to a service's stream socket. Allowing
`httpd_t → unconfined_service_t` would let the web server reach every service's socket
(abstract ones have no file label to stop it), so the panel runs in a domain of its
own, declared like the engine's `oxpanel_app_t` (the unconfined-service attributes,
`init_t` transition with `nnp_transition` because the unit sets `NoNewPrivileges`),
and the one new permission is `httpd_t → oxpanel_panel_t : unix_stream_socket
connectto`. The socket directory is labelled `httpd_var_run_t` (as the engine labels
application sockets) and the ACME webroot of host-name mode `httpd_sys_content_t`.
The module is the panel package's (`oxpanel-panel.cil`, loaded in `%post`, removed on
erase): the rules exist only because of the panel, the public engine policy stays
unaware of a proprietary product, and removing the panel removes them. No boolean is
changed. (Whether more rules were needed was found on the VM: see the report.)

**Default: port 8443, any name.** Port 443 belongs to customers' sites and its default
server refuses unknown names; giving the panel a name there means the operator needs a
DNS name before the panel works, and the name competes with customers' names. A port
of its own works at once (by address), never collides, and is already `http_port_t`
in the stock policy. Its server block is `default_server` on 8443 only, so it does
not interfere with the engine's catch-alls on 80/443; the installer's detection of a
foreign `default_server` now looks at ports 80/443 only (it used to switch the
engine's catch-all off as soon as *any* `default_server` existed — found by this
stream; it would have exposed the first customer site to every unknown name).
*Host-name mode* (`--panel-hostname`) is the alternative: 80 (ACME webroot + redirect)
and 443 under that name, in a file read before OxPanel's own so that a customer site
of the same name can never capture the panel (Nginx keeps the first server and warns).

**Certificate.** Self-signed at install (EC P-256, names: host name, addresses), so
the panel works immediately. `oxpanel-panel-setup certificate --cert --key` installs a
real one (checked against the key and the host name, `nginx -t`, rolled back if
refused). A real certificate from an ACME authority is the operator's ACME client's
job (webroot served in host-name mode); the engine's ACME machinery is for customers'
sites and stays separate — entangling them would put the panel's certificate in the
engine's records, reconcile and Automatic HTTPS for no gain.

**Request limits.** Nginx's `client_max_body_size` is 4 MiB, above every limit the
panel enforces itself (64 KiB default, 1 MiB maximum by configuration, file-manager
chunks of 192 KiB of data in base64), so the panel answers with its own error codes;
`proxy_request_buffering off`; `proxy_read_timeout 360 s` for dependency
installation. The browser's own `Host` (port included) is passed, because the panel
compares `Origin` with `Host`.

**First administrator.** The installer calls the panel's own bootstrap (never a
default password): a random one-time password printed at the end of the run, never
written to `/var/log/oxpanel-install.log`; first sign-in forces a password change and
two-factor enrolment. A later run finds the administrator and prints nothing.

**Engine scopes.** The panel needs all four (it creates, suspends and deletes
accounts), so none are set; the handbook's confinement applies to *other*, less
trusted clients. Confining the panel itself would need splitting it into two
processes with two accounts — not done.

**A bundle with the panel.** The public repository never contains the proprietary
RPM. `make dist PANEL_RPM=/path` copies a panel RPM built in the panel's repository
into `dist/release` (and its checksum into `SHA256SUMS`); `install.sh` then installs it
by itself (`--no-panel` to skip). `INSTALL=product` acceptance needs the same
`PANEL_RPM`.

## Not included

A confining SELinux policy for the panel (its domain carries unconfined-service
attributes); automatic ACME for the panel's own certificate; a dnf repository for the
panel; RPM signing; the UI's own browser run in the unattended acceptance (it is run
by hand against a kept VM: see the report).
