# Usability release: engine 0.3.2 — design

Date: 2026-11-16. Status: implemented on branch `m7-usability` (from `main`
a703d0b = v0.3.1). The console half (panel 0.2.2) is a separate stream on the
same API contract (48d65a6).

The release makes the panel easier to live with for administrators and their
customers. Most of it is console work; the engine adds four things the console
cannot do by itself. Disk limits on ext4 were assessed and are **not** in this
release (see `2026-11-16-ext4-quota-design.md`).

## 1. Downloading a backup: `ReadBackupMember`

**What.** `ReadBackupMember {tenant, backup_id, member, offset, length}` →
`{data, size_bytes, eof}`, scope `vhost`; at most 1 MiB per call (0 means
1 MiB). `member` is one of the record's `members[].name` or `manifest.json`.
`oxpanel-ctl backup download TENANT ID MEMBER [-o FILE]` uses it (the output
file is created with `O_EXCL`, never overwritten, and removed if the engine
refuses half-way).

**Why this way.** The panel runs as `panelapi`, which must not read
`/var/lib/oxpanel-backups` (root-only, and the archives contain every tenant's
files). A chunked read RPC keeps that boundary: the engine decides which file
is handed out and to whom, the panel streams it to the browser without holding
it in memory, and the gRPC message size limit is never approached.

- **Members, not paths.** The request names a file the engine itself recorded
  when it sealed the backup; there is no path in the API to validate, so none
  can escape. The file is still opened with `openat2(RESOLVE_BENEATH |
  RESOLVE_NO_SYMLINKS)` beneath the backup directory and must be a regular
  file of the recorded size — a swapped or truncated archive is
  `FAILED_PRECONDITION`, not data.
- **Isolation as for a restore.** The backup is looked up for the tenant and
  must come from the tenant's current uid; anything else is `NOT_FOUND` (not
  `PERMISSION_DENIED`: the panel must not learn that another tenant's id
  exists). Only `READY` backups are read.
- **Scope `vhost`**, like the other per-tenant reads that return tenant
  content (the files RPCs): the customer-facing tier may download its own
  backups; `read` alone may not, because a backup is content, not status.
- **Dry-run.** Works against the in-memory fake OS the console's end-to-end
  tests run, from where dry-run backups live.
- A side fix found while testing: Reconcile compared a backup's manifest with
  what the *current* engine would write, so an upgrade flagged every older
  backup as `BACKUP_ARCHIVE_MODIFIED`. The manifest is now compared as the
  engine version it names wrote it.

**Rejected.** A signed URL served by Nginx from the backup directory (it would
make the archives web-readable, `httpd_t` reading root-only data, and a token
scheme to get right); copying the archive into the tenant's home (doubles the
disk use, counts against the tenant's quota, and leaves copies behind); a
server-streaming RPC (resumption after a dropped connection is simpler with
offsets, and the console already has a chunked reader for the files RPCs).

**Not included.** Uploading a backup from elsewhere; downloading a database
dump separately from its backup (it is a member like the others).

## 2. Host certificates: the panel's own name

**What.** A *consumer* registers a host name in a root-owned file
`/etc/oxpanel/host-certificates.d/<consumer>.conf` (`name=`,
`challenges=engine|consumer`, optional `redirect_port=`); the engine obtains
and renews a certificate for it and writes `/etc/pki/oxpanel-host/<consumer>.crt`
(0644) and `.key` (0600). `GetHostInfo.host_certificates` and
`oxpanel-ctl cert host [CONSUMER]` report each registration (issued, renewing,
pending, disabled, invalid; issuer, expiry, reason, next attempt, paths).
Details in HANDBOOK §9.4.

**Why.** The panel served a self-signed certificate until the administrator
installed one by hand; on the owner's real host that meant copying the mail
certificate and a cron job to repeat it. The engine already obtains a
certificate for a name that is not a site — the mail host name — with all the
care that took (reachability pre-check, back-off, renewal, verification,
rollback). Reusing that machinery for any registered name gives the panel an
automatic certificate without a second ACME client on the host.

- **A file, not an RPC.** The registration is host configuration written by a
  root-run setup tool (the panel's package and `oxpanel-panel-setup`), not
  something `panelapi` may change at runtime: a compromised panel process must
  not be able to make the engine request certificates for arbitrary names.
  Root ownership and "not group/world-writable" are checked; any deviation, an
  unknown line or a bad value is `INVALID` and nothing is done for it (fail
  closed; the reason is reported).
- **The engine knows nothing about the panel.** It does not render the
  panel's TLS server or decide which certificate the panel serves; it only
  produces a verified pair at a fixed path and reloads Nginx after replacing
  it, so a consumer that points `ssl_certificate` at it picks up renewals by
  itself. The precedence (a certificate installed by the administrator wins,
  then the automatic one, then whatever was there before) is the panel's
  (`oxpanel-panel-setup certificate --sync`).
- **Challenges.** `engine`: a challenge-only port-80 server per name that no
  engine-rendered server answers already (sites, aliases, the mail host name),
  404 or a redirect to the consumer's port for other paths — for the panel in
  port mode, which has no port-80 server of its own. `consumer`: the panel in
  host-name mode already has a port-80 server for its name and serves the
  engine's challenge directory there. Both validated with `nginx -t` and
  rolled back like every Nginx change; drift-checked.
- **An operator's run does not wait.** The periodic task respects the
  back-off (1 h, 6 h, then daily); `RunAutoHttps` without a domain
  (`oxpanel-ctl cert auto run`, also run by the installer after enabling the
  panel) tries host certificates at once, back-off or not, as a run for one
  site does. Found on the VM: a panel installed before its name resolved had
  backed off, and after the operator fixed DNS the panel waited up to a day.
  The reachability check still runs first, so the authority is never asked
  for a name that does not resolve here.
- **No placeholder.** The paths do not exist until a real certificate does, so
  "the file exists" means "a verified certificate for the name"; the panel
  keeps its self-signed one until then.
- **Removal.** A removed registration's pair is removed at the next sweep, but
  kept (and retried) while Nginx still refers to it — removing a file Nginx
  loads would make the next reload fail for every site on the host.
- **Reconcile.** `HOST_CERTIFICATE_KEY_EXPOSED`, `ORPHAN_HOST_CERTIFICATE_FILE`,
  `HOST_CERTIFICATE_CHALLENGE_DRIFT`.

**Rejected.** Putting the panel's name into a site (it would appear among the
customer's sites, be counted, suspended, deleted with a tenant); an RPC for
registration (see above); certbot as a dependency of the panel (a second ACME
account, second renewal timer, second set of failure modes); customer names in
the panel's certificate (a customer could then make the panel's certificate
fail to renew, and the list would leak who is hosted here).

**Not included.** Wildcards, DNS-01, more than one name per registration
(the panel has one name; a second consumer registers its own file).

## 3. Public addresses in `GetHostInfo`

**What.** `public_ipv4` / `public_ipv6`: `OXPANEL_PUBLIC_IPV4/_IPV6`, else DNS
hosting's `OXPANEL_DNS_IPV4/_IPV6`, else empty. The installer writes them with
`--public-ipv4/--public-ipv6`, filled from `--dns-ipv4/--dns-ipv6`.

**Why.** The panel tells customers where to point their domains ("create an A
record for … pointing to …"). Only the operator knows the public address: on a
VPS behind NAT the interfaces carry private ones, and guessing by asking an
outside service would make the engine (which runs with `PrivateNetwork=yes`)
talk to the internet. So the value is configured, validated at start (an
address of the family that is not unspecified, loopback, multicast or
broadcast — the daemon refuses to start otherwise, the installer refuses
before writing), and empty when unknown; the panel then says it does not know
rather than showing a wrong address.

**Rejected.** Reading the interfaces (wrong behind NAT); an outside lookup
(network from the engine, a third party learning about the host).

## 4. Login banning in `GetHostInfo`

**What.** `login_banning {active, jails, detail}`: active when fail2ban is
installed, `fail2ban.service` is active and OxPanel's jail files enable jails.

**Why.** The installer offers login banning, but the panel could not tell an
administrator whether it is on — and the console now shows "how to switch it
on" with the exact installer command (HANDBOOK §3.0, "Switching on an optional
feature later"). The engine only reads its own jail files (never through a
symlink) and asks `systemctl is-active`; it does not run `fail2ban-client`
(which needs the fail2ban socket, outside the unit's sandbox, and would add an
SELinux question for a status line).

**Not included.** Listing or lifting bans from the panel (a later feature,
needs a narrow root helper); switching fail2ban on from the panel (the
installer does that, with EPEL as an explicit decision).

## Installer changes

- `--only` takes a comma-separated list of stages (validated: an unknown name
  is refused instead of running nothing).
- The panel's name for its certificate: `--panel-hostname`, else the mail host
  name (with email), else `hostname -f` when it has a dot; passed as `--name`
  in port mode only to a setup tool whose usage mentions it (panel 0.2.1 does
  not and installs as before), and not over a name the setup tool kept before
  the run (the administrator's). A name the 0.2.2 package derives while the
  run upgrades it from 0.2.1 does not count: it is taken from the subject CN
  of the certificate installed by hand, which ACME certificates (the engine's
  among them) no longer carry, so it falls back to `hostname -f`. Found on the
  VM with the owner's upgrade: the panel got a certificate for the host's own
  name instead of the mail host name it is reached by. After `enable` a certificate run (`oxpanel-ctl cert auto run`, bounded
  by `timeout 300`, not fatal); the summary says which certificate the panel
  serves, from `oxpanel-panel-setup status`.

## Decisions the owner may want to reverse

- `ReadBackupMember` in scope `vhost` (not `read`).
- A registration with any unknown line is invalid (strict), rather than
  ignoring unknown lines for forward compatibility.
- The installer never guesses the public address.
- Host certificates in Pebble's integration run report `renewing` right after
  issue (Pebble's certificates last 10 days, inside the 30-day renewal window);
  `issued` is proven by the unit tests only.
