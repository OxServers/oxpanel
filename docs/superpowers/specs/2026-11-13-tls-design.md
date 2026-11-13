# HTTPS for virtual hosts (M2b, tls stream) — design

Date: 2026-11-13. Status: implemented on branch `m2b-tls`.

## Goal

Serve virtual hosts over HTTPS with a certificate the operator uploads
("bring your own") or one the engine obtains and renews from an ACME
certificate authority (Let's Encrypt, HTTP-01), without giving the daemon a
network and without any process other than root and Nginx's master ever
being able to read a site's private key.

## API

Four RPCs at the end of the service, all in the existing `vhost` scope:
`InstallCertificate` (chain + key in the request body), `RemoveCertificate`,
`RequestCertificate` (ACME, may take a minute or two; the result says whether
the authority issued and carries the client's output), `RenewCertificates`
(renew every ACME certificate that is due; the daemon also does this itself 5
minutes after start and then every 12 hours). `VirtualHost` gains
`certificate` (source, issuer, not-before/not-after, names, *uncovered* server
names, installed-at — never the key), `redirect_https` and `hsts`;
`ConfigureVirtualHostRequest` gains `redirect_https` and `hsts`; `HostInfo`
gains `tls_available`, `acme_available` and `acme_directory_url`;
`DriftKind` gains `TLS_CERTIFICATE_DRIFT` and `ORPHAN_TLS_FILE`. Field numbers
are those reserved for this stream.

The certificate is deliberately **not** part of `ConfigureVirtualHost`: a
reconfiguration keeps it, a removal of the site removes it. `redirect_https`
and `hsts` are stored with the site but only take effect while it has a
certificate, so a panel can set them first and attach the certificate later.

## Storage and validation

- `/etc/pki/oxpanel` (root, `0700`, labelled `cert_t` like the rest of
  `/etc/pki`, which Nginx may read): `<domain>.crt` (`0644`) and
  `<domain>.key` (`0600`). Nginx's master runs as root and reads both.
- The chain is public and kept in the virtual-host record too, so the
  certificate file is *rendered from the record* like every other file and
  `Reconcile` can compare it. The key exists only in its file.
- Input is parsed by our own PEM reader (allow-listed block types, at most 8
  certificates, base64 only, encrypted keys refused) and re-emitted in
  canonical form — the bytes that were sent are never written. Sizes are
  capped (64 KiB chain, 16 KiB key) before anything else.
- OpenSSL does the cryptography: the material is staged in the root-only
  directory, then `openssl x509` (issuer, dates, subjectAltName) and the
  comparison of `openssl x509 -pubkey` with `openssl pkey -pubout` (key
  belongs to the certificate). OpenSSL is only ever given *paths*; the key is
  never an argument, never logged (`CertificateUpload`'s `Debug` omits it,
  the RPC logs only the domain), never in a record or a response.
- The daemon itself checks validity (not before / not after) and that the
  certificate covers the site's domain (wildcards cover exactly one label, as
  browsers apply them). Aliases it does not cover are *reported*
  (`uncovered_names`), not refused: a certificate for `example.com` alone is
  a legitimate choice for a site with a `www.` alias.
- The chain is not verified against a trust store: a private CA or a
  self-signed certificate is the operator's decision.
- Activation follows the existing validate → activate → roll back rule. A
  replaced key does not change the Nginx file, so `nginx -t` is run
  explicitly in that case; on rejection the files and record are restored.

Considered and rejected: parsing X.509 in Rust (`x509-parser`/`rustls-pemfile`
plus `ring`/`rsa` for key matching) — more dependencies and code we own for
something OpenSSL, which is on every AlmaLinux host, already does. OpenSSL
became a hard `Requires` of the RPM.

## Nginx

- Per site: a port-80 block as before, plus — with a certificate — a
  `listen 443 ssl http2` (IPv4 and IPv6) block serving the identical site
  (PHP, application proxy, hardening). `X-Forwarded-Proto $scheme` was
  already in the proxy block; PHP gets `HTTPS=on` from the stock
  `fastcgi_params`.
- TLS settings: TLS 1.2 and 1.3; ECDHE with AES-GCM / ChaCha20 only (Mozilla
  "intermediate" minus the finite-field DHE suites, so no DH parameter file is
  needed); shared session cache; no session tickets (their keys would need
  rotation). **No OCSP stapling**: it requires a resolver and outbound
  connections from the web server, and Let's Encrypt has shut down its OCSP
  responders, so for the main use it would do nothing.
- `redirect_https`: the port-80 block answers `301 https://$host$request_uri`
  for everything *except* the ACME challenge location. `hsts`:
  `Strict-Transport-Security: max-age=31536000` (no `includeSubDomains`, no
  `preload`) over HTTPS only; off by default because browsers remember it for
  a year.
- Every active site serves `/.well-known/acme-challenge/` on port 80 from
  `/var/lib/oxpanel-acme/challenges` (`alias`, `disable_symlinks on`, before
  the dot-file rule). Not over HTTPS — HTTP-01 is plain HTTP.
- The catch-all in `00-oxpanel.conf` gains a `443 ssl default_server` with
  `ssl_reject_handshake on`: an unknown name (or no SNI) gets a failed
  handshake — never a tenant's certificate, never a tenant's site. This needs
  Nginx ≥ 1.19.4 (AlmaLinux 9 has 1.20). Existing hosts pick it up at the next
  start, as with every change of the include file.
- **Suspended sites** answer 503 on both ports, over HTTPS still with their
  own certificate (a visitor sees the 503 page, not a certificate warning),
  never redirect and answer no ACME challenges. Hence certificates cannot be
  requested for a suspended tenant and their renewals are skipped (caught up
  at the next round after resume; a 30-day margin leaves ample time).
  Installing or removing an uploaded certificate stays possible: it is an
  operator's action and gives the tenant nothing.

## ACME

### Driving certbot vs. our own client

AlmaLinux 9's base repositories have no ACME client; certbot is in EPEL and
brings a stack of Python packages with it. Options weighed:

1. **certbot from EPEL.** Least protocol code of our own, but: a third-party
   repository becomes a hard dependency of the RPM and of the source install;
   certbot wants to own the whole lifecycle (its own key generation, its own
   `/etc/letsencrypt` tree, renewal timers, hooks) and therefore holds the
   private keys itself — we would have to either let an unprivileged account
   hold every site's key or run certbot as root; and its renewal model fights
   our "records are the source of truth" rule.
2. **acme.sh / lego** — not packaged at all on AlmaLinux 9; a shell script or
   a downloaded binary is worse than either alternative.
3. **(chosen) A small ACME client in this workspace, `oxpanel-acme`** (~700
   lines with tests): RFC 8555 with HTTP-01 only, account key ECDSA P-256,
   `ureq` + `rustls` (ring) for HTTPS, `ring` for the JWS signatures. It works
   from the base OS, follows our process model, and — the deciding point —
   it never sees a site's private key: the daemon generates the key and the
   CSR with OpenSSL and hands over only the CSR, which is public. The cost is
   protocol code we own; it is proven end to end against Pebble (below).

The new dependencies (`ureq`, `rustls`, `ring`, `rustls-webpki`, …) are used
only by `oxpanel-acme`, not by the daemon, and pass `cargo deny`. They use no
OpenSSL and no bundled root store: the client trusts the system bundle
(`/etc/pki/tls/certs/ca-bundle.crt`) or `OXPANEL_ACME_CA_FILE`.

### Process model

The daemon keeps `PrivateNetwork=yes`. `RequestCertificate`:

1. (under the mutation lock) preflight — OpenSSL, the client binary, the
   `oxpanel-acme` account and its four directories must exist, else
   `FAILED_PRECONDITION` before anything is created; generate a fresh EC P-256
   key into `/etc/pki/oxpanel/<domain>.key.pending` (it leaves OpenSSL on
   stdout, straight into a root-only file) and write the CSR (SAN = domain and
   all aliases, empty subject) to `/var/lib/oxpanel-acme/csr/`.
2. (lock released — this takes as long as the authority does) run
   `systemd-run --wait --collect` a transient unit `oxpanel-acme-<domain>`:
   `User=oxpanel-acme`, no capabilities, `NoNewPrivileges`,
   `ProtectSystem=strict` with `ReadWritePaths` only for its account,
   challenge and output directories, `ProtectHome=yes`, `PrivateTmp`,
   `PrivateDevices`, `MemoryDenyWriteExecute`, `RuntimeMaxSec=240`. Its output
   goes to the journal and is read back (never `--pipe`; see the
   applications design).
3. (lock again) read the delivered chain without following symlinks and with
   a size bound (`fsutil::read_untrusted`: the directory belongs to an
   unprivileged account), validate it **exactly like an upload** against the
   pending key, install it, and in every case delete the pending key, CSR and
   reply.

The client can write its account key, the challenge directory and its output
directory, and read the CSR. It cannot read `/etc/pki/oxpanel` (root `0700`),
tenant homes or anything else of note; a compromised client could at worst
publish wrong challenge files or deliver a wrong chain, which the daemon
refuses. A refusal by the authority is a *result* (`succeeded=false` and the
reason), not an RPC error. One request per domain at a time; the RPC (and
the renewal RPC) run on a detached task so a caller giving up cannot cut a
request off between issuing and installing.

Each ACME directory URL gets its own account key, so switching between
staging and production needs no cleanup. Directory URL, CA file, contact
e-mail and renewal margin are configurable (`OXPANEL_ACME_*`) and validated
with an allow-list, because they end up in the client's argument vector.

### SELinux

The client runs as `unconfined_service_t` like any transient unit. The
challenge directory is labelled `httpd_sys_content_t` by a `filecon` in
`oxpanel.cil` so Nginx can read it; the rest of `/var/lib/oxpanel-acme` stays
`var_lib_t`, unreadable for `httpd_t`. The RPM runs `restorecon` on it after
loading the module (tmpfiles created it earlier).

## Automatic HTTPS

Added at the owner's request after the first version: every site gets a
certificate by itself and keeps one that covers all of its names, without
anyone calling `RequestCertificate`.

**Defaults (deliberate).** On for the host (`OXPANEL_AUTO_HTTPS=true`) and on
for every site (`ConfigureVirtualHostRequest.auto_https_opt_out = false`),
because the owner's intent is that a new site gets HTTPS by itself. The proto
field is an *opt-out* so that the protobuf default (false) means "on" and a
panel that does not know the field gets the intended behaviour. A host with
public DNS pointing elsewhere (or none) costs nothing but a local check per
site and back-off, never a request to the authority.

**When it runs.** Three seconds after `ConfigureVirtualHost` (new site or
changed names) and after `ResumeTenant` for the tenant's sites — late enough
that Nginx has reloaded, which also removes the reload race of the first
version; a sweep a minute after start and every 15 minutes; and
`RunAutoHttps` (`oxpanel-ctl cert auto run [domain]`). The sweep is cheap: a
site is only touched if a name is uncovered and not backing off.

**What it does for a site** (`auto_https::plan`): nothing for a valid
uploaded certificate; otherwise, if any server name is neither covered by the
site's (unexpired) ACME certificate nor backing off, it orders the covered
names plus those names, the domain first. If the domain itself is uncovered
and backing off, it waits.

**Uploaded certificates** are never replaced while valid. An *expired*
uploaded certificate is replaced if the site has Automatic HTTPS on: the site
is broken for every visitor at that point, and the operator can opt the site
out to keep full control. Considered and rejected: never touching an uploaded
certificate (leaves an expired site broken), replacing it before expiry
(overrides an explicit operator choice).

**Rate limits.** Before the authority is asked, `oxpanel-acme --mode
precheck` (same unprivileged unit; the daemon keeps `PrivateNetwork=yes`)
publishes a random probe file in the challenge directory and, for each name,
resolves it and fetches `http://<name>/.well-known/acme-challenge/<probe>`
from *every* address it resolves to (at most 4, three tries each, plain
HTTP/1.1 with the right `Host`, as the authority does). It reports
`ok <name>` / `skip <name> <reason>` in a file the daemon reads without
following symlinks and believes only about names it asked for. Then:

- names that fail are left out of the order and backed off: 1 h, 6 h, then
  every 24 h (per name, counted per consecutive failure);
- if the domain itself fails, nothing is ordered and no key is made;
- if every name that passed is already covered, nothing is ordered (adding a
  broken alias does not re-issue the certificate);
- a refusal by the authority backs off every name it was asked for.

At most two pre-checks or orders run at once host-wide (a semaphore shared
with manual requests and renewals), and one site's work is serialised (a
per-site lock; a manual request now waits for a running automatic one
instead of being refused). Renewals of sites under Automatic HTTPS go through
the same path, so an alias that stopped resolving drops out of the renewed
certificate instead of failing it.

**State** per site in `/var/lib/oxpanel/auto-https/<domain>.json` (root
`0600`): last attempt, last error in plain words, and per-name failures, next
attempt and reason. It survives restarts, is removed with the site, and a
stray file is `ORPHAN_AUTO_HTTPS_STATE` drift. An unreadable file counts as a
fresh start (it holds only back-off).

**Status** (`GetAutoHttpsStatus`, `oxpanel-ctl cert auto status [domain]`):
`DISABLED` (host switch off or site opted out), `SUSPENDED`, `UPLOADED`,
`COVERED`, `PARTIAL` (domain covered, some names skipped), `PENDING`, `FAILED`
(no certificate yet, retried later); covered, pending and skipped names (with
reason, failures and next attempt), last and next attempt, last error.

**Naming.** The feature is called "Automatic HTTPS" (`auto_https` in the API,
configuration and code), deliberately not the name another product uses.

## Choosing the certificate authority; External Account Binding

`OXPANEL_ACME_DIRECTORY_URL` selects any RFC 8555 authority: Let's Encrypt
(default), its staging directory, ZeroSSL, Google Trust Services, a private
CA. Providers that require External Account Binding (RFC 8555 §7.3.4) are
supported through `OXPANEL_ACME_EAB_FILE`: a root-only file with `kid=` and
`hmac_key=` (base64url, as the providers hand it out). The daemon refuses to
use it unless it is a regular file owned by root with no group/other bits,
and passes it to the client with `LoadCredential=` — systemd reads it and
shows it to that one unit only, so the secret is never an argument, never in
the daemon's memory beyond the path, never logged, never returned. The client
adds an HS256 JWS over its account key (`externalAccountBinding`) to
`newAccount`. The HMAC is checked against RFC 4231 test case 2 in unit tests,
and end to end against Pebble with `externalAccountBindingRequired`.

## Reconcile

`TLS_CERTIFICATE_DRIFT`: the certificate file is missing or differs from the
record, or the key is missing, not a regular file, not owned by root or
readable by group/others. `ORPHAN_TLS_FILE`: anything else in
`/etc/pki/oxpanel` (a pending key of a request in flight is expected). The
Nginx file — including the 443 block — was already compared by
`VHOST_CONFIG_DRIFT`. Whether the key still matches the certificate is not
checked (that needs OpenSSL; reconciliation runs no programs).

## Lifecycle

- Removing a virtual host removes its certificate, key and any ACME leftovers
  after Nginx has stopped using them.
- Deleting a tenant was already refused while it owns virtual hosts, so no
  certificate can outlive its tenant.
- Changing a site's aliases keeps the certificate; the uncovered ones appear
  in `uncovered_names` until a new certificate covers them — obtained by
  Automatic HTTPS within seconds when it is on for the site, otherwise by
  the operator.

## Testing

- Unit tests (`FakeSystem`): exact argv of every OpenSSL call, of `genpkey`,
  `req` and of the `systemd-run` invocation; no argument ever contains key
  material; modes of the directory, key and certificate; wrong key, expired,
  not yet valid, wrong name and nameless certificates refused with nothing
  left behind; Nginx rejection rolls back; redirect/HSTS rendering; suspended
  rendering; renewal only of due ACME certificates of active tenants;
  reconcile; two gRPC tests (no key in any response; a read-only peer is
  refused). The fake OpenSSL understands fake PEM blocks that spell out
  issuer, dates, names and key id.
- `tests-integration/run-inside.sh`, section "HTTPS": a private CA made with
  OpenSSL; wrong key, expired and wrong-name certificates refused; the served
  certificate is byte-for-byte the uploaded one (fingerprint over
  `s_client`); HTTP/2; TLS 1.1 refused; unknown SNI and no SNI get no
  certificate; redirect with ACME challenges still answered; HSTS only over
  HTTPS; suspension; drift and healing; PHP sees `HTTPS=on`; a Node.js app
  sees `X-Forwarded-Proto: https`.
- **ACME end to end against Pebble** (Let's Encrypt's test CA, release
  v2.10.1, downloaded by the test script and verified against a pinned
  SHA-256): Pebble runs locally with its HTTP-01 port set to 80 and resolves
  the test names through `/etc/hosts`; the daemon is pointed at it with
  `OXPANEL_ACME_DIRECTORY_URL`/`OXPANEL_ACME_CA_FILE`. Proven: account
  registration, order, HTTP-01 validation through the real Nginx while the
  site redirects to HTTPS, finalisation with our CSR, delivery, installation,
  serving over HTTPS with the issued chain (verified against Pebble's root),
  renewal (Pebble issues 10-day certificates so they are due at once), a
  failing validation reported as a result, cleanup. Pebble also rejects 5 %
  of nonces at random, which exercises the client's retry. **Not proven**:
  issuance by the real Let's Encrypt (needs public DNS); the 12-hour timer
  itself (the same code path is exercised through `RenewCertificates`), and
  the 15-minute sweep timer (the sweep itself runs through `RunAutoHttps`).
- **Automatic HTTPS and EAB, end to end against Pebble** (container and the
  enforcing VM): a new site gets a certificate with no request; an alias
  added later is covered; an unresolvable alias is skipped while the rest
  stays covered, backs off for an hour, the back-off survives a restart and is
  respected by a full run, while a run for the one site retries; an opted-out
  site, a suspended tenant and the host-wide switch get nothing; a suspended
  site catches up on resume; a valid uploaded certificate is left alone;
  Pebble with `externalAccountBindingRequired` refuses without a binding,
  the daemon refuses a binding file others can read, and issues with it.

## Not included

DNS-01 and wildcard certificates from ACME;
TLS-ALPN-01; OCSP stapling; per-site TLS settings or client certificates;
per-site choice of certificate authority; an expiry e-mail of our own (the
panel reads `not_after`; Let's Encrypt has stopped expiry mails); the
firewall — port 443 must be opened by the operator
(`firewall-cmd --add-service=https --permanent && firewall-cmd --reload`).
