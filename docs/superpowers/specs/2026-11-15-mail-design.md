# Built-in email (M5, mail stream) — design

Date: 2026-11-15. Status: implemented on branch `m5-mail`, from `main`
(cd4a629, engine 0.2.0). Engine version 0.3.0. The owner's decisions and the
RPC contract are in `.claude/handoff/tasks/mail-contract.md`; deviations are
listed at the end.

## Goal

Every hosting account can have email on its own domains: mailboxes it reads
over IMAPS/POP3S and webmail, sends through authenticated submission,
forwarders, a catch-all, autoresponders; DNS records kept for it when the
host serves the domain's zone. Email is an optional host component like DNS
hosting (`install.sh --mail`). It follows the engine's rules: records are
the proof of ownership, every file is rendered from records, a request that
cannot succeed is refused before anything is created, everything is
idempotent and resumable, secrets are never in argv, logs, records or
responses, and nothing handles a customer's mail with another identity.

## The servers

| Part | From | Why |
|---|---|---|
| Postfix 3.5 (SMTP, submission) | AppStream | decided |
| Dovecot 2.3 + Pigeonhole (IMAPS, POP3S, LMTP, logins, Sieve) | AppStream | decided |
| Rspamd 4.3 (spam filter, DKIM signer, milter) | rspamd.com's own signed repository (HTTPS, `gpgcheck=1`, `repo_gpgcheck=1`); its libraries (jemalloc, hyperscan, libsodium) from EPEL | not in EPEL 9 (checked first, as asked); the upstream repository is the project's own and signed. Its repository file uses plain HTTP — the installer writes its own with HTTPS. Its RPM does not create the `_rspamd` account; the installer does. |
| Roundcube 1.5.15 | EPEL (`roundcubemail`) | packaged cleanly (no vendoring). It drops a location into Nginx's default server (`/etc/nginx/default.d/roundcubemail.conf`, localhost-only, through the masked shared PHP pool); the installer empties it. 1.5 is an LTS line maintained by EPEL. |
| ClamAV (optional, off) | EPEL | decided; `OXPANEL_MAIL_ANTIVIRUS`, through Rspamd's antivirus module |
| OxPanel's mail policy service | the daemon binary (`mail-policy`) | limits and site mail (below) |

**Ownership of the configuration.** Postfix's `main.cf`/`master.cf` and
Dovecot's `dovecot.conf` cannot be extended by includes enough for this
(restriction lists, listeners, passdbs), so while email is on OxPanel owns
them entirely, rendered from records (the distribution's files are kept once
as `*.oxpanel-orig`, put back by `install.sh --uninstall --purge-mail`).
Rspamd is configured through its own `local.d` files. The stock units are
used for Postfix, Dovecot and Rspamd (their own sandboxes); OxPanel ships
`oxpanel-mail-policy.service` and `oxpanel-webmail.service`.

**Apply.** `mail::ops::apply` renders every file, writes only what changed
(atomically, owner and mode set), and reloads exactly the servers whose
files changed (`systemctl reload-or-restart`, which also starts a stopped
one; Nginx is tested before its reload and the previous file restored on
failure). A marker written before the files and removed after the reloads
makes an interrupted apply reload everything next time. Dovecot is
reloaded whenever its password files change: it re-reads them only when it
notices their time stamp change (two changes within one second were missed
— found by the integration suite with a suspension right after a mailbox
change) and it caches logins.

## Records and ownership

`/var/lib/oxpanel/mail/domains/<domain>.json` (root 0600) holds a mail
domain with its mode, external MX hosts, catch-all, DKIM keys (current and
retired), mailboxes (quota, bcrypt hash, enabled, autoresponder) and
forwarders; `/var/lib/oxpanel/mail/limits/<account>.json` an account's own
limits. Every value is re-validated on save and load.

**Which domains.** A mail domain must be a name the account already holds
here: one of its sites' names (domain or alias), or a name inside one of its
DNS zones — never another account's site or mail domain, never the mail host
name. This uses the existing first-come ownership of names; it does not
prove registration (as for sites and zones). Sites cannot take the mail host
name, nor `webmail.`/`autoconfig.`/`autodiscover.` of another account's
mail domain.

**Modes.** `local` (here), `external` (only MX records, to the provider's
hosts, in that order) or `off`. Switching modes keeps mailboxes and their
mail; they are served only in `local`. There is no RPC to delete a mail
domain (the contract has none): mode `off` is the way to stop it, and a
mail domain without mailboxes or forwarders goes with its account.

## Mail storage and identity

A mailbox lives in `~/mail/<domain>/<local>/` (Maildir), created by the
engine **as the account** (`mkdir -p -m 0700` under `setpriv`), owned by the
account's uid, so the account's disk quota counts it. Dovecot's user database
gives each mailbox the account's uid/gid and home; `first_valid_uid`/
`last_valid_uid` are the engine's tenant range, so Dovecot refuses any other
uid. Delivery (LMTP), Sieve, IMAP and POP3 run with that identity; the
mailbox size limit is Dovecot's quota (`userdb_quota_rule`, LMTP checks it at
RCPT). Removing a mailbox removes it from the servers at once, then its mail
**as the account** (`rm -rf --one-file-system`, which never follows a
symlink) in the background, resumed at start-up. Because the account owns
`~/mail`, symlinks there can only lead its own identity somewhere it can
already write; backups read the home as the account (links are stored as
links). Mail keeps the home's own label (`user_home_t`), which Dovecot may
use under the stock policy (proven on the enforcing VM).

**Passwords** are hashed in the daemon with bcrypt (cost 12, `$2y$`), stored
as Dovecot's `{BLF-CRYPT}` in the record and Dovecot's password file
(root:dovecot 0640) — never in plain text, never in argv, never logged, never
returned. Weak passwords are refused (`weak_password`): under 10
characters, fewer than 4 different characters, digits only, a well-known
password, or containing the local part or the domain's first label. At most
72 bytes (bcrypt's limit; longer would be cut silently).

## Sending

- **Port 25** relays nothing (`reject_unauth_destination`, no
  `permit_mynetworks` anywhere); it accepts mail for hosted domains only.
- **Submission** (587 with STARTTLS required, 465 with TLS) needs a login
  (Dovecot SASL); **a mailbox may send only as its own address**: the
  envelope through `reject_sender_login_mismatch` (each mailbox maps to
  itself), the `From:` header through a Rspamd prefilter (`rspamd.local.lua`)
  that rejects a logged-in message whose single From address is not the
  login. This is the simplest sound rule; sending as a forwarder address or
  another mailbox of the same customer is refused (aliases and identities
  are not in this version).
- **Sites** (PHP's `mail()`, anything calling sendmail) use
  `/usr/sbin/oxpanel-daemon sendmail` (PHP's `sendmail_path`, set host-wide
  in `/etc/php.d/90-oxpanel-mail.ini`, which sites cannot change). It hands
  the message to the policy service over `/run/oxpanel-mail/sendmail.sock`,
  which takes the account from the connection's uid (`SO_PEERCRED`), requires
  the envelope sender and every `From:` address to be at one of the account's
  domains (its sites' names, its mail domains, and names below them),
  removes `Bcc:` with `-t`, adds `From:` if missing, and hands it to Postfix
  through `public/oxinject` (reachable by the `postdrop` group only) with
  `XCLIENT LOGIN=site.<account>`. Postfix's own sendmail is restricted to
  root (`authorized_submit_users = root`). Callers that are not accounts
  (root's scripts), and every caller while email is off, go to Postfix's
  sendmail unchanged.
- **Autoresponders** (Sieve vacation in Dovecot's delivery, as the account)
  go through the same sendmail (`/usr/libexec/oxpanel/sendmail`, a link to
  the daemon binary) with the null sender; they count against the account.
- **Limits**: recipients per clock hour (UTC) for the account (all its
  mailboxes and sites) and for each mailbox, from `SetMailLimits` or the host
  defaults (500 / 200). Submission is checked at the end of each message by
  the policy service (`DEFER_IF_PERMIT`, a 450: the client tries later);
  site mail fails with `EX_TEMPFAIL` (75). Counters are in
  `/var/lib/oxpanel-mail/usage/usage.json` (survive restarts);
  `GetMailUsage` reads them. Each recipient counts, so one message to 100
  people is 100.
- **DKIM**: Rspamd signs mail that is logged in (mailboxes, and site mail
  with its XCLIENT login), with the key of the `From:` domain
  (`use_domain = header`, mismatching envelope/header domains not signed);
  never inbound mail (a forged `From:` from the internet is not signed by
  us).
- **DKIM rotation** (`RotateDkimKey`) never signs with a key receivers
  cannot find yet. When the domain's DNS is elsewhere it takes two calls:
  the first makes a new key under a new selector and keeps it *pending*
  (`dkim_pending` in the record; returned as `Dkim.pending_*` and in
  `required_records`), the old key goes on signing; a later call looks the
  new selector up in public DNS (the DNS probe, outside the mutation lock)
  and switches when the record is there. `force` switches at once (the
  caller accepts the risk). When this host serves the zone, one call does
  both: the new key is put into the zone first, then it signs. A call while
  a key is pending never makes another one; the old key's record stays
  published for 7 days after the switch. The record is written before each
  step, so an interrupted rotation continues on the next call.

### The policy service

`oxpanel-mail-policy.service` runs the daemon binary as `oxpanel-mail`
(groups `postfix` for its Postfix socket, `postdrop` to hand mail in), no
network at all, read-only system except its counters, in SELinux domain
`oxpanel_app_t`. Postfix asks it on `policy.sock` (group `postfix`, 0660:
no tenant can forge requests that use up someone's limit); sites reach it
on `sendmail.sock` (0666; identity from the kernel). It re-reads
`policy.json` (rendered by the daemon: accounts with uid, suspension, limits
and sender domains; mailboxes with account and enabled flag) whenever it
changes.

### Last logins

`Mailbox.last_login` is the last IMAP or POP3 login (webmail logs in over
IMAP), recorded by Dovecot's `last_login` plugin (IMAP and POP3 only, not
delivery or `doveadm`) into a `file:` dict through Dovecot's dict service.
The mail processes run as the account, so they reach the dict socket
(`0660`, group `oxpanel-maildict`) by `mail_access_groups =
oxpanel-maildict`, a group created by the package that only Dovecot's mail
processes get: an account's own code (PHP, applications, tasks, SFTP) does
not have it and cannot write anyone's last login. The dict service
(Dovecot's own account) alone writes `/var/lib/oxpanel-mail/lastlogin/`
(`dovecot` 0700, `dovecot_var_lib_t`); the daemon reads the file (bounded,
no links followed) for `ListMailboxes`. Without the group (a host that has
not got it yet) the plugin is not configured and `last_login` stays unset.

## Receiving

Postfix: `virtual_mailbox_domains`/`virtual_mailbox_maps`/
`virtual_alias_maps` as `texthash:` maps (no `postmap`; read at reload), LMTP
to Dovecot. Every mailbox is listed in the aliases as itself, so a catch-all
(`@domain`, which must be a mailbox of the domain: catch-alls never forward
elsewhere) does not take it. Forwarders: up to 10 destinations
(`too_many_destinations`), any address; `keep_copy` also delivers to the
mailbox of the same address (and requires one); a forwarder over a mailbox
without `keep_copy`, or a mailbox over a forwarder, is `address_in_use`.
Loops through this host's forwarders (any accounts) are refused
(`forward_loop`); Postfix bounds expansion (100) and recursion (10).
Rspamd scans everything (reject at 15, header at 6; no Redis, so no
greylisting, Bayes or Rspamd's own rate limits).

## Suspension and deletion

Suspending an account: its mailboxes are added to Dovecot's deny passdb (no
IMAP/POP3/submission/webmail login; sessions ended with `doveadm kick`), its
domains answer 450 on every Postfix listener (deferred, not bounced: senders
retry for days), its sites' sendmail is refused. Resuming undoes it. Changes
to a suspended account's email are refused (`account_suspended`), like DNS.
Deleting an account is refused while it has mailboxes or forwarders; the
cascading deletion removes its mail domains (servers first), DKIM keys,
autoresponder scripts, webmail certificates and limits, before its sites and
zones; the mail goes with the home.

## DNS

For a local domain: MX 10 to the mail host name; SPF `v=spf1
a:<mail host> ~all`; the DKIM key (`ox<unix time>._domainkey`, 2048-bit RSA)
and a retired key for 7 days after `RotateDkimKey`; DMARC `v=DMARC1; p=none`;
CNAMEs `webmail`, `autoconfig`, `autodiscover` → the mail host; SRV
`_imaps._tcp` 993, `_pop3s._tcp` 995, `_submissions._tcp` 465,
`_submission._tcp` 587. External: the provider's MX only (SPF/DKIM/DMARC are
the provider's; the customer adds them). When this host serves the
domain's zone (same account), these are engine-kept, protected records
(origin `mail`), and the account cannot add records that take their places
(an MX beside the engine's, a second SPF, anything at the DKIM/DMARC names or
the CNAME names); enabling email removes such records the account had added
(logged), as for sites. Otherwise they are returned as `required_records`.
A CNAME at a name a site serves is left out (the site's address wins). An
automatic zone with a mail domain is not removed with its last site.

## TLS and certificates

Clients: TLS only — IMAPS 993, POP3S 995, submission 587 (STARTTLS required,
`smtpd_tls_auth_only`), 465 (TLS from the first byte); no 110/143. TLS 1.2+,
ECDHE AES-GCM/ChaCha20 for Dovecot; Postfix `high` ciphers for mandatory
TLS, opportunistic TLS on port 25. Until the mail host name has a
certificate, a self-signed one (made at first start) is used. Certificates
of the mail host name and of every `webmail.<domain>` come from the ACME
authority through the existing machinery (`acme::prepare`/`run_precheck`/
`run_client`, `tls::verify_material`, the same back-off), on Automatic
HTTPS's cadence and a few seconds after a mail domain is set up; they are
kept in `/etc/pki/oxpanel-mail` (root-only), apart from the sites'. Postfix,
Dovecot and Nginx are reloaded after a new one. SNI per mail domain is not
offered (one host name for every client protocol).

## Host checks (`GetMailHost` warnings)

`GetMailHost` (polled by dashboards) only reads the last result of two
network checks kept in `/var/lib/oxpanel-mail/host-checks.json`; a call
that finds it missing, older than 6 hours or about another host name starts
a new check in the background (one at a time). Through the DNS probe's
transient unit (the daemon has no network): the mail host name's address
and that address's reverse name (`REVERSE_DNS_MISMATCH` unless it is the
mail host name, or when the name does not resolve), and a TCP connection to
port 25 of a public mail server, reading its greeting
(`PORT_25_BLOCKED` when it fails; the server is `OXPANEL_MAIL_PORT25_CHECK`,
by default `gmail-smtp-in.l.google.com`, `off` to never try). A check that
cannot be made (no resolver, the target does not resolve) gives no warning.

## Webmail

Roundcube, one for the host, `oxpanel-webmail.service`: its own PHP-FPM
master as `oxpanel-webmail` (supplementary group `apache` only to read the
package's `defaults.inc.php`), `RCUBE_CONFIG_PATH` → OxPanel's configuration
(`/etc/oxpanel-webmail/roundcube`, root:oxpanel-webmail 0640, with the
session key from a root-only file), SQLite database in
`/var/lib/oxpanel-webmail` (initialised and upgraded by the unit), no
plugins, one identity (the mailbox's address), HTTPS-only cookies, login
rate limit, logins logged to syslog (for fail2ban). It connects to Dovecot
and Postfix on the loopback over TLS like any client, so passwords,
suspension and limits apply unchanged; `IPAddressAllow=localhost`.
Nginx serves it as `webmail.<domain>` for each local mail domain over HTTPS
only once the name has a certificate (503 on HTTP until then, then a 301);
`autoconfig.<domain>` serves Thunderbird's client settings.

## Reconcile and convergence

`MAIL_CONFIG_DRIFT` (a rendered file missing or different, a mail service not
running, mail domains while email is off), `MAIL_DOMAIN_DRIFT` (interrupted
record, account gone, a mailbox directory missing, not a directory or not
owned by the account), `ORPHAN_MAIL_FILE` (a DKIM key or autoresponder
directory no record accounts for). Reconcile reports; the daemon's start-up
convergence repairs (finishes interrupted domains and mailbox removals,
retires DKIM keys, re-renders everything, enables the services), as for DNS.

## Backups

Mail is in the home, so account backups and restores include it (read and
written as the account, links stored as links). The mail records (domains,
mailboxes with their hashes) are engine state under `/var/lib/oxpanel`,
like DNS zones: a restore brings the mail back into existing mailboxes; it
does not recreate deleted mailboxes.

## SELinux

Narrow additions to `packaging/selinux/oxpanel.cil`: the policy service and
Roundcube's PHP-FPM run in `oxpanel_app_t` (with `httpd_exec_t` as an
entrypoint for php-fpm); their socket directories are `httpd_var_run_t`
(Nginx and sites' PHP may connect, through the existing rule); autoresponder
scripts are `dovecot_var_lib_t`. Found on the enforcing VM and allowed
narrowly: Postfix's SMTP server connecting to the policy service (`policy.sock`)
and to Rspamd's milter (Rspamd has no policy module: unconfined service
domain; its socket is in Postfix's spool), and Dovecot's delivery running
OxPanel's sendmail for autoresponders (`sendmail.sock`).

## Not included

Mailing lists; aliases/identities a mailbox may send as besides its own
address; shared mailboxes, calendars, contacts (the later enterprise
product); ManageSieve or user-written filters; per-domain SNI; Outlook's
Autodiscover XML (the SRV/CNAME records are published; Thunderbird's
`autoconfig` is served); greylisting, Bayes, Rspamd's
web interface; checking a pending DKIM key in the background (the caller
calls `RotateDkimKey` again); deleting a mail domain record (mode `off`, or the account's deletion);
recreating deleted mailboxes from a backup.

## Deviations from the contract (for the console)

The proto follows the console's assumed block (names, field numbers)
except:

- `DeleteMailboxResponse` has only `deleted`; there is no `job` field and no
  `JOB_KIND_DELETE_MAILBOX`: the mailbox leaves the servers at once and its
  mail is removed in the background (resumed at start-up).
- `MailWarningKind` adds `MAIL_WARNING_KIND_SERVICE_NOT_RUNNING = 4`.
  `GetMailHost` produces all four kinds. `REVERSE_DNS_MISMATCH` and
  `PORT_25_BLOCKED` come from a check made in the background (see "Host
  checks"): they appear a few seconds after the first `GetMailHost` call
  (or start-up) and are at most 6 hours old.
- `Mailbox.last_login` is set once Dovecot recorded a login (IMAP, POP3,
  webmail); unset means never, or not recorded (a host without the group
  `oxpanel-maildict`).
- `MailDomain.dkim` is unset unless the mode is `LOCAL`; `published` is
  `YES` when the zone is hosted here, otherwise `UNKNOWN` (never `NO`).
- `RotateDkimKey` is a two-step rotation (see "DKIM rotation"). Added:
  `RotateDkimKeyRequest.force = 3` (bool: switch to the new key at once);
  `Dkim.pending_selector = 4`, `Dkim.pending_public_key_record = 5` (the
  new key waiting to be seen in public DNS; empty: no rotation in
  progress) and `Dkim.pending_published = 6` (`YES`/`NO`: what the
  `RotateDkimKey` call that returned it saw in public DNS; `YES` when the
  zone is hosted here; `UNKNOWN` otherwise). The returned `MailDomain`
  shows whether the switch happened: `dkim.selector` is the new selector
  and `pending_selector` is empty. While a key is pending its TXT record is
  also in `required_records`. No new error code: "not seen yet" is an
  answer, not an error.
  The dry-run engine never sees public DNS: there, with the zone not
  hosted, the second step needs `force` (with the zone hosted one call
  switches, as on a real host).
- `MailDnsRecord`: `type` is `MX`, `TXT`, `CNAME` or `SRV`; for SRV `value`
  is `"<weight> <port> <target>"` and `priority` the priority.
- `SetMailDomainRequest.catch_all`: a local part or an address of the
  domain, and it must be a mailbox of the domain; `external_mx` only (and
  required, 1..=10) in `EXTERNAL`.
- `PutMailboxRequest.quota_bytes` 0 means "none of its own", which under an
  account maximum is that maximum. A new mailbox needs a password (`invalid
  password` otherwise).
- Error codes (message prefix `code: …`): as contracted, plus
  `mail_domain_not_found` (NOT_FOUND), `mail_domain_not_owned`
  (FAILED_PRECONDITION), `mailbox_not_found`, `forwarder_not_found`,
  `queued_mail_not_found` (NOT_FOUND). gRPC statuses: `mail_unavailable`,
  `mail_domain_not_local` FAILED_PRECONDITION; `mailbox_exists`,
  `address_in_use` ALREADY_EXISTS; `mailbox_limit_reached`
  RESOURCE_EXHAUSTED; `mailbox_quota_above_limit`, `forward_loop`,
  `too_many_destinations`, `weak_password` INVALID_ARGUMENT.
  `mailbox_exists` occurs only while a mailbox of that address is still
  being removed (`PutMailbox` is create-or-update). Field validation errors
  keep the engine's usual `invalid <field>: …` (INVALID_ARGUMENT). Changes
  to a suspended account's email: `account_suspended: …`
  (FAILED_PRECONDITION). Deleting an account that still has mailboxes or
  forwarders: `tenant '<name>' still has mailboxes or forwarders; …`
  (FAILED_PRECONDITION).
- `GetMailQueueRequest.page_size` 0 is 100, at most 1000.
- Scopes: `GetMailHost`, `GetMailQueue`, `CheckDeliverability`, every
  `Get*`/`List*` and `GetMailUsage`/`GetMailLimits` need `read`;
  `DeleteQueuedMail`, `FlushMailQueue`, `SetMailLimits` need `tenant`; the
  other changes `vhost`.
