# Email limits over a host default; the mail filter's own resolver — design

Date: 2026-11-15. Engine 0.3.1 (branch `m6-mail-defaults`, from `main`
8831f08 = v0.3.0); panel 0.2.1 (console branch `mail-defaults`). The
owner's decisions are fixed; this records how they were built.

## 1. Email limits: a low host default, layers, explicit unlimited

**Before (0.3.0).** One optional value per limit and account
(`/var/lib/oxpanel/mail/limits/<account>.json`); absent meant the host
default from the environment (500 and 200 recipients an hour), 0 meant
unlimited. `SetMailLimits` took four integers, so "unset" could not be
said: the panel sent 0 when a plan had no email limits, which lifted every
limit, and a request that left a field out did the same.

**Model.** Each of the four limits (mailboxes, largest mailbox, recipients
per hour for the account and for a mailbox) resolves through three places,
the first that says something winning:

1. the account's **account layer** — staff's override for this account;
2. the account's **plan layer** — what a panel copies from the plan;
3. the **host default** — a record, `/var/lib/oxpanel/mail/defaults.json`.

A layer's setting is `inherit` (proto `MAIL_LIMIT_MODE_INHERIT = 0`, also
what a left-out field is), a value, or `unlimited`. A host default is a
value or `unlimited`. So unlimited only ever comes from an explicit
`unlimited`; a property test checks that the effective limit always comes
from the first place that sets it and is unlimited only when that place
says so. The policy map the policy service reads is rendered from the
resolved limits, so a change of the default reaches every following
account at once (one apply re-renders it; the service re-reads it).

**Why two layers in the engine** rather than one layer plus a label: the
engine stays role-agnostic (it already accepts plan-derived caps for PHP),
the source of each limit is reported by the engine itself
(`MailLimitEffective.source`), and `oxpanel-ctl` can set either layer on a
host without a panel. **Why the host default is a record** rather than the
environment: it must be changeable from the panel and `oxpanel-ctl` at
runtime. The `OXPANEL_MAIL_RATE_*`/`OXPANEL_MAIL_MAX_*` settings remain as
the built-in default (now 30/20/unlimited/unlimited) until a default is set.

**API.** `SetMailLimitsRequest` gains `layer` (PLAN or ACCOUNT) and
`settings`, which replace that layer; its old four integers are still
accepted from older clients (0 now meaning inherit, written to the account
layer, the plan layer cleared). `MailLimits` keeps the four effective
integers (0 = unlimited) and adds both layers and each effective limit with
its source. `GetMailDefaults` (read) / `SetMailDefaults` (`tenant` scope;
left-out limits unchanged) with the built-in values for "back to the
built-in default".

**Panel policy (console).** Assigning a plan sets the plan layer to the
plan's settings, inherit included (so a move to a plan without email limits
returns the account to the host default), and ends the account's override,
as assigning a plan replaces an account's other limits; later edits of a
plan do not reach its accounts (as for its other limits). Only the
administrator reads and changes the host default.

**Migration.** An engine 0.3.0 record (no `version`) is converted when read:
values become the account layer (absent → inherit, 0 → unlimited), except
that an account holding exactly the old sending defaults (500 and 200)
follows the host default for those two, and one holding all old defaults
(0, 0, 500, 200) for all four. It is written in the new form the next time
it changes. The panel's one-time upgrade step then sets the plan layer of
every account on a plan with email limits and turns the override values
equal to the plan's into `inherit`, so plan-derived values are labelled
"plan" (and a plan that set exactly 500/200 gets them back). Plans
themselves: all-zero email limits become all inherit; a plan with any
non-zero value keeps it and its zeros become `unlimited` (what they meant).
Proved by unit tests and by acceptance `INSTALL=upgrade OLD_REF=v0.3.0`.

**Alternatives rejected.** Keeping 0 = unlimited with a separate "unset"
flag per field (two ways to say the same thing); a sentinel such as
`u32::MAX` for unlimited (invisible in the API); storing the plan layer only
in the panel (the engine could not report the source, and `oxpanel-ctl`
users would see stale labels); a staff override that survives plan changes
(inconsistent with how plans replace an account's other limits; the owner
may reverse this in the panel alone).

## 2. The mail filter's own DNS resolver

**Problem.** Rspamd's blocklist lookups through a public resolver are
refused (`DBL_BLOCKED_OPENRESOLVER`), and ~20 lookups per message through a
forwarder are slow on a cold cache.

**Design.** `install.sh --mail` installs Unbound (AppStream) and writes
`OXPANEL_MAIL_RESOLVER=true`; with that and `/usr/sbin/unbound` present the
engine renders `/etc/oxpanel-mail-resolver/unbound.conf` (root:unbound
0640), points Rspamd at `127.0.0.1:5335` (`local.d/options.inc`) and runs
`oxpanel-mail-resolver.service`, shipped in the engine package:

- 127.0.0.1, port 5335 (not 53: OxPanel's BIND or a system resolver may be
  there); `access-control` refuses everything but 127.0.0.0/8;
- recursive, caching, DNSSEC-validating (`validator iterator`, the
  distribution's root key `/var/lib/unbound/root.key`, kept current by the
  distribution's `unbound-anchor.timer`, which the installer enables);
- bounded: one thread, 512 queries in flight, ~60 MB of caches, 1000
  queries/s per upstream zone, `MemoryMax=256M`;
- hardened: no remote control, ANY refused, minimal responses, never asks a
  server on the loopback, glue/DNSSEC-stripping/below-NXDOMAIN hardening,
  `unwanted-reply-threshold`;
- runs as `unbound` with no privileges at all (port above 1024, no chroot,
  empty capability set, `ProtectSystem=strict`, `PrivateDevices`, syscall
  filter); not the distribution's `unbound.service`; `/etc/resolv.conf`
  untouched; outgoing ports as the distribution's configuration (SELinux);
- `local.d/*.conf` is included and belongs to the operator (forwarders
  where outbound DNS is blocked; the tests' stub zone).

The file is checked by Reconcile (`MAIL_CONFIG_DRIFT`) and the unit is one
of the mail services (enabled by the start-up convergence, before Rspamd).
`GetMailHost` reports the component and `FILTER_RESOLVER_DOWN` when it is
not running. Turned off (`--no-mail-resolver`, Unbound removed) the engine
removes its file (only if it is its own) and disables the unit. Without the
setting nothing is done, so a package upgrade never starts it: a 0.3.0 host
gets it on its next `install.sh --mail` run (a plain installer run keeps the
block's email settings as they are). `--uninstall` stops it,
`--purge-mail` deletes `/etc/oxpanel-mail-resolver`; the firewall is never
touched (loopback only).

**Degraded, not broken.** With the resolver stopped, Rspamd's lookups fail
at once (closed loopback port; 1 s timeout, 2 retransmits) and Postfix's
`milter_default_action = accept` keeps mail flowing; the acceptance tests
deliver with it stopped.

**Not included.** Detecting "blocklist lookups refused" from Rspamd's log
(it logs to the journal; the warning covers the resolver being down only);
a resolver for the whole host; per-user access control on the loopback
(Unbound cannot see uids; the threat model in SECURITY.md §3.5 says what a
customer can and cannot do).

**Tests.** Unit tests (rendered configuration, Rspamd pointed at it, unit
order, drift, the warning, switching off, nothing without the setting);
`run-inside.sh` (service, listener, `unbound-checkconf`, ownership, ANY
refused, warning, mail with it stopped); acceptance phase 18 (a test
authority on 127.0.0.1:5399 in `local.d`: the resolver answers its name;
the filter's SPF question for a sender in that zone reaches the authority;
nothing answers on the host's own address; mail flows with it stopped; zero
AVC denials), phase 80 §16l (forged answers, ANY, control channel, a flood
from a customer, the filter's lookups afterwards), phase 12 (no resolver
after a package upgrade from 0.3.0; present after `install.sh --mail`). No
test queries Spamhaus or any real blocklist on purpose.
