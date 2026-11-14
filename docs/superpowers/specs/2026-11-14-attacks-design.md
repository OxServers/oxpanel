# Attacks on the newer features, and their crash safety (M4, attacks stream) — design

Date: 2026-11-14. Status: branch `m4-attacks`, from `m3-integration`
(`a136b37`).

## What

The hostile-customer attack suite (acceptance phase 80) and the crash-safety,
gRPC-surface and property tests were written for the base engine. This stream
extends each of them to the features merged since (HTTPS and Automatic HTTPS,
SFTP, disk quotas, databases and the trash, backups, the file manager,
scheduled tasks, PHP settings, backup schedules, DNS hosting, cascade
deletion), and fixes what they found. Engine code changes only where a test
found a defect; each fix has a test that fails without it.

## Phase 80, sections 7-15

Kept in phase 80 (`phases/attack/features.sh`, sourced by `80-attacks.sh`) so
that the AVC accounting and the "nothing outside the tenant changed"
snapshots cover it; its timeout is three times the others'.

- **Where the attacker stands.** A second attacker (`attack3`) has a PHP site,
  a Python application and (for dependency installation) a Node.js one. Feature
  attacks that are code (`phases/attack/feat.py`: DNS over the wire, every
  listener and UNIX socket, SQL through the `mariadb` client) run four ways:
  in the Python application's own process (the language API), as its child,
  as a child of PHP-FPM, and as a scheduled task; database attacks also run
  through PHP's `mysqli`. Where the attacker is a client of the host (SFTP,
  DNS, the operator's panel acting on the tenant's tree, archives, PEM files,
  stored SQL objects) the phase drives real clients on the VM.
- **Expectations as in section 1.** `blocked` (an attack: OPEN fails the
  phase), `open` (a control that proves the harness could succeed), `info`
  (recorded; `docs/SECURITY.md` says why).
- **The battery reaches every new store.** Section 1's probe list is extended
  from what is on disk after the victim got one of everything: every file
  under `/etc/pki/oxpanel`, `/var/lib/oxpanel-acme`, `/var/lib/oxpanel-backups`,
  `/etc/oxpanel-sftp`, `/var/lib/oxpanel-dns`, `/etc/named/oxpanel`, the trash,
  task, job and zone records, plus writes into each directory, the MariaDB
  administrator accounts and `rndc` with the engine's key.
- **DNS hosting is switched on for the phase** (as `run-inside.sh` does) and
  off again at its end.

## Crash safety of the newer workflows

`tests/crash_safety_features.rs` applies `crash_safety.rs`' method (fail /
kill before / kill after every external command, restart on the same disk,
repeat, require consistency and a clean `Reconcile`, with and without the
SELinux code paths) to 28 workflows. To make the fake OS tell the truth for
these workflows three things were added to it, each opt-in so existing tests
are unchanged: the fake BIND follows `zones.conf` (serves exactly the
configured zones and reloads a zone whose statement changed, as `rndc
reconfig` does), `systemctl show` reports job units that `systemd-run` never
started as `not-found`, and the test emulates `systemctl enable`'s timer links
and BIND's key creation. Job workflows are "repeated" the way the daemon
resumes them: a running job is driven to its end, and the request is made
again only if its result is not there.

## Rejected

- *A separate phase (81) for the features.* It would duplicate the setup and
  the AVC classification, and split one threat model over two reports.
- *Running the feature attacks as `setpriv` from the root shell only.* That is
  the tenant's uid but not its SELinux domain, unit sandbox or cgroup: a hole
  in the sandbox would be missed and a denial misclassified.
- *A Pebble CA in phase 80.* `run-inside.sh` already drives one; here the
  attack surface is the challenge directory and the uploaded PEM, which need
  no CA.

## Not included

See `docs/SECURITY.md`, known gap 11.
