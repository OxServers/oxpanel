# OxPanel engine — threat model

Scope: `oxpanel-daemon` and `oxpanel-ctl` at the state described in
[FEATURES.md](FEATURES.md) (tenants, virtual hosts, PHP-FPM, Node.js and Python
applications, per-site logs, management RPCs, per-peer scopes), and of the
features merged since: HTTPS and Automatic HTTPS, SFTP, disk quotas,
databases and their trash, backups, the file manager, scheduled tasks, PHP
settings, backup schedules and DNS hosting. Their own threat analysis is in
their design records (`docs/superpowers/specs/2026-11-1{3,4}-*-design.md`);
their attacks are tested as the operator by `tests-integration/run-inside.sh`
(also on the VM, phase 20) and from where a hostile customer stands — its
PHP, its applications, its scheduled tasks, its SFTP session, the files,
archives, SQL objects and DNS data it controls — by phase 80, sections 1 and
7-15 (`tests-acceptance/phases/attack/features.sh`).

This is a description of what the code does and what the tests try, not a
promise. Every statement of the form "stopped by X" names the test that tries
to break it; the section "Known gaps" lists what is not stopped. Anything not
listed here has not been analysed.

## 1. Assets

| Asset | Where | Why it matters |
|---|---|---|
| Root on the host | the daemon runs as uid 0 | Whoever can make the daemon run an arbitrary command or write an arbitrary path owns the machine. |
| The records | `/var/lib/oxpanel/{tenants,vhosts}/*.json`, root-only | A record is the daemon's proof that it created something. Forged records let a caller make the daemon `userdel` a system account. |
| Other tenants' data | `/home/<tenant>`, mode `0700` (+ one ACL for the web server) | The product's reason to exist. |
| The web server | Nginx, `nginx` account | It can read every tenant's document root; whoever controls what it reads controls what the world sees. |
| Host availability | CPU, memory, tasks, disk, the single mutation lock | One tenant must not be able to take the host or another tenant down. |
| The configuration | `/etc/oxpanel/daemon.env`, generated Nginx, systemd and PHP-FPM files | Written by the daemon from validated values; edited, they become code that runs as root or as another user. |

## 2. Trust boundaries

```
 internet ──► nginx (80) ──► tenant PHP-FPM socket / tenant app socket        [tenant code, tenant uid]
                │
 panel (proprietary, separate host service account)
      │  gRPC over /run/oxpanel/oxpanel.sock   (SO_PEERCRED, per-peer scopes)
      ▼
 oxpanel-daemon (root, sandboxed unit, no network namespace)
      │  argv only, no shell:  useradd · userdel · setfacl · nginx -t · systemctl · setpriv · semanage …
      ▼
 operating system: accounts, cgroups, Nginx, systemd, SELinux policy
```

1. **Network to Nginx.** Anyone on the Internet. Nginx is the only listener the
   engine creates.
2. **Nginx to tenant code.** Nginx hands requests to a per-tenant UNIX socket;
   the tenant's code runs under the tenant's uid.
3. **Tenant code to the host.** The kernel (uid separation, cgroups), the unit
   sandbox, SELinux.
4. **Panel to daemon.** One UNIX socket. The kernel tells the daemon who is on
   the other end.
5. **Daemon to the OS.** The daemon never trusts an API value: it is validated
   by an allow-list type before it reaches a path, a file or an argv.

## 3. Attackers, and what stops each

### 3.1 Tenant code (a customer who can upload PHP, Node.js or Python)

Assumed capability: arbitrary code execution as the tenant's uid inside the
tenant's PHP-FPM instance or application unit, including spawning processes,
creating files and links in its own home, and making network connections.

| Goal | Stopped by | Tried by |
|---|---|---|
| Read or write another tenant's home, document root, application directory, logs | Home `0700` owned by the tenant; the web server's ACL names `nginx` only; log directory `root:root 0750` | phase 80, section 1 (every runtime, language-native and through a child process) |
| Read `/etc/shadow`, the records, `daemon.env`, root's files | root-owned modes; records `0600` in a `0700` directory | phase 80, section 1 |
| Reach the engine API | socket `root:oxpanel 0660` and the peer gate (a tenant is not in the allowed set) | phase 80 (connect and `oxpanel-ctl` from inside the tenant); `unauthorised_peer_is_cut_off_before_grpc`; run-inside "unauthorised peer (bob, a tenant) is refused" |
| Connect to another tenant's PHP or application socket | socket directory `0750` with an ACL for the web server only; socket ACL names `nginx` | phase 80, section 1; run-inside |
| Plant a symlink or hard link so that Nginx serves a file the tenant does not own | `disable_symlinks if_not_owner`; `protected_hardlinks` | phase 80, section 2 |
| Plant a symlink so that the root daemon acts outside the tenant (`setfacl`, `restorecon`/`semanage`, document-root creation, `du`, `userdel -r`) | document root created as the tenant and verified to be a real directory owned by the tenant; `setfacl --physical`; `du` without following links; `userdel` removes links, not targets | phase 80, section 4 (including a race between a path flipping from directory to link and repeated configuration and removal of the site) |
| Make the file manager act outside the home (a link to `/etc/passwd` or another home, a directory swapped for a link during a walk, archive entries named `../x` or `/etc/x`, links and hard links in archives, zip and tar bombs, names with control or bidirectional characters) | every file operation runs as the tenant (never root) with no capabilities; request paths resolved with `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)`, walks descriptor to descriptor with `O_NOFOLLOW`; archive entries rebuilt component by component and refused, never "fixed"; ratio, byte and entry caps while extracting | `files_tests` (symlinks out of the home, traversal, hostile archives, bombs); run-inside "file manager" section (as root against a real home) |
| Escalate privilege | `NoNewPrivileges`, empty capability bounding set, `RestrictSUIDSGID`, no setuid helpers reachable | phase 80 probes `sudo`, `su`, `systemd-run`, `mount`, `nsenter`, `setfacl /etc`, `useradd` from inside each runtime; `/proc/self/status` checks |
| Exhaust memory | `MemoryMax` on the tenant slice, `MemorySwapMax=0`: the kernel kills inside the slice | phase 80, section 5 (PHP, Node.js, Python); the victim and the host are unaffected |
| Fork bomb | `TasksMax` on the slice | phase 80, section 5b |
| Fill `/tmp` | `PrivateTmp`: the tenant's `/tmp` is per unit and discarded at restart. **Not bounded in size: see gaps.** | phase 80, section 5c |
| Keep running after suspension, site removal or deletion | the processes live in the unit's cgroup (`KillMode=control-group`), so stopping the unit ends detached children too | phase 80, section 6 |
| Smuggle a header or path to reach another tenant's site, or a suspended site | Nginx parses and re-serialises every request; one upstream socket per tenant; the suspended block has no document root and no upstream | phase 80, section 3: Host variants, absolute-form requests, duplicate or malformed headers, `Content-Length` with `Transfer-Encoding`, CRLF in the path, traversal encodings |
| Make the engine misbehave with a hostile name, domain or path | allow-list newtypes; rendered files built only from validated values | `tests/properties.rs` (every validator and renderer), `tests/grpc_surface.rs` |
| Make root run SQL through a stored object (a routine or trigger body that the `mariadb` client splits differently from the server: `--<control char>`, `\g`; proven to work against `mariadb-dump --routines \| mariadb` on MariaDB 10.5) when a database is moved to the trash and back or restored from a backup | dumps leave triggers, routines and events out; they are captured as text and replayed one per client process with `--binary-mode --sandbox` under a delimiter that does not occur in the text; `\C` and NUL refused; views via `EXECUTE IMMEDIATE` from a hex literal; objects with a definer outside the tenant never created, and dropped after a load | `db::objects` tests (`replay_scripts_are_exact_and_refuse_client_commands`), run-inside "the crafted procedure ran nothing as root on restore" |
| Keep reaching a deleted database (an open session, or a grant that would apply to the next database of the same name) | grants revoked and the holders' sessions ended before the move; the trash schema `oxpanel_trash_<id>` cannot be named by any tenant; a restored database gets no grants | `deleting_moves_the_database_aside_with_its_objects`; run-inside "a session inside the deleted database is ended", "the old user's grant does not apply to the new database of the same name" |
| Use a scheduled task to escape: run as root or another tenant, outlive its time limit, reach the engine, read another tenant | a task is a oneshot unit with `User=` the tenant in the tenant's slice and the application sandbox (`InaccessiblePaths=/run/oxpanel` on top), `TimeoutStartSec` ends its whole control group; the engine renders the unit from integers and allow-listed words only (no command line, every argument quoted with `%` and `$` escaped, no quotes or backslashes accepted), and a URL task can only fetch the tenant's own server names, pinned to 127.0.0.1 | `task` unit tests (`injection_attempts_in_every_field_are_refused`, `a_record_that_was_tampered_with_is_never_rendered`), `tests/essentials_properties.rs` (every accepted argument list round-trips through systemd's quoting; no argument changes another line of the unit), run-inside "its output is readable, it ran as the tenant…", "nothing it started outlives it", "refused requests created no unit" |
| Escape SFTP: a shell, a command, port, socket or stdio forwarding, a key planted in `~/.ssh/authorized_keys`, the engine's keys file, other homes or the host through the chroot, links and hard links out of it, a session kept across suspension or key removal | `Match Group oxpanel-tenants` drop-in (forced `internal-sftp`, chroot, every forwarding off, `MaxAuthTries 3`, keys file outside the home), `restrict` on every key, keys file `root:root 0640` + ACL for its tenant, sessions ended through the tenant's user slice | phase 80, section 7 (real `ssh`/`sftp` clients: `-W`, `-L`, `-R`, `-D`, `-tt`, a command, planted key; `get`/`put`/`ln`/`symlink`/`rename` outside; sshd's effective configuration per tenant; a live session through suspension and `end_sessions`; key removal and re-addition while the tenant plants `home/<t>` links) |
| Make the file manager act outside the home, or as root, on a tree, an archive or a name the tenant controls | see the file-manager row above | phase 80, section 8: every operation through planted links to `/etc`, `/`, another home and relative links, absolute and traversal forms, a FIFO, 72 jobs raced against a directory swapped for a link to `/etc`, hostile archives uploaded through the panel (zip slip, absolute names, links and hard links, devices, FIFOs, set-uid, names with control and bidirectional characters, a leading dash, non-UTF-8, ratio, gzip and entry-count bombs), quota exhaustion mid-upload and mid-extraction, writes while suspended, the job spool |
| Read another site's private key or the ACME account; answer an ACME challenge for a name the tenant does not host; inject Nginx configuration through an uploaded certificate or key | keys root-only in `/etc/pki/oxpanel`; challenges served from the engine's directory (`disable_symlinks on`) for every site, before any tenant location; PEM normalised to its blocks; certificates checked against the site's names and the key | battery (every file of `/etc/pki/oxpanel` and `/var/lib/oxpanel-acme`); phase 80, section 9 (planted challenge answers and links, traversal into the ACME directory, a request for a foreign name, PEM with directives before, between and after its blocks); `src/proptests.rs` (`accepted_pem_is_only_blocks_of_the_expected_kind`) |
| Reach another tenant's database or the trash from tenant code; `FILE`, `LOAD DATA`, `INTO OUTFILE`; the server's administrator accounts through the socket; exhaust the server's connections | one account per database user, grants only on the tenant's own databases, no global privilege; `MAX_USER_CONNECTIONS` per account; MariaDB's `unix_socket` accounts are `root` and `mysql` only | phase 80, section 10, from the Python application (in-process and child), PHP (`mysqli` and a child) and a scheduled task: 27 attempts each; 60 simultaneous connections; `feature_properties.rs` (names, grants, quoting) |
| Make a backup capture or a restore write what the tenant may not; run code as root or outside the sandbox through a restored `package.json`; restore across tenants or into a name outside the tenant's prefix; inherit a deleted tenant's retained backup | archives read and written as the tenant; dependencies installed by `npm`/`pip` in a transient unit as the tenant (see gap 13); backups and database names looked up for the tenant only | phase 80, section 11 (links to `/etc/shadow`, another home and the records; restore over a document root swapped for a link to `/etc`; an install script reporting its uid, groups and what it can reach; a retained backup and a new tenant of the same name and uid) |
| Make a scheduled task outlive its limit, its tenant's suspension or deletion; reach another site or the network through a URL task | the unit's control group (`TimeoutStartSec`, `KillMode=control-group`); URL tasks pinned to the tenant's own names on 127.0.0.1, `--max-redirs 0` | phase 80, section 12 (double fork, `setsid`, `nohup`; a redirect to another tenant's site; 20 URL forms: other names, numeric, octal, hex and IPv6 loopback, credentials, ports, other schemes, metadata address) |
| Change PHP settings with `.user.ini` beyond the pool's hardening | `open_basedir`, `allow_url_include`, `display_errors` are `php_admin_*`; Nginx's `client_max_body_size` bounds uploads whatever PHP allows | phase 80, section 12 |
| Inject into a zone file; take a zone of another tenant, a public suffix, the engine's catalog or a special-use domain; transfer, update or control the DNS server from tenant code | records rendered one per line from validated values; zones refused when they overlap another tenant, are a public suffix, the catalog or special-use (found by phase 80, section 6 below); transfers need the TSIG key, no dynamic updates, no recursion, control channel keyed | phase 80, section 13 (from the Python application, PHP and a task: AXFR/IXFR of a victim's zone and the catalog, recursion, `version.bind`, raw and `nsupdate` dynamic updates, `rndc`; 25 hostile record values and names; engine records; DNSSEC on and off) |
| Race the tenant's own cascade deletion to survive it, to make the engine delete outside the home, or to leave something to the next tenant of the name | the cascade stops units, tasks, sessions, database accounts, then `userdel`; nothing is followed through links | phase 80, section 14 (a respawning task, detached children, a database session, an upload in flight, a live SFTP session, links to `/etc`, `/usr`, the records and the victim; then the same name created again) |
| Talk to any listener or UNIX socket on the host | see gap 2 | phase 80, section 15 (every listening TCP port and every UNIX socket in the host's namespace, from the application, PHP and a task) |
| Change PHP settings beyond what the API offers (`open_basedir`, `allow_url_include`, another site's limits) | only eight settings exist in the API, as numbers and flags the engine renders (a time zone is allow-listed and must be a `TZif` file); a site with settings gets a pool of its own, so nothing leaks between sites the way `fastcgi_param PHP_VALUE` would; the hardening lines are not reachable | `php_settings` unit tests, `accepted_php_settings_render_only_known_lines`, run-inside "a time zone that would inject a directive is refused" |

**What SELinux adds, and how a denial is classified.** Kernel permission
checks (DAC) run before SELinux, so an AVC denial for tenant code means Unix
permissions did *not* stop that particular call and the policy did. Phase 80
lists every AVC raised during the attacks and classifies it by source and
target domain:

* source is tenant code (`httpd_t` for PHP-FPM, `oxpanel_app_t` for
  applications), or the target is an object of tenant code (a system daemon
  refusing to write into a tenant's pipe): an attack that was denied. Pass.
* source is anything else (the daemon, `init_t`, Nginx's own processes): a
  legitimate operation was refused, a hole in our policy or a feature that
  broke under enforcement. The phase fails.

At the commit tested, one full run of the attacks raised 28 denials, all of the
first kind: `getattr` by `php-fpm` on `/etc/shadow` and `/etc/gshadow`
(`shadow_t`) and on a systemd unit file (`systemd_unit_file_t`), `read` of a
unit file by a child `cat`, `mounton /mnt` by `mount` (`httpd_t`), and a
`dbus-broker` refusal to write into a PHP child's pipe after `systemd-run`.
With sections 7-15 (m4-attacks, on the VM) a run raises 43, still all of
the first kind; the new ones are PHP's children (`httpd_t`) refused
`name_connect` to the loopback ports of sshd, Nginx, rpcbind and BIND's
control channel (`ssh_port_t`, `http_port_t`, `portmap_port_t`,
`rndc_port_t`) and access to the rpcbind and udev sockets while section 15
tries every listener; the application domain and scheduled tasks are not
refused them by SELinux (gap 2) and are recorded as `info`.
They show the layering working: `stat()` of `/etc/shadow` is allowed by Unix
permissions (search permission on `/etc` is all it needs) and SELinux refuses it,
while opening the file was refused by Unix permissions first; the application unit
file is world-readable (`0644`), so for PHP it is SELinux alone that keeps it
unread (phase 80 records, per runtime, what is readable among such world-readable
files as `info`). Zero denials came from the daemon, `init_t` or Nginx.

### 3.2 A compromised panel (the proprietary service holding a peer slot)

Assumed capability: authenticated calls on the socket with whatever scopes the
operator granted that uid; arbitrary field values.

* **Scopes.** `OXPANEL_PEER_SCOPES=uid:read+vhost` confines a peer before
  validation or any OS call; a peer limited to `read+vhost` can never delete a
  tenant. A new RPC without a scope decision fails the build
  (`every_rpc_has_a_scope_decision`) and every RPC is tested both with and without
  its scope (`every_rpc_is_refused_without_its_scope_and_passes_with_it`).
* **Validation.** Every field is an allow-list newtype; malformed, oversized,
  truncated and unknown-field messages leave state untouched
  (`malformed_requests_are_refused_without_side_effects`,
  `oversized_requests_are_refused_before_decoding`,
  `random_requests_never_panic_or_corrupt_state`).
* **File content.** A `vhost`-scoped peer can read and change any tenant's
  files through the file manager, as that tenant and only beneath its home
  (`ReadFile` and every change need `vhost`; listing needs `read`, so a
  monitoring peer never sees content such as a database password). Nothing
  it sends reaches a file outside a home, and nothing runs as root.
* **Ownership.** The daemon only modifies what a record says it created, so even
  a full-scope peer cannot make it delete `root` or adopt `nginx`
  (`never_adopts_a_foreign_account_or_group`).
* **Deleting a customer in one go.** `DeleteTenant` with `cascade` needs the
  `delete` scope *and* the tenant's name repeated in `confirm_username`, so a
  stray or forged call with only a name wipes nothing
  (`a_cascade_needs_the_name_twice_and_a_valid_retention`). A `delete`-scoped
  peer can still delete any tenant on purpose; that is the scope's meaning.
* **Blast radius it still has.** A `tenant`-scoped peer can create accounts and
  set limits; a `vhost`-scoped peer can point a site's document root and
  application entry anywhere *inside a tenant's own home* and choose which
  tenant's code runs. Nothing in the engine stops a full-scope panel from
  suspending every tenant. These are the panel's powers by design; its own
  authorisation is its own problem.
* **Denial of service.** Requests are capped (256 KiB, 16 streams per
  connection, 300 s), every mutation takes one global lock, and a slow
  `InstallAppDependencies` does not hold it
  (`a_running_dependency_installation_blocks_nobody`). A peer that holds
  connections open does not starve others
  (`idle_and_abusive_connections_do_not_starve_other_clients`).

### 3.3 A local unprivileged user (an account that is not a tenant: a shell user, a service)

* Cannot connect to the socket (`0660 root:oxpanel`) and is cut off by the peer
  gate before any HTTP/2 is parsed if it could. Membership is judged from the
  account database, not from the process's own group list
  (run-inside "process groups alone do not grant access").
* Cannot read the records or the configuration (root-only).
* Can read world-readable files the engine writes: unit files and PHP-FPM
  configuration (`0644`). These contain tenant names and paths, never secrets.
  See the gaps.

### 3.4 The network

* The engine opens no network listener: gRPC is a UNIX socket, the daemon unit
  has `PrivateNetwork=yes` and `IPAddressDeny=any`; nothing to scan.
* Nginx on port 80 is the only exposure. An unknown or missing `Host` reaches
  no tenant (`return 444`); a suspended site serves nothing from the tenant.
  HTTPS (port 443) is served for sites with a certificate (uploaded, ACME, or
  Automatic HTTPS); an unknown name or a client without SNI gets a failed
  handshake. Sites without a certificate, and port 80 unless a site redirects,
  are in the clear. sshd (SFTP, tenants confined to a chroot) is the other
  exposure the engine configures.
* DNS hosting (off by default) exposes port 53 (TCP and UDP) through
  `oxpanel-dns.service`, BIND in its packaged `named_t` domain under a
  hardened unit. It answers authoritatively for hosted zones only: no
  recursion and no cache for anybody (no open resolver, nothing to poison),
  response-rate limiting against reflection, version and host name hidden,
  no dynamic updates. Zone transfers and the catalog of hosted domains need
  the TSIG key (`hmac-sha256`, root:named 0640, never in argv, logs or
  responses); NOTIFY goes only to configured secondaries. The control
  channel listens on the loopback with a root-only key; the daemon reaches
  it through `rndc` in a transient unit, keeping its own `PrivateNetwork`.
  Every zone file is rendered from validated records (one line per record,
  no `$` directive; property-tested against arbitrary input) and checked by
  `named-checkzone` before the server sees it. A tenant can only change its
  own zones; zones never overlap, never are a public suffix, and never
  cover another tenant's sites. DNSSEC private keys belong to the server's
  account (0600) and are never read by the engine. The delegation and DS
  checks run in a transient unit under a dynamic unprivileged user.

## 4. What the tests prove, by layer

| Layer | Where | Runs in |
|---|---|---|
| Validators and renderers: no input panics; an accepted value round-trips and has the property its type promises; rendered files gain no line their inputs did not ask for | `oxpanel-daemon/tests/properties.rs` (names, domains, paths, units, Nginx, FPM, file-manager paths and modes), `tests/essentials_properties.rs` (task units, URLs, schedules, PHP settings), `tests/feature_properties.rs` (SSH keys and the keys file, key labels, SFTP and database passwords, database names, grants and SQL quoting, job/backup/trash/upload identifiers), `src/proptests.rs` (uploaded certificate and key PEM, logs, `systemctl` output), `src/dns/proptests.rs` (zone files, names, the probe's wire-format parser) | `make test` |
| gRPC surface: scope decisions generated from `panel.proto`, unauthorised peers, malformed/oversized/truncated/unknown-field frames to every RPC, field-level hostile messages to every RPC, concurrent clients, no lost updates, no deadlock | `tests/grpc_surface.rs` | `make test` |
| Crash safety: the daemon is killed before and after every external command of every workflow, restarted, the request repeated; the end state must equal the uninterrupted run and reconcile clean (also with SELinux paths). Base workflows in `tests/crash_safety.rs`; certificates and Automatic HTTPS, SFTP keys and passwords, disk quotas, databases and the trash, scheduled tasks, per-site PHP pools, backup schedules, DNS zones, records and DNSSEC, backup, restore, database restore, file jobs and cascade deletion in `tests/crash_safety_features.rs` | `tests/crash_safety.rs`, `tests/crash_safety_features.rs` | `make test` |
| Real-host attacks from tenant code | `tests-acceptance/phases/80-attacks.sh` | `make acceptance` (VM, SELinux enforcing) |
| Feature to test mapping | `docs/traceability.map`, `scripts/traceability.sh` | `make traceability`, CI |

## 5. Known gaps

Stated plainly, in order of how much they matter.

1. **Disk quotas only where the host enforces them.** With XFS user quotas
   (handbook §9.1, acceptance phase 15) a tenant's files are bounded wherever
   its uid owns them on that file system; without them (or for a tenant
   without a disk limit) a tenant can fill the file system through its home,
   its private `/tmp` or its logs, and take every other tenant's writes down
   with it. Phase 80 measures the `/tmp` case and reports the space consumed.
2. **Applications are not confined by a policy beyond `oxpanel_app_t`.** The
   domain lets the web server connect to them and nothing else, but inside it
   the application can do what its uid can: read world-readable files
   (`/etc/passwd`, and see below), connect to any TCP port (including `127.0.0.1`
   services and the Internet) and, as on any default Linux, see other
   processes' command lines in `/proc` (no `hidepid`; phase 80 records what is
   readable as `info`, it asserts only that other tenants' data, secrets and
   control surfaces are not). There is no outbound network filter.
3. **PHP is not confined by SELinux beyond `httpd_t`.** `open_basedir` is the
   language-level fence; `exec()` is not disabled, so a script can run any
   program the uid can (phase 80 runs the same probes with `cat` as a child to
   show the OS layer holds without it). A tenant can raise `memory_limit` with
   `ini_set`; only the cgroup bounds it.
4. **The daemon is not confined by SELinux.** It runs as root with a hardened
   unit (no network, capability deny-list, seccomp allow-list, `ProtectSystem=strict`)
   but in an unconfined-service domain: a bug that gives code execution in the
   daemon is root on the host.
5. **World-readable files and listings** (phase 80 reports each, per runtime,
   as `info`, not as a failure; observed on the VM from Node.js and Python code,
   PHP is kept from most of them by `open_basedir` and SELinux): `/etc/oxpanel-php/<tenant>.conf`
   and the unit files are `0644`; `/run/oxpanel-app` and `/run/oxpanel-php` can be listed; another
   tenant's process command line is readable in `/proc`. Together a local or tenant user learns tenant
   names, home paths, application domains and the programs other tenants run (no secret is in
   them: the property tests assert that rendered files contain only the template and the validated inputs;
   a secret passed on a command line would leak, and the engine never does that). Also Nginx's own
   `/var/log/nginx/access.log` and `error.log` are `0644` (the distribution's
   default). Tenant sites log to their own closed files, so the main log holds
   only requests no site claimed (unknown `Host`, bare IP: client address,
   `Host`, user agent).
6. **No resource accounting for the web tier.** Nginx workers are shared; one
   tenant's request flood competes with everyone's (no `limit_req`).
7. **Single mutation lock.** Throughput of provisioning is serial by design;
   `docs/PERFORMANCE.md` has the numbers. A panel that hangs a client mid-request
   cannot hold the lock beyond the 300 s request timeout.
8. **A full-scope panel is fully trusted.** See 3.2.
9. **No tamper-evident audit trail.** Every request is logged to the
   journal with the calling peer (`peer="uid=0 gid=0 pid=…"`), the RPC and the
   tenant or domain, but the journal is the only record and root can edit it.
10. **Tenant homes and `/tmp` are outside the daemon's control.** A tenant can
    leave its own home in any state (delete its document root, replace it by a
    link, fill it): the daemon tolerates all of it (phase 80, section 4) but
    cannot make the files sensible.
11. **What phase 80 does not try.** It attacks every feature from tenant
    code (sections 7-15), but not: an ACME order end to end (no test CA on
    the VM in phase 80; `run-inside.sh` drives one against Pebble), so a
    tenant racing the ACME helper's challenge files is covered only by the
    challenge directory being the engine's own and not writable; the External
    Account Binding secret (not configured on the VM; the file is checked to
    be root-only by the engine at start); a `requirements.txt` naming a
    hostile package index (the `package.json` case shows the installer's
    identity and reach, which are the same for `pip`); the DNS server's
    response-rate limiting under load; SFTP brute force beyond reading sshd's
    effective `MaxAuthTries` (the fail2ban phase covers bans).
12. **DNS: first come, first served.** A tenant can create the zone of any
    registrable domain no other tenant holds or has a site in, whether or
    not it owns the domain. Publicly that only matters once the registry
    delegates the domain to this host's name servers; on this host it
    blocks the real owner's zone until the operator deletes it. There is no
    proof of ownership beyond `CheckDnsZone`'s delegation report. This
    includes a zone holding the host's own name-server names (refused today
    only because `named-checkzone` wants addresses for in-zone name
    servers); whether those should be reserved too is an owner decision.
    Injection is tried in `run-inside.sh` (every field) and in phase 80,
    section 13; the DNS server's response-rate limiting is enabled but its
    effect under attack is not measured.
13. **Dependency installation runs in the stock unconfined service domain,
    with the account's supplementary groups.** `npm install` and `pip
    install` run in a transient unit as the tenant (`NoNewPrivileges`, no
    capabilities, `ProtectSystem=strict`, only the home writable), but not in
    `oxpanel_app_t` and not through `setpriv --clear-groups`: a package's
    install script holds the tenant's marker groups `oxpanel-tenants` (and
    `oxpanel-sftp-password`), which own no file on the host (phase 80,
    section 11 checks both). Unix permissions are what keeps it from other
    tenants and the engine, as for the application itself.
14. **World-listable directories of the stack.** `/var/lib/mysql` is
    MariaDB's own `0755`: tenant code can list it and learn the names of
    every database on the host (the databases themselves are `0700
    mysql`); `/var/lib/oxpanel-acme` must be searchable by the web server and
    lists its four subdirectory names. Phase 80 records both as `info`.
    Restricting `/var/lib/mysql` to `0711` is a host decision (the package
    owns the mode).
15. **PHP settings are defaults, not limits.** `memory_limit`,
    `upload_max_filesize`, `max_execution_time` and the others are
    `php_value`: a script (`ini_set`, `set_time_limit`) or a `.user.ini`
    changes them (phase 80 records `memory_limit` after a `.user.ini` as
    `info`). The cgroup bounds memory, Nginx's `client_max_body_size` bounds
    uploads (asserted), the hardening lines cannot be changed (asserted).

## 6. Defects found by the testing work

Each has a regression test next to the code; the final report of the work
repeats them with the gate results.

| Severity | Defect | Found by | Fixed |
|---|---|---|---|
| medium | A request that switched PHP or an application off, or removed a site, and was interrupted (daemon killed) left the PHP pool or the application *running with no record*; repeating the request did not clean up, because the decision was taken from the record that was already gone. A removed customer's code kept running. Now decided from what is on disk and the record is deleted last. | `tests/crash_safety.rs` | yes |
| medium | A dependency installation that finished after its tenant was suspended (or its site removed) restarted the application: a suspended tenant's code ran again. Now the restart is decided under the mutation lock from the current records. | `tests/grpc_surface.rs` | yes |
| low | PHP-FPM and application units took the slice name from the record's `slice_unit` string instead of deriving it from the validated tenant name, so a record edited by hand (or damaged) with a line break in that field would have added a directive to a unit. Now derived. | `tests/properties.rs` | yes |
| medium | On SELinux hosts `RemoveVirtualHost` failed (`Internal`) when the tenant had deleted its own document root (accident or attack): `restorecon` was run on the missing path. The site could then never be removed, and the tenant never deleted, without editing the engine's records by hand. | `80-attacks.sh` | yes |
| high | A tenant's zone request (`CreateDnsZone`, which the customer tier holds) for `catalog.oxpanel.invalid`, the engine's own catalog of hosted zones, was accepted; the server's checker then rejected the configuration, but the zone's record and file stayed, so every later configuration was rejected too: no tenant could change DNS any more, and every cascading deletion failed at its DNS step (host-wide denial of service by one customer). Reserved names (the catalog, `.invalid`, `.localhost`, `.local`, `.arpa`, `.onion`, `.alt`) are now refused before anything is written. | `80-attacks.sh` (section 13) | yes: `dns::tests::the_catalog_and_special_use_domains_cannot_become_zones` |
| medium | A zone creation the server's configuration checker rejected left its record and zone file behind (whatever the reason for the rejection), poisoning every later configuration as above. The creation is now undone whole. | `80-attacks.sh` (section 13) | yes: `dns::tests::a_zone_the_configuration_checker_rejects_leaves_nothing` |
| medium | The DNS server was told to reload only when the configuration files changed. A daemon killed (or a reload that failed) between writing them and the reload left the server on its old configuration for good: a new zone not served, a deleted one still served, a DNSSEC switch not applied; neither repeating the request nor restarting the daemon changed the files again, so nothing reloaded. A marker written before the files and removed after the reload now decides. | `tests/crash_safety_features.rs` | yes |
| low | Switching DNSSEC off, interrupted after the zone's record was saved, left the signing keys and the server's signing state; repeating the request returned at once because the record already said "off". The tail of an interrupted switch is now completed by the repeat. | `tests/crash_safety_features.rs` | yes |
| low | `GetHostInfo`, which a dashboard polls, parsed every tenant and virtual-host record to produce two counts: 277 ms at 10,000 tenants. Now counts directory entries (a damaged record still counts). | `oxpanel-bench` | yes |
