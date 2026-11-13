# Lifecycle: database trash, dumps in backups, deleting a customer in one go — design

Date: 2026-11-14. Status: implemented on branch `m3-lifecycle` (from `m2-integration`).

Three features that change what happens to a customer's data at the end of
its life. The owner's decisions are marked **(owner)**; everything else was
decided here and can be reversed.

## Findings that shaped the design (MariaDB 10.5.29, measured)

1. `RENAME TABLE a.t TO b.t` is refused for a table with triggers (`1435
   Trigger in wrong schema`) and for a view (`1450 Changing schema … is not
   allowed`). Stored routines and events belong to the schema and disappear
   with `DROP DATABASE`. MariaDB has no `RENAME DATABASE`.
2. Grants outlive `DROP DATABASE`: a `GRANT … ON \`acme\_wp\`.*` applies to the
   next database called `acme_wp`. `REVOKE` does not reach a session that is
   already inside the database (`USE acme_wp`): it keeps its database-level
   privileges until it changes database. So a grant only stops applying
   immediately if it is revoked **and** the holder's sessions are ended.
3. **A tenant can make a `mariadb-dump | mariadb` restore run SQL as root.**
   Stored-routine and trigger bodies are kept verbatim, including a trailing
   comment, and the client and the server do not tokenise comments the same
   way: the server takes `--` followed by a control character as a comment,
   the client does not. A tenant user with the ordinary privileges created
   `PROCEDURE p() BEGIN SELECT 1; END --<0x01> ;; CREATE DATABASE pwned2 ;;`
   (one statement for the server); `mariadb-dump --routines` wrote it out
   under `DELIMITER ;;`, and restoring that file as root created `pwned2`.
   A client command in a body (`\g`, same comment trick) does the same with
   any delimiter. Table definitions and views are not affected: the server
   prints them from its parse tree (no comments), and data is quoted by the
   dump tool.
4. `CREATE TRIGGER|PROCEDURE|FUNCTION|EVENT` and `DROP TRIGGER` are not
   allowed in prepared statements (`EXECUTE IMMEDIATE`); `CREATE VIEW`,
   `RENAME TABLE`, `DROP VIEW` and `SHOW CREATE …` are.
5. `SHOW CREATE VIEW` after `USE <db>` prints the view without the database
   name (`… from \`t\``), so a view can be re-created under another name.
6. The client has `--binary-mode` (no backslash commands except `\C`, and
   `DELIMITER` only between statements) and `--sandbox` (no command that
   touches the file system) — both present in 10.5.29.

## Re-creating stored objects safely ("guarded replay")

Everything that re-creates a trigger, routine or event from its definition
(trash restore, database restore from a backup) goes through one function,
`db::objects::replay`, which:

- runs **one client process per object**, with `--binary-mode --sandbox`;
- writes `SET SESSION sql_mode` (and `time_zone` for events) as hex
  literals, `USE` the target, then `DELIMITER <d>`, the definition, `<d>` —
  where `<d>` is `?oxpanel-end-<n>?`, chosen so that it occurs nowhere in the
  definition. The client can therefore never split inside the definition,
  and if it mistakes the end of the definition for an open string or
  comment, the server receives the definition followed by `?oxpanel-end…`,
  which is a syntax error everywhere outside a comment: the statement fails,
  nothing else runs (each object has its own process);
- refuses (does not replay, reports) a definition containing `\C` (the one
  client command binary mode still obeys; it would change how the server
  decodes the rest) or a NUL byte;
- refuses an object whose **definer is not an account of the owning tenant**
  (`<tenant>_<suffix>@localhost`): a restore never creates an object that
  runs with someone else's privileges (e.g. a `root` definer and `SQL
  SECURITY DEFINER` a tenant could call);
- afterwards checks the target database: any view, trigger, routine or event
  whose definer is not the tenant's is dropped and reported (this covers
  views loaded from a dump).

Views need no client parsing: they are re-created with `EXECUTE IMMEDIATE`
from a hex literal, in rounds until no more succeed (views may use views).

An object that cannot be re-created never costs table data: the tables are
in place first. Such objects are returned to the caller with kind, name,
reason and their full definition (`DatabaseObjectIssue`), so nothing is lost
silently. Events are re-created as they were (tenants cannot create events —
no `EVENT` privilege — so an event in a tenant database was put there by an
administrator with a tenant definer).

## 1. Database trash (replaces the immediate drop in `DeleteDatabase`)

**(owner)** Deleting does not dump. The database is disabled and moved aside
with its deletion time; the name is free at once; it is purged after 30
days; restoring always needs a new name from the caller (refused if it
exists); trash does not count against the disk limit, but the total size of
a tenant's trash is capped (per-tenant setting, default = the tenant's disk
limit) and a delete that would exceed it is refused with a message to empty
older trash first; the customer may purge one item or all early.

Mechanics:

- One hidden schema per trashed database, `oxpanel_trash_<id>` (id
  `t<unix millis>`). Tenant names starting with `oxpanel` are reserved, so no
  `DbName` (`<tenant>_<suffix>`) can ever be this name — no tenant can create
  it or be granted it. Record `/var/lib/oxpanel/db-trash/<id>.json`: original
  name, tenant, engine, schema, deletion time, size, state, and the captured
  definitions of views, triggers, routines and events (tenant-written SQL;
  root-only file).
- `DeleteDatabase` (same RPC, same `vhost` scope), in this order:
  1. read-only: the database's size; refused (`FAILED_PRECONDITION`) if the
     tenant's trash plus this size would exceed the cap — before anything;
  2. the definitions of views, triggers, routines and events are captured
     (`SHOW CREATE … ` after `USE`, `sql_mode`, `time_zone`, definer) while
     the grants still exist: once a view's definer has lost its privileges
     the server shows the view's stored, fully qualified text, which names
     the old database (found by the integration test);
  3. the database record goes to `deleting`; the tenant's users lose their
     grants on the name (`REVOKE`), and every user that held a grant has its
     sessions ended (`KILL USER`, finding 2) — so the grant stops applying
     now and can never apply to a new database of that name. The objects are
     listed again (one created in between is captured too) and the trash
     record is written (state `moving`) — before anything is dropped;
  4. trash schema created; triggers and views dropped; all tables moved with
     **one** `RENAME TABLE` (atomic); `DROP DATABASE` (routines and events go
     with it); trash record `trashed`; database record deleted.
  Repeating the request after a crash continues from the recorded state (the
  move re-lists what is still in the original schema; the captured
  definitions are not taken again once recorded).
- `ListDatabaseTrash(tenant)` (`read`), `RestoreDatabaseTrash(tenant,
  trash_id, new_name)` (`vhost`), `PurgeDatabaseTrash(tenant, trash_id)` with
  an empty id = all of the tenant's (`vhost`). `DeleteDatabaseResponse`
  carries the trash id and purge time.
- Restore: `new_name` must be a free name of the same tenant (no record, not
  on the server, not covered by a foreign pattern grant, within the database
  cap). Database record (`provisioning`) and trash state `restoring` (with
  the new name) are written first; then `CREATE DATABASE`, one `RENAME TABLE`
  back, views, guarded replay of the rest, definer check, `DROP DATABASE` of
  the trash schema, records. **No grants** are given: the restored database
  is reachable by nobody until the customer grants it (proof needed for
  anything else, and there is none: the old users may have been deleted or
  re-purposed). Repeating an interrupted restore with the same new name
  finishes it; another name is refused while one is recorded.
- Purge: `DROP DATABASE` of the trash schema, then the record. Overdue items
  (older than `OXPANEL_DB_TRASH_DAYS`, default 30) are purged at start-up and
  every hour; one that cannot be purged (MariaDB down) is retried and
  reported by `Reconcile`.
- Cap: `ResourceLimits.db_trash_max_bytes` (0 = the tenant's
  `disk_max_bytes`; unlimited when the tenant has no disk limit). Size is
  data + index as `information_schema` reports it, measured at deletion.
- Disk accounting: XFS user quotas charge blocks to the file's owner, and
  every file under `/var/lib/mysql` belongs to `mysql`. Neither databases nor
  trash ever count against a tenant's disk quota (verified on the acceptance
  VM: a tenant's quota usage does not move when its database grows). The
  trash cap is therefore the only bound on trash, as the owner asked.
- Suspension: trash has no grants, nothing to stop. Restoring while
  suspended is allowed (the database gets no grants anyway).
- Tenant deletion: the refusing `DeleteTenant` also refuses while the tenant
  has trash; the cascade purges it.
- Reconcile: `DATABASE_TRASH_DRIFT` (record whose schema is gone, an
  interrupted move or restore, an item past its purge date) and
  `ORPHAN_DATABASE_TRASH` (an `oxpanel_trash_*` schema without a record).
  A trash schema is also reported if an account OxPanel does not manage has
  a pattern grant covering it.

Rejected: a dump on delete (owner); one shared trash schema (table names of
different databases collide, and a purge would have to pick tables); keeping
the tables in the original schema renamed (`RENAME DATABASE` does not
exist and the name must be free at once).

## 2. Database dumps inside backups

- `CreateBackup` adds every `ready` database of the tenant (trash is not
  backed up). With databases recorded and MariaDB unusable the request is
  refused before anything is created; their size is added to the free-space
  estimate.
- Members per database `<name>`:
  - `db-<name>.sql.gz` (kind `mariadb`): tables, data and views, written by
    the job's worker with `mariadb-dump --single-transaction --quick
    --skip-triggers --hex-blob --skip-comments --skip-dump-date
    --default-character-set=utf8mb4 …` (no `--routines`, no `--events`;
    consistent for InnoDB tables) piped through `gzip`, hashed while copied,
    counted against the same size budget as the home; root-only file; no
    password anywhere (root over the UNIX socket, `unix_socket`
    authentication, `--no-defaults`). It runs in the job's unit: the tenant's
    slice, nice 19, batch CPU, idle-class I/O priority, the job's time limit.
    The server's own work for the dump is charged to MariaDB, not the tenant.
    A failed dump fails the backup (`the dump of database X failed`) and
    leaves nothing.
  - `db-<name>.objects.json` (kind `mariadb-objects`): the triggers,
    routines and events (and view definers), captured by the daemon when the
    backup starts — never replayed from SQL text written by a dump tool
    (finding 3).
- The record, the manifest and `ListBackups` list `databases` (name, size
  on the server, member names). Sealing requires every listed database's
  dump to be complete.
- **Restoring** is separate from files **(owner)**: `RestoreBackupDatabase
  (tenant, backup_id, database, new_name)` (`tenant` scope, like
  `RestoreBackup`) and `RestoreRetainedBackupDatabase(backup_id,
  source_tenant, target_tenant, database, new_name)` (`delete` scope, like
  `RestoreRetainedBackup`) — into a **new** name of the target tenant, never
  over an existing database. It is a job (`JOB_KIND_RESTORE_DATABASE`): the
  daemon records the database (`provisioning`) and creates it empty; the
  worker verifies size and SHA-256 of the dump, then streams it through
  `gzip -d` into `mariadb --binary-mode --sandbox <new_name>` as root; at the
  end the daemon replays the objects (guarded), drops anything with a foreign
  definer, and marks the database ready. A failed load drops the new
  database and its record. No grants.

## 3. Deleting a customer in one go (cascade)

- `DeleteTenant` keeps refusing by default. With `cascade=true` it needs
  `confirm_username` equal to the tenant's name (`INVALID_ARGUMENT`
  otherwise, before anything is read), the `delete` scope (as before), and
  returns a job (`JOB_KIND_DELETE_TENANT`, `GetJob`).
- Optional final backup **(owner)**: `final_backup_retain_days` 1–366
  (0 = none). The cascade first takes a backup (files and databases) with
  that retention; only when it is complete, sealed and retained does
  destruction start. If it fails, the job fails and nothing is deleted.
  The existing retention API took months (1–12); `CreateBackup.retain_days`
  and `RetainBackup.retain_days` (1–366) were added beside the months field
  (setting both is `INVALID_ARGUMENT`).
- Order of removal (each step idempotent, driven by records): tenant record
  to `deleting`, retained backups detached from the name; PHP and
  applications stopped; every site removed (Nginx file, certificate and key,
  Automatic HTTPS state, logs, PHP pool, application unit); SFTP access
  (sessions ended, keys, password, mount); database users (locked, sessions
  killed, dropped) and databases dropped **immediately**, trash purged (no
  30-day trash on a whole-customer deletion); backups that are not retained
  removed; disk quota cleared; `userdel --remove`; slice units; job history;
  record.
- The job runs inside the daemon (no worker: every step is a short
  command) and is recorded (`/var/lib/oxpanel/jobs`, phase and child backup
  job). At start-up the daemon re-drives every running cascade job; a
  half-done deletion is also completed by repeating the request (it returns
  the running job, or starts a new one for a tenant left in `deleting`).
  Once the tenant is `deleting` no final backup is attempted any more (it was
  either complete or not requested).
- While a cascade job runs, no other job for the tenant is started, and the
  refusing `DeleteTenant` is refused.

## Known limitations

- `KILL USER` ends *all* sessions of a user that held a grant on the deleted
  database, also those working in another database of the tenant (MariaDB
  cannot end only the sessions inside one database). A site using that user
  reconnects on its next request.
- A view whose definer has no privileges any more is printed by the server
  (and by `mariadb-dump`) with its original database name. Restored under a
  new name it then refers to the old database (of the same tenant) or fails
  and is reported; it never reaches another tenant's data (the definer's own
  grants apply).
- The dump's own work is done by MariaDB, outside the tenant's slice; only the
  client side of it is charged to the tenant.
- Events are re-created as they were (enabled or not). Tenants cannot create
  events; an event in a tenant database was put there by an administrator.
- The replay guard relies on the client never splitting inside a text that
  does not contain the delimiter and on binary mode obeying no backslash
  command but `\C`. Both were measured on MariaDB 10.5.29; a client that
  behaves otherwise would need the guard revisited (the unit tests pin the
  exact scripts).

## Not included

Dumps of other engines; per-database restore of only some tables; restoring
records; renaming a database in place; grants on a restored database;
off-host copies.
