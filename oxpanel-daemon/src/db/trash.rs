//! The database trash: `DeleteDatabase` moves a database aside instead of
//! dropping it.
//!
//! Owner decisions (see `docs/superpowers/specs/2026-11-14-lifecycle-design.md`):
//! no dump on delete; the name is free at once; purged after
//! `OXPANEL_DB_TRASH_DAYS` (30); a restore always needs a new name; the trash
//! does not count against the disk limit but its total size per tenant is
//! capped (`Limits::db_trash_cap`); the customer may purge early.
//!
//! A trashed database is a hidden schema `oxpanel_trash_<id>` holding its
//! tables (moved with one `RENAME TABLE`) and a record holding the
//! definitions of its views, triggers, routines and events (which cannot be
//! moved; see [`super::objects`]). Nobody is granted the hidden schema, and no
//! tenant can name it.
//!
//! Grants on the old name are revoked and the holders' sessions ended before
//! anything moves: MariaDB keeps database-level grants after `DROP DATABASE`
//! (they would apply to the next database of that name) and a session already
//! inside the database keeps its privileges until it leaves it.

use tracing::{info, warn};

use super::mariadb::{self, content, Schema};
use super::objects;
use super::{ready_tenant, revoke_script, sql, unusable, DbService, DATABASE};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::host::{Drift, DriftKind};
use crate::records::{
    now_unix, DatabaseRecord, DbObjectDef, DbState, DbTrashRecord, ObjectIssue, TenantRecord,
    TrashState, RECORD_VERSION,
};
use crate::validate::{DbName, TrashId, Username, TRASH_SCHEMA_PREFIX};

/// What `DeleteDatabase` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deleted {
    /// OxPanel has no such database.
    NotFound,
    /// The record existed but the server had no such database: nothing to
    /// keep, the record is gone.
    Vanished,
    /// In the trash.
    Trashed(Box<DbTrashRecord>),
}

/// A tenant's trash with its total size and cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashListing {
    pub items: Vec<DbTrashRecord>,
    pub total_bytes: u64,
    /// `None`: no limit.
    pub cap_bytes: Option<u64>,
}

fn new_trash_id(ctx: &Ctx) -> Result<TrashId> {
    let mut millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    loop {
        let id = TrashId::from_millis(millis);
        if ctx.store.load_trash(&id)?.is_none() {
            return Ok(id);
        }
        millis += 1;
    }
}

fn trash_of(ctx: &Ctx, tenant: &Username) -> Result<Vec<DbTrashRecord>> {
    let mut all = ctx.store.list_trash()?;
    all.retain(|t| t.tenant == tenant.as_str());
    Ok(all)
}

/// The tenant's trash record `id`; another tenant's is `NOT_FOUND`.
fn trash_item(ctx: &Ctx, tenant: &Username, id: &TrashId) -> Result<DbTrashRecord> {
    ctx.store
        .load_trash(id)?
        .filter(|t| t.tenant == tenant.as_str())
        .ok_or_else(|| Error::TrashNotFound {
            tenant: tenant.to_string(),
            id: id.to_string(),
        })
}

impl DbService {
    /// Move a database OxPanel created into its tenant's trash.
    pub async fn delete_database(&self, name: &str) -> Result<Deleted> {
        let name = DbName::parse(name, "name")?;
        let _guard = self.ctx.lock.lock().await;
        let Some(mut rec) = self.ctx.store.load_database(&name)? else {
            return Ok(Deleted::NotFound);
        };
        let schema = Schema::of_db(&name);
        let server = mariadb::snapshot(&self.ctx).await?;
        let on_server = server.schemata.contains(name.as_str());
        let pending = self
            .ctx
            .store
            .list_trash()?
            .into_iter()
            .find(|t| t.name == rec.name && t.state == TrashState::Moving);
        // 1. Read-only: refused before anything changes.
        let listed = if on_server {
            mariadb::objects(&self.ctx, &schema).await?
        } else {
            mariadb::SchemaObjects::default()
        };
        let size = if on_server {
            mariadb::schema_sizes(&self.ctx, std::slice::from_ref(&schema))
                .await?
                .get(name.as_str())
                .copied()
                .unwrap_or(0)
        } else {
            0
        };
        if pending.is_none() && rec.state != DbState::Deleting {
            self.refuse_over_cap(name.tenant(), size)?;
        }
        // Captured while the grants still exist: once a view's definer has
        // lost its privileges, the server shows the view's stored, fully
        // qualified text, which names the old database.
        let early = if pending.is_none() && on_server && rec.state != DbState::Deleting {
            Some(objects::capture(&self.ctx, &schema, &listed, true).await?)
        } else {
            None
        };
        // 2. Nobody reaches it any more: grants revoked, holders' sessions ended.
        if rec.state != DbState::Deleting {
            rec.state = DbState::Deleting;
            self.ctx.store.save_database(&rec)?;
        }
        self.take_away(&rec, &name, &server).await?;
        // What is there now (an object made in between is kept too).
        let listed = if on_server {
            mariadb::objects(&self.ctx, &schema).await?
        } else {
            listed
        };
        if !on_server && pending.is_none() {
            self.ctx.store.delete_database(&name)?;
            warn!(tenant = %rec.tenant, database = %name, "database record removed; the server had no such database");
            return Ok(Deleted::Vanished);
        }
        // 3. Definitions captured and recorded before anything is dropped.
        let mut trash = if let Some(t) = pending {
            t
        } else {
            let objects = self.complete_capture(&schema, &listed, early).await?;
            let id = new_trash_id(&self.ctx)?;
            let now = now_unix();
            let t = DbTrashRecord {
                version: RECORD_VERSION,
                id: id.to_string(),
                name: rec.name.clone(),
                tenant: rec.tenant.clone(),
                engine: rec.engine,
                deleted_at_unix: now,
                purge_at_unix: now
                    .saturating_add(u64::from(self.ctx.config.db_trash_days) * 86_400),
                size_bytes: size,
                state: TrashState::Moving,
                objects,
            };
            self.ctx.store.save_trash(&t)?;
            t
        };
        // 4. Move: triggers and views dropped, all tables in one RENAME,
        //    the schema (with its routines and events) dropped.
        let id = TrashId::parse(&trash.id)?;
        let target = Schema::of_trash(&id);
        let mut script = content::create_schema(&target);
        if on_server {
            for o in listed.objects.iter().filter(|o| {
                matches!(
                    o.kind,
                    crate::records::DbObjectKind::Trigger | crate::records::DbObjectKind::View
                )
            }) {
                script.push_str(&content::drop_object(&schema, o.kind, &o.name));
            }
            script.push_str(&content::rename_tables(&schema, &target, &listed.tables));
            script.push_str(&content::drop_schema(&schema));
        }
        mariadb::run_hardened(&self.ctx, script).await?;
        trash.state = TrashState::Trashed;
        self.ctx.store.save_trash(&trash)?;
        self.ctx.store.delete_database(&name)?;
        info!(tenant = %rec.tenant, database = %name, trash = %id, bytes = trash.size_bytes, objects = trash.objects.len(), "database moved to the trash");
        Ok(Deleted::Trashed(Box::new(trash)))
    }

    /// The definitions captured before the grants were revoked, brought up
    /// to date with what `listed` (taken afterwards) holds: objects dropped
    /// in between are left out, objects made in between are captured now.
    async fn complete_capture(
        &self,
        schema: &Schema,
        listed: &mariadb::SchemaObjects,
        early: Option<Vec<DbObjectDef>>,
    ) -> Result<Vec<DbObjectDef>> {
        let Some(mut defs) = early else {
            return objects::capture(&self.ctx, schema, listed, true).await;
        };
        let missing = mariadb::SchemaObjects {
            tables: Vec::new(),
            objects: listed
                .objects
                .iter()
                .filter(|o| !defs.iter().any(|d| d.kind == o.kind && d.name == o.name))
                .cloned()
                .collect(),
        };
        defs.retain(|d| {
            listed
                .objects
                .iter()
                .any(|o| o.kind == d.kind && o.name == d.name)
        });
        defs.extend(objects::capture(&self.ctx, schema, &missing, true).await?);
        Ok(defs)
    }

    /// The tenant's users lose every grant on `name`, and the sessions of
    /// those that held one end: a grant revoked from a session that is inside
    /// the database would otherwise keep working until it leaves it.
    async fn take_away(
        &self,
        rec: &DatabaseRecord,
        name: &DbName,
        server: &mariadb::ServerState,
    ) -> Result<()> {
        let mut script = String::new();
        let mut holders = Vec::new();
        for user in self.ctx.store.list_db_users()? {
            if user.tenant != rec.tenant {
                continue;
            }
            let user_name = DbName::parse(&user.name, "name")?;
            let revoke = revoke_script(server, &user_name, name);
            let recorded = user.grants.contains(&rec.name);
            if !revoke.is_empty() && server.account(&user_name).is_some() {
                script.push_str(&revoke);
                script.push_str(&sql::kill_sessions(&user_name));
            }
            if recorded {
                holders.push(user);
            }
        }
        if !script.is_empty() {
            mariadb::execute(&self.ctx, script).await?;
        }
        for mut user in holders {
            user.grants.retain(|g| g != &rec.name);
            self.ctx.store.save_db_user(&user)?;
        }
        Ok(())
    }

    fn refuse_over_cap(&self, tenant: &Username, size: u64) -> Result<()> {
        let Some(rec) = self.ctx.store.load_tenant(tenant)? else {
            return Ok(());
        };
        let Some(cap) = rec.limits.db_trash_cap() else {
            return Ok(());
        };
        let held: u64 = trash_of(&self.ctx, tenant)?
            .iter()
            .map(|t| t.size_bytes)
            .sum();
        if held.saturating_add(size) > cap {
            return Err(Error::DbTrashFull {
                tenant: tenant.to_string(),
                held,
                size,
                cap,
            });
        }
        Ok(())
    }

    /// The tenant's trash, oldest first, with its total and cap.
    pub async fn list_trash(&self, tenant: &str) -> Result<TrashListing> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let rec = self
            .ctx
            .store
            .load_tenant(&tenant)?
            .ok_or_else(|| Error::TenantNotFound(tenant.to_string()))?;
        let items = trash_of(&self.ctx, &tenant)?;
        Ok(TrashListing {
            total_bytes: items.iter().map(|t| t.size_bytes).sum(),
            cap_bytes: rec.limits.db_trash_cap(),
            items,
        })
    }

    /// Bring a trashed database back as `new_name` (a free name of the same
    /// tenant), with no grants. Returns the database and the objects that
    /// could not be re-created.
    pub async fn restore_trash(
        &self,
        tenant: &str,
        trash_id: &str,
        new_name: &str,
    ) -> Result<(DatabaseRecord, Vec<ObjectIssue>)> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let id = TrashId::parse(trash_id)?;
        let new_name = DbName::parse_for(new_name, &tenant, "new_name")?;
        let _guard = self.ctx.lock.lock().await;
        ready_tenant(&self.ctx, &tenant)?;
        let mut trash = trash_item(&self.ctx, &tenant, &id)?;
        let server = mariadb::snapshot(&self.ctx).await?;
        match &trash.state {
            TrashState::Moving => {
                return Err(unusable(
                    DATABASE,
                    &DbName::parse(&trash.name, "name")?,
                    "is still being moved into the trash; repeat DeleteDatabase first",
                ))
            }
            TrashState::Restoring { new_name: recorded } if recorded != new_name.as_str() => {
                return Err(Error::invalid(
                    "new_name",
                    format!("a restore of this database as '{recorded}' was interrupted; repeat it with that name"),
                ))
            }
            TrashState::Restoring { .. } => {}
            TrashState::Trashed => {
                claimable(&self.ctx, &server, &tenant, &new_name)?;
                self.ctx.store.save_database(&DatabaseRecord {
                    version: RECORD_VERSION,
                    name: new_name.to_string(),
                    tenant: tenant.to_string(),
                    engine: trash.engine,
                    created_at_unix: now_unix(),
                    state: DbState::Provisioning,
                })?;
                trash.state = TrashState::Restoring {
                    new_name: new_name.to_string(),
                };
                self.ctx.store.save_trash(&trash)?;
            }
        }
        let mut rec = self
            .ctx
            .store
            .load_database(&new_name)?
            .unwrap_or(DatabaseRecord {
                version: RECORD_VERSION,
                name: new_name.to_string(),
                tenant: tenant.to_string(),
                engine: trash.engine,
                created_at_unix: now_unix(),
                state: DbState::Provisioning,
            });
        let source = Schema::of_trash(&id);
        let target = Schema::of_db(&new_name);
        let tables = if server.schemata.contains(source.as_str()) {
            mariadb::objects(&self.ctx, &source).await?.tables
        } else {
            Vec::new()
        };
        let script =
            content::create_schema(&target) + &content::rename_tables(&source, &target, &tables);
        mariadb::run_hardened(&self.ctx, script).await?;
        let mut issues = objects::recreate(&self.ctx, &target, &tenant, &trash.objects).await?;
        issues.extend(objects::drop_foreign(&self.ctx, &target, &tenant).await?);
        mariadb::run_hardened(&self.ctx, content::drop_schema(&source)).await?;
        rec.state = DbState::Ready;
        self.ctx.store.save_database(&rec)?;
        self.ctx.store.delete_trash(&id)?;
        info!(%tenant, from = %trash.name, database = %new_name, trash = %id, not_recreated = issues.len(), "database restored from the trash");
        Ok((rec, issues))
    }

    /// Purge one of the tenant's trashed databases, or all of them (`trash_id`
    /// empty). Returns how many were purged.
    pub async fn purge_trash(&self, tenant: &str, trash_id: &str) -> Result<u32> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let id = if trash_id.is_empty() {
            None
        } else {
            Some(TrashId::parse(trash_id)?)
        };
        let _guard = self.ctx.lock.lock().await;
        if self.ctx.store.load_tenant(&tenant)?.is_none() {
            return Err(Error::TenantNotFound(tenant.to_string()));
        }
        let items = match &id {
            Some(id) => vec![trash_item(&self.ctx, &tenant, id)?],
            None => trash_of(&self.ctx, &tenant)?,
        };
        let mut purged = 0;
        for t in items {
            if t.state != TrashState::Trashed {
                if id.is_some() {
                    return Err(unusable(
                        DATABASE,
                        &DbName::parse(&t.name, "name")?,
                        "is being moved into or restored from the trash; repeat that request first",
                    ));
                }
                continue;
            }
            purge_one(&self.ctx, &t).await?;
            purged += 1;
        }
        Ok(purged)
    }
}

/// A name a new database may take: unknown to OxPanel and to the server,
/// reachable by no account OxPanel does not manage, within the cap. Used by
/// `CreateDatabase` and by both kinds of restore.
pub(crate) fn claimable(
    ctx: &Ctx,
    server: &mariadb::ServerState,
    tenant: &Username,
    name: &DbName,
) -> Result<()> {
    if ctx.store.load_database(name)?.is_some() {
        return Err(unusable(
            DATABASE,
            name,
            "already exists; choose a name that is not in use",
        ));
    }
    if server.schemata.contains(name.as_str()) {
        return Err(Error::DbNotManaged {
            kind: DATABASE,
            name: name.to_string(),
        });
    }
    let managed = super::managed_accounts(&ctx.store.list_db_users()?);
    if let Some((grantee, pattern)) = super::foreign_reach(server, &managed, name.as_str()) {
        warn!(database = %name, %grantee, %pattern, "database refused: an unmanaged account's grant covers the name");
        return Err(unusable(
            DATABASE,
            name,
            "would be reachable by an account OxPanel does not manage (a database-level grant whose pattern covers the name; see the journal); remove that grant or choose another name",
        ));
    }
    let max = ctx.config.db_max_databases;
    let owned = ctx
        .store
        .list_databases()?
        .iter()
        .filter(|d| d.tenant == tenant.as_str())
        .count();
    if owned >= usize::try_from(max).unwrap_or(usize::MAX) {
        return Err(Error::DbLimitReached {
            tenant: tenant.to_string(),
            kind: DATABASE,
            max,
        });
    }
    Ok(())
}

/// Drop a trash schema, then forget it. The caller holds the mutation lock.
async fn purge_one(ctx: &Ctx, t: &DbTrashRecord) -> Result<()> {
    let id = TrashId::parse(&t.id)?;
    mariadb::run_hardened(ctx, content::drop_schema(&Schema::of_trash(&id))).await?;
    ctx.store.delete_trash(&id)?;
    info!(tenant = %t.tenant, database = %t.name, trash = %id, "deleted database purged from the trash");
    Ok(())
}

/// Purge every trashed database past its date. Returns how many.
pub async fn purge_overdue(ctx: &Ctx) -> Result<usize> {
    let _guard = ctx.lock.lock().await;
    let now = now_unix();
    let due: Vec<DbTrashRecord> = ctx
        .store
        .list_trash()?
        .into_iter()
        .filter(|t| t.state == TrashState::Trashed && t.purge_at_unix <= now)
        .collect();
    for t in &due {
        purge_one(ctx, t).await?;
    }
    Ok(due.len())
}

/// Purge overdue trash now and then every hour, for as long as the daemon runs.
pub fn spawn_purger(ctx: Ctx) {
    tokio::spawn(async move {
        loop {
            // Nothing to do (and no MariaDB needed) without trash.
            let any = ctx.store.list_trash().map_or(true, |t| !t.is_empty());
            if any {
                match purge_overdue(&ctx).await {
                    Ok(0) => {}
                    Ok(n) => info!(purged = n, "overdue deleted databases purged"),
                    Err(e) => {
                        warn!(error = %e, "could not purge overdue deleted databases; will retry");
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    });
}

/// Whether the tenant still has deleted databases in its trash.
pub fn tenant_has_trash(ctx: &Ctx, tenant: &Username) -> Result<bool> {
    Ok(!trash_of(ctx, tenant)?.is_empty())
}

/// Remove every database object of a tenant at once — users, databases,
/// trash — for the deletion of the whole tenant (no 30-day trash). The
/// caller holds the mutation lock. Idempotent.
pub async fn drop_everything(ctx: &Ctx, tenant: &TenantRecord) -> Result<()> {
    let name = Username::parse(&tenant.username)?;
    let users: Vec<_> = ctx
        .store
        .list_db_users()?
        .into_iter()
        .filter(|u| u.tenant == tenant.username)
        .collect();
    let databases: Vec<_> = ctx
        .store
        .list_databases()?
        .into_iter()
        .filter(|d| d.tenant == tenant.username)
        .collect();
    let trash = trash_of(ctx, &name)?;
    if users.is_empty() && databases.is_empty() && trash.is_empty() {
        return Ok(());
    }
    let server = mariadb::snapshot(ctx).await?;
    // Mark first, so a crash part-way leaves records that say what is going on.
    let mut script = String::new();
    for mut u in users.clone() {
        if u.state != DbState::Deleting {
            u.state = DbState::Deleting;
            ctx.store.save_db_user(&u)?;
        }
        let user = DbName::parse(&u.name, "name")?;
        if server.account(&user).is_some() {
            script.push_str(&sql::set_locked(&user, true));
            script.push_str(&sql::kill_sessions(&user));
            script.push_str(&sql::drop_user(&user));
        }
    }
    for mut d in databases.clone() {
        if d.state != DbState::Deleting {
            d.state = DbState::Deleting;
            ctx.store.save_database(&d)?;
        }
        script.push_str(&sql::drop_database(&DbName::parse(&d.name, "name")?));
    }
    for t in &trash {
        script.push_str(&content::drop_schema(&Schema::of_trash(&TrashId::parse(
            &t.id,
        )?)));
    }
    if !script.is_empty() {
        mariadb::run_hardened(ctx, script).await?;
    }
    for u in &users {
        ctx.store.delete_db_user(&DbName::parse(&u.name, "name")?)?;
    }
    for d in &databases {
        ctx.store
            .delete_database(&DbName::parse(&d.name, "name")?)?;
    }
    for t in &trash {
        ctx.store.delete_trash(&TrashId::parse(&t.id)?)?;
    }
    info!(tenant = %name, users = users.len(), databases = databases.len(), trash = trash.len(), "every database object of the tenant dropped");
    Ok(())
}

/// Reconcile: trash records against the server.
pub fn drifts(
    trash: &[DbTrashRecord],
    server: &mariadb::ServerState,
    tenants: &[TenantRecord],
    out: &mut Vec<Drift>,
) {
    let now = now_unix();
    for t in trash {
        let schema = TrashId::parse(&t.id)
            .map(|id| id.schema())
            .unwrap_or_default();
        let problem = if tenants.iter().any(|x| x.username == t.tenant) {
            match &t.state {
                TrashState::Moving => Some(
                    "moving the database into the trash was interrupted; repeat DeleteDatabase"
                        .to_owned(),
                ),
                TrashState::Restoring { new_name } => Some(format!(
                    "restoring it as '{new_name}' was interrupted; repeat RestoreDatabaseTrash with that name"
                )),
                TrashState::Trashed if !server.schemata.contains(&schema) => Some(format!(
                    "the trash schema {schema} does not exist on the server; PurgeDatabaseTrash removes the record"
                )),
                TrashState::Trashed if t.purge_at_unix <= now => Some(
                    "past its purge date but not purged yet (is MariaDB running?)".to_owned(),
                ),
                TrashState::Trashed => None,
            }
        } else {
            Some(format!("tenant '{}' has no record", t.tenant))
        };
        if let Some(detail) = problem {
            out.push(Drift::new(
                DriftKind::DatabaseTrashDrift,
                format!("{} ({})", t.id, t.name),
                detail,
            ));
        }
    }
    for schema in server
        .schemata
        .iter()
        .filter(|s| s.starts_with(TRASH_SCHEMA_PREFIX))
    {
        if !trash
            .iter()
            .any(|t| TrashId::parse(&t.id).is_ok_and(|id| &id.schema() == schema))
        {
            out.push(Drift::new(
                DriftKind::OrphanDatabaseTrash,
                schema.as_str(),
                "a trash schema that no trash record accounts for (reported, never removed)",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::mariadb::hex_text;
    use crate::db::tests::{harness, kinds, mutations, Harness, MARIADB, PASSWORD};
    use crate::records::DbObjectKind;
    use crate::system::bin;
    use crate::validate::Limits;

    /// Every object kind, all by `alice_app`, plus a procedure whose definer
    /// is root (put there by an administrator).
    const OBJECTS: [&str; 6] = [
        "CREATE ALGORITHM=UNDEFINED DEFINER=`alice_app`@`localhost` SQL SECURITY DEFINER VIEW `recent` AS select `posts`.`id` AS `id` from `posts`",
        "CREATE DEFINER=`alice_app`@`localhost` TRIGGER stamp BEFORE INSERT ON posts FOR EACH ROW SET NEW.id = NEW.id + 1",
        "CREATE DEFINER=`alice_app`@`localhost` PROCEDURE `cleanup`()\nBEGIN DELETE FROM posts; END",
        "CREATE DEFINER=`alice_app`@`localhost` FUNCTION `twice`(x INT) RETURNS int(11)\n    DETERMINISTIC\nRETURN x * 2",
        "CREATE DEFINER=`alice_app`@`localhost` EVENT `nightly` ON SCHEDULE EVERY 1 DAY DO CALL cleanup()",
        "CREATE DEFINER=`root`@`localhost` PROCEDURE `rootly`()\nSELECT 1",
    ];

    /// `alice_wp` with two tables and every kind of object, granted to
    /// `alice_app`.
    async fn fixture(h: &Harness) -> Result<()> {
        h.db.create_database("alice", "alice_wp", MARIADB).await?;
        h.db.create_user("alice", "alice_app", PASSWORD, MARIADB)
            .await?;
        h.db.grant("alice_app", "alice_wp").await?;
        let mut script = format!(
            "CREATE TABLE `alice_wp`.`posts` (id INT);\nCREATE TABLE `alice_wp`.`users` (id INT);\nUSE `alice_wp`;\nSET SESSION sql_mode = {};\n",
            hex_text("STRICT_TRANS_TABLES")
        );
        for o in OBJECTS {
            script.push_str("DELIMITER $$\n");
            script.push_str(o);
            script.push_str("\n$$\n");
        }
        h.sys.mariadb_admin(&script)?;
        h.sys.clear_calls();
        Ok(())
    }

    fn trashed(d: Deleted) -> DbTrashRecord {
        match d {
            Deleted::Trashed(t) => *t,
            other => panic!("not trashed: {other:?}"),
        }
    }

    /// The scripts sent through the hardened client.
    fn hardened(h: &Harness) -> Vec<String> {
        h.sys
            .calls_to(bin::MARIADB)
            .into_iter()
            .filter(|c| {
                c.args
                    .iter()
                    .rev()
                    .take(2)
                    .map(|a| a.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    == ["--sandbox", "--binary-mode"]
            })
            .filter_map(|c| c.stdin)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .collect()
    }

    fn name(s: &str) -> DbName {
        DbName::parse(s, "name").unwrap_or_else(|e| panic!("{e}"))
    }

    fn record(h: &Harness, id: &str) -> Result<DbTrashRecord> {
        Ok(h.ctx
            .store
            .load_trash(&TrashId::parse(id)?)?
            .unwrap_or_else(|| panic!("record {id}")))
    }

    async fn grant_exists(h: &Harness, user: &str, db: &str) -> Result<bool> {
        Ok(mariadb::snapshot(&h.ctx)
            .await?
            .grant_on(&name(user), &name(db))
            .is_some())
    }

    #[tokio::test]
    async fn deleting_moves_the_database_aside_with_its_objects() -> Result<()> {
        let h = harness().await;
        fixture(&h).await?;
        let t = trashed(h.db.delete_database("alice_wp").await?);
        let schema = format!("oxpanel_trash_{}", t.id);
        assert_eq!(
            mutations(&h),
            vec![
                "USE `alice_wp`;\nSHOW CREATE VIEW `recent`;\nSHOW CREATE TRIGGER `stamp`;\nSHOW CREATE FUNCTION `twice`;\nSHOW CREATE PROCEDURE `cleanup`;\nSHOW CREATE PROCEDURE `rootly`;\nSHOW CREATE EVENT `nightly`;\n".to_owned(),
                "REVOKE ALL PRIVILEGES ON `alice\\_wp`.* FROM 'alice_app'@'localhost';\nKILL USER 'alice_app'@'localhost';\n".to_owned(),
                format!("CREATE DATABASE IF NOT EXISTS `{schema}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\nDROP VIEW IF EXISTS `alice_wp`.`recent`;\nDROP TRIGGER IF EXISTS `alice_wp`.`stamp`;\nRENAME TABLE `alice_wp`.`posts` TO `{schema}`.`posts`, `alice_wp`.`users` TO `{schema}`.`users`;\nDROP DATABASE IF EXISTS `alice_wp`;\n"),
            ]
        );
        // Every script that names tenant-chosen things went through the
        // hardened client; the revoke (validated names only) needs no more.
        let hard = hardened(&h);
        assert_eq!(hard.len(), 2, "{hard:?}");
        assert!(hard.iter().any(|s| s.contains("SHOW CREATE")));
        assert!(hard.iter().any(|s| s.contains("RENAME TABLE")));
        // The record: trashed, every object kept, purged in 30 days.
        assert_eq!(record(&h, &t.id)?, t);
        assert_eq!(t.state, TrashState::Trashed);
        assert_eq!((t.name.as_str(), t.tenant.as_str()), ("alice_wp", "alice"));
        assert_eq!(t.purge_at_unix, t.deleted_at_unix + 30 * 86_400);
        assert_eq!(t.size_bytes, 16_384);
        let kept: Vec<(DbObjectKind, &str, &str)> = t
            .objects
            .iter()
            .map(|o| (o.kind, o.name.as_str(), o.definer.as_str()))
            .collect();
        assert_eq!(
            kept,
            vec![
                (DbObjectKind::View, "recent", "alice_app@localhost"),
                (DbObjectKind::Trigger, "stamp", "alice_app@localhost"),
                (DbObjectKind::Function, "twice", "alice_app@localhost"),
                (DbObjectKind::Procedure, "cleanup", "alice_app@localhost"),
                (DbObjectKind::Procedure, "rootly", "root@localhost"),
                (DbObjectKind::Event, "nightly", "alice_app@localhost"),
            ]
        );
        let texts: Vec<&str> = t.objects.iter().map(|o| o.definition.as_str()).collect();
        let [view, trigger, procedure, function, event, rootly] = OBJECTS;
        assert_eq!(
            texts,
            vec![view, trigger, function, procedure, rootly, event]
        );
        assert!(t
            .objects
            .iter()
            .filter(|o| o.kind != DbObjectKind::View)
            .all(|o| o.sql_mode == "STRICT_TRANS_TABLES"));
        // On the server: the tables in the hidden schema, the name gone.
        assert_eq!(h.sys.mariadb_schema("alice_wp"), None);
        assert_eq!(
            h.sys.mariadb_schema(&schema),
            Some((vec!["posts".to_owned(), "users".to_owned()], vec![]))
        );
        assert!(h
            .db
            .list_users("alice")
            .await?
            .iter()
            .all(|u| u.grants.is_empty()));
        // The name is free at once, and the old grant does not come back.
        assert!(h.db.create_database("alice", "alice_wp", MARIADB).await?.1);
        assert!(!grant_exists(&h, "alice_app", "alice_wp").await?);
        assert!(h.host.reconcile().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn restoring_needs_a_new_name_and_recreates_the_objects_without_grants() -> Result<()> {
        let h = harness().await;
        fixture(&h).await?;
        let t = trashed(h.db.delete_database("alice_wp").await?);
        let schema = format!("oxpanel_trash_{}", t.id);
        h.db.create_database("alice", "alice_wp", MARIADB).await?;
        h.sys.clear_calls();
        // Refused: an existing name, another tenant's name, another
        // tenant's trash, no name.
        assert!(matches!(
            h.db.restore_trash("alice", &t.id, "alice_wp").await,
            Err(Error::DbObjectUnusable { .. })
        ));
        assert!(matches!(
            h.db.restore_trash("alice", &t.id, "acme_back").await,
            Err(Error::InvalidInput {
                field: "new_name",
                ..
            })
        ));
        assert!(matches!(
            h.db.restore_trash("acme", &t.id, "acme_back").await,
            Err(Error::TrashNotFound { .. })
        ));
        assert!(matches!(
            h.db.restore_trash("alice", &t.id, "").await,
            Err(Error::InvalidInput { .. })
        ));
        assert!(mutations(&h).is_empty(), "refusals change nothing");
        let (rec, issues) = h.db.restore_trash("alice", &t.id, "alice_back").await?;
        assert_eq!(
            (rec.name.as_str(), rec.state),
            ("alice_back", DbState::Ready)
        );
        // The root-definer procedure is not re-created; it is reported with
        // its definition.
        let [issue] = issues.as_slice() else {
            panic!("{issues:?}");
        };
        assert_eq!(
            (issue.kind, issue.name.as_str()),
            (DbObjectKind::Procedure, "rootly")
        );
        assert!(
            issue.reason.contains("definer 'root@localhost'"),
            "{}",
            issue.reason
        );
        assert_eq!(issue.definition, OBJECTS[5]);
        let target = Schema::of_db(&name("alice_back"));
        let replay = |n: &str| {
            t.objects
                .iter()
                .find(|o| o.name == n)
                .and_then(|d| objects::replay_script(&target, d))
                .unwrap_or_else(|| panic!("{n}"))
        };
        let sent = mutations(&h);
        assert_eq!(
            sent,
            vec![
                format!("CREATE DATABASE IF NOT EXISTS `alice_back` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\nRENAME TABLE `{schema}`.`posts` TO `alice_back`.`posts`, `{schema}`.`users` TO `alice_back`.`users`;\n"),
                content::create_view(&target, OBJECTS[0]),
                // One client process per object: routines, triggers, events.
                replay("cleanup"),
                replay("twice"),
                replay("stamp"),
                replay("nightly"),
                format!("DROP DATABASE IF EXISTS `{schema}`;\n"),
            ]
        );
        let hard = hardened(&h);
        assert!(
            sent.iter().all(|s| hard.contains(s)),
            "all through the hardened client"
        );
        let (tables, mut objs) = h
            .sys
            .mariadb_schema("alice_back")
            .unwrap_or_else(|| panic!("restored schema"));
        objs.sort();
        assert_eq!(tables, ["posts", "users"]);
        let want =
            |k: &str, n: &str| (k.to_owned(), n.to_owned(), "alice_app@localhost".to_owned());
        assert_eq!(
            objs,
            vec![
                want("EVENT", "nightly"),
                want("FUNCTION", "twice"),
                want("PROCEDURE", "cleanup"),
                want("TRIGGER", "stamp"),
                want("VIEW", "recent"),
            ]
        );
        assert!(
            !grant_exists(&h, "alice_app", "alice_back").await?,
            "no grants"
        );
        assert_eq!(h.sys.mariadb_schema(&schema), None);
        assert_eq!(h.ctx.store.load_trash(&TrashId::parse(&t.id)?)?, None);
        assert!(matches!(
            h.db.restore_trash("alice", &t.id, "alice_again").await,
            Err(Error::TrashNotFound { .. })
        ));
        assert!(h.host.reconcile().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn a_delete_over_the_trash_cap_is_refused_before_anything_changes() -> Result<()> {
        let h = harness().await;
        h.tenants
            .update_limits("alice", Limits::default().with_db_trash(20_000))
            .await?;
        h.db.create_database("alice", "alice_a", MARIADB).await?;
        h.db.create_database("alice", "alice_b", MARIADB).await?;
        h.db.create_user("alice", "alice_app", PASSWORD, MARIADB)
            .await?;
        h.db.grant("alice_app", "alice_b").await?;
        trashed(h.db.delete_database("alice_a").await?);
        h.sys.clear_calls();
        assert!(matches!(
            h.db.delete_database("alice_b").await,
            Err(Error::DbTrashFull {
                held: 16_384,
                size: 16_384,
                cap: 20_000,
                ..
            })
        ));
        assert!(mutations(&h).is_empty(), "refused before any change");
        let rec = h.ctx.store.load_database(&name("alice_b"))?;
        assert_eq!(rec.map(|r| r.state), Some(DbState::Ready));
        assert!(grant_exists(&h, "alice_app", "alice_b").await?);
        let listing = h.db.list_trash("alice").await?;
        assert_eq!(
            (listing.total_bytes, listing.cap_bytes),
            (16_384, Some(20_000))
        );
        assert_eq!(h.db.purge_trash("alice", "").await?, 1);
        trashed(h.db.delete_database("alice_b").await?);
        // Without a setting the disk limit is the cap; without one, none.
        assert_eq!(h.db.list_trash("acme").await?.cap_bytes, None);
        Ok(())
    }

    #[tokio::test]
    async fn purging_one_or_all_and_overdue_items() -> Result<()> {
        let h = harness().await;
        let mut ids = Vec::new();
        for db in ["alice_a", "alice_b", "alice_c"] {
            h.db.create_database("alice", db, MARIADB).await?;
            ids.push(trashed(h.db.delete_database(db).await?).id);
        }
        let [a, b, c] = ids.as_slice() else {
            panic!("{ids:?}");
        };
        h.sys.clear_calls();
        assert!(matches!(
            h.db.purge_trash("acme", a).await,
            Err(Error::TrashNotFound { .. })
        ));
        assert!(matches!(
            h.db.purge_trash("alice", "nope").await,
            Err(Error::InvalidInput { .. })
        ));
        assert_eq!(h.db.purge_trash("alice", a).await?, 1);
        assert_eq!(
            hardened(&h),
            vec![format!("DROP DATABASE IF EXISTS `oxpanel_trash_{a}`;\n")]
        );
        assert_eq!(h.sys.mariadb_schema(&format!("oxpanel_trash_{a}")), None);
        // Overdue: only that one goes.
        let mut overdue = record(&h, b)?;
        overdue.purge_at_unix = 1;
        h.ctx.store.save_trash(&overdue)?;
        assert_eq!(purge_overdue(&h.ctx).await?, 1);
        assert_eq!(purge_overdue(&h.ctx).await?, 0);
        let left: Vec<String> = h
            .ctx
            .store
            .list_trash()?
            .into_iter()
            .map(|t| t.id)
            .collect();
        assert_eq!(left.as_slice(), std::slice::from_ref(c));
        // An item being moved or restored is not purged.
        let mut busy = record(&h, c)?;
        busy.state = TrashState::Moving;
        h.ctx.store.save_trash(&busy)?;
        assert!(matches!(
            h.db.purge_trash("alice", c).await,
            Err(Error::DbObjectUnusable { .. })
        ));
        assert_eq!(h.db.purge_trash("alice", "").await?, 0, "skipped by 'all'");
        busy.state = TrashState::Trashed;
        h.ctx.store.save_trash(&busy)?;
        assert_eq!(h.db.purge_trash("alice", "").await?, 1);
        assert!(h.ctx.store.list_trash()?.is_empty());
        assert!(h.host.reconcile().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn an_interrupted_move_or_restore_is_completed_by_repeating_it() -> Result<()> {
        let h = harness().await;
        h.db.create_database("alice", "alice_wp", MARIADB).await?;
        h.db.create_user("alice", "alice_app", PASSWORD, MARIADB)
            .await?;
        h.db.grant("alice_app", "alice_wp").await?;
        h.sys
            .mariadb_admin("CREATE TABLE `alice_wp`.`t` (a INT);\n")?;
        // State, objects, size, revoke, objects again: then the move fails.
        for _ in 0..5 {
            h.sys.script_pass_through(bin::MARIADB);
        }
        h.sys
            .script_failure(bin::MARIADB, 1, "ERROR 1205 (HY000): Lock wait timeout");
        assert!(h.db.delete_database("alice_wp").await.is_err());
        let rec = h.ctx.store.load_database(&name("alice_wp"))?;
        assert_eq!(rec.map(|r| r.state), Some(DbState::Deleting));
        let pending = h.ctx.store.list_trash()?;
        let [moving] = pending.as_slice() else {
            panic!("{pending:?}");
        };
        assert_eq!(moving.state, TrashState::Moving);
        let subject = format!("{} (alice_wp)", moving.id);
        let drifts = h.host.reconcile().await?;
        assert!(
            kinds(&drifts).contains(&(DriftKind::DatabaseTrashDrift, subject.as_str())),
            "{drifts:?}"
        );
        let t = trashed(h.db.delete_database("alice_wp").await?);
        assert_eq!(t.id, moving.id, "the same trash item");
        assert_eq!(
            h.sys
                .mariadb_schema(&format!("oxpanel_trash_{}", t.id))
                .map(|s| s.0),
            Some(vec!["t".to_owned()])
        );
        // A restore that fails after it recorded the new name.
        h.sys.script_pass_through(bin::MARIADB);
        h.sys.script_pass_through(bin::MARIADB);
        h.sys
            .script_failure(bin::MARIADB, 1, "ERROR 1205 (HY000): Lock wait timeout");
        assert!(h
            .db
            .restore_trash("alice", &t.id, "alice_back")
            .await
            .is_err());
        let rec = h.ctx.store.load_database(&name("alice_back"))?;
        assert_eq!(rec.map(|r| r.state), Some(DbState::Provisioning));
        let drifts = h.host.reconcile().await?;
        assert!(
            kinds(&drifts).contains(&(DriftKind::DatabaseTrashDrift, subject.as_str())),
            "{drifts:?}"
        );
        assert!(matches!(
            h.db.restore_trash("alice", &t.id, "alice_other").await,
            Err(Error::InvalidInput {
                field: "new_name",
                ..
            })
        ));
        assert!(matches!(
            h.db.purge_trash("alice", &t.id).await,
            Err(Error::DbObjectUnusable { .. })
        ));
        let (rec, issues) = h.db.restore_trash("alice", &t.id, "alice_back").await?;
        assert!(issues.is_empty());
        assert_eq!(rec.state, DbState::Ready);
        assert_eq!(
            h.sys.mariadb_schema("alice_back").map(|s| s.0),
            Some(vec!["t".to_owned()])
        );
        assert!(h.host.reconcile().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn reconcile_reports_orphaned_vanished_overdue_and_reachable_trash() -> Result<()> {
        let h = harness().await;
        let mut ids = Vec::new();
        for db in ["alice_a", "alice_b"] {
            h.db.create_database("alice", db, MARIADB).await?;
            ids.push(trashed(h.db.delete_database(db).await?).id);
        }
        let [a, b] = ids.as_slice() else {
            panic!("{ids:?}");
        };
        h.sys.mariadb_admin(&format!(
            "CREATE DATABASE `oxpanel_trash_t0000000000001`;\nDROP DATABASE `oxpanel_trash_{a}`;\n"
        ))?;
        let mut overdue = record(&h, b)?;
        overdue.purge_at_unix = 1;
        h.ctx.store.save_trash(&overdue)?;
        h.sys.mariadb_admin(
            "CREATE USER 'spy'@'%';\nGRANT SELECT ON `oxpanel%`.* TO 'spy'@'%';\n",
        )?;
        let drifts = h.host.reconcile().await?;
        let (gone, late) = (format!("{a} (alice_a)"), format!("{b} (alice_b)"));
        let reach = format!("oxpanel_trash_{b}");
        let mut found = kinds(&drifts);
        found.sort_unstable();
        let mut want = vec![
            (
                DriftKind::DatabasePrivilegeDrift,
                "oxpanel_trash_t0000000000001",
            ),
            (DriftKind::DatabasePrivilegeDrift, reach.as_str()),
            (DriftKind::DatabaseTrashDrift, gone.as_str()),
            (DriftKind::DatabaseTrashDrift, late.as_str()),
            (
                DriftKind::OrphanDatabaseTrash,
                "oxpanel_trash_t0000000000001",
            ),
        ];
        want.sort_unstable();
        assert_eq!(found, want, "{drifts:?}");
        Ok(())
    }

    #[tokio::test]
    async fn trash_is_owned_and_a_whole_tenant_is_dropped_at_once() -> Result<()> {
        let h = harness().await;
        let alice = Username::parse("alice")?;
        h.db.create_database("alice", "alice_wp", MARIADB).await?;
        h.db.create_database("alice", "alice_old", MARIADB).await?;
        h.db.create_user("alice", "alice_app", PASSWORD, MARIADB)
            .await?;
        h.db.grant("alice_app", "alice_wp").await?;
        let t = trashed(h.db.delete_database("alice_old").await?);
        assert!(tenant_has_trash(&h.ctx, &alice)?);
        h.sys.clear_calls();
        let rec = h
            .ctx
            .store
            .load_tenant(&alice)?
            .unwrap_or_else(|| panic!("tenant"));
        drop_everything(&h.ctx, &rec).await?;
        assert_eq!(
            hardened(&h),
            vec![format!(
                "ALTER USER 'alice_app'@'localhost' ACCOUNT LOCK;\nKILL USER 'alice_app'@'localhost';\nDROP USER IF EXISTS 'alice_app'@'localhost';\nDROP DATABASE IF EXISTS `alice_wp`;\nDROP DATABASE IF EXISTS `oxpanel_trash_{}`;\n",
                t.id
            )]
        );
        assert!(h.ctx.store.list_databases()?.is_empty());
        assert!(h.ctx.store.list_db_users()?.is_empty());
        assert!(h.ctx.store.list_trash()?.is_empty());
        assert!(!crate::db::tenant_has_objects(&h.ctx, &alice)?);
        assert_eq!(h.sys.mariadb_schema("alice_wp"), None);
        // Nothing left: a second run touches nothing.
        h.sys.clear_calls();
        drop_everything(&h.ctx, &rec).await?;
        assert!(h.sys.calls().is_empty());
        // Trash alone keeps a tenant from being deleted.
        h.db.create_database("alice", "alice_x", MARIADB).await?;
        trashed(h.db.delete_database("alice_x").await?);
        assert!(crate::db::tenant_has_objects(&h.ctx, &alice)?);
        assert!(!tenant_has_trash(&h.ctx, &Username::parse("acme")?)?);
        assert!(h.host.reconcile().await?.is_empty());
        Ok(())
    }
}
