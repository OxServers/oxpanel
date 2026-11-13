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
        let mut trash = match pending {
            Some(t) => t,
            None => {
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
            }
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
        let script = content::create_schema(&target)
            + &content::rename_tables(&source, &target, &tables);
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
            let any = ctx.store.list_trash().map(|t| !t.is_empty()).unwrap_or(true);
            if any {
                match purge_overdue(&ctx).await {
                    Ok(0) => {}
                    Ok(n) => info!(purged = n, "overdue deleted databases purged"),
                    Err(e) => warn!(error = %e, "could not purge overdue deleted databases; will retry"),
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
        script.push_str(&content::drop_schema(&Schema::of_trash(&TrashId::parse(&t.id)?)));
    }
    if !script.is_empty() {
        mariadb::run_hardened(ctx, script).await?;
    }
    for u in &users {
        ctx.store.delete_db_user(&DbName::parse(&u.name, "name")?)?;
    }
    for d in &databases {
        ctx.store.delete_database(&DbName::parse(&d.name, "name")?)?;
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
        let schema = TrashId::parse(&t.id).map(|id| id.schema()).unwrap_or_default();
        let problem = if !tenants.iter().any(|x| x.username == t.tenant) {
            Some(format!("tenant '{}' has no record", t.tenant))
        } else {
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
