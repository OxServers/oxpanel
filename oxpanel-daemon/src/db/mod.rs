//! Tenant databases and database users.
//!
//! This module holds the engine-independent workflow: records, naming,
//! ownership, caps, suspension, reconciliation. Everything that speaks to a
//! particular server lives in a submodule per engine — today only
//! [`mariadb`]. Every record carries its [`DbEngine`]; a second engine
//! (PostgreSQL, MongoDB) is added as a sibling submodule plus one arm in each
//! place below that calls into `mariadb::` (see the design record
//! `docs/superpowers/specs/2026-11-13-db-design.md`).
//!
//! A tenant may own databases and database users. The rules mirror the ones
//! for POSIX accounts:
//!
//! - **Own it or leave it.** A record under `/var/lib/oxpanel/{databases,
//!   db-users}` is the proof that OxPanel created a database or an account.
//!   Without one nothing is altered or dropped, and a name that already
//!   exists on the server without a record is refused, never adopted. The
//!   server's own schemas and accounts cannot even be named (see
//!   [`DbName`]).
//! - **Names are namespaced by tenant**: `<tenant>_<suffix>`. The owner is
//!   derived from the name itself, so no request can address another
//!   tenant's object by accident, and two tenants can never collide.
//! - **A user reaches only its tenant's databases.** Accounts are created
//!   with no privileges at all (`USAGE`), may connect only locally
//!   (`'name'@'localhost'`), and are granted a fixed, database-level set of
//!   privileges ([`mariadb::DB_PRIVILEGES`]) on databases of the *same*
//!   tenant only — checked here and again when a record is saved.
//! - **Secrets.** The password arrives in the request, is hashed in memory
//!   and is forgotten; see [`mariadb`]. It is not in any record, and
//!   no RPC returns it. Repeating `CreateDatabaseUser` for an existing user
//!   therefore cannot verify the password and leaves it unchanged.
//! - **Limits.** `MAX_USER_CONNECTIONS` per account, and a cap on databases
//!   and on users per tenant.
//! - **Suspension** locks every account of the tenant and ends its open
//!   sessions; resuming unlocks them. Accounts created while suspended are
//!   born locked.
//! - **Deleting a tenant** is refused while it owns databases or users, as
//!   it is for virtual hosts: dropping data is always an explicit request.
//!
//! Every mutation first reads the server state ([`mariadb::snapshot`]), so a
//! request that cannot succeed — MariaDB absent or stopped, a foreign object
//! in the way, a cap reached — is refused before a record is written.
//! Records are written before the statements that depend on them and carry
//! a state, so every request can be repeated after a crash.

pub mod mariadb;
pub mod objects;
pub mod trash;

use std::collections::{BTreeMap, BTreeSet};

use mariadb::{sql, ServerState};
use tracing::info;

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::host::{Drift, DriftKind};
use crate::records::{
    now_unix, DatabaseRecord, DbEngine, DbState, DbUserRecord, TenantRecord, TenantState,
    RECORD_VERSION,
};
use crate::validate::{DbName, DbPassword, Username};

const DATABASE: &str = "database";
const USER: &str = "database user";

/// Whether one database engine can be used, and how much OxPanel keeps in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineFacts {
    pub engine: DbEngine,
    pub available: bool,
    /// Server version; empty when not available.
    pub version: String,
    pub database_count: u32,
    pub user_count: u32,
}

#[derive(Debug, Clone)]
pub struct DbService {
    ctx: Ctx,
}

fn unusable(kind: &'static str, name: &DbName, reason: &'static str) -> Error {
    Error::DbObjectUnusable {
        kind,
        name: name.to_string(),
        reason,
    }
}

fn not_found(kind: &'static str, name: &DbName) -> Error {
    Error::DbObjectNotFound {
        kind,
        name: name.to_string(),
    }
}

/// The tenant must exist and be fully provisioned.
fn ready_tenant(ctx: &Ctx, name: &Username) -> Result<TenantRecord> {
    let rec = ctx
        .store
        .load_tenant(name)?
        .ok_or_else(|| Error::TenantNotFound(name.to_string()))?;
    if rec.state != TenantState::Ready {
        return Err(Error::TenantNotReady(name.to_string()));
    }
    Ok(rec)
}

fn ready_user(ctx: &Ctx, name: &DbName) -> Result<DbUserRecord> {
    let rec = ctx
        .store
        .load_db_user(name)?
        .ok_or_else(|| not_found(USER, name))?;
    match rec.state {
        DbState::Ready => Ok(rec),
        DbState::Provisioning => Err(unusable(
            USER,
            name,
            "was not created completely; repeat CreateDatabaseUser",
        )),
        DbState::Deleting => Err(unusable(
            USER,
            name,
            "is being deleted; repeat DeleteDatabaseUser",
        )),
    }
}

fn ready_database(ctx: &Ctx, name: &DbName) -> Result<DatabaseRecord> {
    let rec = ctx
        .store
        .load_database(name)?
        .ok_or_else(|| not_found(DATABASE, name))?;
    match rec.state {
        DbState::Ready => Ok(rec),
        DbState::Provisioning => Err(unusable(
            DATABASE,
            name,
            "was not created completely; repeat CreateDatabase",
        )),
        DbState::Deleting => Err(unusable(
            DATABASE,
            name,
            "is being deleted; repeat DeleteDatabase",
        )),
    }
}

/// Statements that take away whatever `user` holds on `database`; empty if
/// the server knows no such grant (`REVOKE` fails on a grant that is absent).
fn revoke_script(server: &ServerState, user: &DbName, database: &DbName) -> String {
    let mut script = String::new();
    if let Some(held) = server.grant_on(user, database) {
        if held.contains(mariadb::GRANT_OPTION) {
            script.push_str(&sql::revoke_grant_option(user, database));
        }
        if held.iter().any(|p| p != mariadb::GRANT_OPTION) {
            script.push_str(&sql::revoke(user, database));
        }
    }
    script
}

/// A repeated create request may only confirm what the record describes.
fn check_existing(
    kind: &'static str,
    name: &DbName,
    state: DbState,
    recorded: DbEngine,
    requested: DbEngine,
    deleting: &'static str,
) -> Result<()> {
    if recorded != requested {
        return Err(Error::DbObjectUnusable {
            kind,
            name: name.to_string(),
            reason: "already exists on another database engine",
        });
    }
    if state == DbState::Deleting {
        return Err(Error::DbObjectUnusable {
            kind,
            name: name.to_string(),
            reason: deleting,
        });
    }
    Ok(())
}

/// The accounts OxPanel manages, as grantees (`'name'@'localhost'`).
fn managed_accounts(users: &[DbUserRecord]) -> BTreeSet<String> {
    users
        .iter()
        .map(|u| format!("'{}'@'{}'", u.name, mariadb::ACCOUNT_HOST))
        .collect()
}

/// An account outside `managed` whose database-level grant pattern covers
/// `database`: `(grantee, pattern)`.
fn foreign_reach<'a>(
    server: &'a ServerState,
    managed: &BTreeSet<String>,
    database: &str,
) -> Option<(&'a str, &'a str)> {
    server
        .db_privs
        .iter()
        .filter(|(grantee, _)| !managed.contains(*grantee))
        .find_map(|(grantee, patterns)| {
            patterns
                .keys()
                .find(|p| mariadb::pattern_matches(p, database))
                .map(|p| (grantee.as_str(), p.as_str()))
        })
}

fn optional_tenant(raw: &str) -> Result<Option<Username>> {
    if raw.is_empty() {
        Ok(None)
    } else {
        Username::parse_field(raw, "tenant").map(Some)
    }
}

impl DbService {
    pub fn new(ctx: Ctx) -> Self {
        Self { ctx }
    }

    /// Create a database for a tenant, or confirm (and if necessary
    /// re-create) one OxPanel already recorded. Returns whether it is new.
    pub async fn create_database(
        &self,
        tenant: &str,
        name: &str,
        engine: DbEngine,
    ) -> Result<(DatabaseRecord, bool)> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let name = DbName::parse_for(name, &tenant, "name")?;
        let _guard = self.ctx.lock.lock().await;
        ready_tenant(&self.ctx, &tenant)?;
        let existing = self.ctx.store.load_database(&name)?;
        if let Some(rec) = &existing {
            check_existing(
                DATABASE,
                &name,
                rec.state,
                rec.engine,
                engine,
                "is being deleted; repeat DeleteDatabase",
            )?;
        }
        let server = mariadb::snapshot(&self.ctx).await?;
        let mut rec = if let Some(rec) = existing {
            rec
        } else {
            // Never adopt a database OxPanel did not create, nor create one
            // that someone else could already reach (see `claimable`).
            trash::claimable(&self.ctx, &server, &tenant, &name)?;
            let rec = DatabaseRecord {
                version: RECORD_VERSION,
                name: name.to_string(),
                tenant: tenant.to_string(),
                engine,
                created_at_unix: now_unix(),
                state: DbState::Provisioning,
            };
            // Claim the name before the server knows it.
            self.ctx.store.save_database(&rec)?;
            rec
        };
        let created = rec.state == DbState::Provisioning;
        if !server.schemata.contains(name.as_str()) {
            mariadb::execute(&self.ctx, sql::create_database(&name)).await?;
            info!(%tenant, database = %name, "database created");
        }
        if created {
            rec.state = DbState::Ready;
            self.ctx.store.save_database(&rec)?;
        }
        Ok((rec, created))
    }

    /// Databases (of one tenant, or all) with their size on the server;
    /// the size is 0 when MariaDB cannot be asked.
    pub async fn list_databases(&self, tenant: &str) -> Result<Vec<(DatabaseRecord, u64)>> {
        let tenant = optional_tenant(tenant)?;
        let mut recs = self.ctx.store.list_databases()?;
        if let Some(t) = &tenant {
            recs.retain(|d| d.tenant == t.as_str());
        }
        let names: Vec<DbName> = recs
            .iter()
            .filter_map(|d| DbName::parse(&d.name, "name").ok())
            .collect();
        let sizes = match mariadb::sizes(&self.ctx, &names).await {
            Ok(sizes) => sizes,
            Err(Error::DbUnavailable(_)) => BTreeMap::new(),
            Err(e) => return Err(e),
        };
        Ok(recs
            .into_iter()
            .map(|d| {
                let size = sizes.get(&d.name).copied().unwrap_or(0);
                (d, size)
            })
            .collect())
    }

    /// Create a database user for a tenant. For a user that already exists
    /// the password is left as it is; an account that went missing on the
    /// server is re-created with this password and its recorded grants.
    pub async fn create_user(
        &self,
        tenant: &str,
        name: &str,
        password: &str,
        engine: DbEngine,
    ) -> Result<(DbUserRecord, bool)> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let name = DbName::parse_for(name, &tenant, "name")?;
        let password = DbPassword::parse(password)?;
        let _guard = self.ctx.lock.lock().await;
        let tenant_rec = ready_tenant(&self.ctx, &tenant)?;
        let existing = self.ctx.store.load_db_user(&name)?;
        if let Some(rec) = &existing {
            check_existing(
                USER,
                &name,
                rec.state,
                rec.engine,
                engine,
                "is being deleted; repeat DeleteDatabaseUser",
            )?;
        }
        let server = mariadb::snapshot(&self.ctx).await?;
        let mut rec = if let Some(rec) = existing {
            rec
        } else {
            // Never adopt an account OxPanel did not create — on any host.
            if server.has_user_named(name.as_str()) {
                return Err(Error::DbNotManaged {
                    kind: USER,
                    name: name.to_string(),
                });
            }
            let max = self.ctx.config.db_max_users;
            let owned = self
                .ctx
                .store
                .list_db_users()?
                .iter()
                .filter(|u| u.tenant == tenant.as_str())
                .count();
            if owned >= usize::try_from(max).unwrap_or(usize::MAX) {
                return Err(Error::DbLimitReached {
                    tenant: tenant.to_string(),
                    kind: USER,
                    max,
                });
            }
            let rec = DbUserRecord {
                version: RECORD_VERSION,
                name: name.to_string(),
                tenant: tenant.to_string(),
                engine,
                created_at_unix: now_unix(),
                state: DbState::Provisioning,
                max_user_connections: self.ctx.config.db_max_user_connections,
                grants: Vec::new(),
            };
            self.ctx.store.save_db_user(&rec)?;
            rec
        };
        let created = rec.state == DbState::Provisioning;
        if created || server.account(&name).is_none() {
            self.put_account(&tenant_rec, &rec, &name, &password)
                .await?;
        }
        if created {
            rec.state = DbState::Ready;
            self.ctx.store.save_db_user(&rec)?;
        }
        Ok((rec, created))
    }

    /// (Re-)create the account from its record: password, connection limit,
    /// lock state of the tenant, and every recorded grant.
    async fn put_account(
        &self,
        tenant: &TenantRecord,
        rec: &DbUserRecord,
        name: &DbName,
        password: &DbPassword,
    ) -> Result<()> {
        let hash = mariadb::PasswordHash::of(password);
        let mut script = sql::create_user(name, &hash, rec.max_user_connections, tenant.suspended);
        for grant in &rec.grants {
            let database = DbName::parse_for(grant, name.tenant(), "database")?;
            script.push_str(&sql::grant(name, &database));
        }
        mariadb::execute_secret(&self.ctx, script).await?;
        info!(tenant = %rec.tenant, user = %name, locked = tenant.suspended, "database user created");
        Ok(())
    }

    /// Database users of one tenant, or all. Carries no secret.
    pub async fn list_users(&self, tenant: &str) -> Result<Vec<DbUserRecord>> {
        let tenant = optional_tenant(tenant)?;
        let mut recs = self.ctx.store.list_db_users()?;
        if let Some(t) = &tenant {
            recs.retain(|u| u.tenant == t.as_str());
        }
        Ok(recs)
    }

    /// Replace a user's password. Open sessions stay open.
    pub async fn set_password(&self, name: &str, password: &str) -> Result<()> {
        let name = DbName::parse(name, "name")?;
        let password = DbPassword::parse(password)?;
        let _guard = self.ctx.lock.lock().await;
        let rec = ready_user(&self.ctx, &name)?;
        let tenant = ready_tenant(&self.ctx, name.tenant())?;
        let server = mariadb::snapshot(&self.ctx).await?;
        if server.account(&name).is_none() {
            // The account was removed behind our back: this request carries
            // everything needed to put it back.
            return self.put_account(&tenant, &rec, &name, &password).await;
        }
        let hash = mariadb::PasswordHash::of(&password);
        mariadb::execute_secret(&self.ctx, sql::set_password(&name, &hash)).await?;
        info!(tenant = %rec.tenant, user = %name, "database user password replaced");
        Ok(())
    }

    /// Remove a user OxPanel created and end its sessions. Returns `false`
    /// if OxPanel has no such user.
    pub async fn delete_user(&self, name: &str) -> Result<bool> {
        let name = DbName::parse(name, "name")?;
        let _guard = self.ctx.lock.lock().await;
        let Some(mut rec) = self.ctx.store.load_db_user(&name)? else {
            return Ok(false);
        };
        let server = mariadb::snapshot(&self.ctx).await?;
        if rec.state != DbState::Deleting {
            rec.state = DbState::Deleting;
            self.ctx.store.save_db_user(&rec)?;
        }
        if server.account(&name).is_some() {
            // Lock first so nothing reconnects between the kill and the drop.
            let script = [
                sql::set_locked(&name, true),
                sql::kill_sessions(&name),
                sql::drop_user(&name),
            ]
            .concat();
            mariadb::execute(&self.ctx, script).await?;
        }
        self.ctx.store.delete_db_user(&name)?;
        info!(tenant = %rec.tenant, user = %name, "database user dropped");
        Ok(true)
    }

    /// Let `user` work in `database`. Both must belong to the same tenant.
    pub async fn grant(&self, user: &str, database: &str) -> Result<(DbUserRecord, bool)> {
        let user = DbName::parse(user, "user")?;
        let database = DbName::parse(database, "database")?;
        if user.tenant() != database.tenant() {
            return Err(Error::invalid(
                "database",
                "belongs to another tenant than the user",
            ));
        }
        let _guard = self.ctx.lock.lock().await;
        ready_tenant(&self.ctx, user.tenant())?;
        let mut rec = ready_user(&self.ctx, &user)?;
        if ready_database(&self.ctx, &database)?.engine != rec.engine {
            return Err(Error::invalid(
                "database",
                "lives on another database engine than the user",
            ));
        }
        let server = mariadb::snapshot(&self.ctx).await?;
        if server.account(&user).is_none() {
            return Err(unusable(
                USER,
                &user,
                "is missing on the MariaDB server; repeat CreateDatabaseUser",
            ));
        }
        if !server.schemata.contains(database.as_str()) {
            return Err(unusable(
                DATABASE,
                &database,
                "is missing on the MariaDB server; repeat CreateDatabase",
            ));
        }
        let changed = !rec.grants.iter().any(|g| g == database.as_str());
        if changed {
            rec.grants.push(database.to_string());
            rec.grants.sort();
            self.ctx.store.save_db_user(&rec)?;
        }
        // Always: repeating the request restores a grant removed by hand.
        mariadb::execute(&self.ctx, sql::grant(&user, &database)).await?;
        if changed {
            info!(tenant = %rec.tenant, %user, %database, "database access granted");
        }
        Ok((rec, changed))
    }

    /// Take `database` away from `user`.
    pub async fn revoke(&self, user: &str, database: &str) -> Result<(DbUserRecord, bool)> {
        let user = DbName::parse(user, "user")?;
        let database = DbName::parse(database, "database")?;
        if user.tenant() != database.tenant() {
            return Err(Error::invalid(
                "database",
                "belongs to another tenant than the user",
            ));
        }
        let _guard = self.ctx.lock.lock().await;
        let mut rec = ready_user(&self.ctx, &user)?;
        let server = mariadb::snapshot(&self.ctx).await?;
        let script = revoke_script(&server, &user, &database);
        if !script.is_empty() {
            mariadb::execute(&self.ctx, script).await?;
        }
        let changed = rec.grants.iter().any(|g| g == database.as_str());
        if changed {
            rec.grants.retain(|g| g != database.as_str());
            self.ctx.store.save_db_user(&rec)?;
            info!(tenant = %rec.tenant, %user, %database, "database access revoked");
        }
        Ok((rec, changed))
    }
}

/// Whether the tenant still owns a database, a database user or a deleted
/// database in its trash (`DeleteTenant` refuses while it does).
pub fn tenant_has_objects(ctx: &Ctx, tenant: &Username) -> Result<bool> {
    Ok(trash::tenant_has_trash(ctx, tenant)?
        || ctx
        .store
        .list_databases()?
        .iter()
        .any(|d| d.tenant == tenant.as_str())
        || ctx
            .store
            .list_db_users()?
            .iter()
            .any(|u| u.tenant == tenant.as_str()))
}

/// Lock (suspend) or unlock (resume) every database account of a tenant.
/// Locking also ends the accounts' open sessions, which a lock alone leaves
/// connected. A tenant without database users never touches MariaDB.
/// The caller holds the mutation lock.
pub async fn set_locked_all(ctx: &Ctx, tenant: &TenantRecord, locked: bool) -> Result<()> {
    let users: Vec<DbUserRecord> = ctx
        .store
        .list_db_users()?
        .into_iter()
        .filter(|u| u.tenant == tenant.username && u.state != DbState::Deleting)
        .collect();
    if users.is_empty() {
        return Ok(());
    }
    let server = mariadb::snapshot(ctx).await?;
    let mut script = String::new();
    for user in &users {
        let name = DbName::parse(&user.name, "name")?;
        if server.account(&name).is_none() {
            continue; // reported by Reconcile; nothing to lock
        }
        script.push_str(&sql::set_locked(&name, locked));
        if locked {
            script.push_str(&sql::kill_sessions(&name));
        }
    }
    if !script.is_empty() {
        mariadb::execute(ctx, script).await?;
        info!(tenant = %tenant.username, locked, accounts = users.len(), "database accounts (un)locked");
    }
    Ok(())
}

/// Availability and record counts of every engine, for `GetHostInfo`.
pub async fn facts(ctx: &Ctx) -> Result<Vec<EngineFacts>> {
    let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    let databases = ctx.store.list_databases()?;
    let users = ctx.store.list_db_users()?;
    let engine = DbEngine::Mariadb;
    let (available, version) = match mariadb::snapshot(ctx).await {
        Ok(server) => (true, server.version),
        Err(_) => (false, String::new()),
    };
    Ok(vec![EngineFacts {
        engine,
        available,
        version,
        database_count: count(databases.iter().filter(|d| d.engine == engine).count()),
        user_count: count(users.iter().filter(|u| u.engine == engine).count()),
    }])
}

/// Differences between the database records and the MariaDB server.
/// Read-only (`SELECT` statements only). The caller holds the mutation lock.
pub async fn drifts(ctx: &Ctx, tenants: &[TenantRecord]) -> Result<Vec<Drift>> {
    let databases = ctx.store.list_databases()?;
    let users = ctx.store.list_db_users()?;
    let trashed = ctx.store.list_trash()?;
    let server = match mariadb::snapshot(ctx).await {
        Ok(server) => server,
        Err(Error::DbUnavailable(why)) => {
            // A host without MariaDB and without database records is consistent.
            if databases.is_empty() && users.is_empty() && trashed.is_empty() {
                return Ok(Vec::new());
            }
            return Ok(vec![Drift::new(
                DriftKind::DatabaseMissing,
                "mariadb",
                format!(
                    "{} database(s) and {} user(s) are recorded but cannot be checked: {why}",
                    databases.len(),
                    users.len()
                ),
            )]);
        }
        Err(e) => return Err(e),
    };
    let by_name: BTreeMap<&str, &TenantRecord> =
        tenants.iter().map(|t| (t.username.as_str(), t)).collect();
    let mut out = Vec::new();
    for d in &databases {
        if let Some(problem) = database_problem(d, &server, &by_name) {
            out.push(Drift::new(
                DriftKind::DatabaseMissing,
                d.name.as_str(),
                problem,
            ));
        }
    }
    for u in &users {
        check_user(u, &server, &by_name, &mut out)?;
    }
    check_unrecorded(&databases, &users, &server, tenants, &mut out);
    trash::drifts(&trashed, &server, tenants, &mut out);
    check_trash_reach(&users, &server, &mut out);
    Ok(out)
}

/// Trash schemas are reachable by nobody but the server's administrators:
/// an account OxPanel does not manage whose pattern grant covers one is
/// reported (OxPanel's own accounts only hold exact, escaped names).
fn check_trash_reach(users: &[DbUserRecord], server: &ServerState, out: &mut Vec<Drift>) {
    let managed = managed_accounts(users);
    for schema in server
        .schemata
        .iter()
        .filter(|s| s.starts_with(crate::validate::TRASH_SCHEMA_PREFIX))
    {
        if let Some((grantee, pattern)) = foreign_reach(server, &managed, schema) {
            out.push(Drift::new(
                DriftKind::DatabasePrivilegeDrift,
                schema.as_str(),
                format!("{grantee}, an account OxPanel does not manage, can reach this deleted database (`{pattern}`)"),
            ));
        }
    }
}

fn interrupted(state: DbState, create: &str, delete: &str) -> Option<String> {
    match state {
        DbState::Ready => None,
        DbState::Provisioning => Some(format!("creation was interrupted; repeat {create}")),
        DbState::Deleting => Some(format!("deletion was interrupted; repeat {delete}")),
    }
}

fn database_problem(
    d: &DatabaseRecord,
    server: &ServerState,
    tenants: &BTreeMap<&str, &TenantRecord>,
) -> Option<String> {
    if !tenants.contains_key(d.tenant.as_str()) {
        return Some(format!("tenant '{}' has no record", d.tenant));
    }
    if let Some(problem) = interrupted(d.state, "CreateDatabase", "DeleteDatabase") {
        return Some(problem);
    }
    (!server.schemata.contains(&d.name)).then(|| {
        "the database does not exist on the server; repeat CreateDatabase to re-create it (empty)"
            .to_owned()
    })
}

/// One finding per user: either the account is missing, or everything in
/// which it differs from its record.
fn check_user(
    u: &DbUserRecord,
    server: &ServerState,
    tenants: &BTreeMap<&str, &TenantRecord>,
    out: &mut Vec<Drift>,
) -> Result<()> {
    let missing =
        |detail: String| Drift::new(DriftKind::DatabaseUserMissing, u.name.as_str(), detail);
    let Some(tenant) = tenants.get(u.tenant.as_str()) else {
        out.push(missing(format!("tenant '{}' has no record", u.tenant)));
        return Ok(());
    };
    if let Some(problem) = interrupted(u.state, "CreateDatabaseUser", "DeleteDatabaseUser") {
        out.push(missing(problem));
        return Ok(());
    }
    let name = DbName::parse(&u.name, "name")?;
    let Some(account) = server.account(&name) else {
        out.push(missing(
            "the account does not exist on the server; SetDatabaseUserPassword re-creates it"
                .to_owned(),
        ));
        return Ok(());
    };
    let mut problems: Vec<String> = Vec::new();
    if account.locked != tenant.suspended {
        problems.push(if tenant.suspended {
            "the account is not locked although the tenant is suspended".to_owned()
        } else {
            "the account is locked although the tenant is not suspended".to_owned()
        });
    }
    if account.max_user_connections != u.max_user_connections {
        problems.push(format!(
            "MAX_USER_CONNECTIONS is {}, the record says {}",
            account.max_user_connections, u.max_user_connections
        ));
    }
    if account.plugin != mariadb::AUTH_PLUGIN {
        problems.push(format!("authenticates with '{}'", account.plugin));
    }
    let grantee = mariadb::account(&name);
    let list = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(", ");
    if let Some(global) = server.global.get(&grantee) {
        problems.push(format!("holds global privileges: {}", list(global)));
    }
    if let Some(kinds) = server.other.get(&grantee) {
        problems.push(format!("holds {} grants", list(kinds)));
    }
    privilege_problems(u, &name, server, &mut problems)?;
    if !problems.is_empty() {
        out.push(Drift::new(
            DriftKind::DatabasePrivilegeDrift,
            u.name.as_str(),
            problems.join("; "),
        ));
    }
    Ok(())
}

/// Compare the database-level privileges of `name` with its recorded grants.
fn privilege_problems(
    u: &DbUserRecord,
    name: &DbName,
    server: &ServerState,
    problems: &mut Vec<String>,
) -> Result<()> {
    let wanted: BTreeSet<String> = mariadb::DB_PRIVILEGES
        .iter()
        .map(|p| (*p).to_owned())
        .collect();
    let list = |set: Vec<&String>| {
        set.into_iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut expected: BTreeMap<String, &str> = BTreeMap::new();
    for grant in &u.grants {
        let database = DbName::parse_for(grant, name.tenant(), "database")?;
        expected.insert(mariadb::grant_pattern(&database), grant.as_str());
    }
    let empty = BTreeMap::new();
    let held = server
        .db_privs
        .get(&mariadb::account(name))
        .unwrap_or(&empty);
    for (pattern, privileges) in held {
        if !expected.contains_key(pattern) {
            problems.push(format!(
                "holds {} on `{pattern}`, which the record does not grant",
                list(privileges.iter().collect())
            ));
            continue;
        }
        let extra: Vec<&String> = privileges.difference(&wanted).collect();
        if !extra.is_empty() {
            problems.push(format!("holds {} on `{pattern}` in addition", list(extra)));
        }
        let lacking: Vec<&String> = wanted.difference(privileges).collect();
        if !lacking.is_empty() {
            problems.push(format!("lacks {} on `{pattern}`", list(lacking)));
        }
    }
    for (pattern, database) in &expected {
        if !held.contains_key(pattern) {
            problems.push(format!(
                "has no privileges on '{database}' although the record grants it"
            ));
        }
    }
    Ok(())
}

/// Objects on the server that carry a tenant's prefix without a record, and
/// accounts OxPanel does not manage that can reach a managed database.
fn check_unrecorded(
    databases: &[DatabaseRecord],
    users: &[DbUserRecord],
    server: &ServerState,
    tenants: &[TenantRecord],
    out: &mut Vec<Drift>,
) {
    let owner_of = |name: &str| {
        tenants
            .iter()
            .map(|t| t.username.as_str())
            .find(|t| {
                name.strip_prefix(t)
                    .is_some_and(|rest| rest.starts_with(crate::validate::DB_SEPARATOR))
            })
            .map(str::to_owned)
    };
    let recorded_dbs: BTreeSet<&str> = databases.iter().map(|d| d.name.as_str()).collect();
    let recorded_users: BTreeSet<&str> = users.iter().map(|u| u.name.as_str()).collect();
    for schema in &server.schemata {
        if recorded_dbs.contains(schema.as_str()) {
            continue;
        }
        if let Some(tenant) = owner_of(schema) {
            out.push(Drift::new(
                DriftKind::OrphanDatabaseObject,
                schema.as_str(),
                format!("a database with the prefix of tenant '{tenant}' that has no record"),
            ));
        }
    }
    for a in &server.accounts {
        if a.host == mariadb::ACCOUNT_HOST && recorded_users.contains(a.user.as_str()) {
            continue;
        }
        if let Some(tenant) = owner_of(&a.user) {
            out.push(Drift::new(
                DriftKind::OrphanDatabaseObject,
                format!("'{}'@'{}'", a.user, a.host),
                format!("an account with the prefix of tenant '{tenant}' that has no record"),
            ));
        }
    }
    let managed = managed_accounts(users);
    for (grantee, patterns) in &server.db_privs {
        if managed.contains(grantee) {
            continue;
        }
        for pattern in patterns.keys() {
            for database in databases {
                if mariadb::pattern_matches(pattern, &database.name) {
                    out.push(Drift::new(
                        DriftKind::DatabasePrivilegeDrift,
                        database.name.as_str(),
                        format!(
                            "{grantee}, an account OxPanel does not manage, holds privileges on it (`{pattern}`)"
                        ),
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::host::HostService;
    use crate::system::{bin, CommandSpec, FakeSystem};
    use crate::tenant::TenantService;
    use crate::validate::Limits;
    use std::sync::Arc;

    const MARIADB: DbEngine = DbEngine::Mariadb;
    const PASSWORD: &str = "Secret-pass-123";
    const HASH: &str = "*683682FA5B18D74444A8178F2DD3E999D9007573";

    struct Harness {
        _dir: tempfile::TempDir,
        sys: Arc<FakeSystem>,
        ctx: Ctx,
        tenants: TenantService,
        db: DbService,
        host: HostService,
    }

    /// Tenants `alice`, `acme` and `acme_shop`; MariaDB installed and empty.
    async fn harness_with(configure: impl FnOnce(&mut Config)) -> Harness {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let mut cfg = Config::default();
        cfg.state_dir = dir.path().join("state");
        cfg.home_base = dir.path().join("home");
        cfg.systemd_unit_dir = dir.path().join("systemd");
        cfg.nginx_log_dir = dir.path().join("log");
        cfg.php_conf_dir = dir.path().join("php");
        cfg.nginx_conf_dir = dir.path().join("nginx").join("oxpanel.d");
        cfg.nginx_include_file = dir
            .path()
            .join("nginx")
            .join("conf.d")
            .join("00-oxpanel.conf");
        crate::config::sandbox_feature_paths(&mut cfg, dir.path());
        configure(&mut cfg);
        for d in [&cfg.home_base, &cfg.systemd_unit_dir] {
            std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("{e}"));
        }
        let sys = Arc::new(FakeSystem::new());
        sys.install_mariadb();
        let ctx = Ctx::new(cfg, sys.clone(), false);
        ctx.store.init().unwrap_or_else(|e| panic!("{e}"));
        let h = Harness {
            _dir: dir,
            sys,
            tenants: TenantService::new(ctx.clone()),
            db: DbService::new(ctx.clone()),
            host: HostService::new(ctx.clone()),
            ctx,
        };
        for tenant in ["alice", "acme", "acme_shop"] {
            h.tenants
                .create(tenant, Limits::default(), "")
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        }
        // As the daemon does at start: the sshd drop-in is in place.
        crate::sftp::converge_all(&h.ctx)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        h.sys.clear_calls();
        h
    }

    async fn harness() -> Harness {
        harness_with(|_| {}).await
    }

    fn args(c: &CommandSpec) -> Vec<String> {
        c.args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// The scripts that changed something (everything but the read-only
    /// queries: state, sizes, object listings).
    fn mutations(h: &Harness) -> Vec<String> {
        h.sys
            .mariadb_scripts()
            .into_iter()
            .filter(|s| {
                s != mariadb::SNAPSHOT_SQL
                    && !s.starts_with(mariadb::SIZES_SQL_PREFIX)
                    && !s.starts_with(mariadb::OBJECTS_SQL_PREFIX)
            })
            .collect()
    }

    fn kinds(d: &[Drift]) -> Vec<(DriftKind, &str)> {
        d.iter().map(|d| (d.kind, d.subject.as_str())).collect()
    }

    #[tokio::test]
    async fn create_database_runs_the_exact_client_and_statement() -> Result<()> {
        let h = harness().await;
        let (rec, created) = h.db.create_database("alice", "alice_wp", MARIADB).await?;
        assert!(created);
        assert_eq!(
            (rec.name.as_str(), rec.tenant.as_str(), rec.state),
            ("alice_wp", "alice", DbState::Ready)
        );
        let calls = h.sys.calls();
        assert_eq!(calls.len(), 2, "state query, then the statement");
        for c in &calls {
            assert_eq!(c.program, bin::MARIADB);
            assert_eq!(
                args(c),
                vec![
                    "--no-defaults",
                    "--protocol=socket",
                    "--socket=/var/lib/mysql/mysql.sock",
                    "--user=root",
                    "--batch",
                    "--skip-column-names",
                    "--default-character-set=utf8mb4",
                    "--connect-timeout=10",
                ],
                "the argument vector is constant: SQL travels on stdin only"
            );
            assert!(c.run_as.is_none());
        }
        assert_eq!(
            h.sys.mariadb_scripts(),
            vec![
                mariadb::SNAPSHOT_SQL.to_owned(),
                "CREATE DATABASE IF NOT EXISTS `alice_wp` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n".to_owned(),
            ]
        );
        // Replay: confirmed, nothing executed.
        h.sys.clear_calls();
        let (again, created) = h.db.create_database("alice", "alice_wp", MARIADB).await?;
        assert!(!created);
        assert_eq!(again, rec);
        assert!(mutations(&h).is_empty());
        let listed = h.db.list_databases("alice").await?;
        assert_eq!(listed, vec![(rec, 16_384)]);
        assert!(h.db.list_databases("acme").await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn names_are_namespaced_and_hostile_input_never_reaches_the_server() -> Result<()> {
        let h = harness().await;
        for (tenant, name) in [
            ("alice", "bob_wp"),
            ("alice", "wp"),
            ("alice", "alice_wp`; DROP DATABASE mysql; --"),
            ("alice", "alice_wp'; DROP USER 'root'@'localhost'; --"),
            ("alice", "alice_w%"),
            ("alice", "alice\\_wp"),
            ("alice", "mysql"),
            ("alice", "information_schema"),
            ("alice`", "alice_wp"),
            ("acme", "acme_shop_wp"),
            ("root", "root_wp"),
        ] {
            for result in [
                h.db.create_database(tenant, name, MARIADB)
                    .await
                    .map(|_| ()),
                h.db.create_user(tenant, name, PASSWORD, MARIADB)
                    .await
                    .map(|_| ()),
            ] {
                assert!(
                    matches!(result, Err(Error::InvalidInput { .. })),
                    "{tenant:?} {name:?}: {result:?}"
                );
            }
        }
        for name in ["mysql", "root", "alice_wp' OR '1'='1", "alice_`wp`", ""] {
            assert!(matches!(
                h.db.delete_database(name).await,
                Err(Error::InvalidInput { .. })
            ));
            assert!(matches!(
                h.db.delete_user(name).await,
                Err(Error::InvalidInput { .. })
            ));
            assert!(matches!(
                h.db.set_password(name, PASSWORD).await,
                Err(Error::InvalidInput { .. })
            ));
            assert!(matches!(
                h.db.grant(name, "alice_wp").await,
                Err(Error::InvalidInput { .. })
            ));
            assert!(matches!(
                h.db.revoke("alice_app", name).await,
                Err(Error::InvalidInput { .. })
            ));
        }
        assert!(matches!(
            h.db.list_databases("al`ice").await,
            Err(Error::InvalidInput { .. })
        ));
        assert!(
            h.sys.calls().is_empty(),
            "validation happens before anything runs"
        );
        // `acme_shop_wp` is the name of tenant acme_shop, and only its.
        assert!(
            h.db.create_database("acme_shop", "acme_shop_wp", MARIADB)
                .await?
                .1
        );
        assert!(matches!(
            h.db.create_database("ghost", "ghost_wp", MARIADB).await,
            Err(Error::TenantNotFound(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn foreign_objects_are_never_adopted_or_dropped() -> Result<()> {
        let h = harness().await;
        h.sys
            .mariadb_admin("CREATE DATABASE `alice_legacy`;\nCREATE USER 'alice_legacy'@'%';\n")?;
        assert!(matches!(
            h.db.create_database("alice", "alice_legacy", MARIADB).await,
            Err(Error::DbNotManaged { .. })
        ));
        assert!(matches!(
            h.db.create_user("alice", "alice_legacy", PASSWORD, MARIADB)
                .await,
            Err(Error::DbNotManaged { .. })
        ));
        // No record, so "delete" finds nothing and touches nothing.
        assert_eq!(h.db.delete_database("alice_legacy").await?, trash::Deleted::NotFound);
        assert!(!h.db.delete_user("alice_legacy").await?);
        assert!(mutations(&h).is_empty());
        assert!(h.ctx.store.list_databases()?.is_empty());
        assert!(h.ctx.store.list_db_users()?.is_empty());
        let drifts = h.host.reconcile().await?;
        assert_eq!(
            kinds(&drifts),
            vec![
                (DriftKind::OrphanDatabaseObject, "alice_legacy"),
                (DriftKind::OrphanDatabaseObject, "'alice_legacy'@'%'"),
            ]
        );
        // A hand-written pattern grant (like the stock `test\_%` one) would
        // reach a new database the moment it exists: such a name is refused.
        h.sys.mariadb_admin(
            "CREATE USER 'anyone'@'%';\nGRANT ALL PRIVILEGES ON `alice\\_%`.* TO 'anyone'@'%';\n",
        )?;
        h.sys.clear_calls();
        assert!(matches!(
            h.db.create_database("alice", "alice_new", MARIADB).await,
            Err(Error::DbObjectUnusable {
                kind: "database",
                ..
            })
        ));
        assert!(mutations(&h).is_empty());
        assert!(h.ctx.store.list_databases()?.is_empty());
        // A name the pattern does not cover is fine.
        assert!(h.db.create_database("acme", "acme_new", MARIADB).await?.1);
        Ok(())
    }

    #[tokio::test]
    async fn unavailable_mariadb_is_refused_before_anything_is_recorded() -> Result<()> {
        let h = harness().await;
        h.sys.set_mariadb_running(false);
        for result in [
            h.db.create_database("alice", "alice_wp", MARIADB)
                .await
                .map(|_| ()),
            h.db.create_user("alice", "alice_app", PASSWORD, MARIADB)
                .await
                .map(|_| ()),
        ] {
            assert!(
                matches!(&result, Err(Error::DbUnavailable(why)) if why.contains("not running")),
                "{result:?}"
            );
        }
        assert!(h.ctx.store.list_databases()?.is_empty());
        assert!(h.ctx.store.list_db_users()?.is_empty());
        let facts = facts(&h.ctx).await?;
        assert!(
            matches!(facts.as_slice(), [f] if f.engine == MARIADB && !f.available && f.version.is_empty()),
            "{facts:?}"
        );

        // Not installed at all: the client is never even started.
        let bare = Arc::new(FakeSystem::new());
        let ctx = Ctx::new((*h.ctx.config).clone(), bare.clone(), false);
        let db = DbService::new(ctx.clone());
        assert!(matches!(
            db.create_database("alice", "alice_wp", MARIADB).await,
            Err(Error::DbUnavailable(why)) if why.contains("not installed")
        ));
        assert!(bare.calls().is_empty());
        assert!(drifts(&ctx, &[]).await?.is_empty());

        h.sys.set_mariadb_running(true);
        let facts = super::facts(&h.ctx).await?;
        assert!(
            matches!(facts.as_slice(), [f] if f.available && f.version == "10.5.29-MariaDB"),
            "{facts:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn create_user_sends_only_the_hash_and_only_on_stdin() -> Result<()> {
        let h = harness().await;
        let (rec, created) =
            h.db.create_user("alice", "alice_app", PASSWORD, MARIADB)
                .await?;
        assert!(created);
        assert_eq!(
            (rec.state, rec.max_user_connections, rec.grants.len()),
            (DbState::Ready, 25, 0)
        );
        assert_eq!(
            mutations(&h),
            vec![format!(
                "CREATE OR REPLACE USER 'alice_app'@'localhost' IDENTIFIED VIA mysql_native_password USING '{HASH}' WITH MAX_USER_CONNECTIONS 25 ACCOUNT UNLOCK;\n"
            )]
        );
        let calls = h.sys.calls();
        for c in &calls {
            let shown = format!("{c:?} {}", c.display());
            assert!(!shown.contains(PASSWORD), "plaintext in a command: {shown}");
            assert!(
                c.args
                    .iter()
                    .all(|a| !a.to_string_lossy().contains(PASSWORD)
                        && !a.to_string_lossy().contains(HASH)),
                "secret in argv"
            );
            let script = String::from_utf8_lossy(c.stdin.as_deref().unwrap_or_default());
            assert!(!script.contains(PASSWORD), "plaintext sent to the server");
        }
        let create = calls.last().unwrap_or_else(|| panic!("no call"));
        assert!(create.secret_input, "the hash is marked as a secret");
        assert!(!format!("{create:?}").contains(HASH));
        // The record holds neither the password nor its hash.
        let record = std::fs::read_to_string(h.ctx.config.db_users_dir().join("alice_app.json"))
            .map_err(|e| Error::io("read", "record", e))?;
        assert!(!record.contains(PASSWORD) && !record.contains(&HASH[1..]));

        // Replay, even with another password: confirmed, password untouched.
        h.sys.clear_calls();
        let (_, created) =
            h.db.create_user("alice", "alice_app", "Another-pass-456", MARIADB)
                .await?;
        assert!(!created);
        assert!(mutations(&h).is_empty());
        assert_eq!(h.db.list_users("alice").await?, vec![rec]);
        for bad in ["short", "", "new\nline-password"] {
            assert!(matches!(
                h.db.create_user("alice", "alice_two", bad, MARIADB).await,
                Err(Error::InvalidInput {
                    field: "password",
                    ..
                })
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_failing_secret_statement_reveals_nothing() -> Result<()> {
        let h = harness().await;
        h.db.create_user("alice", "alice_app", PASSWORD, MARIADB)
            .await?;
        // The state query runs; the ALTER USER then fails the way the real
        // client reports it: by echoing the statement, hash included.
        h.sys.script_pass_through(bin::MARIADB);
        h.sys.script_failure(
            bin::MARIADB,
            1,
            &format!("--------------\nALTER USER 'alice_app'@'localhost' IDENTIFIED VIA mysql_native_password USING '{HASH}'\n--------------\n\nERROR 1396 (HY000) at line 1: Operation ALTER USER failed for 'alice_app'@'localhost' USING '{HASH}'"),
        );
        let err =
            h.db.set_password("alice_app", PASSWORD)
                .await
                .err()
                .unwrap_or_else(|| panic!("expected a failure"));
        let shown = format!("{err} {err:?}");
        assert!(
            !shown.contains(PASSWORD) && !shown.contains(&HASH[1..]),
            "{shown}"
        );
        assert!(
            matches!(&err, Error::CommandFailed { stderr, .. } if stderr == "ERROR 1396 (HY000) at line 1"),
            "{err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn password_change_and_user_deletion_run_exact_statements() -> Result<()> {
        let h = harness().await;
        h.db.create_user("alice", "alice_app", "First-pass-000", MARIADB)
            .await?;
        h.sys.clear_calls();
        h.db.set_password("alice_app", PASSWORD).await?;
        assert_eq!(
            mutations(&h),
            vec![format!(
                "ALTER USER 'alice_app'@'localhost' IDENTIFIED VIA mysql_native_password USING '{HASH}';\n"
            )]
        );
        assert!(h.sys.calls().last().is_some_and(|c| c.secret_input));
        assert!(matches!(
            h.db.set_password("alice_nobody", PASSWORD).await,
            Err(Error::DbObjectNotFound { .. })
        ));
        h.sys.clear_calls();
        assert!(h.db.delete_user("alice_app").await?);
        assert_eq!(
            mutations(&h),
            vec!["ALTER USER 'alice_app'@'localhost' ACCOUNT LOCK;\nKILL USER 'alice_app'@'localhost';\nDROP USER IF EXISTS 'alice_app'@'localhost';\n".to_owned()]
        );
        assert!(
            !h.db.delete_user("alice_app").await?,
            "second delete is a no-op"
        );
        assert!(h.db.list_users("").await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn grants_stay_inside_the_tenant_and_escape_wildcards() -> Result<()> {
        let h = harness().await;
        h.db.create_database("acme_shop", "acme_shop_wp", MARIADB)
            .await?;
        h.db.create_database("alice", "alice_wp", MARIADB).await?;
        h.db.create_user("acme_shop", "acme_shop_app", PASSWORD, MARIADB)
            .await?;
        h.db.create_user("alice", "alice_app", PASSWORD, MARIADB)
            .await?;
        h.sys.clear_calls();
        // Another tenant's database: refused by name, nothing runs.
        assert!(matches!(
            h.db.grant("alice_app", "acme_shop_wp").await,
            Err(Error::InvalidInput {
                field: "database",
                ..
            })
        ));
        assert!(matches!(
            h.db.revoke("alice_app", "acme_shop_wp").await,
            Err(Error::InvalidInput { .. })
        ));
        assert!(h.sys.calls().is_empty());
        assert!(matches!(
            h.db.grant("alice_app", "alice_nosuch").await,
            Err(Error::DbObjectNotFound {
                kind: "database",
                ..
            })
        ));
        assert!(matches!(
            h.db.grant("alice_nosuch", "alice_wp").await,
            Err(Error::DbObjectNotFound {
                kind: "database user",
                ..
            })
        ));
        assert!(mutations(&h).is_empty());

        let (rec, changed) = h.db.grant("acme_shop_app", "acme_shop_wp").await?;
        assert!(changed);
        assert_eq!(rec.grants, vec!["acme_shop_wp"]);
        assert_eq!(
            mutations(&h),
            vec!["GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, REFERENCES, INDEX, ALTER, CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE, TRIGGER ON `acme\\_shop\\_wp`.* TO 'acme_shop_app'@'localhost';\n".to_owned()]
        );
        assert!(!h.db.grant("acme_shop_app", "acme_shop_wp").await?.1);
        assert_eq!(
            h.host.reconcile().await?,
            vec![],
            "a granted user is not drift"
        );

        h.sys.clear_calls();
        let (rec, changed) = h.db.revoke("acme_shop_app", "acme_shop_wp").await?;
        assert!(changed && rec.grants.is_empty());
        assert_eq!(
            mutations(&h),
            vec![
                "REVOKE ALL PRIVILEGES ON `acme\\_shop\\_wp`.* FROM 'acme_shop_app'@'localhost';\n"
                    .to_owned()
            ]
        );
        h.sys.clear_calls();
        assert!(!h.db.revoke("acme_shop_app", "acme_shop_wp").await?.1);
        assert!(mutations(&h).is_empty(), "nothing left to revoke");
        Ok(())
    }

    #[tokio::test]
    async fn deleting_a_database_revokes_it_first() -> Result<()> {
        let h = harness().await;
        h.db.create_database("alice", "alice_wp", MARIADB).await?;
        h.db.create_database("alice", "alice_shop", MARIADB).await?;
        h.db.create_user("alice", "alice_app", PASSWORD, MARIADB)
            .await?;
        h.db.grant("alice_app", "alice_wp").await?;
        h.db.grant("alice_app", "alice_shop").await?;
        h.sys.clear_calls();
        let trash::Deleted::Trashed(t) = h.db.delete_database("alice_wp").await? else {
            panic!("not trashed");
        };
        assert_eq!(
            mutations(&h),
            vec![
                // The grant goes, and the sessions of its holder end with it.
                "REVOKE ALL PRIVILEGES ON `alice\\_wp`.* FROM 'alice_app'@'localhost';\nKILL USER 'alice_app'@'localhost';\n".to_owned(),
                format!("CREATE DATABASE IF NOT EXISTS `oxpanel_trash_{}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\nDROP DATABASE IF EXISTS `alice_wp`;\n", t.id),
            ]
        );
        assert_eq!(
            h.db.list_users("alice")
                .await?
                .first()
                .map(|u| u.grants.clone()),
            Some(vec!["alice_shop".to_owned()])
        );
        assert_eq!(h.db.delete_database("alice_wp").await?, trash::Deleted::NotFound);
        assert_eq!(h.host.reconcile().await?, vec![]);
        Ok(())
    }

    #[tokio::test]
    async fn caps_per_tenant_are_enforced_before_anything_is_created() -> Result<()> {
        let h = harness_with(|c| {
            c.db_max_databases = 1;
            c.db_max_users = 1;
            c.db_max_user_connections = 7;
        })
        .await;
        h.db.create_database("alice", "alice_one", MARIADB).await?;
        let (user, _) =
            h.db.create_user("alice", "alice_one", PASSWORD, MARIADB)
                .await?;
        assert_eq!(user.max_user_connections, 7);
        h.sys.clear_calls();
        assert!(matches!(
            h.db.create_database("alice", "alice_two", MARIADB).await,
            Err(Error::DbLimitReached {
                max: 1,
                kind: "database",
                ..
            })
        ));
        assert!(matches!(
            h.db.create_user("alice", "alice_two", PASSWORD, MARIADB)
                .await,
            Err(Error::DbLimitReached { max: 1, .. })
        ));
        assert!(mutations(&h).is_empty());
        // The cap is per tenant; a replay of an existing object is not a new one.
        assert!(h.db.create_database("acme", "acme_one", MARIADB).await?.1);
        assert!(!h.db.create_database("alice", "alice_one", MARIADB).await?.1);
        assert!(mutations(&h).iter().all(|s| s.contains("`acme_one`")));
        Ok(())
    }

    #[tokio::test]
    async fn interrupted_requests_are_completed_by_repeating_them() -> Result<()> {
        let h = harness().await;
        // The state query works, the statement fails: the name stays claimed.
        for attempt in 0..2 {
            h.sys.script_pass_through(bin::MARIADB);
            h.sys
                .script_failure(bin::MARIADB, 1, "ERROR 1021 (HY000) at line 1: Disk full");
            let result = if attempt == 0 {
                h.db.create_database("alice", "alice_wp", MARIADB)
                    .await
                    .map(|_| ())
            } else {
                h.db.create_user("alice", "alice_app", PASSWORD, MARIADB)
                    .await
                    .map(|_| ())
            };
            assert!(
                matches!(result, Err(Error::CommandFailed { .. })),
                "{result:?}"
            );
        }
        assert_eq!(
            kinds(&h.host.reconcile().await?),
            vec![
                (DriftKind::DatabaseMissing, "alice_wp"),
                (DriftKind::DatabaseUserMissing, "alice_app"),
            ]
        );
        assert!(matches!(
            h.db.grant("alice_app", "alice_wp").await,
            Err(Error::DbObjectUnusable { .. })
        ));
        let (db, created) = h.db.create_database("alice", "alice_wp", MARIADB).await?;
        assert!(created && db.state == DbState::Ready);
        let (user, created) =
            h.db.create_user("alice", "alice_app", PASSWORD, MARIADB)
                .await?;
        assert!(created && user.state == DbState::Ready);
        assert_eq!(h.host.reconcile().await?, vec![]);

        // Interrupted deletions resume the same way.
        h.ctx.store.save_database(&DatabaseRecord {
            state: DbState::Deleting,
            ..db
        })?;
        assert!(matches!(
            h.db.create_database("alice", "alice_wp", MARIADB).await,
            Err(Error::DbObjectUnusable { .. })
        ));
        assert!(matches!(
            h.db.delete_database("alice_wp").await?,
            trash::Deleted::Trashed(_)
        ));
        h.ctx.store.save_db_user(&DbUserRecord {
            state: DbState::Deleting,
            ..user
        })?;
        assert!(matches!(
            h.db.set_password("alice_app", PASSWORD).await,
            Err(Error::DbObjectUnusable { .. })
        ));
        assert!(h.db.delete_user("alice_app").await?);
        assert_eq!(h.host.reconcile().await?, vec![]);
        Ok(())
    }

    #[tokio::test]
    async fn suspension_locks_accounts_and_tenant_deletion_is_refused() -> Result<()> {
        let h = harness().await;
        h.db.create_database("alice", "alice_wp", MARIADB).await?;
        h.db.create_user("alice", "alice_app", PASSWORD, MARIADB)
            .await?;
        h.db.create_user("acme", "acme_app", PASSWORD, MARIADB)
            .await?;
        h.sys.clear_calls();
        h.tenants.set_suspended("alice", true).await?;
        assert_eq!(
            mutations(&h),
            vec!["ALTER USER 'alice_app'@'localhost' ACCOUNT LOCK;\nKILL USER 'alice_app'@'localhost';\n".to_owned()],
            "only this tenant's accounts, locked and disconnected"
        );
        assert_eq!(h.host.reconcile().await?, vec![], "suspension is not drift");
        // A user created while suspended is born locked.
        h.sys.clear_calls();
        h.db.create_user("alice", "alice_two", PASSWORD, MARIADB)
            .await?;
        assert!(mutations(&h)
            .first()
            .is_some_and(|s| s.ends_with(" ACCOUNT LOCK;\n")));
        // Unlocked by hand: reported.
        h.sys
            .mariadb_admin("ALTER USER 'alice_app'@'localhost' ACCOUNT UNLOCK;\n")?;
        let found = h.host.reconcile().await?;
        assert_eq!(
            kinds(&found),
            vec![(DriftKind::DatabasePrivilegeDrift, "alice_app")]
        );
        assert!(found.first().is_some_and(|d| d
            .detail
            .contains("not locked although the tenant is suspended")));
        h.sys.clear_calls();
        h.tenants.set_suspended("alice", false).await?;
        assert_eq!(
            mutations(&h),
            vec!["ALTER USER 'alice_app'@'localhost' ACCOUNT UNLOCK;\nALTER USER 'alice_two'@'localhost' ACCOUNT UNLOCK;\n".to_owned()]
        );
        assert_eq!(h.host.reconcile().await?, vec![]);

        // DeleteTenant refuses while databases or users exist.
        assert!(matches!(
            h.tenants.delete("alice", true).await,
            Err(Error::TenantHasDatabases(_))
        ));
        assert!(h.sys.calls_to(bin::USERDEL).is_empty());
        h.db.delete_database("alice_wp").await?;
        assert!(matches!(
            h.tenants.delete("alice", true).await,
            Err(Error::TenantHasDatabases(_))
        ));
        h.db.delete_user("alice_app").await?;
        h.db.delete_user("alice_two").await?;
        // The deleted database is in the trash: the tenant still owns it.
        assert!(matches!(
            h.tenants.delete("alice", true).await,
            Err(Error::TenantHasDatabases(_))
        ));
        assert_eq!(h.db.purge_trash("alice", "").await?, 1);
        assert!(h.tenants.delete("alice", true).await?);
        // A tenant without database users never contacts MariaDB when suspended.
        h.sys.clear_calls();
        h.tenants.set_suspended("acme_shop", true).await?;
        assert!(h.sys.calls_to(bin::MARIADB).is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn reconcile_reports_what_was_changed_by_hand() -> Result<()> {
        let h = harness().await;
        h.db.create_database("alice", "alice_wp", MARIADB).await?;
        h.db.create_database("alice", "alice_gone", MARIADB).await?;
        h.db.create_database("acme", "acme_wp", MARIADB).await?;
        h.db.create_user("alice", "alice_app", PASSWORD, MARIADB)
            .await?;
        h.db.create_user("alice", "alice_gone", PASSWORD, MARIADB)
            .await?;
        h.db.create_user("acme", "acme_app", PASSWORD, MARIADB)
            .await?;
        h.db.grant("alice_app", "alice_wp").await?;
        assert_eq!(h.host.reconcile().await?, vec![]);
        h.sys.clear_calls();

        h.sys.mariadb_admin(concat!(
            "GRANT FILE ON *.* TO 'alice_app'@'localhost';\n",
            "GRANT SELECT ON `acme\\_wp`.* TO 'alice_app'@'localhost';\n",
            "GRANT EVENT ON `alice\\_wp`.* TO 'alice_app'@'localhost' WITH GRANT OPTION;\n",
            "ALTER USER 'alice_app'@'localhost' WITH MAX_USER_CONNECTIONS 0;\n",
            "DROP DATABASE `alice_gone`;\n",
            "DROP USER IF EXISTS 'alice_gone'@'localhost';\n",
            "CREATE DATABASE `acme_stray`;\n",
            "CREATE USER 'intruder'@'%';\n",
            "GRANT SELECT ON `acme_wp`.* TO 'intruder'@'%';\n",
        ))?;
        let found = h.host.reconcile().await?;
        assert_eq!(
            kinds(&found),
            vec![
                (DriftKind::DatabaseMissing, "alice_gone"),
                (DriftKind::DatabasePrivilegeDrift, "alice_app"),
                (DriftKind::DatabaseUserMissing, "alice_gone"),
                (DriftKind::OrphanDatabaseObject, "acme_stray"),
                (DriftKind::DatabasePrivilegeDrift, "acme_wp"),
            ]
        );
        let detail = found.get(1).map(|d| d.detail.as_str()).unwrap_or_default();
        for expected in [
            "MAX_USER_CONNECTIONS is 0, the record says 25",
            "holds global privileges: FILE",
            "holds SELECT on `acme\\_wp`, which the record does not grant",
            "holds EVENT, GRANT OPTION on `alice\\_wp` in addition",
        ] {
            assert!(
                detail.contains(expected),
                "missing {expected:?} in {detail:?}"
            );
        }
        assert!(found
            .get(4)
            .is_some_and(|d| d.detail.contains("'intruder'@'%'")));
        assert!(
            mutations(&h).is_empty(),
            "reconcile only reads: nothing was repaired"
        );

        // Repeating the requests heals what OxPanel owns.
        h.db.create_database("alice", "alice_gone", MARIADB).await?;
        h.db.set_password("alice_gone", PASSWORD).await?;
        h.db.revoke("alice_app", "alice_wp").await?;
        h.db.grant("alice_app", "alice_wp").await?;
        let left = h.host.reconcile().await?;
        assert_eq!(
            kinds(&left),
            vec![
                (DriftKind::DatabasePrivilegeDrift, "alice_app"),
                (DriftKind::OrphanDatabaseObject, "acme_stray"),
                (DriftKind::DatabasePrivilegeDrift, "acme_wp"),
            ],
            "what OxPanel did not grant or create stays for the operator"
        );
        assert!(left
            .first()
            .is_some_and(|d| !d.detail.contains("in addition") && d.detail.contains("FILE")));

        // A stopped server with records is one finding, not silence.
        h.sys.set_mariadb_running(false);
        let down = h.host.reconcile().await?;
        assert_eq!(kinds(&down), vec![(DriftKind::DatabaseMissing, "mariadb")]);
        Ok(())
    }
}
