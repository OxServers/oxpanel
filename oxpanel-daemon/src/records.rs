//! Durable records of what OxPanel owns.
//!
//! A record is the daemon's proof that *it* created an account or a virtual
//! host. Without a record the daemon refuses to modify or delete anything —
//! that rule is what keeps a compromised or buggy panel from asking the root
//! daemon to `userdel` an unrelated system account.
//!
//! Records are JSON files under `state_dir/{tenants,vhosts}/<name>.json`,
//! written atomically. The `state` field makes multi-step workflows resumable.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::validate::{BackupId, DbName, Domain, JobId, Limits, RelPath, Username};

pub const RECORD_VERSION: u32 = 1;
const RECORD_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantState {
    /// `useradd` succeeded; limits/labels/ACLs may still be incomplete.
    Provisioning,
    Ready,
    Deleting,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantRecord {
    pub version: u32,
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    pub limits: Limits,
    pub slice_unit: String,
    pub created_at_unix: u64,
    pub state: TenantState,
    /// Opaque owner label from the panel; empty = none. Absent in v1 records.
    #[serde(default)]
    pub owner: String,
    /// While set, every virtual host of the tenant answers 503. Absent in
    /// records written before suspension existed.
    #[serde(default)]
    pub suspended: bool,
    /// SSH public keys that may log in over SFTP as this tenant. SFTP access
    /// exists exactly while this list is not empty. Absent in records written
    /// before SFTP existed.
    #[serde(default)]
    pub sftp_keys: Vec<SftpKeyRecord>,
    /// The tenant has an SFTP password. Only this flag is recorded: the
    /// password exists solely as the hash in the shadow database.
    #[serde(default)]
    pub sftp_password: bool,
}

/// One SSH public key of a tenant. Everything in here is public.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SftpKeyRecord {
    /// Key type as OpenSSH names it, e.g. `ssh-ed25519`.
    pub key_type: String,
    /// The key itself, base64.
    pub blob: String,
    /// `SHA256:…`, as `ssh-keygen -l` prints it; identifies the key in the API.
    pub fingerprint: String,
    /// Free-form name given by the owner (`laptop`); may be empty.
    #[serde(default)]
    pub label: String,
    pub added_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VHostRecord {
    pub version: u32,
    pub domain: String,
    pub tenant: String,
    pub document_root: String,
    pub aliases: Vec<String>,
    pub config_path: PathBuf,
    pub created_at_unix: u64,
    /// `*.php` is executed by the tenant's PHP-FPM pool. Absent in records
    /// written before PHP support existed.
    #[serde(default)]
    pub php: bool,
    /// The application behind this virtual host, if any.
    #[serde(default)]
    pub app: Option<AppRecord>,
    /// Redirect plain HTTP to HTTPS / send HSTS. Both take effect only while
    /// `tls` is set.
    #[serde(default)]
    pub redirect_https: bool,
    #[serde(default)]
    pub hsts: bool,
    /// The installed certificate, if any.
    #[serde(default)]
    pub tls: Option<TlsRecord>,
    /// Whether Automatic HTTPS looks after this site.
    #[serde(default)]
    pub auto_https: AutoHttpsChoice,
}

/// A site's Automatic HTTPS setting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoHttpsChoice {
    /// Looked after (whenever the host-wide switch is on).
    #[default]
    On,
    /// The site opted out.
    Off,
}

impl AutoHttpsChoice {
    pub fn from_opt_out(opt_out: bool) -> Self {
        if opt_out {
            Self::Off
        } else {
            Self::On
        }
    }

    pub fn is_on(self) -> bool {
        self == Self::On
    }
}

/// Where a certificate came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertSource {
    /// Installed through the API ("bring your own").
    Uploaded,
    /// Issued by the ACME certificate authority; renewed automatically.
    Acme,
}

/// A virtual host's certificate. The chain is public and kept here, so the
/// certificate file is rendered from the record like every other file; the
/// private key exists only in its root-only file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsRecord {
    pub source: CertSource,
    /// Issuer distinguished name of the leaf certificate.
    pub issuer: String,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
    /// DNS names of the leaf certificate (may contain wildcards).
    pub names: Vec<String>,
    /// The certificate chain exactly as written to the certificate file.
    pub chain_pem: String,
    pub installed_at_unix: u64,
}

/// Which interpreter runs an application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppRuntime {
    Node,
    Python,
}

impl AppRuntime {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Python => "python",
        }
    }

    /// Entry point used when the request names none.
    pub fn default_entry(self) -> &'static str {
        match self {
            Self::Node => "app.js",
            Self::Python => "app.py",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRecord {
    pub runtime: AppRuntime,
    /// Application directory relative to the tenant home.
    pub root: String,
    /// Program to run, relative to `root`.
    pub entry: String,
}

/// Life cycle of a database or database-user record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DbState {
    /// The name is claimed; the object may not exist on the server yet.
    Provisioning,
    Ready,
    Deleting,
}

/// The database server an object lives on. Names are unique across
/// engines (one namespace per tenant), so records are keyed by name alone and
/// a later engine adds a variant here, not a second set of records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DbEngine {
    /// The default: records written before the field existed are MariaDB's.
    #[default]
    Mariadb,
}

impl DbEngine {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mariadb => "mariadb",
        }
    }
}

/// A database OxPanel created for a tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseRecord {
    pub version: u32,
    pub name: String,
    pub tenant: String,
    #[serde(default)]
    pub engine: DbEngine,
    pub created_at_unix: u64,
    pub state: DbState,
}

/// A database account OxPanel created for a tenant (on MariaDB
/// `'<name>'@'localhost'`). Neither the password nor its hash is ever recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbUserRecord {
    pub version: u32,
    pub name: String,
    pub tenant: String,
    #[serde(default)]
    pub engine: DbEngine,
    pub created_at_unix: u64,
    pub state: DbState,
    /// `MAX_USER_CONNECTIONS` the account was created with.
    pub max_user_connections: u32,
    /// Databases of the same tenant this user may work in (sorted).
    pub grants: Vec<String>,
}

impl VHostRecord {
    /// All server names this vhost claims.
    pub fn all_names(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.domain.as_str()).chain(self.aliases.iter().map(String::as_str))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupState {
    /// The job that writes it is still running (or was interrupted).
    Creating,
    /// Sealed: every member is on disk and listed with its checksum.
    Ready,
}

/// One file of a backup, with what is needed to verify it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupMember {
    /// File name inside the backup directory.
    pub name: String,
    /// What it holds: `home`, `records`, … (see `backup.rs`).
    pub kind: String,
    pub size_bytes: u64,
    /// Lower-case hexadecimal SHA-256 of the file.
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRecord {
    pub version: u32,
    pub id: String,
    pub tenant: String,
    /// The tenant's uid when the backup was made. A backup is only ever
    /// restored into the account it was taken from.
    pub uid: u32,
    pub created_at_unix: u64,
    pub state: BackupState,
    /// Total size of the members; 0 until sealed.
    pub size_bytes: u64,
    pub members: Vec<BackupMember>,
    /// Virtual hosts the tenant had when the backup was made.
    pub domains: Vec<String>,
    /// Kept until this time (UNIX seconds) whatever the per-tenant count
    /// says, and across `DeleteTenant`; 0 = no such mark.
    #[serde(default)]
    pub retain_until_unix: u64,
    /// The tenant was deleted while this retained backup was kept. Invisible
    /// to every per-tenant RPC (a later tenant of the same name never sees
    /// it); only the operator RPCs for retained backups reach it.
    #[serde(default)]
    pub tenant_deleted: bool,
    /// Directories left out of the home archive by the exclusion rules
    /// (`backup::EXCLUDE_RULES`), relative to the home ("." is the home
    /// itself), as found when the backup was started; at most
    /// `backup::EXCLUDED_LISTED` of them.
    #[serde(default)]
    pub excluded: Vec<String>,
    /// How many there were in all.
    #[serde(default)]
    pub excluded_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    Backup,
    Restore,
}

impl JobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Backup => "backup",
            Self::Restore => "restore",
        }
    }
}

/// What a restore does with a file that already exists in the home. There is
/// no default: the caller must choose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnExisting {
    /// Files in the backup replace the current ones.
    Overwrite,
    /// Existing files (and directories, symlinks) are left untouched; only
    /// what is missing is restored.
    Keep,
}

impl OnExisting {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Overwrite => "overwrite",
            Self::Keep => "keep",
        }
    }
}

/// What happened to one application site after a restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteResult {
    pub domain: String,
    pub succeeded: bool,
    /// One line: what was done, or why it failed.
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Running,
    Succeeded,
    Failed,
}

/// A backup or restore in flight or finished. The work itself runs in a
/// transient systemd unit, so the record is what lets a restarted daemon
/// find it again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    pub version: u32,
    pub id: String,
    pub kind: JobKind,
    pub tenant: String,
    pub backup_id: String,
    /// The transient unit doing the work (without `.service`).
    pub unit: String,
    pub state: JobState,
    /// One line from the engine: what happened.
    pub message: String,
    /// The end of what the worker printed (warnings, the reason of a failure).
    pub output: String,
    pub started_at_unix: u64,
    /// 0 while running.
    pub finished_at_unix: u64,
    /// Restores: the caller's choice for files that already exist.
    #[serde(default)]
    pub on_existing: Option<OnExisting>,
    /// Restores: archive entries written, and entries skipped because they
    /// already existed (`Keep`). Directories count as entries.
    #[serde(default)]
    pub restored_entries: u64,
    #[serde(default)]
    pub skipped_entries: u64,
    /// Restores: per application site, the virtualenv and dependency
    /// reinstallation (dependencies are not in backups).
    #[serde(default)]
    pub sites: Vec<SiteResult>,
}

/// Seconds since the UNIX epoch, saturating at 0 if the clock is before 1970.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// File-backed record store.
#[derive(Debug, Clone)]
pub struct Store {
    tenants_dir: PathBuf,
    vhosts_dir: PathBuf,
    /// `state_dir/databases` and `state_dir/db-users`.
    databases: PathBuf,
    db_users: PathBuf,
    backup_records: PathBuf,
    job_records: PathBuf,
}

impl Store {
    pub fn new(config: &Config) -> Self {
        Self {
            tenants_dir: config.tenants_dir(),
            vhosts_dir: config.vhosts_dir(),
            databases: config.databases_dir(),
            db_users: config.db_users_dir(),
            backup_records: config.backup_records_dir(),
            job_records: config.jobs_dir(),
        }
    }

    /// Create the state directories with root-only permissions.
    pub fn init(&self) -> Result<()> {
        fsutil::ensure_dir(&self.tenants_dir, DIR_MODE)?;
        fsutil::ensure_dir(&self.databases, DIR_MODE)?;
        fsutil::ensure_dir(&self.db_users, DIR_MODE)?;
        fsutil::ensure_dir(&self.vhosts_dir, DIR_MODE)?;
        fsutil::ensure_dir(&self.backup_records, DIR_MODE)?;
        fsutil::ensure_dir(&self.job_records, DIR_MODE)
    }

    fn tenant_path(&self, name: &Username) -> PathBuf {
        self.tenants_dir.join(format!("{name}.json"))
    }

    fn vhost_path(&self, domain: &Domain) -> PathBuf {
        self.vhosts_dir.join(format!("{domain}.json"))
    }

    pub fn load_tenant(&self, name: &Username) -> Result<Option<TenantRecord>> {
        load(&self.tenant_path(name))
    }

    pub fn save_tenant(&self, rec: &TenantRecord) -> Result<()> {
        let name = Username::parse(&rec.username)?;
        // Keys are rendered into a file sshd trusts: only valid ones are stored.
        for key in &rec.sftp_keys {
            crate::sftp::check_key_record(key)?;
        }
        save(&self.tenant_path(&name), rec)
    }

    pub fn delete_tenant(&self, name: &Username) -> Result<bool> {
        fsutil::remove_if_exists(&self.tenant_path(name))
    }

    pub fn list_tenants(&self) -> Result<Vec<TenantRecord>> {
        list(&self.tenants_dir)
    }

    /// Number of tenant records, without reading them: `GetHostInfo` is polled
    /// by dashboards and must not parse every file for a number. A damaged
    /// record is still a record, so it counts.
    pub fn count_tenants(&self) -> Result<usize> {
        Ok(fsutil::list_files_with_suffix(&self.tenants_dir, ".json")?.len())
    }

    pub fn load_vhost(&self, domain: &Domain) -> Result<Option<VHostRecord>> {
        load(&self.vhost_path(domain))
    }

    pub fn save_vhost(&self, rec: &VHostRecord) -> Result<()> {
        let domain = Domain::parse(&rec.domain)?;
        RelPath::parse(&rec.document_root)?;
        if let Some(app) = &rec.app {
            RelPath::parse_field(&app.root, "app.root")?;
            RelPath::parse_field(&app.entry, "app.entry")?;
        }
        save(&self.vhost_path(&domain), rec)
    }

    pub fn delete_vhost(&self, domain: &Domain) -> Result<bool> {
        fsutil::remove_if_exists(&self.vhost_path(domain))
    }

    pub fn list_vhosts(&self) -> Result<Vec<VHostRecord>> {
        list(&self.vhosts_dir)
    }

    /// Number of virtual-host records, without reading them (see [`Self::count_tenants`]).
    pub fn count_vhosts(&self) -> Result<usize> {
        Ok(fsutil::list_files_with_suffix(&self.vhosts_dir, ".json")?.len())
    }

    fn database_path(&self, name: &DbName) -> PathBuf {
        self.databases.join(format!("{name}.json"))
    }

    fn db_user_path(&self, name: &DbName) -> PathBuf {
        self.db_users.join(format!("{name}.json"))
    }

    pub fn load_database(&self, name: &DbName) -> Result<Option<DatabaseRecord>> {
        load(&self.database_path(name))
    }

    /// The name is re-validated and must belong to the recorded tenant.
    pub fn save_database(&self, rec: &DatabaseRecord) -> Result<()> {
        let tenant = Username::parse(&rec.tenant)?;
        let name = DbName::parse_for(&rec.name, &tenant, "name")?;
        save(&self.database_path(&name), rec)
    }

    pub fn delete_database(&self, name: &DbName) -> Result<bool> {
        fsutil::remove_if_exists(&self.database_path(name))
    }

    pub fn list_databases(&self) -> Result<Vec<DatabaseRecord>> {
        list(&self.databases)
    }

    pub fn load_db_user(&self, name: &DbName) -> Result<Option<DbUserRecord>> {
        load(&self.db_user_path(name))
    }

    /// The name and every granted database are re-validated and must belong
    /// to the recorded tenant: a record can never describe a cross-tenant grant.
    pub fn save_db_user(&self, rec: &DbUserRecord) -> Result<()> {
        let tenant = Username::parse(&rec.tenant)?;
        let name = DbName::parse_for(&rec.name, &tenant, "name")?;
        for g in &rec.grants {
            DbName::parse_for(g, &tenant, "database")?;
        }
        save(&self.db_user_path(&name), rec)
    }

    pub fn delete_db_user(&self, name: &DbName) -> Result<bool> {
        fsutil::remove_if_exists(&self.db_user_path(name))
    }

    pub fn list_db_users(&self) -> Result<Vec<DbUserRecord>> {
        list(&self.db_users)
    }

    fn backup_path(&self, id: &BackupId) -> PathBuf {
        self.backup_records.join(format!("{id}.json"))
    }

    fn job_path(&self, id: &JobId) -> PathBuf {
        self.job_records.join(format!("{id}.json"))
    }

    pub fn load_backup(&self, id: &BackupId) -> Result<Option<BackupRecord>> {
        load(&self.backup_path(id))
    }

    pub fn save_backup(&self, rec: &BackupRecord) -> Result<()> {
        let id = BackupId::parse(&rec.id)?;
        Username::parse_field(&rec.tenant, "tenant")?;
        save(&self.backup_path(&id), rec)
    }

    pub fn delete_backup(&self, id: &BackupId) -> Result<bool> {
        fsutil::remove_if_exists(&self.backup_path(id))
    }

    /// Every backup record, oldest first (identifiers sort by creation time).
    pub fn list_backups(&self) -> Result<Vec<BackupRecord>> {
        list(&self.backup_records)
    }

    pub fn load_job(&self, id: &JobId) -> Result<Option<JobRecord>> {
        load(&self.job_path(id))
    }

    pub fn save_job(&self, rec: &JobRecord) -> Result<()> {
        let id = JobId::parse(&rec.id)?;
        Username::parse_field(&rec.tenant, "tenant")?;
        BackupId::parse(&rec.backup_id)?;
        save(&self.job_path(&id), rec)
    }

    pub fn delete_job(&self, id: &JobId) -> Result<bool> {
        fsutil::remove_if_exists(&self.job_path(id))
    }

    /// Every job record, oldest first.
    pub fn list_jobs(&self) -> Result<Vec<JobRecord>> {
        list(&self.job_records)
    }
}

fn load<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    let Some(bytes) = fsutil::read_optional(path)? else {
        return Ok(None);
    };
    let rec: T = serde_json::from_slice(&bytes).map_err(|e| Error::CorruptRecord {
        path: path.to_owned(),
        reason: e.to_string(),
    })?;
    Ok(Some(rec))
}

fn save<T: Serialize>(path: &Path, rec: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(rec)
        .map_err(|e| Error::Internal(format!("serialise record: {e}")))?;
    bytes.push(b'\n');
    fsutil::write_atomic(path, &bytes, RECORD_MODE)?;
    Ok(())
}

/// A corrupt record is logged and skipped here so one damaged file cannot
/// block every other tenant's operations; mutations on the damaged tenant
/// itself still fail closed through [`load`].
fn list<T: for<'de> Deserialize<'de>>(dir: &Path) -> Result<Vec<T>> {
    let mut out = Vec::new();
    for path in fsutil::list_files_with_suffix(dir, ".json")? {
        match load::<T>(&path) {
            Ok(Some(rec)) => out.push(rec),
            Ok(None) => {}
            Err(Error::CorruptRecord { path, reason }) => {
                tracing::error!(path = %path.display(), %reason, "corrupt record skipped; repair or remove it");
            }
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let mut cfg = Config::default();
        cfg.state_dir = dir.path().join("state");
        let s = Store::new(&cfg);
        s.init().unwrap_or_else(|e| panic!("init: {e}"));
        (dir, s)
    }

    fn tenant(name: &str) -> TenantRecord {
        TenantRecord {
            version: RECORD_VERSION,
            username: name.into(),
            uid: 20000,
            gid: 20000,
            home: PathBuf::from(format!("/home/{name}")),
            limits: Limits::default(),
            slice_unit: format!("oxpanel-tenant-{name}.slice"),
            created_at_unix: 1_700_000_000,
            state: TenantState::Ready,
            owner: String::new(),
            suspended: false,
            sftp_keys: Vec::new(),
            sftp_password: false,
        }
    }

    #[test]
    fn tenant_round_trip_and_listing() -> Result<()> {
        let (_d, s) = store();
        let alice = Username::parse("alice")?;
        assert_eq!(s.load_tenant(&alice)?, None);
        s.save_tenant(&tenant("alice"))?;
        s.save_tenant(&tenant("bob"))?;
        assert_eq!(s.load_tenant(&alice)?, Some(tenant("alice")));
        let names: Vec<String> = s.list_tenants()?.into_iter().map(|t| t.username).collect();
        assert_eq!(names, vec!["alice", "bob"]);
        assert!(s.delete_tenant(&alice)?);
        assert!(!s.delete_tenant(&alice)?);
        assert_eq!(s.list_tenants()?.len(), 1);
        Ok(())
    }

    #[test]
    fn counting_records_does_not_read_them() -> Result<()> {
        let (_d, s) = store();
        s.save_tenant(&tenant("alice"))?;
        fsutil::write_atomic(
            &s.tenant_path(&Username::parse("bob")?),
            b"{not json",
            0o600,
        )?;
        assert_eq!(s.count_tenants()?, 2, "a damaged record is still a record");
        assert_eq!(s.list_tenants()?.len(), 1);
        assert_eq!(s.count_vhosts()?, 0);
        Ok(())
    }

    #[test]
    fn records_are_root_only_files() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let (_d, s) = store();
        s.save_tenant(&tenant("alice"))?;
        let p = s.tenant_path(&Username::parse("alice")?);
        let mode = std::fs::metadata(&p)
            .map_err(|e| Error::io("stat", &p, e))?
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o600);
        Ok(())
    }

    #[test]
    fn corrupt_record_fails_its_own_load_but_not_listing() -> Result<()> {
        let (_d, s) = store();
        let p = s.tenant_path(&Username::parse("alice")?);
        fsutil::write_atomic(&p, b"{not json", 0o600)?;
        s.save_tenant(&tenant("bob"))?;
        assert!(matches!(
            s.load_tenant(&Username::parse("alice")?),
            Err(Error::CorruptRecord { .. })
        ));
        let names: Vec<String> = s.list_tenants()?.into_iter().map(|t| t.username).collect();
        assert_eq!(
            names,
            vec!["bob"],
            "corrupt record is skipped, others still listed"
        );
        Ok(())
    }

    #[test]
    fn v1_records_without_owner_still_load() -> Result<()> {
        let (_d, s) = store();
        let p = s.tenant_path(&Username::parse("alice")?);
        let v1 = br#"{"version":1,"username":"alice","uid":20000,"gid":20000,"home":"/home/alice","limits":{"memory_max_bytes":null,"cpu_weight":null,"io_weight":null,"tasks_max":null},"slice_unit":"oxpanel-tenant-alice.slice","created_at_unix":1,"state":"ready"}"#;
        fsutil::write_atomic(&p, v1, 0o600)?;
        assert_eq!(
            s.load_tenant(&Username::parse("alice")?)?.map(|t| t.owner),
            Some(String::new())
        );
        Ok(())
    }

    #[test]
    fn save_validates_names_so_records_cannot_escape_the_directory() {
        let (_d, s) = store();
        let mut bad = tenant("alice");
        bad.username = "../../etc/passwd".into();
        assert!(s.save_tenant(&bad).is_err());
        let v = VHostRecord {
            version: 1,
            domain: "../x".into(),
            tenant: "alice".into(),
            document_root: "public_html".into(),
            aliases: vec![],
            config_path: PathBuf::from("/x"),
            created_at_unix: 0,
            php: false,
            app: None,
            redirect_https: false,
            hsts: false,
            tls: None,
            auto_https: AutoHttpsChoice::On,
        };
        assert!(s.save_vhost(&v).is_err());
    }

    #[test]
    fn database_records_round_trip_and_cannot_cross_tenants() -> Result<()> {
        let (_d, s) = store();
        let db = DatabaseRecord {
            version: RECORD_VERSION,
            name: "alice_wp".into(),
            tenant: "alice".into(),
            engine: DbEngine::Mariadb,
            created_at_unix: 1,
            state: DbState::Ready,
        };
        let user = DbUserRecord {
            version: RECORD_VERSION,
            name: "alice_app".into(),
            tenant: "alice".into(),
            engine: DbEngine::Mariadb,
            created_at_unix: 1,
            state: DbState::Ready,
            max_user_connections: 25,
            grants: vec!["alice_wp".into()],
        };
        s.save_database(&db)?;
        s.save_db_user(&user)?;
        let name = DbName::parse("alice_wp", "name")?;
        assert_eq!(s.load_database(&name)?, Some(db.clone()));
        assert_eq!(s.list_db_users()?, vec![user.clone()]);
        // A record whose name or grant belongs to another tenant is refused.
        assert!(s
            .save_database(&DatabaseRecord {
                tenant: "bob".into(),
                ..db.clone()
            })
            .is_err());
        assert!(s
            .save_db_user(&DbUserRecord {
                grants: vec!["bob_wp".into()],
                ..user.clone()
            })
            .is_err());
        assert!(s
            .save_database(&DatabaseRecord {
                name: "../../etc/passwd".into(),
                ..db
            })
            .is_err());
        let json = std::fs::read_to_string(s.db_user_path(&DbName::parse("alice_app", "name")?))
            .map_err(|e| Error::io("read", "record", e))?;
        assert!(
            !json.contains("password") && !json.contains("hash"),
            "no secret in a record"
        );
        assert!(json.contains(r#""engine": "mariadb""#), "{json}");
        // A record from before the engine field reads as MariaDB; an engine
        // this build does not know is an error, not a guess.
        let old: DbUserRecord = serde_json::from_str(&json.replace(r#""engine": "mariadb","#, ""))
            .map_err(|e| Error::Internal(e.to_string()))?;
        assert_eq!(old.engine, DbEngine::Mariadb);
        assert!(serde_json::from_str::<DbUserRecord>(&json.replace("mariadb", "oracle")).is_err());
        assert!(s.delete_database(&name)?);
        assert!(s.list_databases()?.is_empty());
        Ok(())
    }
}
