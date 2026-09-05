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
use crate::validate::{Domain, Limits, RelPath, Username};

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
}

impl VHostRecord {
    /// All server names this vhost claims.
    pub fn all_names(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.domain.as_str()).chain(self.aliases.iter().map(String::as_str))
    }
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
}

impl Store {
    pub fn new(config: &Config) -> Self {
        Self {
            tenants_dir: config.tenants_dir(),
            vhosts_dir: config.vhosts_dir(),
        }
    }

    /// Create the state directories with root-only permissions.
    pub fn init(&self) -> Result<()> {
        fsutil::ensure_dir(&self.tenants_dir, DIR_MODE)?;
        fsutil::ensure_dir(&self.vhosts_dir, DIR_MODE)
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
        save(&self.tenant_path(&name), rec)
    }

    pub fn delete_tenant(&self, name: &Username) -> Result<bool> {
        fsutil::remove_if_exists(&self.tenant_path(name))
    }

    pub fn list_tenants(&self) -> Result<Vec<TenantRecord>> {
        list(&self.tenants_dir)
    }

    pub fn load_vhost(&self, domain: &Domain) -> Result<Option<VHostRecord>> {
        load(&self.vhost_path(domain))
    }

    pub fn save_vhost(&self, rec: &VHostRecord) -> Result<()> {
        let domain = Domain::parse(&rec.domain)?;
        RelPath::parse(&rec.document_root)?;
        save(&self.vhost_path(&domain), rec)
    }

    pub fn delete_vhost(&self, domain: &Domain) -> Result<bool> {
        fsutil::remove_if_exists(&self.vhost_path(domain))
    }

    pub fn list_vhosts(&self) -> Result<Vec<VHostRecord>> {
        list(&self.vhosts_dir)
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
        };
        assert!(s.save_vhost(&v).is_err());
    }
}
