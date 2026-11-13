//! Zone records: `state_dir/dns-zones/<zone>.json`, root-only, written
//! atomically like every other record. A zone record is the proof that
//! OxPanel created the zone and the only source its zone file is rendered
//! from (together with the site records and the host's DNS settings).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::rr::{RawRr, Rr};
use crate::config::Config;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::validate::{Domain, Username};

const RECORD_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneState {
    /// Claimed; files and server configuration may not be in place yet.
    Provisioning,
    Ready,
    Deleting,
}

/// A record the tenant added, with its stable id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRr {
    pub id: u64,
    #[serde(flatten)]
    pub rr: RawRr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneRecord {
    pub version: u32,
    pub zone: String,
    pub tenant: String,
    pub created_at_unix: u64,
    pub state: ZoneState,
    /// Created for a site (and removed with its last site while the tenant
    /// has added nothing to it), not by `CreateDnsZone`.
    pub automatic: bool,
    /// SOA serial of the zone as last rendered.
    pub serial: u32,
    /// SHA-256 of the rendered zone without its serial: a new serial is
    /// issued exactly when this changes.
    pub content_sha256: String,
    /// Records the tenant added.
    pub records: Vec<StoredRr>,
    pub next_id: u64,
    /// DNSSEC signing is on.
    #[serde(default)]
    pub dnssec: bool,
    /// The serial the DNS server was last told to load: a request that was
    /// interrupted after writing the file still reloads the zone when it is
    /// repeated.
    #[serde(default)]
    pub loaded_serial: u32,
}

impl ZoneRecord {
    pub fn domain(&self) -> Result<Domain> {
        Domain::parse_field(&self.zone, "zone")
    }

    /// The tenant's records, validated (a record that no longer validates
    /// makes the zone unusable rather than reaching a zone file).
    pub fn rrs(&self) -> Result<Vec<(u64, Rr)>> {
        let zone = self.domain()?;
        self.records
            .iter()
            .map(|s| Ok((s.id, Rr::parse(&s.rr, &zone)?)))
            .collect()
    }
}

/// The catalog zone's own serial bookkeeping.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogRecord {
    pub serial: u32,
    pub content_sha256: String,
}

#[derive(Debug, Clone)]
pub struct ZoneStore {
    dir: PathBuf,
}

impl ZoneStore {
    pub fn new(config: &Config) -> Self {
        Self {
            dir: config.state_dir.join("dns-zones"),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, zone: &Domain) -> PathBuf {
        self.dir.join(format!("{zone}.json"))
    }

    fn catalog_path(&self) -> PathBuf {
        self.dir.join("catalog.state")
    }

    pub fn load(&self, zone: &Domain) -> Result<Option<ZoneRecord>> {
        let Some(bytes) = fsutil::read_optional(&self.path(zone))? else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| Error::CorruptRecord {
                path: self.path(zone),
                reason: e.to_string(),
            })
    }

    /// The name, the tenant and every record are re-validated: a record can
    /// never describe what the API would refuse.
    pub fn save(&self, rec: &ZoneRecord) -> Result<()> {
        let zone = rec.domain()?;
        Username::parse_field(&rec.tenant, "tenant")?;
        rec.rrs()?;
        fsutil::ensure_dir(&self.dir, DIR_MODE)?;
        write_json(&self.path(&zone), rec)
    }

    pub fn delete(&self, zone: &Domain) -> Result<bool> {
        fsutil::remove_if_exists(&self.path(zone))
    }

    /// Every zone record; a damaged one is logged and skipped (operations on
    /// that zone still fail closed through [`Self::load`]).
    pub fn list(&self) -> Result<Vec<ZoneRecord>> {
        let mut out = Vec::new();
        for path in fsutil::list_files_with_suffix(&self.dir, ".json")? {
            let Some(bytes) = fsutil::read_optional(&path)? else {
                continue;
            };
            match serde_json::from_slice::<ZoneRecord>(&bytes) {
                Ok(rec) => out.push(rec),
                Err(e) => {
                    tracing::error!(path = %path.display(), reason = %e, "corrupt zone record skipped; repair or remove it");
                }
            }
        }
        Ok(out)
    }

    pub fn count(&self) -> Result<usize> {
        Ok(fsutil::list_files_with_suffix(&self.dir, ".json")?.len())
    }

    pub fn load_catalog(&self) -> Result<CatalogRecord> {
        Ok(fsutil::read_optional(&self.catalog_path())?
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default())
    }

    pub fn save_catalog(&self, rec: &CatalogRecord) -> Result<()> {
        fsutil::ensure_dir(&self.dir, DIR_MODE)?;
        write_json(&self.catalog_path(), rec)
    }
}

fn write_json<T: Serialize>(path: &Path, rec: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(rec)
        .map_err(|e| Error::Internal(format!("serialise record: {e}")))?;
    bytes.push(b'\n');
    fsutil::write_atomic(path, &bytes, RECORD_MODE)?;
    Ok(())
}
