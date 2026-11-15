//! Email records: `state_dir/mail/domains/<domain>.json` (one per mail
//! domain, with its mailboxes, forwarders and autoresponders) and
//! `state_dir/mail/limits/<account>.json`. Root-only, written atomically.
//! A mail domain record is the proof that OxPanel set the domain up and the
//! only source the mail servers' maps are rendered from; it holds the
//! mailboxes' password *hashes* (never a password).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::validate::{Domain, MailDestination, MailLocalPart, Username};

const RECORD_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailMode {
    /// This host receives, stores and sends the domain's mail.
    Local,
    /// Another provider does (the MX records point at it).
    External,
    /// The domain has no mail.
    Off,
}

impl MailMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::External => "external",
            Self::Off => "off",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordState {
    /// Claimed; files and services may not be in place yet.
    Provisioning,
    Ready,
    /// Being removed (a mailbox: its mail is being deleted).
    Deleting,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkimKey {
    /// `ox` followed by the creation time: unique per domain.
    pub selector: String,
    /// Base64 of the public key (SubjectPublicKeyInfo DER), the `p=` value.
    pub public_key: String,
    pub created_at_unix: u64,
    /// For a retired key: when its DNS record is dropped.
    #[serde(default)]
    pub retire_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoreplyRecord {
    pub enabled: bool,
    pub subject: String,
    pub body: String,
    #[serde(default)]
    pub starts_at_unix: Option<u64>,
    #[serde(default)]
    pub ends_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxRecord {
    pub state: RecordState,
    /// 0: no limit of its own.
    pub quota_bytes: u64,
    /// `{BLF-CRYPT}$2y$…`: what Dovecot verifies. Never a password.
    pub password_hash: String,
    pub enabled: bool,
    pub created_at_unix: u64,
    #[serde(default)]
    pub autoreply: Option<AutoreplyRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwarderRecord {
    pub destinations: Vec<String>,
    pub keep_copy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailDomainRecord {
    pub version: u32,
    pub domain: String,
    pub tenant: String,
    pub created_at_unix: u64,
    pub state: RecordState,
    pub mode: MailMode,
    #[serde(default)]
    pub external_mx: Vec<String>,
    /// Local part of the mailbox that gets mail for unknown addresses.
    #[serde(default)]
    pub catch_all: Option<String>,
    /// The signing key (local mode; kept while the domain exists).
    #[serde(default)]
    pub dkim: Option<DkimKey>,
    /// Earlier keys whose records stay published for a while.
    #[serde(default)]
    pub dkim_retired: Vec<DkimKey>,
    /// A new key made by `RotateDkimKey` while the domain's DNS is not
    /// hosted here: published by the customer, not used for signing until
    /// its record is seen in public DNS (or the rotation is forced).
    #[serde(default)]
    pub dkim_pending: Option<DkimKey>,
    #[serde(default)]
    pub mailboxes: BTreeMap<String, MailboxRecord>,
    #[serde(default)]
    pub forwarders: BTreeMap<String, ForwarderRecord>,
}

impl MailDomainRecord {
    pub fn domain(&self) -> Result<Domain> {
        Domain::parse_field(&self.domain, "domain")
    }

    /// Every DKIM key the domain holds: signing, pending and retired.
    pub fn dkim_keys(&self) -> impl Iterator<Item = &DkimKey> {
        self.dkim
            .iter()
            .chain(&self.dkim_pending)
            .chain(&self.dkim_retired)
    }

    /// Mailboxes that exist (not being removed).
    pub fn live_mailboxes(&self) -> impl Iterator<Item = (&String, &MailboxRecord)> {
        self.mailboxes
            .iter()
            .filter(|(_, m)| m.state != RecordState::Deleting)
    }

    /// Everything that reaches a file is re-validated here, so a record can
    /// never describe what the API would refuse.
    pub fn validate(&self) -> Result<()> {
        self.domain()?;
        Username::parse_field(&self.tenant, "tenant")?;
        for local in self.mailboxes.keys().chain(self.forwarders.keys()) {
            MailLocalPart::parse(local)?;
        }
        if let Some(c) = &self.catch_all {
            MailLocalPart::parse_field(c, "catch_all")?;
        }
        for mx in &self.external_mx {
            Domain::parse_field(mx, "external_mx")?;
        }
        for f in self.forwarders.values() {
            for d in &f.destinations {
                let parsed = MailDestination::parse(d)?;
                if parsed.as_str() != d {
                    return Err(Error::invalid("destinations", "not in canonical form"));
                }
            }
        }
        for m in self.mailboxes.values() {
            if !crate::mail::password::is_hash(&m.password_hash) {
                return Err(Error::invalid("password", "the stored hash is not usable"));
            }
        }
        for k in self.dkim_keys() {
            check_selector(&k.selector)?;
            if !k
                .public_key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
            {
                return Err(Error::invalid("dkim", "the public key is not base64"));
            }
        }
        Ok(())
    }
}

/// `ox` and digits.
pub fn check_selector(s: &str) -> Result<()> {
    let ok = s
        .strip_prefix("ox")
        .is_some_and(|d| (1..=20).contains(&d.len()) && d.bytes().all(|b| b.is_ascii_digit()));
    if ok {
        Ok(())
    } else {
        Err(Error::invalid("dkim", "bad selector"))
    }
}

/// An account's own email limits; `None` = the host default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailLimitsRecord {
    pub tenant: String,
    #[serde(default)]
    pub max_mailboxes: Option<u32>,
    #[serde(default)]
    pub max_mailbox_bytes: Option<u64>,
    #[serde(default)]
    pub rate_account: Option<u32>,
    #[serde(default)]
    pub rate_mailbox: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct MailStore {
    domains: PathBuf,
    limits: PathBuf,
}

impl MailStore {
    pub fn new(config: &Config) -> Self {
        let root = config.state_dir.join("mail");
        Self {
            domains: root.join("domains"),
            limits: root.join("limits"),
        }
    }

    pub fn domains_dir(&self) -> &Path {
        &self.domains
    }

    fn path(&self, domain: &Domain) -> PathBuf {
        self.domains.join(format!("{domain}.json"))
    }

    pub fn load(&self, domain: &Domain) -> Result<Option<MailDomainRecord>> {
        read_json(&self.path(domain))
    }

    pub fn save(&self, rec: &MailDomainRecord) -> Result<()> {
        rec.validate()?;
        fsutil::ensure_dir(&self.domains, DIR_MODE)?;
        write_json(&self.path(&rec.domain()?), rec)
    }

    pub fn delete(&self, domain: &Domain) -> Result<bool> {
        fsutil::remove_if_exists(&self.path(domain))
    }

    /// Every mail domain; a damaged record is logged and skipped
    /// (operations on it still fail closed through [`Self::load`]).
    pub fn list(&self) -> Result<Vec<MailDomainRecord>> {
        let mut out = Vec::new();
        for path in fsutil::list_files_with_suffix(&self.domains, ".json")? {
            match read_json::<MailDomainRecord>(&path) {
                Ok(Some(rec)) if rec.validate().is_ok() => out.push(rec),
                Ok(_) => {
                    tracing::error!(path = %path.display(), "invalid mail domain record skipped; repair or remove it");
                }
                Err(e) => {
                    tracing::error!(path = %path.display(), error = %e, "corrupt mail domain record skipped; repair or remove it");
                }
            }
        }
        out.sort_by(|a, b| a.domain.cmp(&b.domain));
        Ok(out)
    }

    pub fn list_tenant(&self, tenant: &str) -> Result<Vec<MailDomainRecord>> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|r| r.tenant == tenant)
            .collect())
    }

    fn limits_path(&self, tenant: &Username) -> PathBuf {
        self.limits.join(format!("{tenant}.json"))
    }

    pub fn load_limits(&self, tenant: &Username) -> Result<MailLimitsRecord> {
        Ok(
            read_json(&self.limits_path(tenant))?.unwrap_or_else(|| MailLimitsRecord {
                tenant: tenant.to_string(),
                ..MailLimitsRecord::default()
            }),
        )
    }

    pub fn save_limits(&self, rec: &MailLimitsRecord) -> Result<()> {
        let tenant = Username::parse_field(&rec.tenant, "tenant")?;
        fsutil::ensure_dir(&self.limits, DIR_MODE)?;
        write_json(&self.limits_path(&tenant), rec)
    }

    pub fn delete_limits(&self, tenant: &Username) -> Result<bool> {
        fsutil::remove_if_exists(&self.limits_path(tenant))
    }

    pub fn limits_files(&self) -> Result<Vec<PathBuf>> {
        fsutil::list_files_with_suffix(&self.limits, ".json")
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    let Some(bytes) = fsutil::read_optional(path)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| Error::CorruptRecord {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })
}

fn write_json<T: Serialize>(path: &Path, rec: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(rec)
        .map_err(|e| Error::Internal(format!("serialise record: {e}")))?;
    bytes.push(b'\n');
    fsutil::write_atomic(path, &bytes, RECORD_MODE)?;
    Ok(())
}
