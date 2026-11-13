//! Strict validation of every value that crosses the API boundary.
//!
//! The daemon runs as root and turns these values into user names, file-system
//! paths, systemd unit names and Nginx directives. Validation is therefore an
//! allow-list, never a deny-list: only the characters we are certain are safe
//! in *all* of those contexts are accepted.

use std::fmt;

use crate::error::{Error, Result};

/// Minimum accepted `MemoryMax=`. Anything lower just produces an OOM-kill loop.
pub const MIN_MEMORY_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// systemd's inclusive range for `CPUWeight=` / `IOWeight=`.
pub const MAX_WEIGHT: u32 = 10_000;
/// Smallest accepted disk limit. Less than this cannot even hold a site.
pub const MIN_DISK_MAX_BYTES: u64 = 1024 * 1024;
/// Smallest accepted inode limit (a fresh home already holds a handful of files).
pub const MIN_INODES_MAX: u64 = 100;
/// Shortest SFTP password the engine accepts; further policy is the panel's.
pub const MIN_SFTP_PASSWORD_CHARS: usize = 12;
/// Longest accepted SFTP password (characters).
pub const MAX_SFTP_PASSWORD_CHARS: usize = 256;
/// Most SSH public keys one tenant may hold.
pub const MAX_SFTP_KEYS: usize = 20;
/// Longest accepted public-key line (a 16384-bit RSA key is about 2.8 kB).
const SSH_KEY_LINE_MAX: usize = 8 * 1024;
const SSH_KEY_LABEL_MAX: usize = 64;
/// RSA moduli OpenSSH on the target accepts.
const RSA_MIN_BITS: usize = 2048;
const RSA_MAX_BITS: usize = 16384;
const USERNAME_MIN: usize = 3;
const USERNAME_MAX: usize = 32; // useradd's limit
const DOMAIN_MAX: usize = 253;
const LABEL_MAX: usize = 63;
const RELPATH_MAX: usize = 255;
pub const DEFAULT_DOCUMENT_ROOT: &str = "public_html";

/// Account names that must never become tenants even if they do not exist yet.
/// The real guard is the "is this user managed by OxPanel?" check at
/// provisioning time; this list is defence in depth.
const RESERVED_USERNAMES: &[&str] = &[
    "root",
    "bin",
    "daemon",
    "adm",
    "lp",
    "sync",
    "shutdown",
    "halt",
    "mail",
    "operator",
    "games",
    "ftp",
    "nobody",
    "nginx",
    "apache",
    "httpd",
    "www",
    "www-data",
    "oxpanel",
    "sshd",
    "dbus",
    "polkitd",
    "chrony",
    "tss",
    "sssd",
    "rpc",
    "rpcuser",
    "tcpdump",
    "unbound",
    "postfix",
    "mysql",
    "mariadb",
    "postgres",
    "redis",
    "php-fpm",
    "admin",
    "administrator",
    "sudo",
    "wheel",
    "sys",
    "systemd",
    "users",
    "nfsnobody",
    "backup",
    "toor",
];
const RESERVED_PREFIXES: &[&str] = &["systemd-", "oxpanel"];

/// A validated tenant user name: `^[a-z][a-z0-9_-]{2,31}$`, not reserved.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Username(String);

impl Username {
    pub fn parse(raw: &str) -> Result<Self> {
        Self::parse_field(raw, "username")
    }

    pub fn parse_field(raw: &str, field: &'static str) -> Result<Self> {
        let n = raw.chars().count();
        if !(USERNAME_MIN..=USERNAME_MAX).contains(&n) {
            return Err(Error::invalid(
                field,
                format!("must be {USERNAME_MIN}..={USERNAME_MAX} characters"),
            ));
        }
        let mut chars = raw.chars();
        match chars.next() {
            Some(c) if c.is_ascii_lowercase() => {}
            _ => {
                return Err(Error::invalid(
                    field,
                    "must start with a lower-case letter a-z",
                ))
            }
        }
        if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
            return Err(Error::invalid(
                field,
                "only a-z, 0-9, '_' and '-' are allowed",
            ));
        }
        if RESERVED_USERNAMES.contains(&raw) || RESERVED_PREFIXES.iter().any(|p| raw.starts_with(p))
        {
            return Err(Error::invalid(field, "name is reserved"));
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An opaque owner label supplied by the panel (e.g. a reseller id):
/// `^[a-z0-9][a-z0-9_.-]{0,63}$`. Stored and filtered on, never interpreted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OwnerLabel(String);

impl OwnerLabel {
    /// Empty input means "no owner".
    pub fn parse_optional(raw: &str) -> Result<Option<Self>> {
        if raw.is_empty() {
            return Ok(None);
        }
        let field = "owner";
        if raw.len() > 64 {
            return Err(Error::invalid(field, "must be at most 64 characters"));
        }
        let mut bytes = raw.bytes();
        match bytes.next() {
            Some(b) if b.is_ascii_lowercase() || b.is_ascii_digit() => {}
            _ => return Err(Error::invalid(field, "must start with a-z or 0-9")),
        }
        if !bytes.all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
        }) {
            return Err(Error::invalid(
                field,
                "only a-z, 0-9, '_', '.' and '-' are allowed",
            ));
        }
        Ok(Some(Self(raw.to_owned())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OwnerLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated, fully-qualified DNS host name in canonical lower-case ASCII
/// form (A-labels only). Suitable for `server_name` and for use as a file name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Domain(String);

impl Domain {
    pub fn parse(raw: &str) -> Result<Self> {
        Self::parse_field(raw, "domain")
    }

    pub fn parse_field(raw: &str, field: &'static str) -> Result<Self> {
        if raw.is_empty() || raw.len() > DOMAIN_MAX {
            return Err(Error::invalid(
                field,
                format!("must be 1..={DOMAIN_MAX} characters"),
            ));
        }
        if !raw.is_ascii() {
            return Err(Error::invalid(
                field,
                "must be ASCII (use IDNA A-labels / punycode)",
            ));
        }
        if raw != raw.to_ascii_lowercase() {
            return Err(Error::invalid(field, "must be lower-case"));
        }
        let labels: Vec<&str> = raw.split('.').collect();
        if labels.len() < 2 {
            return Err(Error::invalid(
                field,
                "must be a fully-qualified name with at least two labels",
            ));
        }
        for label in &labels {
            if label.is_empty() || label.len() > LABEL_MAX {
                return Err(Error::invalid(
                    field,
                    format!("labels must be 1..={LABEL_MAX} characters"),
                ));
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(Error::invalid(
                    field,
                    "labels may only contain a-z, 0-9 and '-'",
                ));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(Error::invalid(
                    field,
                    "labels may not start or end with '-'",
                ));
            }
        }
        // Reject anything that is an IPv4 literal (numeric TLD).
        if labels
            .last()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(Error::invalid(field, "top-level label may not be numeric"));
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated path *relative to a tenant home*: one or more components,
/// each `^[A-Za-z0-9._-]+$` and neither `.` nor `..`. No leading `/`, no empty
/// or trailing components. Never contains characters that are meaningful to
/// Nginx (`;`, `{`, `}`, `"`, `$`, whitespace) or to a shell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelPath(String);

impl RelPath {
    pub fn parse(raw: &str) -> Result<Self> {
        Self::parse_field(raw, "document_root")
    }

    pub fn parse_field(raw: &str, field: &'static str) -> Result<Self> {
        if raw.is_empty() {
            return Err(Error::invalid(field, "must not be empty"));
        }
        if raw.len() > RELPATH_MAX {
            return Err(Error::invalid(
                field,
                format!("must be at most {RELPATH_MAX} bytes"),
            ));
        }
        if raw.starts_with('/') {
            return Err(Error::invalid(field, "must be relative to the tenant home"));
        }
        for comp in raw.split('/') {
            if comp.is_empty() {
                return Err(Error::invalid(
                    field,
                    "empty path component (double or trailing '/')",
                ));
            }
            if comp == "." || comp == ".." {
                return Err(Error::invalid(
                    field,
                    "'.' and '..' components are not allowed",
                ));
            }
            if !comp
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
            {
                return Err(Error::invalid(
                    field,
                    "components may only contain A-Z, a-z, 0-9, '.', '_' and '-'",
                ));
            }
        }
        Ok(Self(raw.to_owned()))
    }

    /// The default document root, `public_html`.
    pub fn default_document_root() -> Self {
        Self(DEFAULT_DOCUMENT_ROOT.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validated resource limits. `None` means "systemd default".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct Limits {
    pub memory_max_bytes: Option<u64>,
    pub cpu_weight: Option<u32>,
    pub io_weight: Option<u32>,
    pub tasks_max: Option<u32>,
    /// Disk space the tenant's files may occupy on the file system holding
    /// the homes (kernel user quota). Absent in records written before
    /// quotas existed.
    #[serde(default)]
    pub disk_max_bytes: Option<u64>,
    /// Number of files and directories the tenant may own there.
    #[serde(default)]
    pub inodes_max: Option<u64>,
}

impl Limits {
    /// Validate raw wire values (0 = unset).
    pub fn parse(
        memory_max_bytes: u64,
        cpu_weight: u32,
        io_weight: u32,
        tasks_max: u32,
    ) -> Result<Self> {
        let memory_max_bytes = match memory_max_bytes {
            0 => None,
            b if b < MIN_MEMORY_MAX_BYTES => {
                return Err(Error::invalid(
                    "limits.memory_max_bytes",
                    format!("must be 0 (unlimited) or at least {MIN_MEMORY_MAX_BYTES} bytes"),
                ))
            }
            b => Some(b),
        };
        let weight = |v: u32, field: &'static str| -> Result<Option<u32>> {
            match v {
                0 => Ok(None),
                w if (1..=MAX_WEIGHT).contains(&w) => Ok(Some(w)),
                _ => Err(Error::invalid(
                    field,
                    format!("must be 0 (default) or 1..={MAX_WEIGHT}"),
                )),
            }
        };
        Ok(Self {
            memory_max_bytes,
            cpu_weight: weight(cpu_weight, "limits.cpu_weight")?,
            io_weight: weight(io_weight, "limits.io_weight")?,
            tasks_max: if tasks_max == 0 {
                None
            } else {
                Some(tasks_max)
            },
            disk_max_bytes: None,
            inodes_max: None,
        })
    }

    /// Add the disk-quota part of the limits (raw wire values, 0 = unlimited).
    /// Whether the host can enforce them is checked by the workflow.
    pub fn with_disk(mut self, disk_max_bytes: u64, inodes_max: u64) -> Result<Self> {
        self.disk_max_bytes = match disk_max_bytes {
            0 => None,
            b if b < MIN_DISK_MAX_BYTES => {
                return Err(Error::invalid(
                    "limits.disk_max_bytes",
                    format!("must be 0 (unlimited) or at least {MIN_DISK_MAX_BYTES} bytes"),
                ))
            }
            b => Some(b),
        };
        self.inodes_max = match inodes_max {
            0 => None,
            n if n < MIN_INODES_MAX => {
                return Err(Error::invalid(
                    "limits.inodes_max",
                    format!("must be 0 (unlimited) or at least {MIN_INODES_MAX}"),
                ))
            }
            n => Some(n),
        };
        Ok(self)
    }

    /// Whether any kernel disk quota is requested.
    pub fn has_disk_quota(&self) -> bool {
        self.disk_max_bytes.is_some() || self.inodes_max.is_some()
    }
}

/// An SFTP password: 12..=256 characters, none of them control characters
/// (a newline would start a second `user:password` line for `chpasswd`).
/// `Debug` never shows it; it is handed to `chpasswd` on stdin only.
#[derive(Clone, PartialEq, Eq)]
pub struct SftpPassword(String);

impl SftpPassword {
    pub fn parse(raw: &str) -> Result<Self> {
        let chars = raw.chars().count();
        if !(MIN_SFTP_PASSWORD_CHARS..=MAX_SFTP_PASSWORD_CHARS).contains(&chars) {
            return Err(Error::invalid(
                "password",
                format!("must be {MIN_SFTP_PASSWORD_CHARS}..={MAX_SFTP_PASSWORD_CHARS} characters"),
            ));
        }
        if raw.chars().any(char::is_control) {
            return Err(Error::invalid(
                "password",
                "must not contain control characters (newlines, tabs, NUL, …)",
            ));
        }
        Ok(Self(raw.to_owned()))
    }

    /// The password, for the one place that writes it to `chpasswd`.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SftpPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SftpPassword([redacted])")
    }
}

/// A label for an SSH key (e.g. `laptop`, `deploy@ci`): `^[A-Za-z0-9@._+-]{1,64}$`.
/// It is written into the tenant's authorized-keys file, so nothing that
/// could start a new line or a new field is accepted.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyLabel(String);

impl KeyLabel {
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.is_empty() || raw.len() > SSH_KEY_LABEL_MAX {
            return Err(Error::invalid(
                "label",
                format!("must be 1..={SSH_KEY_LABEL_MAX} characters"),
            ));
        }
        if !raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'@' | b'.' | b'_' | b'+' | b'-'))
        {
            return Err(Error::invalid(
                "label",
                "only A-Z, a-z, 0-9, '@', '.', '_', '+' and '-' are allowed",
            ));
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The SHA-256 fingerprint of an SSH public key as OpenSSH prints it:
/// `SHA256:` followed by 43 base64 characters (no padding).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyFingerprint(String);

impl KeyFingerprint {
    pub fn parse(raw: &str) -> Result<Self> {
        let ok = raw.strip_prefix("SHA256:").is_some_and(|rest| {
            rest.len() == 43
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
        });
        if !ok {
            return Err(Error::invalid(
                "fingerprint",
                "must be 'SHA256:' followed by 43 base64 characters, as ssh-keygen -l prints it",
            ));
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated SSH public key.
///
/// Accepted: one line in the format of an `id_*.pub` file — key type, base64
/// key, optional comment — and nothing in front of the type (no `command=`,
/// `from=` or other options: the engine decides the options, see
/// [`crate::sftp`]). The key type must be one of Ed25519, ECDSA (NIST P-256,
/// P-384, P-521), RSA of at least 2048 bits, or the FIDO variants of Ed25519
/// and ECDSA; DSA is refused. The base64 part is decoded and must be exactly
/// one well-formed key of the declared type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPublicKey {
    key_type: &'static str,
    /// Canonical (re-encoded, padded) base64 of the key blob.
    blob: String,
    fingerprint: String,
    /// The comment of the line, if it is usable as a label.
    comment: Option<KeyLabel>,
}

/// Key types OxPanel accepts, by their name on the wire.
const SSH_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// Reads the length-prefixed fields of an SSH key blob (RFC 4253 §6.6).
struct BlobReader<'a>(&'a [u8]);

impl<'a> BlobReader<'a> {
    fn string(&mut self) -> Option<&'a [u8]> {
        let (len, rest) = self.0.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
        let (field, rest) = rest.split_at_checked(len)?;
        self.0 = rest;
        Some(field)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Size in bits of a positive multi-precision integer (RFC 4251 `mpint`).
fn mpint_bits(m: &[u8]) -> Option<usize> {
    // Negative numbers have the top bit of the first byte set.
    if m.first().is_some_and(|b| b & 0x80 != 0) {
        return None;
    }
    let first = m.iter().position(|b| *b != 0)?;
    let top = m.get(first)?;
    let significant = m.len().checked_sub(first)?;
    significant
        .checked_mul(8)?
        .checked_sub(usize::try_from(top.leading_zeros()).ok()?)
}

/// An uncompressed elliptic-curve point (`0x04 || X || Y`) on the named curve.
fn ecdsa_point(r: &mut BlobReader<'_>, curve: &str, len: usize) -> Option<()> {
    if r.string()? != curve.as_bytes() {
        return None;
    }
    let point = r.string()?;
    (point.len() == len && point.first() == Some(&0x04)).then_some(())
}

/// `Some(())` when `blob` is exactly one well-formed public key of `key_type`.
fn check_key_blob(key_type: &str, blob: &[u8]) -> Option<()> {
    let mut r = BlobReader(blob);
    if r.string()? != key_type.as_bytes() {
        return None;
    }
    match key_type {
        "ssh-ed25519" => (r.string()?.len() == 32).then_some(())?,
        "sk-ssh-ed25519@openssh.com" => {
            (r.string()?.len() == 32).then_some(())?;
            r.string()?; // application
        }
        "ecdsa-sha2-nistp256" => ecdsa_point(&mut r, "nistp256", 65)?,
        "ecdsa-sha2-nistp384" => ecdsa_point(&mut r, "nistp384", 97)?,
        "ecdsa-sha2-nistp521" => ecdsa_point(&mut r, "nistp521", 133)?,
        "sk-ecdsa-sha2-nistp256@openssh.com" => {
            ecdsa_point(&mut r, "nistp256", 65)?;
            r.string()?; // application
        }
        "ssh-rsa" => {
            let exponent = mpint_bits(r.string()?)?;
            let modulus = mpint_bits(r.string()?)?;
            (exponent >= 2 && (RSA_MIN_BITS..=RSA_MAX_BITS).contains(&modulus)).then_some(())?;
        }
        _ => return None,
    }
    r.is_empty().then_some(())
}

impl SshPublicKey {
    /// Parse one `authorized_keys`-style line without options.
    pub fn parse(raw: &str) -> Result<Self> {
        const FIELD: &str = "public_key";
        let line = raw.trim_matches([' ', '\t', '\n', '\r']);
        if line.is_empty() {
            return Err(Error::invalid(FIELD, "must not be empty"));
        }
        if line.len() > SSH_KEY_LINE_MAX {
            return Err(Error::invalid(
                FIELD,
                format!("must be at most {SSH_KEY_LINE_MAX} bytes"),
            ));
        }
        if !line.bytes().all(|b| b == b' ' || b.is_ascii_graphic()) {
            return Err(Error::invalid(
                FIELD,
                "must be a single line of printable ASCII (exactly one key)",
            ));
        }
        let mut parts = line.splitn(3, ' ');
        let (declared, encoded) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        let Some(key_type) = SSH_KEY_TYPES.iter().copied().find(|t| *t == declared) else {
            return Err(Error::invalid(
                FIELD,
                "must start with a supported key type (ssh-ed25519, ecdsa-sha2-nistp256/384/521, ssh-rsa, sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com); key options are not accepted",
            ));
        };
        Self::from_parts(key_type, encoded, parts.next().unwrap_or("").trim())
    }

    /// Build from the stored form (type and base64 blob), validating it again.
    pub fn from_stored(key_type: &str, blob: &str) -> Result<Self> {
        let Some(key_type) = SSH_KEY_TYPES.iter().copied().find(|t| *t == key_type) else {
            return Err(Error::invalid("public_key", "unsupported key type"));
        };
        Self::from_parts(key_type, blob, "")
    }

    fn from_parts(key_type: &'static str, encoded: &str, comment: &str) -> Result<Self> {
        use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
        use base64::Engine as _;
        use sha2::Digest as _;
        const FIELD: &str = "public_key";
        let blob = STANDARD
            .decode(encoded)
            .map_err(|_| Error::invalid(FIELD, "the key is not valid base64"))?;
        if check_key_blob(key_type, &blob).is_none() {
            return Err(Error::invalid(
                FIELD,
                if key_type == "ssh-rsa" {
                    format!("not a well-formed RSA key of {RSA_MIN_BITS}..={RSA_MAX_BITS} bits")
                } else {
                    format!("not a well-formed {key_type} key")
                },
            ));
        }
        let fingerprint = format!(
            "SHA256:{}",
            STANDARD_NO_PAD.encode(sha2::Sha256::digest(&blob))
        );
        Ok(Self {
            key_type,
            blob: STANDARD.encode(&blob),
            fingerprint,
            comment: KeyLabel::parse(comment).ok(),
        })
    }

    pub fn key_type(&self) -> &'static str {
        self.key_type
    }

    /// Canonical base64 of the key blob.
    pub fn blob(&self) -> &str {
        &self.blob
    }

    /// `SHA256:…`, as `ssh-keygen -l` prints it.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The comment of the parsed line when it is a valid [`KeyLabel`].
    pub fn comment(&self) -> Option<&KeyLabel> {
        self.comment.as_ref()
    }
}

/// Longest suffix of a database or database-user name. With the longest
/// tenant name (32) and the separator the result is 57 characters, inside
/// MariaDB's limits (64 for a database, 80 for a user name in 10.5).
const DB_SUFFIX_MAX: usize = 24;
/// The separator between the tenant name and the suffix.
pub const DB_SEPARATOR: char = '_';
/// Names of MariaDB's own schemas and accounts. The grammar below cannot
/// produce most of them; `information_schema` and `performance_schema` it
/// could (a tenant called `information`), so they are refused by name.
const DB_RESERVED: &[&str] = &[
    "mysql",
    "information_schema",
    "performance_schema",
    "sys",
    "root",
    "mariadb.sys",
    "test",
];
pub const DB_PASSWORD_MIN: usize = 8;
pub const DB_PASSWORD_MAX: usize = 128;

/// A validated name of a MariaDB database or database user:
/// `<tenant>_<suffix>` with suffix `^[a-z0-9]{1,24}$`.
///
/// The suffix cannot contain the separator, so the tenant is always the text
/// before the *last* `_` — unambiguous even though tenant names may contain
/// `_` themselves (`acme_shop_wp` belongs to tenant `acme_shop`, and tenant
/// `acme` can never create it). Two tenants can therefore never collide, and
/// the name contains nothing that needs escaping in an SQL identifier or
/// string (no quote, backtick or backslash).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DbName {
    name: String,
    tenant: Username,
}

impl DbName {
    /// Parse a name whose owner is derived from the name itself.
    pub fn parse(raw: &str, field: &'static str) -> Result<Self> {
        let bad = || {
            Error::invalid(
                field,
                format!(
                    "must be <tenant>_<suffix>, suffix 1..={DB_SUFFIX_MAX} characters a-z, 0-9"
                ),
            )
        };
        if DB_RESERVED.contains(&raw) {
            return Err(Error::invalid(field, "name is reserved"));
        }
        let (tenant, suffix) = raw.rsplit_once(DB_SEPARATOR).ok_or_else(bad)?;
        if suffix.is_empty()
            || suffix.len() > DB_SUFFIX_MAX
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return Err(bad());
        }
        let tenant = Username::parse_field(tenant, field).map_err(|_| bad())?;
        Ok(Self {
            name: raw.to_owned(),
            tenant,
        })
    }

    /// Parse a name that must belong to `tenant`.
    pub fn parse_for(raw: &str, tenant: &Username, field: &'static str) -> Result<Self> {
        let name = Self::parse(raw, field)?;
        if &name.tenant != tenant {
            return Err(Error::invalid(
                field,
                format!("must start with the tenant name and '_' ({tenant}_...)"),
            ));
        }
        Ok(name)
    }

    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// The tenant this name belongs to.
    pub fn tenant(&self) -> &Username {
        &self.tenant
    }
}

impl fmt::Display for DbName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// A database user's password as it arrived in a request: 8..=128
/// characters without control characters. Policy (strength, rotation) is the
/// panel's; this is the engine's last line of defence. The value is never
/// printed: `Debug` is redacted and there is no `Display`.
#[derive(Clone, PartialEq, Eq)]
pub struct DbPassword(String);

impl DbPassword {
    pub fn parse(raw: &str) -> Result<Self> {
        let field = "password";
        let n = raw.chars().count();
        if !(DB_PASSWORD_MIN..=DB_PASSWORD_MAX).contains(&n) {
            return Err(Error::invalid(
                field,
                format!("must be {DB_PASSWORD_MIN}..={DB_PASSWORD_MAX} characters"),
            ));
        }
        if raw.chars().any(char::is_control) {
            return Err(Error::invalid(field, "must not contain control characters"));
        }
        Ok(Self(raw.to_owned()))
    }

    /// The secret itself; only the hashing code may ask for it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DbPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DbPassword(<redacted>)")
    }
}

/// Identifier of a backup (`b` + creation time in milliseconds) or of a job
/// (`j` + start time). Allow-listed because both become file and unit names.
fn parse_id(raw: &str, prefix: char, field: &'static str) -> Result<String> {
    let mut chars = raw.chars();
    let digits = raw.len().saturating_sub(1);
    if chars.next() != Some(prefix)
        || !(10..=20).contains(&digits)
        || !chars.all(|c| c.is_ascii_digit())
    {
        return Err(Error::invalid(
            field,
            format!("must be '{prefix}' followed by 10 to 20 digits"),
        ));
    }
    Ok(raw.to_owned())
}

/// A validated backup identifier: `^b[0-9]{10,20}$`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BackupId(String);

impl BackupId {
    pub fn parse(raw: &str) -> Result<Self> {
        parse_id(raw, 'b', "backup_id").map(Self)
    }

    /// The identifier for a backup created at `unix_millis`.
    pub fn from_millis(unix_millis: u128) -> Self {
        Self(format!("b{unix_millis:013}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BackupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated job identifier: `^j[0-9]{10,20}$`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct JobId(String);

impl JobId {
    pub fn parse(raw: &str) -> Result<Self> {
        parse_id(raw, 'j', "job_id").map(Self)
    }

    /// The identifier for a job started at `unix_millis`.
    pub fn from_millis(unix_millis: u128) -> Self {
        Self(format!("j{unix_millis:013}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Length of a month for retention periods: a twelfth of the Gregorian
/// year, so that 12 months is one year to the second.
pub const RETENTION_MONTH_SECS: u64 = 2_629_746;

/// A retention period in whole months, 1 to 12 (`field` names the API field).
pub fn retain_months(months: u32, field: &'static str) -> Result<u64> {
    if (1..=12).contains(&months) {
        Ok(u64::from(months) * RETENTION_MONTH_SECS)
    } else {
        Err(Error::invalid(field, "must be between 1 and 12 months"))
    }
}

#[cfg(test)]
mod id_tests {
    use super::*;

    #[test]
    fn backup_and_job_ids_are_allow_listed() {
        assert!(BackupId::parse("b1731500000123").is_ok());
        assert_eq!(BackupId::from_millis(5).as_str(), "b0000000000005");
        assert!(JobId::parse(JobId::from_millis(1_731_500_000_123).as_str()).is_ok());
        for bad in [
            "",
            "b",
            "b123",
            "j1731500000123",
            "b1731500000123/..",
            "../b1731500000123",
            "b17315000001x3",
            "b1731500000123\n",
            "b173150000012300000000000000",
            "B1731500000123",
            "b१७३१५००००००१२३",
        ] {
            assert!(BackupId::parse(bad).is_err(), "{bad:?}");
        }
        assert!(JobId::parse("b1731500000123").is_err());
    }

    #[test]
    fn retention_is_one_to_twelve_months() {
        assert_eq!(retain_months(12, "retain_months").ok(), Some(31_556_952));
        assert_eq!(retain_months(1, "retain_months").ok(), Some(2_629_746));
        for bad in [0, 13, u32::MAX] {
            assert!(retain_months(bad, "retain_months").is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_names_belong_to_exactly_one_tenant() -> Result<()> {
        let acme = Username::parse("acme")?;
        let acme_shop = Username::parse("acme_shop")?;
        let n = DbName::parse_for("acme_wp", &acme, "name")?;
        assert_eq!((n.as_str(), n.tenant()), ("acme_wp", &acme));
        // The tenant is the text before the last separator.
        assert_eq!(DbName::parse("acme_shop_wp", "name")?.tenant(), &acme_shop);
        assert!(is_invalid(DbName::parse_for("acme_shop_wp", &acme, "name")));
        assert!(DbName::parse_for("acme_shop_wp", &acme_shop, "name").is_ok());
        assert_eq!(
            DbName::parse("foo-bar_db1", "name")?.tenant().as_str(),
            "foo-bar"
        );
        let longest = format!("{}_{}", "x".repeat(32), "9".repeat(24));
        assert_eq!(longest.len(), 57);
        assert!(DbName::parse(&longest, "name").is_ok());
        Ok(())
    }

    #[test]
    fn db_names_reject_injection_reserved_and_foreign_names() {
        let too_long = format!("acme_{}", "a".repeat(25));
        for bad in [
            "",
            "acme",
            "acme_",
            "_wp",
            "acme_WP",
            "acme_w-p",
            "acme_w.p",
            "acme_wp`; DROP DATABASE mysql; --",
            "acme_wp'",
            "acme_wp\"",
            "acme_wp\\",
            "acme_wp;",
            "acme_wp ",
            "acme_w%",
            "acme_wp\n",
            "acme_wp\0",
            "acme_ẅp",
            "mysql",
            "sys",
            "root",
            "information_schema",
            "performance_schema",
            "mariadb.sys",
            "root_x",
            "mysql_x",
            "ab_x",
            "Acme_wp",
            "acme`_wp",
            "acme'@'%_x",
            too_long.as_str(),
        ] {
            assert!(is_invalid(DbName::parse(bad, "name")), "{bad:?}");
        }
    }

    #[test]
    fn db_password_bounds_and_redaction() -> Result<()> {
        assert!(is_invalid(DbPassword::parse("")));
        assert!(is_invalid(DbPassword::parse("short77")));
        assert!(is_invalid(DbPassword::parse(&"a".repeat(129))));
        assert!(is_invalid(DbPassword::parse("line\nbreak-pw")));
        assert!(is_invalid(DbPassword::parse("nul\0byte-pw")));
        let p = DbPassword::parse("it's \"quoted\" \\ `päss` ; --")?;
        assert_eq!(p.expose(), "it's \"quoted\" \\ `päss` ; --");
        assert_eq!(format!("{p:?}"), "DbPassword(<redacted>)");
        Ok(())
    }

    fn is_invalid<T: fmt::Debug>(r: Result<T>) -> bool {
        matches!(r, Err(Error::InvalidInput { .. }))
    }

    #[test]
    fn username_accepts_sane_names() {
        for ok in [
            "alice",
            "web_01",
            "a-b-c",
            "abc",
            "x1234567890123456789012345678901",
        ] {
            assert!(Username::parse(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn username_rejects_dangerous_names() {
        for bad in [
            "",
            "ab",
            "Alice",
            "1abc",
            "-abc",
            "_abc",
            "al ice",
            "al;ice",
            "al/ice",
            "al.ice",
            "al\nice",
            "alice$",
            "ali\0ce",
            "root",
            "nginx",
            "oxpanel",
            "oxpanel-x",
            "systemd-network",
            "wheel",
            "a".repeat(33).as_str(),
            "ünïcode",
            "al\u{200b}ice",
            "..",
            "user@host",
            "$(id)",
            "`id`",
            "--uid",
            "-r",
        ] {
            assert!(is_invalid(Username::parse(bad)), "{bad:?}");
        }
    }

    #[test]
    fn owner_label_rules() {
        assert_eq!(OwnerLabel::parse_optional("").ok(), Some(None));
        for ok in ["reseller1", "acme.hosting", "r-42", "0abc", "a_b"] {
            assert!(OwnerLabel::parse_optional(ok).is_ok(), "{ok}");
        }
        for bad in [
            "Reseller",
            "-x",
            ".x",
            "a b",
            "a;b",
            "a/b",
            "ä",
            &"a".repeat(65),
        ] {
            assert!(is_invalid(OwnerLabel::parse_optional(bad)), "{bad:?}");
        }
    }

    #[test]
    fn domain_accepts_valid_names() {
        for ok in [
            "example.com",
            "a.b.c.example.co.uk",
            "xn--bcher-kva.example",
            "1a.example.net",
            "my-site.example.org",
        ] {
            assert!(Domain::parse(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn domain_rejects_invalid_names() {
        let long_label = format!("{}.example.com", "a".repeat(64));
        let too_long = format!("{}.com", ["abcdefghij"; 26].join("."));
        for bad in [
            "",
            "localhost",
            "Example.com",
            "exam ple.com",
            "example.com.",
            ".example.com",
            "ex..ample.com",
            "-example.com",
            "example-.com",
            "example.com;",
            "example.com{",
            "example.com}",
            "example.com\"",
            "$host.example.com",
            "*.example.com",
            "192.168.1.1",
            "10.0.0.1",
            "exämple.com",
            "example.com/../etc",
            "example.com\n",
            "example.c om",
            long_label.as_str(),
            too_long.as_str(),
            "example_domain.com",
        ] {
            assert!(is_invalid(Domain::parse(bad)), "{bad:?}");
        }
    }

    #[test]
    fn relpath_accepts_valid_paths() {
        for ok in [
            "public_html",
            "www/site-1",
            "a/b/c.d",
            "public_html/v2.0",
            "sub.dir/deep_er-path",
        ] {
            assert!(RelPath::parse(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn relpath_rejects_traversal_and_metacharacters() {
        for bad in [
            "",
            "/etc",
            "/",
            "..",
            "../etc",
            "a/../b",
            "./a",
            "a/./b",
            "a//b",
            "a/",
            "a b",
            "a;b",
            "a{b",
            "a}b",
            "a\"b",
            "a$b",
            "a\nb",
            "a\\b",
            "a*b",
            "a?b",
            "~alice",
            "a:b",
            "a|b",
            "a`b",
            "ä",
            "a\0b",
            &"a".repeat(256),
        ] {
            assert!(is_invalid(RelPath::parse(bad)), "{bad:?}");
        }
    }

    #[test]
    fn limits_parse_and_bounds() {
        assert_eq!(Limits::parse(0, 0, 0, 0).ok(), Some(Limits::default()));
        let l = Limits::parse(MIN_MEMORY_MAX_BYTES, 1, MAX_WEIGHT, 50).ok();
        assert_eq!(
            l,
            Some(Limits {
                memory_max_bytes: Some(MIN_MEMORY_MAX_BYTES),
                cpu_weight: Some(1),
                io_weight: Some(MAX_WEIGHT),
                tasks_max: Some(50),
                ..Limits::default()
            })
        );
        assert!(is_invalid(Limits::parse(MIN_MEMORY_MAX_BYTES - 1, 0, 0, 0)));
        assert!(is_invalid(Limits::parse(0, MAX_WEIGHT + 1, 0, 0)));
        assert!(is_invalid(Limits::parse(0, 0, MAX_WEIGHT + 1, 0)));
    }

    #[test]
    fn disk_limits_parse_and_bounds() -> Result<()> {
        let base = Limits::default();
        assert_eq!(base.with_disk(0, 0)?, base);
        assert!(!base.has_disk_quota());
        let l = base.with_disk(MIN_DISK_MAX_BYTES, MIN_INODES_MAX)?;
        assert_eq!(
            (l.disk_max_bytes, l.inodes_max),
            (Some(MIN_DISK_MAX_BYTES), Some(MIN_INODES_MAX))
        );
        assert!(l.has_disk_quota());
        assert!(base.with_disk(0, 5000)?.has_disk_quota());
        assert!(is_invalid(base.with_disk(MIN_DISK_MAX_BYTES - 1, 0)));
        assert!(is_invalid(base.with_disk(0, MIN_INODES_MAX - 1)));
        // Records written before quotas existed still load.
        let old: Limits = serde_json::from_str(
            r#"{"memory_max_bytes":null,"cpu_weight":5,"io_weight":null,"tasks_max":null}"#,
        )
        .map_err(|e| Error::Internal(e.to_string()))?;
        assert_eq!((old.cpu_weight, old.disk_max_bytes), (Some(5), None));
        Ok(())
    }

    // Throwaway keys generated with `ssh-keygen`; fingerprints from `ssh-keygen -l`.
    const ED25519_BLOB: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIGNQ8nctDOzq4yQ8Bix4hfkkqCQw0kkYzl6hc7hg7rRo";
    const ED25519_FP: &str = "SHA256:d61vVJ9GcopAzh14aZ3bTeCz+981/iT/jSIxXFS8pjQ";
    const RSA2048: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCgqXDlUFWAX9AH//+b+nL28dRjcv1LcY9olh0gS4CyAj2mx9bHPnjCBzNksuAY8XWXjMJPRCe4SpnFsoRTDNHs3PmtRuo/4B6KtXodSSKPWpNdblemnG32j8csnzPVmGfQbTuk5W0bBQA5nxsRENVjh5K5kNrSO5SqpLAduOOG/OEEaLvF6PswEZuHfBTRYiNF9FgasniKt/qYkEgtJ3nwwzTaybf0L111ELP/CIHMT1EBja+ceFnoo2wcg0+FYGAvjkdcLyZONcHEXsGFD+URBv2sG8cL5aekTeFENrB/0y61w/vNKTn7H3vXA0eKkju41I2EghfbUBhwDHjemujL rsa2048";
    const RSA1024: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC8hAmgV+3wrL6AhqlLfB48OnQYBum5QCCBuW75++8tK6SVSf04pjgy3jvpiaoIlislmOF4p/PTqkQfkwGppaRE4BO0GsQr5TsuPHZ8VkwHWV+NvScf0N2uj/Oyteid28Lb+rZWbqt8x5MvVQTUesROtEuunjwellM3G+hK0D7yEw== rsa1024";
    const ECDSA256: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCPCQ5RPJL6Of0dEwqmMxFaxsEIMTgTuoqdjIkhuKJBRxt4u5xxce+n8yuTHQ+EVvhVfmIFaBrQ9IenhTvA47u8= ec";

    #[test]
    fn ssh_key_accepts_plain_keys_and_computes_the_openssh_fingerprint() -> Result<()> {
        let k = SshPublicKey::parse(&format!("ssh-ed25519 {ED25519_BLOB} alice@laptop"))?;
        assert_eq!(k.key_type(), "ssh-ed25519");
        assert_eq!(k.fingerprint(), ED25519_FP);
        assert_eq!(k.comment().map(KeyLabel::as_str), Some("alice@laptop"));
        assert_eq!(k.blob(), ED25519_BLOB);
        // Surrounding white space and a missing or unusable comment are fine.
        let bare = SshPublicKey::parse(&format!("  ssh-ed25519 {ED25519_BLOB}\n"))?;
        assert_eq!(bare.comment(), None);
        let odd = SshPublicKey::parse(&format!("ssh-ed25519 {ED25519_BLOB} my key (old)"))?;
        assert_eq!(odd.comment(), None, "an unusable comment is dropped");
        assert_eq!(odd.fingerprint(), ED25519_FP);
        assert_eq!(
            SshPublicKey::from_stored(k.key_type(), k.blob())?.fingerprint(),
            ED25519_FP
        );
        assert_eq!(
            SshPublicKey::parse(RSA2048)?.fingerprint(),
            "SHA256:H1e19kwLaC4z2PEcd8wTFLZs15jrHfkNQ5fV9OE0Jlc"
        );
        assert_eq!(
            SshPublicKey::parse(ECDSA256)?.fingerprint(),
            "SHA256:WXfDgbyQ6VkZ+BgiCeSpzsvA1bZVLsX3/n4u1ddioxE"
        );
        Ok(())
    }

    #[test]
    fn ssh_key_rejects_options_other_types_and_malformed_blobs() {
        let key = format!("ssh-ed25519 {ED25519_BLOB}");
        let two_lines = format!("{key}\n{key}");
        let with_options = format!("command=\"/bin/sh\" {key}");
        let with_flag = format!("no-port-forwarding {key}");
        let wrong_type = format!("ecdsa-sha2-nistp256 {ED25519_BLOB}");
        let truncated = format!("ssh-ed25519 {}", ED25519_BLOB.get(..40).unwrap_or(""));
        let trailing = format!("ssh-ed25519 {ED25519_BLOB}AAAA");
        let huge = format!("ssh-ed25519 {}", "A".repeat(SSH_KEY_LINE_MAX));
        let tab = format!("ssh-ed25519\t{ED25519_BLOB}");
        let nul = format!("{key} a\0b");
        for bad in [
            "",
            "   ",
            "ssh-ed25519",
            "ssh-ed25519 ",
            "ssh-ed25519 not*base64",
            "ssh-dss AAAAB3NzaC1kc3MAAACBAJ x",
            RSA1024,
            two_lines.as_str(),
            with_options.as_str(),
            with_flag.as_str(),
            wrong_type.as_str(),
            truncated.as_str(),
            trailing.as_str(),
            huge.as_str(),
            tab.as_str(),
            nul.as_str(),
        ] {
            assert!(is_invalid(SshPublicKey::parse(bad)), "{bad:?}");
        }
        assert!(is_invalid(SshPublicKey::from_stored(
            "ssh-dss",
            ED25519_BLOB
        )));
        assert!(is_invalid(SshPublicKey::from_stored(
            "ssh-ed25519",
            "AAAA\nssh-ed25519 AAAA"
        )));
    }

    #[test]
    fn rsa_size_is_read_from_the_key_itself() {
        assert_eq!(mpint_bits(&[0x01, 0x00, 0x01]), Some(17));
        assert_eq!(mpint_bits(&[0x00, 0x80]), Some(8));
        assert_eq!(mpint_bits(&[0x80]), None, "negative");
        assert_eq!(mpint_bits(&[]), None);
        assert_eq!(mpint_bits(&[0, 0]), None, "zero");
    }

    #[test]
    fn sftp_passwords_have_a_minimum_length_and_no_control_characters() {
        for ok in [
            "correct horse",
            "x".repeat(12).as_str(),
            "pässwörd-ünïcode",
            "with:colon:s and spaces",
        ] {
            assert!(SftpPassword::parse(ok).is_ok(), "{ok}");
        }
        let long = "y".repeat(MAX_SFTP_PASSWORD_CHARS + 1);
        for bad in [
            "",
            "elevenchars",
            "two\nlines-here",
            "tab\there-and-more",
            "nul\0-in-the-middle",
            long.as_str(),
        ] {
            assert!(is_invalid(SftpPassword::parse(bad)), "{bad:?}");
        }
        let p = SftpPassword::parse("hunter2-hunter2").unwrap_or_else(|e| panic!("{e}"));
        assert!(!format!("{p:?}").contains("hunter2"));
        // The error message never echoes the password either.
        let e = SftpPassword::parse("short-pw")
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(!e.contains("short-pw"), "{e}");
    }

    #[test]
    fn key_labels_and_fingerprints() {
        for ok in ["laptop", "deploy@ci", "a", "Work.Mac-2_x+y"] {
            assert!(KeyLabel::parse(ok).is_ok(), "{ok}");
        }
        for bad in ["", "two words", "a\nb", "a,b", "a\"b", "ü", &"a".repeat(65)] {
            assert!(is_invalid(KeyLabel::parse(bad)), "{bad:?}");
        }
        assert!(KeyFingerprint::parse(ED25519_FP).is_ok());
        let padded = format!("{ED25519_FP}=");
        let newline = format!("{}\n", ED25519_FP.get(..49).unwrap_or(""));
        for bad in [
            "",
            "SHA256:",
            "MD5:aa:bb",
            "SHA256:short",
            padded.as_str(),
            newline.as_str(),
        ] {
            assert!(is_invalid(KeyFingerprint::parse(bad)), "{bad:?}");
        }
    }
}

// --- File manager -------------------------------------------------------------

/// Longest path inside a home the file manager accepts, in bytes (the
/// kernel's `PATH_MAX` is 4096 for the whole path, the home included).
pub const FILE_PATH_MAX: usize = 3072;
/// Longest name of one entry, in bytes (the kernel's `NAME_MAX`).
pub const FILE_NAME_MAX: usize = 255;
/// Most components a path may have.
pub const FILE_PATH_DEPTH_MAX: usize = 64;

/// A path inside a tenant's home, relative to it: what every file-manager
/// request names. `""` (or `"."`) is the home itself.
///
/// The text is a plain list of names separated by `/`: no leading `/`, no
/// empty, `.` or `..` component, no NUL, at most [`FILE_PATH_MAX`] bytes and
/// [`FILE_PATH_DEPTH_MAX`] components, each at most [`FILE_NAME_MAX`] bytes.
/// Lexical confinement is only the first layer: the worker resolves every
/// path with `openat2(RESOLVE_BENEATH)` from the home as the tenant, so a
/// symlink cannot lead out either (see `files_worker.rs`).
///
/// A path that names something that already exists may contain any
/// character the file system allows except NUL — names created over SFTP
/// with control characters must be removable. A name the engine *creates*
/// must pass [`check_new_name`].
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "String", into = "String")]
pub struct FilePath(String);

impl FilePath {
    /// A path to something that may exist.
    pub fn parse(raw: &str, field: &'static str) -> Result<Self> {
        if raw.is_empty() || raw == "." {
            return Ok(Self::home());
        }
        if raw.len() > FILE_PATH_MAX {
            return Err(Error::invalid(
                field,
                format!("must be at most {FILE_PATH_MAX} bytes"),
            ));
        }
        if raw.starts_with('/') {
            return Err(Error::invalid(field, "must be relative to the home"));
        }
        let mut depth = 0;
        for comp in raw.split('/') {
            depth += 1;
            if comp.is_empty() {
                return Err(Error::invalid(
                    field,
                    "empty path component (double or trailing '/')",
                ));
            }
            if comp == "." || comp == ".." {
                return Err(Error::invalid(
                    field,
                    "'.' and '..' components are not allowed",
                ));
            }
            if comp.len() > FILE_NAME_MAX {
                return Err(Error::invalid(
                    field,
                    format!("a name may be at most {FILE_NAME_MAX} bytes"),
                ));
            }
            if comp.contains('\0') {
                return Err(Error::invalid(field, "contains a NUL character"));
            }
        }
        if depth > FILE_PATH_DEPTH_MAX {
            return Err(Error::invalid(
                field,
                format!("may have at most {FILE_PATH_DEPTH_MAX} components"),
            ));
        }
        Ok(Self(raw.to_owned()))
    }

    /// A path whose last name the engine is going to create: as
    /// [`Self::parse`], and the last component must pass [`check_new_name`].
    /// The home itself is never new.
    pub fn parse_new(raw: &str, field: &'static str) -> Result<Self> {
        let path = Self::parse(raw, field)?;
        match path.file_name() {
            Some(name) => check_new_name(name, field).map(|()| path),
            None => Err(Error::invalid(field, "must name an entry inside the home")),
        }
    }

    /// The home itself.
    pub fn home() -> Self {
        Self(String::new())
    }

    pub fn is_home(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path as the caller sees it: `.` for the home.
    pub fn display(&self) -> &str {
        if self.is_home() {
            "."
        } else {
            &self.0
        }
    }

    /// The last name, `None` for the home.
    pub fn file_name(&self) -> Option<&str> {
        if self.is_home() {
            None
        } else {
            self.0.rsplit('/').next()
        }
    }

    /// The directory holding this entry (the home for a top-level name and
    /// for the home itself).
    #[must_use]
    pub fn parent(&self) -> Self {
        match self.0.rsplit_once('/') {
            Some((parent, _)) => Self(parent.to_owned()),
            None => Self::home(),
        }
    }

    /// `self/name`, validated like any other path.
    pub fn join(&self, name: &str, field: &'static str) -> Result<Self> {
        if self.is_home() {
            Self::parse(name, field)
        } else {
            Self::parse(&format!("{}/{name}", self.0), field)
        }
    }

    /// The names, outermost first (none for the home).
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|c| !c.is_empty())
    }

    /// Whether `other` is this path or below it, by name.
    pub fn contains(&self, other: &Self) -> bool {
        self.is_home() || other.0 == self.0 || other.0.starts_with(&format!("{}/", self.0))
    }
}

impl TryFrom<String> for FilePath {
    type Error = Error;
    fn try_from(raw: String) -> Result<Self> {
        Self::parse(&raw, "path")
    }
}

impl From<FilePath> for String {
    fn from(p: FilePath) -> Self {
        p.0
    }
}

impl fmt::Display for FilePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display())
    }
}

/// Characters a name the engine creates may not contain although they are
/// printable in the narrow sense: invisible format and direction controls
/// (a name like `invoice\u{202e}fdp.exe` displays as something it is not)
/// and Unicode's other separators.
fn is_hidden_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
        | '\u{180B}'..='\u{180F}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}'
        | '\u{2060}'..='\u{206F}' | '\u{3164}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}'
        | '\u{FFA0}' | '\u{FFF0}'..='\u{FFFF}' | '\u{E0000}'..='\u{E0FFF}')
}

/// A name the engine is about to create (upload, new folder, rename target,
/// archive member): 1 to [`FILE_NAME_MAX`] bytes of visible characters —
/// letters, digits, punctuation and symbols of any script — and the ASCII
/// space, but not at either end; not `.` or `..`. Refused: `/`, NUL, every
/// control character (newline, tab, escape, DEL, C1), other whitespace and
/// invisible formatting characters. A leading `-` is allowed: names never
/// reach an argument list (the worker gets them inside JSON on standard
/// input and uses them only with `*at` system calls).
pub fn check_new_name(name: &str, field: &'static str) -> Result<()> {
    if name.is_empty() || name.len() > FILE_NAME_MAX {
        return Err(Error::invalid(
            field,
            format!("a name must be 1 to {FILE_NAME_MAX} bytes long"),
        ));
    }
    if name == "." || name == ".." {
        return Err(Error::invalid(field, "'.' and '..' are not names"));
    }
    if name.starts_with(' ') || name.ends_with(' ') {
        return Err(Error::invalid(
            field,
            "a name may not begin or end with a space",
        ));
    }
    let visible = |c: char| {
        c == ' ' || !(c.is_control() || c.is_whitespace() || is_hidden_char(c) || c == '/')
    };
    if !name.chars().all(visible) {
        return Err(Error::invalid(
            field,
            "a new name may contain visible characters and spaces only (no '/', control, invisible or formatting characters)",
        ));
    }
    Ok(())
}

/// Permission bits the file manager sets: `0` to `0775` — read, write and
/// execute for the owner and the tenant's private group, read and execute
/// for others. Never set-uid, set-gid or sticky, never world-writable. On a
/// file or directory with an access-control list (a document root and what
/// is created inside it) the group bits are the ACL *mask*, which can only
/// narrow what the engine's `u:nginx:r-x` entry grants, never widen it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileMode(u32);

/// The bits [`FileMode`] may contain.
pub const FILE_MODE_ALLOWED: u32 = 0o775;

impl FileMode {
    pub fn parse(raw: u32, field: &'static str) -> Result<Self> {
        if raw & !0o7777 != 0 {
            return Err(Error::invalid(
                field,
                "must be a permission mode (0 to 0775)",
            ));
        }
        if raw & 0o7000 != 0 {
            return Err(Error::invalid(
                field,
                "set-uid, set-gid and sticky bits are not offered",
            ));
        }
        if raw & 0o002 != 0 {
            return Err(Error::invalid(
                field,
                "world-writable modes are not offered",
            ));
        }
        Ok(Self(raw))
    }

    pub fn bits(self) -> u32 {
        self.0
    }
}

/// A file-manager job identifier: `^f[0-9]{10,20}$`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileJobId(String);

impl FileJobId {
    pub fn parse(raw: &str) -> Result<Self> {
        parse_id(raw, 'f', "job_id").map(Self)
    }

    pub fn from_millis(unix_millis: u128) -> Self {
        Self(format!("f{unix_millis:013}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FileJobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An upload identifier: `^u[0-9]{10,20}$`. It also names the partial file
/// (`.oxpanel-upload-<id>`) next to the upload's target.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UploadId(String);

impl UploadId {
    pub fn parse(raw: &str) -> Result<Self> {
        parse_id(raw, 'u', "upload_id").map(Self)
    }

    pub fn from_millis(unix_millis: u128) -> Self {
        Self(format!("u{unix_millis:013}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The partial file's name.
    pub fn partial_name(&self) -> String {
        format!(".oxpanel-upload-{}", self.0)
    }
}

impl fmt::Display for UploadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod file_tests {
    use super::*;

    #[test]
    fn file_paths_are_relative_plain_and_bounded() -> Result<()> {
        assert!(FilePath::parse("", "path")?.is_home());
        assert!(FilePath::parse(".", "path")?.is_home());
        for ok in [
            "public_html",
            "public_html/index.php",
            "-rf",
            "a b/c d.txt",
            "dir/--help",
            "Ünïcödé/日本語.txt",
            "line\nbreak",
            "tab\there",
            ".hidden/.x",
            "...",
        ] {
            assert_eq!(FilePath::parse(ok, "path")?.as_str(), ok);
        }
        let deep = vec!["d"; FILE_PATH_DEPTH_MAX].join("/");
        assert!(FilePath::parse(&deep, "path").is_ok());
        let long_name = "n".repeat(FILE_NAME_MAX);
        assert!(FilePath::parse(&long_name, "path").is_ok());
        for bad in [
            "/etc/passwd".to_owned(),
            "/".to_owned(),
            "../alice".to_owned(),
            "a/../../etc".to_owned(),
            "a/./b".to_owned(),
            "./a".to_owned(),
            "a/".to_owned(),
            "a//b".to_owned(),
            "a/..".to_owned(),
            "..".to_owned(),
            "nul\0byte".to_owned(),
            format!("{deep}/d"),
            "n".repeat(FILE_NAME_MAX + 1),
            "x/".repeat(FILE_PATH_MAX),
        ] {
            assert!(is_invalid(FilePath::parse(&bad, "path")), "{bad:?}");
        }
        Ok(())
    }

    #[test]
    fn file_path_helpers() -> Result<()> {
        let p = FilePath::parse("a/b/c.txt", "path")?;
        assert_eq!(p.file_name(), Some("c.txt"));
        assert_eq!(p.parent().as_str(), "a/b");
        assert_eq!(p.parent().parent().parent(), FilePath::home());
        assert_eq!(FilePath::home().join("x", "path")?.as_str(), "x");
        assert_eq!(p.parent().join("d", "path")?.as_str(), "a/b/d");
        assert!(FilePath::home().join("..", "path").is_err());
        assert_eq!(p.components().collect::<Vec<_>>(), ["a", "b", "c.txt"]);
        assert!(FilePath::parse("a", "p")?.contains(&p));
        assert!(!FilePath::parse("a/b/c", "p")?.contains(&p));
        assert!(FilePath::home().contains(&p));
        assert_eq!(FilePath::home().display(), ".");
        let json = serde_json::to_string(&p).map_err(|e| Error::Internal(e.to_string()))?;
        assert_eq!(json, "\"a/b/c.txt\"");
        assert!(serde_json::from_str::<FilePath>("\"../x\"").is_err());
        Ok(())
    }

    #[test]
    fn new_names_are_visible_text() {
        let too_long = "n".repeat(FILE_NAME_MAX + 1);
        for ok in [
            "index.php",
            "-rf",
            "--help",
            "my file (1).txt",
            "日本語",
            "émoji 🎉.png",
            ".htaccess",
            "...",
        ] {
            assert!(check_new_name(ok, "name").is_ok(), "{ok:?}");
        }
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a\nb",
            "a\rb",
            "a\tb",
            "esc\u{1b}[31m",
            "del\u{7f}",
            "c1\u{85}",
            "nul\0",
            " lead",
            "trail ",
            "nb\u{a0}sp",
            "rtl\u{202e}fdp.exe",
            "zero\u{200b}width",
            "bom\u{feff}",
            too_long.as_str(),
        ] {
            assert!(is_invalid(check_new_name(bad, "name")), "{bad:?}");
        }
        assert!(FilePath::parse_new("dir/a\nb", "path").is_err());
        assert!(
            FilePath::parse_new("di\nr/ab", "path").is_ok(),
            "only the new name is checked"
        );
        assert!(FilePath::parse_new("", "path").is_err());
    }

    #[test]
    fn file_modes_are_the_safe_subset() {
        for ok in [0, 0o600, 0o644, 0o640, 0o700, 0o755, 0o750, 0o664, 0o775] {
            assert_eq!(
                FileMode::parse(ok, "mode").map(FileMode::bits).ok(),
                Some(ok)
            );
        }
        for bad in [
            0o4755,
            0o2755,
            0o1777,
            0o777,
            0o666,
            0o646,
            0o10_000,
            u32::MAX,
        ] {
            assert!(is_invalid(FileMode::parse(bad, "mode")), "{bad:o}");
        }
    }

    #[test]
    fn file_job_and_upload_ids_are_allow_listed() {
        assert!(FileJobId::parse(FileJobId::from_millis(1_731_500_000_123).as_str()).is_ok());
        let u = UploadId::from_millis(1_731_500_000_123);
        assert!(UploadId::parse(u.as_str()).is_ok());
        assert_eq!(u.partial_name(), ".oxpanel-upload-u1731500000123");
        for bad in ["", "j1731500000123", "u1731500000123/..", "u17315000001x3"] {
            assert!(
                FileJobId::parse(bad).is_err() && UploadId::parse(bad).is_err(),
                "{bad:?}"
            );
        }
    }

    fn is_invalid<T: std::fmt::Debug>(r: Result<T>) -> bool {
        matches!(r, Err(Error::InvalidInput { .. }))
    }
}
