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

#[cfg(test)]
mod tests {
    use super::*;

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
