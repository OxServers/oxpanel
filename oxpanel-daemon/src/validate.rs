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
        })
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
                tasks_max: Some(50)
            })
        );
        assert!(is_invalid(Limits::parse(MIN_MEMORY_MAX_BYTES - 1, 0, 0, 0)));
        assert!(is_invalid(Limits::parse(0, MAX_WEIGHT + 1, 0, 0)));
        assert!(is_invalid(Limits::parse(0, 0, MAX_WEIGHT + 1, 0)));
    }
}
