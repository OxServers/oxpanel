//! Daemon configuration, read from `OXPANEL_*` environment variables.
//!
//! The systemd unit ships an `EnvironmentFile=/etc/oxpanel/daemon.env`; every
//! value has a production default so an empty file is a valid configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::auth::Scope;
use crate::error::{Error, Result};

/// Everything the daemon needs to know about its environment.
#[derive(Debug, Clone)]
pub struct Config {
    /// UNIX socket the gRPC server listens on.
    pub socket_path: PathBuf,
    /// Group that owns the socket (mode 0660). `None` = leave as created (0600, root only).
    pub socket_group: Option<String>,
    /// Peer UIDs allowed to call the API.
    pub allowed_uids: BTreeSet<u32>,
    /// Peer GIDs (effective or supplementary) allowed to call the API.
    /// The socket group is always included when set.
    pub allowed_gids: BTreeSet<u32>,
    /// Whether UID 0 may call the API regardless of the lists above.
    pub allow_root_peer: bool,
    /// Peers confined to a subset of the API: uid -> scopes. A uid that is
    /// not listed may call everything (see [`crate::auth::ScopePolicy`]).
    pub peer_scopes: BTreeMap<u32, BTreeSet<Scope>>,
    /// Inclusive UID range tenants are allocated from. A dedicated primary
    /// group with the same numeric id is created for each tenant.
    pub uid_min: u32,
    pub uid_max: u32,
    /// Parent directory of tenant homes.
    pub home_base: PathBuf,
    /// Daemon state: tenant and vhost records.
    pub state_dir: PathBuf,
    /// Directory holding one `<domain>.conf` per virtual host.
    pub nginx_conf_dir: PathBuf,
    /// File in `conf.d` that includes `nginx_conf_dir/*.conf`.
    pub nginx_include_file: PathBuf,
    /// Where tenant slice units and drop-ins are written.
    pub systemd_unit_dir: PathBuf,
    /// Per-virtual-host access and error logs.
    pub nginx_log_dir: PathBuf,
    /// One PHP-FPM pool configuration per tenant that uses PHP. World-readable
    /// (no secrets): each pool's master runs as its tenant and must read it.
    pub php_conf_dir: PathBuf,
    /// Account the web server workers run as; it is granted traverse/read
    /// access to document roots through POSIX ACLs.
    pub web_user: String,
    /// Install a catch-all `default_server` that closes connections for
    /// unknown host names, so no tenant ever becomes the default site.
    pub nginx_default_server: bool,
    /// Upper bound for any single external command.
    pub command_timeout: Duration,
    /// Use the in-memory [`crate::system::FakeSystem`] instead of the real OS.
    /// For developing clients without root; never set in production.
    pub dry_run: bool,
    /// `tracing` filter directive, e.g. `info` or `oxpanel_daemon=debug`.
    pub log_filter: String,
    /// Certificates (`<domain>.crt`) and private keys (`<domain>.key`) of
    /// virtual hosts. Root-only.
    pub tls_dir: PathBuf,
    /// Working directories shared with the ACME client (see [`crate::acme`]).
    pub acme_dir: PathBuf,
    /// ACME directory certificates are requested from.
    pub acme_directory_url: String,
    /// PEM bundle the ACME client trusts instead of the system's, for a
    /// private or test certificate authority.
    pub acme_ca_file: Option<PathBuf>,
    /// Contact address registered with the ACME account.
    pub acme_email: Option<String>,
    /// ACME certificates are renewed once they expire within this time.
    pub acme_renew_before: Duration,
    /// Root-only file with the External Account Binding (`kid=`, `hmac_key=`)
    /// some certificate authorities require. Handed to the ACME client as a
    /// systemd credential, never as an argument.
    pub acme_eab_file: Option<PathBuf>,
    /// Automatic HTTPS: obtain certificates for sites without being asked.
    pub auto_https: crate::records::AutoHttpsChoice,
}

/// Let's Encrypt's production directory.
pub const DEFAULT_ACME_DIRECTORY_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";

impl Default for Config {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/oxpanel/oxpanel.sock"),
            socket_group: Some("oxpanel".to_owned()),
            allowed_uids: BTreeSet::new(),
            allowed_gids: BTreeSet::new(),
            allow_root_peer: true,
            peer_scopes: BTreeMap::new(),
            uid_min: 20_000,
            uid_max: 29_999,
            home_base: PathBuf::from("/home"),
            state_dir: PathBuf::from("/var/lib/oxpanel"),
            nginx_conf_dir: PathBuf::from("/etc/nginx/oxpanel.d"),
            nginx_include_file: PathBuf::from("/etc/nginx/conf.d/00-oxpanel.conf"),
            systemd_unit_dir: PathBuf::from("/etc/systemd/system"),
            nginx_log_dir: PathBuf::from("/var/log/nginx/oxpanel"),
            php_conf_dir: PathBuf::from("/etc/oxpanel-php"),
            web_user: "nginx".to_owned(),
            nginx_default_server: true,
            command_timeout: Duration::from_secs(60),
            dry_run: false,
            log_filter: "info".to_owned(),
            tls_dir: PathBuf::from("/etc/pki/oxpanel"),
            acme_dir: PathBuf::from("/var/lib/oxpanel-acme"),
            acme_directory_url: DEFAULT_ACME_DIRECTORY_URL.to_owned(),
            acme_ca_file: None,
            acme_email: None,
            acme_renew_before: Duration::from_secs(30 * 86_400),
            acme_eab_file: None,
            // A new site gets HTTPS by itself (the owner's intent).
            auto_https: crate::records::AutoHttpsChoice::On,
        }
    }
}

impl Config {
    /// Build a configuration from the process environment.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Build a configuration from an arbitrary key lookup (testable).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let mut c = Self::default();
        let path = |k: &str, cur: &mut PathBuf| -> Result<()> {
            if let Some(v) = get(k) {
                let p = PathBuf::from(v.trim());
                if !p.is_absolute() {
                    return Err(Error::invalid(
                        "config",
                        format!("{k} must be an absolute path"),
                    ));
                }
                *cur = p;
            }
            Ok(())
        };
        path("OXPANEL_SOCKET_PATH", &mut c.socket_path)?;
        path("OXPANEL_HOME_BASE", &mut c.home_base)?;
        path("OXPANEL_STATE_DIR", &mut c.state_dir)?;
        path("OXPANEL_NGINX_CONF_DIR", &mut c.nginx_conf_dir)?;
        path("OXPANEL_NGINX_INCLUDE_FILE", &mut c.nginx_include_file)?;
        path("OXPANEL_SYSTEMD_UNIT_DIR", &mut c.systemd_unit_dir)?;
        path("OXPANEL_NGINX_LOG_DIR", &mut c.nginx_log_dir)?;
        path("OXPANEL_PHP_CONF_DIR", &mut c.php_conf_dir)?;

        if let Some(g) = get("OXPANEL_SOCKET_GROUP") {
            let g = g.trim();
            c.socket_group = if g.is_empty() {
                None
            } else {
                Some(g.to_owned())
            };
        }
        if let Some(v) = get("OXPANEL_ALLOWED_UIDS") {
            c.allowed_uids = parse_id_list("OXPANEL_ALLOWED_UIDS", &v)?;
        }
        if let Some(v) = get("OXPANEL_ALLOWED_GIDS") {
            c.allowed_gids = parse_id_list("OXPANEL_ALLOWED_GIDS", &v)?;
        }
        if let Some(v) = get("OXPANEL_ALLOW_ROOT_PEER") {
            c.allow_root_peer = parse_bool("OXPANEL_ALLOW_ROOT_PEER", &v)?;
        }
        if let Some(v) = get("OXPANEL_PEER_SCOPES") {
            c.peer_scopes = parse_peer_scopes(&v)?;
        }
        if let Some(v) = get("OXPANEL_UID_MIN") {
            c.uid_min = parse_u32("OXPANEL_UID_MIN", &v)?;
        }
        if let Some(v) = get("OXPANEL_UID_MAX") {
            c.uid_max = parse_u32("OXPANEL_UID_MAX", &v)?;
        }
        if let Some(v) = get("OXPANEL_WEB_USER") {
            let v = v.trim();
            if v.is_empty()
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return Err(Error::invalid(
                    "config",
                    "OXPANEL_WEB_USER must be a plain account name",
                ));
            }
            v.clone_into(&mut c.web_user);
        }
        if let Some(v) = get("OXPANEL_NGINX_DEFAULT_SERVER") {
            c.nginx_default_server = parse_bool("OXPANEL_NGINX_DEFAULT_SERVER", &v)?;
        }
        if let Some(v) = get("OXPANEL_COMMAND_TIMEOUT_SECS") {
            let secs = parse_u32("OXPANEL_COMMAND_TIMEOUT_SECS", &v)?;
            if secs == 0 {
                return Err(Error::invalid(
                    "config",
                    "OXPANEL_COMMAND_TIMEOUT_SECS must be > 0",
                ));
            }
            c.command_timeout = Duration::from_secs(u64::from(secs));
        }
        if let Some(v) = get("OXPANEL_DRY_RUN") {
            c.dry_run = parse_bool("OXPANEL_DRY_RUN", &v)?;
        }
        if let Some(v) = get("OXPANEL_LOG") {
            c.log_filter = v;
        }
        path("OXPANEL_TLS_DIR", &mut c.tls_dir)?;
        path("OXPANEL_ACME_DIR", &mut c.acme_dir)?;
        c.acme_from_lookup(&get)?;
        c.validate()?;
        Ok(c)
    }

    /// The `OXPANEL_ACME_*` settings.
    fn acme_from_lookup(&mut self, get: &impl Fn(&str) -> Option<String>) -> Result<()> {
        if let Some(v) = get("OXPANEL_ACME_DIRECTORY_URL") {
            v.trim().clone_into(&mut self.acme_directory_url);
        }
        if let Some(v) = get("OXPANEL_ACME_CA_FILE") {
            let v = v.trim();
            self.acme_ca_file = (!v.is_empty()).then(|| PathBuf::from(v));
        }
        if let Some(v) = get("OXPANEL_ACME_EMAIL") {
            let v = v.trim();
            self.acme_email = (!v.is_empty()).then(|| v.to_owned());
        }
        if let Some(v) = get("OXPANEL_ACME_EAB_FILE") {
            let v = v.trim();
            self.acme_eab_file = (!v.is_empty()).then(|| PathBuf::from(v));
        }
        if let Some(v) = get("OXPANEL_AUTO_HTTPS") {
            self.auto_https = crate::records::AutoHttpsChoice::from_opt_out(!parse_bool(
                "OXPANEL_AUTO_HTTPS",
                &v,
            )?);
        }
        if let Some(v) = get("OXPANEL_ACME_RENEW_DAYS") {
            let days = parse_u32("OXPANEL_ACME_RENEW_DAYS", &v)?;
            if !(1..=60).contains(&days) {
                return Err(Error::invalid(
                    "config",
                    "OXPANEL_ACME_RENEW_DAYS must be 1..=60",
                ));
            }
            self.acme_renew_before = Duration::from_secs(u64::from(days) * 86_400);
        }
        Ok(())
    }

    /// The ACME settings end up in the argument vector of the ACME client
    /// (through `systemd-run`, which expands `$` and `%`), so they get an
    /// allow-list too.
    fn validate_acme(&self) -> Result<()> {
        let url = &self.acme_directory_url;
        let rest = url.strip_prefix("https://").unwrap_or_default();
        if rest.is_empty()
            || url.len() > 255
            || !rest.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~' | b':' | b'/')
            })
        {
            return Err(Error::invalid(
                "config",
                "OXPANEL_ACME_DIRECTORY_URL must be an https:// URL made of A-Z, a-z, 0-9 and . - _ ~ : /",
            ));
        }
        if let Some(p) = &self.acme_ca_file {
            check_path("OXPANEL_ACME_CA_FILE", p)?;
        }
        if let Some(p) = &self.acme_eab_file {
            check_path("OXPANEL_ACME_EAB_FILE", p)?;
        }
        if let Some(email) = &self.acme_email {
            let ok = email.len() <= 254
                && email.split_once('@').is_some_and(|(local, host)| {
                    !local.is_empty()
                        && local.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-')
                        })
                        && crate::validate::Domain::parse(host).is_ok()
                });
            if !ok {
                return Err(Error::invalid(
                    "config",
                    "OXPANEL_ACME_EMAIL must be a plain address such as hostmaster@example.com",
                ));
            }
        }
        if self.tls_dir == self.acme_dir
            || self.tls_dir.starts_with(&self.acme_dir)
            || self.acme_dir.starts_with(&self.tls_dir)
        {
            return Err(Error::invalid(
                "config",
                "OXPANEL_TLS_DIR and OXPANEL_ACME_DIR must be separate directories",
            ));
        }
        Ok(())
    }

    /// Cross-field checks.
    pub fn validate(&self) -> Result<()> {
        for (key, p) in [
            ("OXPANEL_SOCKET_PATH", &self.socket_path),
            ("OXPANEL_HOME_BASE", &self.home_base),
            ("OXPANEL_STATE_DIR", &self.state_dir),
            ("OXPANEL_NGINX_CONF_DIR", &self.nginx_conf_dir),
            ("OXPANEL_NGINX_INCLUDE_FILE", &self.nginx_include_file),
            ("OXPANEL_SYSTEMD_UNIT_DIR", &self.systemd_unit_dir),
            ("OXPANEL_NGINX_LOG_DIR", &self.nginx_log_dir),
            ("OXPANEL_PHP_CONF_DIR", &self.php_conf_dir),
            ("OXPANEL_TLS_DIR", &self.tls_dir),
            ("OXPANEL_ACME_DIR", &self.acme_dir),
        ] {
            check_path(key, p)?;
        }
        self.validate_acme()?;
        if self.uid_min < 1000 {
            return Err(Error::invalid(
                "config",
                "OXPANEL_UID_MIN must be >= 1000 (system accounts are below)",
            ));
        }
        if self.uid_max < self.uid_min {
            return Err(Error::invalid(
                "config",
                "OXPANEL_UID_MAX must be >= OXPANEL_UID_MIN",
            ));
        }
        if self.uid_max == u32::MAX {
            return Err(Error::invalid(
                "config",
                "OXPANEL_UID_MAX must be < 4294967295",
            ));
        }
        if self.nginx_conf_dir
            == self
                .nginx_include_file
                .parent()
                .unwrap_or(&self.nginx_conf_dir)
        {
            return Err(Error::invalid(
                "config",
                "OXPANEL_NGINX_INCLUDE_FILE must not live inside OXPANEL_NGINX_CONF_DIR",
            ));
        }
        Ok(())
    }

    /// `state_dir/tenants`.
    pub fn tenants_dir(&self) -> PathBuf {
        self.state_dir.join("tenants")
    }

    /// `state_dir/vhosts`.
    pub fn vhosts_dir(&self) -> PathBuf {
        self.state_dir.join("vhosts")
    }
}

/// Configured paths end up inside Nginx directives and `semanage` regular
/// expressions, so they get the same character allow-list as tenant input.
fn check_path(key: &str, p: &Path) -> Result<()> {
    let Some(s) = p.to_str() else {
        return Err(Error::invalid(
            "config",
            format!("{key} must be valid UTF-8"),
        ));
    };
    if !p.is_absolute() || s == "/" {
        return Err(Error::invalid(
            "config",
            format!("{key} must be an absolute path below /"),
        ));
    }
    if p.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) {
        return Err(Error::invalid(
            "config",
            format!("{key} must not contain '.' or '..' components"),
        ));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(Error::invalid(
            "config",
            format!("{key} may only contain A-Z, a-z, 0-9, '/', '.', '_' and '-'"),
        ));
    }
    Ok(())
}

fn parse_id_list(key: &str, raw: &str) -> Result<BTreeSet<u32>> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<u32>()
                .map_err(|_| Error::invalid("config", format!("{key}: '{s}' is not a numeric id")))
        })
        .collect()
}

/// `uid:scope+scope,uid:scope` — e.g. `1001:read+vhost,1002:all`.
fn parse_peer_scopes(raw: &str) -> Result<BTreeMap<u32, BTreeSet<Scope>>> {
    const KEY: &str = "OXPANEL_PEER_SCOPES";
    let bad = |why: String| Error::invalid("config", format!("{KEY}: {why}"));
    let mut out = BTreeMap::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (uid, scopes) = entry
            .split_once(':')
            .ok_or_else(|| bad(format!("'{entry}' is not uid:scope+scope")))?;
        let uid = uid
            .trim()
            .parse::<u32>()
            .map_err(|_| bad(format!("'{uid}' is not a numeric uid")))?;
        let mut set = BTreeSet::new();
        for s in scopes.split('+').map(str::trim) {
            if s == "all" {
                set.extend(Scope::ALL);
            } else {
                set.insert(Scope::parse(s).ok_or_else(|| {
                    bad(format!(
                        "'{s}' is not a scope (read, vhost, tenant, delete, all)"
                    ))
                })?);
            }
        }
        if out.insert(uid, set).is_some() {
            return Err(bad(format!("uid {uid} is listed twice")));
        }
    }
    Ok(out)
}

fn parse_u32(key: &str, raw: &str) -> Result<u32> {
    raw.trim().parse::<u32>().map_err(|_| {
        Error::invalid(
            "config",
            format!("{key}: '{raw}' is not an unsigned integer"),
        )
    })
}

fn parse_bool(key: &str, raw: &str) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(Error::invalid(
            "config",
            format!("{key}: '{raw}' is not a boolean"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn from(pairs: &[(&str, &str)]) -> Result<Config> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Config::from_lookup(|k| m.get(k).cloned())
    }

    #[test]
    fn defaults_are_valid() {
        let c = from(&[]).ok();
        assert!(c.is_some());
    }

    #[test]
    fn parses_lists_and_flags() {
        let c = from(&[
            ("OXPANEL_ALLOWED_UIDS", "1001, 1002"),
            ("OXPANEL_ALLOWED_GIDS", "990"),
            ("OXPANEL_ALLOW_ROOT_PEER", "no"),
            ("OXPANEL_SOCKET_GROUP", ""),
            ("OXPANEL_DRY_RUN", "true"),
        ]);
        let c = match c {
            Ok(c) => c,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(c.allowed_uids, [1001, 1002].into_iter().collect());
        assert_eq!(c.allowed_gids, [990].into_iter().collect());
        assert!(!c.allow_root_peer);
        assert_eq!(c.socket_group, None);
        assert!(c.dry_run);
    }

    #[test]
    fn parses_peer_scopes() {
        let c = from(&[("OXPANEL_PEER_SCOPES", "1001:read+vhost, 1002:all,")])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            c.peer_scopes.get(&1001),
            Some(&[Scope::Read, Scope::VHost].into_iter().collect())
        );
        assert_eq!(c.peer_scopes.get(&1002).map(BTreeSet::len), Some(4));
        assert!(from(&[]).is_ok_and(|c| c.peer_scopes.is_empty()));
        for bad in [
            "1001",
            "abc:read",
            "1001:admin",
            "1001:",
            "1001:read,1001:vhost",
        ] {
            assert!(from(&[("OXPANEL_PEER_SCOPES", bad)]).is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_bad_values() {
        assert!(from(&[("OXPANEL_SOCKET_PATH", "relative/sock")]).is_err());
        assert!(from(&[("OXPANEL_ALLOWED_UIDS", "1001,abc")]).is_err());
        assert!(from(&[("OXPANEL_UID_MIN", "500")]).is_err());
        assert!(from(&[("OXPANEL_UID_MIN", "30000"), ("OXPANEL_UID_MAX", "20000")]).is_err());
        assert!(from(&[("OXPANEL_COMMAND_TIMEOUT_SECS", "0")]).is_err());
        assert!(from(&[("OXPANEL_HOME_BASE", "/srv/ho me")]).is_err());
        assert!(from(&[("OXPANEL_HOME_BASE", "/srv/../home")]).is_err());
        assert!(from(&[("OXPANEL_HOME_BASE", "/")]).is_err());
        assert!(from(&[("OXPANEL_NGINX_CONF_DIR", "/etc/nginx/ox;panel.d")]).is_err());
        assert!(from(&[("OXPANEL_HOME_BASE", "/srv/web-homes_v2")]).is_ok());
        assert!(from(&[("OXPANEL_WEB_USER", "nginx;rm")]).is_err());
        for bad in [
            "http://ca.example/directory",
            "https://",
            "https://ca.example/dir?x=$HOME",
            "https://ca.example/%n",
            "https://ca.example/a b",
        ] {
            assert!(
                from(&[("OXPANEL_ACME_DIRECTORY_URL", bad)]).is_err(),
                "{bad}"
            );
        }
        assert!(
            from(&[("OXPANEL_ACME_DIRECTORY_URL", "https://localhost:14000/dir")])
                .is_ok_and(|c| c.acme_directory_url == "https://localhost:14000/dir")
        );
        assert!(from(&[("OXPANEL_ACME_EMAIL", "ops+tls@example.com")]).is_ok());
        assert!(from(&[("OXPANEL_ACME_EMAIL", "ops@example.com --evil")]).is_err());
        assert!(from(&[("OXPANEL_ACME_CA_FILE", "/etc/pki/my ca.pem")]).is_err());
        assert!(from(&[("OXPANEL_ACME_RENEW_DAYS", "0")]).is_err());
        assert!(from(&[]).is_ok_and(|c| c.auto_https.is_on() && c.acme_eab_file.is_none()));
        assert!(from(&[("OXPANEL_AUTO_HTTPS", "false")]).is_ok_and(|c| !c.auto_https.is_on()));
        assert!(from(&[("OXPANEL_AUTO_HTTPS", "sometimes")]).is_err());
        assert!(from(&[("OXPANEL_ACME_EAB_FILE", "/etc/oxpanel/acme-eab")])
            .is_ok_and(|c| c.acme_eab_file.as_deref() == Some(Path::new("/etc/oxpanel/acme-eab"))));
        assert!(from(&[("OXPANEL_ACME_EAB_FILE", "/etc/oxpanel/acme eab")]).is_err());
        assert!(from(&[("OXPANEL_TLS_DIR", "/var/lib/oxpanel-acme/keys")]).is_err());
        assert!(from(&[
            ("OXPANEL_NGINX_CONF_DIR", "/etc/nginx/conf.d"),
            ("OXPANEL_NGINX_INCLUDE_FILE", "/etc/nginx/conf.d/x.conf")
        ])
        .is_err());
    }
}
