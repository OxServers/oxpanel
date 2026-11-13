//! OxPanel's own BIND instance: its configuration, keys and commands.
//!
//! The DNS server is BIND 9 from AlmaLinux's AppStream, run as its own
//! service, `oxpanel-dns.service` (shipped in `packaging/systemd`), with a
//! configuration OxPanel owns completely: `/etc/named/oxpanel/` (labelled
//! like the rest of `/etc/named`) and `/var/lib/oxpanel-dns/` (zone files,
//! signing keys, the server's working directory). The distribution's
//! `/etc/named.conf` and `named.service` are never touched: the stock
//! configuration listens on the loopback only and is a resolver for the
//! host, and turning it into a public authoritative server would mean
//! rewriting its `options` block, which no include can do.
//!
//! What the configuration enforces (see [`render_named_conf`]):
//! authoritative only (no recursion and no cache, for anybody), queries
//! answered for every zone it holds, zone transfers only to holders of the
//! transfer key, no dynamic updates, NOTIFY only to the configured
//! secondaries, version, host name and server id hidden, response-rate
//! limiting (except for the host itself), a control channel on the loopback
//! that only the root-only rndc key opens.
//!
//! Every change is validated by the server's own checker before the server
//! sees it: a zone file with `named-checkzone` (on a staging copy, so the
//! live file is never replaced by a rejected one), the configuration with
//! `named-checkconf` (the previous files are restored if it is rejected).
//! A changed zone is reloaded alone (`rndc reload <zone>`); a changed set of
//! zones is a `reconfig`, which loads new zones and drops removed ones
//! without reloading the others.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine as _;

use super::config::DnsConfig;
use super::zone::CATALOG_ZONE;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::nginx::safe_path_str;
use crate::system::{bin, CommandSpec};
use crate::validate::Domain;

pub const SERVICE: &str = "oxpanel-dns.service";
/// The stock service of the bind package; it must not run beside ours.
pub const STOCK_SERVICE: &str = "named.service";
pub const RNDC_KEY: &str = "oxpanel-rndc";
pub const TRANSFER_KEY: &str = "oxpanel-transfer";
pub const POLICY: &str = "oxpanel";
/// The server's account (from the bind package).
pub const SERVER_GROUP: &str = "named";
const RNDC_PORT: u16 = 953;
const HEADER: &str = "// Managed by oxpanel-daemon. Manual edits will be overwritten.";
/// Configuration files are read by the server through its group.
pub const CONF_MODE: u32 = 0o640;
pub const ZONE_MODE: u32 = 0o644;
/// rndc talks to the server outside the daemon's network-less sandbox.
const RNDC_TIMEOUT: Duration = Duration::from_secs(30);
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Where everything lives.
#[derive(Debug, Clone)]
pub struct Layout {
    pub conf_dir: PathBuf,
    pub data_dir: PathBuf,
}

impl Layout {
    pub fn new(cfg: &DnsConfig) -> Self {
        Self {
            conf_dir: cfg.conf_dir.clone(),
            data_dir: cfg.data_dir.clone(),
        }
    }

    pub fn named_conf(&self) -> PathBuf {
        self.conf_dir.join("named.conf")
    }
    pub fn zones_conf(&self) -> PathBuf {
        self.conf_dir.join("zones.conf")
    }
    pub fn rndc_key(&self) -> PathBuf {
        self.conf_dir.join("rndc.key")
    }
    /// The TSIG key secondaries authenticate zone transfers with. The
    /// operator copies this file to each secondary.
    pub fn transfer_key(&self) -> PathBuf {
        self.conf_dir.join("transfer.key")
    }
    pub fn rndc_conf(&self) -> PathBuf {
        self.conf_dir.join("rndc.conf")
    }
    /// Zone files; the server writes its signed copies and journals here.
    pub fn zones_dir(&self) -> PathBuf {
        self.data_dir.join("zones")
    }
    /// Zone files waiting for `named-checkzone`; root only.
    pub fn staging_dir(&self) -> PathBuf {
        self.data_dir.join("staging")
    }
    /// One directory of signing keys per signed zone, the server's own.
    pub fn keys_dir(&self) -> PathBuf {
        self.data_dir.join("keys")
    }
    /// The server's working directory.
    pub fn work_dir(&self) -> PathBuf {
        self.data_dir.join("data")
    }
    pub fn zone_file(&self, zone: &Domain) -> PathBuf {
        self.zones_dir().join(format!("{zone}.zone"))
    }
    pub fn staging_file(&self, zone: &str) -> PathBuf {
        self.staging_dir().join(format!("{zone}.zone"))
    }
    pub fn key_dir(&self, zone: &Domain) -> PathBuf {
        self.keys_dir().join(zone.as_str())
    }
    pub fn catalog_file(&self) -> PathBuf {
        self.zones_dir().join(format!("{CATALOG_ZONE}.zone"))
    }
    /// Files the server keeps next to a zone file: the signed copy, journals
    /// and their backups.
    pub fn server_artefacts(&self, zone: &Domain) -> Vec<PathBuf> {
        let base = self.zone_file(zone);
        let s = base.to_string_lossy();
        [".jnl", ".jbk", ".signed", ".signed.jnl", ".signed.jbk"]
            .iter()
            .map(|ext| PathBuf::from(format!("{s}{ext}")))
            .collect()
    }
}

/// `address` or `address port N` as BIND writes an address with a port.
fn server_addr(sa: &SocketAddr) -> String {
    if sa.port() == 53 {
        sa.ip().to_string()
    } else {
        format!("{} port {}", sa.ip(), sa.port())
    }
}

/// The server's main configuration file.
pub fn render_named_conf(cfg: &DnsConfig, l: &Layout) -> Result<String> {
    let (rndc_key, transfer_key, zones_conf, work) =
        (l.rndc_key(), l.transfer_key(), l.zones_conf(), l.work_dir());
    let rndc_key = safe_path_str(&rndc_key)?;
    let transfer_key = safe_path_str(&transfer_key)?;
    let zones_conf = safe_path_str(&zones_conf)?;
    let work = safe_path_str(&work)?;
    let notify = if cfg.secondaries.is_empty() {
        String::new()
    } else {
        let list: Vec<String> = cfg.secondaries.iter().map(server_addr).collect();
        format!("    also-notify {{ {}; }};\n", list.join("; "))
    };
    let mut servers = String::new();
    let mut seen = Vec::new();
    for sa in &cfg.secondaries {
        if !seen.contains(&sa.ip()) {
            seen.push(sa.ip());
            let _ = writeln!(
                servers,
                "server {} {{ keys {{ \"{TRANSFER_KEY}\"; }}; }};",
                sa.ip()
            );
        }
    }
    Ok(format!(
        "{HEADER}
// OxPanel's authoritative DNS server (oxpanel-dns.service). Zones: zones.conf.
include \"{rndc_key}\";
include \"{transfer_key}\";

options {{
    directory \"{work}\";
    pid-file none;
    session-keyfile none;
    listen-on port 53 {{ any; }};
    listen-on-v6 port 53 {{ any; }};
    // Authoritative only: no recursion and no cache, for anybody.
    recursion no;
    allow-recursion {{ none; }};
    allow-query-cache {{ none; }};
    allow-query {{ any; }};
    // Zone transfers only with the transfer key; never dynamic updates.
    allow-transfer {{ none; }};
    allow-update {{ none; }};
    notify explicit;
{notify}    version none;
    hostname none;
    server-id none;
    dnssec-validation no;
    minimal-responses yes;
    // Response-rate limiting against reflection attacks.
    rate-limit {{
        responses-per-second 20;
        window 5;
        exempt-clients {{ 127.0.0.1; ::1; }};
    }};
}};

// The control channel: loopback only, and only with the root-only rndc key.
controls {{
    inet 127.0.0.1 port {RNDC_PORT} allow {{ 127.0.0.1; }} keys {{ \"{RNDC_KEY}\"; }};
}};

// Secondaries: NOTIFY and transfers to them are signed with the transfer key.
{servers}
// DNSSEC: one combined signing key (ECDSA P-256), kept until the zone is
// unsigned, so the DS at the registrar never has to change; NSEC3 without
// salt or extra iterations (RFC 9276). Signatures are renewed by the server.
dnssec-policy \"{POLICY}\" {{
    keys {{ csk lifetime unlimited algorithm ecdsap256sha256; }};
    nsec3param iterations 0 optout no salt-length 0;
}};

include \"{zones_conf}\";
"
    ))
}

/// The zone statements: every zone, plus the catalog.
pub fn render_zones_conf(zones: &[(Domain, bool)], l: &Layout) -> Result<String> {
    let mut s = format!(
        "{HEADER}
// The catalog: secondaries configured with it learn every zone below by themselves.
zone \"{CATALOG_ZONE}\" {{
    type master;
    file \"{}\";
    allow-query {{ 127.0.0.1; ::1; key \"{TRANSFER_KEY}\"; }};
    allow-transfer {{ key \"{TRANSFER_KEY}\"; }};
}};
",
        safe_path_str(&l.catalog_file())?
    );
    for (zone, signed) in zones {
        let _ = write!(
            s,
            "zone \"{zone}\" {{\n    type master;\n    file \"{}\";\n    allow-transfer {{ key \"{TRANSFER_KEY}\"; }};\n",
            safe_path_str(&l.zone_file(zone))?
        );
        if *signed {
            let _ = write!(
                s,
                "    key-directory \"{}\";\n    dnssec-policy \"{POLICY}\";\n    inline-signing yes;\n",
                safe_path_str(&l.key_dir(zone))?
            );
        }
        s.push_str("};\n");
    }
    Ok(s)
}

pub fn render_rndc_conf(l: &Layout) -> Result<String> {
    Ok(format!(
        "{HEADER}
include \"{}\";
options {{
    default-key \"{RNDC_KEY}\";
    default-server 127.0.0.1;
    default-port {RNDC_PORT};
}};
",
        safe_path_str(&l.rndc_key())?
    ))
}

/// A TSIG/rndc key statement. The secret is base64 of 32 random bytes.
pub fn render_key(name: &str, secret: &str) -> String {
    format!("key \"{name}\" {{\n    algorithm hmac-sha256;\n    secret \"{secret}\";\n}};\n")
}

/// Whether a key file holds a usable key of that name (the secret itself
/// is only decoded to check its length; it is never logged or returned).
pub fn key_file_is_valid(text: &str, name: &str) -> bool {
    let named = text.contains(&format!("key \"{name}\""));
    let secret = text
        .split("secret \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok());
    named && text.contains("algorithm hmac-sha256;") && secret.is_some_and(|s| s.len() == 32)
}

/// 32 random bytes from the kernel, base64.
pub fn new_secret() -> Result<String> {
    use std::io::Read as _;
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| Error::io("read", "/dev/urandom", e))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// `named-checkconf <named.conf>`: syntax and semantics of the whole
/// configuration (zone files are checked one by one with checkzone).
pub fn checkconf(l: &Layout, timeout: Duration) -> CommandSpec {
    CommandSpec::new(bin::NAMED_CHECKCONF, timeout).arg(l.named_conf())
}

/// `named-checkzone` with the server's own strictness for primary zones:
/// host-name rules (`check-names fail`), MX and SRV records that point at a
/// CNAME refused; integrity checks only inside the zone (no lookups).
pub fn checkzone(zone: &str, file: &Path, timeout: Duration) -> CommandSpec {
    CommandSpec::new(bin::NAMED_CHECKZONE, timeout)
        .args(["-k", "fail", "-M", "fail", "-S", "fail", "-i", "local"])
        .arg(zone)
        .arg(file)
}

/// `rndc <args>` against the server, run in a transient unit: the daemon
/// has no network, and the control channel is TCP on the loopback. The
/// output goes to a root-only file (systemd opens it), never a pipe.
pub fn rndc(cfg: &Config, out: &Path, args: &[&str]) -> Result<CommandSpec> {
    let l = Layout::new(&cfg.dns);
    let mut cmd = CommandSpec::new(bin::SYSTEMD_RUN, RNDC_TIMEOUT)
        .args(["--wait", "--collect", "--quiet"])
        .arg(format!(
            "--property=StandardOutput=truncate:{}",
            safe_path_str(out)?
        ));
    for p in [
        "CapabilityBoundingSet=",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "RuntimeMaxSec=60",
    ] {
        cmd = cmd.arg(format!("--property={p}"));
    }
    Ok(cmd
        .arg("--")
        .arg(bin::RNDC)
        .arg("-c")
        .arg(l.rndc_conf())
        .args(args))
}

/// A fresh output file for a transient unit, in the root-only scratch
/// directory next to the socket.
pub fn scratch_file(cfg: &Config, what: &str) -> Result<PathBuf> {
    let dir = cfg.scratch_dir();
    fsutil::ensure_dir(&dir, 0o700)?;
    Ok(dir.join(format!(
        "{what}-{}-{}.out",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;

    fn layout() -> Layout {
        Layout::new(&DnsConfig::default())
    }

    #[test]
    fn the_server_configuration_is_authoritative_only_and_hardened() -> Result<()> {
        let mut cfg = DnsConfig::default();
        cfg.secondaries = vec![
            "198.51.100.20:53".parse().unwrap(),
            "127.0.0.1:853".parse().unwrap(),
        ];
        let c = render_named_conf(&cfg, &layout())?;
        for must in [
            "include \"/etc/named/oxpanel/rndc.key\";",
            "include \"/etc/named/oxpanel/transfer.key\";",
            "directory \"/var/lib/oxpanel-dns/data\";",
            "recursion no;",
            "allow-recursion { none; };",
            "allow-query-cache { none; };",
            "allow-transfer { none; };",
            "allow-update { none; };",
            "notify explicit;",
            "also-notify { 198.51.100.20; 127.0.0.1 port 853; };",
            "version none;",
            "hostname none;",
            "server-id none;",
            "rate-limit {",
            "inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { \"oxpanel-rndc\"; };",
            "server 198.51.100.20 { keys { \"oxpanel-transfer\"; }; };",
            "server 127.0.0.1 { keys { \"oxpanel-transfer\"; }; };",
            "keys { csk lifetime unlimited algorithm ecdsap256sha256; };",
            "nsec3param iterations 0 optout no salt-length 0;",
            "include \"/etc/named/oxpanel/zones.conf\";",
        ] {
            assert!(c.contains(must), "missing {must}\n{c}");
        }
        assert!(!c.contains("secret"), "no secret in the main file");
        let none = render_named_conf(&DnsConfig::default(), &layout())?;
        assert!(!none.contains("also-notify"));
        assert!(!none.contains("\nserver "));
        Ok(())
    }

    #[test]
    fn zone_statements_and_signing() -> Result<()> {
        let z = |s: &str| Domain::parse(s).unwrap();
        let c = render_zones_conf(
            &[(z("example.com"), false), (z("signed.example"), true)],
            &layout(),
        )?;
        assert_eq!(
            c,
            "// Managed by oxpanel-daemon. Manual edits will be overwritten.
// The catalog: secondaries configured with it learn every zone below by themselves.
zone \"catalog.oxpanel.invalid\" {
    type master;
    file \"/var/lib/oxpanel-dns/zones/catalog.oxpanel.invalid.zone\";
    allow-query { 127.0.0.1; ::1; key \"oxpanel-transfer\"; };
    allow-transfer { key \"oxpanel-transfer\"; };
};
zone \"example.com\" {
    type master;
    file \"/var/lib/oxpanel-dns/zones/example.com.zone\";
    allow-transfer { key \"oxpanel-transfer\"; };
};
zone \"signed.example\" {
    type master;
    file \"/var/lib/oxpanel-dns/zones/signed.example.zone\";
    allow-transfer { key \"oxpanel-transfer\"; };
    key-directory \"/var/lib/oxpanel-dns/keys/signed.example\";
    dnssec-policy \"oxpanel\";
    inline-signing yes;
};
"
        );
        Ok(())
    }

    #[test]
    fn keys_are_random_and_checked_without_showing_them() -> Result<()> {
        let a = new_secret()?;
        let b = new_secret()?;
        assert_ne!(a, b);
        let k = render_key(TRANSFER_KEY, &a);
        assert!(key_file_is_valid(&k, TRANSFER_KEY));
        assert!(!key_file_is_valid(&k, RNDC_KEY));
        assert!(!key_file_is_valid(
            &render_key(TRANSFER_KEY, "c2hvcnQ="),
            TRANSFER_KEY
        ));
        assert!(!key_file_is_valid("", TRANSFER_KEY));
        Ok(())
    }

    #[test]
    fn exact_argv_of_the_checkers_and_rndc() -> Result<()> {
        let t = Duration::from_secs(5);
        let argv = |c: &CommandSpec| -> Vec<String> {
            let (p, a) = c.exec_plan();
            std::iter::once(p.to_owned())
                .chain(a.iter().map(|s| s.to_string_lossy().into_owned()))
                .collect()
        };
        assert_eq!(
            argv(&checkconf(&layout(), t)),
            ["/usr/sbin/named-checkconf", "/etc/named/oxpanel/named.conf"]
        );
        assert_eq!(
            argv(&checkzone(
                "example.com",
                Path::new("/var/lib/oxpanel-dns/staging/example.com.zone"),
                t
            )),
            [
                "/usr/sbin/named-checkzone",
                "-k",
                "fail",
                "-M",
                "fail",
                "-S",
                "fail",
                "-i",
                "local",
                "example.com",
                "/var/lib/oxpanel-dns/staging/example.com.zone"
            ]
        );
        let cfg = Config::default();
        assert_eq!(
            argv(&rndc(
                &cfg,
                Path::new("/run/oxpanel/scratch/rndc-1.out"),
                &["reload", "example.com"]
            )?),
            [
                "/usr/bin/systemd-run",
                "--wait",
                "--collect",
                "--quiet",
                "--property=StandardOutput=truncate:/run/oxpanel/scratch/rndc-1.out",
                "--property=CapabilityBoundingSet=",
                "--property=ProtectSystem=strict",
                "--property=ProtectHome=yes",
                "--property=PrivateTmp=yes",
                "--property=PrivateDevices=yes",
                "--property=RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
                "--property=RuntimeMaxSec=60",
                "--",
                "/usr/sbin/rndc",
                "-c",
                "/etc/named/oxpanel/rndc.conf",
                "reload",
                "example.com"
            ]
        );
        Ok(())
    }
}
