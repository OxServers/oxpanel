//! Host-wide DNS settings (`OXPANEL_DNS_*`).
//!
//! DNS hosting is off until the operator switches it on, because it needs
//! facts only the operator knows: the name-server host names registered at
//! the registrars (with glue), the contact for the SOA record, and the
//! public addresses of this host. The addresses are never guessed from the
//! network interfaces — behind NAT those are private — so at least one must
//! be configured.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::validate::Domain;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    /// `OXPANEL_DNS`: host this host's tenants' zones.
    pub enabled: bool,
    /// `OXPANEL_DNS_NAMESERVERS`: the NS records of every zone, in order.
    pub nameservers: Vec<Domain>,
    /// `OXPANEL_DNS_SOA_CONTACT`: `hostmaster@example.net`.
    pub soa_contact: String,
    /// `OXPANEL_DNS_IPV4` / `OXPANEL_DNS_IPV6`: where sites' names point.
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    /// `OXPANEL_DNS_SECONDARIES`: servers that get NOTIFY and may transfer
    /// zones with the TSIG key (`address` or `address:port`).
    pub secondaries: Vec<SocketAddr>,
    /// `OXPANEL_DNS_DEFAULT_TTL`: TTL of records that do not set one.
    pub default_ttl: u32,
    /// `OXPANEL_DNS_NEGATIVE_TTL`: how long "no such name" is cached (SOA minimum).
    pub negative_ttl: u32,
    /// `OXPANEL_DNS_CHECK_RESOLVER`: the resolver the delegation and DS
    /// checks ask (`address` or `address:port`); default: the first
    /// `nameserver` of `/etc/resolv.conf`.
    pub check_resolver: Option<SocketAddr>,
    /// `OXPANEL_DNS_MAX_ZONES`: zones per tenant.
    pub max_zones: u32,
    /// `OXPANEL_DNS_MAX_RECORDS`: records a tenant may add to one zone.
    pub max_records: u32,
    /// OxPanel's DNS server configuration. Fixed: the shipped
    /// `oxpanel-dns.service` names it.
    pub conf_dir: PathBuf,
    /// Zone files, signing keys and the server's working directory.
    pub data_dir: PathBuf,
    /// `OXPANEL_PUBLIC_SUFFIX_LIST`: the host's public suffix list.
    pub suffix_list: PathBuf,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            nameservers: Vec::new(),
            soa_contact: String::new(),
            ipv4: None,
            ipv6: None,
            secondaries: Vec::new(),
            default_ttl: 3600,
            negative_ttl: 3600,
            check_resolver: None,
            max_zones: 50,
            max_records: 500,
            conf_dir: PathBuf::from("/etc/named/oxpanel"),
            data_dir: PathBuf::from("/var/lib/oxpanel-dns"),
            suffix_list: PathBuf::from("/usr/share/publicsuffix/public_suffix_list.dat"),
        }
    }
}

fn bad(key: &str, why: impl std::fmt::Display) -> Error {
    Error::invalid("config", format!("{key}: {why}"))
}

/// `address` (port 53) or `address:port` / `[v6]:port`.
pub fn parse_server(key: &str, raw: &str) -> Result<SocketAddr> {
    let raw = raw.trim();
    if let Ok(sa) = raw.parse::<SocketAddr>() {
        return Ok(sa);
    }
    raw.parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, 53))
        .map_err(|_| {
            bad(
                key,
                format!("'{raw}' is not an IP address (optionally with :port)"),
            )
        })
}

/// `local@domain`, local part `a-z 0-9 . _ -`.
fn check_contact(raw: &str) -> Result<()> {
    let ok = raw.split_once('@').is_some_and(|(local, domain)| {
        !local.is_empty()
            && local.len() <= 63
            && !local.starts_with('.')
            && !local.ends_with('.')
            && !local.contains("..")
            && local.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            })
            && Domain::parse(domain).is_ok()
    });
    if ok {
        Ok(())
    } else {
        Err(bad(
            "OXPANEL_DNS_SOA_CONTACT",
            "must be a plain lower-case address such as hostmaster@example.net",
        ))
    }
}

/// The SOA `RNAME` form of the contact: `hostmaster.example.net.` (dots in
/// the local part escaped).
pub fn soa_rname(contact: &str) -> String {
    let (local, domain) = contact.split_once('@').unwrap_or(("hostmaster", contact));
    format!("{}.{domain}.", local.replace('.', "\\."))
}

fn parse_u32(key: &str, raw: &str) -> Result<u32> {
    raw.trim()
        .parse()
        .map_err(|_| bad(key, format!("'{raw}' is not an unsigned integer")))
}

impl DnsConfig {
    /// Read the `OXPANEL_DNS_*` settings.
    pub fn from_lookup(get: &impl Fn(&str) -> Option<String>) -> Result<Self> {
        let mut c = Self::default();
        if let Some(v) = get("OXPANEL_DNS") {
            c.enabled = match v.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" | "" => false,
                _ => return Err(bad("OXPANEL_DNS", format!("'{v}' is not a boolean"))),
            };
        }
        if let Some(v) = get("OXPANEL_DNS_NAMESERVERS") {
            for ns in v.split([',', ' ']).map(str::trim).filter(|s| !s.is_empty()) {
                let ns = Domain::parse(ns.trim_end_matches('.')).map_err(|_| {
                    bad(
                        "OXPANEL_DNS_NAMESERVERS",
                        format!("'{ns}' is not a host name"),
                    )
                })?;
                if !c.nameservers.contains(&ns) {
                    c.nameservers.push(ns);
                }
            }
        }
        if let Some(v) = get("OXPANEL_DNS_SOA_CONTACT") {
            v.trim().clone_into(&mut c.soa_contact);
        }
        if let Some(v) = get("OXPANEL_DNS_IPV4").filter(|v| !v.trim().is_empty()) {
            c.ipv4 =
                Some(v.trim().parse().map_err(|_| {
                    bad("OXPANEL_DNS_IPV4", format!("'{v}' is not an IPv4 address"))
                })?);
        }
        if let Some(v) = get("OXPANEL_DNS_IPV6").filter(|v| !v.trim().is_empty()) {
            c.ipv6 =
                Some(v.trim().parse().map_err(|_| {
                    bad("OXPANEL_DNS_IPV6", format!("'{v}' is not an IPv6 address"))
                })?);
        }
        if let Some(v) = get("OXPANEL_DNS_SECONDARIES") {
            for s in v.split([',', ' ']).filter(|s| !s.trim().is_empty()) {
                let sa = parse_server("OXPANEL_DNS_SECONDARIES", s)?;
                if !c.secondaries.contains(&sa) {
                    c.secondaries.push(sa);
                }
            }
        }
        if let Some(v) = get("OXPANEL_DNS_CHECK_RESOLVER").filter(|v| !v.trim().is_empty()) {
            c.check_resolver = Some(parse_server("OXPANEL_DNS_CHECK_RESOLVER", &v)?);
        }
        for (key, target) in [
            ("OXPANEL_DNS_DEFAULT_TTL", &mut c.default_ttl),
            ("OXPANEL_DNS_NEGATIVE_TTL", &mut c.negative_ttl),
            ("OXPANEL_DNS_MAX_ZONES", &mut c.max_zones),
            ("OXPANEL_DNS_MAX_RECORDS", &mut c.max_records),
        ] {
            if let Some(v) = get(key) {
                *target = parse_u32(key, &v)?;
            }
        }
        if let Some(v) = get("OXPANEL_PUBLIC_SUFFIX_LIST") {
            c.suffix_list = PathBuf::from(v.trim());
        }
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&self) -> Result<()> {
        for (key, v) in [
            ("OXPANEL_DNS_DEFAULT_TTL", self.default_ttl),
            ("OXPANEL_DNS_NEGATIVE_TTL", self.negative_ttl),
        ] {
            if !(super::rr::MIN_TTL..=86_400).contains(&v) {
                return Err(bad(key, "must be 60..=86400 seconds"));
            }
        }
        if !(1..=100_000).contains(&self.max_records) {
            return Err(bad("OXPANEL_DNS_MAX_RECORDS", "must be 1..=100000"));
        }
        if !self.enabled {
            return Ok(());
        }
        if self.nameservers.is_empty() {
            return Err(bad(
                "OXPANEL_DNS_NAMESERVERS",
                "DNS hosting needs the host names of its name servers (at least two, as registrars require), e.g. ns1.example.net,ns2.example.net",
            ));
        }
        check_contact(&self.soa_contact)?;
        if self.ipv4.is_none() && self.ipv6.is_none() {
            return Err(bad(
                "OXPANEL_DNS_IPV4",
                "DNS hosting needs the public address(es) of this host (OXPANEL_DNS_IPV4 and/or OXPANEL_DNS_IPV6); they are not guessed from the interfaces, which are private behind NAT",
            ));
        }
        Ok(())
    }

    /// Things the operator should know about the configuration.
    pub fn warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        if !self.enabled {
            return w;
        }
        if self.nameservers.len() < 2 {
            w.push("only one name server is configured: registrars require at least two (OXPANEL_DNS_NAMESERVERS)".to_owned());
        }
        if self.secondaries.is_empty() {
            w.push(format!(
                "no secondary name server is configured: {} must all be answered by this host alone, which works but gives no redundancy (if this host is down, the domains do not resolve at all); see the handbook on setting up a secondary",
                self.nameservers
                    .iter()
                    .map(Domain::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        w
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;
    use std::collections::HashMap;

    fn from(pairs: &[(&str, &str)]) -> Result<DnsConfig> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        DnsConfig::from_lookup(&|k: &str| m.get(k).cloned())
    }

    const ON: [(&str, &str); 4] = [
        ("OXPANEL_DNS", "true"),
        (
            "OXPANEL_DNS_NAMESERVERS",
            "ns1.example.net, ns2.example.net.",
        ),
        ("OXPANEL_DNS_SOA_CONTACT", "host.master@example.net"),
        ("OXPANEL_DNS_IPV4", "203.0.113.10"),
    ];

    #[test]
    fn off_by_default_and_complete_when_on() {
        let c = from(&[]).unwrap();
        assert!(!c.enabled);
        assert!(c.warnings().is_empty());
        let c = from(&ON).unwrap();
        assert_eq!(c.nameservers.len(), 2);
        assert_eq!(soa_rname(&c.soa_contact), "host\\.master.example.net.");
        assert_eq!(c.warnings().len(), 1, "no secondary: flagged");
        let mut with = ON.to_vec();
        with.push((
            "OXPANEL_DNS_SECONDARIES",
            "198.51.100.20, 127.0.0.1:853,[2001:db8::1]:5353",
        ));
        with.push(("OXPANEL_DNS_CHECK_RESOLVER", "127.0.0.1"));
        let c = from(&with).unwrap();
        assert_eq!(c.secondaries.len(), 3);
        assert_eq!(c.secondaries[0].port(), 53);
        assert_eq!(c.check_resolver.map(|s| s.port()), Some(53));
        assert!(c.warnings().is_empty());
    }

    #[test]
    fn incomplete_or_bad_settings_are_refused() {
        for (drop, (key, _)) in ON.iter().enumerate().skip(1) {
            let mut v = ON.to_vec();
            v.remove(drop);
            assert!(from(&v).is_err(), "without {key}");
        }
        for (k, bad) in [
            ("OXPANEL_DNS", "maybe"),
            ("OXPANEL_DNS_NAMESERVERS", "ns1.example.net;rm"),
            ("OXPANEL_DNS_SOA_CONTACT", "Host@example.net"),
            ("OXPANEL_DNS_SOA_CONTACT", "a b@example.net"),
            ("OXPANEL_DNS_SOA_CONTACT", "hostmaster"),
            ("OXPANEL_DNS_IPV4", "203.0.113"),
            ("OXPANEL_DNS_IPV6", "2001:db8::zz"),
            ("OXPANEL_DNS_SECONDARIES", "ns2.example.net"),
            ("OXPANEL_DNS_DEFAULT_TTL", "5"),
            ("OXPANEL_DNS_MAX_RECORDS", "0"),
        ] {
            let mut v = ON.to_vec();
            v.push((k, bad));
            assert!(from(&v).is_err(), "{k}={bad}");
        }
    }
}
