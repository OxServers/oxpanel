//! Zone files, rendered from records only.
//!
//! A zone file is: one header comment, the SOA record, the apex NS records
//! of the configured name servers, the address records of the tenant's
//! sites in the zone, (later: the engine's mail records,
//! [`mail_records`]), then the tenant's own records — one line each, in the
//! order they were added. Every line comes from [`Rr::render`] or from the
//! SOA renderer below; nothing is copied from a request.
//!
//! The serial changes exactly when the rendered content does (see
//! [`next_serial`]); the content hash in the zone record says whether it did.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use super::config::{soa_rname, DnsConfig};
use super::rr::{RData, RelName, Rr, Target};
use crate::validate::Domain;

pub const HEADER: &str = "; Managed by oxpanel-daemon. Manual edits will be overwritten.";
/// SOA timers: refresh 2 h, retry 1 h, expire 14 days (secondaries keep
/// answering for two weeks without the primary).
const REFRESH: u32 = 7200;
const RETRY: u32 = 3600;
const EXPIRE: u32 = 1_209_600;
/// The catalog zone through which secondaries learn which zones exist
/// (RFC 9432, schema version 1, which BIND 9.16 reads). Never delegated:
/// `.invalid` cannot exist in the public DNS.
pub const CATALOG_ZONE: &str = "catalog.oxpanel.invalid";

/// Where a record the engine maintains comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// SOA and the apex NS records.
    Zone,
    /// The address records of a site's name.
    Site(String),
    /// Mail records (none yet; see [`mail_records`]).
    Mail,
}

impl Origin {
    pub fn label(&self) -> String {
        match self {
            Self::Zone => "zone".to_owned(),
            Self::Site(d) => format!("site:{d}"),
            Self::Mail => "mail".to_owned(),
        }
    }
}

/// A name inside the zone that one of the tenant's sites serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteName {
    pub name: RelName,
    /// The site (virtual host domain) that serves it.
    pub site: String,
}

/// Everything a zone file is rendered from.
#[derive(Debug, Clone, Copy)]
pub struct ZoneInput<'a> {
    pub zone: &'a Domain,
    pub cfg: &'a DnsConfig,
    pub sites: &'a [SiteName],
    /// The tenant's records, in id order.
    pub records: &'a [Rr],
}

/// The hook for OxPanel's own mail records (MX, SPF, DKIM, DMARC) once the
/// engine hosts mail: engine-maintained, protected like the site records,
/// rendered between them and the tenant's records. There is no mail server
/// on the host today, so there are none; tenants who use an external mail
/// provider add that provider's records themselves.
pub fn mail_records(_zone: &Domain) -> Vec<(Rr, Origin)> {
    Vec::new()
}

/// The records the engine maintains, except the SOA: apex NS, then the
/// address records of every site name, then mail.
pub fn engine_records(input: &ZoneInput<'_>) -> Vec<(Rr, Origin)> {
    let mut out = Vec::new();
    for ns in &input.cfg.nameservers {
        out.push((
            Rr {
                name: RelName::apex(),
                ttl: 0,
                data: RData::Ns(Target::host(ns)),
            },
            Origin::Zone,
        ));
    }
    for s in input.sites {
        if let Some(v4) = input.cfg.ipv4 {
            out.push((
                Rr {
                    name: s.name.clone(),
                    ttl: 0,
                    data: RData::A(v4),
                },
                Origin::Site(s.site.clone()),
            ));
        }
        if let Some(v6) = input.cfg.ipv6 {
            out.push((
                Rr {
                    name: s.name.clone(),
                    ttl: 0,
                    data: RData::Aaaa(v6),
                },
                Origin::Site(s.site.clone()),
            ));
        }
    }
    out.extend(mail_records(input.zone));
    out
}

/// The SOA record's data after `SOA`.
pub fn soa_data(cfg: &DnsConfig, serial: u32) -> String {
    let mname = cfg
        .nameservers
        .first()
        .map_or_else(|| "localhost.".to_owned(), |ns| format!("{ns}."));
    format!(
        "{mname} {} {serial} {REFRESH} {RETRY} {EXPIRE} {}",
        soa_rname(&cfg.soa_contact),
        cfg.negative_ttl
    )
}

/// Every line of the zone file.
pub fn render_lines(input: &ZoneInput<'_>, serial: u32) -> Vec<String> {
    let ttl = input.cfg.default_ttl;
    let mut lines = vec![
        HEADER.to_owned(),
        format!(
            "{}. {ttl} IN SOA {}",
            input.zone,
            soa_data(input.cfg, serial)
        ),
    ];
    for (rr, _) in engine_records(input) {
        lines.push(rr.render(input.zone, ttl));
    }
    for rr in input.records {
        lines.push(rr.render(input.zone, ttl));
    }
    lines
}

pub fn render(input: &ZoneInput<'_>, serial: u32) -> String {
    let mut s = render_lines(input, serial).join("\n");
    s.push('\n');
    s
}

/// SHA-256 of the zone as rendered with serial 0.
pub fn content_hash(input: &ZoneInput<'_>) -> String {
    sha256_hex(render(input, 0).as_bytes())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    super::wire::hex_upper(&h.finalize()).to_ascii_lowercase()
}

/// The serial after `prev`: the current time in seconds, as long as that is
/// later than `prev` in serial-number arithmetic (RFC 1982), otherwise
/// `prev + 1`. It survives restarts (the previous serial is in the record),
/// a clock that steps back (it then counts up from `prev`), and it is what
/// secondaries accept: always "greater" than the last one.
pub fn next_serial(prev: u32, now_unix: u64) -> u32 {
    let candidate = u32::try_from(now_unix & 0xffff_ffff).unwrap_or(0);
    let diff = candidate.wrapping_sub(prev);
    if diff != 0 && diff < (1 << 31) {
        candidate
    } else {
        prev.wrapping_add(1)
    }
}

/// `a` is later than `b` in serial-number arithmetic.
pub fn serial_gt(a: u32, b: u32) -> bool {
    let diff = a.wrapping_sub(b);
    diff != 0 && diff < (1 << 31)
}

/// The label of a member zone in the catalog: SHA-1 of its wire-format name
/// (catalog schema version 1).
pub fn catalog_label(zone: &Domain) -> String {
    let mut h = sha1::Sha1::new();
    for label in zone.as_str().split('.') {
        h.update([u8::try_from(label.len()).unwrap_or(63)]);
        h.update(label.as_bytes());
    }
    h.update([0]);
    super::wire::hex_upper(&h.finalize()).to_ascii_lowercase()
}

/// The catalog zone listing `members`.
pub fn render_catalog(members: &[Domain], serial: u32) -> String {
    let c = CATALOG_ZONE;
    let mut s = format!(
        "{HEADER}
{c}. 3600 IN SOA invalid. invalid. {serial} 3600 600 2147483646 0
{c}. 3600 IN NS invalid.
version.{c}. 3600 IN TXT \"1\"
"
    );
    for m in members {
        let _ = writeln!(s, "{}.zones.{c}. 3600 IN PTR {m}.", catalog_label(m));
    }
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;
    use crate::dns::rr::{RawRr, RrType};

    pub(crate) fn cfg() -> DnsConfig {
        DnsConfig {
            enabled: true,
            nameservers: vec![
                Domain::parse("ns1.example.net").unwrap(),
                Domain::parse("ns2.example.net").unwrap(),
            ],
            soa_contact: "hostmaster@example.net".into(),
            ipv4: Some("203.0.113.10".parse().unwrap()),
            ipv6: Some("2001:db8::10".parse().unwrap()),
            ..DnsConfig::default()
        }
    }

    #[test]
    fn a_zone_file_is_exactly_its_records() {
        let zone = Domain::parse("example.com").unwrap();
        let cfg = cfg();
        let sites = [
            SiteName {
                name: RelName::apex(),
                site: "example.com".into(),
            },
            SiteName {
                name: RelName::parse("www", &zone).unwrap(),
                site: "example.com".into(),
            },
        ];
        let mut mx = RawRr {
            name: "@".into(),
            rtype: Some(RrType::Mx),
            value: "mx1.mail.example.org".into(),
            ..RawRr::default()
        };
        mx.priority = 10;
        let records = [Rr::parse(&mx, &zone).unwrap()];
        let input = ZoneInput {
            zone: &zone,
            cfg: &cfg,
            sites: &sites,
            records: &records,
        };
        assert_eq!(
            render(&input, 1_763_100_000),
            "; Managed by oxpanel-daemon. Manual edits will be overwritten.
example.com. 3600 IN SOA ns1.example.net. hostmaster.example.net. 1763100000 7200 3600 1209600 3600
example.com. 3600 IN NS ns1.example.net.
example.com. 3600 IN NS ns2.example.net.
example.com. 3600 IN A 203.0.113.10
example.com. 3600 IN AAAA 2001:db8::10
www.example.com. 3600 IN A 203.0.113.10
www.example.com. 3600 IN AAAA 2001:db8::10
example.com. 3600 IN MX 10 mx1.mail.example.org.
"
        );
        // The hash ignores the serial but sees everything else.
        let h = content_hash(&input);
        assert_eq!(h, content_hash(&input));
        let no_mx = ZoneInput {
            records: &[],
            ..input
        };
        assert_ne!(h, content_hash(&no_mx));
        assert!(mail_records(&zone).is_empty(), "no mail records by default");
    }

    #[test]
    fn serials_only_ever_increase() {
        let now = 1_763_100_000;
        assert_eq!(next_serial(0, now), 1_763_100_000);
        assert_eq!(
            next_serial(1_763_100_000, now),
            1_763_100_001,
            "same second"
        );
        assert_eq!(
            next_serial(1_763_100_500, now),
            1_763_100_501,
            "clock stepped back"
        );
        assert_eq!(next_serial(5, now + 10), 1_763_100_010);
        assert_eq!(
            next_serial(u32::MAX, u64::from(u32::MAX - 5)),
            0,
            "wraps as RFC 1982 allows"
        );
        for prev in [0u32, 1, 1 << 31, u32::MAX - 1, 1_763_100_000] {
            for t in [0u64, now, u64::from(u32::MAX) + 5] {
                assert!(serial_gt(next_serial(prev, t), prev), "{prev} {t}");
            }
        }
    }

    #[test]
    fn the_catalog_lists_members_by_hashed_label() {
        let zone = Domain::parse("example.com").unwrap();
        // The label BIND and the catalog specification expect for example.com.
        assert_eq!(
            catalog_label(&zone),
            "c5e4b4da1e5a620ddaa3635e55c3732a5b49c7f4"
        );
        let text = render_catalog(&[zone], 7);
        assert!(text.contains(
            "c5e4b4da1e5a620ddaa3635e55c3732a5b49c7f4.zones.catalog.oxpanel.invalid. 3600 IN PTR example.com.\n"
        ));
        assert!(text.contains("version.catalog.oxpanel.invalid. 3600 IN TXT \"1\"\n"));
        assert!(text.contains(" 7 3600 600 2147483646 0\n"));
    }
}
