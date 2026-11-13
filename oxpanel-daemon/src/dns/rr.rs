//! DNS resource records: allow-list validation of every field and rendering
//! of one record as one zone-file line.
//!
//! What can reach a zone file is decided here. Owner names and host names
//! are made of `a-z 0-9 - _` labels (and a leading `*` for wildcards), so
//! they cannot carry a space, a quote, a semicolon, a parenthesis, a `$` or
//! a line break; addresses are re-printed from parsed `Ipv4Addr`/`Ipv6Addr`;
//! numbers are numbers. The only free text — TXT and CAA values — is limited
//! to printable ASCII, and the renderer splits it into strings of at most 255
//! bytes, escapes `"` and `\` and quotes every string, so no value can end
//! its string early or start a new directive. One record is always exactly
//! one line.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::validate::Domain;

/// Shortest TTL a record may ask for (seconds). 0 means "the zone default".
pub const MIN_TTL: u32 = 60;
/// Longest TTL a record may ask for: one week.
pub const MAX_TTL: u32 = 604_800;
/// Longest TXT value (characters). A 4096-bit DKIM key is about 800.
pub const MAX_TXT_LEN: usize = 4000;
/// Longest CAA value.
pub const MAX_CAA_LEN: usize = 255;
/// A character-string in the DNS holds at most 255 bytes.
const TXT_CHUNK: usize = 255;
const LABEL_MAX: usize = 63;
const NAME_MAX: usize = 253;

/// The record types tenants may add.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RrType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Srv,
    Caa,
    Ns,
}

impl RrType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Mx => "MX",
            Self::Txt => "TXT",
            Self::Srv => "SRV",
            Self::Caa => "CAA",
            Self::Ns => "NS",
        }
    }

    /// Owner names of these types are host names: no `_` (the DNS server
    /// refuses such names for them, `check-names`).
    fn owner_is_hostname(self) -> bool {
        matches!(self, Self::A | Self::Aaaa | Self::Mx | Self::Ns)
    }

    /// Types a wildcard owner (`*.x`) may have.
    fn wildcard_allowed(self) -> bool {
        matches!(
            self,
            Self::A | Self::Aaaa | Self::Cname | Self::Mx | Self::Txt
        )
    }

    /// Address records: what the engine maintains for sites.
    pub fn is_address(self) -> bool {
        matches!(self, Self::A | Self::Aaaa)
    }
}

/// An owner name relative to the zone: `@` (the apex) or one or more labels.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelName(String);

impl RelName {
    pub fn apex() -> Self {
        Self("@".to_owned())
    }

    /// Validate `raw` as a name inside `zone`. ASCII letters are lowered.
    pub fn parse(raw: &str, zone: &Domain) -> Result<Self> {
        let field = "record.name";
        let s = raw.trim().to_ascii_lowercase();
        if s.is_empty() || s == "@" {
            return Ok(Self::apex());
        }
        if s == zone.as_str()
            || s == format!("{zone}.")
            || s.ends_with(&format!(".{zone}"))
            || s.ends_with(&format!(".{zone}."))
        {
            return Err(Error::invalid(
                field,
                format!(
                    "names are relative to the zone: give '@' or 'www', not '{s}' (inside {zone} that would be '{s}.{zone}')"
                ),
            ));
        }
        for (i, label) in s.split('.').enumerate() {
            if i == 0 && label == "*" {
                continue;
            }
            check_label(label, field, true)?;
        }
        let me = Self(s);
        if me.fqdn(zone).len() > NAME_MAX {
            return Err(Error::invalid(
                field,
                format!("the full name may be at most {NAME_MAX} characters"),
            ));
        }
        Ok(me)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_apex(&self) -> bool {
        self.0 == "@"
    }

    pub fn is_wildcard(&self) -> bool {
        self.0 == "*" || self.0.starts_with("*.")
    }

    /// The absolute name, without the final dot.
    pub fn fqdn(&self, zone: &Domain) -> String {
        if self.is_apex() {
            zone.to_string()
        } else {
            format!("{}.{zone}", self.0)
        }
    }

    /// The name relative to `zone` of an absolute name inside it.
    pub fn relative_to(fqdn: &str, zone: &Domain) -> Option<Self> {
        if fqdn == zone.as_str() {
            return Some(Self::apex());
        }
        fqdn.strip_suffix(&format!(".{zone}"))
            .map(|rel| Self(rel.to_owned()))
    }

    /// `self` is `other` or below it.
    pub fn is_at_or_below(&self, other: &Self) -> bool {
        other.is_apex() || self == other || self.0.ends_with(&format!(".{}", other.0))
    }

    fn labels(&self) -> Vec<&str> {
        if self.is_apex() {
            Vec::new()
        } else {
            self.0.split('.').collect()
        }
    }
}

/// One label: 1..=63 of `a-z 0-9 - _`, not starting or ending with `-`;
/// `_` only where `underscore` allows it.
fn check_label(label: &str, field: &'static str, underscore: bool) -> Result<()> {
    if label.is_empty() || label.len() > LABEL_MAX {
        return Err(Error::invalid(
            field,
            format!("labels must be 1..={LABEL_MAX} characters"),
        ));
    }
    let ok = label.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || (underscore && b == b'_')
    });
    if !ok {
        return Err(Error::invalid(
            field,
            if underscore {
                "labels may only contain a-z, 0-9, '-' and '_'"
            } else {
                "labels of host names may only contain a-z, 0-9 and '-'"
            },
        ));
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(Error::invalid(
            field,
            "labels may not start or end with '-'",
        ));
    }
    Ok(())
}

/// An absolute host name a record points at, or the root (`.`, "nothing"),
/// which only MX (null MX) and SRV (no service) accept.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Target(String);

impl Target {
    /// `underscore`: allow `_` in labels (CNAME targets such as a mail
    /// provider's DKIM keys); host names for MX, NS and SRV never have one.
    fn parse(raw: &str, root_ok: bool, underscore: bool) -> Result<Self> {
        let field = "record.value";
        let s = raw.trim().to_ascii_lowercase();
        if s == "." {
            return if root_ok {
                Ok(Self(".".to_owned()))
            } else {
                Err(Error::invalid(field, "a host name is required"))
            };
        }
        let s = s.strip_suffix('.').unwrap_or(&s);
        if s.is_empty() || s.len() > NAME_MAX {
            return Err(Error::invalid(
                field,
                format!("must be a host name of 1..={NAME_MAX} characters"),
            ));
        }
        let labels: Vec<&str> = s.split('.').collect();
        if labels.len() < 2 {
            return Err(Error::invalid(
                field,
                "must be a fully-qualified host name such as mail.example.com",
            ));
        }
        for label in &labels {
            check_label(label, field, underscore)?;
        }
        if labels
            .last()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(Error::invalid(field, "must be a host name, not an address"));
        }
        Ok(Self(s.to_owned()))
    }

    /// A validated domain as a target (the engine's own NS records).
    pub fn host(d: &Domain) -> Self {
        Self(d.as_str().to_owned())
    }

    pub fn is_root(&self) -> bool {
        self.0 == "."
    }

    /// Without the final dot (`.` for the root).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn render(&self) -> String {
        if self.is_root() {
            ".".to_owned()
        } else {
            format!("{}.", self.0)
        }
    }
}

/// Text of a TXT record: printable ASCII only.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxtValue(String);

impl TxtValue {
    pub fn parse(raw: &str) -> Result<Self> {
        let field = "record.value";
        if raw.len() > MAX_TXT_LEN {
            return Err(Error::invalid(
                field,
                format!("TXT values may be at most {MAX_TXT_LEN} characters"),
            ));
        }
        if !raw.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
            return Err(Error::invalid(
                field,
                "TXT values may only contain printable ASCII characters (no line breaks, tabs or non-ASCII)",
            ));
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Quoted character-strings of at most 255 bytes each, separated by
    /// spaces. An empty value is one empty string.
    pub fn render(&self) -> String {
        let bytes = self.0.as_bytes();
        if bytes.is_empty() {
            return "\"\"".to_owned();
        }
        let mut out = String::with_capacity(bytes.len() + 8);
        for (i, chunk) in bytes.chunks(TXT_CHUNK).enumerate() {
            if i > 0 {
                out.push(' ');
            }
            out.push('"');
            for &b in chunk {
                if b == b'"' || b == b'\\' {
                    out.push('\\');
                }
                out.push(char::from(b));
            }
            out.push('"');
        }
        out
    }
}

/// The property tag of a CAA record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CaaTag {
    Issue,
    IssueWild,
    Iodef,
}

impl CaaTag {
    fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "issue" => Ok(Self::Issue),
            "issuewild" => Ok(Self::IssueWild),
            "iodef" => Ok(Self::Iodef),
            _ => Err(Error::invalid(
                "record.caa_tag",
                "must be issue, issuewild or iodef",
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::IssueWild => "issuewild",
            Self::Iodef => "iodef",
        }
    }
}

/// The data of one record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(Target),
    Mx {
        preference: u16,
        exchange: Target,
    },
    Txt(TxtValue),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: Target,
    },
    Caa {
        flags: u8,
        tag: CaaTag,
        value: String,
    },
    Ns(Target),
}

impl RData {
    pub fn rtype(&self) -> RrType {
        match self {
            Self::A(_) => RrType::A,
            Self::Aaaa(_) => RrType::Aaaa,
            Self::Cname(_) => RrType::Cname,
            Self::Mx { .. } => RrType::Mx,
            Self::Txt(_) => RrType::Txt,
            Self::Srv { .. } => RrType::Srv,
            Self::Caa { .. } => RrType::Caa,
            Self::Ns(_) => RrType::Ns,
        }
    }

    /// The record data as it stands in a zone file after the type.
    pub fn render(&self) -> String {
        match self {
            Self::A(a) => a.to_string(),
            Self::Aaaa(a) => a.to_string(),
            Self::Cname(t) | Self::Ns(t) => t.render(),
            Self::Mx {
                preference,
                exchange,
            } => format!("{preference} {}", exchange.render()),
            Self::Txt(t) => t.render(),
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => format!("{priority} {weight} {port} {}", target.render()),
            Self::Caa { flags, tag, value } => {
                format!("{flags} {} \"{value}\"", tag.as_str())
            }
        }
    }

    /// The host name this record points at, if any.
    pub fn target(&self) -> Option<&Target> {
        match self {
            Self::Cname(t) | Self::Ns(t) => Some(t),
            Self::Mx { exchange, .. } => Some(exchange),
            Self::Srv { target, .. } => Some(target),
            _ => None,
        }
    }
}

/// A record as it arrives from the API (or a stored record): every field
/// as sent, nothing validated yet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawRr {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: Option<RrType>,
    #[serde(default)]
    pub ttl: u32,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub priority: u32,
    #[serde(default)]
    pub weight: u32,
    #[serde(default)]
    pub port: u32,
    #[serde(default)]
    pub caa_flags: u32,
    #[serde(default)]
    pub caa_tag: String,
}

/// A validated record of a zone.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rr {
    pub name: RelName,
    /// 0 = the zone default.
    pub ttl: u32,
    pub data: RData,
}

fn u16_field(v: u32, field: &'static str) -> Result<u16> {
    u16::try_from(v).map_err(|_| Error::invalid(field, "must be 0..=65535"))
}

impl Rr {
    /// Validate a record for `zone`.
    pub fn parse(raw: &RawRr, zone: &Domain) -> Result<Self> {
        let rtype = raw
            .rtype
            .ok_or_else(|| Error::invalid("record.type", "a record type is required"))?;
        let name = RelName::parse(&raw.name, zone)?;
        if name.is_wildcard() && !rtype.wildcard_allowed() {
            return Err(Error::invalid(
                "record.name",
                format!(
                    "a wildcard name may only have A, AAAA, CNAME, MX or TXT records, not {}",
                    rtype.as_str()
                ),
            ));
        }
        if rtype.owner_is_hostname() {
            for label in name.labels() {
                if label != "*" {
                    check_label(label, "record.name", false)?;
                }
            }
        }
        if raw.ttl != 0 && !(MIN_TTL..=MAX_TTL).contains(&raw.ttl) {
            return Err(Error::invalid(
                "record.ttl",
                format!("must be 0 (the zone default) or {MIN_TTL}..={MAX_TTL} seconds"),
            ));
        }
        let data = parse_data(rtype, raw)?;
        Self::check_shape(&name, &data)?;
        Ok(Self {
            name,
            ttl: raw.ttl,
            data,
        })
    }

    /// Rules that tie the name to the type.
    fn check_shape(name: &RelName, data: &RData) -> Result<()> {
        match data {
            RData::Cname(_) if name.is_apex() => Err(Error::invalid(
                "record.name",
                "a CNAME cannot be at the apex of a zone (the apex has SOA and NS records)",
            )),
            RData::Ns(_) if name.is_apex() => Err(Error::invalid(
                "record.name",
                "the apex name servers are the host's own and cannot be changed; NS records delegate names below the apex",
            )),
            RData::Srv { .. } => {
                let labels = name.labels();
                let ok = labels.len() >= 2
                    && labels.first().is_some_and(|l| l.starts_with('_') && l.len() > 1)
                    && labels
                        .get(1)
                        .is_some_and(|l| matches!(*l, "_tcp" | "_udp" | "_tls" | "_sctp"));
                if ok {
                    Ok(())
                } else {
                    Err(Error::invalid(
                        "record.name",
                        "an SRV name is _service._protocol (e.g. _autodiscover._tcp), optionally followed by a name",
                    ))
                }
            }
            _ => Ok(()),
        }
    }

    /// The record as stored and returned by the API.
    pub fn to_raw(&self) -> RawRr {
        let mut raw = RawRr {
            name: self.name.as_str().to_owned(),
            rtype: Some(self.data.rtype()),
            ttl: self.ttl,
            ..RawRr::default()
        };
        match &self.data {
            RData::A(a) => raw.value = a.to_string(),
            RData::Aaaa(a) => raw.value = a.to_string(),
            RData::Cname(t) | RData::Ns(t) => t.as_str().clone_into(&mut raw.value),
            RData::Mx {
                preference,
                exchange,
            } => {
                raw.priority = u32::from(*preference);
                exchange.as_str().clone_into(&mut raw.value);
            }
            RData::Txt(t) => t.as_str().clone_into(&mut raw.value),
            RData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                raw.priority = u32::from(*priority);
                raw.weight = u32::from(*weight);
                raw.port = u32::from(*port);
                target.as_str().clone_into(&mut raw.value);
            }
            RData::Caa { flags, tag, value } => {
                raw.caa_flags = u32::from(*flags);
                tag.as_str().clone_into(&mut raw.caa_tag);
                value.clone_into(&mut raw.value);
            }
        }
        raw
    }

    /// One zone-file line: `<owner>. <ttl> IN <type> <data>`.
    pub fn render(&self, zone: &Domain, default_ttl: u32) -> String {
        let ttl = if self.ttl == 0 { default_ttl } else { self.ttl };
        let mut line = String::new();
        let _ = write!(
            line,
            "{}. {ttl} IN {} {}",
            self.name.fqdn(zone),
            self.data.rtype().as_str(),
            self.data.render()
        );
        line
    }
}

fn parse_data(rtype: RrType, raw: &RawRr) -> Result<RData> {
    let field = "record.value";
    Ok(match rtype {
        RrType::A => {
            let a: Ipv4Addr = raw.value.trim().parse().map_err(|_| {
                Error::invalid(field, "must be an IPv4 address such as 203.0.113.10")
            })?;
            if a.is_unspecified() || a.is_multicast() || a.is_broadcast() {
                return Err(Error::invalid(field, "must be a unicast IPv4 address"));
            }
            RData::A(a)
        }
        RrType::Aaaa => {
            let a: Ipv6Addr = raw.value.trim().parse().map_err(|_| {
                Error::invalid(field, "must be an IPv6 address such as 2001:db8::10")
            })?;
            if a.is_unspecified() || a.is_multicast() {
                return Err(Error::invalid(field, "must be a unicast IPv6 address"));
            }
            RData::Aaaa(a)
        }
        RrType::Cname => RData::Cname(Target::parse(&raw.value, false, true)?),
        RrType::Ns => RData::Ns(Target::parse(&raw.value, false, false)?),
        RrType::Mx => {
            let preference = u16_field(raw.priority, "record.priority")?;
            let exchange = Target::parse(&raw.value, true, false)?;
            if exchange.is_root() && preference != 0 {
                return Err(Error::invalid(
                    "record.priority",
                    "a null MX (value \".\": this domain receives no mail) must have priority 0",
                ));
            }
            RData::Mx {
                preference,
                exchange,
            }
        }
        RrType::Txt => RData::Txt(TxtValue::parse(&raw.value)?),
        RrType::Srv => RData::Srv {
            priority: u16_field(raw.priority, "record.priority")?,
            weight: u16_field(raw.weight, "record.weight")?,
            port: u16_field(raw.port, "record.port")?,
            target: Target::parse(&raw.value, true, false)?,
        },
        RrType::Caa => {
            let flags = match raw.caa_flags {
                0 => 0,
                128 => 128,
                _ => {
                    return Err(Error::invalid(
                        "record.caa_flags",
                        "must be 0 or 128 (critical)",
                    ))
                }
            };
            let tag = CaaTag::parse(&raw.caa_tag)?;
            let value = raw.value.trim();
            if value.len() > MAX_CAA_LEN
                || !value
                    .bytes()
                    .all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\')
            {
                return Err(Error::invalid(
                    field,
                    format!("CAA values are at most {MAX_CAA_LEN} printable ASCII characters without '\"' or '\\'"),
                ));
            }
            if tag == CaaTag::Iodef
                && !(value.starts_with("mailto:") || value.starts_with("https://"))
            {
                return Err(Error::invalid(
                    field,
                    "an iodef value is a mailto: or https:// URL",
                ));
            }
            RData::Caa {
                flags,
                tag,
                value: value.to_owned(),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;

    fn zone() -> Domain {
        Domain::parse("example.com").unwrap()
    }

    fn raw(name: &str, rtype: RrType, value: &str) -> RawRr {
        RawRr {
            name: name.into(),
            rtype: Some(rtype),
            value: value.into(),
            ..RawRr::default()
        }
    }

    fn line(r: &RawRr) -> Result<String> {
        Ok(Rr::parse(r, &zone())?.render(&zone(), 3600))
    }

    #[test]
    fn every_type_renders_one_exact_line() -> Result<()> {
        assert_eq!(
            line(&raw("@", RrType::A, "203.0.113.10"))?,
            "example.com. 3600 IN A 203.0.113.10"
        );
        assert_eq!(
            line(&raw("www", RrType::Aaaa, "2001:DB8:0::10"))?,
            "www.example.com. 3600 IN AAAA 2001:db8::10"
        );
        assert_eq!(
            line(&raw("Shop", RrType::Cname, "Shops.Example.NET."))?,
            "shop.example.com. 3600 IN CNAME shops.example.net."
        );
        let mut mx = raw("@", RrType::Mx, "mx1.mail.example.net");
        mx.priority = 10;
        mx.ttl = 300;
        assert_eq!(
            line(&mx)?,
            "example.com. 300 IN MX 10 mx1.mail.example.net."
        );
        let mut null_mx = raw("@", RrType::Mx, ".");
        assert_eq!(line(&null_mx)?, "example.com. 3600 IN MX 0 .");
        null_mx.priority = 5;
        assert!(line(&null_mx).is_err(), "null MX needs priority 0");
        assert_eq!(
            line(&raw(
                "_dmarc",
                RrType::Txt,
                "v=DMARC1; p=none; rua=mailto:d@example.com"
            ))?,
            "_dmarc.example.com. 3600 IN TXT \"v=DMARC1; p=none; rua=mailto:d@example.com\""
        );
        let mut srv = raw(
            "_autodiscover._tcp",
            RrType::Srv,
            "autodiscover.mail.example.net",
        );
        srv.priority = 0;
        srv.weight = 5;
        srv.port = 443;
        assert_eq!(
            line(&srv)?,
            "_autodiscover._tcp.example.com. 3600 IN SRV 0 5 443 autodiscover.mail.example.net."
        );
        let mut caa = raw("@", RrType::Caa, "letsencrypt.org");
        caa.caa_tag = "issue".into();
        assert_eq!(
            line(&caa)?,
            "example.com. 3600 IN CAA 0 issue \"letsencrypt.org\""
        );
        assert_eq!(
            line(&raw("sub", RrType::Ns, "ns1.other.example"))?,
            "sub.example.com. 3600 IN NS ns1.other.example."
        );
        assert_eq!(
            line(&raw("selector1._domainkey", RrType::Cname, "selector1-example-com._domainkey.tenant.onmail.example"))?,
            "selector1._domainkey.example.com. 3600 IN CNAME selector1-example-com._domainkey.tenant.onmail.example."
        );
        Ok(())
    }

    #[test]
    fn txt_is_split_into_255_byte_strings_and_escaped() -> Result<()> {
        let long = "k".repeat(600);
        let l = line(&raw("s1._domainkey", RrType::Txt, &long))?;
        let want = format!(
            "s1._domainkey.example.com. 3600 IN TXT \"{}\" \"{}\" \"{}\"",
            "k".repeat(255),
            "k".repeat(255),
            "k".repeat(90)
        );
        assert_eq!(l, want);
        assert_eq!(
            line(&raw(
                "q",
                RrType::Txt,
                r#"a"b\c;d (e) $INCLUDE /etc/shadow"#
            ))?,
            r#"q.example.com. 3600 IN TXT "a\"b\\c;d (e) $INCLUDE /etc/shadow""#
        );
        assert_eq!(
            line(&raw("e", RrType::Txt, ""))?,
            "e.example.com. 3600 IN TXT \"\""
        );
        for bad in ["a\nb", "a\rb", "tab\there", "caf\u{e9}", "nul\0"] {
            assert!(line(&raw("x", RrType::Txt, bad)).is_err(), "{bad:?}");
        }
        assert!(line(&raw("x", RrType::Txt, &"a".repeat(MAX_TXT_LEN + 1))).is_err());
        Ok(())
    }

    #[test]
    fn names_cannot_escape_the_zone_or_carry_syntax() {
        for bad in [
            "a b",
            "a;b",
            "a\nb",
            "$INCLUDE",
            "$GENERATE",
            "(",
            ")",
            "a\"b",
            "a\\b",
            "..",
            "a..b",
            ".a",
            "a.",
            "-a",
            "a-",
            "a/b",
            "a*b",
            "x.*",
            "**",
            "@.x",
            "example.com",
            "www.example.com",
            "www.example.com.",
            "ünï",
            &"a".repeat(64),
        ] {
            assert!(
                RelName::parse(bad, &zone()).is_err(),
                "{bad:?} was accepted"
            );
        }
        let long = vec!["a".repeat(63); 4].join(".");
        assert!(RelName::parse(&long, &zone()).is_err(), "over 253 in all");
        for good in [
            "@",
            "",
            "www",
            "_dmarc",
            "s1._domainkey",
            "*",
            "*.dev",
            "a-b.c_d",
        ] {
            assert!(RelName::parse(good, &zone()).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn host_names_and_types_follow_the_dns_rules() {
        // `_` only where the DNS allows it.
        assert!(line(&raw("_x", RrType::A, "192.0.2.1")).is_err());
        assert!(line(&raw("a._x", RrType::Mx, "mx.example.net")).is_err());
        assert!(line(&raw("x", RrType::Mx, "m_x.example.net")).is_err());
        // Wildcards: not for NS, SRV or CAA.
        assert!(line(&raw("*", RrType::Ns, "ns.example.net")).is_err());
        assert!(line(&raw("*.x", RrType::A, "192.0.2.1")).is_ok());
        // No CNAME or NS at the apex.
        assert!(line(&raw("@", RrType::Cname, "x.example.net")).is_err());
        assert!(line(&raw("@", RrType::Ns, "ns.example.net")).is_err());
        // SRV needs _service._proto.
        assert!(line(&raw("sip", RrType::Srv, "sip.example.net")).is_err());
        assert!(line(&raw("_sip._smoke", RrType::Srv, "sip.example.net")).is_err());
        // Targets are host names, never addresses or single labels.
        for bad in ["192.0.2.1", "localhost", "a b.example", "x;y.example", ""] {
            assert!(line(&raw("w", RrType::Cname, bad)).is_err(), "{bad:?}");
        }
        // Addresses are parsed, never copied.
        for bad in [
            "1.2.3",
            "01.2.3.4",
            "0.0.0.0",
            "224.0.0.1",
            "1.2.3.4 ; x",
            "1.2.3.4\nx",
        ] {
            assert!(line(&raw("a", RrType::A, bad)).is_err(), "{bad:?}");
        }
        assert!(line(&raw("a", RrType::Aaaa, "::")).is_err());
        // TTL bounds.
        let mut r = raw("a", RrType::A, "192.0.2.1");
        r.ttl = 59;
        assert!(line(&r).is_err());
        r.ttl = MAX_TTL + 1;
        assert!(line(&r).is_err());
        // Numbers in range.
        let mut mx = raw("@", RrType::Mx, "mx.example.net");
        mx.priority = 70_000;
        assert!(line(&mx).is_err());
        // CAA.
        let mut caa = raw("@", RrType::Caa, "letsencrypt.org");
        caa.caa_tag = "issue".into();
        caa.caa_flags = 1;
        assert!(line(&caa).is_err());
        caa.caa_flags = 0;
        caa.value = "le\"; x".into();
        assert!(line(&caa).is_err());
        caa.caa_tag = "iodef".into();
        caa.value = "ftp://x".into();
        assert!(line(&caa).is_err());
        caa.value = "mailto:security@example.com".into();
        assert!(line(&caa).is_ok());
        assert!(Rr::parse(&RawRr::default(), &zone()).is_err(), "no type");
    }

    #[test]
    fn records_round_trip_through_their_stored_form() -> Result<()> {
        let mut srv = raw("_imaps._tcp", RrType::Srv, "imap.example.net");
        srv.priority = 1;
        srv.weight = 2;
        srv.port = 993;
        srv.ttl = 600;
        let rr = Rr::parse(&srv, &zone())?;
        assert_eq!(Rr::parse(&rr.to_raw(), &zone())?, rr);
        let json =
            serde_json::to_string(&rr.to_raw()).map_err(|e| Error::Internal(e.to_string()))?;
        assert!(json.contains(r#""type":"SRV""#), "{json}");
        Ok(())
    }

    #[test]
    fn relative_names_relate() {
        let z = zone();
        let www = RelName::parse("www", &z).unwrap();
        let a = RelName::parse("a.www", &z).unwrap();
        assert!(a.is_at_or_below(&www));
        assert!(www.is_at_or_below(&RelName::apex()));
        assert!(!www.is_at_or_below(&a));
        assert!(!RelName::parse("xwww", &z).unwrap().is_at_or_below(&www));
        assert_eq!(RelName::relative_to("a.www.example.com", &z), Some(a));
        assert_eq!(
            RelName::relative_to("example.com", &z),
            Some(RelName::apex())
        );
        assert_eq!(RelName::relative_to("xexample.com", &z), None);
    }
}
