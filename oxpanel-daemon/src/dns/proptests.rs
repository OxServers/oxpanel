//! Property tests of the record validators and the zone renderer: whatever
//! a request carries, an accepted record renders as exactly one well-formed
//! zone-file line inside the zone, and a zone file holds exactly the lines
//! its records ask for.

use proptest::prelude::*;

use super::config::DnsConfig;
use super::rr::{RawRr, RelName, Rr, RrType};
use super::zone::{self, SiteName, ZoneInput};
use crate::validate::Domain;

/// A token of a zone-file line, and whether it was quoted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    text: String,
    quoted: bool,
}

/// Split a line the way the DNS server's master-file parser does for the
/// characters that matter: whitespace separates, `"…"` is one string in
/// which `\x` stands for `x`. `None` for a line that is not well-formed
/// (an unterminated string, a dangling escape).
fn tokenize(line: &str) -> Option<Vec<Token>> {
    let mut out = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c == ' ' {
            chars.next();
            continue;
        }
        if c == '"' {
            chars.next();
            let mut s = String::new();
            loop {
                match chars.next()? {
                    '\\' => s.push(chars.next()?),
                    '"' => break,
                    other => s.push(other),
                }
            }
            out.push(Token {
                text: s,
                quoted: true,
            });
        } else {
            let mut s = String::new();
            while let Some(&c) = chars.peek() {
                if c == ' ' || c == '"' {
                    break;
                }
                s.push(c);
                chars.next();
            }
            out.push(Token {
                text: s,
                quoted: false,
            });
        }
    }
    Some(out)
}

const TYPES: [RrType; 8] = [
    RrType::A,
    RrType::Aaaa,
    RrType::Cname,
    RrType::Mx,
    RrType::Txt,
    RrType::Srv,
    RrType::Caa,
    RrType::Ns,
];

/// Check one rendered record line: inside the zone, five fixed fields, no
/// unquoted syntax of the master-file format, and nothing but what the
/// record says.
fn check_line(line: &str, rr: &Rr, zone: &Domain) -> std::result::Result<(), String> {
    if line.contains('\n') || line.contains('\r') {
        return Err("line break".into());
    }
    let toks = tokenize(line).ok_or("not well-formed")?;
    if toks.len() < 5 {
        return Err("too few fields".into());
    }
    let owner = &toks[0].text;
    if toks[0].quoted || !(owner == &format!("{zone}.") || owner.ends_with(&format!(".{zone}."))) {
        return Err(format!("owner {owner} outside the zone"));
    }
    if toks[2].text != "IN" || toks[3].text != rr.data.rtype().as_str() {
        return Err("class or type".into());
    }
    for t in toks.iter().filter(|t| !t.quoted) {
        if t.text.starts_with('$') || t.text.contains([';', '(', ')', '"', '\\']) {
            return Err(format!("unquoted syntax in {t:?}"));
        }
    }
    if let super::rr::RData::Txt(v) = &rr.data {
        let joined: String = toks[4..].iter().map(|t| t.text.as_str()).collect();
        if toks[4..].iter().any(|t| !t.quoted || t.text.len() > 255) || joined != v.as_str() {
            return Err("TXT strings do not give back the value".into());
        }
    }
    Ok(())
}

fn any_text() -> impl Strategy<Value = String> {
    prop_oneof![
        ".*",
        "[ -~]{0,600}",
        "[a-z0-9_.*@-]{0,70}",
        Just("$INCLUDE /etc/shadow".to_owned()),
        Just("x\nevil. 1 IN A 1.2.3.4".to_owned()),
        Just("a\" ; (".to_owned()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Arbitrary input: refused, or exactly one well-formed line.
    #[test]
    fn any_accepted_record_is_one_clean_line(
        name in any_text(),
        t in 0usize..8,
        value in any_text(),
        ttl in prop_oneof![Just(0u32), 0u32..1_000_000],
        priority in 0u32..70_000,
        caa_flags in prop_oneof![Just(0u32), Just(128u32), 0u32..300],
        caa_tag in prop_oneof![Just("issue".to_owned()), Just("iodef".to_owned()), ".{0,10}"],
    ) {
        let zone = Domain::parse("example.com").unwrap();
        let raw = RawRr {
            name,
            rtype: Some(TYPES[t]),
            ttl,
            value,
            priority,
            weight: priority / 2,
            port: priority / 3,
            caa_flags,
            caa_tag,
        };
        if let Ok(rr) = Rr::parse(&raw, &zone) {
            let line = rr.render(&zone, 3600);
            prop_assert!(check_line(&line, &rr, &zone).is_ok(), "{:?}: {line}", check_line(&line, &rr, &zone));
            prop_assert_eq!(Rr::parse(&rr.to_raw(), &zone).ok(), Some(rr));
        }
    }

    /// Valid records of every kind: the zone file has exactly the header,
    /// the SOA, the engine's lines and one line per record — nothing else.
    #[test]
    fn a_zone_file_holds_exactly_what_was_asked(
        texts in proptest::collection::vec("[ -~]{0,700}", 0..6),
        labels in proptest::collection::vec("[a-z][a-z0-9-]{0,20}[a-z0-9]", 0..6),
        sites in proptest::collection::vec("[a-z][a-z0-9]{0,10}", 0..4),
    ) {
        let zone = Domain::parse("example.com").unwrap();
        let mut records = Vec::new();
        for (i, t) in texts.iter().enumerate() {
            let raw = RawRr { name: format!("_t{i}"), rtype: Some(RrType::Txt), value: t.clone(), ..RawRr::default() };
            records.push(Rr::parse(&raw, &zone).unwrap());
        }
        for l in &labels {
            let raw = RawRr { name: l.clone(), rtype: Some(RrType::Aaaa), value: "2001:db8::1".into(), ..RawRr::default() };
            records.push(Rr::parse(&raw, &zone).unwrap());
        }
        let sites: Vec<SiteName> = sites.iter().map(|s| SiteName { name: RelName::parse(s, &zone).unwrap(), site: "example.com".into() }).collect();
        let cfg = DnsConfig {
            nameservers: vec![Domain::parse("ns1.example.net").unwrap(), Domain::parse("ns2.example.net").unwrap()],
            soa_contact: "hostmaster@example.net".into(),
            ipv4: Some("203.0.113.10".parse().unwrap()),
            ..DnsConfig::default()
        };
        let input = ZoneInput { zone: &zone, cfg: &cfg, sites: &sites, records: &records };
        let text = zone::render(&input, 42);
        let lines: Vec<&str> = text.lines().collect();
        prop_assert_eq!(lines.len(), 2 + 2 + sites.len() + records.len());
        prop_assert_eq!(lines[0], zone::HEADER);
        prop_assert!(lines[1].starts_with("example.com. 3600 IN SOA ns1.example.net. hostmaster.example.net. 42 "));
        for (line, rr) in lines[lines.len() - records.len()..].iter().zip(&records) {
            prop_assert!(check_line(line, rr, &zone).is_ok(), "{line}");
        }
        prop_assert!(text.lines().skip(1).all(|l| !l.starts_with('$') && !l.starts_with(';')));
    }

    /// Owner names: accepted ones stay inside the zone and are made of
    /// labels only.
    #[test]
    fn names_stay_inside_the_zone(name in any_text()) {
        let zone = Domain::parse("example.com").unwrap();
        if let Ok(n) = RelName::parse(&name, &zone) {
            let fq = n.fqdn(&zone);
            prop_assert!(fq == "example.com" || fq.ends_with(".example.com"));
            prop_assert!(fq.len() <= 253);
            prop_assert!(fq.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_' | b'*')));
        }
    }

    /// The probe's parser never panics, whatever a server sends.
    #[test]
    fn hostile_responses_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        let _ = super::wire::decode(&bytes);
    }
}
