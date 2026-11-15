//! The DNS records a mail domain needs.
//!
//! Local mode: MX to the mail host name; SPF allowing the mail host; the
//! DKIM key (and a retired one for a week); DMARC `p=none` to start;
//! `webmail`, `autoconfig` and `autodiscover` as CNAMEs of the mail host
//! name; SRV records for IMAPS, POP3S and submission (RFC 6186, 8314).
//! External mode: the provider's MX records only (its SPF, DKIM and
//! DMARC are the provider's to give; the customer adds them). Off: none.
//!
//! When the domain's zone is hosted here, these are engine-kept
//! (protected) records of the zone; otherwise they are what the customer
//! must create at its DNS provider.

use super::store::{MailDomainRecord, MailMode};
use crate::validate::Domain;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailRecord {
    /// Relative to the mail domain: `@`, `_dmarc`, `ox1._domainkey`, ...
    pub name: String,
    /// `MX`, `TXT`, `CNAME`, `SRV`.
    pub rtype: &'static str,
    /// MX/CNAME/SRV: the target host name; TXT: the text.
    pub value: String,
    /// MX preference or SRV priority.
    pub priority: u16,
    /// SRV only.
    pub weight: u16,
    pub port: u16,
}

impl MailRecord {
    fn new(name: &str, rtype: &'static str, value: String) -> Self {
        Self {
            name: name.to_owned(),
            rtype,
            value,
            priority: 0,
            weight: 0,
            port: 0,
        }
    }
}

/// The DKIM TXT value of a public key.
pub fn dkim_txt(public_key: &str) -> String {
    format!("v=DKIM1; k=rsa; p={public_key}")
}

pub const DMARC_TXT: &str = "v=DMARC1; p=none";

pub fn spf_txt(host: &Domain) -> String {
    format!("v=spf1 a:{host} ~all")
}

/// Every record `d` needs, relative to the domain. `now` decides which
/// retired DKIM keys are still published.
pub fn required(d: &MailDomainRecord, host: &Domain, now: u64) -> Vec<MailRecord> {
    let mut out = Vec::new();
    match d.mode {
        MailMode::Off => {}
        MailMode::External => {
            for (i, mx) in d.external_mx.iter().enumerate() {
                let mut r = MailRecord::new("@", "MX", mx.clone());
                r.priority = u16::try_from((i + 1) * 10).unwrap_or(u16::MAX);
                out.push(r);
            }
        }
        MailMode::Local => {
            let mut mx = MailRecord::new("@", "MX", host.to_string());
            mx.priority = 10;
            out.push(mx);
            out.push(MailRecord::new("@", "TXT", spf_txt(host)));
            // The signing key, a new key waiting to be seen in DNS, and
            // retired keys for their last week.
            for k in d.dkim.iter().chain(&d.dkim_pending).chain(
                d.dkim_retired
                    .iter()
                    .filter(|k| k.retire_at_unix.is_some_and(|t| t > now)),
            ) {
                out.push(MailRecord::new(
                    &format!("{}._domainkey", k.selector),
                    "TXT",
                    dkim_txt(&k.public_key),
                ));
            }
            out.push(MailRecord::new("_dmarc", "TXT", DMARC_TXT.to_owned()));
            for name in ["webmail", "autoconfig", "autodiscover"] {
                out.push(MailRecord::new(name, "CNAME", host.to_string()));
            }
            for (name, port) in [
                ("_imaps._tcp", 993),
                ("_pop3s._tcp", 995),
                ("_submissions._tcp", 465),
                ("_submission._tcp", 587),
            ] {
                let mut r = MailRecord::new(name, "SRV", host.to_string());
                r.weight = 1;
                r.port = port;
                out.push(r);
            }
        }
    }
    out
}

/// `name` (relative to `domain`) relative to `zone`, which is `domain` or a
/// parent of it.
pub fn relative_to_zone(name: &str, domain: &str, zone: &str) -> Option<String> {
    let fq = if name == "@" {
        domain.to_owned()
    } else {
        format!("{name}.{domain}")
    };
    if fq == zone {
        Some("@".to_owned())
    } else {
        fq.strip_suffix(&format!(".{zone}")).map(str::to_owned)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::mail::store::{DkimKey, RecordState};

    fn record(mode: MailMode) -> MailDomainRecord {
        MailDomainRecord {
            version: 1,
            domain: "shop.example.com".into(),
            tenant: "alice".into(),
            created_at_unix: 0,
            state: RecordState::Ready,
            mode,
            external_mx: vec![
                "aspmx.l.google.com".into(),
                "alt1.aspmx.l.google.com".into(),
            ],
            catch_all: None,
            dkim: Some(DkimKey {
                selector: "ox1".into(),
                public_key: "AAAB".into(),
                created_at_unix: 0,
                retire_at_unix: None,
            }),
            dkim_retired: vec![DkimKey {
                selector: "ox0".into(),
                public_key: "ZZZ".into(),
                created_at_unix: 0,
                retire_at_unix: Some(100),
            }],
            dkim_pending: None,
            mailboxes: std::collections::BTreeMap::default(),
            forwarders: std::collections::BTreeMap::default(),
        }
    }

    #[test]
    fn each_mode_gets_exactly_its_records() {
        let host = Domain::parse("mail.host.net").unwrap();
        let local = required(&record(MailMode::Local), &host, 50);
        let names: Vec<(&str, &str)> = local.iter().map(|r| (r.name.as_str(), r.rtype)).collect();
        assert_eq!(
            names,
            [
                ("@", "MX"),
                ("@", "TXT"),
                ("ox1._domainkey", "TXT"),
                ("ox0._domainkey", "TXT"),
                ("_dmarc", "TXT"),
                ("webmail", "CNAME"),
                ("autoconfig", "CNAME"),
                ("autodiscover", "CNAME"),
                ("_imaps._tcp", "SRV"),
                ("_pop3s._tcp", "SRV"),
                ("_submissions._tcp", "SRV"),
                ("_submission._tcp", "SRV"),
            ]
        );
        assert_eq!(local[1].value, "v=spf1 a:mail.host.net ~all");
        assert_eq!(local[2].value, "v=DKIM1; k=rsa; p=AAAB");
        // The retired key is gone once its week is over.
        assert_eq!(required(&record(MailMode::Local), &host, 200).len(), 11);
        let ext = required(&record(MailMode::External), &host, 0);
        assert_eq!(ext.len(), 2);
        assert_eq!(
            (ext[1].priority, ext[1].value.as_str()),
            (20, "alt1.aspmx.l.google.com")
        );
        assert!(required(&record(MailMode::Off), &host, 0).is_empty());
    }

    #[test]
    fn names_move_into_the_zone() {
        assert_eq!(
            relative_to_zone("@", "example.com", "example.com").as_deref(),
            Some("@")
        );
        assert_eq!(
            relative_to_zone("_dmarc", "shop.example.com", "example.com").as_deref(),
            Some("_dmarc.shop")
        );
        assert_eq!(
            relative_to_zone("@", "shop.example.com", "example.com").as_deref(),
            Some("shop")
        );
        assert_eq!(relative_to_zone("@", "example.org", "example.com"), None);
    }
}
