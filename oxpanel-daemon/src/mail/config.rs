//! Host-wide email settings (`OXPANEL_MAIL_*`).
//!
//! Email is off until the operator installs the mail component
//! (`install.sh --mail`) and switches it on, because it needs a fact only
//! the operator knows: the host name mail clients connect to, which must
//! resolve to this host and should be its reverse DNS name.

use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::validate::Domain;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailConfig {
    /// `OXPANEL_MAIL`: host the accounts' email.
    pub enabled: bool,
    /// `OXPANEL_MAIL_HOSTNAME`: the host name of the mail server (SMTP
    /// banner, the certificate, MX targets, client settings).
    pub hostname: Option<Domain>,
    /// `OXPANEL_MAIL_WEBMAIL`: serve Roundcube as `webmail.<domain>`
    /// (default on; nothing is served when Roundcube is not installed).
    pub webmail: bool,
    /// `OXPANEL_MAIL_ANTIVIRUS`: scan mail with ClamAV through the filter
    /// (default off: ClamAV needs about 1 GB of memory).
    pub antivirus: bool,
    /// `OXPANEL_MAIL_MAX_MAILBOXES`: mailboxes per account unless the
    /// account has its own limit (0 = unlimited).
    pub max_mailboxes: u32,
    /// `OXPANEL_MAIL_MAX_MAILBOX_BYTES`: largest mailbox size (0 = unlimited).
    pub max_mailbox_bytes: u64,
    /// `OXPANEL_MAIL_RATE_ACCOUNT` / `OXPANEL_MAIL_RATE_MAILBOX`: recipients
    /// per clock hour an account (all its mailboxes and sites) and one
    /// mailbox may send to (0 = unlimited).
    pub rate_account: u32,
    pub rate_mailbox: u32,
    /// `OXPANEL_MAIL_MESSAGE_MAX_BYTES`: largest message accepted.
    pub message_max_bytes: u64,
    /// `OXPANEL_MAIL_PORT25_CHECK`: a public mail server whose port 25
    /// `GetMailHost` tries to reach, to warn when the provider blocks
    /// outbound SMTP (default `gmail-smtp-in.l.google.com`; `off`: never
    /// tried, no such warning).
    pub port25_check: Option<Domain>,
    /// Fixed locations (tests move them).
    pub postfix_dir: PathBuf,
    pub dovecot_dir: PathBuf,
    pub rspamd_dir: PathBuf,
    /// Root-owned state the mail services read: DKIM keys, autoresponder
    /// scripts, the policy service's map and counters.
    pub state_dir: PathBuf,
    /// Roundcube's configuration and its PHP-FPM pool.
    pub webmail_dir: PathBuf,
    /// Roundcube's database and temporary files.
    pub webmail_data_dir: PathBuf,
    /// The one Nginx file with the webmail, autoconfiguration and mail host
    /// name servers.
    pub nginx_file: PathBuf,
    /// Sockets of the policy service (the sendmail socket and Postfix's
    /// policy socket).
    pub run_dir: PathBuf,
    /// The filter's milter socket directory: `_rspamd:postfix 0750`, so no
    /// local process other than Postfix (and the filter) can reach it.
    pub milter_dir: PathBuf,
    /// Certificates of the mail names (root-only): the mail host name's and
    /// the webmail names' (`<name>.crt`, `<name>.key`, obtained like the
    /// sites' through ACME), and the self-signed one used until the mail host
    /// name has a real one. Apart from the sites' (`/etc/pki/oxpanel`).
    pub selfsigned_dir: PathBuf,
    /// Roundcube's front page as packaged: webmail is offered when it exists.
    pub roundcube_index: PathBuf,
    /// bcrypt cost of mailbox password hashes. Not configurable from the
    /// environment: always [`super::password::COST`] in production; tests
    /// lower it to keep debug builds fast.
    pub password_cost: u32,
}

impl Default for MailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hostname: None,
            webmail: true,
            antivirus: false,
            max_mailboxes: 0,
            max_mailbox_bytes: 0,
            rate_account: 500,
            rate_mailbox: 200,
            message_max_bytes: 25 * 1024 * 1024,
            port25_check: Domain::parse(DEFAULT_PORT25_CHECK).ok(),
            postfix_dir: PathBuf::from("/etc/postfix"),
            dovecot_dir: PathBuf::from("/etc/dovecot"),
            rspamd_dir: PathBuf::from("/etc/rspamd"),
            state_dir: PathBuf::from("/var/lib/oxpanel-mail"),
            webmail_dir: PathBuf::from("/etc/oxpanel-webmail"),
            webmail_data_dir: PathBuf::from("/var/lib/oxpanel-webmail"),
            nginx_file: PathBuf::from("/etc/nginx/conf.d/oxpanel-mail.conf"),
            run_dir: PathBuf::from("/run/oxpanel-mail"),
            milter_dir: PathBuf::from("/var/spool/postfix/oxpanel-milter"),
            selfsigned_dir: PathBuf::from("/etc/pki/oxpanel-mail"),
            roundcube_index: PathBuf::from("/usr/share/roundcubemail/public_html/index.php"),
            password_cost: super::password::COST,
        }
    }
}

pub const DEFAULT_PORT25_CHECK: &str = "gmail-smtp-in.l.google.com";

fn bad(key: &str, why: impl std::fmt::Display) -> Error {
    Error::invalid("config", format!("{key}: {why}"))
}

fn parse_bool(key: &str, raw: &str) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        _ => Err(bad(key, format!("'{raw}' is not a boolean"))),
    }
}

impl MailConfig {
    /// Read the `OXPANEL_MAIL_*` settings.
    pub fn from_lookup(get: &impl Fn(&str) -> Option<String>) -> Result<Self> {
        let mut c = Self::default();
        if let Some(v) = get("OXPANEL_MAIL") {
            c.enabled = parse_bool("OXPANEL_MAIL", &v)?;
        }
        if let Some(v) = get("OXPANEL_MAIL_HOSTNAME").filter(|v| !v.trim().is_empty()) {
            c.hostname =
                Some(Domain::parse(v.trim().trim_end_matches('.')).map_err(|_| {
                    bad("OXPANEL_MAIL_HOSTNAME", format!("'{v}' is not a host name"))
                })?);
        }
        if let Some(v) = get("OXPANEL_MAIL_WEBMAIL") {
            c.webmail = parse_bool("OXPANEL_MAIL_WEBMAIL", &v)?;
        }
        if let Some(v) = get("OXPANEL_MAIL_ANTIVIRUS") {
            c.antivirus = parse_bool("OXPANEL_MAIL_ANTIVIRUS", &v)?;
        }
        if let Some(v) = get("OXPANEL_MAIL_PORT25_CHECK") {
            let v = v.trim().trim_end_matches('.');
            c.port25_check = if v.is_empty() || v.eq_ignore_ascii_case("off") {
                None
            } else {
                Some(Domain::parse(v).map_err(|_| {
                    bad(
                        "OXPANEL_MAIL_PORT25_CHECK",
                        format!("'{v}' is not a host name (or off)"),
                    )
                })?)
            };
        }
        for (key, target) in [
            ("OXPANEL_MAIL_MAX_MAILBOXES", &mut c.max_mailboxes),
            ("OXPANEL_MAIL_RATE_ACCOUNT", &mut c.rate_account),
            ("OXPANEL_MAIL_RATE_MAILBOX", &mut c.rate_mailbox),
        ] {
            if let Some(v) = get(key) {
                *target = v
                    .trim()
                    .parse()
                    .map_err(|_| bad(key, format!("'{v}' is not an unsigned integer")))?;
            }
        }
        for (key, target) in [
            ("OXPANEL_MAIL_MAX_MAILBOX_BYTES", &mut c.max_mailbox_bytes),
            ("OXPANEL_MAIL_MESSAGE_MAX_BYTES", &mut c.message_max_bytes),
        ] {
            if let Some(v) = get(key) {
                *target = v
                    .trim()
                    .parse()
                    .map_err(|_| bad(key, format!("'{v}' is not an unsigned integer")))?;
            }
        }
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&self) -> Result<()> {
        if !(1024 * 1024..=200 * 1024 * 1024).contains(&self.message_max_bytes) {
            return Err(bad(
                "OXPANEL_MAIL_MESSAGE_MAX_BYTES",
                "must be 1 MiB ..= 200 MiB",
            ));
        }
        if self.enabled && self.hostname.is_none() {
            return Err(bad(
                "OXPANEL_MAIL_HOSTNAME",
                "email needs the host name mail clients and other servers reach this host by (e.g. mail.example.net); it should resolve to this host and be its reverse DNS name",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn from(pairs: &[(&str, &str)]) -> Result<MailConfig> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        MailConfig::from_lookup(&|k| m.get(k).cloned())
    }

    #[test]
    fn email_is_off_by_default_and_needs_a_host_name_when_on() {
        let c = from(&[]).unwrap();
        assert!(!c.enabled);
        assert!(c.webmail && !c.antivirus);
        assert!(from(&[("OXPANEL_MAIL", "yes")]).is_err());
        let c = from(&[
            ("OXPANEL_MAIL", "yes"),
            ("OXPANEL_MAIL_HOSTNAME", "mail.example.net."),
            ("OXPANEL_MAIL_RATE_ACCOUNT", "1000"),
            ("OXPANEL_MAIL_ANTIVIRUS", "on"),
        ])
        .unwrap();
        assert_eq!(c.hostname.unwrap().as_str(), "mail.example.net");
        assert_eq!(c.rate_account, 1000);
        assert!(c.antivirus);
        assert!(from(&[("OXPANEL_MAIL_HOSTNAME", "not a name")]).is_err());
        assert!(from(&[("OXPANEL_MAIL_RATE_MAILBOX", "-1")]).is_err());
        assert!(from(&[("OXPANEL_MAIL_MESSAGE_MAX_BYTES", "10")]).is_err());
        assert_eq!(
            from(&[]).unwrap().port25_check.unwrap().as_str(),
            DEFAULT_PORT25_CHECK
        );
        assert_eq!(
            from(&[("OXPANEL_MAIL_PORT25_CHECK", "off")])
                .unwrap()
                .port25_check,
            None
        );
        assert_eq!(
            from(&[("OXPANEL_MAIL_PORT25_CHECK", "mx.example.org")])
                .unwrap()
                .port25_check
                .unwrap()
                .as_str(),
            "mx.example.org"
        );
        assert!(from(&[("OXPANEL_MAIL_PORT25_CHECK", "a b")]).is_err());
    }
}
