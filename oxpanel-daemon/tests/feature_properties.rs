//! Property tests of the validators and renderers the feature streams added
//! that `properties.rs` and `essentials_properties.rs` do not cover: SSH
//! public keys, key labels and the authorized-keys file the engine writes,
//! SFTP and database passwords, database names and every place a database
//! name or a tenant-chosen identifier reaches SQL, and the job, backup,
//! trash and upload identifiers that become file names. (Zone files are in
//! `src/dns/proptests.rs`, task units and PHP settings in
//! `essentials_properties.rs`, file-manager paths in `properties.rs`,
//! certificate PEM in `src/proptests.rs`.)
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use proptest::prelude::*;

use oxpanel_daemon::db::mariadb;
use oxpanel_daemon::php_settings::PhpLimits;
use oxpanel_daemon::records::{SftpKeyRecord, TenantRecord, TenantState};
use oxpanel_daemon::sftp::render_keys_file;
use oxpanel_daemon::validate::{
    BackupId, DbName, DbPassword, FileJobId, JobId, KeyFingerprint, KeyLabel, Limits, SftpPassword,
    SshPublicKey, TrashId, UploadId, Username,
};

const KEY_ED25519: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGNQ8nctDOzq4yQ8Bix4hfkkqCQw0kkYzl6hc7hg7rRo alice@laptop";
const KEY_ECDSA: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCPCQ5RPJL6Of0dEwqmMxFaxsEIMTgTuoqdjIkhuKJBRxt4u5xxce+n8yuTHQ+EVvhVfmIFaBrQ9IenhTvA47u8=";

fn any_text() -> impl Strategy<Value = String> {
    prop_oneof![
        ".{0,80}",
        "\\PC{0,80}",
        any::<Vec<u8>>().prop_map(|b| String::from_utf8_lossy(&b).into_owned()),
    ]
}

/// A valid key line, altered the way an attacker would: options in front,
/// a second line, a changed character, whitespace, a different type name.
fn near_key() -> impl Strategy<Value = String> {
    let base = prop_oneof![Just(KEY_ED25519.to_owned()), Just(KEY_ECDSA.to_owned())];
    (base, 0..9usize, any::<usize>(), "[ -~\n\r\t]{0,12}").prop_map(|(k, how, at, junk)| {
        let at = at % k.len();
        match how {
            0 => format!("{junk}{k}"),
            1 => format!("command=\"{junk}\",no-pty {k}"),
            2 => format!("{k}\n{junk}"),
            3 => {
                let mut s = k.into_bytes();
                s[at] = if s[at] == b'A' { b'B' } else { b'A' };
                String::from_utf8_lossy(&s).into_owned()
            }
            4 => k.replacen(' ', &format!(" {junk}"), 1),
            5 => k.replacen("ssh-", "ssh-dss-", 1),
            6 => format!("{k} {junk}"),
            7 => k[..at].to_owned(),
            _ => k,
        }
    })
}

fn tenant(keys: Vec<SftpKeyRecord>) -> TenantRecord {
    TenantRecord {
        version: 1,
        username: "alice".into(),
        uid: 20000,
        gid: 20000,
        home: PathBuf::from("/home/alice"),
        limits: Limits::default(),
        slice_unit: "oxpanel-tenant-alice.slice".into(),
        created_at_unix: 0,
        state: TenantState::Ready,
        owner: String::new(),
        suspended: false,
        sftp_keys: keys,
        sftp_password: false,
        php_limits: PhpLimits::default(),
    }
}

fn record_of(key: &SshPublicKey, label: &str) -> SftpKeyRecord {
    SftpKeyRecord {
        key_type: key.key_type().to_owned(),
        blob: key.blob().to_owned(),
        fingerprint: key.fingerprint().to_owned(),
        label: label.to_owned(),
        added_at_unix: 0,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn no_text_makes_a_feature_parser_panic(s in any_text()) {
        let _ = SshPublicKey::parse(&s);
        let _ = SshPublicKey::from_stored("ssh-ed25519", &s);
        let _ = KeyLabel::parse(&s);
        let _ = KeyFingerprint::parse(&s);
        let _ = SftpPassword::parse(&s);
        let _ = DbPassword::parse(&s);
        let _ = DbName::parse(&s, "name");
        let _ = BackupId::parse(&s);
        let _ = JobId::parse(&s);
        let _ = TrashId::parse(&s);
        let _ = FileJobId::parse(&s);
        let _ = UploadId::parse(&s);
        let _ = mariadb::quote(&s);
        let _ = mariadb::hex_text(&s);
        let _ = mariadb::parse_objects(&s);
        let _ = mariadb::pattern_matches(&s, &s);
    }

    /// An accepted key is one of the allowed types, carries no option, and
    /// is reduced to its canonical form: type, base64 blob, fingerprint.
    /// Re-reading the stored form gives the same key; nothing an attacker
    /// put around it survives.
    #[test]
    fn an_accepted_key_is_canonical_and_carries_no_option(s in near_key()) {
        if let Ok(k) = SshPublicKey::parse(&s) {
            prop_assert!(k.key_type().chars().all(|c| c.is_ascii_alphanumeric() || "-@.".contains(c)));
            prop_assert!(!k.key_type().contains("dss"));
            prop_assert!(k.blob().bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)));
            prop_assert!(KeyFingerprint::parse(k.fingerprint()).is_ok());
            let again = SshPublicKey::from_stored(k.key_type(), k.blob()).expect("stored form re-reads");
            prop_assert_eq!(again.fingerprint(), k.fingerprint());
            // The line started with the type: no option in front.
            prop_assert!(s.trim_start().starts_with(k.key_type()));
            prop_assert!(!s.trim().contains('\n'));
            if let Some(c) = k.comment() {
                prop_assert!(KeyLabel::parse(c.as_str()).is_ok());
            }
        }
    }

    /// A label is a plain token: it can neither start a new line nor a new
    /// field in the authorized-keys file.
    #[test]
    fn an_accepted_label_is_a_plain_token(s in prop_oneof!["[A-Za-z0-9@._+-]{0,70}", any_text()]) {
        if KeyLabel::parse(&s).is_ok() {
            prop_assert!(!s.is_empty() && s.len() <= 64);
            prop_assert!(s.bytes().all(|b| b.is_ascii_graphic() && !b"\"'\\,=#".contains(&b)));
        }
    }

    /// The authorized-keys file is its header plus exactly one `restrict`
    /// line per key, whatever the records say; a record with a hostile
    /// label or a blob that is not its fingerprint's is never rendered.
    #[test]
    fn the_keys_file_is_one_restricted_line_per_key(labels in proptest::collection::vec(prop_oneof!["[a-z@.]{0,10}", any_text()], 0..4), tamper in any::<bool>()) {
        let a = SshPublicKey::parse(KEY_ED25519).unwrap();
        let b = SshPublicKey::parse(KEY_ECDSA).unwrap();
        let mut keys: Vec<SftpKeyRecord> = labels.iter().enumerate().map(|(i, l)| record_of(if i % 2 == 0 { &a } else { &b }, l)).collect();
        if tamper {
            if let Some(k) = keys.first_mut() {
                k.blob.push_str("\nrestrict,command=\"/bin/sh\" ssh-ed25519 AAAA");
            }
        }
        match render_keys_file(&tenant(keys.clone())) {
            Ok(text) => {
                let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
                prop_assert_eq!(lines.len(), keys.len(), "{}", text);
                for (l, k) in lines.iter().zip(&keys) {
                    prop_assert!(l.starts_with("restrict "), "{}", l);
                    let words: Vec<&str> = l.split(' ').collect();
                    prop_assert!(words.len() == 3 || words.len() == 4, "{}", l);
                    prop_assert_eq!(words[2], k.blob.as_str());
                }
                prop_assert!(!tamper || keys.is_empty());
                for k in &keys {
                    prop_assert!(k.label.is_empty() || KeyLabel::parse(&k.label).is_ok());
                }
            }
            Err(_) => prop_assert!(tamper || keys.iter().any(|k| !k.label.is_empty() && KeyLabel::parse(&k.label).is_err())),
        }
    }

    /// Passwords go to `chpasswd` and the database server on stdin, one per
    /// line: an accepted one has no control character (no second line).
    #[test]
    fn an_accepted_password_is_one_line(s in prop_oneof![".{0,300}", "[ -~]{10,40}", "[a-z]{6,20}[\n\r\0\t][a-z]{1,8}", any_text()]) {
        for ok in [SftpPassword::parse(&s).is_ok(), DbPassword::parse(&s).is_ok()] {
            if ok {
                prop_assert!(!s.chars().any(char::is_control));
                prop_assert!(!s.is_empty() && s.chars().count() <= 256);
            }
        }
        if let Ok(p) = SftpPassword::parse(&s) {
            let shown = format!("{p:?}");
            prop_assert!(!shown.contains(&s) || s.is_empty());
        }
    }

    /// A database name belongs to exactly one tenant: `<tenant>_<suffix>`
    /// with a suffix of lowercase letters and digits. It is safe in every
    /// SQL position the engine uses it in, and a grant on it covers no other
    /// tenant's database.
    #[test]
    fn a_database_name_is_safe_and_belongs_to_its_tenant(
        s in prop_oneof!["[a-z][a-z0-9_-]{0,12}_[a-z0-9]{1,12}", "[a-z_%\\\\`'\";. -]{1,30}", any_text()],
        other in "[a-z][a-z0-9_-]{0,10}_[a-z0-9_%]{1,10}",
    ) {
        if let Ok(n) = DbName::parse(&s, "name") {
            let t = n.tenant().as_str();
            prop_assert_eq!(n.as_str(), s.as_str());
            let prefix = format!("{t}_");
            prop_assert!(s.starts_with(&prefix));
            prop_assert!(s[t.len() + 1..].bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()));
            prop_assert!(s.len() <= 64);
            prop_assert!(!s.contains(['`', '\'', '"', '\\', ';', ' ', '%', '\n']));
            let owner = Username::parse(t).unwrap();
            prop_assert!(DbName::parse_for(&s, &owner, "name").is_ok());
            // The account literal has exactly the two quoted parts.
            let acct = mariadb::account(&n);
            prop_assert_eq!(acct.matches('\'').count(), 4, "{}", acct);
            // The grant pattern matches the name and nothing of another tenant.
            let pat = mariadb::grant_pattern(&n);
            prop_assert!(mariadb::pattern_matches(&pat, &s));
            if other != s {
                prop_assert!(!mariadb::pattern_matches(&pat, &other), "{} matches {}", pat, other);
            }
        }
    }

    /// A name a tenant chose (a table, a trigger, a routine) is quoted so
    /// that it stays one identifier: inside the outer back-quotes every
    /// back-quote is doubled. Text a tenant wrote is a hex literal.
    #[test]
    fn tenant_identifiers_and_text_stay_inert(s in any_text()) {
        let q = mariadb::quote(&s);
        prop_assert!(q.starts_with('`') && q.ends_with('`'));
        let inner = &q[1..q.len() - 1];
        prop_assert_eq!(inner.replace("``", ""), s.replace('`', ""));
        prop_assert!(!inner.replace("``", "").contains('`'));
        let h = mariadb::hex_text(&s);
        let body = h.strip_prefix("CONVERT(X'").and_then(|r| r.strip_suffix("' USING utf8mb4)")).expect("shape");
        prop_assert!(body.bytes().all(|b| b.is_ascii_hexdigit()));
        prop_assert_eq!(body.len(), s.len() * 2);
    }

    /// Identifiers of jobs, backups, trash items and uploads become file
    /// and unit names: an accepted one is a letter and digits, nothing else.
    #[test]
    fn identifiers_are_safe_file_names(s in prop_oneof!["[bjtfu][0-9]{8,22}", "[a-z]{0,2}[0-9./\\-\n]{0,24}", any_text()]) {
        for ok in [
            BackupId::parse(&s).is_ok(),
            JobId::parse(&s).is_ok(),
            TrashId::parse(&s).is_ok(),
            FileJobId::parse(&s).is_ok(),
            UploadId::parse(&s).is_ok(),
        ] {
            if ok {
                prop_assert!((11..=21).contains(&s.len()));
                prop_assert!(s[1..].bytes().all(|b| b.is_ascii_digit()));
                prop_assert!(s.as_bytes()[0].is_ascii_lowercase());
            }
        }
    }
}

// ---- Email ------------------------------------------------------------------------

mod mail {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use proptest::prelude::*;

    use oxpanel_daemon::mail::policy::{self, SubmitRequest};
    use oxpanel_daemon::mail::render::{self, Account, Model};
    use oxpanel_daemon::mail::store::{
        AutoreplyRecord, ForwarderRecord, MailDomainRecord, MailMode, MailboxRecord, RecordState,
    };
    use oxpanel_daemon::validate::{
        AutoreplyBody, AutoreplySubject, Domain, MailAddress, MailDestination, MailLocalPart,
        MailPassword, QueueId,
    };

    use super::any_text;

    fn local_like() -> impl Strategy<Value = String> {
        prop_oneof![
            "[a-z0-9._+=-]{0,70}",
            "[A-Za-z0-9._+=\"@ <>\\-\n\r]{0,20}",
            any_text()
        ]
    }

    const HASH: &str = "{BLF-CRYPT}$2y$04$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01234";

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// An accepted local part is plain text a map, a path, a Sieve
        /// string and an argument can all carry.
        #[test]
        fn local_parts_are_plain(s in local_like()) {
            if let Ok(l) = MailLocalPart::parse(&s) {
                let t = l.as_str();
                prop_assert!((1..=64).contains(&t.len()));
                prop_assert!(t.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)));
                prop_assert!(!t.starts_with(['.', '-', '_']) && !t.ends_with(['.', '-', '_']));
                prop_assert!(!t.contains(".."));
            }
        }

        /// Addresses and destinations: one `@`, no space, no line break, no
        /// quote, no angle bracket — nothing that could end a map field or
        /// an SMTP command.
        #[test]
        fn addresses_and_destinations_are_single_tokens(l in local_like(), d in prop_oneof!["[a-z0-9.-]{1,30}", any_text()]) {
            let raw = format!("{l}@{d}");
            if let Ok(a) = MailAddress::parse(&raw) {
                prop_assert_eq!(a.to_string(), raw.clone());
            }
            if let Ok(dest) = MailDestination::parse(&raw) {
                let t = dest.as_str();
                prop_assert_eq!(t.matches('@').count(), 1);
                prop_assert!(t.bytes().all(|b| b.is_ascii_graphic() && !b"<>\",;\\()".contains(&b)));
                prop_assert!(policy::plain_address(t));
                let again = MailDestination::parse(t).unwrap();
                prop_assert_eq!(again.as_str(), t);
            }
        }

        /// A password is never shorter than 10 characters, never longer
        /// than 72 bytes and never holds a control character.
        #[test]
        fn passwords_are_bounded(p in any_text()) {
            let local = MailLocalPart::parse("info").unwrap();
            let domain = Domain::parse("example.com").unwrap();
            if let Ok(pw) = MailPassword::parse(&p, &local, &domain) {
                prop_assert!(p.chars().count() >= 10 && p.len() <= 72);
                prop_assert!(!p.chars().any(char::is_control));
                let shown = format!("{pw:?}");
                prop_assert!(!shown.contains(&p));
            }
        }

        #[test]
        fn queue_ids_are_letters_and_digits(s in prop_oneof!["[A-Za-z0-9]{3,24}", any_text()]) {
            if let Ok(q) = QueueId::parse(&s) {
                prop_assert!(q.as_str().bytes().all(|b| b.is_ascii_alphanumeric()));
                prop_assert!(!q.as_str().starts_with('-'));
            }
        }

        /// Whatever text an autoresponder is given, its script has exactly
        /// one vacation command and the text comes back from the Sieve
        /// string unchanged (no early end of string, no injected command).
        #[test]
        fn sieve_scripts_hold_the_text_and_nothing_else(subject in any_text(), body in any_text()) {
            let (Ok(s), Ok(b)) = (AutoreplySubject::parse(&subject), AutoreplyBody::parse(&body)) else {
                return Ok(());
            };
            prop_assert!(!s.as_str().contains(['\n', '\r']));
            let r = AutoreplyRecord {
                enabled: true,
                subject: s.as_str().to_owned(),
                body: b.as_str().to_owned(),
                starts_at_unix: Some(1_800_000_000),
                ends_at_unix: None,
            };
            let script = render::sieve_script("info@example.com", &r);
            let parsed = sieve_strings(&script);
            prop_assert!(parsed.contains(&r.subject), "subject lost: {script}");
            prop_assert!(parsed.contains(&r.body), "body lost: {script}");
            // Outside the strings, the script is always the same.
            let skeleton = strip_strings(&script);
            prop_assert_eq!(skeleton.matches("vacation").count(), 1, "{}", skeleton);
            prop_assert_eq!(skeleton.matches(';').count(), 3, "{}", skeleton);
        }

        /// The maps and password files have exactly one line per entry,
        /// whatever (valid) names the records hold.
        #[test]
        fn maps_have_one_line_per_entry(
            locals in proptest::collection::btree_set("[a-z][a-z0-9._-]{0,10}[a-z0-9]", 1..6),
            dests in proptest::collection::vec("[a-z][a-z0-9+=._-]{0,8}@[a-z]{1,8}\\.org", 1..4),
            suspended in any::<bool>(),
        ) {
            let locals: Vec<String> = locals.into_iter().filter(|l| MailLocalPart::parse(l).is_ok()).collect();
            prop_assume!(!locals.is_empty());
            let dests: Vec<String> = dests.into_iter().filter_map(|d| MailDestination::parse(&d).ok()).map(|d| d.to_string()).collect();
            prop_assume!(!dests.is_empty());
            let mut rec = MailDomainRecord {
                version: 1,
                domain: "example.com".into(),
                tenant: "alice".into(),
                created_at_unix: 0,
                state: RecordState::Ready,
                mode: MailMode::Local,
                external_mx: vec![],
                catch_all: None,
                dkim: None,
                dkim_retired: vec![],
                mailboxes: BTreeMap::new(),
                forwarders: BTreeMap::new(),
            };
            for l in &locals {
                rec.mailboxes.insert(l.clone(), MailboxRecord {
                    state: RecordState::Ready,
                    quota_bytes: 0,
                    password_hash: HASH.into(),
                    enabled: true,
                    created_at_unix: 0,
                    autoreply: None,
                });
            }
            rec.forwarders.insert("fwd-x".into(), ForwarderRecord { destinations: dests.clone(), keep_copy: false });
            rec.validate().unwrap();
            let m = Model {
                hostname: Domain::parse("mail.host.net").unwrap(),
                accounts: BTreeMap::from([("alice".to_owned(), Account {
                    name: "alice".into(),
                    uid: 20000,
                    gid: 20000,
                    home: PathBuf::from("/home/alice"),
                    suspended,
                    rate_account: 1,
                    rate_mailbox: 1,
                    sender_domains: std::collections::BTreeSet::default(),
                })]),
                domains: vec![rec],
                cert: PathBuf::from("/c"),
                key: PathBuf::from("/k"),
                uid_min: 20000,
                uid_max: 29999,
            };
            let maps = render::postfix_maps(&m);
            let body = |s: &str| s.lines().filter(|l| !l.starts_with('#')).count();
            prop_assert_eq!(body(&maps["mailboxes"]), locals.len());
            prop_assert_eq!(body(&maps["aliases"]), locals.len() + 1);
            prop_assert_eq!(body(&maps["senders"]), if suspended { 0 } else { locals.len() });
            prop_assert_eq!(body(&maps["recipient_access"]), usize::from(suspended));
            for (name, text) in maps.iter().filter(|(n, _)| **n != "recipient_access") {
                for l in text.lines().filter(|l| !l.starts_with('#')) {
                    let _ = name;
                    prop_assert_eq!(l.split(' ').count(), 2, "{}", l);
                }
            }
            let files = render::dovecot_files(&m).unwrap();
            prop_assert_eq!(files["passwd"].lines().count(), locals.len());
            prop_assert_eq!(files["users"].lines().count(), locals.len());
            for l in files["users"].lines() {
                prop_assert_eq!(l.split(':').count(), 9, "{}", l);
            }
        }

        /// The policy service's parsers never panic, and what they make of
        /// any message is either refused or plain addresses and CRLF lines.
        #[test]
        fn site_messages_never_smuggle_commands(
            msg in prop_oneof![any::<Vec<u8>>(), "(([A-Za-z-]{1,8}: [ -~]{0,30}|[ \t][ -~]{0,10})\r?\n){0,6}\r?\n[ -~\r\n.]{0,60}".prop_map(String::into_bytes)],
            sender in proptest::option::of(local_like()),
            extract in any::<bool>(),
            rcpt in proptest::collection::vec(local_like(), 0..3),
        ) {
            let _ = policy::addresses(&String::from_utf8_lossy(&msg));
            let req = SubmitRequest { sender, recipients: rcpt, extract };
            if let Ok(m) = policy::prepare(&req, &msg) {
                prop_assert!(policy::plain_address(&m.sender));
                for r in &m.recipients {
                    prop_assert!(policy::plain_address(r));
                }
                prop_assert!(!(1..=policy::MAX_SITE_RECIPIENTS).contains(&0));
                prop_assert!(m.recipients.len() <= policy::MAX_SITE_RECIPIENTS);
                let data = policy::smtp_data(&m.message);
                prop_assert!(data.ends_with(b"\r\n.\r\n"));
                // Every line of the data ends with CRLF and no line is a lone dot
                // before the end.
                let body = &data[..data.len() - 3];
                for line in body.split(|b| *b == b'\n') {
                    if !line.is_empty() {
                        prop_assert!(line.ends_with(b"\r") || line.is_empty());
                    }
                    prop_assert_ne!(line, b".\r");
                }
            }
        }
    }

    /// The contents of the Sieve strings of a script.
    fn sieve_strings(script: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur: Option<String> = None;
        let mut esc = false;
        for c in script.chars() {
            match (&mut cur, c) {
                (Some(s), _) if esc => {
                    s.push(c);
                    esc = false;
                }
                (Some(_), '\\') => esc = true,
                (Some(_), '"') => out.push(cur.take().unwrap_or_default()),
                (Some(s), _) => s.push(c),
                (None, '"') => cur = Some(String::new()),
                (None, _) => {}
            }
        }
        out
    }

    fn strip_strings(script: &str) -> String {
        let mut out = String::new();
        let (mut inside, mut esc) = (false, false);
        for c in script.chars() {
            if inside {
                if esc {
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else if c == '"' {
                    inside = false;
                    out.push_str("\"\"");
                }
            } else if c == '"' {
                inside = true;
            } else if c != '#' || !out.ends_with('\n') && !out.is_empty() {
                out.push(c);
            }
        }
        out
    }
}
