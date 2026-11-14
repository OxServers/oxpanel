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
