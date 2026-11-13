//! DNSSEC: what the registrar needs (DS and DNSKEY records), computed from
//! the *public* key files the DNS server writes for a signed zone.
//!
//! Keys are generated, stored and rolled by the DNS server itself (BIND's
//! `dnssec-policy`, see [`super::bind`]): the private halves stay in the
//! zone's key directory, owned by the server's account with mode 0600, and
//! the engine never opens them. It reads only `K<zone>+<alg>+<tag>.key`,
//! which holds the DNSKEY record in presentation form, and derives the DS
//! record (SHA-256, RFC 4509) and the key tag (RFC 4034 appendix B) itself.

use std::path::Path;

use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::fsutil;
use crate::validate::Domain;

/// The algorithm every signed zone uses: ECDSA P-256 with SHA-256 (13).
pub const ALGORITHM: u8 = 13;
pub const ALGORITHM_NAME: &str = "ECDSAP256SHA256 (13)";
pub const DENIAL: &str = "NSEC3 (no salt, 0 extra iterations, no opt-out)";
/// A key with the SEP bit: the one the parent's DS points at.
const FLAG_SEP: u16 = 0x0001;
const FLAG_ZONE: u16 = 0x0100;
const MAX_KEY_FILE: u64 = 16 * 1024;

/// A DNSKEY record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsKey {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

impl DnsKey {
    /// From the presentation form after `DNSKEY`: `257 3 13 <base64…>`.
    pub fn parse(fields: &[&str]) -> Option<Self> {
        let (flags, rest) = fields.split_first()?;
        let (protocol, rest) = rest.split_first()?;
        let (algorithm, rest) = rest.split_first()?;
        let b64: String = rest.concat();
        Some(Self {
            flags: flags.parse().ok()?,
            protocol: protocol.parse().ok()?,
            algorithm: algorithm.parse().ok()?,
            public_key: base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .ok()?,
        })
    }

    fn rdata(&self) -> Vec<u8> {
        let mut r = Vec::with_capacity(4 + self.public_key.len());
        r.extend_from_slice(&self.flags.to_be_bytes());
        r.push(self.protocol);
        r.push(self.algorithm);
        r.extend_from_slice(&self.public_key);
        r
    }

    pub fn is_key_signing(&self) -> bool {
        self.flags & FLAG_SEP != 0 && self.flags & FLAG_ZONE != 0
    }

    /// RFC 4034 appendix B.
    pub fn key_tag(&self) -> u16 {
        let mut ac: u32 = 0;
        for (i, b) in self.rdata().iter().enumerate() {
            ac += if i % 2 == 0 {
                u32::from(*b) << 8
            } else {
                u32::from(*b)
            };
        }
        ac += (ac >> 16) & 0xffff;
        u16::try_from(ac & 0xffff).unwrap_or(0)
    }

    /// The SHA-256 DS digest (upper-case hex) for `zone`.
    pub fn ds_digest(&self, zone: &Domain) -> String {
        let mut h = Sha256::new();
        for label in zone.as_str().split('.') {
            // Labels of a validated domain are 1..=63 bytes.
            h.update([u8::try_from(label.len()).unwrap_or(63)]);
            h.update(label.as_bytes());
        }
        h.update([0]);
        h.update(self.rdata());
        super::wire::hex_upper(&h.finalize())
    }

    /// `example.com. IN DS 29363 13 2 79D3…`
    pub fn ds_record(&self, zone: &Domain) -> String {
        format!(
            "{zone}. IN DS {} {} 2 {}",
            self.key_tag(),
            self.algorithm,
            self.ds_digest(zone)
        )
    }

    pub fn dnskey_record(&self, zone: &Domain) -> String {
        format!(
            "{zone}. IN DNSKEY {} {} {} {}",
            self.flags,
            self.protocol,
            self.algorithm,
            base64::engine::general_purpose::STANDARD.encode(&self.public_key)
        )
    }
}

/// The DNSKEY records in the text of a `.key` file (comments skipped).
pub fn parse_key_file(text: &str) -> Vec<DnsKey> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with(';'))
        .filter_map(|l| {
            let fields: Vec<&str> = l.split_whitespace().collect();
            let at = fields
                .iter()
                .position(|f| f.eq_ignore_ascii_case("DNSKEY"))?;
            DnsKey::parse(fields.get(at + 1..)?)
        })
        .collect()
}

/// The key-signing keys in a zone's key directory, by key tag. The files
/// belong to the DNS server's account: they are read without following
/// links, with a size bound, and only the public `.key` files.
pub fn key_signing_keys(key_dir: &Path) -> Result<Vec<DnsKey>> {
    let mut keys = Vec::new();
    for path in fsutil::list_files_with_suffix(key_dir, ".key")? {
        if let Some(bytes) = fsutil::read_untrusted(&path, MAX_KEY_FILE)? {
            keys.extend(
                parse_key_file(&String::from_utf8_lossy(&bytes))
                    .into_iter()
                    .filter(DnsKey::is_key_signing),
            );
        }
    }
    keys.sort_by_key(DnsKey::key_tag);
    keys.dedup();
    Ok(keys)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;

    /// Made by BIND 9.16 (`dnssec-policy`), DS from `dnssec-dsfromkey -2`.
    const KEY_FILE: &str = "; This is a key-signing key, keyid 29363, for example.com.
; Created: 20261113200415 (Fri Nov 13 20:04:15 2026)
example.com. 3600 IN DNSKEY 257 3 13 ojVvxeNn+jDXp4IEn3MFAEGpvWkGafaqWDICjTZhmoowSmtPAMaGnZ6u W6lcZgTCJKOfldsnn+s5IL50zkfVeA==
";

    #[test]
    fn ds_and_key_tag_match_the_dns_server_tools() {
        let zone = Domain::parse("example.com").unwrap();
        let keys = parse_key_file(KEY_FILE);
        assert_eq!(keys.len(), 1);
        let k = &keys[0];
        assert!(k.is_key_signing());
        assert_eq!(k.key_tag(), 29363);
        assert_eq!(
            k.ds_record(&zone),
            "example.com. IN DS 29363 13 2 79D38907566B83D16997F1187109BCD309C3DCC69E31F1286F7718C945E578CA"
        );
        assert!(k
            .dnskey_record(&zone)
            .starts_with("example.com. IN DNSKEY 257 3 13 ojVvxeNn+jDX"));
    }

    #[test]
    fn only_public_key_signing_keys_are_read() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Kexample.com.+013+29363.key"), KEY_FILE).unwrap();
        std::fs::write(
            dir.path().join("Kexample.com.+013+00001.key"),
            "example.com. 3600 IN DNSKEY 256 3 13 AAAA\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("Kexample.com.+013+29363.private"),
            "PrivateKey: secret",
        )
        .unwrap();
        let keys = key_signing_keys(dir.path()).unwrap();
        assert_eq!(
            keys.iter().map(DnsKey::key_tag).collect::<Vec<_>>(),
            vec![29363]
        );
        assert!(key_signing_keys(&dir.path().join("none"))
            .unwrap()
            .is_empty());
    }
}
