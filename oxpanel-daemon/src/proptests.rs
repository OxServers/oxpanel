//! Property tests of crate-private parsers: text that comes back from the
//! operating system (log files, `systemctl show`) or from configuration, and
//! is therefore not under the daemon's control.

use std::path::Path;

use proptest::prelude::*;

use crate::nginx::safe_path_str;
use crate::tenant::parse_cgroup_usage;
use crate::tls::{normalise_pem, PemKind};
use crate::vhost::tail_file;

proptest! {
    /// A log file holds whatever clients sent: any bytes, any length. The
    /// tail is never more than was asked for, starts at a line boundary when
    /// the file was cut, and reading never fails or panics on content.
    #[test]
    fn the_tail_of_any_file_is_bounded_and_starts_at_a_line(
        content in proptest::collection::vec(any::<u8>(), 0..4096),
        limit in 1u64..5000,
    ) {
        let dir = tempfile::tempdir().map_err(|e| TestCaseError::fail(e.to_string()))?;
        let path = dir.path().join("x.log");
        std::fs::write(&path, &content).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let (text, truncated) = tail_file(&path, limit).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let len = content.len() as u64;
        prop_assert_eq!(truncated, len > limit);
        if truncated {
            let start = usize::try_from(len - limit).unwrap_or(0);
            let window = String::from_utf8_lossy(content.get(start..).unwrap_or_default()).into_owned();
            // Everything returned is the end of the window, after its first line break.
            prop_assert!(window.ends_with(&text));
            match window.find('\n') {
                Some(i) => prop_assert_eq!(text.as_str(), window.get(i + 1..).unwrap_or_default()),
                None => prop_assert!(text.is_empty()),
            }
        } else {
            prop_assert_eq!(text, String::from_utf8_lossy(&content).into_owned());
        }
    }

    #[test]
    fn a_missing_log_is_empty_not_an_error(name in "[a-z]{1,12}", limit in any::<u64>()) {
        let dir = tempfile::tempdir().map_err(|e| TestCaseError::fail(e.to_string()))?;
        let got = tail_file(&dir.path().join(name), limit).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(got, (String::new(), false));
    }

    /// `systemctl show` output is parsed line by line; nothing in it can
    /// panic the parser or overflow the sums.
    #[test]
    fn any_systemctl_output_parses_without_overflow(
        text in prop_oneof![
            ".{0,200}",
            "((MemoryCurrent|CPUUsageNSec|TasksCurrent|Other)=([0-9]{1,25}|\\[not set\\]|-1|18446744073709551615| )\n){0,12}",
        ]
    ) {
        let (mem, cpu, tasks) = parse_cgroup_usage(&text);
        // 2^64-1 is systemd's "not set": it never counts.
        if text.lines().all(|l| !l.starts_with("MemoryCurrent=")) {
            prop_assert_eq!(mem, 0);
        }
        let _ = (cpu, tasks);
    }

    /// Whatever passes `safe_path_str` cannot end or extend a directive in
    /// Nginx, a unit file or an FPM configuration.
    #[test]
    fn a_path_that_passes_is_plain(s in prop_oneof![".{0,60}", "/[A-Za-z0-9._/-]{0,60}", "/[a-z]{1,8}[ ;\n{}$\"'#=][a-z]{1,8}"]) {
        if let Ok(ok) = safe_path_str(Path::new(&s)) {
            prop_assert_eq!(ok, s.as_str());
            prop_assert!(s.starts_with('/'));
            prop_assert!(s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-')));
        }
    }
}

/// PEM documents as an uploader could shape them: real blocks with text,
/// directives and other blocks around and between them, odd boundaries.
fn near_pem() -> impl Strategy<Value = String> {
    let block = |label: &'static str| {
        "[A-Za-z0-9+/]{4,200}={0,2}".prop_map(move |b| {
            let wrapped: Vec<String> = b
                .as_bytes()
                .chunks(64)
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .collect();
            format!(
                "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
                wrapped.join("\n")
            )
        })
    };
    let junk = prop_oneof![
        Just(String::new()),
        Just("}\nserver { listen 8444; root /; }\n".to_owned()),
        Just("ssl_certificate /etc/shadow;\n".to_owned()),
        Just("Bag Attributes\n    friendlyName: x\n".to_owned()),
        Just("-----BEGIN CERTIFICATE-----\n".to_owned()),
        Just("-----END CERTIFICATE-----\n".to_owned()),
        Just("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n".to_owned()),
        ".{0,40}\n",
    ];
    let piece = prop_oneof![
        block("CERTIFICATE"),
        block("PRIVATE KEY"),
        block("EC PRIVATE KEY"),
        block("RSA PRIVATE KEY"),
        block("CERTIFICATE REQUEST"),
        block("X509 CRL"),
        junk,
    ];
    proptest::collection::vec(piece, 0..6).prop_map(|v| v.concat())
}

proptest! {
    /// Uploaded certificate chains and keys end up in files Nginx reads and
    /// next to its configuration: whatever is accepted is only BEGIN/END
    /// lines of the expected kinds and base64 lines of at most 64 columns —
    /// nothing a configuration parser could take for a directive — and
    /// normalising again changes nothing.
    #[test]
    fn accepted_pem_is_only_blocks_of_the_expected_kind(s in prop_oneof![near_pem(), ".{0,200}"], kind in 0..3usize) {
        let kind = match kind { 0 => PemKind::Chain, 1 => PemKind::Key, _ => PemKind::Csr };
        if let Ok(out) = normalise_pem(&s, kind) {
            prop_assert!(!out.is_empty());
            for line in out.lines() {
                let boundary = line.starts_with("-----BEGIN ") || line.starts_with("-----END ");
                if boundary {
                    prop_assert!(line.ends_with("-----"));
                    let label = line.trim_start_matches("-----BEGIN ").trim_start_matches("-----END ").trim_end_matches("-----");
                    let ok = match kind {
                        PemKind::Chain => label == "CERTIFICATE",
                        PemKind::Csr => label == "CERTIFICATE REQUEST",
                        PemKind::Key => label.ends_with("PRIVATE KEY") && !label.contains("ENCRYPTED"),
                    };
                    prop_assert!(ok, "{}", line);
                } else {
                    prop_assert!(!line.is_empty() && line.len() <= 64, "{:?}", line);
                    prop_assert!(line.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')), "{:?}", line);
                }
            }
            prop_assert_eq!(normalise_pem(&out, kind).ok(), Some(out.clone()));
        }
    }
}
