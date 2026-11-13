//! Property tests of crate-private parsers: text that comes back from the
//! operating system (log files, `systemctl show`) or from configuration, and
//! is therefore not under the daemon's control.

use std::path::Path;

use proptest::prelude::*;

use crate::nginx::safe_path_str;
use crate::tenant::parse_cgroup_usage;
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
