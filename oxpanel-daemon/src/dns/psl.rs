//! The registrable domain of a name, from the host's public suffix list.
//!
//! A zone created for a site is the site's *registrable* domain
//! (`shop.example.co.uk` → `example.co.uk`), and no zone may ever be a
//! public suffix (`co.uk`, `github.io`): a tenant holding such a zone would
//! answer, on this host, for every other customer below it. Which names are
//! public suffixes is what the Public Suffix List says; AlmaLinux ships it
//! as the `publicsuffix-list` package (`/usr/share/publicsuffix/
//! public_suffix_list.dat`), kept current by the distribution. The engine
//! reads that file — it embeds no copy of its own — and refuses DNS work
//! when it is missing rather than guess.
//!
//! Rules are matched as the list's own algorithm says: the most specific
//! rule wins, exception rules (`!www.ck`) beat wildcards (`*.ck`), and a
//! name under no rule has its top-level label as public suffix. Both the
//! ICANN and the private section count: `user.github.io` is a registrable
//! domain of its own, which is what a hosting provider needs. Rules written
//! in Unicode are converted to A-labels (punycode), because names reach the
//! engine in that form only.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use crate::error::{Error, Result};
use crate::fsutil;
use crate::validate::Domain;

/// The list, parsed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SuffixList {
    rules: HashSet<String>,
    wildcards: HashSet<String>,
    exceptions: HashSet<String>,
}

/// Largest list file the engine reads (the real one is about 230 KB).
const MAX_LIST_BYTES: u64 = 4 << 20;

impl SuffixList {
    pub fn parse(text: &str) -> Self {
        let mut list = Self::default();
        for line in text.lines() {
            // The rule is the first whitespace-separated word of the line.
            let Some(rule) = line.split_whitespace().next() else {
                continue;
            };
            if rule.starts_with("//") {
                continue;
            }
            let (set, rule) = if let Some(r) = rule.strip_prefix('!') {
                (&mut list.exceptions, r)
            } else if let Some(r) = rule.strip_prefix("*.") {
                (&mut list.wildcards, r)
            } else {
                (&mut list.rules, rule)
            };
            if let Some(ascii) = to_ascii_name(rule) {
                set.insert(ascii);
            }
        }
        list
    }

    pub fn len(&self) -> usize {
        self.rules.len() + self.wildcards.len() + self.exceptions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of trailing labels of `name` that form its public suffix.
    fn suffix_labels(&self, labels: &[&str]) -> usize {
        let n = labels.len();
        let mut best = 1; // the implicit "*" rule
        for k in 1..=n {
            let candidate = labels.get(n - k..).unwrap_or_default().join(".");
            if self.exceptions.contains(&candidate) {
                // An exception rule's suffix is the rule minus its first label.
                return k - 1;
            }
            if self.rules.contains(&candidate) {
                best = best.max(k);
            }
            if k < n {
                // `*.ck` makes `<any>.ck` a suffix.
                if self.wildcards.contains(&candidate) {
                    best = best.max(k + 1);
                }
            }
        }
        best
    }

    /// Whether `name` itself is a public suffix.
    pub fn is_public_suffix(&self, name: &str) -> bool {
        let labels: Vec<&str> = name.split('.').collect();
        self.suffix_labels(&labels) >= labels.len()
    }

    /// The registrable domain of `name`: its public suffix plus one label.
    /// `None` when `name` is a public suffix itself.
    pub fn registrable(&self, name: &str) -> Option<String> {
        let labels: Vec<&str> = name.split('.').collect();
        let suffix = self.suffix_labels(&labels);
        if suffix >= labels.len() {
            return None;
        }
        labels
            .get(labels.len() - suffix - 1..)
            .map(|tail| tail.join("."))
    }
}

/// A rule as A-labels; `None` for anything that cannot be a DNS name.
fn to_ascii_name(rule: &str) -> Option<String> {
    let mut out = Vec::new();
    for label in rule.split('.') {
        if label.is_empty() {
            return None;
        }
        if label.is_ascii() {
            out.push(label.to_ascii_lowercase());
        } else {
            out.push(format!("xn--{}", punycode_encode(&label.to_lowercase())?));
        }
    }
    Some(out.join("."))
}

/// RFC 3492 encoding of one label (without the `xn--` prefix). The variable
/// names are those of the RFC's pseudocode, so the two can be compared.
#[allow(clippy::many_single_char_names)]
fn punycode_encode(input: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    const DIGITS: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let digit = |d: u32| -> char {
        usize::try_from(d)
            .ok()
            .and_then(|i| DIGITS.get(i))
            .map_or('a', |b| char::from(*b))
    };
    let adapt = |mut delta: u32, numpoints: u32, first: bool| -> u32 {
        delta /= if first { DAMP } else { 2 };
        delta += delta / numpoints;
        let mut k = 0;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        k + (BASE - TMIN + 1) * delta / (delta + SKEW)
    };
    let chars: Vec<u32> = input.chars().map(u32::from).collect();
    let mut out: String = input.chars().filter(char::is_ascii).collect();
    let basic = u32::try_from(out.len()).ok()?;
    if basic > 0 {
        out.push('-');
    }
    let mut n: u32 = 0x80;
    let mut delta: u32 = 0;
    let mut bias: u32 = 72;
    let mut h = basic;
    let total = u32::try_from(chars.len()).ok()?;
    while h < total {
        let m = chars.iter().copied().filter(|&c| c >= n).min()?;
        delta = delta.checked_add((m - n).checked_mul(h + 1)?)?;
        n = m;
        for &c in &chars {
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        TMIN
                    } else if k >= bias + TMAX {
                        TMAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    out.push(digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                out.push(digit(q));
                bias = adapt(delta, h + 1, h == basic);
                delta = 0;
                h += 1;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    Some(out)
}

/// The list file, parsed once and again whenever it changes on disk (the
/// package is updated with the system).
type Cached = (Option<SystemTime>, Arc<SuffixList>);
static CACHE: OnceLock<Mutex<Option<(std::path::PathBuf, Cached)>>> = OnceLock::new();

/// Load the list from `path`. `Ok(None)` when the file does not exist.
pub fn load(path: &Path) -> Result<Option<Arc<SuffixList>>> {
    let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = cache.lock() {
        if let Some((p, (t, list))) = guard.as_ref() {
            if p == path && *t == mtime && mtime.is_some() {
                return Ok(Some(list.clone()));
            }
        }
    }
    let Some(bytes) = fsutil::read_untrusted(path, MAX_LIST_BYTES)? else {
        return Ok(None);
    };
    let list = Arc::new(SuffixList::parse(&String::from_utf8_lossy(&bytes)));
    if list.is_empty() {
        return Err(Error::Internal(format!(
            "{} holds no public-suffix rules",
            path.display()
        )));
    }
    if let Ok(mut guard) = cache.lock() {
        *guard = Some((path.to_owned(), (mtime, list.clone())));
    }
    Ok(Some(list))
}

/// The zone apex for `name`: its registrable domain.
pub fn zone_apex(list: &SuffixList, name: &Domain) -> Option<Domain> {
    list.registrable(name.as_str())
        .and_then(|s| Domain::parse(&s).ok())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;

    const LIST: &str = "\
// ===BEGIN ICANN DOMAINS===
com
uk
co.uk
*.ck
!www.ck
jp
*.kawasaki.jp
!city.kawasaki.jp
公司.cn
cn
// ===BEGIN PRIVATE DOMAINS===
github.io
";

    #[test]
    fn registrable_domains_follow_the_list_algorithm() {
        let l = SuffixList::parse(LIST);
        let reg = |n: &str| l.registrable(n);
        assert_eq!(reg("example.com").as_deref(), Some("example.com"));
        assert_eq!(reg("shop.example.com").as_deref(), Some("example.com"));
        assert_eq!(reg("a.b.example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(reg("co.uk"), None);
        assert_eq!(reg("com"), None);
        assert_eq!(reg("foo.ck"), None, "*.ck: foo.ck is a suffix");
        assert_eq!(reg("bar.foo.ck").as_deref(), Some("bar.foo.ck"));
        assert_eq!(reg("www.ck").as_deref(), Some("www.ck"), "exception");
        assert_eq!(reg("a.www.ck").as_deref(), Some("www.ck"));
        assert_eq!(reg("city.kawasaki.jp").as_deref(), Some("city.kawasaki.jp"));
        assert_eq!(reg("x.y.kawasaki.jp").as_deref(), Some("x.y.kawasaki.jp"));
        assert_eq!(reg("user.github.io").as_deref(), Some("user.github.io"));
        assert_eq!(reg("github.io"), None);
        // Unlisted top-level domain: the implicit "*" rule.
        assert_eq!(reg("shop.example.test").as_deref(), Some("example.test"));
        assert_eq!(reg("test"), None);
        // Unicode rules match their A-label form.
        assert_eq!(reg("xn--55qx5d.cn"), None);
        assert_eq!(reg("a.b.xn--55qx5d.cn").as_deref(), Some("b.xn--55qx5d.cn"));
        assert!(l.is_public_suffix("co.uk"));
        assert!(!l.is_public_suffix("example.co.uk"));
    }

    #[test]
    fn punycode_matches_rfc_3492() {
        assert_eq!(punycode_encode("bücher").as_deref(), Some("bcher-kva"));
        assert_eq!(punycode_encode("公司").as_deref(), Some("55qx5d"));
        assert_eq!(punycode_encode("münchen").as_deref(), Some("mnchen-3ya"));
        assert_eq!(punycode_encode("中国").as_deref(), Some("fiqs8s"));
    }

    #[test]
    fn the_hosts_list_is_read_if_present() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("list.dat");
        assert!(load(&p).unwrap().is_none());
        std::fs::write(&p, LIST).unwrap();
        let l = load(&p).unwrap().unwrap();
        assert_eq!(
            zone_apex(&l, &Domain::parse("www.example.co.uk").unwrap()).map(|d| d.to_string()),
            Some("example.co.uk".to_owned())
        );
        std::fs::write(&p, "// nothing\n").unwrap();
        let later = SystemTime::now() + std::time::Duration::from_secs(10);
        let f = std::fs::File::options().write(true).open(&p).unwrap();
        f.set_modified(later).unwrap();
        assert!(
            load(&p).is_err(),
            "an empty list is an error, not 'nothing is public'"
        );
        // The real list, where the build image has it.
        if let Ok(Some(real)) = load(Path::new("/usr/share/publicsuffix/public_suffix_list.dat")) {
            assert!(real.is_public_suffix("co.uk"));
            assert_eq!(
                real.registrable("www.example.co.uk").as_deref(),
                Some("example.co.uk")
            );
            assert!(real.is_public_suffix("xn--55qx5d.cn"));
        }
    }
}
