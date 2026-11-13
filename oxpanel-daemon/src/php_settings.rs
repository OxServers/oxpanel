//! PHP settings per site: the allow-list, its bounds, and what they render to.
//!
//! A site may change exactly the settings of [`PhpSettings`]. Every value is
//! a number or a flag that the engine renders itself (`256M`, `120`, `on`),
//! except the time zone, which is allow-listed character by character and
//! must be a time-zone file of the host's database. There is no way to name
//! any other setting, so the pool's hardening (`open_basedir`,
//! `allow_url_include`, upload and session directories) cannot be reached.
//!
//! Bounds: each value lies between a fixed minimum and the tenant's cap
//! ([`PhpLimits`] on the tenant record, 0 = the host maximum), which in turn
//! lies within the host maximum (`OXPANEL_PHP_MAX_*`). A cap lowered later
//! clamps what is rendered ([`effective`]); the requested value stays in the
//! record.
//!
//! Where they apply: a site with settings gets its own pool inside the
//! tenant's PHP-FPM instance (see `php::render_pool_conf_with_sites`), never
//! `fastcgi_param PHP_VALUE`, which FPM keeps in the worker for later
//! requests of other sites. Nginx follows the size and time settings
//! ([`nginx_tuning`]), or they would do nothing.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Smallest values a site may set.
pub const MIN_MEMORY_MB: u32 = 16;
pub const MIN_UPLOAD_MB: u32 = 1;
pub const MIN_SECS: u32 = 1;
pub const MIN_INPUT_VARS: u32 = 100;
/// Nginx's own FastCGI timeout, kept as the floor of the rendered ones.
const NGINX_DEFAULT_TIMEOUT_SECS: u32 = 60;
/// Head room between PHP's limit and Nginx's, so PHP ends a slow script
/// (with its own error) before Nginx gives up on it.
const NGINX_TIMEOUT_MARGIN_SECS: u32 = 30;
/// Longest accepted time-zone name.
const TIME_ZONE_MAX: usize = 64;

/// A site's PHP settings. `None` / `false` / empty = PHP's default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhpSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_limit_mb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_max_filesize_mb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_max_size_mb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_execution_time_secs: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_input_time_secs: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_input_vars: Option<u32>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub display_errors: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub date_timezone: String,
}

impl PhpSettings {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Upper bounds of PHP settings. As a tenant's caps, 0 = the host maximum.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhpLimits {
    #[serde(default)]
    pub memory_limit_mb: u32,
    /// Applies to `upload_max_filesize` and `post_max_size`.
    #[serde(default)]
    pub upload_max_mb: u32,
    #[serde(default)]
    pub max_execution_time_secs: u32,
    #[serde(default)]
    pub max_input_time_secs: u32,
    #[serde(default)]
    pub max_input_vars: u32,
}

impl PhpLimits {
    /// The host maxima when the operator sets none.
    pub const HOST_DEFAULT: Self = Self {
        memory_limit_mb: 1024,
        upload_max_mb: 256,
        max_execution_time_secs: 300,
        max_input_time_secs: 300,
        max_input_vars: 10_000,
    };

    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// A tenant's caps resolved against the host maxima: every field set.
    #[must_use]
    pub fn resolve(&self, host: &Self) -> Self {
        let pick = |cap: u32, max: u32| if cap == 0 { max } else { cap.min(max) };
        Self {
            memory_limit_mb: pick(self.memory_limit_mb, host.memory_limit_mb),
            upload_max_mb: pick(self.upload_max_mb, host.upload_max_mb),
            max_execution_time_secs: pick(
                self.max_execution_time_secs,
                host.max_execution_time_secs,
            ),
            max_input_time_secs: pick(self.max_input_time_secs, host.max_input_time_secs),
            max_input_vars: pick(self.max_input_vars, host.max_input_vars),
        }
    }

    /// Validate a tenant's caps from the wire (0 = the host maximum): each
    /// must lie between the setting's minimum and the host maximum.
    pub fn parse_caps(raw: &Self, host: &Self) -> Result<Self> {
        for (value, min, max, field) in [
            (
                raw.memory_limit_mb,
                MIN_MEMORY_MB,
                host.memory_limit_mb,
                "limits.memory_limit_mb",
            ),
            (
                raw.upload_max_mb,
                MIN_UPLOAD_MB,
                host.upload_max_mb,
                "limits.upload_max_filesize_mb",
            ),
            (
                raw.max_execution_time_secs,
                MIN_SECS,
                host.max_execution_time_secs,
                "limits.max_execution_time_seconds",
            ),
            (
                raw.max_input_time_secs,
                MIN_SECS,
                host.max_input_time_secs,
                "limits.max_input_time_seconds",
            ),
            (
                raw.max_input_vars,
                MIN_INPUT_VARS,
                host.max_input_vars,
                "limits.max_input_vars",
            ),
        ] {
            in_bounds(value, min, max, field)?;
        }
        Ok(*raw)
    }
}

fn in_bounds(value: u32, min: u32, max: u32, field: &'static str) -> Result<Option<u32>> {
    match value {
        0 => Ok(None),
        v if (min..=max).contains(&v) => Ok(Some(v)),
        _ => Err(Error::invalid(
            field,
            format!("must be {min}..={max} (0 = the default)"),
        )),
    }
}

/// A site's settings as they arrive on the wire (0 / false / empty = default).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawSettings {
    pub memory_limit_mb: u32,
    pub upload_max_filesize_mb: u32,
    pub post_max_size_mb: u32,
    pub max_execution_time_secs: u32,
    pub max_input_time_secs: u32,
    pub max_input_vars: u32,
    pub display_errors: bool,
    pub date_timezone: String,
}

/// Validate a site's settings against `caps` (resolved: every field set).
pub fn parse(raw: &RawSettings, caps: &PhpLimits, zoneinfo_dir: &Path) -> Result<PhpSettings> {
    let upload = in_bounds(
        raw.upload_max_filesize_mb,
        MIN_UPLOAD_MB,
        caps.upload_max_mb,
        "settings.upload_max_filesize_mb",
    )?;
    let post = in_bounds(
        raw.post_max_size_mb,
        MIN_UPLOAD_MB,
        caps.upload_max_mb,
        "settings.post_max_size_mb",
    )?;
    if let (Some(u), Some(p)) = (upload, post) {
        if p < u {
            return Err(Error::invalid(
                "settings.post_max_size_mb",
                "must be at least upload_max_filesize_mb (a request carries the whole file)",
            ));
        }
    }
    let date_timezone = if raw.date_timezone.is_empty() {
        String::new()
    } else {
        parse_time_zone(&raw.date_timezone, "settings.date_timezone", zoneinfo_dir)?
    };
    Ok(PhpSettings {
        memory_limit_mb: in_bounds(
            raw.memory_limit_mb,
            MIN_MEMORY_MB,
            caps.memory_limit_mb,
            "settings.memory_limit_mb",
        )?,
        upload_max_filesize_mb: upload,
        post_max_size_mb: post,
        max_execution_time_secs: in_bounds(
            raw.max_execution_time_secs,
            MIN_SECS,
            caps.max_execution_time_secs,
            "settings.max_execution_time_seconds",
        )?,
        max_input_time_secs: in_bounds(
            raw.max_input_time_secs,
            MIN_SECS,
            caps.max_input_time_secs,
            "settings.max_input_time_seconds",
        )?,
        max_input_vars: in_bounds(
            raw.max_input_vars,
            MIN_INPUT_VARS,
            caps.max_input_vars,
            "settings.max_input_vars",
        )?,
        display_errors: raw.display_errors,
        date_timezone,
    })
}

/// An IANA time-zone name (`Europe/Berlin`, `UTC`, `Etc/GMT+5`): letters,
/// digits, `_ + -` in `/`-separated components that start with a letter, at
/// most 64 bytes, and a compiled time-zone file (`TZif`) of that name in
/// `zoneinfo_dir`. Nothing in it can end or extend a line of a configuration
/// file or a systemd calendar expression.
pub fn parse_time_zone(raw: &str, field: &'static str, zoneinfo_dir: &Path) -> Result<String> {
    let bad = || {
        Error::invalid(
            field,
            "must be a time zone such as Europe/Berlin, UTC or America/New_York",
        )
    };
    if raw.is_empty() || raw.len() > TIME_ZONE_MAX {
        return Err(bad());
    }
    for comp in raw.split('/') {
        let mut bytes = comp.bytes();
        if !bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
            || !bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'-'))
        {
            return Err(bad());
        }
    }
    let path = zoneinfo_dir.join(raw);
    let mut magic = [0_u8; 4];
    let is_tzif = std::fs::File::open(&path)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut magic))
        .is_ok()
        && &magic == b"TZif";
    if !is_tzif {
        return Err(Error::invalid(field, format!("unknown time zone '{raw}'")));
    }
    Ok(raw.to_owned())
}

/// What is rendered for `settings` under `caps` (resolved): each value
/// clamped to its cap, and `post_max_size` derived (upload + 1 MiB, for the
/// rest of the request) when only `upload_max_filesize` was given, and never
/// below it.
pub fn effective(settings: &PhpSettings, caps: &PhpLimits) -> PhpSettings {
    let clamp = |v: Option<u32>, cap: u32| v.map(|v| v.min(cap));
    let upload = clamp(settings.upload_max_filesize_mb, caps.upload_max_mb);
    let post = match (clamp(settings.post_max_size_mb, caps.upload_max_mb), upload) {
        (Some(p), Some(u)) => Some(p.max(u)),
        (Some(p), None) => Some(p),
        (None, Some(u)) => Some(u.saturating_add(1)),
        (None, None) => None,
    };
    PhpSettings {
        memory_limit_mb: clamp(settings.memory_limit_mb, caps.memory_limit_mb),
        upload_max_filesize_mb: upload,
        post_max_size_mb: post,
        max_execution_time_secs: clamp(
            settings.max_execution_time_secs,
            caps.max_execution_time_secs,
        ),
        max_input_time_secs: clamp(settings.max_input_time_secs, caps.max_input_time_secs),
        max_input_vars: clamp(settings.max_input_vars, caps.max_input_vars),
        display_errors: settings.display_errors,
        date_timezone: settings.date_timezone.clone(),
    }
}

/// The FPM pool lines for (effective) settings. `display_errors` is not
/// among them: it is part of every pool's hardening block (an admin flag).
pub fn pool_lines(s: &PhpSettings) -> Result<String> {
    use std::fmt::Write as _;
    let mut out = String::new();
    for (key, value, unit) in [
        ("memory_limit", s.memory_limit_mb, "M"),
        ("upload_max_filesize", s.upload_max_filesize_mb, "M"),
        ("post_max_size", s.post_max_size_mb, "M"),
        ("max_execution_time", s.max_execution_time_secs, ""),
        ("max_input_time", s.max_input_time_secs, ""),
        ("max_input_vars", s.max_input_vars, ""),
    ] {
        if let Some(v) = value {
            let _ = writeln!(out, "php_value[{key}] = {v}{unit}");
        }
    }
    if !s.date_timezone.is_empty() {
        // Re-checked by its characters: it ends up in a configuration file.
        let ok = s.date_timezone.len() <= TIME_ZONE_MAX
            && s.date_timezone
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'-' | b'/'));
        if !ok {
            return Err(Error::Internal(format!(
                "time zone '{}' is not renderable",
                s.date_timezone
            )));
        }
        let _ = writeln!(out, "php_value[date.timezone] = {}", s.date_timezone);
    }
    Ok(out)
}

/// What Nginx must follow for (effective) settings: the request body size
/// (Nginx's default of 1 MiB would refuse a larger upload before PHP sees
/// it) and the FastCGI timeouts (Nginx's 60 s would end a longer script with
/// a 504). `None` when no setting needs it, so a site that sets nothing
/// renders exactly as before.
pub fn nginx_tuning(s: &PhpSettings) -> Option<crate::nginx::PhpTuning> {
    let timeout = |secs: Option<u32>| {
        secs.map(|s| {
            s.saturating_add(NGINX_TIMEOUT_MARGIN_SECS)
                .max(NGINX_DEFAULT_TIMEOUT_SECS)
        })
    };
    let t = crate::nginx::PhpTuning {
        client_max_body_mb: s.post_max_size_mb.or(s.upload_max_filesize_mb),
        read_timeout_secs: timeout(s.max_execution_time_secs),
        send_timeout_secs: timeout(s.max_input_time_secs),
    };
    (t != crate::nginx::PhpTuning::default()).then_some(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zoneinfo() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        for (name, body) in [
            ("UTC", &b"TZif2..."[..]),
            ("Europe/Berlin", b"TZif2..."),
            ("Etc/GMT+5", b"TZif2..."),
            ("leapseconds", b"# not a zone"),
        ] {
            let p = d.path().join(name);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap_or_else(|e| panic!("{e}"));
            }
            std::fs::write(&p, body).unwrap_or_else(|e| panic!("{e}"));
        }
        d
    }

    #[test]
    fn values_are_bounded_by_the_caps_and_rendered_by_the_engine() -> Result<()> {
        let z = zoneinfo();
        let caps = PhpLimits::HOST_DEFAULT;
        let s = parse(
            &RawSettings {
                memory_limit_mb: 256,
                upload_max_filesize_mb: 64,
                max_execution_time_secs: 120,
                max_input_time_secs: 90,
                max_input_vars: 5000,
                display_errors: true,
                date_timezone: "Europe/Berlin".into(),
                ..RawSettings::default()
            },
            &caps,
            z.path(),
        )?;
        let e = effective(&s, &caps);
        assert_eq!(e.post_max_size_mb, Some(65), "derived from the upload size");
        assert_eq!(
            pool_lines(&e)?,
            "php_value[memory_limit] = 256M
php_value[upload_max_filesize] = 64M
php_value[post_max_size] = 65M
php_value[max_execution_time] = 120
php_value[max_input_time] = 90
php_value[max_input_vars] = 5000
php_value[date.timezone] = Europe/Berlin
"
        );
        assert_eq!(
            nginx_tuning(&e),
            Some(crate::nginx::PhpTuning {
                client_max_body_mb: Some(65),
                read_timeout_secs: Some(150),
                send_timeout_secs: Some(120),
            })
        );
        // Short limits keep Nginx's own 60 s.
        let short = PhpSettings {
            max_execution_time_secs: Some(5),
            ..PhpSettings::default()
        };
        assert_eq!(
            nginx_tuning(&short).and_then(|t| t.read_timeout_secs),
            Some(60)
        );
        assert_eq!(nginx_tuning(&PhpSettings::default()), None);
        assert_eq!(pool_lines(&PhpSettings::default())?, "");
        Ok(())
    }

    #[test]
    fn out_of_bounds_values_are_refused() {
        let z = zoneinfo();
        let caps = PhpLimits::HOST_DEFAULT;
        for raw in [
            RawSettings {
                memory_limit_mb: 8,
                ..RawSettings::default()
            },
            RawSettings {
                memory_limit_mb: 4096,
                ..RawSettings::default()
            },
            RawSettings {
                upload_max_filesize_mb: 257,
                ..RawSettings::default()
            },
            RawSettings {
                upload_max_filesize_mb: 64,
                post_max_size_mb: 32,
                ..RawSettings::default()
            },
            RawSettings {
                max_execution_time_secs: 301,
                ..RawSettings::default()
            },
            RawSettings {
                max_input_vars: 99,
                ..RawSettings::default()
            },
            RawSettings {
                date_timezone: "../../etc/passwd".into(),
                ..RawSettings::default()
            },
            RawSettings {
                date_timezone: "Europe/Berlin\nphp_admin_value[open_basedir] = /".into(),
                ..RawSettings::default()
            },
            RawSettings {
                date_timezone: "Mars/Olympus".into(),
                ..RawSettings::default()
            },
            RawSettings {
                date_timezone: "leapseconds".into(),
                ..RawSettings::default()
            },
        ] {
            assert!(parse(&raw, &caps, z.path()).is_err(), "{raw:?}");
        }
        assert!(parse(
            &RawSettings {
                date_timezone: "Etc/GMT+5".into(),
                ..RawSettings::default()
            },
            &caps,
            z.path()
        )
        .is_ok());
    }

    #[test]
    fn tenant_caps_lie_within_the_host_maxima_and_clamp_later() -> Result<()> {
        let host = PhpLimits::HOST_DEFAULT;
        let caps = PhpLimits::parse_caps(
            &PhpLimits {
                memory_limit_mb: 128,
                ..PhpLimits::default()
            },
            &host,
        )?;
        let resolved = caps.resolve(&host);
        assert_eq!(resolved.memory_limit_mb, 128);
        assert_eq!(resolved.upload_max_mb, 256, "0 = the host maximum");
        assert!(PhpLimits::parse_caps(
            &PhpLimits {
                memory_limit_mb: 2048,
                ..PhpLimits::default()
            },
            &host
        )
        .is_err());
        let z = zoneinfo();
        assert!(parse(
            &RawSettings {
                memory_limit_mb: 256,
                ..RawSettings::default()
            },
            &resolved,
            z.path()
        )
        .is_err());
        // A setting made under a higher cap is clamped, not dropped.
        let set = PhpSettings {
            memory_limit_mb: Some(512),
            upload_max_filesize_mb: Some(200),
            post_max_size_mb: Some(220),
            ..PhpSettings::default()
        };
        let small = PhpLimits {
            memory_limit_mb: 128,
            upload_max_mb: 100,
            ..host
        };
        let e = effective(&set, &small);
        assert_eq!(e.memory_limit_mb, Some(128));
        assert_eq!(e.upload_max_filesize_mb, Some(100));
        assert_eq!(e.post_max_size_mb, Some(100));
        Ok(())
    }

    #[test]
    fn records_without_settings_serialise_to_nothing() -> Result<()> {
        let json = serde_json::to_string(&PhpSettings::default())
            .map_err(|e| Error::Internal(e.to_string()))?;
        assert_eq!(json, "{}");
        Ok(())
    }
}
