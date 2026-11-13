//! Scheduled tasks — what hosting customers call cron jobs.
//!
//! A task is a record (`state_dir/tasks/<tenant>.<name>.json`) rendered into
//! a oneshot service and a timer under the systemd unit directory:
//!
//! - the service runs **as the tenant**, in the tenant's slice (its limits
//!   apply and `GetTenantUsage` counts it), sandboxed like an application
//!   unit, in the application domain on SELinux hosts, with a time limit
//!   (`TimeoutStartSec`: at the limit the whole control group is ended, so
//!   nothing it started outlives it);
//! - a oneshot unit that is still running is not started a second time, so
//!   a task never overlaps with itself;
//! - the timer carries the schedule (`OnCalendar=`) and a fixed random delay
//!   per unit, so a thousand "every hour" tasks do not start in the same
//!   second.
//!
//! Not a crontab: a crontab line is run by a shell, outside the tenant's
//! slice, with no time limit and no overlap protection.
//!
//! What a task runs is **structured** (an interpreter chosen by the engine,
//! a script inside the home, arguments; or a URL of one of the tenant's own
//! sites), never a command line: nothing the caller sends is interpreted by a
//! shell or can add a directive to a unit. Every word of `ExecStart=` is
//! allow-listed and written double-quoted, with systemd's `%` and `$`
//! expansions escaped ([`exec_line`]).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::app;
use crate::config::{Config, Essentials};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::host::{Drift, DriftKind};
use crate::nginx::safe_path_str;
use crate::records::{self, now_unix, AppRuntime, TenantRecord, TenantState, RECORD_VERSION};
use crate::system::{bin, CommandSpec};
use crate::systemd;
use crate::validate::{Domain, RelPath, Username};

const HEADER: &str = "# Managed by oxpanel-daemon. Manual edits will be overwritten.\n";
const FILE_MODE: u32 = 0o644;
const DIR_MODE: u32 = 0o700;
/// Longest task name.
pub const NAME_MAX: usize = 32;
/// Most arguments of a task, and longest argument.
pub const MAX_ARGS: usize = 16;
pub const ARG_MAX: usize = 256;
/// Longest URL of a URL task.
pub const URL_MAX: usize = 2048;
/// Time limit when the request names none, and the shortest one.
pub const DEFAULT_TIMEOUT_SECS: u32 = 300;
pub const MIN_TIMEOUT_SECS: u32 = 10;
/// Upper bound of the per-unit random delay.
const SPREAD_MAX_SECS: u32 = 900;
/// Lines of output returned by [`TaskService::read_log`].
const LOG_LINES: &str = "200";
/// What a URL task's request says it is.
const URL_USER_AGENT: &str = "OxPanel-task";
/// "every N minutes" / "every N hours": divisors of 60 and 24, so the
/// interval is exact across the hour and the day.
pub const MINUTE_INTERVALS: [u32; 11] = [1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30];
pub const HOUR_INTERVALS: [u32; 7] = [1, 2, 3, 4, 6, 8, 12];
const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/// What a task runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    Php,
    Node,
    Python,
    Url,
}

/// When a task runs. Integers only; [`Schedule::calendar`] maps them onto
/// `OnCalendar=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "form", rename_all = "snake_case")]
pub enum Schedule {
    EveryMinutes {
        interval: u32,
    },
    EveryHours {
        interval: u32,
        minute: u32,
    },
    Daily {
        hour: u32,
        minute: u32,
    },
    Weekly {
        weekday: u32,
        hour: u32,
        minute: u32,
    },
    Monthly {
        day: u32,
        hour: u32,
        minute: u32,
    },
}

/// The form of a schedule as requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    EveryMinutes,
    EveryHours,
    Daily,
    Weekly,
    Monthly,
}

/// A schedule as it arrives on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawSchedule {
    pub form: Option<Form>,
    pub interval: u32,
    pub minute: u32,
    pub hour: u32,
    pub weekday: u32,
    pub day_of_month: u32,
    pub time_zone: String,
}

impl Schedule {
    /// Validate a schedule; returns it and its time zone ("" for the "every
    /// N minutes" form, which does not depend on one).
    pub fn parse(raw: &RawSchedule, cfg: &Essentials) -> Result<(Self, String)> {
        const F: &str = "spec.schedule";
        let minute = || bounded(raw.minute, 0, 59, "spec.schedule.minute");
        let hour = || bounded(raw.hour, 0, 23, "spec.schedule.hour");
        let schedule = match raw.form {
            None => return Err(Error::invalid(F, "a schedule form is required")),
            Some(Form::EveryMinutes) => {
                if !MINUTE_INTERVALS.contains(&raw.interval) {
                    return Err(Error::invalid(
                        "spec.schedule.interval",
                        "every N minutes: N must be 1, 2, 3, 4, 5, 6, 10, 12, 15, 20 or 30",
                    ));
                }
                if raw.interval < cfg.task_min_interval_minutes {
                    return Err(Error::invalid(
                        "spec.schedule.interval",
                        format!(
                            "this host runs tasks at most every {} minutes",
                            cfg.task_min_interval_minutes
                        ),
                    ));
                }
                Self::EveryMinutes {
                    interval: raw.interval,
                }
            }
            Some(Form::EveryHours) => {
                if !HOUR_INTERVALS.contains(&raw.interval) {
                    return Err(Error::invalid(
                        "spec.schedule.interval",
                        "every N hours: N must be 1, 2, 3, 4, 6, 8 or 12",
                    ));
                }
                Self::EveryHours {
                    interval: raw.interval,
                    minute: minute()?,
                }
            }
            Some(Form::Daily) => Self::Daily {
                hour: hour()?,
                minute: minute()?,
            },
            Some(Form::Weekly) => Self::Weekly {
                weekday: bounded(raw.weekday, 0, 6, "spec.schedule.weekday")?,
                hour: hour()?,
                minute: minute()?,
            },
            Some(Form::Monthly) => Self::Monthly {
                day: bounded(raw.day_of_month, 1, 28, "spec.schedule.day_of_month")?,
                hour: hour()?,
                minute: minute()?,
            },
        };
        let shortest = schedule.period_secs() / 60;
        if shortest < cfg.task_min_interval_minutes {
            return Err(Error::invalid(
                "spec.schedule",
                format!(
                    "this host runs tasks at most every {} minutes",
                    cfg.task_min_interval_minutes
                ),
            ));
        }
        let time_zone = match schedule {
            Self::EveryMinutes { .. } => {
                if !raw.time_zone.is_empty() {
                    return Err(Error::invalid(
                        "spec.schedule.time_zone",
                        "not used by the every-N-minutes form",
                    ));
                }
                String::new()
            }
            _ if raw.time_zone.is_empty() => String::new(),
            _ => crate::php_settings::parse_time_zone(
                &raw.time_zone,
                "spec.schedule.time_zone",
                &cfg.zoneinfo_dir,
            )?,
        };
        Ok((schedule, time_zone))
    }

    /// Re-check a schedule read from a record (it ends up in a unit file).
    fn check(&self) -> Result<()> {
        let ok = match *self {
            Self::EveryMinutes { interval } => MINUTE_INTERVALS.contains(&interval),
            Self::EveryHours { interval, minute } => {
                HOUR_INTERVALS.contains(&interval) && minute < 60
            }
            Self::Daily { hour, minute } => hour < 24 && minute < 60,
            Self::Weekly {
                weekday,
                hour,
                minute,
            } => weekday < 7 && hour < 24 && minute < 60,
            Self::Monthly { day, hour, minute } => {
                (1..=28).contains(&day) && hour < 24 && minute < 60
            }
        };
        if ok {
            Ok(())
        } else {
            Err(Error::Internal(format!(
                "task schedule {self:?} is out of range"
            )))
        }
    }

    /// The shortest time between two runs.
    pub fn period_secs(&self) -> u32 {
        match *self {
            Self::EveryMinutes { interval } => interval * 60,
            Self::EveryHours { interval, .. } => interval * 3600,
            Self::Daily { .. } => 86_400,
            Self::Weekly { .. } => 7 * 86_400,
            // February.
            Self::Monthly { .. } => 28 * 86_400,
        }
    }

    /// The systemd calendar expression: digits, fixed tokens and the
    /// validated time zone only. `UTC` when no time zone is given.
    pub fn calendar(&self, time_zone: &str) -> String {
        let tz = if time_zone.is_empty() {
            "UTC"
        } else {
            time_zone
        };
        match *self {
            Self::EveryMinutes { interval } => format!("*-*-* *:00/{interval:02}:00"),
            Self::EveryHours { interval, minute } => {
                format!("*-*-* 00/{interval:02}:{minute:02}:00 {tz}")
            }
            Self::Daily { hour, minute } => format!("*-*-* {hour:02}:{minute:02}:00 {tz}"),
            Self::Weekly {
                weekday,
                hour,
                minute,
            } => format!(
                "{} *-*-* {hour:02}:{minute:02}:00 {tz}",
                WEEKDAYS.get(weekday as usize).copied().unwrap_or("Sun")
            ),
            Self::Monthly { day, hour, minute } => {
                format!("*-*-{day:02} {hour:02}:{minute:02}:00 {tz}")
            }
        }
    }

    /// `RandomizedDelaySec=`: up to the period (at most 15 minutes), fixed
    /// per unit, so every task keeps its exact interval but tasks of the same
    /// schedule do not start together.
    pub fn randomized_delay_secs(&self) -> u32 {
        self.period_secs().min(SPREAD_MAX_SECS) - 1
    }
}

fn bounded(v: u32, min: u32, max: u32, field: &'static str) -> Result<u32> {
    if (min..=max).contains(&v) {
        Ok(v)
    } else {
        Err(Error::invalid(field, format!("must be {min}..={max}")))
    }
}

/// A task name: `a-z 0-9 -`, 1–32, starting with a letter or digit.
pub fn parse_name(raw: &str, field: &'static str) -> Result<String> {
    let mut bytes = raw.bytes();
    let ok = raw.len() <= NAME_MAX
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(raw.to_owned())
    } else {
        Err(Error::invalid(
            field,
            "must be 1-32 characters a-z, 0-9 and '-', starting with a letter or digit",
        ))
    }
}

/// An argument: at most 256 bytes of printable ASCII without the quotes,
/// the backtick, the backslash, `$` and `%` — nothing that could end a
/// quoted word in a unit file or trigger one of systemd's expansions.
pub fn parse_arg(raw: &str) -> Result<String> {
    let ok = raw.len() <= ARG_MAX
        && raw.bytes().all(|b| {
            (0x20..0x7f).contains(&b) && !matches!(b, b'"' | b'\'' | b'`' | b'\\' | b'$' | b'%')
        });
    if ok {
        Ok(raw.to_owned())
    } else {
        Err(Error::invalid(
            "spec.args",
            "each argument: at most 256 bytes of printable ASCII without quotes, backtick, backslash, '$' or '%'",
        ))
    }
}

/// A URL task's URL: `http://` or `https://`, a host that is a valid domain
/// (no user info, no port), and a path/query of allow-listed characters
/// with `%` only as a `%XX` escape. Returns the URL and its host.
pub fn parse_url(raw: &str) -> Result<(String, Domain)> {
    const F: &str = "spec.url";
    if raw.len() > URL_MAX {
        return Err(Error::invalid(F, format!("at most {URL_MAX} bytes")));
    }
    let rest = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("http://"))
        .ok_or_else(|| Error::invalid(F, "must start with http:// or https://"))?;
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (host, path) = rest.split_at(split);
    if host.contains(['@', ':']) {
        return Err(Error::invalid(F, "no user name, password or port"));
    }
    let host = Domain::parse_field(host, F)?;
    let bytes = path.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        let ok = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'/'
                    | b'?'
                    | b'&'
                    | b'='
                    | b'+'
                    | b','
                    | b';'
                    | b':'
                    | b'@'
                    | b'!'
                    | b'*'
                    | b'('
                    | b')'
            )
            || (b == b'%'
                && bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit));
        if !ok {
            return Err(Error::invalid(
                F,
                "the path and query may contain A-Z a-z 0-9 - . _ ~ / ? & = + , ; : @ ! * ( ) and %XX escapes",
            ));
        }
    }
    Ok((raw.to_owned(), host))
}

/// A task as it arrives on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawSpec {
    pub name: String,
    pub kind: Option<TaskKind>,
    pub script: String,
    pub args: Vec<String>,
    pub virtualenv: String,
    pub url: String,
    pub schedule: RawSchedule,
    pub timeout_secs: u32,
    pub disabled: bool,
}

/// A scheduled task OxPanel created for a tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskRecord {
    pub version: u32,
    pub tenant: String,
    pub name: String,
    pub kind: TaskKind,
    /// PHP, Node.js, Python: the script, relative to the home.
    #[serde(default)]
    pub script: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Python: a virtualenv relative to the home; empty = the system's python3.
    #[serde(default)]
    pub virtualenv: String,
    /// URL tasks.
    #[serde(default)]
    pub url: String,
    pub schedule: Schedule,
    /// Time zone of the schedule; empty = UTC.
    #[serde(default)]
    pub time_zone: String,
    pub timeout_secs: u32,
    pub enabled: bool,
    pub created_at_unix: u64,
}

impl TaskRecord {
    /// The record without its creation time, for "did anything change".
    fn same_spec(&self, other: &Self) -> bool {
        Self {
            created_at_unix: 0,
            ..self.clone()
        } == Self {
            created_at_unix: 0,
            ..other.clone()
        }
    }
}

/// Validate a request into a record (tenant and creation time left empty).
/// Everything a task needs from the request is checked here, before
/// anything is looked up or touched.
pub fn parse_spec(raw: &RawSpec, cfg: &Essentials) -> Result<TaskRecord> {
    let name = parse_name(&raw.name, "spec.name")?;
    let kind = raw
        .kind
        .ok_or_else(|| Error::invalid("spec.kind", "PHP, NODE, PYTHON or URL"))?;
    let (schedule, time_zone) = Schedule::parse(&raw.schedule, cfg)?;
    let timeout_secs = match raw.timeout_secs {
        0 => DEFAULT_TIMEOUT_SECS.min(cfg.task_max_timeout_secs),
        t => bounded(
            t,
            MIN_TIMEOUT_SECS,
            cfg.task_max_timeout_secs,
            "spec.timeout_seconds",
        )?,
    };
    if raw.args.len() > MAX_ARGS {
        return Err(Error::invalid(
            "spec.args",
            format!("at most {MAX_ARGS} arguments"),
        ));
    }
    let args = raw
        .args
        .iter()
        .map(|a| parse_arg(a))
        .collect::<Result<Vec<_>>>()?;
    let (script, url) = if kind == TaskKind::Url {
        if !raw.script.is_empty() || !args.is_empty() || !raw.virtualenv.is_empty() {
            return Err(Error::invalid(
                "spec",
                "a URL task takes a url only (no script, arguments or virtualenv)",
            ));
        }
        (String::new(), parse_url(&raw.url)?.0)
    } else {
        if !raw.url.is_empty() {
            return Err(Error::invalid("spec.url", "only for URL tasks"));
        }
        (
            RelPath::parse_field(&raw.script, "spec.script")?.to_string(),
            String::new(),
        )
    };
    let virtualenv = match (kind, raw.virtualenv.as_str()) {
        (_, "") => String::new(),
        (TaskKind::Python, v) => RelPath::parse_field(v, "spec.virtualenv")?.to_string(),
        _ => return Err(Error::invalid("spec.virtualenv", "only for Python tasks")),
    };
    Ok(TaskRecord {
        version: RECORD_VERSION,
        tenant: String::new(),
        name,
        kind,
        script,
        args,
        virtualenv,
        url,
        schedule,
        time_zone,
        timeout_secs,
        enabled: !raw.disabled,
        created_at_unix: 0,
    })
}

/// Re-check a record (a file) before it is saved or rendered.
fn check_record(rec: &TaskRecord) -> Result<(Username, String)> {
    let tenant = Username::parse_field(&rec.tenant, "tenant")?;
    let name = parse_name(&rec.name, "name")?;
    rec.schedule.check()?;
    for a in &rec.args {
        parse_arg(a)?;
    }
    if rec.kind == TaskKind::Url {
        parse_url(&rec.url)?;
    } else {
        RelPath::parse_field(&rec.script, "script")?;
    }
    if !rec.virtualenv.is_empty() {
        RelPath::parse_field(&rec.virtualenv, "virtualenv")?;
    }
    if !rec.time_zone.is_empty()
        && !rec
            .time_zone
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'-' | b'/'))
    {
        return Err(Error::Internal(format!(
            "task time zone '{}' is not renderable",
            rec.time_zone
        )));
    }
    if rec.timeout_secs == 0 {
        return Err(Error::Internal("task without a time limit".into()));
    }
    Ok((tenant, name))
}

// --- units -------------------------------------------------------------

/// `oxpanel-task-<escaped tenant>-<escaped name>` (without suffix). Both
/// parts are escaped (`-` → `\x2d`), so the `-` between them is unambiguous.
pub fn unit_base(tenant: &Username, name: &str) -> String {
    format!(
        "oxpanel-task-{}-{}",
        systemd::escape_unit_component(tenant.as_str()),
        systemd::escape_unit_component(name)
    )
}

/// Paths of the two units of a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskUnits {
    pub service_name: String,
    pub timer_name: String,
    pub service: PathBuf,
    pub timer: PathBuf,
    /// The symlink `systemctl enable` creates for the timer.
    pub timer_wanted: PathBuf,
}

impl TaskUnits {
    pub fn new(unit_dir: &Path, tenant: &Username, name: &str) -> Self {
        let base = unit_base(tenant, name);
        let (service_name, timer_name) = (format!("{base}.service"), format!("{base}.timer"));
        Self {
            service: unit_dir.join(&service_name),
            timer: unit_dir.join(&timer_name),
            timer_wanted: unit_dir.join("timers.target.wants").join(&timer_name),
            service_name,
            timer_name,
        }
    }

    fn of(cfg: &Config, rec: &TaskRecord) -> Result<Self> {
        let (tenant, name) = check_record(rec)?;
        Ok(Self::new(&cfg.systemd_unit_dir, &tenant, &name))
    }
}

/// The program and its arguments, as the service executes them.
pub fn argv(rec: &TaskRecord, home: &Path) -> Result<Vec<String>> {
    let path = |rel: &str| -> Result<String> { Ok(safe_path_str(&home.join(rel))?.to_owned()) };
    let mut words: Vec<String> = match rec.kind {
        TaskKind::Php => vec![
            bin::PHP_CLI.into(),
            "-f".into(),
            path(&rec.script)?,
            "--".into(),
        ],
        TaskKind::Node => vec![bin::NODE.into(), path(&rec.script)?],
        TaskKind::Python if rec.virtualenv.is_empty() => {
            vec![bin::PYTHON3.into(), path(&rec.script)?]
        }
        // systemd may not execute a path under a home on SELinux hosts:
        // `env`, a system binary, executes the virtualenv's interpreter.
        TaskKind::Python => vec![
            bin::ENV.into(),
            path(&format!("{}/bin/python", rec.virtualenv))?,
            path(&rec.script)?,
        ],
        TaskKind::Url => {
            let (url, host) = parse_url(&rec.url)?;
            return Ok(vec![
                bin::CURL.into(),
                "--silent".into(),
                "--show-error".into(),
                "--fail".into(),
                "--max-time".into(),
                rec.timeout_secs.to_string(),
                "--proto".into(),
                "=http,https".into(),
                "--max-redirs".into(),
                "0".into(),
                "--user-agent".into(),
                URL_USER_AGENT.into(),
                // The tenant's own site, on this host: never another machine.
                "--resolve".into(),
                format!("{host}:80:127.0.0.1"),
                "--resolve".into(),
                format!("{host}:443:127.0.0.1"),
                "--output".into(),
                "/dev/null".into(),
                "--write-out".into(),
                "HTTP %{http_code}, %{size_download} bytes in %{time_total}s".into(),
                "--".into(),
                url,
            ]);
        }
    };
    words.extend(rec.args.iter().cloned());
    Ok(words)
}

/// `ExecStart=` value: the program (a constant absolute path) followed by
/// every other word double-quoted, with systemd's specifier (`%`) and
/// variable (`$`) expansions escaped. A word holding a control character,
/// a quote or a backslash is refused: it could not be written safely.
pub fn exec_line(argv: &[String]) -> Result<String> {
    let (program, rest) = argv
        .split_first()
        .ok_or_else(|| Error::Internal("empty task command".into()))?;
    if !program.starts_with('/')
        || !program
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(Error::Internal(format!("task program '{program}'")));
    }
    let mut line = program.clone();
    for word in rest {
        if !word
            .bytes()
            .all(|b| (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\')
        {
            return Err(Error::Internal("task word cannot be quoted safely".into()));
        }
        line.push_str(" \"");
        line.push_str(&word.replace('%', "%%").replace('$', "$$"));
        line.push('"');
    }
    Ok(line)
}

/// The working directory: the script's directory (as `cd dir && php x`
/// would), or the home for URL tasks.
fn working_dir(rec: &TaskRecord, home: &Path) -> PathBuf {
    match rec.kind {
        TaskKind::Url => home.to_owned(),
        _ => home
            .join(&rec.script)
            .parent()
            .map_or_else(|| home.to_owned(), Path::to_path_buf),
    }
}

/// The service unit of a task.
pub fn render_service(rec: &TaskRecord, tenant: &TenantRecord, selinux: bool) -> Result<String> {
    let (name, task) = check_record(rec)?;
    if name.as_str() != tenant.username {
        return Err(Error::Internal(format!(
            "task {} rendered for tenant {}",
            rec.name, tenant.username
        )));
    }
    let home = safe_path_str(&tenant.home)?;
    let workdir = working_dir(rec, &tenant.home);
    let workdir = safe_path_str(&workdir)?;
    let exec = exec_line(&argv(rec, &tenant.home)?)?;
    // Derived from the validated name, not copied from the record (see php::render_unit).
    let slice = systemd::slice_unit_name(&name);
    let selinux_context = app::selinux_context_line(selinux);
    let timeout = rec.timeout_secs;
    Ok(format!(
        "{HEADER}[Unit]
Description=OxPanel scheduled task {task} of tenant {name}
Documentation=https://github.com/OxServers/oxpanel
After=network.target

[Service]
Type=oneshot
User={name}
Group={name}
Slice={slice}
{selinux_context}WorkingDirectory={workdir}
Environment=HOME={home}
Environment=OXPANEL_TASK={task}
ExecStart={exec}
# The time limit: the whole control group is ended, children included.
TimeoutStartSec={timeout}s
TimeoutStopSec=10s
UMask=0022

# The task already runs unprivileged as the tenant; this narrows it further.
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ReadWritePaths={home}
# The engine's socket is closed to tenants by its mode; here it does not even exist.
InaccessiblePaths=-/run/oxpanel
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
"
    ))
}

/// The timer unit of a task.
pub fn render_timer(rec: &TaskRecord) -> Result<String> {
    let (name, task) = check_record(rec)?;
    let service = format!("{}.service", unit_base(&name, &task));
    let calendar = rec.schedule.calendar(&rec.time_zone);
    let delay = rec.schedule.randomized_delay_secs();
    Ok(format!(
        "{HEADER}[Unit]
Description=Schedule of OxPanel task {task} of tenant {name}
Documentation=https://github.com/OxServers/oxpanel

[Timer]
Unit={service}
OnCalendar={calendar}
# A fixed offset per unit: each task keeps its interval, tasks do not start together.
RandomizedDelaySec={delay}s
FixedRandomDelay=yes
AccuracySec=1s
# Missed runs (the host was off) are not caught up, as with cron.
Persistent=false

[Install]
WantedBy=timers.target
"
    ))
}

// --- records -----------------------------------------------------------

fn record_path(cfg: &Config, tenant: &str, name: &str) -> PathBuf {
    cfg.tasks_dir().join(format!("{tenant}.{name}.json"))
}

fn load(cfg: &Config, tenant: &Username, name: &str) -> Result<Option<TaskRecord>> {
    records::load(&record_path(cfg, tenant.as_str(), name))
}

fn save(cfg: &Config, rec: &TaskRecord) -> Result<()> {
    let (tenant, name) = check_record(rec)?;
    fsutil::ensure_dir(&cfg.tasks_dir(), DIR_MODE)?;
    records::save(&record_path(cfg, tenant.as_str(), &name), rec)
}

/// Every task record.
pub fn list_all(cfg: &Config) -> Result<Vec<TaskRecord>> {
    records::list(&cfg.tasks_dir())
}

/// The tasks of one tenant, by name.
pub fn list_for(cfg: &Config, tenant: &str) -> Result<Vec<TaskRecord>> {
    let mut all = list_all(cfg)?;
    all.retain(|t| t.tenant == tenant);
    all.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(all)
}

// --- status ------------------------------------------------------------

/// What systemd knows about a task's last and next run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskStatus {
    pub running: bool,
    /// UNIX seconds; 0 = unknown / none.
    pub last_started: u64,
    pub last_finished: u64,
    /// systemd's `Result` of the last run; empty if it has not run.
    pub last_result: String,
    pub last_exit_status: i32,
    pub next_run: u64,
}

/// A time as `systemctl show` prints it, to UNIX seconds: `@1731580000`
/// (`--timestamp=unix`), or `Fri 2026-11-13 20:47:00 UTC` — systemd 252
/// prints a timer's next elapse that way whatever `--timestamp` says, in the
/// zone of its environment, which the daemon sets to UTC for every command.
/// Anything else (empty, `n/a`, another zone) is 0: unknown.
fn unix_stamp(text: &str) -> u64 {
    if let Some(secs) = text.strip_prefix('@') {
        return secs
            .split('.')
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
    }
    let words: Vec<&str> = text.split_whitespace().collect();
    let [_weekday, date, time, "UTC"] = words.as_slice() else {
        return 0;
    };
    let num = |n: &str| n.parse::<i64>().ok();
    let mut dates = date.split('-').map(num);
    let mut times = time.split('.').next().unwrap_or("").split(':').map(num);
    let (
        Some(Some(year)),
        Some(Some(month)),
        Some(Some(day)),
        Some(Some(hour)),
        Some(Some(minute)),
        Some(Some(second)),
    ) = (
        dates.next(),
        dates.next(),
        dates.next(),
        times.next(),
        times.next(),
        times.next(),
    )
    else {
        return 0;
    };
    // Days from the civil date (Howard Hinnant's algorithm).
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second).unwrap_or(0)
}

/// Parse `systemctl show` output for a task's service and timer.
pub fn parse_status(show: &str, units: &TaskUnits) -> TaskStatus {
    let mut by_unit: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for block in show.split("\n\n") {
        let props: BTreeMap<String, String> = block
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        if let Some(id) = props.get("Id") {
            by_unit.insert(id.clone(), props);
        }
    }
    let empty = BTreeMap::new();
    let svc = by_unit.get(&units.service_name).unwrap_or(&empty);
    let timer = by_unit.get(&units.timer_name).unwrap_or(&empty);
    let get = |m: &BTreeMap<String, String>, k: &str| m.get(k).cloned().unwrap_or_default();
    let last_started = unix_stamp(&get(svc, "ExecMainStartTimestamp"));
    let running = matches!(
        get(svc, "ActiveState").as_str(),
        "activating" | "active" | "deactivating"
    );
    TaskStatus {
        running,
        last_started,
        last_finished: unix_stamp(&get(svc, "ExecMainExitTimestamp")),
        last_result: if last_started == 0 || running {
            String::new()
        } else {
            get(svc, "Result")
        },
        last_exit_status: get(svc, "ExecMainStatus").parse().unwrap_or(0),
        next_run: unix_stamp(&get(timer, "NextElapseUSecRealtime")),
    }
}

// --- the service -------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TaskService {
    ctx: Ctx,
}

fn systemctl(ctx: &Ctx) -> CommandSpec {
    CommandSpec::new(bin::SYSTEMCTL, ctx.config.command_timeout)
}

impl TaskService {
    pub fn new(ctx: Ctx) -> Self {
        Self { ctx }
    }

    fn ready_tenant(&self, name: &Username) -> Result<TenantRecord> {
        let rec = self
            .ctx
            .store
            .load_tenant(name)?
            .ok_or_else(|| Error::TenantNotFound(name.to_string()))?;
        if rec.state != TenantState::Ready {
            return Err(Error::TenantNotReady(name.to_string()));
        }
        Ok(rec)
    }

    fn load_task(&self, tenant: &Username, name: &str) -> Result<TaskRecord> {
        load(&self.ctx.config, tenant, name)?.ok_or_else(|| Error::TaskNotFound {
            tenant: tenant.to_string(),
            name: name.to_owned(),
        })
    }

    /// Everything the host must provide before a task of `kind` can run.
    async fn require_runtime(&self, kind: TaskKind) -> Result<()> {
        match kind {
            TaskKind::Node => app::preflight(&self.ctx, AppRuntime::Node).await,
            TaskKind::Python => app::preflight(&self.ctx, AppRuntime::Python).await,
            TaskKind::Php | TaskKind::Url => {
                let (program, what) = if kind == TaskKind::Php {
                    (bin::PHP_CLI, "PHP's command-line interpreter (php-cli)")
                } else {
                    (bin::CURL, "curl")
                };
                if !self.ctx.sys.is_installed(program).await {
                    return Err(Error::RuntimeUnavailable(what));
                }
                app::require_policy(&self.ctx).await
            }
        }
    }

    /// Create or replace a task (idempotent). Everything is validated and
    /// every precondition checked before anything is written; the record
    /// is written before the units, so a repeated request completes an
    /// interrupted one. Returns the record and whether anything changed.
    pub async fn put(&self, tenant: &str, raw: &RawSpec) -> Result<(TaskRecord, bool)> {
        let name = Username::parse_field(tenant, "tenant")?;
        let cfg = &self.ctx.config;
        let draft = parse_spec(raw, &cfg.essentials)?;
        let _guard = self.ctx.lock.lock().await;
        let tenant_rec = self.ready_tenant(&name)?;
        if draft.kind == TaskKind::Url {
            let (_, host) = parse_url(&draft.url)?;
            let own =
                self.ctx.store.list_vhosts()?.iter().any(|v| {
                    v.tenant == name.as_str() && v.all_names().any(|n| n == host.as_str())
                });
            if !own {
                return Err(Error::invalid(
                    "spec.url",
                    format!("'{host}' is not one of this tenant's sites"),
                ));
            }
        }
        self.require_runtime(draft.kind).await?;
        let existing = load(cfg, &name, &draft.name)?;
        if existing.is_none() {
            let max = cfg.essentials.task_max_per_tenant;
            if list_for(cfg, name.as_str())?.len() >= max as usize {
                return Err(Error::TaskLimitReached {
                    tenant: name.to_string(),
                    max,
                });
            }
        }
        let rec = TaskRecord {
            tenant: name.to_string(),
            created_at_unix: existing
                .as_ref()
                .map_or_else(now_unix, |e| e.created_at_unix),
            ..draft
        };
        let record_changed = existing.as_ref().is_none_or(|e| !e.same_spec(&rec));
        if record_changed {
            save(cfg, &rec)?;
        }
        let files_changed = write_units(&self.ctx, &rec, &tenant_rec).await?;
        apply_timer(&self.ctx, &rec, &tenant_rec, files_changed).await?;
        if record_changed || files_changed {
            info!(tenant = %name, task = %rec.name, enabled = rec.enabled, "scheduled task saved");
        }
        Ok((rec, record_changed || files_changed))
    }

    /// Remove a task: its timer stops, a running instance is ended, both
    /// units and the record go. Returns whether it existed.
    pub async fn delete(&self, tenant: &str, name: &str) -> Result<bool> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let name = parse_name(name, "name")?;
        let _guard = self.ctx.lock.lock().await;
        let Some(rec) = load(&self.ctx.config, &tenant, &name)? else {
            return Ok(false);
        };
        remove_task(&self.ctx, &rec).await?;
        info!(%tenant, task = %name, "scheduled task deleted");
        Ok(true)
    }

    /// The tenant's tasks.
    pub async fn list(&self, tenant: &str) -> Result<Vec<TaskRecord>> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        self.ready_tenant(&tenant)?;
        list_for(&self.ctx.config, tenant.as_str())
    }

    /// What systemd knows about each task's last and next run (one call).
    pub async fn status(&self, tasks: &[TaskRecord]) -> Result<Vec<TaskStatus>> {
        if tasks.is_empty() {
            return Ok(Vec::new());
        }
        let units = tasks
            .iter()
            .map(|t| TaskUnits::of(&self.ctx.config, t))
            .collect::<Result<Vec<_>>>()?;
        let mut cmd = systemctl(&self.ctx).args([
            "show",
            "--timestamp=unix",
            "--property=Id,ActiveState,Result,ExecMainStartTimestamp,ExecMainExitTimestamp,ExecMainStatus,NextElapseUSecRealtime",
            "--",
        ]);
        for u in &units {
            cmd = cmd.arg(&u.service_name).arg(&u.timer_name);
        }
        let show = self.ctx.sys.run(cmd).await?.stdout_lossy();
        Ok(units.iter().map(|u| parse_status(&show, u)).collect())
    }

    /// Start a task now (enabled or not). Returns `false` if it is already
    /// running: it is never started twice. Refused while suspended.
    pub async fn run_now(&self, tenant: &str, name: &str) -> Result<bool> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let name = parse_name(name, "name")?;
        let _guard = self.ctx.lock.lock().await;
        let tenant_rec = self.ready_tenant(&tenant)?;
        if tenant_rec.suspended {
            return Err(Error::TenantNotReady(tenant.to_string()));
        }
        let rec = self.load_task(&tenant, &name)?;
        // The unit must be what the record says (an interrupted Put).
        if write_units(&self.ctx, &rec, &tenant_rec).await? {
            apply_timer(&self.ctx, &rec, &tenant_rec, true).await?;
        }
        let units = TaskUnits::of(&self.ctx.config, &rec)?;
        if self
            .status(std::slice::from_ref(&rec))
            .await?
            .first()
            .is_some_and(|s| s.running)
        {
            return Ok(false);
        }
        self.ctx
            .sys
            .run_ok(
                systemctl(&self.ctx)
                    .args(["start", "--no-block", "--"])
                    .arg(&units.service_name),
            )
            .await?;
        info!(%tenant, task = %name, "scheduled task started by request");
        Ok(true)
    }

    /// The end of the task's output, from the journal.
    pub async fn read_log(&self, tenant: &str, name: &str) -> Result<String> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let name = parse_name(name, "name")?;
        let rec = self.load_task(&tenant, &name)?;
        let units = TaskUnits::of(&self.ctx.config, &rec)?;
        let out = self
            .ctx
            .sys
            .run_ok(
                CommandSpec::new(bin::JOURNALCTL, self.ctx.config.command_timeout)
                    .args(["--no-pager", "--output=short-iso", "--lines"])
                    .arg(LOG_LINES)
                    .arg("--unit")
                    .arg(&units.service_name),
            )
            .await?;
        Ok(out.stdout_lossy())
    }
}

/// Write both units; `daemon-reload` if either changed. Returns whether.
async fn write_units(ctx: &Ctx, rec: &TaskRecord, tenant: &TenantRecord) -> Result<bool> {
    let cfg = &ctx.config;
    let units = TaskUnits::of(cfg, rec)?;
    let service = render_service(rec, tenant, ctx.selinux)?;
    let timer = render_timer(rec)?;
    let a = fsutil::write_atomic(&units.service, service.as_bytes(), FILE_MODE)?;
    let b = fsutil::write_atomic(&units.timer, timer.as_bytes(), FILE_MODE)?;
    if a || b {
        systemd::daemon_reload(ctx.sys.as_ref(), cfg.command_timeout).await?;
    }
    Ok(a || b)
}

/// Enable the timer of an enabled task of a tenant that is not suspended
/// (restarting it when its unit changed, so the new schedule applies),
/// disable it otherwise. A run in progress is left to finish.
async fn apply_timer(
    ctx: &Ctx,
    rec: &TaskRecord,
    tenant: &TenantRecord,
    changed: bool,
) -> Result<()> {
    let units = TaskUnits::of(&ctx.config, rec)?;
    let timer = units.timer_name;
    if rec.enabled && !tenant.suspended {
        if changed {
            ctx.sys
                .run_ok(systemctl(ctx).args(["enable", "--"]).arg(&timer))
                .await?;
            ctx.sys
                .run_ok(systemctl(ctx).args(["restart", "--"]).arg(&timer))
                .await?;
        } else {
            ctx.sys
                .run_ok(systemctl(ctx).args(["enable", "--now", "--"]).arg(&timer))
                .await?;
        }
    } else {
        ctx.sys
            .run_ok(systemctl(ctx).args(["disable", "--now", "--"]).arg(&timer))
            .await?;
    }
    Ok(())
}

/// Stop and remove a task's units, then its record (last: until then a
/// repeated request finds it and finishes). The caller holds the lock.
async fn remove_task(ctx: &Ctx, rec: &TaskRecord) -> Result<()> {
    let cfg = &ctx.config;
    let units = TaskUnits::of(cfg, rec)?;
    if units.timer.exists() {
        ctx.sys
            .run_ok(
                systemctl(ctx)
                    .args(["disable", "--now", "--"])
                    .arg(&units.timer_name),
            )
            .await?;
    }
    if units.service.exists() {
        ctx.sys
            .run_ok(systemctl(ctx).args(["stop", "--"]).arg(&units.service_name))
            .await?;
    }
    let a = fsutil::remove_if_exists(&units.timer)?;
    let b = fsutil::remove_if_exists(&units.service)?;
    if a || b {
        systemd::daemon_reload(ctx.sys.as_ref(), cfg.command_timeout).await?;
        // A unit that failed stays listed until its state is reset.
        ctx.sys
            .run(
                systemctl(ctx)
                    .args(["reset-failed", "--"])
                    .arg(&units.service_name),
            )
            .await?;
    }
    let (tenant, name) = check_record(rec)?;
    fsutil::remove_if_exists(&record_path(cfg, tenant.as_str(), &name))?;
    Ok(())
}

/// Suspend / resume: every timer of the tenant is disabled and every running
/// task stopped, or the timers of enabled tasks are enabled again. Disabled
/// as well as stopped, so a reboot does not revive a suspended tenant's tasks.
pub async fn set_running_all(ctx: &Ctx, tenant: &TenantRecord, running: bool) -> Result<()> {
    for rec in list_for(&ctx.config, &tenant.username)? {
        let units = TaskUnits::of(&ctx.config, &rec)?;
        if !units.timer.exists() {
            continue;
        }
        if running {
            if rec.enabled {
                ctx.sys
                    .run_ok(
                        systemctl(ctx)
                            .args(["enable", "--now", "--"])
                            .arg(&units.timer_name),
                    )
                    .await?;
            }
        } else {
            ctx.sys
                .run_ok(
                    systemctl(ctx)
                        .args(["disable", "--now", "--"])
                        .arg(&units.timer_name),
                )
                .await?;
            ctx.sys
                .run_ok(systemctl(ctx).args(["stop", "--"]).arg(&units.service_name))
                .await?;
        }
    }
    Ok(())
}

/// Deleting a tenant: every task goes (configuration, not data). The
/// caller holds the mutation lock.
pub async fn remove_all(ctx: &Ctx, tenant: &str) -> Result<usize> {
    let tasks = list_for(&ctx.config, tenant)?;
    for rec in &tasks {
        remove_task(ctx, rec).await?;
    }
    if !tasks.is_empty() {
        info!(tenant, tasks = tasks.len(), "scheduled tasks removed");
    }
    Ok(tasks.len())
}

/// `Reconcile`: units that differ from their records, timers enabled when
/// they should not be (or the reverse), and units without a record.
pub fn drifts(ctx: &Ctx, tenants: &[TenantRecord]) -> Result<Vec<Drift>> {
    let cfg = &ctx.config;
    let by_name: BTreeMap<&str, &TenantRecord> =
        tenants.iter().map(|t| (t.username.as_str(), t)).collect();
    let mut out = Vec::new();
    let mut known: BTreeSet<PathBuf> = BTreeSet::new();
    for rec in list_all(cfg)? {
        let subject = format!("{}/{}", rec.tenant, rec.name);
        let Some(tenant) = by_name.get(rec.tenant.as_str()) else {
            out.push(Drift::new(
                DriftKind::TaskUnitDrift,
                subject,
                format!("tenant '{}' has no record", rec.tenant),
            ));
            continue;
        };
        let units = TaskUnits::of(cfg, &rec)?;
        known.insert(units.service.clone());
        known.insert(units.timer.clone());
        if tenant.state != TenantState::Ready {
            continue;
        }
        for (path, expected) in [
            (&units.service, render_service(&rec, tenant, ctx.selinux)?),
            (&units.timer, render_timer(&rec)?),
        ] {
            if let Some(problem) = crate::host::compare_file(path, &expected)? {
                out.push(Drift::new(
                    DriftKind::TaskUnitDrift,
                    subject.clone(),
                    format!("{} {problem}", path.display()),
                ));
            }
        }
        let want = rec.enabled && !tenant.suspended;
        let have = units.timer_wanted.symlink_metadata().is_ok();
        if want != have {
            out.push(Drift::new(
                DriftKind::TaskUnitDrift,
                subject,
                if want {
                    "the timer is not enabled; repeat PutScheduledTask"
                } else {
                    "the timer is enabled although the task is off or the tenant suspended"
                },
            ));
        }
    }
    for suffix in [".service", ".timer"] {
        for path in fsutil::list_files_with_suffix(&cfg.systemd_unit_dir, suffix)? {
            let ours = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("oxpanel-task-"));
            if ours && !known.contains(&path) {
                out.push(Drift::new(
                    DriftKind::OrphanTaskUnit,
                    path.to_string_lossy(),
                    "no scheduled task record accounts for this unit",
                ));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::system::FakeSystem;
    use std::sync::Arc;

    pub(crate) fn essentials() -> Essentials {
        Essentials::default()
    }

    fn raw(name: &str, kind: TaskKind) -> RawSpec {
        RawSpec {
            name: name.into(),
            kind: Some(kind),
            script: "public_html/cron.php".into(),
            schedule: RawSchedule {
                form: Some(Form::EveryMinutes),
                interval: 15,
                ..RawSchedule::default()
            },
            ..RawSpec::default()
        }
    }

    fn tenant_rec(name: &str) -> TenantRecord {
        let n = Username::parse(name).unwrap_or_else(|e| panic!("{e}"));
        TenantRecord {
            version: RECORD_VERSION,
            username: name.into(),
            uid: 20000,
            gid: 20000,
            home: PathBuf::from(format!("/home/{name}")),
            limits: crate::validate::Limits::default(),
            slice_unit: systemd::slice_unit_name(&n),
            created_at_unix: 0,
            state: TenantState::Ready,
            owner: String::new(),
            suspended: false,
            sftp_keys: Vec::new(),
            sftp_password: false,
            php_limits: crate::php_settings::PhpLimits::default(),
        }
    }

    fn rec(tenant: &str, spec: &RawSpec) -> TaskRecord {
        let mut r = parse_spec(spec, &essentials()).unwrap_or_else(|e| panic!("{e}"));
        r.tenant = tenant.into();
        r
    }

    #[test]
    fn schedules_map_onto_calendar_expressions() -> Result<()> {
        let e = essentials();
        let cases = [
            (
                Form::EveryMinutes,
                15,
                0,
                0,
                0,
                0,
                "",
                "*-*-* *:00/15:00",
                899,
            ),
            (
                Form::EveryMinutes,
                5,
                0,
                0,
                0,
                0,
                "",
                "*-*-* *:00/05:00",
                299,
            ),
            (
                Form::EveryHours,
                2,
                30,
                0,
                0,
                0,
                "",
                "*-*-* 00/02:30:00 UTC",
                899,
            ),
            (
                Form::Daily,
                0,
                5,
                3,
                0,
                0,
                "Europe/Berlin",
                "*-*-* 03:05:00 Europe/Berlin",
                899,
            ),
            (
                Form::Weekly,
                0,
                0,
                23,
                0,
                0,
                "",
                "Sun *-*-* 23:00:00 UTC",
                899,
            ),
            (
                Form::Monthly,
                0,
                59,
                1,
                0,
                28,
                "",
                "*-*-28 01:59:00 UTC",
                899,
            ),
        ];
        for (form, interval, minute, hour, weekday, day, tz, want, delay) in cases {
            let (s, zone) = Schedule::parse(
                &RawSchedule {
                    form: Some(form),
                    interval,
                    minute,
                    hour,
                    weekday,
                    day_of_month: day,
                    time_zone: tz.into(),
                },
                &e,
            )?;
            assert_eq!(s.calendar(&zone), want);
            assert_eq!(s.randomized_delay_secs(), delay);
        }
        Ok(())
    }

    #[test]
    fn schedules_outside_the_allow_list_are_refused() {
        let e = essentials();
        for (form, interval, minute, hour, weekday, day, tz) in [
            (None, 15, 0, 0, 0, 0, ""),
            (Some(Form::EveryMinutes), 7, 0, 0, 0, 0, ""),
            (Some(Form::EveryMinutes), 1, 0, 0, 0, 0, ""), // below the host minimum (5)
            (Some(Form::EveryMinutes), 15, 0, 0, 0, 0, "UTC"),
            (Some(Form::EveryHours), 5, 0, 0, 0, 0, ""),
            (Some(Form::EveryHours), 2, 60, 0, 0, 0, ""),
            (Some(Form::Daily), 0, 0, 24, 0, 0, ""),
            (Some(Form::Weekly), 0, 0, 1, 7, 0, ""),
            (Some(Form::Monthly), 0, 0, 1, 0, 29, ""),
            (Some(Form::Monthly), 0, 0, 1, 0, 0, ""),
            (
                Some(Form::Daily),
                0,
                0,
                1,
                0,
                0,
                "Europe/Berlin; OnCalendar=*:*",
            ),
            (Some(Form::Daily), 0, 0, 1, 0, 0, "../../../etc/passwd"),
        ] {
            assert!(
                Schedule::parse(
                    &RawSchedule {
                        form,
                        interval,
                        minute,
                        hour,
                        weekday,
                        day_of_month: day,
                        time_zone: tz.into(),
                    },
                    &e
                )
                .is_err(),
                "{form:?} {interval} {minute} {hour} {weekday} {day} {tz:?}"
            );
        }
    }

    #[test]
    fn php_task_units_are_exact() -> Result<()> {
        let mut spec = raw("nightly-report", TaskKind::Php);
        spec.args = vec!["--mode=full".into(), "two words".into()];
        spec.timeout_secs = 120;
        let r = rec("foo-bar", &spec);
        let t = tenant_rec("foo-bar");
        let units = TaskUnits::new(
            Path::new("/etc/systemd/system"),
            &Username::parse("foo-bar")?,
            "nightly-report",
        );
        assert_eq!(
            units.service_name,
            "oxpanel-task-foo\\x2dbar-nightly\\x2dreport.service"
        );
        assert_eq!(
            units.timer_name,
            "oxpanel-task-foo\\x2dbar-nightly\\x2dreport.timer"
        );
        assert_eq!(
            units.timer_wanted,
            PathBuf::from("/etc/systemd/system/timers.target.wants/oxpanel-task-foo\\x2dbar-nightly\\x2dreport.timer")
        );
        let service = render_service(&r, &t, true)?;
        assert_eq!(
            service,
            "# Managed by oxpanel-daemon. Manual edits will be overwritten.
[Unit]
Description=OxPanel scheduled task nightly-report of tenant foo-bar
Documentation=https://github.com/OxServers/oxpanel
After=network.target

[Service]
Type=oneshot
User=foo-bar
Group=foo-bar
Slice=oxpanel-tenant-foo\\x2dbar.slice
SELinuxContext=system_u:system_r:oxpanel_app_t:s0
WorkingDirectory=/home/foo-bar/public_html
Environment=HOME=/home/foo-bar
Environment=OXPANEL_TASK=nightly-report
ExecStart=/usr/bin/php \"-f\" \"/home/foo-bar/public_html/cron.php\" \"--\" \"--mode=full\" \"two words\"
# The time limit: the whole control group is ended, children included.
TimeoutStartSec=120s
TimeoutStopSec=10s
UMask=0022

# The task already runs unprivileged as the tenant; this narrows it further.
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ReadWritePaths=/home/foo-bar
# The engine's socket is closed to tenants by its mode; here it does not even exist.
InaccessiblePaths=-/run/oxpanel
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
"
        );
        assert!(!render_service(&r, &t, false)?.contains("SELinuxContext"));
        assert_eq!(
            render_timer(&r)?,
            "# Managed by oxpanel-daemon. Manual edits will be overwritten.
[Unit]
Description=Schedule of OxPanel task nightly-report of tenant foo-bar
Documentation=https://github.com/OxServers/oxpanel

[Timer]
Unit=oxpanel-task-foo\\x2dbar-nightly\\x2dreport.service
OnCalendar=*-*-* *:00/15:00
# A fixed offset per unit: each task keeps its interval, tasks do not start together.
RandomizedDelaySec=899s
FixedRandomDelay=yes
AccuracySec=1s
# Missed runs (the host was off) are not caught up, as with cron.
Persistent=false

[Install]
WantedBy=timers.target
"
        );
        Ok(())
    }

    #[test]
    fn every_kind_executes_a_system_binary() -> Result<()> {
        let home = Path::new("/home/alice");
        let mut node = raw("n", TaskKind::Node);
        node.script = "apps/x/job.js".into();
        assert_eq!(
            argv(&rec("alice", &node), home)?,
            vec!["/usr/bin/node", "/home/alice/apps/x/job.js"]
        );
        let mut py = raw("p", TaskKind::Python);
        py.script = "apps/api/job.py".into();
        py.args = vec!["x".into()];
        assert_eq!(
            argv(&rec("alice", &py), home)?,
            vec!["/usr/bin/python3", "/home/alice/apps/api/job.py", "x"]
        );
        py.virtualenv = "apps/api/.venv".into();
        assert_eq!(
            argv(&rec("alice", &py), home)?,
            vec![
                "/usr/bin/env",
                "/home/alice/apps/api/.venv/bin/python",
                "/home/alice/apps/api/job.py",
                "x"
            ]
        );
        let url = RawSpec {
            script: String::new(),
            url: "https://shop.example.com/wp-cron.php?doing_wp_cron=1&x=%2F".into(),
            ..raw("u", TaskKind::Url)
        };
        let r = rec("alice", &url);
        let words = argv(&r, home)?;
        assert_eq!(words.first().map(String::as_str), Some("/usr/bin/curl"));
        assert!(words
            .windows(2)
            .any(|w| w == ["--resolve", "shop.example.com:443:127.0.0.1"]));
        assert_eq!(
            words.last().map(String::as_str),
            Some("https://shop.example.com/wp-cron.php?doing_wp_cron=1&x=%2F")
        );
        let line = exec_line(&words)?;
        assert!(
            line.contains("\"HTTP %%{http_code}, %%{size_download} bytes in %%{time_total}s\""),
            "{line}"
        );
        assert!(
            line.ends_with("\"https://shop.example.com/wp-cron.php?doing_wp_cron=1&x=%%2F\""),
            "{line}"
        );
        assert_eq!(working_dir(&r, home), PathBuf::from("/home/alice"));
        Ok(())
    }

    #[test]
    fn injection_attempts_in_every_field_are_refused() {
        let e = essentials();
        let base = raw("ok", TaskKind::Php);
        let mut bad: Vec<RawSpec> = Vec::new();
        for name in [
            "",
            "A",
            "-x",
            "x y",
            "x\nUser=root",
            "x.y",
            "a/b",
            &"a".repeat(33),
        ] {
            bad.push(RawSpec {
                name: name.into(),
                ..base.clone()
            });
        }
        for script in [
            "",
            "/etc/passwd",
            "../bob/x.php",
            "x.php\nExecStartPre=/bin/sh",
            "x.php; rm -rf ~",
            "x y.php",
            "$HOME/x.php",
        ] {
            bad.push(RawSpec {
                script: script.into(),
                ..base.clone()
            });
        }
        for arg in [
            "a\"b",
            "a'b",
            "a`b`",
            "a\\nb",
            "$HOME",
            "${HOME}",
            "%h",
            "a\nb",
            "a\tb",
            &"x".repeat(257),
        ] {
            bad.push(RawSpec {
                args: vec![arg.into()],
                ..base.clone()
            });
        }
        bad.push(RawSpec {
            args: vec!["x".into(); 17],
            ..base.clone()
        });
        bad.push(RawSpec {
            url: "https://example.com/".into(),
            ..base.clone()
        });
        bad.push(RawSpec {
            virtualenv: "apps/.venv".into(),
            ..base.clone()
        });
        bad.push(RawSpec {
            kind: Some(TaskKind::Python),
            virtualenv: "../../usr".into(),
            ..base.clone()
        });
        bad.push(RawSpec {
            kind: None,
            ..base.clone()
        });
        bad.push(RawSpec {
            timeout_secs: 5,
            ..base.clone()
        });
        bad.push(RawSpec {
            timeout_secs: 3601,
            ..base.clone()
        });
        for spec in &bad {
            assert!(parse_spec(spec, &e).is_err(), "{spec:?}");
        }
        assert!(parse_spec(&base, &e).is_ok());
    }

    #[test]
    fn url_injection_attempts_are_refused() {
        let e = essentials();
        let base = RawSpec {
            kind: Some(TaskKind::Url),
            script: String::new(),
            ..raw("u", TaskKind::Url)
        };
        let mut bad = Vec::new();
        for url in [
            "ftp://example.com/",
            "https://user:pw@example.com/",
            "https://example.com:8080/",
            "https://example.com/a b",
            "https://example.com/$HOME",
            "https://example.com/%zz",
            "https://example.com/\"",
            "https://example.com/x\nUser=root",
            "https://127.0.0.1/",
            "https://example.com/#frag",
        ] {
            bad.push(RawSpec {
                kind: Some(TaskKind::Url),
                script: String::new(),
                url: url.into(),
                ..base.clone()
            });
        }
        for spec in &bad {
            assert!(parse_spec(spec, &e).is_err(), "{spec:?}");
        }
        assert!(parse_spec(
            &RawSpec {
                url: "https://example.com/cron.php?a=1&b=%2F".into(),
                ..base
            },
            &e
        )
        .is_ok());
    }

    #[test]
    fn a_record_that_was_tampered_with_is_never_rendered() {
        let t = tenant_rec("alice");
        let good = rec("alice", &raw("job", TaskKind::Php));
        let mut cases = Vec::new();
        for f in [
            |r: &mut TaskRecord| r.args = vec!["x\"\nUser=root".into()],
            |r: &mut TaskRecord| r.script = "x.php\nUser=root".into(),
            |r: &mut TaskRecord| r.time_zone = "UTC\nOnCalendar=*:*".into(),
            |r: &mut TaskRecord| r.name = "job\nx".into(),
            |r: &mut TaskRecord| r.tenant = "bob".into(),
            |r: &mut TaskRecord| r.schedule = Schedule::EveryMinutes { interval: 7 },
            |r: &mut TaskRecord| r.timeout_secs = 0,
        ] {
            let mut r = good.clone();
            f(&mut r);
            cases.push(r);
        }
        for r in &cases {
            assert!(
                render_service(r, &t, false).is_err() || render_timer(r).is_err(),
                "{r:?}"
            );
        }
    }

    #[test]
    fn status_comes_from_systemctl_show() {
        let units = TaskUnits::new(
            Path::new("/etc/systemd/system"),
            &Username::parse("alice").unwrap(),
            "job",
        );
        let show = "Id=oxpanel-task-alice-job.service\nActiveState=inactive\nResult=exit-code\nExecMainStartTimestamp=@1794571200\nExecMainExitTimestamp=@1794571203\nExecMainStatus=3\n\nId=oxpanel-task-alice-job.timer\nActiveState=active\nNextElapseUSecRealtime=@1794572100\n";
        assert_eq!(
            parse_status(show, &units),
            TaskStatus {
                running: false,
                last_started: 1_794_571_200,
                last_finished: 1_794_571_203,
                last_result: "exit-code".into(),
                last_exit_status: 3,
                next_run: 1_794_572_100,
            }
        );
        assert_eq!(unix_stamp("Fri 2026-11-13 20:47:00 UTC"), 1_794_602_820);
        assert_eq!(unix_stamp("Thu 1970-01-01 00:00:01 UTC"), 1);
        assert_eq!(unix_stamp("Sat 2024-02-29 12:00:00 UTC"), 1_709_208_000);
        assert_eq!(
            unix_stamp("Sat 2026-11-14 01:47:00 PKT"),
            0,
            "not UTC: unknown"
        );
        assert_eq!(unix_stamp("n/a"), 0);
        let never = "Id=oxpanel-task-alice-job.service\nActiveState=inactive\nResult=success\nExecMainStartTimestamp=\nExecMainStatus=0\n\nId=oxpanel-task-alice-job.timer\nNextElapseUSecRealtime=\n";
        assert_eq!(parse_status(never, &units), TaskStatus::default());
        let running = "Id=oxpanel-task-alice-job.service\nActiveState=activating\nResult=success\nExecMainStartTimestamp=@5\n";
        assert!(parse_status(running, &units).running);
        assert_eq!(parse_status(running, &units).last_result, "");
    }

    struct Harness {
        _dir: tempfile::TempDir,
        sys: Arc<FakeSystem>,
        svc: TaskService,
        ctx: Ctx,
    }

    fn harness() -> Harness {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let mut cfg = Config::default();
        crate::config::sandbox_feature_paths(&mut cfg, dir.path());
        cfg.state_dir = dir.path().join("state");
        cfg.systemd_unit_dir = dir.path().join("systemd");
        cfg.essentials.task_max_per_tenant = 3;
        std::fs::create_dir_all(&cfg.systemd_unit_dir).unwrap_or_else(|e| panic!("{e}"));
        let sys = Arc::new(FakeSystem::new());
        let ctx = Ctx::new(cfg, sys.clone(), false);
        ctx.store.init().unwrap_or_else(|e| panic!("{e}"));
        ctx.store
            .save_tenant(&tenant_rec("alice"))
            .unwrap_or_else(|e| panic!("{e}"));
        Harness {
            _dir: dir,
            sys: sys.clone(),
            svc: TaskService::new(ctx.clone()),
            ctx,
        }
    }

    fn systemctl_calls(sys: &FakeSystem) -> Vec<Vec<String>> {
        sys.calls_to(bin::SYSTEMCTL)
            .iter()
            .map(|c| {
                c.args
                    .iter()
                    .map(|a| a.to_string_lossy().into_owned())
                    .collect()
            })
            .collect()
    }

    fn v(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    #[tokio::test]
    async fn put_writes_units_enables_the_timer_and_is_idempotent() -> Result<()> {
        let h = harness();
        let spec = raw("job", TaskKind::Php);
        let (r, changed) = h.svc.put("alice", &spec).await?;
        assert!(changed);
        assert_eq!(r.tenant, "alice");
        let timer = "oxpanel-task-alice-job.timer";
        assert_eq!(
            systemctl_calls(&h.sys),
            vec![
                v(&["daemon-reload"]),
                v(&["enable", "--", timer]),
                v(&["restart", "--", timer]),
            ]
        );
        let units = TaskUnits::of(&h.ctx.config, &r)?;
        assert!(units.service.exists() && units.timer.exists());
        h.sys.clear_calls();
        let (_, changed) = h.svc.put("alice", &spec).await?;
        assert!(!changed, "repeating the request changes nothing");
        assert_eq!(
            systemctl_calls(&h.sys),
            vec![v(&["enable", "--now", "--", timer])]
        );
        // Switched off: the timer is disabled, the units stay (run now works).
        h.sys.clear_calls();
        let off = RawSpec {
            disabled: true,
            ..spec.clone()
        };
        let (_, changed) = h.svc.put("alice", &off).await?;
        assert!(changed);
        assert_eq!(
            systemctl_calls(&h.sys),
            vec![v(&["disable", "--now", "--", timer])]
        );
        assert!(units.service.exists());
        Ok(())
    }

    #[tokio::test]
    async fn the_per_tenant_limit_and_preconditions_are_checked_first() -> Result<()> {
        let h = harness();
        h.svc.put("alice", &raw("one", TaskKind::Php)).await?;
        h.svc.put("alice", &raw("two", TaskKind::Php)).await?;
        h.svc.put("alice", &raw("four", TaskKind::Php)).await?;
        h.sys.clear_calls();
        assert!(matches!(
            h.svc.put("alice", &raw("three", TaskKind::Php)).await,
            Err(Error::TaskLimitReached { max: 3, .. })
        ));
        // Replacing an existing one is not a new task.
        assert!(h
            .svc
            .put(
                "alice",
                &RawSpec {
                    timeout_secs: 60,
                    ..raw("two", TaskKind::Php)
                }
            )
            .await
            .is_ok());
        h.svc.delete("alice", "two").await?;
        h.sys.set_missing(bin::PHP_CLI);
        h.sys.clear_calls();
        assert!(matches!(
            h.svc.put("alice", &raw("three", TaskKind::Php)).await,
            Err(Error::RuntimeUnavailable(_))
        ));
        assert!(systemctl_calls(&h.sys).is_empty(), "nothing touched");
        assert!(load(&h.ctx.config, &Username::parse("alice")?, "three")?.is_none());
        // A URL task may only name the tenant's own sites.
        let url = RawSpec {
            kind: Some(TaskKind::Url),
            script: String::new(),
            url: "http://victim.example/".into(),
            ..raw("u", TaskKind::Url)
        };
        assert!(matches!(
            h.svc.put("alice", &url).await,
            Err(Error::InvalidInput { .. })
        ));
        assert!(matches!(
            h.svc.put("carol", &raw("x", TaskKind::Php)).await,
            Err(Error::TenantNotFound(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn delete_suspend_resume_and_tenant_removal() -> Result<()> {
        let h = harness();
        h.svc.put("alice", &raw("on", TaskKind::Php)).await?;
        h.svc
            .put(
                "alice",
                &RawSpec {
                    disabled: true,
                    ..raw("off", TaskKind::Php)
                },
            )
            .await?;
        let mut t = tenant_rec("alice");
        h.sys.clear_calls();
        set_running_all(&h.ctx, &t, false).await?;
        assert_eq!(
            systemctl_calls(&h.sys),
            vec![
                v(&["disable", "--now", "--", "oxpanel-task-alice-off.timer"]),
                v(&["stop", "--", "oxpanel-task-alice-off.service"]),
                v(&["disable", "--now", "--", "oxpanel-task-alice-on.timer"]),
                v(&["stop", "--", "oxpanel-task-alice-on.service"]),
            ]
        );
        // A task saved while suspended is born disabled; run-now is refused.
        t.suspended = true;
        h.ctx.store.save_tenant(&t)?;
        h.sys.clear_calls();
        h.svc.put("alice", &raw("later", TaskKind::Php)).await?;
        assert_eq!(
            systemctl_calls(&h.sys).last(),
            Some(&v(&[
                "disable",
                "--now",
                "--",
                "oxpanel-task-alice-later.timer"
            ]))
        );
        assert!(matches!(
            h.svc.run_now("alice", "on").await,
            Err(Error::TenantNotReady(_))
        ));
        h.sys.clear_calls();
        set_running_all(&h.ctx, &tenant_rec("alice"), true).await?;
        assert_eq!(
            systemctl_calls(&h.sys),
            vec![
                v(&["enable", "--now", "--", "oxpanel-task-alice-later.timer"]),
                v(&["enable", "--now", "--", "oxpanel-task-alice-on.timer"]),
            ],
            "only enabled tasks come back"
        );
        h.ctx.store.save_tenant(&tenant_rec("alice"))?;
        assert!(
            h.svc.run_now("alice", "off").await?,
            "run now also runs a task that is off"
        );
        assert!(matches!(
            h.svc.run_now("alice", "nope").await,
            Err(Error::TaskNotFound { .. })
        ));
        h.sys.clear_calls();
        assert!(h.svc.delete("alice", "on").await?);
        assert_eq!(
            systemctl_calls(&h.sys),
            vec![
                v(&["disable", "--now", "--", "oxpanel-task-alice-on.timer"]),
                v(&["stop", "--", "oxpanel-task-alice-on.service"]),
                v(&["daemon-reload"]),
                v(&["reset-failed", "--", "oxpanel-task-alice-on.service"]),
            ]
        );
        assert!(!h.svc.delete("alice", "on").await?);
        assert_eq!(remove_all(&h.ctx, "alice").await?, 2);
        assert!(list_for(&h.ctx.config, "alice")?.is_empty());
        assert!(
            fsutil::list_files_with_suffix(&h.ctx.config.systemd_unit_dir, ".timer")?.is_empty()
        );
        Ok(())
    }

    #[tokio::test]
    async fn run_now_starts_without_blocking_and_reads_the_journal() -> Result<()> {
        let h = harness();
        h.svc.put("alice", &raw("job", TaskKind::Php)).await?;
        h.sys.clear_calls();
        assert!(h.svc.run_now("alice", "job").await?);
        let calls = systemctl_calls(&h.sys);
        assert_eq!(
            calls.last(),
            Some(&v(&[
                "start",
                "--no-block",
                "--",
                "oxpanel-task-alice-job.service"
            ]))
        );
        assert_eq!(
            calls.first(),
            Some(&v(&[
                "show",
                "--timestamp=unix",
                "--property=Id,ActiveState,Result,ExecMainStartTimestamp,ExecMainExitTimestamp,ExecMainStatus,NextElapseUSecRealtime",
                "--",
                "oxpanel-task-alice-job.service",
                "oxpanel-task-alice-job.timer",
            ]))
        );
        h.svc.read_log("alice", "job").await?;
        let j: Vec<String> = h
            .sys
            .calls_to(bin::JOURNALCTL)
            .remove(0)
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            j,
            v(&[
                "--no-pager",
                "--output=short-iso",
                "--lines",
                "200",
                "--unit",
                "oxpanel-task-alice-job.service"
            ])
        );
        Ok(())
    }

    #[tokio::test]
    async fn reconcile_reports_edited_missing_and_orphan_units() -> Result<()> {
        let h = harness();
        let (r, _) = h.svc.put("alice", &raw("job", TaskKind::Php)).await?;
        let units = TaskUnits::of(&h.ctx.config, &r)?;
        let tenants = vec![tenant_rec("alice")];
        // The fake system does not create the enable symlink.
        let kinds = |d: &[Drift]| {
            d.iter()
                .map(|d| (d.kind, d.subject.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            kinds(&drifts(&h.ctx, &tenants)?),
            vec![(DriftKind::TaskUnitDrift, "alice/job".to_owned())],
            "timer not enabled"
        );
        std::fs::create_dir_all(units.timer_wanted.parent().unwrap_or(Path::new("/")))
            .map_err(|e| Error::io("mkdir", "wants", e))?;
        std::os::unix::fs::symlink(&units.timer, &units.timer_wanted)
            .map_err(|e| Error::io("symlink", "wants", e))?;
        assert!(drifts(&h.ctx, &tenants)?.is_empty());
        std::fs::write(&units.service, "edited").map_err(|e| Error::io("write", "x", e))?;
        let stray = h
            .ctx
            .config
            .systemd_unit_dir
            .join("oxpanel-task-bob-x.timer");
        std::fs::write(&stray, "x").map_err(|e| Error::io("write", "x", e))?;
        assert_eq!(
            kinds(&drifts(&h.ctx, &tenants)?),
            vec![
                (DriftKind::TaskUnitDrift, "alice/job".to_owned()),
                (
                    DriftKind::OrphanTaskUnit,
                    stray.to_string_lossy().into_owned()
                ),
            ]
        );
        Ok(())
    }
}
