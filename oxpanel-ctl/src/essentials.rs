//! `oxpanel-ctl task|php|backup-schedule`: scheduled tasks, PHP settings per
//! site and scheduled backups.

use std::process::ExitCode;

use clap::{Args, Subcommand};
use tonic::transport::Channel;

use oxpanel_proto::v1 as pb;
use oxpanel_proto::v1::ox_panel_engine_client::OxPanelEngineClient;

use crate::emit;

macro_rules! say {
    ($($arg:tt)*) => { emit(&format!($($arg)*)) };
}

type Client = OxPanelEngineClient<Channel>;

#[derive(Subcommand, Debug)]
pub(crate) enum TaskCmd {
    /// Create or replace a scheduled task (cron job). It runs as the tenant,
    /// inside its limits, with a time limit, never twice at once.
    ///
    /// Schedules: "every 15m", "every 2h at :30", "hourly at :05",
    /// "daily 03:30", "weekly sun 03:30", "monthly 1 03:30".
    Set {
        tenant: String,
        name: String,
        #[command(flatten)]
        what: TaskWhat,
        /// When it runs (see above).
        #[arg(long)]
        schedule: String,
        /// Time zone of the hour and minute (IANA, e.g. Europe/Berlin); default UTC.
        #[arg(long, default_value = "")]
        tz: String,
        /// An argument for the script (repeat for more).
        #[arg(long = "arg", allow_hyphen_values = true)]
        args: Vec<String>,
        /// Python: a virtualenv directory relative to the home (e.g. apps/api/.venv).
        #[arg(long, default_value = "")]
        venv: String,
        /// Time limit in seconds (default 300).
        #[arg(long, default_value_t = 0)]
        timeout: u32,
        /// Saved, but not run on its schedule (`task run` still runs it).
        #[arg(long)]
        disabled: bool,
    },
    /// The tenant's tasks, with their last and next run.
    List { tenant: String },
    /// Run a task now (returns at once; see `task log`).
    Run { tenant: String, name: String },
    /// The end of a task's output.
    Log { tenant: String, name: String },
    /// Remove a task (a running instance is ended).
    Delete { tenant: String, name: String },
}

/// What a task runs: exactly one of these.
#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub(crate) struct TaskWhat {
    /// A PHP script, relative to the tenant home (needs php-cli).
    #[arg(long)]
    php: Option<String>,
    /// A Node.js script, relative to the tenant home.
    #[arg(long)]
    node: Option<String>,
    /// A Python script, relative to the tenant home.
    #[arg(long)]
    python: Option<String>,
    /// A URL of one of the tenant's own sites, fetched on this host.
    #[arg(long)]
    url: Option<String>,
}

#[derive(Subcommand, Debug)]
pub(crate) enum PhpCmd {
    /// Replace a PHP site's settings; without options, PHP's defaults again.
    Set {
        domain: String,
        #[command(flatten)]
        settings: PhpSettingArgs,
    },
    /// Cap the PHP settings of a tenant's sites (a plan); 0 = host maximum.
    Limits {
        tenant: String,
        /// memory_limit cap, e.g. 256M.
        #[arg(long, default_value = "0", value_parser = parse_mib)]
        memory_limit: u32,
        /// upload_max_filesize and post_max_size cap, e.g. 64M.
        #[arg(long, default_value = "0", value_parser = parse_mib)]
        upload_max: u32,
        /// max_execution_time cap in seconds.
        #[arg(long, default_value_t = 0)]
        max_execution_time: u32,
        /// max_input_time cap in seconds.
        #[arg(long, default_value_t = 0)]
        max_input_time: u32,
        /// max_input_vars cap.
        #[arg(long, default_value_t = 0)]
        max_input_vars: u32,
    },
}

#[derive(Args, Debug)]
pub(crate) struct PhpSettingArgs {
    /// memory_limit, e.g. 256M or 1G.
    #[arg(long, default_value = "0", value_parser = parse_mib)]
    memory_limit: u32,
    /// upload_max_filesize, e.g. 64M.
    #[arg(long, default_value = "0", value_parser = parse_mib)]
    upload_max: u32,
    /// post_max_size, e.g. 65M (default: upload_max + 1M).
    #[arg(long, default_value = "0", value_parser = parse_mib)]
    post_max: u32,
    /// max_execution_time in seconds (CPU time of the script).
    #[arg(long, default_value_t = 0)]
    max_execution_time: u32,
    /// max_input_time in seconds.
    #[arg(long, default_value_t = 0)]
    max_input_time: u32,
    /// max_input_vars.
    #[arg(long, default_value_t = 0)]
    max_input_vars: u32,
    /// display_errors on.
    #[arg(long)]
    display_errors: bool,
    /// date.timezone (IANA, e.g. Europe/Berlin).
    #[arg(long, default_value = "")]
    timezone: String,
}

#[derive(Subcommand, Debug)]
pub(crate) enum ScheduleCmd {
    /// Set when the engine backs the tenant up by itself: off, daily,
    /// weekly, or default (the host default). Times are UTC; the minute is
    /// always the engine's.
    Set {
        tenant: String,
        /// off, daily, weekly or default.
        frequency: String,
        /// Hour of day, UTC (0-23); default: assigned within the host's window.
        #[arg(long)]
        hour: Option<u32>,
        /// Weekly: sun, mon, tue, wed, thu, fri or sat; default: assigned.
        #[arg(long)]
        weekday: Option<String>,
    },
    /// The tenant's schedule, next run and last result.
    Show { tenant: String },
}

/// `256M`, `1G` (or a plain number of MiB) to MiB.
fn parse_mib(s: &str) -> Result<u32, String> {
    let s = s.trim();
    let (num, factor) = match s.chars().last() {
        Some('G' | 'g') => (&s[..s.len() - 1], 1024),
        Some('M' | 'm') => (&s[..s.len() - 1], 1),
        _ => (s, 1),
    };
    num.parse::<u32>()
        .ok()
        .and_then(|n| n.checked_mul(factor))
        .ok_or_else(|| format!("'{s}' is not a size such as 256M or 1G"))
}

const WEEKDAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

fn weekday(s: &str) -> Result<u32, String> {
    WEEKDAYS
        .iter()
        .position(|d| *d == s.to_ascii_lowercase())
        .and_then(|i| u32::try_from(i).ok())
        .ok_or_else(|| format!("'{s}' is not a weekday (sun, mon, ... sat)"))
}

fn hh_mm(s: &str) -> Result<(u32, u32), String> {
    let bad = || format!("'{s}' is not a time such as 03:30");
    let (h, m) = s.split_once(':').ok_or_else(bad)?;
    let h = if h.is_empty() {
        Ok(0)
    } else {
        h.parse().map_err(|_| bad())
    }?;
    Ok((h, m.parse().map_err(|_| bad())?))
}

/// "every 15m", "every 2h at :30", "hourly at :05", "daily 03:30",
/// "weekly sun 03:30", "monthly 1 03:30". The engine validates the values.
fn parse_schedule(s: &str, tz: &str) -> Result<pb::TaskSchedule, String> {
    use pb::TaskScheduleForm as F;
    let words: Vec<&str> = s.split_whitespace().collect();
    let mut out = pb::TaskSchedule {
        time_zone: tz.to_owned(),
        ..pb::TaskSchedule::default()
    };
    let bad = || format!("'{s}' is not a schedule (e.g. \"every 15m\", \"daily 03:30\")");
    let num = |w: &str| w.parse::<u32>().map_err(|_| bad());
    let form = match words.as_slice() {
        ["every", n] if n.ends_with('m') => {
            out.interval = num(n.trim_end_matches('m'))?;
            F::EveryMinutes
        }
        ["every", n, rest @ ..] if n.ends_with('h') => {
            out.interval = num(n.trim_end_matches('h'))?;
            out.minute = match rest {
                [] => 0,
                ["at", t] => hh_mm(t)?.1,
                _ => return Err(bad()),
            };
            F::EveryHours
        }
        ["hourly", rest @ ..] => {
            out.interval = 1;
            out.minute = match rest {
                [] => 0,
                ["at", t] => hh_mm(t)?.1,
                _ => return Err(bad()),
            };
            F::EveryHours
        }
        ["daily", t] => {
            (out.hour, out.minute) = hh_mm(t)?;
            F::Daily
        }
        ["weekly", d, t] => {
            out.weekday = weekday(d)?;
            (out.hour, out.minute) = hh_mm(t)?;
            F::Weekly
        }
        ["monthly", d, t] => {
            out.day_of_month = num(d)?;
            (out.hour, out.minute) = hh_mm(t)?;
            F::Monthly
        }
        _ => return Err(bad()),
    };
    out.form = form.into();
    Ok(out)
}

/// Seconds of an optional timestamp (0 when absent).
macro_rules! ts {
    ($t:expr) => {
        $t.as_ref().map_or(0, |t| t.seconds)
    };
}

fn print_task(t: &pb::ScheduledTask) {
    let spec = t.spec.clone().unwrap_or_default();
    let kind = pb::TaskKind::try_from(spec.kind).map_or("unknown", |k| match k {
        pb::TaskKind::Php => "php",
        pb::TaskKind::Node => "node",
        pb::TaskKind::Python => "python",
        pb::TaskKind::Url => "url",
        pb::TaskKind::Unspecified => "unknown",
    });
    let what = if spec.url.is_empty() {
        spec.script.clone()
    } else {
        spec.url.clone()
    };
    say!(
        "task={} tenant={} kind={} run={} args={} enabled={} calendar=\"{}\" timeout={} running={} last_started={} last_finished={} last_result={} last_exit_status={} next_run={} unit={}",
        spec.name,
        t.tenant,
        kind,
        what,
        if spec.args.is_empty() { "-".to_owned() } else { spec.args.join(" ") },
        !spec.disabled,
        t.calendar,
        spec.timeout_seconds,
        t.running,
        ts!(t.last_started),
        ts!(t.last_finished),
        if t.last_result.is_empty() { "-" } else { t.last_result.as_str() },
        t.last_exit_status,
        ts!(t.next_run),
        t.unit,
    );
}

pub(crate) async fn run_task(c: &mut Client, cmd: TaskCmd) -> Result<ExitCode, tonic::Status> {
    match cmd {
        TaskCmd::Set {
            tenant,
            name,
            what,
            schedule,
            tz,
            args,
            venv,
            timeout,
            disabled,
        } => {
            let schedule =
                parse_schedule(&schedule, &tz).map_err(tonic::Status::invalid_argument)?;
            let (kind, script, url) = match what {
                TaskWhat { php: Some(s), .. } => (pb::TaskKind::Php, s, String::new()),
                TaskWhat { node: Some(s), .. } => (pb::TaskKind::Node, s, String::new()),
                TaskWhat {
                    python: Some(s), ..
                } => (pb::TaskKind::Python, s, String::new()),
                TaskWhat { url: Some(u), .. } => (pb::TaskKind::Url, String::new(), u),
                _ => {
                    return Err(tonic::Status::invalid_argument(
                        "--php, --node, --python or --url",
                    ))
                }
            };
            let r = c
                .put_scheduled_task(pb::PutScheduledTaskRequest {
                    tenant,
                    spec: Some(pb::ScheduledTaskSpec {
                        name,
                        kind: kind.into(),
                        script,
                        args,
                        virtualenv: venv,
                        url,
                        schedule: Some(schedule),
                        timeout_seconds: timeout,
                        disabled,
                    }),
                })
                .await?
                .into_inner();
            say!("changed={}", r.changed);
            if let Some(t) = &r.task {
                print_task(t);
            }
        }
        TaskCmd::List { tenant } => {
            let r = c
                .list_scheduled_tasks(pb::ListScheduledTasksRequest { tenant })
                .await?
                .into_inner();
            for t in &r.tasks {
                print_task(t);
            }
        }
        TaskCmd::Run { tenant, name } => {
            let r = c
                .run_scheduled_task(pb::RunScheduledTaskRequest { tenant, name })
                .await?
                .into_inner();
            say!("started={}", r.started);
        }
        TaskCmd::Log { tenant, name } => {
            let r = c
                .read_scheduled_task_log(pb::ReadScheduledTaskLogRequest { tenant, name })
                .await?
                .into_inner();
            for line in r.text.lines() {
                say!("{line}");
            }
        }
        TaskCmd::Delete { tenant, name } => {
            let r = c
                .delete_scheduled_task(pb::DeleteScheduledTaskRequest { tenant, name })
                .await?
                .into_inner();
            say!("deleted={}", r.deleted);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn php_line(prefix: &str, s: Option<&pb::PhpSettings>) -> String {
    match s {
        None => format!("{prefix}=default"),
        Some(s) => format!(
            "{prefix}.memory_limit={}M {prefix}.upload_max_filesize={}M {prefix}.post_max_size={}M {prefix}.max_execution_time={} {prefix}.max_input_time={} {prefix}.max_input_vars={} {prefix}.display_errors={} {prefix}.date_timezone={}",
            s.memory_limit_mb,
            s.upload_max_filesize_mb,
            s.post_max_size_mb,
            s.max_execution_time_seconds,
            s.max_input_time_seconds,
            s.max_input_vars,
            s.display_errors,
            if s.date_timezone.is_empty() { "-" } else { s.date_timezone.as_str() },
        ),
    }
}

/// The PHP settings of a site, as set and as they apply.
fn print_php_settings(v: &pb::VirtualHost) {
    say!(
        "domain={} {} {}",
        v.domain,
        php_line("php", v.php_settings.as_ref()),
        php_line("effective", v.php_settings_effective.as_ref())
    );
}

pub(crate) async fn run_php(c: &mut Client, cmd: PhpCmd) -> Result<ExitCode, tonic::Status> {
    match cmd {
        PhpCmd::Set {
            domain,
            settings: s,
        } => {
            let r = c
                .set_php_settings(pb::SetPhpSettingsRequest {
                    domain,
                    settings: Some(pb::PhpSettings {
                        memory_limit_mb: s.memory_limit,
                        upload_max_filesize_mb: s.upload_max,
                        post_max_size_mb: s.post_max,
                        max_execution_time_seconds: s.max_execution_time,
                        max_input_time_seconds: s.max_input_time,
                        max_input_vars: s.max_input_vars,
                        display_errors: s.display_errors,
                        date_timezone: s.timezone,
                    }),
                })
                .await?
                .into_inner();
            say!("changed={}", r.changed);
            if let Some(v) = &r.vhost {
                print_php_settings(v);
            }
        }
        PhpCmd::Limits {
            tenant,
            memory_limit,
            upload_max,
            max_execution_time,
            max_input_time,
            max_input_vars,
        } => {
            let r = c
                .set_tenant_php_limits(pb::SetTenantPhpLimitsRequest {
                    username: tenant,
                    limits: Some(pb::PhpLimits {
                        memory_limit_mb: memory_limit,
                        upload_max_filesize_mb: upload_max,
                        max_execution_time_seconds: max_execution_time,
                        max_input_time_seconds: max_input_time,
                        max_input_vars,
                    }),
                })
                .await?
                .into_inner();
            say!("changed={}", r.changed);
            if let Some(t) = &r.tenant {
                let l = t.php_limits.unwrap_or_default();
                say!(
                    "tenant={} php_limits.memory_limit={}M php_limits.upload_max={}M php_limits.max_execution_time={} php_limits.max_input_time={} php_limits.max_input_vars={}",
                    t.username,
                    l.memory_limit_mb,
                    l.upload_max_filesize_mb,
                    l.max_execution_time_seconds,
                    l.max_input_time_seconds,
                    l.max_input_vars
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn frequency_name(f: i32) -> &'static str {
    match pb::BackupFrequency::try_from(f) {
        Ok(pb::BackupFrequency::Off) => "off",
        Ok(pb::BackupFrequency::Daily) => "daily",
        Ok(pb::BackupFrequency::Weekly) => "weekly",
        _ => "default",
    }
}

fn print_schedule(s: &pb::BackupSchedule) {
    let result =
        pb::ScheduledBackupResult::try_from(s.last_result).map_or("unknown", |r| match r {
            pb::ScheduledBackupResult::None => "none",
            pb::ScheduledBackupResult::Running => "running",
            pb::ScheduledBackupResult::Succeeded => "succeeded",
            pb::ScheduledBackupResult::Failed => "failed",
            pb::ScheduledBackupResult::Deferred => "deferred",
        });
    say!(
        "tenant={} frequency={} host_default={} at={:02}:{:02}UTC{} weekday={}{} next_run={} last_run={} last_job={} last_result={} enabled_on_host={}",
        s.tenant,
        frequency_name(s.frequency),
        s.host_default,
        s.hour,
        s.minute,
        if s.hour_assigned { "(assigned)" } else { "" },
        WEEKDAYS.get(s.weekday as usize).copied().unwrap_or("?"),
        if s.weekday_assigned { "(assigned)" } else { "" },
        ts!(s.next_run),
        ts!(s.last_run),
        if s.last_job_id.is_empty() { "-" } else { s.last_job_id.as_str() },
        result,
        s.enabled_on_host,
    );
    if !s.last_message.is_empty() {
        say!("last_message={}", s.last_message);
    }
}

pub(crate) async fn run_schedule(
    c: &mut Client,
    cmd: ScheduleCmd,
) -> Result<ExitCode, tonic::Status> {
    let s = match cmd {
        ScheduleCmd::Set {
            tenant,
            frequency,
            hour,
            weekday: day,
        } => {
            let frequency = match frequency.as_str() {
                "off" => pb::BackupFrequency::Off,
                "daily" => pb::BackupFrequency::Daily,
                "weekly" => pb::BackupFrequency::Weekly,
                "default" => pb::BackupFrequency::Unspecified,
                other => {
                    return Err(tonic::Status::invalid_argument(format!(
                        "'{other}': off, daily, weekly or default"
                    )))
                }
            };
            let weekday = day
                .map(|d| weekday(&d))
                .transpose()
                .map_err(tonic::Status::invalid_argument)?;
            c.set_backup_schedule(pb::SetBackupScheduleRequest {
                tenant,
                frequency: frequency.into(),
                hour,
                weekday,
            })
            .await?
            .into_inner()
        }
        ScheduleCmd::Show { tenant } => c
            .get_backup_schedule(pb::GetBackupScheduleRequest { tenant })
            .await?
            .into_inner(),
    };
    print_schedule(&s);
    Ok(ExitCode::SUCCESS)
}

/// The essentials part of `host info`.
pub(crate) fn print_host_info(i: &pb::HostInfo) {
    let l = i.php_limits.unwrap_or_default();
    say!(
        "php_cli={} php_max.memory_limit={}M php_max.upload_max={}M php_max.max_execution_time={} php_max.max_input_time={} php_max.max_input_vars={} task_max_per_tenant={} task_min_interval={}m task_max_timeout={}s backup_schedules={} backup_schedule_default={}",
        i.php_cli_available,
        l.memory_limit_mb,
        l.upload_max_filesize_mb,
        l.max_execution_time_seconds,
        l.max_input_time_seconds,
        l.max_input_vars,
        i.task_max_per_tenant,
        i.task_min_interval_minutes,
        i.task_max_timeout_seconds,
        i.backup_schedules_enabled,
        frequency_name(i.backup_schedule_default),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedules_are_read_like_people_write_them() {
        use pb::TaskScheduleForm as Form;
        let parse = |text: &str| parse_schedule(text, "").unwrap_or_default();
        let every = parse("every 15m");
        assert_eq!(
            (every.form, every.interval),
            (Form::EveryMinutes.into(), 15)
        );
        let hours = parse("every 2h at :30");
        assert_eq!(
            (hours.form, hours.interval, hours.minute),
            (Form::EveryHours.into(), 2, 30)
        );
        assert_eq!(parse("hourly at :05").minute, 5);
        let daily = parse("daily 03:30");
        assert_eq!(
            (daily.form, daily.hour, daily.minute),
            (Form::Daily.into(), 3, 30)
        );
        let weekly = parse("weekly sun 23:00");
        assert_eq!(
            (weekly.form, weekly.weekday, weekly.hour),
            (Form::Weekly.into(), 0, 23)
        );
        let monthly = parse("monthly 28 01:00");
        assert_eq!(
            (monthly.form, monthly.day_of_month),
            (Form::Monthly.into(), 28)
        );
        for bad in [
            "",
            "sometimes",
            "every 15",
            "daily 3",
            "weekly funday 01:00",
            "every 2h 30",
        ] {
            assert!(parse_schedule(bad, "").is_err(), "{bad}");
        }
        assert_eq!(parse_mib("1G"), Ok(1024));
        assert_eq!(parse_mib("256M"), Ok(256));
        assert!(parse_mib("lots").is_err());
    }
}
