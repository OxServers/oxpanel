//! Property tests of the scheduled-task, PHP-settings and backup-schedule
//! validators and renderers: whatever a caller sends is either refused or
//! rendered into exactly the shape the engine intends.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use oxpanel_daemon::backup_schedule::{self, Effective, Frequency};
use oxpanel_daemon::config::Essentials;
use oxpanel_daemon::php_settings::{self, PhpLimits, RawSettings};
use oxpanel_daemon::records::{TenantRecord, TenantState};
use oxpanel_daemon::task::{self, Form, RawSchedule, RawSpec, TaskKind};
use oxpanel_daemon::validate::{Limits, Username};
use proptest::prelude::*;

/// systemd's reading of an `ExecStart=` value, for the words we write: the
/// program unquoted, every other word double-quoted, `%%` and `$$` as the
/// escapes of `%` and `$`. Returns `None` for anything else.
fn systemd_split(line: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut chars = line.chars().peekable();
    let mut program = String::new();
    while let Some(&c) = chars.peek() {
        if c == ' ' {
            break;
        }
        program.push(c);
        chars.next();
    }
    words.push(program);
    while let Some(c) = chars.next() {
        if c != ' ' || chars.next() != Some('"') {
            return None;
        }
        let mut word = String::new();
        loop {
            match chars.next()? {
                '"' => break,
                '\\' => return None,
                '%' => {
                    if chars.next()? != '%' {
                        return None;
                    }
                    word.push('%');
                }
                '$' => {
                    if chars.next()? != '$' {
                        return None;
                    }
                    word.push('$');
                }
                c if c.is_control() => return None,
                c => word.push(c),
            }
        }
        words.push(word);
    }
    Some(words)
}

fn tenant() -> TenantRecord {
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
        sftp_keys: Vec::new(),
        sftp_password: false,
        php_limits: PhpLimits::default(),
    }
}

fn form() -> impl Strategy<Value = Option<Form>> {
    prop_oneof![
        Just(None),
        Just(Some(Form::EveryMinutes)),
        Just(Some(Form::EveryHours)),
        Just(Some(Form::Daily)),
        Just(Some(Form::Weekly)),
        Just(Some(Form::Monthly)),
    ]
}

fn small_or_any() -> impl Strategy<Value = u32> {
    prop_oneof![0u32..70, any::<u32>()]
}

fn hostile() -> impl Strategy<Value = String> {
    prop_oneof![
        "[A-Za-z][A-Za-z_/+-]{0,20}",
        ".{0,40}",
        "[a-z]{1,5}[;\"'`\\\\$%\n\r\t\0 #{}][a-z]{1,5}",
        "UTC|Europe/Berlin|Etc/GMT\\+5|America/New_York",
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn an_accepted_schedule_renders_to_a_plain_calendar_expression(
        form in form(),
        interval in small_or_any(),
        minute in small_or_any(),
        hour in small_or_any(),
        weekday in small_or_any(),
        day in small_or_any(),
        tz in hostile(),
    ) {
        let cfg = Essentials::default();
        let raw = RawSchedule { form, interval, minute, hour, weekday, day_of_month: day, time_zone: tz };
        if let Ok((s, zone)) = task::Schedule::parse(&raw, &cfg) {
            let cal = s.calendar(&zone);
            prop_assert!(cal.bytes().all(|b| b.is_ascii_alphanumeric() || b" *-:/_+".contains(&b)), "{cal:?}");
            prop_assert!(s.period_secs() >= cfg.task_min_interval_minutes * 60);
            prop_assert!(s.randomized_delay_secs() < s.period_secs());
        }
    }

    #[test]
    fn accepted_arguments_survive_unit_quoting_exactly(
        args in proptest::collection::vec(prop_oneof!["[ -~]{0,30}", "[A-Za-z0-9 =,./:;@+_!?()<>{}|*~-]{0,30}", ".{0,30}"], 0..20),
        script in "[a-z]{1,8}(/[a-z.]{1,8}){0,2}",
    ) {
        let cfg = Essentials::default();
        let spec = RawSpec {
            name: "job".into(),
            kind: Some(TaskKind::Php),
            script,
            args: args.clone(),
            schedule: RawSchedule { form: Some(Form::Daily), hour: 3, ..RawSchedule::default() },
            ..RawSpec::default()
        };
        let Ok(mut rec) = task::parse_spec(&spec, &cfg) else { return Ok(()); };
        rec.tenant = "alice".into();
        let argv = task::argv(&rec, Path::new("/home/alice")).unwrap();
        let line = task::exec_line(&argv).unwrap();
        prop_assert_eq!(systemd_split(&line), Some(argv));
        // Only ExecStart differs from a task without arguments: no argument
        // can add, remove or change any other line of the unit.
        let unit = task::render_service(&rec, &tenant(), true).unwrap();
        let plain = task::render_service(&task::TaskRecord { args: Vec::new(), ..rec.clone() }, &tenant(), true).unwrap();
        let other = |u: &str| u.lines().filter(|l| !l.starts_with("ExecStart=")).map(str::to_owned).collect::<Vec<_>>();
        prop_assert_eq!(other(&unit), other(&plain));
        prop_assert_eq!(unit.lines().count(), plain.lines().count());
    }

    #[test]
    fn an_accepted_url_is_plain_and_pinned_to_this_host(url in prop_oneof![
        "https?://[a-z]{1,8}\\.example/[A-Za-z0-9/?&=%._~-]{0,30}",
        ".{0,60}",
    ]) {
        if let Ok((u, host)) = task::parse_url(&url) {
            prop_assert!(u.starts_with("http://") || u.starts_with("https://"));
            prop_assert!(u.bytes().all(|b| b.is_ascii_graphic() && !b"\"'`\\$<>{}|^#[] ".contains(&b)), "{u:?}");
            let rec = task::TaskRecord {
                version: 1, tenant: "alice".into(), name: "u".into(), kind: TaskKind::Url,
                script: String::new(), args: Vec::new(), virtualenv: String::new(), url: u.clone(),
                schedule: task::Schedule::Daily { hour: 1, minute: 0 }, time_zone: String::new(),
                timeout_secs: 60, enabled: true, created_at_unix: 0,
            };
            let argv = task::argv(&rec, Path::new("/home/alice")).unwrap();
            let resolve = format!("{host}:443:127.0.0.1");
            prop_assert!(argv.contains(&resolve));
            prop_assert_eq!(systemd_split(&task::exec_line(&argv).unwrap()), Some(argv));
        }
    }

    #[test]
    fn accepted_php_settings_render_only_known_lines(
        memory in small_or_any(), upload in small_or_any(), post in small_or_any(),
        exec in small_or_any(), input in small_or_any(), vars in prop_oneof![0u32..20_000, any::<u32>()],
        display in any::<bool>(), tz in hostile(),
        cap_memory in 0u32..2048,
    ) {
        let host = PhpLimits::HOST_DEFAULT;
        let zoneinfo = Path::new("/usr/share/zoneinfo");
        let Ok(caps) = PhpLimits::parse_caps(&PhpLimits { memory_limit_mb: cap_memory, ..PhpLimits::default() }, &host) else {
            prop_assert!(cap_memory > host.memory_limit_mb || (cap_memory != 0 && cap_memory < php_settings::MIN_MEMORY_MB));
            return Ok(());
        };
        let caps = caps.resolve(&host);
        let raw = RawSettings {
            memory_limit_mb: memory, upload_max_filesize_mb: upload, post_max_size_mb: post,
            max_execution_time_secs: exec, max_input_time_secs: input, max_input_vars: vars,
            display_errors: display, date_timezone: tz,
        };
        if let Ok(s) = php_settings::parse(&raw, &caps, zoneinfo) {
            let e = php_settings::effective(&s, &caps);
            prop_assert!(e.memory_limit_mb.is_none_or(|m| m <= caps.memory_limit_mb));
            prop_assert!(e.upload_max_filesize_mb.is_none_or(|u| e.post_max_size_mb.is_some_and(|p| p >= u)));
            for line in php_settings::pool_lines(&e).unwrap().lines() {
                let (key, value) = line.split_once("] = ").unwrap();
                let key = key.strip_prefix("php_value[").unwrap();
                prop_assert!(["memory_limit", "upload_max_filesize", "post_max_size", "max_execution_time",
                    "max_input_time", "max_input_vars", "date.timezone"].contains(&key), "{line}");
                prop_assert!(value.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_+-".contains(&b)), "{line}");
            }
            if let Some(t) = php_settings::nginx_tuning(&e) {
                prop_assert!(t.read_timeout_secs.is_none_or(|s| s >= 60));
                prop_assert!(t.send_timeout_secs.is_none_or(|s| s >= 60));
            }
        }
    }

    #[test]
    fn the_backup_slot_is_the_latest_instant_of_the_schedule(
        now in 1_000_000_000u64..4_000_000_000,
        hour in 0u32..24, minute in 0u32..60, weekday in 0u32..7, weekly in any::<bool>(),
    ) {
        let e = Effective {
            frequency: if weekly { Frequency::Weekly } else { Frequency::Daily },
            host_default: false, hour, minute, weekday, hour_assigned: false, weekday_assigned: false,
        };
        let period = if weekly { 7 * 86_400 } else { 86_400 };
        let slot = backup_schedule::latest_slot(&e, now).unwrap();
        prop_assert!(slot <= now && now - slot < period);
        prop_assert_eq!(slot % 86_400, u64::from(hour) * 3600 + u64::from(minute) * 60);
        if weekly {
            prop_assert_eq!(((slot / 86_400) + 4) % 7, u64::from(weekday));
        }
        prop_assert_eq!(backup_schedule::next_slot(&e, now), Some(slot + period));
        prop_assert_eq!(backup_schedule::due(&e, slot, now), None);
        prop_assert_eq!(backup_schedule::due(&e, slot - 1, now), Some(slot));
    }

    #[test]
    fn a_task_name_never_escapes_its_unit_name(name in ".{0,40}") {
        if let Ok(n) = task::parse_name(&name, "name") {
            let base = task::unit_base(&Username::parse("foo-bar").unwrap(), &n);
            prop_assert!(base.starts_with("oxpanel-task-foo\\x2dbar-"));
            let rest = base.trim_start_matches("oxpanel-task-foo\\x2dbar-");
            prop_assert!(!rest.contains('-') || rest.contains("\\x2d"));
            prop_assert!(!rest.replace("\\x2d", "").contains('-'));
        }
    }
}
