//! Scheduled backups, held in the engine.
//!
//! A tenant's backup schedule is off, daily or weekly — its own choice, or
//! the host default (`OXPANEL_BACKUP_SCHEDULE_DEFAULT`). A loop in the daemon
//! ([`ScheduleService::spawn`]) starts what is due with the very function
//! `CreateBackup` uses, so a scheduled backup is an ordinary backup: one job
//! per tenant, at most `backup::MAX_RUNNING_JOBS` on the host, the
//! free-space check and reserve, the time limit, and the same keep-count.
//! Backups therefore run whether or not the panel is up.
//!
//! Times are UTC. The minute is always the engine's (a stable hash of the
//! tenant name), so tenants spread over the hour; the hour and the weekday
//! are the caller's or the engine's (within the host's backup window).
//!
//! Due logic ([`latest_slot`]): the most recent scheduled instant at or
//! before now is due when it is later than the last slot handled. After the
//! host was off for days only the most recent slot is due: one catch-up
//! backup, not one per missed day. A new or changed schedule marks the
//! current slot as handled, so nothing starts at once (and an upgrade does
//! not start every tenant's backup together).
//!
//! State per tenant (`state_dir/backup-schedules/<tenant>.json`): the choice
//! and the last slot, run, job, result and message. A failure is recorded
//! and the next slot runs as usual; a backup that cannot start yet (the
//! host's job limit, or another job of the tenant) is deferred: the slot
//! stays due and is tried at the next check.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::backup::{BackupService, MAX_RUNNING_JOBS};
use crate::config::{Config, Essentials};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::host::{Drift, DriftKind};
use crate::records::{
    self, now_unix, JobKind, JobState, TenantRecord, TenantState, RECORD_VERSION,
};
use crate::validate::Username;

const DIR_MODE: u32 = 0o700;
const DAY: u64 = 86_400;
const WEEK: u64 = 7 * DAY;
/// 1970-01-01 was a Thursday (0 = Sunday).
const EPOCH_WEEKDAY: u64 = 4;

/// How often a tenant is backed up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frequency {
    Off,
    Daily,
    Weekly,
}

impl Frequency {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "off" => Some(Self::Off),
            "daily" => Some(Self::Daily),
            "weekly" => Some(Self::Weekly),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Daily => "daily",
            Self::Weekly => "weekly",
        }
    }
}

/// How the last scheduled backup went.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LastResult {
    #[default]
    None,
    Running,
    Succeeded,
    Failed,
    Deferred,
}

/// A tenant's schedule and the scheduler's state for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleRecord {
    pub version: u32,
    pub tenant: String,
    /// The tenant's own choice; `None` = the host default.
    #[serde(default)]
    pub frequency: Option<Frequency>,
    /// Hour (UTC) and weekday chosen by the caller; `None` = assigned.
    #[serde(default)]
    pub hour: Option<u32>,
    #[serde(default)]
    pub weekday: Option<u32>,
    /// The most recent slot that was run, failed, or marked as handled.
    #[serde(default)]
    pub last_slot_unix: u64,
    /// The last attempt: when, which job, how it went.
    #[serde(default)]
    pub last_run_unix: u64,
    #[serde(default)]
    pub last_job: String,
    #[serde(default)]
    pub last_result: LastResult,
    #[serde(default)]
    pub last_message: String,
}

impl ScheduleRecord {
    fn new(tenant: &str) -> Self {
        Self {
            version: RECORD_VERSION,
            tenant: tenant.to_owned(),
            frequency: None,
            hour: None,
            weekday: None,
            last_slot_unix: 0,
            last_run_unix: 0,
            last_job: String::new(),
            last_result: LastResult::None,
            last_message: String::new(),
        }
    }
}

/// The schedule that applies to a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effective {
    pub frequency: Frequency,
    /// The host default applies (the tenant has no choice of its own).
    pub host_default: bool,
    pub hour: u32,
    pub minute: u32,
    pub weekday: u32,
    pub hour_assigned: bool,
    pub weekday_assigned: bool,
}

/// FNV-1a: a stable hash (the standard library's is randomised per process).
fn fnv1a(text: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// The schedule of `tenant`: its record's choices, the rest from the host.
pub fn effective(cfg: &Essentials, tenant: &str, rec: Option<&ScheduleRecord>) -> Effective {
    let h = fnv1a(tenant);
    let (from, to) = cfg.backup_window;
    let span = u64::from(to.saturating_sub(from)) + 1;
    let own = rec.and_then(|r| r.frequency);
    let hour = rec.and_then(|r| r.hour);
    let weekday = rec.and_then(|r| r.weekday);
    // Small values by construction (< 60, < 24, < 7).
    let pick = |v: u64| u32::try_from(v).unwrap_or(0);
    Effective {
        frequency: own.unwrap_or(cfg.backup_schedule_default),
        host_default: own.is_none(),
        minute: pick(h % 60),
        hour: hour.unwrap_or_else(|| from + pick((h / 60) % span)),
        weekday: weekday.unwrap_or_else(|| pick((h / 3600) % 7)),
        hour_assigned: hour.is_none(),
        weekday_assigned: weekday.is_none(),
    }
}

/// The most recent scheduled instant at or before `now`; `None` when off.
pub fn latest_slot(e: &Effective, now: u64) -> Option<u64> {
    let at = u64::from(e.hour) * 3600 + u64::from(e.minute) * 60;
    let day = now / DAY;
    match e.frequency {
        Frequency::Off => None,
        Frequency::Daily => {
            let t = day * DAY + at;
            Some(if t > now { t.checked_sub(DAY)? } else { t })
        }
        Frequency::Weekly => {
            let today = (day + EPOCH_WEEKDAY) % 7;
            let back = (today + 7 - u64::from(e.weekday) % 7) % 7;
            let t = (day.checked_sub(back)?) * DAY + at;
            Some(if t > now { t.checked_sub(WEEK)? } else { t })
        }
    }
}

/// The next scheduled instant after `now`; `None` when off.
pub fn next_slot(e: &Effective, now: u64) -> Option<u64> {
    let period = match e.frequency {
        Frequency::Off => return None,
        Frequency::Daily => DAY,
        Frequency::Weekly => WEEK,
    };
    Some(latest_slot(e, now).map_or(now, |s| s + period))
}

/// The slot to run now, if any.
pub fn due(e: &Effective, last_slot: u64, now: u64) -> Option<u64> {
    latest_slot(e, now).filter(|s| *s > last_slot)
}

fn record_path(cfg: &Config, tenant: &Username) -> PathBuf {
    cfg.backup_schedules_dir().join(format!("{tenant}.json"))
}

fn load(cfg: &Config, tenant: &Username) -> Result<Option<ScheduleRecord>> {
    records::load(&record_path(cfg, tenant))
}

fn save(cfg: &Config, rec: &ScheduleRecord) -> Result<()> {
    let tenant = Username::parse_field(&rec.tenant, "tenant")?;
    fsutil::ensure_dir(&cfg.backup_schedules_dir(), DIR_MODE)?;
    records::save(&record_path(cfg, &tenant), rec)
}

/// What `GetBackupSchedule` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    pub tenant: String,
    pub effective: Effective,
    /// 0 when nothing is scheduled (off here or on the host).
    pub next_run: u64,
    pub last_run: u64,
    pub last_job: String,
    pub last_result: LastResult,
    pub last_message: String,
    pub enabled_on_host: bool,
}

/// What a finished (or vanished) job means for the schedule.
fn job_outcome(ctx: &Ctx, job_id: &str) -> Result<Option<(LastResult, String)>> {
    let Ok(id) = crate::validate::JobId::parse(job_id) else {
        return Ok(Some((LastResult::Failed, "the job is unknown".into())));
    };
    Ok(match ctx.store.load_job(&id)? {
        None => Some((
            LastResult::Failed,
            "the job record is gone; its outcome is unknown".into(),
        )),
        Some(j) => match j.state {
            JobState::Running => None,
            JobState::Succeeded => Some((LastResult::Succeeded, j.message)),
            JobState::Failed => Some((LastResult::Failed, j.message)),
        },
    })
}

#[derive(Debug, Clone)]
pub struct ScheduleService {
    ctx: Ctx,
    backups: BackupService,
}

impl ScheduleService {
    pub fn new(ctx: Ctx, backups: BackupService) -> Self {
        Self { ctx, backups }
    }

    fn tenant(&self, name: &Username) -> Result<TenantRecord> {
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

    fn view(&self, tenant: &str, rec: Option<&ScheduleRecord>, now: u64) -> Result<View> {
        let es = &self.ctx.config.essentials;
        let e = effective(es, tenant, rec);
        let blank = ScheduleRecord::new(tenant);
        let rec = rec.unwrap_or(&blank);
        // A running job is looked at, not waited for: the record is updated
        // at the scheduler's next round.
        let (last_result, last_message) = match rec.last_result {
            LastResult::Running => job_outcome(&self.ctx, &rec.last_job)?
                .unwrap_or((LastResult::Running, rec.last_message.clone())),
            r => (r, rec.last_message.clone()),
        };
        Ok(View {
            tenant: tenant.to_owned(),
            effective: e,
            next_run: if es.backup_schedules {
                next_slot(&e, now).unwrap_or(0)
            } else {
                0
            },
            last_run: rec.last_run_unix,
            last_job: rec.last_job.clone(),
            last_result,
            last_message,
            enabled_on_host: es.backup_schedules,
        })
    }

    /// Set a tenant's schedule: `frequency` `None` = follow the host default;
    /// `hour` (0–23, UTC) and `weekday` (0 = Sunday) `None` = assigned by
    /// the engine. The current slot counts as handled: the first scheduled
    /// backup is the next one.
    pub async fn set(
        &self,
        tenant: &str,
        frequency: Option<Frequency>,
        hour: Option<u32>,
        weekday: Option<u32>,
    ) -> Result<View> {
        let name = Username::parse_field(tenant, "tenant")?;
        if hour.is_some_and(|h| h > 23) {
            return Err(Error::invalid("hour", "must be 0..=23 (UTC)"));
        }
        if weekday.is_some_and(|d| d > 6) {
            return Err(Error::invalid(
                "weekday",
                "must be 0 (Sunday) ..= 6 (Saturday)",
            ));
        }
        let _guard = self.ctx.lock.lock().await;
        self.tenant(&name)?;
        let cfg = &self.ctx.config;
        let now = now_unix();
        let existing = load(cfg, &name)?;
        let mut rec = existing
            .clone()
            .unwrap_or_else(|| ScheduleRecord::new(name.as_str()));
        rec.frequency = frequency;
        rec.hour = hour;
        rec.weekday = weekday;
        let unchanged = existing
            .as_ref()
            .is_some_and(|b| (b.frequency, b.hour, b.weekday) == (frequency, hour, weekday));
        if !unchanged {
            let e = effective(&cfg.essentials, name.as_str(), Some(&rec));
            rec.last_slot_unix = latest_slot(&e, now).unwrap_or(0);
            save(cfg, &rec)?;
            info!(tenant = %name, frequency = e.frequency.as_str(), hour = e.hour, minute = e.minute, "backup schedule set");
        }
        self.view(name.as_str(), Some(&rec), now)
    }

    pub async fn get(&self, tenant: &str) -> Result<View> {
        let name = Username::parse_field(tenant, "tenant")?;
        self.tenant(&name)?;
        let rec = load(&self.ctx.config, &name)?;
        self.view(name.as_str(), rec.as_ref(), now_unix())
    }

    /// One round of the scheduler at `now`: every ready tenant (suspended
    /// ones included) whose slot is due gets a backup. Returns how many
    /// were started.
    pub async fn tick(&self, now: u64) -> Result<usize> {
        if !self.ctx.config.essentials.backup_schedules {
            return Ok(0);
        }
        let mut started = 0;
        for t in self.ctx.store.list_tenants()? {
            if t.state != TenantState::Ready {
                continue;
            }
            let name = Username::parse(&t.username)?;
            match self.tick_tenant(&name, now).await {
                Ok(true) => started += 1,
                Ok(false) => {}
                Err(e) => {
                    warn!(tenant = %name, error = %e, "backup scheduler could not handle this tenant");
                }
            }
        }
        Ok(started)
    }

    /// Returns whether a backup was started for `name`.
    async fn tick_tenant(&self, name: &Username, now: u64) -> Result<bool> {
        let cfg = &self.ctx.config;
        let slot = {
            let _guard = self.ctx.lock.lock().await;
            let Some(mut rec) = load(cfg, name)? else {
                // First sight (a new tenant, or the host default after an
                // upgrade): the current slot counts as handled.
                let mut rec = ScheduleRecord::new(name.as_str());
                let e = effective(&cfg.essentials, name.as_str(), None);
                rec.last_slot_unix = latest_slot(&e, now).unwrap_or(0);
                save(cfg, &rec)?;
                return Ok(false);
            };
            if rec.last_result == LastResult::Running {
                if let Some((result, message)) = job_outcome(&self.ctx, &rec.last_job)? {
                    rec.last_result = result;
                    rec.last_message = message;
                    save(cfg, &rec)?;
                    info!(tenant = %name, job = %rec.last_job, result = ?result, "scheduled backup finished");
                }
            }
            let e = effective(&cfg.essentials, name.as_str(), Some(&rec));
            let Some(slot) = due(&e, rec.last_slot_unix, now) else {
                return Ok(false);
            };
            // Cheap checks first: a backup that cannot start now is
            // deferred without measuring the home.
            let running: Vec<_> = self
                .ctx
                .store
                .list_jobs()?
                .into_iter()
                .filter(|j| j.state == JobState::Running)
                .collect();
            if let Some(job) = running.iter().find(|j| j.tenant == name.as_str()) {
                if job.kind == JobKind::Backup {
                    // A manual backup is running: it is this slot's backup.
                    record(
                        &mut rec,
                        slot,
                        now,
                        LastResult::Running,
                        &job.id,
                        "a backup was already running; it counts as this run",
                    );
                } else {
                    rec.last_result = LastResult::Deferred;
                    rec.last_message = format!(
                        "a {} job of the tenant is running; tried again at the next check",
                        job.kind.as_str()
                    );
                }
                save(cfg, &rec)?;
                return Ok(false);
            }
            if running.len() >= MAX_RUNNING_JOBS {
                rec.last_result = LastResult::Deferred;
                rec.last_message = Error::TooManyJobs.to_string();
                save(cfg, &rec)?;
                return Ok(false);
            }
            slot
        };
        // Not under the lock: `create_job` takes it itself.
        let outcome = self.backups.create_job(name, 0, None).await;
        let _guard = self.ctx.lock.lock().await;
        // Reloaded: the schedule may have been changed meanwhile.
        let mut rec = load(cfg, name)?.unwrap_or_else(|| ScheduleRecord::new(name.as_str()));
        let started = match outcome {
            Ok((job, started)) => {
                let message = if started {
                    "started"
                } else {
                    "a backup was already running; it counts as this run"
                };
                record(&mut rec, slot, now, LastResult::Running, &job.id, message);
                info!(tenant = %name, job = %job.id, "scheduled backup started");
                started
            }
            Err(e @ (Error::TooManyJobs | Error::JobRunning { .. })) => {
                rec.last_result = LastResult::Deferred;
                rec.last_message = e.to_string();
                false
            }
            Err(e) => {
                warn!(tenant = %name, error = %e, "scheduled backup could not start");
                let message = if e.is_client_error() {
                    e.to_string()
                } else {
                    "internal error; see the oxpanel-daemon journal".to_owned()
                };
                record(&mut rec, slot, now, LastResult::Failed, "", &message);
                false
            }
        };
        save(cfg, &rec)?;
        Ok(started)
    }

    /// Run the scheduler: once now (catching up after downtime), then every
    /// `OXPANEL_BACKUP_SCHEDULE_CHECK_SECS`.
    pub fn spawn(self) {
        let es = &self.ctx.config.essentials;
        if !es.backup_schedules {
            info!("scheduled backups are off (OXPANEL_BACKUP_SCHEDULES=false)");
            return;
        }
        let every = es.backup_schedule_check.max(Duration::from_secs(1));
        tokio::spawn(async move {
            loop {
                match self.tick(now_unix()).await {
                    Ok(0) => {}
                    Ok(n) => info!(started = n, "scheduled backups started"),
                    Err(e) => warn!(error = %e, "backup scheduler round failed"),
                }
                tokio::time::sleep(every).await;
            }
        });
    }
}

/// Record an attempt for `slot` (never moving the handled slot backwards).
fn record(
    rec: &mut ScheduleRecord,
    slot: u64,
    now: u64,
    result: LastResult,
    job: &str,
    message: &str,
) {
    rec.last_slot_unix = rec.last_slot_unix.max(slot);
    rec.last_run_unix = now;
    job.clone_into(&mut rec.last_job);
    rec.last_result = result;
    message.clone_into(&mut rec.last_message);
}

/// Deleting a tenant: its schedule goes with it.
pub fn forget(cfg: &Config, tenant: &Username) -> Result<bool> {
    fsutil::remove_if_exists(&record_path(cfg, tenant))
}

/// `Reconcile`: schedule records of tenants that do not exist.
pub fn drifts(cfg: &Config, tenants: &[TenantRecord]) -> Result<Vec<Drift>> {
    let mut out = Vec::new();
    for rec in records::list::<ScheduleRecord>(&cfg.backup_schedules_dir())? {
        if !tenants.iter().any(|t| t.username == rec.tenant) {
            out.push(Drift::new(
                DriftKind::OrphanBackupSchedule,
                rec.tenant.clone(),
                "a backup schedule for a tenant that has no record",
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::FakeSystem;
    use crate::tenant::TenantService;
    use crate::validate::{JobId, Limits};
    use std::sync::Arc;

    fn daily(hour: u32, minute: u32) -> Effective {
        Effective {
            frequency: Frequency::Daily,
            host_default: false,
            hour,
            minute,
            weekday: 0,
            hour_assigned: false,
            weekday_assigned: true,
        }
    }

    // 2026-11-14 (a Saturday) 12:00:00 UTC.
    const NOW: u64 = 1_794_657_600;

    #[test]
    fn slots_are_the_most_recent_scheduled_instants() {
        let e = daily(3, 30);
        let today_0330 = NOW - 12 * 3600 + 3 * 3600 + 30 * 60;
        assert_eq!(latest_slot(&e, NOW), Some(today_0330));
        assert_eq!(next_slot(&e, NOW), Some(today_0330 + DAY));
        // Before the time of day: yesterday's.
        assert_eq!(latest_slot(&daily(13, 0), NOW), Some(NOW + 3600 - DAY));
        assert_eq!(latest_slot(&daily(12, 0), NOW), Some(NOW), "exactly now");
        let weekly = |weekday| Effective {
            frequency: Frequency::Weekly,
            weekday,
            ..daily(12, 0)
        };
        assert_eq!(latest_slot(&weekly(6), NOW), Some(NOW), "Saturday");
        assert_eq!(latest_slot(&weekly(5), NOW), Some(NOW - DAY), "Friday");
        assert_eq!(latest_slot(&weekly(0), NOW), Some(NOW - 6 * DAY), "Sunday");
        let off = Effective {
            frequency: Frequency::Off,
            ..daily(1, 0)
        };
        assert_eq!(latest_slot(&off, NOW), None);
        assert_eq!(next_slot(&off, NOW), None);
    }

    #[test]
    fn after_downtime_only_the_most_recent_slot_is_due() {
        let e = daily(3, 30);
        let handled = latest_slot(&e, NOW - 3 * DAY).unwrap_or(0);
        let slot = due(&e, handled, NOW);
        assert_eq!(slot, latest_slot(&e, NOW), "one catch-up run");
        assert_eq!(due(&e, slot.unwrap_or(0), NOW), None, "and only one");
        let s = slot.unwrap_or(0);
        assert_eq!(due(&e, s, s + DAY - 1), None);
        assert_eq!(due(&e, s, s + DAY), Some(s + DAY), "the next day again");
    }

    #[test]
    fn the_engine_spreads_tenants_within_the_window() {
        let es = Essentials::default();
        let mut minutes = std::collections::BTreeSet::new();
        for i in 0..200 {
            let e = effective(&es, &format!("tenant{i}"), None);
            assert!((1..=5).contains(&e.hour), "{e:?}");
            assert!(e.minute < 60 && e.weekday < 7);
            assert!(e.host_default && e.hour_assigned && e.weekday_assigned);
            assert_eq!(e.frequency, Frequency::Off, "the host default");
            minutes.insert((e.hour, e.minute));
        }
        assert!(
            minutes.len() > 100,
            "spread: {} distinct start times",
            minutes.len()
        );
        assert_eq!(
            effective(&es, "alice", None),
            effective(&es, "alice", None),
            "stable"
        );
        let mut rec = ScheduleRecord::new("alice");
        rec.frequency = Some(Frequency::Weekly);
        rec.hour = Some(22);
        rec.weekday = Some(2);
        let e = effective(&es, "alice", Some(&rec));
        assert_eq!((e.frequency, e.hour, e.weekday), (Frequency::Weekly, 22, 2));
        assert!(!e.host_default && !e.hour_assigned && !e.weekday_assigned);
        assert_eq!(e.minute, effective(&es, "alice", None).minute);
    }

    struct Harness {
        _dir: tempfile::TempDir,
        sys: Arc<FakeSystem>,
        ctx: Ctx,
        backups: BackupService,
        svc: ScheduleService,
    }

    async fn harness() -> Harness {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let mut cfg = Config::default();
        crate::config::sandbox_feature_paths(&mut cfg, dir.path());
        cfg.state_dir = dir.path().join("state");
        cfg.home_base = dir.path().join("home");
        cfg.systemd_unit_dir = dir.path().join("systemd");
        cfg.backup_keep = 2;
        cfg.essentials.backup_schedule_default = Frequency::Daily;
        for d in [&cfg.home_base, &cfg.systemd_unit_dir] {
            std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("{e}"));
        }
        let sys = Arc::new(FakeSystem::new());
        let ctx = Ctx::new(cfg, sys.clone(), false);
        ctx.store.init().unwrap_or_else(|e| panic!("{e}"));
        TenantService::new(ctx.clone())
            .create("alice", Limits::default(), "")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let backups = BackupService::new(ctx.clone()).with_poll_interval(Duration::from_secs(3600));
        Harness {
            _dir: dir,
            sys,
            svc: ScheduleService::new(ctx.clone(), backups.clone()),
            backups,
            ctx,
        }
    }

    fn rewind(h: &Harness, days: u64) -> Result<ScheduleRecord> {
        let name = Username::parse("alice")?;
        let mut rec = load(&h.ctx.config, &name)?.unwrap_or_else(|| ScheduleRecord::new("alice"));
        rec.last_slot_unix = rec.last_slot_unix.saturating_sub(days * DAY);
        save(&h.ctx.config, &rec)?;
        Ok(rec)
    }

    #[tokio::test]
    async fn first_sight_starts_nothing_then_due_slots_run_once() -> Result<()> {
        let h = harness().await;
        let now = now_unix();
        assert_eq!(
            h.svc.tick(now).await?,
            0,
            "first sight marks the slot handled"
        );
        assert_eq!(h.svc.tick(now).await?, 0);
        // The host was off for three days.
        rewind(&h, 3)?;
        assert_eq!(h.svc.tick(now).await?, 1, "one catch-up backup");
        assert_eq!(h.svc.tick(now).await?, 0, "and only one");
        let v = h.svc.get("alice").await?;
        assert_eq!(v.last_result, LastResult::Running);
        assert!(v.next_run > now && v.enabled_on_host && v.effective.host_default);
        // The job ends; the next round records it.
        let job = JobId::parse(&v.last_job)?;
        assert!(h.backups.step(&job).await?);
        h.svc.tick(now).await?;
        let rec = load(&h.ctx.config, &Username::parse("alice")?)?
            .unwrap_or_else(|| ScheduleRecord::new("x"));
        assert_eq!(rec.last_result, LastResult::Succeeded);
        assert_eq!(
            h.backups.list("alice").await?.len(),
            1,
            "an ordinary backup, same keep-count"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_failing_backup_is_recorded_and_does_not_stop_the_next() -> Result<()> {
        let h = harness().await;
        let now = now_unix();
        h.svc
            .set("alice", Some(Frequency::Daily), Some(2), None)
            .await?;
        rewind(&h, 1)?;
        h.sys.set_disk_free(1); // no room: refused before anything exists
        assert_eq!(h.svc.tick(now).await?, 0);
        let v = h.svc.get("alice").await?;
        assert_eq!(v.last_result, LastResult::Failed);
        assert!(
            v.last_message.contains("not enough free space"),
            "{}",
            v.last_message
        );
        assert!(v.next_run > now, "the next run is still scheduled");
        assert_eq!(h.svc.tick(now).await?, 0, "the failed slot is not retried");
        h.sys.set_disk_free(80 << 30);
        rewind(&h, 1)?;
        assert_eq!(h.svc.tick(now).await?, 1, "the next slot runs");
        Ok(())
    }

    #[tokio::test]
    async fn busy_hosts_defer_and_off_means_off() -> Result<()> {
        let h = harness().await;
        let now = now_unix();
        h.svc.tick(now).await?;
        // A manual backup is running when the slot comes: it counts.
        let (manual, _) = h.backups.create("alice", 0, 0).await?;
        rewind(&h, 1)?;
        assert_eq!(h.svc.tick(now).await?, 0);
        let v = h.svc.get("alice").await?;
        assert_eq!(
            (v.last_result, v.last_job.as_str()),
            (LastResult::Running, manual.id.as_str())
        );
        assert!(h.backups.step(&JobId::parse(&manual.id)?).await?);
        // Off: nothing is due, nothing is next.
        let v = h.svc.set("alice", Some(Frequency::Off), None, None).await?;
        assert_eq!(v.next_run, 0);
        rewind(&h, 5)?;
        assert_eq!(h.svc.tick(now).await?, 0);
        assert!(h.svc.set("alice", None, Some(24), None).await.is_err());
        assert!(h.svc.set("alice", None, None, Some(7)).await.is_err());
        assert!(matches!(
            h.svc.get("carol").await,
            Err(Error::TenantNotFound(_))
        ));
        // The tenant goes: its schedule is an orphan until forgotten.
        assert_eq!(drifts(&h.ctx.config, &[])?.len(), 1);
        assert!(forget(&h.ctx.config, &Username::parse("alice")?)?);
        assert!(drifts(&h.ctx.config, &[])?.is_empty());
        Ok(())
    }
}
