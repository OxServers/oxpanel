//! Per-tenant backups and restores, as jobs.
//!
//! A backup is a directory `<backup_dir>/<tenant>/<backup id>/`, root-only,
//! outside every tenant's reach. It holds *members* and a manifest:
//!
//! - `home.tar.gz` (kind `home`) — the tenant's home, written by `tar` running
//!   as the tenant;
//! - `records.json` (kind `records`) — the engine's records of the tenant and
//!   its virtual hosts, so the backup says what it is a backup of;
//! - `manifest.json` — the list of members with size and SHA-256. It is
//!   written last and atomically: a directory without it is not a backup.
//!
//! Further per-tenant data (database dumps) become further members. Sealing
//! ([`BackupService::seal`]) picks up *every* member that has a result file
//! next to it (see [`crate::worker::MemberResult`]), whatever its kind, so a
//! new data source only has to write its member and result file into the
//! backup directory before the job ends; manifest, record, listing, restore
//! verification and reconciliation need no change and the format stays `1`.
//!
//! The work takes longer than a request may, and must not die with the
//! daemon, so it is a **job**: the request writes the records, starts a
//! transient systemd unit and returns. The unit runs this same binary in
//! worker mode ([`crate::worker`]) inside the tenant's slice — charged to the
//! tenant's limits — at the lowest CPU and I/O priority, sandboxed, with a
//! time limit. The daemon only watches: it polls the unit and, when it has
//! ended, seals the backup or removes what was written. A job record in state
//! `running` is all a restarted daemon needs to pick the job up again
//! ([`BackupService::resume_all`]).
//!
//! Decisions (see `docs/superpowers/specs/2026-11-13-backup-design.md`):
//! restore merges over the home; PHP and applications are stopped while it
//! runs; a tenant with backups cannot be deleted; one job per tenant at a time.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::nginx::safe_path_str;
use crate::records::{
    now_unix, BackupMember, BackupRecord, BackupState, JobKind, JobRecord, JobState, TenantRecord,
    TenantState, VHostRecord, RECORD_VERSION,
};
use crate::system::{bin, CommandSpec};
use crate::validate::{BackupId, JobId, Username};
use crate::vhost::VHostService;
use crate::worker::{self, Task};

/// Version of the on-disk layout described in the module documentation.
pub const MANIFEST_FORMAT: u32 = 1;
pub const MANIFEST: &str = "manifest.json";
pub const HOME_MEMBER: &str = "home.tar.gz";
pub const RECORDS_MEMBER: &str = "records.json";
const KIND_RECORDS: &str = "records";
const RESULT_SUFFIX: &str = ".result.json";

const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
/// Jobs running on the host at once, over all tenants.
pub const MAX_RUNNING_JOBS: usize = 4;
/// Finished jobs remembered per tenant.
const JOBS_KEPT_PER_TENANT: usize = 20;
/// How often a running job's unit is looked at.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Measuring a large home takes longer than an ordinary command may.
const MEASURE_TIMEOUT: Duration = Duration::from_secs(240);
/// How much of the worker's output a job record keeps.
const OUTPUT_LINES: &str = "40";
const OUTPUT_MAX_BYTES: usize = 4096;
/// Consecutive faults after which a driver stops looking at its job.
const MAX_DRIVER_FAULTS: u32 = 30;

/// What `manifest.json` holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub id: String,
    pub tenant: String,
    pub created_at_unix: u64,
    pub engine_version: String,
    pub members: Vec<BackupMember>,
}

/// What `records.json` holds.
#[derive(Debug, Serialize)]
struct RecordsMember<'a> {
    tenant: &'a TenantRecord,
    vhosts: &'a [VHostRecord],
}

/// `<backup_dir>/<tenant>`
pub fn tenant_dir(backup_dir: &Path, tenant: &Username) -> PathBuf {
    backup_dir.join(tenant.as_str())
}

/// `<backup_dir>/<tenant>/<id>`
pub fn backup_path(backup_dir: &Path, tenant: &Username, id: &BackupId) -> PathBuf {
    tenant_dir(backup_dir, tenant).join(id.as_str())
}

/// The transient unit of a job, without `.service`.
pub fn unit_name(job: &JobId) -> String {
    format!("oxpanel-job-{job}")
}

/// What `manifest.json` of a sealed backup contains — the single definition,
/// shared by sealing and reconciliation.
pub fn render_manifest(rec: &BackupRecord) -> Result<Vec<u8>> {
    let manifest = Manifest {
        format: MANIFEST_FORMAT,
        id: rec.id.clone(),
        tenant: rec.tenant.clone(),
        created_at_unix: rec.created_at_unix,
        engine_version: env!("CARGO_PKG_VERSION").to_owned(),
        members: rec.members.clone(),
    };
    let mut bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| Error::Internal(format!("serialise manifest: {e}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Where a job's unit stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitState {
    Running,
    /// The worker exited with status 0.
    Exited,
    Failed {
        /// systemd's `Result=`: `exit-code`, `timeout`, `signal`, `oom-kill`, …
        result: String,
        status: Option<u8>,
    },
    /// systemd no longer knows the unit (the host was restarted, or the unit
    /// never started).
    Gone,
}

/// Interpret `systemctl show --property=LoadState,ActiveState,SubState,Result,ExecMainStatus`.
pub fn parse_unit_state(show: &str) -> UnitState {
    let value = |key: &str| {
        show.lines()
            .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
            .unwrap_or("")
            .trim()
    };
    let status = value("ExecMainStatus").parse::<u8>().ok();
    let failed = || UnitState::Failed {
        result: value("Result").to_owned(),
        status,
    };
    match (value("LoadState"), value("ActiveState"), value("SubState")) {
        ("not-found", _, _) | (_, "inactive", _) => UnitState::Gone,
        (_, "active", "exited") if status == Some(0) && value("Result") == "success" => {
            UnitState::Exited
        }
        (_, "failed", _) | (_, "active", "exited") => failed(),
        _ => UnitState::Running,
    }
}

/// One line for the job record about why a worker failed.
fn describe_failure(kind: JobKind, result: &str, status: Option<u8>, limit: Duration) -> String {
    match (result, status) {
        ("timeout", _) => format!(
            "the job exceeded its time limit of {} seconds and was stopped",
            limit.as_secs()
        ),
        ("oom-kill", _) => "the job ran out of memory within the tenant's limits".to_owned(),
        (_, Some(worker::EXIT_INTEGRITY)) => {
            "the archive is damaged (size or checksum differs from what was recorded); nothing was restored".to_owned()
        }
        (_, Some(worker::EXIT_TOO_LARGE)) => {
            "the archive would not fit in the space available for backups".to_owned()
        }
        (_, Some(worker::EXIT_ARCHIVER)) => match kind {
            JobKind::Backup => "the archiver could not read the home directory".to_owned(),
            JobKind::Restore => {
                "the archiver refused or failed to restore some members; the others were restored (see output)".to_owned()
            }
        },
        _ => format!(
            "the worker failed ({}{})",
            if result.is_empty() { "unknown" } else { result },
            status.map_or_else(String::new, |s| format!(", status {s}"))
        ),
    }
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// Keep the end of `text`, at most [`OUTPUT_MAX_BYTES`] long.
fn tail(text: &str) -> String {
    let mut start = text.len().saturating_sub(OUTPUT_MAX_BYTES);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text.get(start..).unwrap_or_default().trim().to_owned()
}

#[derive(Debug, Clone)]
pub struct BackupService {
    ctx: Ctx,
    poll: Duration,
}

impl BackupService {
    pub fn new(ctx: Ctx) -> Self {
        Self {
            ctx,
            poll: POLL_INTERVAL,
        }
    }

    /// How often running jobs are looked at (tests shorten it).
    #[must_use]
    pub fn with_poll_interval(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
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

    /// The archiver and its compressor, which the RPM requires but a host
    /// installed by hand may lack: refused before anything is created.
    async fn archiver_available(&self) -> Result<()> {
        for program in [bin::TAR, bin::GZIP] {
            if !self.ctx.sys.is_installed(program).await {
                return Err(Error::RuntimeUnavailable("the archiver (tar and gzip)"));
            }
        }
        Ok(())
    }

    fn running_jobs(&self) -> Result<Vec<JobRecord>> {
        let mut jobs = self.ctx.store.list_jobs()?;
        jobs.retain(|j| j.state == JobState::Running);
        Ok(jobs)
    }

    /// The job in flight for `tenant`, if any; otherwise make sure the host
    /// has room for one more.
    fn job_in_flight(&self, tenant: &Username) -> Result<Option<JobRecord>> {
        let running = self.running_jobs()?;
        if let Some(job) = running.iter().find(|j| j.tenant == tenant.as_str()) {
            return Ok(Some(job.clone()));
        }
        if running.len() >= MAX_RUNNING_JOBS {
            return Err(Error::TooManyJobs);
        }
        Ok(None)
    }

    /// Identifiers for a new backup and job: the current time, moved forward
    /// until neither is taken. The caller holds the mutation lock.
    fn new_ids(&self) -> Result<(BackupId, JobId)> {
        let mut millis = unix_millis();
        loop {
            let (backup, job) = (BackupId::from_millis(millis), JobId::from_millis(millis));
            if self.ctx.store.load_backup(&backup)?.is_none()
                && self.ctx.store.load_job(&job)?.is_none()
            {
                return Ok((backup, job));
            }
            millis += 1;
        }
    }

    /// Space the home occupies, measured as the tenant (so nothing is looked
    /// at that the tenant could not look at). Sparse files count for what
    /// they occupy, which is also what `tar --sparse` stores.
    async fn home_usage(&self, tenant: &TenantRecord) -> Result<u64> {
        let out = self
            .ctx
            .sys
            .run(
                CommandSpec::new(bin::DU, MEASURE_TIMEOUT)
                    .args(["--summarize", "--one-file-system", "--block-size=1", "--"])
                    .arg(&tenant.home)
                    .as_user(tenant.uid, tenant.gid),
            )
            .await?;
        // A non-zero status only means some directory was unreadable; the
        // total of the rest is still printed.
        out.stdout_lossy()
            .lines()
            .last()
            .and_then(|l| l.split_whitespace().next())
            .and_then(|n| n.parse::<u64>().ok())
            .ok_or_else(|| {
                Error::Internal(format!("unexpected du output for '{}'", tenant.username))
            })
    }

    /// The `systemd-run` invocation for a job: the worker in the tenant's
    /// slice, at the lowest priority, able to write `writable` and nothing else.
    fn job_command(
        &self,
        job: &JobRecord,
        tenant: &TenantRecord,
        writable: &Path,
        task: &Task,
    ) -> Result<CommandSpec> {
        let cfg = &self.ctx.config;
        let writable = safe_path_str(writable)?;
        let exe = safe_path_str(&cfg.worker_exe)?;
        // Restored files keep their archived modes; archives are root-only.
        let umask = match job.kind {
            JobKind::Backup => "0077",
            JobKind::Restore => "0022",
        };
        // Not `--no-block`: systemd-run returns once the unit has started,
        // so the first look at it can never mistake a unit whose start is
        // still queued ("inactive") for one that has already gone.
        let mut cmd = CommandSpec::new(bin::SYSTEMD_RUN, cfg.command_timeout)
            .arg("--quiet")
            .arg(format!("--unit={}", job.unit));
        for property in [
            format!(
                "Description=OxPanel {} job {} (tenant {})",
                job.kind.as_str(),
                job.id,
                tenant.username
            ),
            // Charged to the tenant, and out of everybody's way.
            format!("Slice={}", tenant.slice_unit),
            "Nice=19".to_owned(),
            "CPUSchedulingPolicy=batch".to_owned(),
            "IOSchedulingClass=best-effort".to_owned(),
            "IOSchedulingPriority=7".to_owned(),
            format!("RuntimeMaxSec={}", cfg.backup_timeout.as_secs()),
            // The result stays readable until the daemon has collected it.
            "RemainAfterExit=yes".to_owned(),
            format!("UMask={umask}"),
            // Root, but only to switch to the tenant: without
            // CAP_DAC_OVERRIDE the worker cannot open a tenant's files.
            "CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_SETPCAP".to_owned(),
            "NoNewPrivileges=yes".to_owned(),
            "PrivateNetwork=yes".to_owned(),
            "PrivateTmp=yes".to_owned(),
            "PrivateDevices=yes".to_owned(),
            "ProtectSystem=strict".to_owned(),
            format!("ReadWritePaths={writable}"),
            "ProtectKernelTunables=yes".to_owned(),
            "ProtectKernelModules=yes".to_owned(),
            "ProtectKernelLogs=yes".to_owned(),
            "ProtectControlGroups=yes".to_owned(),
            "ProtectClock=yes".to_owned(),
            "ProtectHostname=yes".to_owned(),
            "RestrictNamespaces=yes".to_owned(),
            "RestrictRealtime=yes".to_owned(),
            // A restored file can never become set-uid or set-gid.
            "RestrictSUIDSGID=yes".to_owned(),
            "LockPersonality=yes".to_owned(),
            "MemoryDenyWriteExecute=yes".to_owned(),
            "SystemCallArchitectures=native".to_owned(),
        ] {
            cmd = cmd.arg("--property").arg(property);
        }
        Ok(cmd.arg("--").arg(exe).args(task.to_args()))
    }

    /// Start a backup of `tenant`. Returns the job and whether it was started
    /// now (`false`: a backup of this tenant was already running).
    pub async fn create(&self, tenant: &str) -> Result<(JobRecord, bool)> {
        let name = Username::parse_field(tenant, "tenant")?;
        self.archiver_available().await?;
        // Measured before the lock is taken: it can take a while.
        let needed = self.home_usage(&self.ready_tenant(&name)?).await?;

        let guard = self.ctx.lock.lock().await;
        let cfg = &self.ctx.config;
        let tenant_rec = self.ready_tenant(&name)?;
        if let Some(job) = self.job_in_flight(&name)? {
            return match job.kind {
                JobKind::Backup => Ok((job, false)),
                JobKind::Restore => Err(Error::JobRunning {
                    tenant: name.to_string(),
                    job: job.id,
                }),
            };
        }
        fsutil::ensure_dir(&cfg.backup_dir, DIR_MODE)?;
        // Refused before anything is created: the archive can be as large as
        // the home, and the reserve must survive it.
        let free = self
            .ctx
            .sys
            .host_stats(&cfg.backup_dir)
            .await?
            .disk_free_bytes;
        let reserve = cfg.backup_min_free_bytes;
        if free < needed.saturating_add(reserve) {
            return Err(Error::BackupNoSpace {
                needed,
                reserve,
                free,
            });
        }

        let (id, job_id) = self.new_ids()?;
        let dir = backup_path(&cfg.backup_dir, &name, &id);
        let vhosts: Vec<VHostRecord> = self
            .ctx
            .store
            .list_vhosts()?
            .into_iter()
            .filter(|v| v.tenant == tenant_rec.username)
            .collect();
        let backup = BackupRecord {
            version: RECORD_VERSION,
            id: id.to_string(),
            tenant: name.to_string(),
            uid: tenant_rec.uid,
            created_at_unix: now_unix(),
            state: BackupState::Creating,
            size_bytes: 0,
            members: Vec::new(),
            domains: vhosts.iter().map(|v| v.domain.clone()).collect(),
        };
        let job = JobRecord {
            version: RECORD_VERSION,
            id: job_id.to_string(),
            kind: JobKind::Backup,
            tenant: name.to_string(),
            backup_id: id.to_string(),
            unit: unit_name(&job_id),
            state: JobState::Running,
            message: String::new(),
            output: String::new(),
            started_at_unix: backup.created_at_unix,
            finished_at_unix: 0,
        };
        // Records first: whatever happens next, a restarted daemon knows
        // there is a job to finish and a directory to account for.
        self.ctx.store.save_backup(&backup)?;
        self.ctx.store.save_job(&job)?;
        let task = Task::Backup {
            uid: tenant_rec.uid,
            gid: tenant_rec.gid,
            home: tenant_rec.home.clone(),
            output: dir.join(HOME_MEMBER),
            // The archive may not grow into the reserve even if the home does.
            max_bytes: free - reserve,
        };
        let started = self
            .prepare_backup_dir(&name, &dir, &tenant_rec, &vhosts)
            .and_then(|()| self.job_command(&job, &tenant_rec, &dir, &task));
        let started = match started {
            Ok(cmd) => self.ctx.sys.run_ok(cmd).await.map(|_| ()),
            Err(e) => Err(e),
        };
        if let Err(e) = started {
            let job = self.abandon_backup(job, "the job could not be started")?;
            error!(job = %job.id, tenant = %name, error = %e, "backup could not be started");
            return Err(e);
        }
        drop(guard);
        info!(job = %job.id, backup = %id, tenant = %name, "backup started");
        self.spawn_driver(job_id);
        Ok((job, true))
    }

    /// The backup's directory with its `records` member in place.
    fn prepare_backup_dir(
        &self,
        name: &Username,
        dir: &Path,
        tenant: &TenantRecord,
        vhosts: &[VHostRecord],
    ) -> Result<()> {
        fsutil::ensure_dir(&tenant_dir(&self.ctx.config.backup_dir, name), DIR_MODE)?;
        fsutil::ensure_dir(dir, DIR_MODE)?;
        let mut bytes = serde_json::to_vec_pretty(&RecordsMember { tenant, vhosts })
            .map_err(|e| Error::Internal(format!("serialise records member: {e}")))?;
        bytes.push(b'\n');
        fsutil::write_atomic(&dir.join(RECORDS_MEMBER), &bytes, FILE_MODE)?;
        Ok(())
    }

    /// Start restoring `tenant` from its backup `backup_id`. Returns the job
    /// and whether it was started now.
    pub async fn restore(&self, tenant: &str, backup_id: &str) -> Result<(JobRecord, bool)> {
        let name = Username::parse_field(tenant, "tenant")?;
        let id = BackupId::parse(backup_id)?;
        self.archiver_available().await?;
        let guard = self.ctx.lock.lock().await;
        let cfg = &self.ctx.config;
        let tenant_rec = self.ready_tenant(&name)?;
        // The backup is looked up *for this tenant*: someone else's backup
        // does not exist here, whatever its identifier.
        let backup = self.backup_of(&name, &id)?;
        if backup.state != BackupState::Ready {
            return Err(Error::BackupNotReady(id.to_string()));
        }
        if backup.uid != tenant_rec.uid {
            return Err(Error::Internal(format!(
                "backup {id} was taken from uid {}, but tenant '{name}' is uid {}",
                backup.uid, tenant_rec.uid
            )));
        }
        if let Some(job) = self.job_in_flight(&name)? {
            return if job.kind == JobKind::Restore && job.backup_id == backup.id {
                Ok((job, false))
            } else {
                Err(Error::JobRunning {
                    tenant: name.to_string(),
                    job: job.id,
                })
            };
        }
        let home = backup
            .members
            .iter()
            .find(|m| m.kind == worker::KIND_HOME)
            .ok_or_else(|| Error::Internal(format!("backup {id} has no home member")))?;
        let (_, job_id) = self.new_ids()?;
        let job = JobRecord {
            version: RECORD_VERSION,
            id: job_id.to_string(),
            kind: JobKind::Restore,
            tenant: name.to_string(),
            backup_id: id.to_string(),
            unit: unit_name(&job_id),
            state: JobState::Running,
            message: String::new(),
            output: String::new(),
            started_at_unix: now_unix(),
            finished_at_unix: 0,
        };
        let task = Task::Restore {
            uid: tenant_rec.uid,
            gid: tenant_rec.gid,
            home: tenant_rec.home.clone(),
            input: backup_path(&cfg.backup_dir, &name, &id).join(&home.name),
            sha256: home.sha256.clone(),
            size: home.size_bytes,
        };
        let cmd = self.job_command(&job, &tenant_rec, &tenant_rec.home, &task)?;
        self.ctx.store.save_job(&job)?;
        // Nothing of the tenant's runs on half-restored files. A suspended
        // tenant's services are stopped already.
        let started = match self.set_services(&tenant_rec, false).await {
            Ok(()) => self.ctx.sys.run_ok(cmd).await.map(|_| ()),
            Err(e) => Err(e),
        };
        if let Err(e) = started {
            error!(job = %job.id, tenant = %name, error = %e, "restore could not be started");
            self.conclude_restore(job, Err("the job could not be started".to_owned()), "")
                .await?;
            return Err(e);
        }
        drop(guard);
        info!(job = %job.id, backup = %id, tenant = %name, "restore started");
        self.spawn_driver(job_id);
        Ok((job, true))
    }

    /// Start (or stop) the tenant's PHP pool and applications, unless the
    /// tenant is suspended: then they stay stopped.
    async fn set_services(&self, tenant: &TenantRecord, running: bool) -> Result<()> {
        if tenant.suspended {
            return Ok(());
        }
        crate::php::set_running(&self.ctx, tenant, running).await?;
        crate::app::set_running_all(&self.ctx, tenant, running).await
    }

    /// The record of `tenant`'s backup `id`.
    fn backup_of(&self, tenant: &Username, id: &BackupId) -> Result<BackupRecord> {
        self.ctx
            .store
            .load_backup(id)?
            .filter(|b| b.tenant == tenant.as_str())
            .ok_or_else(|| Error::BackupNotFound {
                tenant: tenant.to_string(),
                id: id.to_string(),
            })
    }

    /// The tenant's backups, oldest first.
    pub async fn list(&self, tenant: &str) -> Result<Vec<BackupRecord>> {
        let name = Username::parse_field(tenant, "tenant")?;
        if self.ctx.store.load_tenant(&name)?.is_none() {
            return Err(Error::TenantNotFound(name.to_string()));
        }
        let mut all = self.ctx.store.list_backups()?;
        all.retain(|b| b.tenant == name.as_str());
        Ok(all)
    }

    pub async fn job(&self, job_id: &str) -> Result<JobRecord> {
        let id = JobId::parse(job_id)?;
        self.ctx
            .store
            .load_job(&id)?
            .ok_or_else(|| Error::JobNotFound(id.to_string()))
    }

    /// Delete one of the tenant's backups. Returns `false` if it has none
    /// with this identifier.
    pub async fn delete(&self, tenant: &str, backup_id: &str) -> Result<bool> {
        let name = Username::parse_field(tenant, "tenant")?;
        let id = BackupId::parse(backup_id)?;
        let _guard = self.ctx.lock.lock().await;
        let Ok(backup) = self.backup_of(&name, &id) else {
            return Ok(false);
        };
        if let Some(job) = self
            .running_jobs()?
            .into_iter()
            .find(|j| j.backup_id == backup.id)
        {
            return Err(Error::JobRunning {
                tenant: name.to_string(),
                job: job.id,
            });
        }
        self.remove_backup(&name, &id)?;
        info!(backup = %id, tenant = %name, "backup deleted");
        Ok(true)
    }

    /// Remove a backup's files, then its record. Repeating it after a crash
    /// in between completes it.
    fn remove_backup(&self, tenant: &Username, id: &BackupId) -> Result<()> {
        let backup_dir = &self.ctx.config.backup_dir;
        fsutil::remove_dir_tree(&backup_path(backup_dir, tenant, id))?;
        // The tenant's directory goes with its last backup (fails, harmlessly,
        // while others remain).
        let _ = std::fs::remove_dir(tenant_dir(backup_dir, tenant));
        self.ctx.store.delete_backup(id)?;
        Ok(())
    }

    /// Pick up every job that was running when the daemon last stopped.
    pub async fn resume_all(&self) -> Result<usize> {
        let jobs = self.running_jobs()?;
        for job in &jobs {
            info!(job = %job.id, kind = job.kind.as_str(), tenant = %job.tenant, "resuming job");
            self.spawn_driver(JobId::parse(&job.id)?);
        }
        Ok(jobs.len())
    }

    fn spawn_driver(&self, id: JobId) {
        tokio::spawn(self.clone().drive(id));
    }

    /// Watch a job until it has been concluded.
    async fn drive(self, id: JobId) {
        let mut faults = 0;
        loop {
            match self.step(&id).await {
                Ok(true) => return,
                Ok(false) => faults = 0,
                Err(e) => {
                    faults += 1;
                    warn!(job = %id, error = %e, faults, "could not check on job; will retry");
                    if faults >= MAX_DRIVER_FAULTS {
                        error!(job = %id, "giving up on job until the next start; see `oxpanel-ctl host reconcile`");
                        return;
                    }
                }
            }
            tokio::time::sleep(self.poll).await;
        }
    }

    /// Look at a job once; conclude it if its unit has ended. Returns whether
    /// the job is finished.
    pub async fn step(&self, id: &JobId) -> Result<bool> {
        let Some(job) = self.ctx.store.load_job(id)? else {
            return Ok(true);
        };
        if job.state != JobState::Running {
            return Ok(true);
        }
        let state = self.unit_state(&job.unit).await?;
        if state == UnitState::Running {
            return Ok(false);
        }
        let output = self.unit_output(&job.unit).await;
        let _guard = self.ctx.lock.lock().await;
        let outcome = match &state {
            UnitState::Exited => Ok(()),
            // Whether a vanished unit had finished is for the result file to say.
            UnitState::Gone if job.kind == JobKind::Backup => Ok(()),
            UnitState::Gone => Err(
                "the job did not run to its end (was the host restarted?); repeat the restore"
                    .to_owned(),
            ),
            UnitState::Failed { result, status } => Err(describe_failure(
                job.kind,
                result,
                *status,
                self.ctx.config.backup_timeout,
            )),
            UnitState::Running => return Ok(false),
        };
        let unit = job.unit.clone();
        match job.kind {
            JobKind::Backup => self.conclude_backup(job, outcome, &output)?,
            JobKind::Restore => self.conclude_restore(job, outcome, &output).await?,
        };
        self.forget_unit(&unit, &state).await;
        Ok(true)
    }

    async fn unit_state(&self, unit: &str) -> Result<UnitState> {
        let mut cmd = CommandSpec::new(bin::SYSTEMCTL, self.ctx.config.command_timeout).arg("show");
        for property in [
            "LoadState",
            "ActiveState",
            "SubState",
            "Result",
            "ExecMainStatus",
        ] {
            cmd = cmd.arg(format!("--property={property}"));
        }
        let out = self
            .ctx
            .sys
            .run_ok(cmd.arg("--").arg(format!("{unit}.service")))
            .await?;
        Ok(parse_unit_state(&out.stdout_lossy()))
    }

    /// The end of what the worker and the archiver printed. Best effort.
    async fn unit_output(&self, unit: &str) -> String {
        let journal = self
            .ctx
            .sys
            .run(
                CommandSpec::new(bin::JOURNALCTL, self.ctx.config.command_timeout)
                    .args(["--no-pager", "--output=cat", "--lines"])
                    .arg(OUTPUT_LINES)
                    .arg("--unit")
                    .arg(format!("{unit}.service")),
            )
            .await;
        journal.map_or_else(|_| String::new(), |out| tail(&out.stdout_lossy()))
    }

    /// Let systemd drop a unit whose result has been recorded. Best effort.
    async fn forget_unit(&self, unit: &str, state: &UnitState) {
        let verb = match state {
            UnitState::Exited => "stop",
            UnitState::Failed { .. } => "reset-failed",
            UnitState::Running | UnitState::Gone => return,
        };
        let cmd = CommandSpec::new(bin::SYSTEMCTL, self.ctx.config.command_timeout)
            .args([verb, "--"])
            .arg(format!("{unit}.service"));
        if let Err(e) = self.ctx.sys.run(cmd).await {
            warn!(unit, error = %e, "could not clean up the job's unit");
        }
    }

    /// Turn the directory of a finished backup job into a backup: every
    /// member that has a result file is listed with its size and checksum,
    /// then the manifest is written. `Err(reason)` if the worker left no
    /// complete archive.
    fn seal(
        mut backup: BackupRecord,
        dir: &Path,
    ) -> Result<std::result::Result<BackupRecord, String>> {
        let mut members = Vec::new();
        let mut results = Vec::new();
        for path in fsutil::list_files_with_suffix(dir, RESULT_SUFFIX)? {
            let Some(name) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(RESULT_SUFFIX))
            else {
                continue;
            };
            let member = dir.join(name);
            let Some(result) = worker::read_result(&member)? else {
                continue;
            };
            let on_disk = std::fs::metadata(&member).map_or(0, |m| m.len());
            if on_disk != result.size_bytes {
                return Ok(Err(format!(
                    "member {name} is {on_disk} bytes long, its worker reported {}",
                    result.size_bytes
                )));
            }
            members.push(BackupMember {
                name: name.to_owned(),
                kind: result.kind,
                size_bytes: result.size_bytes,
                sha256: result.sha256,
            });
            results.push(path);
        }
        if !members.iter().any(|m| m.kind == worker::KIND_HOME) {
            return Ok(Err(
                "the worker left no complete archive (was it stopped, or the host restarted?)"
                    .to_owned(),
            ));
        }
        let (size_bytes, sha256) = worker::hash_file(&dir.join(RECORDS_MEMBER))?;
        members.push(BackupMember {
            name: RECORDS_MEMBER.to_owned(),
            kind: KIND_RECORDS.to_owned(),
            size_bytes,
            sha256,
        });
        members.sort_by(|a, b| a.name.cmp(&b.name));
        backup.size_bytes = members.iter().map(|m| m.size_bytes).sum();
        backup.members = members;
        backup.state = BackupState::Ready;
        // The commit point of the backup on disk.
        fsutil::write_atomic(&dir.join(MANIFEST), &render_manifest(&backup)?, FILE_MODE)?;
        for path in results {
            fsutil::remove_if_exists(&path)?;
        }
        Ok(Ok(backup))
    }

    /// Record the end of a backup job: a sealed backup, or nothing at all.
    /// The caller holds the mutation lock.
    fn conclude_backup(
        &self,
        job: JobRecord,
        outcome: std::result::Result<(), String>,
        output: &str,
    ) -> Result<JobRecord> {
        let name = Username::parse_field(&job.tenant, "tenant")?;
        let id = BackupId::parse(&job.backup_id)?;
        let dir = backup_path(&self.ctx.config.backup_dir, &name, &id);
        let sealed = match (outcome, self.ctx.store.load_backup(&id)?) {
            (Err(reason), _) => Err(reason),
            (Ok(()), None) => Err("the backup's record is gone".to_owned()),
            (Ok(()), Some(backup)) => Self::seal(backup, &dir)?,
        };
        match sealed {
            Ok(backup) => {
                self.ctx.store.save_backup(&backup)?;
                info!(job = %job.id, backup = %id, tenant = %name, bytes = backup.size_bytes, "backup complete");
                self.enforce_retention(&name)?;
                self.finish_job(
                    job,
                    JobState::Succeeded,
                    format!("backup {id} complete ({} bytes)", backup.size_bytes),
                    output,
                )
            }
            Err(reason) => {
                warn!(job = %job.id, backup = %id, tenant = %name, %reason, "backup failed; removing what was written");
                self.remove_backup(&name, &id)?;
                self.finish_job(job, JobState::Failed, reason, output)
            }
        }
    }

    /// A backup job that never got going: nothing stays behind.
    fn abandon_backup(&self, job: JobRecord, reason: &str) -> Result<JobRecord> {
        self.conclude_backup(job, Err(reason.to_owned()), "")
    }

    /// Record the end of a restore job, after putting the tenant's sites back
    /// into service. The caller holds the mutation lock.
    async fn conclude_restore(
        &self,
        job: JobRecord,
        outcome: std::result::Result<(), String>,
        output: &str,
    ) -> Result<JobRecord> {
        let name = Username::parse_field(&job.tenant, "tenant")?;
        // Whatever the archiver did or did not do, the home must be private
        // and the sites must be servable and running again.
        let service = match self.ctx.store.load_tenant(&name)? {
            Some(tenant) if tenant.state == TenantState::Ready => {
                self.back_into_service(&tenant).await
            }
            _ => Ok(()),
        };
        let (state, message) = match (outcome, service) {
            (Ok(()), Ok(())) => (
                JobState::Succeeded,
                format!("restored from backup {}", job.backup_id),
            ),
            (Err(reason), Ok(())) => (JobState::Failed, reason),
            (outcome, Err(e)) => {
                error!(job = %job.id, tenant = %name, error = %e, "could not put the tenant back into service after a restore");
                let files = match outcome {
                    Ok(()) => "the files were restored".to_owned(),
                    Err(reason) => reason,
                };
                (
                    JobState::Failed,
                    format!("{files}, but the sites could not be put back into service; see the oxpanel-daemon journal"),
                )
            }
        };
        if state == JobState::Succeeded {
            info!(job = %job.id, backup = %job.backup_id, tenant = %name, "restore complete");
        } else {
            warn!(job = %job.id, backup = %job.backup_id, tenant = %name, reason = %message, "restore failed");
        }
        self.finish_job(job, state, message, output)
    }

    /// What a restore may have undone, done again: the home closed to
    /// others, default labels, the web server's access to every document
    /// root (as `ConfigureVirtualHost` grants it), and the tenant's services.
    /// Every step is attempted; the first error is returned.
    async fn back_into_service(&self, tenant: &TenantRecord) -> Result<()> {
        let private = self
            .ctx
            .sys
            .ensure_private_dir(&tenant.home, tenant.uid, tenant.gid)
            .await;
        let labels = if self.ctx.selinux {
            self.ctx
                .sys
                .run_ok(
                    CommandSpec::new(bin::RESTORECON, MEASURE_TIMEOUT)
                        .args(["-R", "--"])
                        .arg(&tenant.home),
                )
                .await
                .map(|_| ())
        } else {
            Ok(())
        };
        let access = VHostService::new(self.ctx.clone())
            .restore_web_access(tenant)
            .await;
        let services = self.set_services(tenant, true).await;
        private.and(labels).and(access).and(services)
    }

    fn finish_job(
        &self,
        mut job: JobRecord,
        state: JobState,
        message: String,
        output: &str,
    ) -> Result<JobRecord> {
        job.state = state;
        job.message = message;
        output.clone_into(&mut job.output);
        job.finished_at_unix = now_unix();
        self.ctx.store.save_job(&job)?;
        // Old history of this tenant makes room.
        let mut finished = self.ctx.store.list_jobs()?;
        finished.retain(|j| j.tenant == job.tenant && j.state != JobState::Running);
        let surplus = finished.len().saturating_sub(JOBS_KEPT_PER_TENANT);
        for old in finished.iter().take(surplus) {
            self.ctx.store.delete_job(&JobId::parse(&old.id)?)?;
        }
        Ok(job)
    }

    /// Keep the newest `backup_keep` complete backups of the tenant.
    fn enforce_retention(&self, tenant: &Username) -> Result<()> {
        let mut ready = self.ctx.store.list_backups()?;
        ready.retain(|b| b.tenant == tenant.as_str() && b.state == BackupState::Ready);
        let keep = usize::try_from(self.ctx.config.backup_keep).unwrap_or(usize::MAX);
        let surplus = ready.len().saturating_sub(keep);
        for old in ready.iter().take(surplus) {
            let id = BackupId::parse(&old.id)?;
            self.remove_backup(tenant, &id)?;
            info!(backup = %id, %tenant, keep, "old backup removed (retention)");
        }
        Ok(())
    }
}

/// `DeleteTenant` is refused while the tenant has backups or a job in
/// flight: backups are found by the tenant's name, so a later tenant of the
/// same name would inherit them, and deleting them silently would destroy
/// the only copy of a customer's data on the say-so of a different request.
pub fn refuse_tenant_deletion(ctx: &Ctx, tenant: &Username) -> Result<()> {
    if let Some(job) = ctx
        .store
        .list_jobs()?
        .into_iter()
        .find(|j| j.tenant == tenant.as_str() && j.state == JobState::Running)
    {
        return Err(Error::JobRunning {
            tenant: tenant.to_string(),
            job: job.id,
        });
    }
    if ctx
        .store
        .list_backups()?
        .iter()
        .any(|b| b.tenant == tenant.as_str())
    {
        return Err(Error::TenantHasBackups(tenant.to_string()));
    }
    Ok(())
}

/// Drop the job history of a tenant that is being deleted, so that a later
/// tenant of the same name starts with none.
pub fn forget_tenant_jobs(ctx: &Ctx, tenant: &Username) -> Result<()> {
    for job in ctx
        .store
        .list_jobs()?
        .iter()
        .filter(|j| j.tenant == tenant.as_str())
    {
        ctx.store.delete_job(&JobId::parse(&job.id)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::system::{FakeSystem, RunAs};
    use crate::tenant::TenantService;
    use crate::validate::Limits;
    use crate::vhost::{VHostRequest, VHostService};
    use std::sync::Arc;

    struct Harness {
        _dir: tempfile::TempDir,
        sys: Arc<FakeSystem>,
        ctx: Ctx,
        tenants: TenantService,
        vhosts: VHostService,
        backups: BackupService,
    }

    const RUNNING: &str = "LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nExecMainStatus=0\n";
    const GONE: &str = "LoadState=not-found\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainStatus=0\n";

    fn failed(result: &str, status: u8) -> String {
        format!("LoadState=loaded\nActiveState=failed\nSubState=failed\nResult={result}\nExecMainStatus={status}\n")
    }

    /// Tenants alice (with a site) and bob. Jobs are driven by hand through
    /// `step`, so the poll interval is an hour.
    async fn harness(selinux: bool) -> Harness {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let mut cfg = Config::default();
        cfg.state_dir = dir.path().join("state");
        cfg.home_base = dir.path().join("home");
        cfg.backup_dir = dir.path().join("backups");
        cfg.systemd_unit_dir = dir.path().join("systemd");
        cfg.nginx_log_dir = dir.path().join("log");
        cfg.php_conf_dir = dir.path().join("php");
        cfg.nginx_conf_dir = dir.path().join("nginx").join("oxpanel.d");
        cfg.nginx_include_file = dir
            .path()
            .join("nginx")
            .join("conf.d")
            .join("00-oxpanel.conf");
        cfg.backup_keep = 2;
        for d in [
            &cfg.home_base,
            &cfg.systemd_unit_dir,
            &dir.path().join("nginx").join("conf.d"),
        ] {
            std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("{e}"));
        }
        let sys = Arc::new(FakeSystem::new());
        let ctx = Ctx::new(cfg, sys.clone(), selinux);
        ctx.store.init().unwrap_or_else(|e| panic!("{e}"));
        let h = Harness {
            _dir: dir,
            sys,
            tenants: TenantService::new(ctx.clone()),
            vhosts: VHostService::new(ctx.clone()),
            backups: BackupService::new(ctx.clone()).with_poll_interval(Duration::from_secs(3600)),
            ctx,
        };
        for tenant in ["alice", "bob"] {
            h.tenants
                .create(tenant, Limits::default(), "")
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        }
        h.vhosts
            .configure(VHostRequest {
                domain: "example.com".into(),
                tenant: "alice".into(),
                php: true,
                ..VHostRequest::default()
            })
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        h.sys.clear_calls();
        h
    }

    fn args(c: &CommandSpec) -> Vec<String> {
        c.args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    impl Harness {
        /// Start a backup and conclude it (the fake worker has finished).
        async fn backup(&self, tenant: &str) -> Result<JobRecord> {
            let (job, started) = self.backups.create(tenant).await?;
            assert!(started);
            self.finish(&job).await
        }

        async fn finish(&self, job: &JobRecord) -> Result<JobRecord> {
            assert!(self.backups.step(&JobId::parse(&job.id)?).await?);
            self.backups.job(&job.id).await
        }

        fn dir(&self, job: &JobRecord) -> PathBuf {
            self.ctx
                .config
                .backup_dir
                .join(&job.tenant)
                .join(&job.backup_id)
        }
    }

    #[test]
    fn unit_states_are_read_from_systemctl_show() {
        assert_eq!(parse_unit_state(RUNNING), UnitState::Running);
        assert_eq!(
            parse_unit_state("LoadState=loaded\nActiveState=activating\nSubState=start\n"),
            UnitState::Running
        );
        assert_eq!(
            parse_unit_state("LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nExecMainStatus=0\n"),
            UnitState::Exited
        );
        assert_eq!(parse_unit_state(GONE), UnitState::Gone);
        assert_eq!(
            parse_unit_state(&failed("exit-code", 12)),
            UnitState::Failed {
                result: "exit-code".into(),
                status: Some(12)
            }
        );
        // Never "succeeded" by accident: an exited unit with a bad status failed.
        assert!(matches!(
            parse_unit_state("LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nExecMainStatus=1\n"),
            UnitState::Failed { .. }
        ));
        assert_eq!(
            parse_unit_state(""),
            UnitState::Running,
            "unknown is not finished"
        );
    }

    #[tokio::test]
    async fn create_starts_a_sandboxed_worker_in_the_tenants_slice() -> Result<()> {
        let h = harness(false).await;
        let (job, started) = h.backups.create("alice").await?;
        assert!(started);
        assert_eq!((job.kind, job.state), (JobKind::Backup, JobState::Running));
        let home = h.ctx.config.home_base.join("alice");
        let home = home.to_string_lossy();
        let dir = h.dir(&job);
        let dir_str = dir.to_string_lossy();

        // Measured as the tenant.
        let du = h.sys.calls_to(bin::DU);
        assert_eq!(du.len(), 1);
        assert_eq!(
            du.first().and_then(|c| c.run_as),
            Some(RunAs {
                uid: 20000,
                gid: 20000
            })
        );

        let run = h.sys.calls_to(bin::SYSTEMD_RUN);
        assert_eq!(run.len(), 1);
        assert!(run.first().is_some_and(|c| c.run_as.is_none()));
        let mut expected: Vec<String> =
            vec!["--quiet".into(), format!("--unit=oxpanel-job-{}", job.id)];
        for property in [
            format!("Description=OxPanel backup job {} (tenant alice)", job.id),
            "Slice=oxpanel-tenant-alice.slice".into(),
            "Nice=19".into(),
            "CPUSchedulingPolicy=batch".into(),
            "IOSchedulingClass=best-effort".into(),
            "IOSchedulingPriority=7".into(),
            "RuntimeMaxSec=21600".into(),
            "RemainAfterExit=yes".into(),
            "UMask=0077".into(),
            "CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_SETPCAP".into(),
            "NoNewPrivileges=yes".into(),
            "PrivateNetwork=yes".into(),
            "PrivateTmp=yes".into(),
            "PrivateDevices=yes".into(),
            "ProtectSystem=strict".into(),
            format!("ReadWritePaths={dir_str}"),
            "ProtectKernelTunables=yes".into(),
            "ProtectKernelModules=yes".into(),
            "ProtectKernelLogs=yes".into(),
            "ProtectControlGroups=yes".into(),
            "ProtectClock=yes".into(),
            "ProtectHostname=yes".into(),
            "RestrictNamespaces=yes".into(),
            "RestrictRealtime=yes".into(),
            "RestrictSUIDSGID=yes".into(),
            "LockPersonality=yes".into(),
            "MemoryDenyWriteExecute=yes".into(),
            "SystemCallArchitectures=native".into(),
        ] {
            expected.push("--property".into());
            expected.push(property);
        }
        // 80 GiB free in the fake, 1 GiB reserve.
        let max_bytes = (79u64 << 30).to_string();
        expected.extend(
            [
                "--",
                "/usr/sbin/oxpanel-daemon",
                "worker",
                "backup",
                "20000",
                "--gid",
                "20000",
                "--home",
                &home,
                "--output",
                &format!("{dir_str}/home.tar.gz"),
                "--max-bytes",
                &max_bytes,
            ]
            .map(str::to_owned),
        );
        assert_eq!(run.first().map(args), Some(expected));

        // In flight: listed as CREATING, not restorable, not deletable.
        let listed = h.backups.list("alice").await?;
        assert_eq!(listed.len(), 1);
        assert!(listed
            .first()
            .is_some_and(|b| b.state == BackupState::Creating && b.domains == ["example.com"]));
        assert!(matches!(
            h.backups.restore("alice", &job.backup_id).await,
            Err(Error::BackupNotReady(_))
        ));
        assert!(matches!(
            h.backups.delete("alice", &job.backup_id).await,
            Err(Error::JobRunning { .. })
        ));
        // A repeated request returns the job that is running.
        let (again, started) = h.backups.create("alice").await?;
        assert!(!started);
        assert_eq!(again.id, job.id);
        assert_eq!(h.sys.calls_to(bin::SYSTEMD_RUN).len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_finished_backup_is_sealed_with_checksums_and_a_manifest() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let h = harness(false).await;
        let (job, _) = h.backups.create("alice").await?;
        let id = JobId::parse(&job.id)?;
        // Still running: nothing changes.
        h.sys.script_stdout(bin::SYSTEMCTL, RUNNING);
        assert!(!h.backups.step(&id).await?);
        assert_eq!(h.backups.job(&job.id).await?.state, JobState::Running);
        h.sys.clear_calls();

        let done = h.finish(&job).await?;
        assert_eq!(done.state, JobState::Succeeded);
        assert!(done.finished_at_unix >= done.started_at_unix && done.finished_at_unix > 0);
        assert!(done
            .message
            .starts_with(&format!("backup {} complete", job.backup_id)));
        let systemctl: Vec<Vec<String>> = h.sys.calls_to(bin::SYSTEMCTL).iter().map(args).collect();
        assert_eq!(
            systemctl,
            vec![
                vec![
                    "show".to_owned(),
                    "--property=LoadState".into(),
                    "--property=ActiveState".into(),
                    "--property=SubState".into(),
                    "--property=Result".into(),
                    "--property=ExecMainStatus".into(),
                    "--".into(),
                    format!("oxpanel-job-{}.service", job.id),
                ],
                vec![
                    "stop".to_owned(),
                    "--".into(),
                    format!("oxpanel-job-{}.service", job.id)
                ],
            ]
        );

        let backups = h.backups.list("alice").await?;
        let backup = backups.first().unwrap_or_else(|| panic!("no backup"));
        assert_eq!(backup.state, BackupState::Ready);
        let kinds: Vec<(&str, &str)> = backup
            .members
            .iter()
            .map(|m| (m.name.as_str(), m.kind.as_str()))
            .collect();
        assert_eq!(
            kinds,
            vec![("home.tar.gz", "home"), ("records.json", "records")]
        );
        let dir = h.dir(&job);
        for m in &backup.members {
            let (size, sha) = worker::hash_file(&dir.join(&m.name))?;
            assert_eq!((m.size_bytes, m.sha256.as_str()), (size, sha.as_str()));
        }
        assert_eq!(
            backup.size_bytes,
            backup.members.iter().map(|m| m.size_bytes).sum::<u64>()
        );
        // The manifest is exactly what the record renders to; the records
        // member names the tenant and its site.
        let manifest = std::fs::read(dir.join(MANIFEST)).map_err(|e| Error::io("read", &dir, e))?;
        assert_eq!(manifest, render_manifest(backup)?);
        let parsed: Manifest = serde_json::from_slice(&manifest).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((parsed.format, parsed.tenant.as_str()), (1, "alice"));
        let records = std::fs::read_to_string(dir.join(RECORDS_MEMBER)).unwrap_or_default();
        assert!(records.contains("\"username\": \"alice\"") && records.contains("example.com"));
        // Root-only all the way down, and no worker leftovers.
        for p in [
            h.ctx.config.backup_dir.clone(),
            h.ctx.config.backup_dir.join("alice"),
            dir.clone(),
        ] {
            let mode = std::fs::metadata(&p)
                .map_err(|e| Error::io("stat", &p, e))?
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700, "{}", p.display());
        }
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .map_err(|e| Error::io("readdir", &dir, e))?
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        names.sort();
        assert_eq!(names, vec!["home.tar.gz", "manifest.json", "records.json"]);
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_or_interrupted_backup_leaves_nothing_behind() -> Result<()> {
        let h = harness(false).await;
        // The worker failed: tar could not read the home.
        let (job, _) = h.backups.create("alice").await?;
        std::fs::write(h.dir(&job).join("home.tar.gz"), b"partial")
            .map_err(|e| Error::io("write", h.dir(&job), e))?;
        std::fs::remove_file(h.dir(&job).join("home.tar.gz.result.json"))
            .map_err(|e| Error::io("rm", h.dir(&job), e))?;
        h.sys
            .script_stdout(bin::SYSTEMCTL, &failed("exit-code", worker::EXIT_ARCHIVER));
        h.sys
            .script_stdout(bin::JOURNALCTL, "tar: .: Cannot open: Permission denied\n");
        h.sys.clear_calls();
        let done = h.finish(&job).await?;
        assert_eq!(done.state, JobState::Failed);
        assert_eq!(
            done.message,
            "the archiver could not read the home directory"
        );
        assert_eq!(done.output, "tar: .: Cannot open: Permission denied");
        assert!(!h.dir(&job).exists(), "no half-written archive stays");
        assert!(!h.ctx.config.backup_dir.join("alice").exists());
        assert!(h.backups.list("alice").await?.is_empty());
        assert!(h
            .sys
            .calls_to(bin::SYSTEMCTL)
            .iter()
            .any(|c| args(c).first().is_some_and(|a| a == "reset-failed")));

        // Time limit, size limit: the same, with a message that says which.
        for (show, needle) in [
            (failed("timeout", 0), "time limit of 21600 seconds"),
            (failed("exit-code", worker::EXIT_TOO_LARGE), "would not fit"),
            (failed("signal", 0), "the worker failed (signal"),
        ] {
            let (job, _) = h.backups.create("alice").await?;
            h.sys.script_stdout(bin::SYSTEMCTL, &show);
            let done = h.finish(&job).await?;
            assert_eq!(done.state, JobState::Failed);
            assert!(done.message.contains(needle), "{}", done.message);
            assert!(h.backups.list("alice").await?.is_empty());
        }

        // The unit vanished (host restarted) before the worker finished: the
        // archive is there but has no result file, so it is not a backup.
        h.sys.set_worker_writes_nothing(true);
        let (job, _) = h.backups.create("alice").await?;
        std::fs::write(h.dir(&job).join("home.tar.gz"), b"looks like an archive")
            .map_err(|e| Error::io("write", h.dir(&job), e))?;
        h.sys.script_stdout(bin::SYSTEMCTL, GONE);
        let done = h.finish(&job).await?;
        assert_eq!(done.state, JobState::Failed);
        assert!(done.message.contains("no complete archive"));
        assert!(!h.dir(&job).exists());
        // … and the same when the unit says it succeeded but left nothing.
        let (job, _) = h.backups.create("alice").await?;
        let done = h.finish(&job).await?;
        assert_eq!(done.state, JobState::Failed);
        assert!(h.backups.list("alice").await?.is_empty());
        h.sys.set_worker_writes_nothing(false);

        // A unit that vanished *after* the worker finished: complete, kept.
        let (job, _) = h.backups.create("alice").await?;
        h.sys.script_stdout(bin::SYSTEMCTL, GONE);
        assert_eq!(h.finish(&job).await?.state, JobState::Succeeded);
        assert_eq!(h.backups.list("alice").await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_worker_that_cannot_be_started_fails_the_job_cleanly() -> Result<()> {
        let h = harness(false).await;
        h.sys.script_failure(
            bin::SYSTEMD_RUN,
            1,
            "Failed to start transient service unit",
        );
        assert!(matches!(
            h.backups.create("alice").await,
            Err(Error::CommandFailed { .. })
        ));
        assert!(h.backups.list("alice").await?.is_empty());
        assert!(!h.ctx.config.backup_dir.join("alice").exists());
        let jobs = h.ctx.store.list_jobs()?;
        assert_eq!(jobs.len(), 1);
        assert!(jobs.first().is_some_and(
            |j| j.state == JobState::Failed && j.message.contains("could not be started")
        ));
        // Nothing is left "running": the next request starts a new job.
        assert!(h.backups.create("alice").await?.1);
        Ok(())
    }

    #[tokio::test]
    async fn requests_that_cannot_succeed_are_refused_before_anything_is_created() -> Result<()> {
        let h = harness(false).await;
        for bad in ["", "root", "../alice", "alice;id", "Alice"] {
            assert!(
                matches!(h.backups.create(bad).await, Err(Error::InvalidInput { .. })),
                "{bad:?}"
            );
        }
        assert!(matches!(
            h.backups.create("carol").await,
            Err(Error::TenantNotFound(_))
        ));
        assert!(matches!(
            h.backups.list("carol").await,
            Err(Error::TenantNotFound(_))
        ));
        // No archiver on the host: refused, nothing measured or started.
        h.sys.set_missing(bin::TAR);
        assert!(matches!(
            h.backups.create("alice").await,
            Err(Error::RuntimeUnavailable(_))
        ));
        assert!(h.sys.calls().is_empty());
        let fresh = FakeSystem::new();
        fresh.set_missing(bin::GZIP);
        let without_gzip =
            BackupService::new(Ctx::new((*h.ctx.config).clone(), Arc::new(fresh), false));
        assert!(matches!(
            without_gzip.restore("alice", "b1731500000123").await,
            Err(Error::RuntimeUnavailable(_))
        ));
        let h = harness(false).await;
        // Not enough room: the fake home is 8192 bytes, the reserve 1 GiB.
        h.sys.set_disk_free((1 << 30) + 8191);
        match h.backups.create("alice").await {
            Err(Error::BackupNoSpace {
                needed,
                reserve,
                free,
            }) => {
                assert_eq!((needed, reserve, free), (8192, 1 << 30, (1 << 30) + 8191));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(h.sys.calls_to(bin::SYSTEMD_RUN).is_empty());
        assert!(h.ctx.store.list_jobs()?.is_empty());
        assert!(h.ctx.store.list_backups()?.is_empty());
        // Exactly enough: the archive may use what is left above the reserve.
        h.sys.set_disk_free((1 << 30) + 8192);
        let (job, _) = h.backups.create("alice").await?;
        let run = h.sys.calls_to(bin::SYSTEMD_RUN);
        let argv = run.first().map(args).unwrap_or_default();
        assert_eq!(argv.last().map(String::as_str), Some("8192"));
        h.finish(&job).await?;

        for bad in [
            "",
            "b1",
            "j1731500000123",
            "../b1731500000123",
            "b1731500000123/x",
        ] {
            assert!(matches!(
                h.backups.restore("alice", bad).await,
                Err(Error::InvalidInput { .. })
            ));
            assert!(matches!(
                h.backups.delete("alice", bad).await,
                Err(Error::InvalidInput { .. })
            ));
        }
        assert!(matches!(
            h.backups.job("b1731500000123").await,
            Err(Error::InvalidInput { .. })
        ));
        assert!(matches!(
            h.backups.job("j1731500000123").await,
            Err(Error::JobNotFound(_))
        ));
        Ok(())
    }

    /// What a finished restore of alice runs: labels, the web server's ACLs
    /// as ConfigureVirtualHost sets them, PHP again, and the unit cleaned up.
    fn expected_after_restore(home: &str, job: &str) -> Vec<(&'static str, Vec<String>)> {
        let docroot = format!("{home}/public_html");
        vec![
            (
                bin::RESTORECON,
                vec!["-R".into(), "--".into(), home.to_owned()],
            ),
            (bin::MKDIR, vec!["-p".into(), "--".into(), docroot.clone()]),
            (
                bin::SETFACL,
                vec![
                    "--physical".into(),
                    "-m".into(),
                    "u:nginx:--x".into(),
                    "--".into(),
                    home.to_owned(),
                ],
            ),
            (
                bin::SETFACL,
                vec![
                    "--physical".into(),
                    "-m".into(),
                    "u:nginx:r-x".into(),
                    "-d".into(),
                    "-m".into(),
                    "u:nginx:r-x".into(),
                    "--".into(),
                    docroot.clone(),
                ],
            ),
            (
                bin::SEMANAGE,
                vec![
                    "fcontext".into(),
                    "-a".into(),
                    "-N".into(),
                    "-e".into(),
                    "/usr/share/nginx/html".into(),
                    "--".into(),
                    docroot.clone(),
                ],
            ),
            (bin::RESTORECON, vec!["-RF".into(), "--".into(), docroot]),
            (
                bin::SYSTEMCTL,
                vec![
                    "enable".into(),
                    "--now".into(),
                    "--".into(),
                    "oxpanel-php-alice.service".into(),
                ],
            ),
            (
                bin::SYSTEMCTL,
                vec![
                    "stop".into(),
                    "--".into(),
                    format!("oxpanel-job-{job}.service"),
                ],
            ),
        ]
    }

    #[tokio::test]
    async fn restore_verifies_stops_services_and_puts_the_site_back() -> Result<()> {
        let h = harness(true).await;
        let made = h.backup("alice").await?;
        let backup = h.backups.list("alice").await?.remove(0);
        let home_member = backup
            .members
            .iter()
            .find(|m| m.kind == "home")
            .unwrap_or_else(|| panic!("no home member"));
        h.sys.clear_calls();

        let (job, started) = h.backups.restore("alice", &made.backup_id).await?;
        assert!(started);
        assert_eq!((job.kind, job.state), (JobKind::Restore, JobState::Running));
        let home = h.ctx.config.home_base.join("alice");
        let home = home.to_string_lossy();
        // PHP is stopped before the worker starts.
        let calls = h.sys.calls();
        let stop = calls.iter().position(|c| {
            c.program == bin::SYSTEMCTL
                && args(c) == ["disable", "--now", "--", "oxpanel-php-alice.service"]
        });
        let run = calls.iter().position(|c| c.program == bin::SYSTEMD_RUN);
        assert!(stop.is_some() && stop < run, "{stop:?} {run:?}");
        let argv = calls
            .iter()
            .find(|c| c.program == bin::SYSTEMD_RUN)
            .map(args)
            .unwrap_or_default();
        // The home is the only writable path, and files keep their modes.
        assert!(argv.contains(&format!("ReadWritePaths={home}")));
        assert!(argv.contains(&"UMask=0022".to_owned()));
        assert!(argv.contains(&"RestrictSUIDSGID=yes".to_owned()));
        assert!(
            argv.contains(&"CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_SETPCAP".to_owned())
        );
        assert!(argv.contains(&"Slice=oxpanel-tenant-alice.slice".to_owned()));
        let tail: Vec<&str> = argv
            .iter()
            .skip_while(|a| *a != "--")
            .map(String::as_str)
            .collect();
        let input = h.dir(&made).join("home.tar.gz");
        assert_eq!(
            tail,
            vec![
                "--",
                "/usr/sbin/oxpanel-daemon",
                "worker",
                "restore",
                "20000",
                "--gid",
                "20000",
                "--home",
                &home,
                "--input",
                &input.to_string_lossy(),
                "--sha256",
                &home_member.sha256,
                "--size",
                &home_member.size_bytes.to_string(),
            ]
        );
        // One job per tenant; the same request returns the same job.
        assert!(matches!(
            h.backups.create("alice").await,
            Err(Error::JobRunning { .. })
        ));
        assert!(!h.backups.restore("alice", &made.backup_id).await?.1);
        assert!(matches!(
            h.backups.delete("alice", &made.backup_id).await,
            Err(Error::JobRunning { .. })
        ));

        h.sys.clear_calls();
        let done = h.finish(&job).await?;
        assert_eq!(done.state, JobState::Succeeded);
        assert_eq!(
            done.message,
            format!("restored from backup {}", made.backup_id)
        );
        // Afterwards: labels, the web server's ACLs as ConfigureVirtualHost
        // sets them, and PHP running again.
        let after: Vec<(&str, Vec<String>)> = h
            .sys
            .calls()
            .iter()
            .filter(|c| c.program != bin::SYSTEMCTL || args(c).first().is_none_or(|a| a != "show"))
            .filter(|c| c.program != bin::JOURNALCTL)
            .map(|c| (c.program, args(c)))
            .collect();
        let expected = expected_after_restore(&home, &job.id);
        assert_eq!(after, expected);
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_restore_still_puts_the_site_back_and_says_why() -> Result<()> {
        let h = harness(false).await;
        let made = h.backup("alice").await?;
        // Damaged archive.
        let (job, _) = h.backups.restore("alice", &made.backup_id).await?;
        h.sys
            .script_stdout(bin::SYSTEMCTL, &failed("exit-code", worker::EXIT_INTEGRITY));
        h.sys.clear_calls();
        let done = h.finish(&job).await?;
        assert_eq!(done.state, JobState::Failed);
        assert!(done.message.contains("damaged") && done.message.contains("nothing was restored"));
        assert!(h
            .sys
            .calls_to(bin::SYSTEMCTL)
            .iter()
            .any(|c| args(c) == ["enable", "--now", "--", "oxpanel-php-alice.service"]));
        // The host restarted in the middle.
        let (job, _) = h.backups.restore("alice", &made.backup_id).await?;
        h.sys.script_stdout(bin::SYSTEMCTL, GONE);
        let done = h.finish(&job).await?;
        assert_eq!(done.state, JobState::Failed);
        assert!(done.message.contains("repeat the restore"));
        // A hostile archive: tar refused members.
        let (job, _) = h.backups.restore("alice", &made.backup_id).await?;
        h.sys
            .script_stdout(bin::SYSTEMCTL, &failed("exit-code", worker::EXIT_ARCHIVER));
        assert!(h
            .finish(&job)
            .await?
            .message
            .contains("refused or failed to restore some members"));
        // The worker could not be started: services come back at once.
        h.sys.script_failure(bin::SYSTEMD_RUN, 1, "nope");
        h.sys.clear_calls();
        assert!(h.backups.restore("alice", &made.backup_id).await.is_err());
        let verbs: Vec<String> = h
            .sys
            .calls_to(bin::SYSTEMCTL)
            .iter()
            .filter_map(|c| args(c).first().cloned())
            .collect();
        assert_eq!(verbs, vec!["disable", "enable"]);
        assert!(h
            .ctx
            .store
            .list_jobs()?
            .iter()
            .all(|j| j.state != JobState::Running));
        // The backup itself is untouched by all of this.
        assert_eq!(h.backups.list("alice").await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_suspended_tenant_can_be_backed_up_and_restored_but_stays_stopped() -> Result<()> {
        let h = harness(false).await;
        h.tenants.set_suspended("alice", true).await?;
        let made = h.backup("alice").await?;
        assert_eq!(made.state, JobState::Succeeded);
        h.sys.clear_calls();
        let (job, _) = h.backups.restore("alice", &made.backup_id).await?;
        assert_eq!(h.finish(&job).await?.state, JobState::Succeeded);
        let touched_php = h
            .sys
            .calls_to(bin::SYSTEMCTL)
            .iter()
            .any(|c| args(c).iter().any(|a| a == "oxpanel-php-alice.service"));
        assert!(
            !touched_php,
            "a suspended tenant's PHP is neither stopped nor started"
        );
        Ok(())
    }

    #[tokio::test]
    async fn one_tenants_backup_cannot_be_restored_or_deleted_through_another() -> Result<()> {
        let h = harness(false).await;
        let made = h.backup("alice").await?;
        h.sys.clear_calls();
        assert!(matches!(
            h.backups.restore("bob", &made.backup_id).await,
            Err(Error::BackupNotFound { .. })
        ));
        assert!(!h.backups.delete("bob", &made.backup_id).await?);
        assert!(h.sys.calls().is_empty(), "nothing ran");
        assert!(h.backups.list("bob").await?.is_empty());
        assert_eq!(h.backups.list("alice").await?.len(), 1);
        assert!(h.dir(&made).join(MANIFEST).is_file());
        // A record that claims another uid (a recreated account) is refused too.
        let id = BackupId::parse(&made.backup_id)?;
        let mut rec = h
            .ctx
            .store
            .load_backup(&id)?
            .unwrap_or_else(|| panic!("record"));
        rec.uid = 29999;
        h.ctx.store.save_backup(&rec)?;
        assert!(matches!(
            h.backups.restore("alice", &made.backup_id).await,
            Err(Error::Internal(_))
        ));
        assert!(h.sys.calls_to(bin::SYSTEMD_RUN).is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn retention_keeps_the_newest_backups_and_delete_is_idempotent() -> Result<()> {
        let h = harness(false).await;
        let mut made = Vec::new();
        for _ in 0..4 {
            made.push(h.backup("alice").await?);
        }
        let kept: Vec<String> = h
            .backups
            .list("alice")
            .await?
            .into_iter()
            .map(|b| b.id)
            .collect();
        let newest: Vec<String> = made.iter().skip(2).map(|j| j.backup_id.clone()).collect();
        assert_eq!(kept, newest, "keep = 2: the two newest remain");
        for old in made.iter().take(2) {
            assert!(!h.dir(old).exists());
        }
        // bob's backups are counted separately.
        h.backup("bob").await?;
        assert_eq!(h.backups.list("alice").await?.len(), 2);

        let id = newest.first().cloned().unwrap_or_default();
        assert!(h.backups.delete("alice", &id).await?);
        assert!(!h.backups.delete("alice", &id).await?);
        assert!(!h.ctx.config.backup_dir.join("alice").join(&id).exists());
        assert_eq!(h.backups.list("alice").await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn jobs_are_limited_per_host_resumed_after_a_restart_and_pruned() -> Result<()> {
        let h = harness(false).await;
        for extra in ["carol", "dave", "erin"] {
            h.tenants.create(extra, Limits::default(), "").await?;
        }
        let mut jobs = Vec::new();
        for tenant in ["alice", "bob", "carol", "dave"] {
            jobs.push(h.backups.create(tenant).await?.0);
        }
        assert!(matches!(
            h.backups.create("erin").await,
            Err(Error::TooManyJobs)
        ));
        // A new daemon (same state on disk) finds the four and finishes them.
        let restarted =
            BackupService::new(h.ctx.clone()).with_poll_interval(Duration::from_millis(5));
        assert_eq!(restarted.resume_all().await?, 4);
        for _ in 0..400 {
            if h.ctx
                .store
                .list_jobs()?
                .iter()
                .all(|j| j.state != JobState::Running)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        for job in &jobs {
            assert_eq!(h.backups.job(&job.id).await?.state, JobState::Succeeded);
        }
        assert_eq!(restarted.resume_all().await?, 0);
        assert!(h.backups.create("erin").await?.1);

        // History is bounded per tenant.
        for _ in 0..JOBS_KEPT_PER_TENANT + 3 {
            h.backup("alice").await?;
        }
        let history = h
            .ctx
            .store
            .list_jobs()?
            .iter()
            .filter(|j| j.tenant == "alice")
            .count();
        assert_eq!(history, JOBS_KEPT_PER_TENANT);
        Ok(())
    }

    #[tokio::test]
    async fn a_tenant_with_backups_or_a_running_job_cannot_be_deleted() -> Result<()> {
        let h = harness(false).await;
        let (job, _) = h.backups.create("bob").await?;
        assert!(matches!(
            h.tenants.delete("bob", true).await,
            Err(Error::JobRunning { .. })
        ));
        h.finish(&job).await?;
        assert!(matches!(
            h.tenants.delete("bob", true).await,
            Err(Error::TenantHasBackups(_))
        ));
        assert!(h.sys.calls_to(bin::USERDEL).is_empty());
        assert!(h.backups.delete("bob", &job.backup_id).await?);
        assert!(h.tenants.delete("bob", true).await?);
        assert!(
            h.ctx.store.list_jobs()?.iter().all(|j| j.tenant != "bob"),
            "the job history goes with the tenant"
        );
        Ok(())
    }

    #[test]
    fn long_output_keeps_its_end() {
        let text = format!("{}\nlast line\n", "é".repeat(OUTPUT_MAX_BYTES));
        let kept = tail(&text);
        assert!(kept.len() <= OUTPUT_MAX_BYTES && kept.ends_with("last line"));
        assert_eq!(tail("  short \n"), "short");
    }
}
