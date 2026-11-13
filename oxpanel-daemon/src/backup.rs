//! Per-tenant backups and restores, as jobs.
//!
//! A backup is a directory `<backup_dir>/<tenant>/<backup id>/`, root-only,
//! outside every tenant's reach. It holds *members* and a manifest:
//!
//! - `home.tar.gz` (kind `home`) — the tenant's home without what can be
//!   rebuilt ([`EXCLUDE_RULES`]), written by `tar` running as the tenant;
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
//! node_modules and virtualenvs are left out (and listed); a restore needs an
//! explicit choice for existing files, stops PHP and applications while it
//! runs and rebuilds the applications' dependencies afterwards; a tenant
//! with backups that are not retained cannot be deleted; one job per tenant
//! at a time.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::ctx::Ctx;
use crate::db::mariadb::{self, Schema};
use crate::db::objects;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::nginx::safe_path_str;
use crate::records::{
    now_unix, AppRuntime, BackupDatabase, BackupMember, BackupRecord, BackupState, DatabaseRecord,
    DbObjectDef, DbState, JobKind, JobRecord, JobState, OnExisting, SiteResult, TenantRecord,
    TenantState, VHostRecord, RECORD_VERSION,
};
use crate::system::{bin, CommandSpec};
use crate::validate::{retention, BackupId, DbName, JobId, Username};
use crate::vhost::VHostService;
use crate::worker::{self, Task};

/// Version of the on-disk layout described in the module documentation.
pub const MANIFEST_FORMAT: u32 = 1;
pub const MANIFEST: &str = "manifest.json";
pub const HOME_MEMBER: &str = "home.tar.gz";
pub const RECORDS_MEMBER: &str = "records.json";
const KIND_RECORDS: &str = "records";
/// Member kind of a database's triggers, routines and events (JSON).
pub const KIND_MARIADB_OBJECTS: &str = "mariadb-objects";

/// `db-<name>.objects.json`: the stored objects of a database in a backup.
pub fn objects_member(database: &str) -> String {
    format!("db-{database}.objects.json")
}

/// What an objects member holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectsMember {
    pub database: String,
    pub objects: Vec<DbObjectDef>,
}
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
/// How often retention dates are checked.
const EXPIRY_INTERVAL: Duration = Duration::from_secs(3600);
/// Consecutive faults after which a driver stops looking at its job.
const MAX_DRIVER_FAULTS: u32 = 30;

/// What the home archive always leaves out (owner decision: large, and
/// rebuilt after a restore), in words, for the manifest and the API. The
/// options that implement them are in [`worker::tar_create`].
pub const EXCLUDE_RULES: [&str; 5] = [
    "./.cache (download caches)",
    "./.npm (npm cache)",
    "node_modules, at any depth",
    "every directory that contains a pyvenv.cfg (Python virtualenvs)",
    "<application root>/.venv of every Python application",
];
/// Excluded directories named in a record and the manifest; the count is
/// always complete.
pub const EXCLUDED_LISTED: usize = 200;

/// What `manifest.json` holds. The exclusion fields were added within format
/// 1 (readers must tolerate fields they do not know).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub id: String,
    pub tenant: String,
    pub created_at_unix: u64,
    pub engine_version: String,
    pub members: Vec<BackupMember>,
    /// What the home archive leaves out, by rule.
    pub exclude_rules: Vec<String>,
    /// The directories that rule matched when the backup was started
    /// (relative to the home; "." is the home itself), at most
    /// [`EXCLUDED_LISTED`], and how many there were.
    pub excluded: Vec<String>,
    pub excluded_count: u64,
    /// The databases in the backup (added within format 1).
    #[serde(default)]
    pub databases: Vec<BackupDatabase>,
}

/// The `.venv` of every Python application of the tenant, relative to its
/// home: left out of the archive by path, besides by their `pyvenv.cfg`.
pub fn app_venvs(tenant: &str, vhosts: &[VHostRecord]) -> Vec<String> {
    vhosts
        .iter()
        .filter(|v| v.tenant == tenant)
        .filter_map(|v| v.app.as_ref())
        .filter(|a| a.runtime == AppRuntime::Python)
        .map(|a| format!("{}/.venv", a.root))
        .collect()
}

/// Turn the pre-scan's NUL-separated output into the excluded directories,
/// relative to `home`: deduplicated, without those inside another excluded
/// one, sorted. ("." — a `pyvenv.cfg` in the home itself — swallows all.)
pub fn excluded_dirs(home: &str, scan: &[u8]) -> Vec<String> {
    let prefix = format!("{home}/");
    let mut dirs: Vec<String> = scan
        .split(|b| *b == 0)
        .filter(|e| !e.is_empty())
        .map(|e| String::from_utf8_lossy(e).into_owned())
        .map(|e| {
            if e == home {
                ".".to_owned()
            } else {
                e.strip_prefix(&prefix)
                    .map_or_else(|| e.clone(), str::to_owned)
            }
        })
        .collect();
    dirs.sort();
    dirs.dedup();
    if dirs.iter().any(|d| d == ".") {
        return vec![".".to_owned()];
    }
    let mut out: Vec<String> = Vec::new();
    for d in dirs {
        // Sorted: an enclosing directory comes before what it contains.
        if !out.iter().any(|o| d.starts_with(&format!("{o}/"))) {
            out.push(d);
        }
    }
    out
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
        exclude_rules: EXCLUDE_RULES.iter().map(|r| (*r).to_owned()).collect(),
        excluded: rec.excluded.clone(),
        excluded_count: rec.excluded_count,
        databases: rec.databases.clone(),
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
            JobKind::Restore => {
                "the archiver refused or failed to restore some members; the others were restored (see output)".to_owned()
            }
            _ => "the archiver could not read the home directory".to_owned(),
        },
        (_, Some(worker::EXIT_DUMP)) => {
            "a database dump failed, so the backup is incomplete and was removed (see output)".to_owned()
        }
        (_, Some(worker::EXIT_LOAD)) => {
            "the dump could not be loaded into the new database, which was removed again (see output)".to_owned()
        }
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

/// What [`BackupService::measure`] found.
struct Measured {
    needed: u64,
    excluded: Vec<String>,
    excluded_count: u64,
}

/// The tenant's databases a backup includes: every ready one (the trash is
/// not backed up).
fn tenant_databases(ctx: &Ctx, tenant: &Username) -> Result<Vec<DatabaseRecord>> {
    let mut dbs = ctx.store.list_databases()?;
    dbs.retain(|d| d.tenant == tenant.as_str() && d.state == DbState::Ready);
    Ok(dbs)
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
    fn job_in_flight(
        &self,
        tenant: &Username,
        except: Option<&JobId>,
    ) -> Result<Option<JobRecord>> {
        let running = self.running_jobs()?;
        if let Some(job) = running
            .iter()
            .find(|j| j.tenant == tenant.as_str() && except.is_none_or(|e| e.as_str() != j.id))
        {
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

    /// What a backup of the home will leave out, and the space the rest
    /// occupies. Both are measured as the tenant (nothing is looked at that
    /// the tenant could not look at, no symlink is followed), on one file
    /// system like the archiver. Sparse files count for what they occupy,
    /// which is also what `tar --sparse` stores.
    async fn measure(&self, tenant: &TenantRecord, venvs: &[String]) -> Result<Measured> {
        let home = safe_path_str(&tenant.home)?;
        // Mirrors `worker::tar_create`: caches pruned silently; node_modules
        // and the applications' .venv printed relative to the home;
        // directories holding a pyvenv.cfg printed absolute.
        let mut find = CommandSpec::new(bin::FIND, MEASURE_TIMEOUT)
            .arg(&tenant.home)
            .args(["-xdev", "(", "-path"])
            .arg(format!("{home}/.cache"))
            .args(["-o", "-path"])
            .arg(format!("{home}/.npm"))
            .args([")", "-prune", "-o", "(", "-name", "node_modules"]);
        for v in venvs {
            find = find.args(["-o", "-path"]).arg(format!("{home}/{v}"));
        }
        let find = find.args([
            ")",
            "-prune",
            "-printf",
            "%P\\0",
            "-o",
            "-name",
            "pyvenv.cfg",
            "-printf",
            "%h\\0",
        ]);
        // A non-zero status only means some directory was unreadable.
        let scan = self
            .ctx
            .sys
            .run(find.as_user(tenant.uid, tenant.gid))
            .await?;
        let all = excluded_dirs(home, &scan.stdout);
        let excluded_count = all.len() as u64;
        let excluded: Vec<String> = all.into_iter().take(EXCLUDED_LISTED).collect();

        let mut du = CommandSpec::new(bin::DU, MEASURE_TIMEOUT)
            .args(["--summarize", "--one-file-system", "--block-size=1"])
            .arg("--exclude=node_modules")
            .arg(format!("--exclude={home}/.cache"))
            .arg(format!("--exclude={home}/.npm"));
        // du takes these as patterns: a name with pattern characters is
        // simply counted (the estimate errs on the large side).
        for d in excluded
            .iter()
            .filter(|d| *d != "." && !d.contains(['*', '?', '[', '\\']))
        {
            du = du.arg(format!("--exclude={home}/{d}"));
        }
        let out = self
            .ctx
            .sys
            .run(
                du.arg("--")
                    .arg(&tenant.home)
                    .as_user(tenant.uid, tenant.gid),
            )
            .await?;
        // As above: the total of what could be read is still printed.
        let needed = out
            .stdout_lossy()
            .lines()
            .last()
            .and_then(|l| l.split_whitespace().next())
            .and_then(|n| n.parse::<u64>().ok())
            .ok_or_else(|| {
                Error::Internal(format!("unexpected du output for '{}'", tenant.username))
            })?;
        Ok(Measured {
            needed,
            excluded,
            excluded_count,
        })
    }

    /// How large an archive may grow: refused before anything is created
    /// unless `needed` fits and the reserve survives it.
    async fn room_for(&self, needed: u64) -> Result<u64> {
        let cfg = &self.ctx.config;
        fsutil::ensure_dir(&cfg.backup_dir, DIR_MODE)?;
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
        // The archive may not grow into the reserve even if the home does.
        Ok(free - reserve)
    }

    /// The `systemd-run` invocation for a job: the worker in the tenant's
    /// slice, at the lowest priority, able to write `writable` and nothing else.
    fn job_command(
        &self,
        job: &JobRecord,
        tenant: &TenantRecord,
        writable: Option<&Path>,
        task: &Task,
    ) -> Result<CommandSpec> {
        let cfg = &self.ctx.config;
        let writable = writable.map(safe_path_str).transpose()?;
        let exe = safe_path_str(&cfg.worker_exe)?;
        // Restored files keep their archived modes; archives are root-only.
        let umask = match job.kind {
            JobKind::Restore => "0022",
            _ => "0077",
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
            // A database restore writes no file at all.
            writable.map_or_else(
                || "ReadOnlyPaths=/".to_owned(),
                |w| format!("ReadWritePaths={w}"),
            ),
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

    /// Start a backup of `tenant`: its home and every ready database. With a
    /// retention (`retain_months` 1–12 or `retain_days` 1–366; 0 and 0 =
    /// none) it is kept that long whatever the per-tenant count says, also
    /// after the tenant is deleted. Returns the job and whether it was
    /// started now (`false`: a backup of this tenant was already running).
    pub async fn create(
        &self,
        tenant: &str,
        retain_months: u32,
        retain_days: u32,
    ) -> Result<(JobRecord, bool)> {
        let name = Username::parse_field(tenant, "tenant")?;
        let period = retention(retain_months, retain_days)?;
        self.create_job(&name, period, None).await
    }

    /// A backup kept for `retain_secs` (0 = an ordinary one), started by the
    /// job `parent` if any (a tenant deletion's final backup: that job is
    /// the tenant's job in flight and does not block this one).
    pub(crate) async fn create_job(
        &self,
        name: &Username,
        retain_secs: u64,
        parent: Option<&JobId>,
    ) -> Result<(JobRecord, bool)> {
        let retain_until_unix = match retain_secs {
            0 => 0,
            s => now_unix().saturating_add(s),
        };
        self.archiver_available().await?;
        // Measured before the lock is taken: it can take a while.
        let venvs = app_venvs(name.as_str(), &self.ctx.store.list_vhosts()?);
        let mut measured = self.measure(&self.ready_tenant(name)?, &venvs).await?;
        let databases = tenant_databases(&self.ctx, name)?;
        let sizes = self.database_sizes(&databases).await?;
        measured.needed = measured
            .needed
            .saturating_add(sizes.values().copied().sum::<u64>());

        let guard = self.ctx.lock.lock().await;
        let tenant_rec = self.ready_tenant(name)?;
        if let Some(job) = self.job_in_flight(name, parent)? {
            return match job.kind {
                JobKind::Backup => Ok((job, false)),
                _ => Err(Error::JobRunning {
                    tenant: name.to_string(),
                    job: job.id,
                }),
            };
        }
        let room = self.room_for(measured.needed).await?;
        // Under the lock, so that the list cannot change before the job starts.
        let databases = tenant_databases(&self.ctx, name)?;
        let captured = self.capture_objects(&databases).await?;

        let (id, job_id) = self.new_ids()?;
        let dir = backup_path(&self.ctx.config.backup_dir, name, &id);
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
            retain_until_unix,
            tenant_deleted: false,
            excluded: measured.excluded,
            excluded_count: measured.excluded_count,
            databases: databases
                .iter()
                .map(|d| BackupDatabase {
                    name: d.name.clone(),
                    engine: d.engine,
                    size_bytes: sizes.get(&d.name).copied().unwrap_or(0),
                    dump_member: worker::dump_member(&d.name),
                    objects_member: objects_member(&d.name),
                })
                .collect(),
        };
        let mut job = JobRecord::start(
            &job_id,
            JobKind::Backup,
            name.as_str(),
            id.as_str(),
            unit_name(&job_id),
        );
        job.started_at_unix = backup.created_at_unix;
        job.parent_job = parent.map(ToString::to_string).unwrap_or_default();
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
            max_bytes: room,
            venvs,
            databases: databases.iter().map(|d| d.name.clone()).collect(),
            socket: self.ctx.config.mariadb_socket.clone(),
        };
        let started = self
            .prepare_backup_dir(name, &dir, &tenant_rec, &vhosts, &captured)
            .and_then(|()| self.job_command(&job, &tenant_rec, Some(&dir), &task));
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
        info!(job = %job.id, backup = %id, tenant = %name, databases = backup.databases.len(), "backup started");
        self.spawn_driver(job_id);
        Ok((job, true))
    }

    /// The size of each database on the server; MariaDB must be usable when
    /// there are databases to back up (refused before anything is created).
    async fn database_sizes(
        &self,
        databases: &[DatabaseRecord],
    ) -> Result<std::collections::BTreeMap<String, u64>> {
        if databases.is_empty() {
            return Ok(std::collections::BTreeMap::new());
        }
        mariadb::snapshot(&self.ctx).await?;
        let names: Vec<DbName> = databases
            .iter()
            .map(|d| DbName::parse(&d.name, "name"))
            .collect::<Result<_>>()?;
        mariadb::sizes(&self.ctx, &names).await
    }

    /// The triggers, routines and events of each database, as text: they
    /// are not taken from the dump (see `db::objects`).
    async fn capture_objects(&self, databases: &[DatabaseRecord]) -> Result<Vec<ObjectsMember>> {
        let mut out = Vec::with_capacity(databases.len());
        for d in databases {
            let schema = Schema::of_db(&DbName::parse(&d.name, "name")?);
            let listed = mariadb::objects(&self.ctx, &schema).await?;
            out.push(ObjectsMember {
                database: d.name.clone(),
                objects: objects::capture(&self.ctx, &schema, &listed, false).await?,
            });
        }
        Ok(out)
    }

    /// The backup's directory with its `records` member and the objects
    /// member of every database in place.
    fn prepare_backup_dir(
        &self,
        name: &Username,
        dir: &Path,
        tenant: &TenantRecord,
        vhosts: &[VHostRecord],
        objects: &[ObjectsMember],
    ) -> Result<()> {
        fsutil::ensure_dir(&tenant_dir(&self.ctx.config.backup_dir, name), DIR_MODE)?;
        fsutil::ensure_dir(dir, DIR_MODE)?;
        let mut bytes = serde_json::to_vec_pretty(&RecordsMember { tenant, vhosts })
            .map_err(|e| Error::Internal(format!("serialise records member: {e}")))?;
        bytes.push(b'\n');
        fsutil::write_atomic(&dir.join(RECORDS_MEMBER), &bytes, FILE_MODE)?;
        for member in objects {
            let mut bytes = serde_json::to_vec_pretty(member)
                .map_err(|e| Error::Internal(format!("serialise objects member: {e}")))?;
            bytes.push(b'\n');
            fsutil::write_atomic(
                &dir.join(objects_member(&member.database)),
                &bytes,
                FILE_MODE,
            )?;
        }
        Ok(())
    }
    /// Start restoring `tenant` from its backup `backup_id`. Returns the job
    /// and whether it was started now.
    pub async fn restore(
        &self,
        tenant: &str,
        backup_id: &str,
        on_existing: OnExisting,
    ) -> Result<(JobRecord, bool)> {
        let name = Username::parse_field(tenant, "tenant")?;
        let id = BackupId::parse(backup_id)?;
        self.archiver_available().await?;
        let guard = self.ctx.lock.lock().await;
        let tenant_rec = self.ready_tenant(&name)?;
        // The backup is looked up *for this tenant*: someone else's backup
        // (and a retained backup of a deleted namesake) does not exist here,
        // whatever its identifier.
        let backup = self.backup_of(&name, &id)?;
        if backup.uid != tenant_rec.uid {
            return Err(Error::Internal(format!(
                "backup {id} was taken from uid {}, but tenant '{name}' is uid {}",
                backup.uid, tenant_rec.uid
            )));
        }
        let started = self
            .start_restore(&tenant_rec, &backup, on_existing)
            .await?;
        drop(guard);
        Ok(started)
    }

    /// The operator's restore of a retained backup of a *deleted* tenant
    /// into an existing tenant (typically the customer's re-created
    /// account). The caller proves intent by naming the backup, the tenant
    /// it was taken from, and the target; anything else is `NOT_FOUND`.
    pub async fn restore_retained(
        &self,
        backup_id: &str,
        source_tenant: &str,
        target_tenant: &str,
        on_existing: OnExisting,
    ) -> Result<(JobRecord, bool)> {
        let id = BackupId::parse(backup_id)?;
        let source = Username::parse_field(source_tenant, "source_tenant")?;
        let target = Username::parse_field(target_tenant, "target_tenant")?;
        self.archiver_available().await?;
        let guard = self.ctx.lock.lock().await;
        let backup = self.retained_of_deleted(&source, &id)?;
        let tenant_rec = self.ready_tenant(&target)?;
        let started = self
            .start_restore(&tenant_rec, &backup, on_existing)
            .await?;
        drop(guard);
        Ok(started)
    }

    /// Restore database `database` of the tenant's backup `backup_id` as
    /// `new_name`, a free name of the same tenant — never over an existing
    /// database. Files are restored separately. Returns the job and whether
    /// it was started now.
    pub async fn restore_database(
        &self,
        tenant: &str,
        backup_id: &str,
        database: &str,
        new_name: &str,
    ) -> Result<(JobRecord, bool)> {
        let name = Username::parse_field(tenant, "tenant")?;
        let id = BackupId::parse(backup_id)?;
        let database = DbName::parse(database, "database")?;
        let new_name = DbName::parse_for(new_name, &name, "new_name")?;
        let guard = self.ctx.lock.lock().await;
        let tenant_rec = self.ready_tenant(&name)?;
        let backup = self.backup_of(&name, &id)?;
        let started = self
            .start_restore_db(&tenant_rec, &backup, &database, &new_name)
            .await?;
        drop(guard);
        Ok(started)
    }

    /// The operator's restore of a database from a retained backup of a
    /// deleted tenant into an existing tenant, under a new name of that
    /// tenant. Same proof of intent as [`Self::restore_retained`].
    pub async fn restore_retained_database(
        &self,
        backup_id: &str,
        source_tenant: &str,
        target_tenant: &str,
        database: &str,
        new_name: &str,
    ) -> Result<(JobRecord, bool)> {
        let id = BackupId::parse(backup_id)?;
        let source = Username::parse_field(source_tenant, "source_tenant")?;
        let target = Username::parse_field(target_tenant, "target_tenant")?;
        let database = DbName::parse(database, "database")?;
        let new_name = DbName::parse_for(new_name, &target, "new_name")?;
        let guard = self.ctx.lock.lock().await;
        let backup = self.retained_of_deleted(&source, &id)?;
        let tenant_rec = self.ready_tenant(&target)?;
        let started = self
            .start_restore_db(&tenant_rec, &backup, &database, &new_name)
            .await?;
        drop(guard);
        Ok(started)
    }

    /// The common half of both database restores. The caller holds the
    /// mutation lock and has checked that `backup` may go into `tenant_rec`.
    async fn start_restore_db(
        &self,
        tenant_rec: &TenantRecord,
        backup: &BackupRecord,
        database: &DbName,
        new_name: &DbName,
    ) -> Result<(JobRecord, bool)> {
        let name = Username::parse_field(&tenant_rec.username, "tenant")?;
        let id = BackupId::parse(&backup.id)?;
        if backup.state != BackupState::Ready {
            return Err(Error::BackupNotReady(id.to_string()));
        }
        let entry = backup
            .databases
            .iter()
            .find(|d| d.name == database.as_str())
            .ok_or_else(|| {
                Error::invalid(
                    "database",
                    format!("backup {id} holds no database '{database}'"),
                )
            })?;
        if let Some(job) = self.job_in_flight(&name, None)? {
            let same = job.kind == JobKind::RestoreDatabase
                && job.backup_id == backup.id
                && job.database == database.as_str()
                && job.new_name == new_name.as_str();
            return if same {
                Ok((job, false))
            } else {
                Err(Error::JobRunning {
                    tenant: name.to_string(),
                    job: job.id,
                })
            };
        }
        let dump = backup
            .members
            .iter()
            .find(|m| m.name == entry.dump_member)
            .ok_or_else(|| {
                Error::Internal(format!("backup {id} lacks member {}", entry.dump_member))
            })?;
        // Refused before anything is recorded: MariaDB unusable, the name taken.
        let server = mariadb::snapshot(&self.ctx).await?;
        crate::db::trash::claimable(&self.ctx, &server, &name, new_name)?;
        let source = Username::parse_field(&backup.tenant, "tenant")?;
        let (_, job_id) = self.new_ids()?;
        let mut job = JobRecord::start(
            &job_id,
            JobKind::RestoreDatabase,
            name.as_str(),
            id.as_str(),
            unit_name(&job_id),
        );
        job.database = database.to_string();
        job.new_name = new_name.to_string();
        let task = Task::RestoreDb {
            input: backup_path(&self.ctx.config.backup_dir, &source, &id).join(&dump.name),
            sha256: dump.sha256.clone(),
            size: dump.size_bytes,
            socket: self.ctx.config.mariadb_socket.clone(),
            database: new_name.to_string(),
        };
        let cmd = self.job_command(&job, tenant_rec, None, &task)?;
        // The name is claimed, then created empty; the worker fills it.
        self.ctx.store.save_database(&DatabaseRecord {
            version: RECORD_VERSION,
            name: new_name.to_string(),
            tenant: name.to_string(),
            engine: entry.engine,
            created_at_unix: now_unix(),
            state: DbState::Provisioning,
        })?;
        self.ctx.store.save_job(&job)?;
        let created = mariadb::run_hardened(
            &self.ctx,
            crate::db::mariadb::content::create_schema(&Schema::of_db(new_name)),
        )
        .await;
        let started = match created {
            Ok(_) => self.ctx.sys.run_ok(cmd).await.map(|_| ()),
            Err(e) => Err(e),
        };
        if let Err(e) = started {
            error!(job = %job.id, tenant = %name, error = %e, "database restore could not be started");
            self.conclude_restore_db(job, Err("the job could not be started".to_owned()), "")
                .await?;
            return Err(e);
        }
        info!(job = %job.id, backup = %id, %database, %new_name, tenant = %name, "database restore started");
        self.spawn_driver(job_id);
        Ok((job, true))
    }

    /// Record the end of a database restore: the stored objects re-created
    /// and the database ready, or the half-loaded database dropped again.
    /// The caller holds the mutation lock.
    async fn conclude_restore_db(
        &self,
        mut job: JobRecord,
        outcome: std::result::Result<(), String>,
        output: &str,
    ) -> Result<JobRecord> {
        let tenant = Username::parse_field(&job.tenant, "tenant")?;
        let new_name = DbName::parse_for(&job.new_name, &tenant, "new_name")?;
        let finished = match outcome {
            Ok(()) => self.finish_db_restore(&job, &tenant, &new_name).await,
            Err(reason) => Err(reason),
        };
        match finished {
            Ok(issues) => {
                if let Some(mut rec) = self.ctx.store.load_database(&new_name)? {
                    rec.state = DbState::Ready;
                    self.ctx.store.save_database(&rec)?;
                }
                let message = format!(
                    "database {} of backup {} restored as {new_name}{}; it has no grants yet",
                    job.database,
                    job.backup_id,
                    if issues.is_empty() {
                        String::new()
                    } else {
                        format!(
                            " ({} stored objects were not re-created, see object_issues)",
                            issues.len()
                        )
                    }
                );
                job.object_issues = issues;
                info!(job = %job.id, tenant = %tenant, database = %new_name, "database restore complete");
                self.finish_job(job, JobState::Succeeded, message, output)
            }
            Err(reason) => {
                warn!(job = %job.id, tenant = %tenant, database = %new_name, %reason, "database restore failed; removing the new database");
                let dropped = mariadb::run_hardened(
                    &self.ctx,
                    crate::db::mariadb::content::drop_schema(&Schema::of_db(&new_name)),
                )
                .await;
                let reason = match dropped {
                    Ok(_) => {
                        self.ctx.store.delete_database(&new_name)?;
                        reason
                    }
                    Err(e) => {
                        error!(job = %job.id, database = %new_name, error = %e, "the half-restored database could not be dropped; DeleteDatabase removes it");
                        format!("{reason}; the half-restored database {new_name} could not be removed (DeleteDatabase removes it)")
                    }
                };
                self.finish_job(job, JobState::Failed, reason, output)
            }
        }
    }

    /// After the worker loaded the dump: the objects member verified and
    /// replayed (guarded), and anything with a foreign definer dropped.
    async fn finish_db_restore(
        &self,
        job: &JobRecord,
        tenant: &Username,
        new_name: &DbName,
    ) -> std::result::Result<Vec<crate::records::ObjectIssue>, String> {
        let fail = |e: Error| format!("the stored objects could not be restored: {e}");
        let id = BackupId::parse(&job.backup_id).map_err(fail)?;
        let backup = self
            .ctx
            .store
            .load_backup(&id)
            .map_err(fail)?
            .ok_or_else(|| "the backup's record is gone".to_owned())?;
        let entry = backup
            .databases
            .iter()
            .find(|d| d.name == job.database)
            .ok_or_else(|| "the database is no longer listed in the backup".to_owned())?;
        let member = backup
            .members
            .iter()
            .find(|m| m.name == entry.objects_member)
            .ok_or_else(|| "the backup lacks the database's objects member".to_owned())?;
        let source = Username::parse_field(&backup.tenant, "tenant").map_err(fail)?;
        let path = backup_path(&self.ctx.config.backup_dir, &source, &id).join(&member.name);
        let (size, sha256) = worker::hash_file(&path).map_err(fail)?;
        if size != member.size_bytes || sha256 != member.sha256 {
            return Err(format!(
                "member {} is damaged (size or checksum differs from the record)",
                member.name
            ));
        }
        let bytes = std::fs::read(&path).map_err(|e| fail(Error::io("read", &path, e)))?;
        let objects_member: ObjectsMember = serde_json::from_slice(&bytes)
            .map_err(|e| format!("member {} cannot be read: {e}", member.name))?;
        let schema = Schema::of_db(new_name);
        let mut issues = objects::recreate(&self.ctx, &schema, tenant, &objects_member.objects)
            .await
            .map_err(fail)?;
        issues.extend(
            objects::drop_foreign(&self.ctx, &schema, tenant)
                .await
                .map_err(fail)?,
        );
        Ok(issues)
    }

    /// The common half of both restores: `backup` into `tenant_rec`'s home,
    /// as that tenant. The caller holds the mutation lock and has checked
    /// that this backup may go into this tenant.
    async fn start_restore(
        &self,
        tenant_rec: &TenantRecord,
        backup: &BackupRecord,
        on_existing: OnExisting,
    ) -> Result<(JobRecord, bool)> {
        let name = Username::parse_field(&tenant_rec.username, "tenant")?;
        let id = BackupId::parse(&backup.id)?;
        if backup.state != BackupState::Ready {
            return Err(Error::BackupNotReady(id.to_string()));
        }
        if let Some(job) = self.job_in_flight(&name, None)? {
            return if job.kind == JobKind::Restore
                && job.backup_id == backup.id
                && job.on_existing == Some(on_existing)
            {
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
        // Stored under the name of the tenant it was taken from.
        let source = Username::parse_field(&backup.tenant, "tenant")?;
        let (_, job_id) = self.new_ids()?;
        let mut job = JobRecord::start(
            &job_id,
            JobKind::Restore,
            name.as_str(),
            id.as_str(),
            unit_name(&job_id),
        );
        job.on_existing = Some(on_existing);
        let task = Task::Restore {
            uid: tenant_rec.uid,
            gid: tenant_rec.gid,
            home: tenant_rec.home.clone(),
            input: backup_path(&self.ctx.config.backup_dir, &source, &id).join(&home.name),
            sha256: home.sha256.clone(),
            size: home.size_bytes,
            on_existing,
        };
        let cmd = self.job_command(&job, tenant_rec, Some(&tenant_rec.home), &task)?;
        self.ctx.store.save_job(&job)?;
        // Nothing of the tenant's runs on half-restored files. A suspended
        // tenant's services are stopped already.
        let started = match self.set_services(tenant_rec, false).await {
            Ok(()) => self.ctx.sys.run_ok(cmd).await.map(|_| ()),
            Err(e) => Err(e),
        };
        if let Err(e) = started {
            error!(job = %job.id, tenant = %name, error = %e, "restore could not be started");
            self.conclude_restore(job, Err("the job could not be started".to_owned()), "")
                .await?;
            return Err(e);
        }
        info!(job = %job.id, backup = %id, from = %source, tenant = %name, "restore started");
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

    /// The record of the (existing) `tenant`'s backup `id`. Retained
    /// backups of a deleted tenant of the same name are not among them.
    fn backup_of(&self, tenant: &Username, id: &BackupId) -> Result<BackupRecord> {
        self.ctx
            .store
            .load_backup(id)?
            .filter(|b| b.tenant == tenant.as_str() && !b.tenant_deleted)
            .ok_or_else(|| Error::BackupNotFound {
                tenant: tenant.to_string(),
                id: id.to_string(),
            })
    }

    /// The retained backup `id` of the deleted tenant `former`.
    fn retained_of_deleted(&self, former: &Username, id: &BackupId) -> Result<BackupRecord> {
        self.ctx
            .store
            .load_backup(id)?
            .filter(|b| b.tenant == former.as_str() && b.tenant_deleted)
            .ok_or_else(|| Error::BackupNotFound {
                tenant: former.to_string(),
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
        all.retain(|b| b.tenant == name.as_str() && !b.tenant_deleted);
        Ok(all)
    }

    /// Every backup with a retention date — of existing tenants and of
    /// deleted ones (`tenant_deleted`) — oldest first. For the operator.
    pub async fn list_retained(&self) -> Result<Vec<BackupRecord>> {
        let mut all = self.ctx.store.list_backups()?;
        all.retain(|b| b.retain_until_unix != 0);
        Ok(all)
    }

    /// Mark one of an existing tenant's complete backups as kept for
    /// `months` (1–12) from now — replacing an earlier date, shorter or
    /// longer. Returns the updated record.
    pub async fn retain(
        &self,
        tenant: &str,
        backup_id: &str,
        months: u32,
        days: u32,
    ) -> Result<BackupRecord> {
        let name = Username::parse_field(tenant, "tenant")?;
        let id = BackupId::parse(backup_id)?;
        let period = match retention(months, days)? {
            0 => {
                return Err(Error::invalid(
                    "retain_months",
                    "give a retention of 1 to 12 months or 1 to 366 days",
                ))
            }
            p => p,
        };
        let _guard = self.ctx.lock.lock().await;
        let mut backup = self.backup_of(&name, &id)?;
        if backup.state != BackupState::Ready {
            return Err(Error::BackupNotReady(id.to_string()));
        }
        backup.retain_until_unix = now_unix().saturating_add(period);
        self.ctx.store.save_backup(&backup)?;
        info!(backup = %id, tenant = %name, until = backup.retain_until_unix, "backup retained");
        Ok(backup)
    }

    /// Delete a retained backup of the deleted tenant `former` before its
    /// date. Returns `false` if there is no such backup.
    pub async fn delete_retained(&self, former: &str, backup_id: &str) -> Result<bool> {
        let name = Username::parse_field(former, "tenant")?;
        let id = BackupId::parse(backup_id)?;
        let _guard = self.ctx.lock.lock().await;
        if self.retained_of_deleted(&name, &id).is_err() {
            return Ok(false);
        }
        self.refuse_while_in_use(&name, &id)?;
        self.remove_backup(&name, &id)?;
        info!(backup = %id, former_tenant = %name, "retained backup deleted");
        Ok(true)
    }

    /// Remove what has passed its retention date: a retained backup of a
    /// deleted tenant goes; on an existing tenant's backup only the mark
    /// lapses (it counts towards the tenant's retention again). Backups in
    /// use by a job are left for the next round. Returns how many were
    /// removed.
    pub async fn expire_retained(&self) -> Result<usize> {
        let _guard = self.ctx.lock.lock().await;
        let now = now_unix();
        let busy: Vec<String> = self
            .running_jobs()?
            .into_iter()
            .map(|j| j.backup_id)
            .collect();
        let mut removed = 0;
        for mut b in self.ctx.store.list_backups()? {
            if b.retain_until_unix == 0 || b.retain_until_unix > now || busy.contains(&b.id) {
                continue;
            }
            let (name, id) = (
                Username::parse_field(&b.tenant, "tenant")?,
                BackupId::parse(&b.id)?,
            );
            if b.tenant_deleted {
                self.remove_backup(&name, &id)?;
                info!(backup = %id, former_tenant = %name, "retained backup expired and removed");
                removed += 1;
            } else {
                b.retain_until_unix = 0;
                self.ctx.store.save_backup(&b)?;
                info!(backup = %id, tenant = %name, "retention period ended; ordinary backup again");
            }
        }
        Ok(removed)
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
        if self.backup_of(&name, &id).is_err() {
            return Ok(false);
        }
        self.refuse_while_in_use(&name, &id)?;
        self.remove_backup(&name, &id)?;
        info!(backup = %id, tenant = %name, "backup deleted");
        Ok(true)
    }

    /// A backup a job is writing or restoring from is not removed.
    fn refuse_while_in_use(&self, tenant: &Username, id: &BackupId) -> Result<()> {
        match self
            .running_jobs()?
            .into_iter()
            .find(|j| j.backup_id == id.as_str())
        {
            Some(job) => Err(Error::JobRunning {
                tenant: tenant.to_string(),
                job: job.id,
            }),
            None => Ok(()),
        }
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
        let mut jobs = self.running_jobs()?;
        // Tenant deletions run in the daemon; `lifecycle` resumes them.
        jobs.retain(|j| j.kind.has_unit());
        for job in &jobs {
            info!(job = %job.id, kind = job.kind.as_str(), tenant = %job.tenant, "resuming job");
            self.spawn_driver(JobId::parse(&job.id)?);
        }
        Ok(jobs.len())
    }

    /// Expire retained backups now and then every hour, for as long as the
    /// daemon runs.
    pub fn spawn_expiry(&self) {
        let svc = self.clone();
        tokio::spawn(async move {
            loop {
                match svc.expire_retained().await {
                    Ok(0) => {}
                    Ok(n) => info!(removed = n, "expired retained backups removed"),
                    Err(e) => warn!(error = %e, "could not expire retained backups; will retry"),
                }
                tokio::time::sleep(EXPIRY_INTERVAL).await;
            }
        });
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
        if job.state != JobState::Running || !job.kind.has_unit() {
            return Ok(true);
        }
        let state = self.unit_state(&job.unit).await?;
        if state == UnitState::Running {
            return Ok(false);
        }
        let output = self.unit_output(&job.unit).await;
        let _guard = self.ctx.lock.lock().await;
        // Concluded by someone else meanwhile (two drivers of one job): done.
        if self
            .ctx
            .store
            .load_job(id)?
            .is_none_or(|j| j.state != JobState::Running)
        {
            return Ok(true);
        }
        let outcome = match &state {
            UnitState::Exited => Ok(()),
            // Whether a vanished unit had finished is for the result file to say.
            UnitState::Gone if job.kind == JobKind::Backup => Ok(()),
            UnitState::Gone => Err(format!(
                "the job did not run to its end (was the host restarted?); repeat the {}",
                job.kind.as_str()
            )),
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
            JobKind::RestoreDatabase => self.conclude_restore_db(job, outcome, &output).await?,
            JobKind::DeleteTenant => return Ok(true),
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
        // Every database the backup set out to include must be complete.
        for d in &backup.databases {
            if !members.iter().any(|m| m.name == d.dump_member) {
                return Ok(Err(format!(
                    "the dump of database {} is missing or incomplete",
                    d.name
                )));
            }
        }
        let daemon_written = std::iter::once((RECORDS_MEMBER.to_owned(), KIND_RECORDS)).chain(
            backup
                .databases
                .iter()
                .map(|d| (d.objects_member.clone(), KIND_MARIADB_OBJECTS)),
        );
        for (name, kind) in daemon_written {
            let (size_bytes, sha256) = worker::hash_file(&dir.join(&name))?;
            members.push(BackupMember {
                name,
                kind: kind.to_owned(),
                size_bytes,
                sha256,
            });
        }
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
        mut job: JobRecord,
        outcome: std::result::Result<(), String>,
        output: &str,
    ) -> Result<JobRecord> {
        let name = Username::parse_field(&job.tenant, "tenant")?;
        let reported = worker::parse_restore_result(output);
        if let Some((restored, skipped)) = reported {
            job.restored_entries = restored;
            job.skipped_entries = skipped;
        }
        // Whatever the archiver did or did not do, the home must be private
        // and the sites must be servable and running again.
        let service = match self.ctx.store.load_tenant(&name)? {
            Some(tenant) if tenant.state == TenantState::Ready => {
                let (service, sites) = self.back_into_service(&tenant).await;
                job.sites = sites;
                service
            }
            _ => Ok(()),
        };
        let counts = if reported.is_some() {
            format!(
                "{} entries restored, {} kept because they already existed",
                job.restored_entries, job.skipped_entries
            )
        } else {
            "the worker reported no entry counts".to_owned()
        };
        let failed_sites: Vec<&str> = job
            .sites
            .iter()
            .filter(|s| !s.succeeded)
            .map(|s| s.domain.as_str())
            .collect();
        let apps = if failed_sites.is_empty() {
            String::new()
        } else {
            format!(
                "; application dependencies could NOT be reinstalled for {} (see sites)",
                failed_sites.join(", ")
            )
        };
        let (state, message) = match (outcome, service) {
            (Ok(()), Ok(())) => (
                JobState::Succeeded,
                format!("restored from backup {} ({counts}){apps}", job.backup_id),
            ),
            (Err(reason), Ok(())) => (JobState::Failed, format!("{reason} ({counts}){apps}")),
            (outcome, Err(e)) => {
                error!(job = %job.id, tenant = %name, error = %e, "could not put the tenant back into service after a restore");
                let files = match outcome {
                    Ok(()) => "the files were restored".to_owned(),
                    Err(reason) => reason,
                };
                (
                    JobState::Failed,
                    format!("{files} ({counts}), but the sites could not be put back into service; see the oxpanel-daemon journal"),
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
    /// root (as `ConfigureVirtualHost` grants it), the applications'
    /// virtualenvs and dependencies (backups leave them out), and the
    /// tenant's services. Every step is attempted; the first error is
    /// returned, with the per-application results.
    async fn back_into_service(&self, tenant: &TenantRecord) -> (Result<()>, Vec<SiteResult>) {
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
        let sites = self.rebuild_apps(tenant).await;
        let services = self.set_services(tenant, true).await;
        (private.and(labels).and(access).and(services), sites)
    }

    /// For every application site of the tenant, before it is started
    /// again: the Python virtualenv, then the dependencies, installed exactly
    /// as `InstallAppDependencies` does (as the tenant, in a transient unit
    /// that may use the network — this daemon and the job's worker may not).
    /// A failure is reported per site and never fails the restore of the
    /// files.
    async fn rebuild_apps(&self, tenant: &TenantRecord) -> Vec<SiteResult> {
        let vhosts = match self.ctx.store.list_vhosts() {
            Ok(v) => v,
            Err(e) => {
                return vec![SiteResult {
                    domain: String::new(),
                    succeeded: false,
                    detail: format!("the sites could not be listed: {e}"),
                }]
            }
        };
        let mut out = Vec::new();
        for v in vhosts.iter().filter(|v| v.tenant == tenant.username) {
            let Some(app) = &v.app else { continue };
            let result = self.rebuild_app(tenant, v, app).await;
            let (succeeded, detail) = match result {
                Ok(done) => (true, done),
                Err(e) => (false, e),
            };
            if !succeeded {
                warn!(domain = %v.domain, tenant = %tenant.username, %detail, "application not rebuilt after a restore");
            }
            out.push(SiteResult {
                domain: v.domain.clone(),
                succeeded,
                detail,
            });
        }
        out
    }

    async fn rebuild_app(
        &self,
        tenant: &TenantRecord,
        vhost: &VHostRecord,
        app: &crate::records::AppRecord,
    ) -> std::result::Result<String, String> {
        crate::app::ensure_venv(&self.ctx, tenant, app)
            .await
            .map_err(|e| format!("the virtualenv could not be created: {e}"))?;
        let manifest = crate::app::dependency_manifest(app.runtime);
        let root = crate::app::app_root(tenant, app);
        if !std::fs::symlink_metadata(root.join(manifest)).is_ok_and(|m| m.is_file()) {
            return Ok(format!("no {manifest}; nothing to install"));
        }
        // Not `install_dependencies`: that restarts the application, which
        // is started later, with the tenant's other services.
        match crate::app::run_installer(&self.ctx, tenant, vhost).await {
            Ok((true, _)) => Ok(format!("dependencies reinstalled from {manifest}")),
            Ok((false, output)) => Err(format!(
                "the dependency installation failed: {}",
                output.lines().last().unwrap_or("no output")
            )),
            Err(e) => Err(format!("the dependency installation could not run: {e}")),
        }
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
        // Retained backups do not count, and are never removed here.
        ready.retain(|b| {
            b.tenant == tenant.as_str()
                && !b.tenant_deleted
                && b.retain_until_unix == 0
                && b.state == BackupState::Ready
        });
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

/// `DeleteTenant` is refused while the tenant has a job in flight or
/// backups that are not retained: deleting them silently would destroy the
/// only copy of a customer's data on the say-so of a different request, so
/// the operator either deletes them or marks them retained. Retained
/// backups survive the deletion ([`detach_retained`]).
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
        .any(|b| b.tenant == tenant.as_str() && !b.tenant_deleted && b.retain_until_unix == 0)
    {
        return Err(Error::TenantHasBackups(tenant.to_string()));
    }
    Ok(())
}

/// The tenant is being deleted: its retained backups stay, detached from
/// the name, so that a later tenant of the same name can neither see nor
/// restore them. Only the operator RPCs for retained backups reach them
/// until their date passes. Idempotent.
pub fn detach_retained(ctx: &Ctx, tenant: &Username) -> Result<()> {
    for mut b in ctx.store.list_backups()? {
        if b.tenant == tenant.as_str() && !b.tenant_deleted && b.retain_until_unix != 0 {
            b.tenant_deleted = true;
            ctx.store.save_backup(&b)?;
            info!(backup = %b.id, %tenant, until = b.retain_until_unix, "retained backup kept after the tenant's deletion");
        }
    }
    Ok(())
}

/// Drop the job history of a tenant that is being deleted, so that a later
/// tenant of the same name starts with none.
/// `keep` is the deletion's own job, which reports the outcome.
pub fn forget_tenant_jobs(ctx: &Ctx, tenant: &Username, keep: Option<&JobId>) -> Result<()> {
    for job in ctx
        .store
        .list_jobs()?
        .iter()
        .filter(|j| j.tenant == tenant.as_str() && keep.is_none_or(|k| k.as_str() != j.id))
    {
        ctx.store.delete_job(&JobId::parse(&job.id)?)?;
    }
    Ok(())
}

/// Remove every backup of `tenant` that is not retained (the deletion of the
/// whole tenant). Retained ones were detached from the name before. The
/// caller holds the mutation lock. Idempotent.
pub fn remove_unretained(ctx: &Ctx, tenant: &Username) -> Result<usize> {
    let doomed: Vec<BackupRecord> = ctx
        .store
        .list_backups()?
        .into_iter()
        .filter(|b| b.tenant == tenant.as_str() && !b.tenant_deleted && b.retain_until_unix == 0)
        .collect();
    let backup_dir = &ctx.config.backup_dir;
    for b in &doomed {
        let id = BackupId::parse(&b.id)?;
        fsutil::remove_dir_tree(&backup_path(backup_dir, tenant, &id))?;
        ctx.store.delete_backup(&id)?;
        info!(backup = %id, %tenant, "backup deleted with its tenant");
    }
    // The tenant's directory goes with its last backup (fails, harmlessly,
    // while retained ones remain).
    let _ = std::fs::remove_dir(tenant_dir(backup_dir, tenant));
    Ok(doomed.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::records::AppRuntime;
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
        crate::config::sandbox_feature_paths(&mut cfg, dir.path());
        cfg.backup_dir = dir.path().join("backups");
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
        // As the daemon does at start: the sshd drop-in is in place.
        crate::sftp::converge_all(&h.ctx)
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
            let (job, started) = self.backups.create(tenant, 0, 0).await?;
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

    /// The exclusion scan of a home without applications.
    fn expected_scan(home: &str) -> Vec<String> {
        [
            home,
            "-xdev",
            "(",
            "-path",
            &format!("{home}/.cache"),
            "-o",
            "-path",
            &format!("{home}/.npm"),
            ")",
            "-prune",
            "-o",
            "(",
            "-name",
            "node_modules",
            ")",
            "-prune",
            "-printf",
            "%P\\0",
            "-o",
            "-name",
            "pyvenv.cfg",
            "-printf",
            "%h\\0",
        ]
        .map(str::to_owned)
        .to_vec()
    }

    /// The size estimate of a home without applications.
    fn expected_du(home: &str) -> Vec<String> {
        [
            "--summarize",
            "--one-file-system",
            "--block-size=1",
            "--exclude=node_modules",
            &format!("--exclude={home}/.cache"),
            &format!("--exclude={home}/.npm"),
            "--",
            home,
        ]
        .map(str::to_owned)
        .to_vec()
    }

    #[tokio::test]
    async fn create_starts_a_sandboxed_worker_in_the_tenants_slice() -> Result<()> {
        let h = harness(false).await;
        let (job, started) = h.backups.create("alice", 0, 0).await?;
        assert!(started);
        assert_eq!((job.kind, job.state), (JobKind::Backup, JobState::Running));
        let home = h.ctx.config.home_base.join("alice");
        let home = home.to_string_lossy();
        let dir = h.dir(&job);
        let dir_str = dir.to_string_lossy();

        // Measured as the tenant: first what will be left out, then the
        // rest.
        let tenant = Some(RunAs {
            uid: 20000,
            gid: 20000,
        });
        let find = h.sys.calls_to(bin::FIND);
        assert_eq!(find.first().and_then(|c| c.run_as), tenant);
        assert_eq!(find.first().map(args), Some(expected_scan(&home)));
        let du = h.sys.calls_to(bin::DU);
        assert_eq!(du.len(), 1);
        assert_eq!(du.first().and_then(|c| c.run_as), tenant);
        assert_eq!(du.first().map(args), Some(expected_du(&home)));

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
                "--venvs",
                "-",
                "--databases",
                "-",
                "--socket",
                "/var/lib/mysql/mysql.sock",
            ]
            .map(str::to_owned),
        );
        assert_eq!(run.first().map(args), Some(expected));
        Ok(())
    }

    #[tokio::test]
    async fn a_backup_in_flight_is_listed_but_neither_restorable_nor_deletable() -> Result<()> {
        let h = harness(false).await;
        let (job, _) = h.backups.create("alice", 0, 0).await?;
        // In flight: listed as CREATING, not restorable, not deletable.
        let listed = h.backups.list("alice").await?;
        assert_eq!(listed.len(), 1);
        assert!(listed
            .first()
            .is_some_and(|b| b.state == BackupState::Creating && b.domains == ["example.com"]));
        assert!(matches!(
            h.backups
                .restore("alice", &job.backup_id, OnExisting::Overwrite)
                .await,
            Err(Error::BackupNotReady(_))
        ));
        assert!(matches!(
            h.backups.delete("alice", &job.backup_id).await,
            Err(Error::JobRunning { .. })
        ));
        // A repeated request returns the job that is running.
        let (again, started) = h.backups.create("alice", 0, 0).await?;
        assert!(!started);
        assert_eq!(again.id, job.id);
        assert_eq!(h.sys.calls_to(bin::SYSTEMD_RUN).len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_finished_backup_is_sealed_with_checksums_and_a_manifest() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let h = harness(false).await;
        let (job, _) = h.backups.create("alice", 0, 0).await?;
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
        let (job, _) = h.backups.create("alice", 0, 0).await?;
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
            let (job, _) = h.backups.create("alice", 0, 0).await?;
            h.sys.script_stdout(bin::SYSTEMCTL, &show);
            let done = h.finish(&job).await?;
            assert_eq!(done.state, JobState::Failed);
            assert!(done.message.contains(needle), "{}", done.message);
            assert!(h.backups.list("alice").await?.is_empty());
        }

        // The unit vanished (host restarted) before the worker finished: the
        // archive is there but has no result file, so it is not a backup.
        h.sys.set_worker_writes_nothing(true);
        let (job, _) = h.backups.create("alice", 0, 0).await?;
        std::fs::write(h.dir(&job).join("home.tar.gz"), b"looks like an archive")
            .map_err(|e| Error::io("write", h.dir(&job), e))?;
        h.sys.script_stdout(bin::SYSTEMCTL, GONE);
        let done = h.finish(&job).await?;
        assert_eq!(done.state, JobState::Failed);
        assert!(done.message.contains("no complete archive"));
        assert!(!h.dir(&job).exists());
        // … and the same when the unit says it succeeded but left nothing.
        let (job, _) = h.backups.create("alice", 0, 0).await?;
        let done = h.finish(&job).await?;
        assert_eq!(done.state, JobState::Failed);
        assert!(h.backups.list("alice").await?.is_empty());
        h.sys.set_worker_writes_nothing(false);

        // A unit that vanished *after* the worker finished: complete, kept.
        let (job, _) = h.backups.create("alice", 0, 0).await?;
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
            h.backups.create("alice", 0, 0).await,
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
        assert!(h.backups.create("alice", 0, 0).await?.1);
        Ok(())
    }

    #[tokio::test]
    async fn requests_that_cannot_succeed_are_refused_before_anything_is_created() -> Result<()> {
        let h = harness(false).await;
        for bad in ["", "root", "../alice", "alice;id", "Alice"] {
            assert!(
                matches!(
                    h.backups.create(bad, 0, 0).await,
                    Err(Error::InvalidInput { .. })
                ),
                "{bad:?}"
            );
        }
        assert!(matches!(
            h.backups.create("carol", 0, 0).await,
            Err(Error::TenantNotFound(_))
        ));
        assert!(matches!(
            h.backups.list("carol").await,
            Err(Error::TenantNotFound(_))
        ));
        // No archiver on the host: refused, nothing measured or started.
        h.sys.set_missing(bin::TAR);
        assert!(matches!(
            h.backups.create("alice", 0, 0).await,
            Err(Error::RuntimeUnavailable(_))
        ));
        assert!(h.sys.calls().is_empty());
        let fresh = FakeSystem::new();
        fresh.set_missing(bin::GZIP);
        let without_gzip =
            BackupService::new(Ctx::new((*h.ctx.config).clone(), Arc::new(fresh), false));
        assert!(matches!(
            without_gzip
                .restore("alice", "b1731500000123", OnExisting::Overwrite)
                .await,
            Err(Error::RuntimeUnavailable(_))
        ));
        let h = harness(false).await;
        // Not enough room: the fake home is 8192 bytes, the reserve 1 GiB.
        h.sys.set_disk_free((1 << 30) + 8191);
        match h.backups.create("alice", 0, 0).await {
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
        let (job, _) = h.backups.create("alice", 0, 0).await?;
        let run = h.sys.calls_to(bin::SYSTEMD_RUN);
        let argv = run.first().map(args).unwrap_or_default();
        let max = argv.iter().skip_while(|a| *a != "--max-bytes").nth(1);
        assert_eq!(max.map(String::as_str), Some("8192"));
        h.finish(&job).await?;

        for bad in [
            "",
            "b1",
            "j1731500000123",
            "../b1731500000123",
            "b1731500000123/x",
        ] {
            assert!(matches!(
                h.backups.restore("alice", bad, OnExisting::Overwrite).await,
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

        let (job, started) = h
            .backups
            .restore("alice", &made.backup_id, OnExisting::Overwrite)
            .await?;
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
                "--existing",
                "overwrite",
            ]
        );
        // One job per tenant; the same request returns the same job.
        assert!(matches!(
            h.backups.create("alice", 0, 0).await,
            Err(Error::JobRunning { .. })
        ));
        assert!(
            !h.backups
                .restore("alice", &made.backup_id, OnExisting::Overwrite)
                .await?
                .1
        );
        assert!(matches!(
            h.backups.delete("alice", &made.backup_id).await,
            Err(Error::JobRunning { .. })
        ));

        h.sys.clear_calls();
        let done = h.finish(&job).await?;
        assert_eq!(done.state, JobState::Succeeded);
        assert_eq!(
            done.message,
            format!(
                "restored from backup {} (the worker reported no entry counts)",
                made.backup_id
            )
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
        let (job, _) = h
            .backups
            .restore("alice", &made.backup_id, OnExisting::Overwrite)
            .await?;
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
        let (job, _) = h
            .backups
            .restore("alice", &made.backup_id, OnExisting::Overwrite)
            .await?;
        h.sys.script_stdout(bin::SYSTEMCTL, GONE);
        let done = h.finish(&job).await?;
        assert_eq!(done.state, JobState::Failed);
        assert!(done.message.contains("repeat the restore"));
        // A hostile archive: tar refused members.
        let (job, _) = h
            .backups
            .restore("alice", &made.backup_id, OnExisting::Overwrite)
            .await?;
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
        assert!(h
            .backups
            .restore("alice", &made.backup_id, OnExisting::Overwrite)
            .await
            .is_err());
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
        let (job, _) = h
            .backups
            .restore("alice", &made.backup_id, OnExisting::Overwrite)
            .await?;
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
            h.backups
                .restore("bob", &made.backup_id, OnExisting::Overwrite)
                .await,
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
            h.backups
                .restore("alice", &made.backup_id, OnExisting::Overwrite)
                .await,
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
            jobs.push(h.backups.create(tenant, 0, 0).await?.0);
        }
        assert!(matches!(
            h.backups.create("erin", 0, 0).await,
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
        assert!(h.backups.create("erin", 0, 0).await?.1);

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
        let (job, _) = h.backups.create("bob", 0, 0).await?;
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

    /// bob with a final backup kept for 3 months, then deleted, then a new
    /// tenant named bob. Returns the harness and the final backup's job.
    async fn retained_backup_of_deleted_bob() -> Result<(Harness, JobRecord)> {
        let h = harness(false).await;
        let month = crate::validate::RETENTION_MONTH_SECS;
        // Validated before anything is created.
        assert!(matches!(
            h.backups.create("bob", 13, 0).await,
            Err(Error::InvalidInput { .. })
        ));
        assert!(h.sys.calls().is_empty() && h.ctx.store.list_backups()?.is_empty());

        // A final backup of bob, kept for 3 months; plus ordinary ones.
        let before = now_unix();
        let fin = h.backups.create("bob", 3, 0).await?.0;
        h.finish(&fin).await?;
        let rec = h.ctx.store.load_backup(&BackupId::parse(&fin.backup_id)?)?;
        let until = rec.as_ref().map_or(0, |r| r.retain_until_unix);
        assert!(until >= before + 3 * month && until <= now_unix() + 3 * month);
        for _ in 0..3 {
            h.backup("bob").await?;
        }
        // keep = 2 ordinary backups, and the retained one on top.
        let listed = h.backups.list("bob").await?;
        assert_eq!(listed.len(), 3);
        assert!(listed.iter().any(|b| b.id == fin.backup_id));

        // Marking an existing backup: validated, own tenant, complete only.
        let other = listed
            .iter()
            .find(|b| b.id != fin.backup_id)
            .map(|b| b.id.clone())
            .unwrap_or_default();
        assert!(matches!(
            h.backups.retain("bob", &other, 0, 0).await,
            Err(Error::InvalidInput { .. })
        ));
        assert!(matches!(
            h.backups.retain("alice", &other, 1, 0).await,
            Err(Error::BackupNotFound { .. })
        ));
        assert!(
            h.backups
                .retain("bob", &other, 1, 0)
                .await?
                .retain_until_unix
                > 0
        );

        // Deleting bob: refused while an ordinary backup is left.
        assert!(matches!(
            h.tenants.delete("bob", true).await,
            Err(Error::TenantHasBackups(_))
        ));
        for b in h.backups.list("bob").await? {
            if b.retain_until_unix == 0 {
                h.backups.delete("bob", &b.id).await?;
            }
        }
        assert!(h.tenants.delete("bob", true).await?);
        let retained = h.backups.list_retained().await?;
        assert_eq!(retained.len(), 2);
        assert!(retained
            .iter()
            .all(|b| b.tenant == "bob" && b.tenant_deleted));
        assert!(h.dir(&fin).join(MANIFEST).is_file(), "the files stay");
        assert_eq!(
            crate::host::HostService::new(h.ctx.clone())
                .reconcile()
                .await?,
            vec![]
        );

        // A new tenant named bob sees nothing of them.
        h.tenants.create("bob", Limits::default(), "").await?;
        assert!(h.backups.list("bob").await?.is_empty());
        assert!(matches!(
            h.backups
                .restore("bob", &fin.backup_id, OnExisting::Overwrite)
                .await,
            Err(Error::BackupNotFound { .. })
        ));
        assert!(matches!(
            h.backups.retain("bob", &fin.backup_id, 12, 0).await,
            Err(Error::BackupNotFound { .. })
        ));
        assert!(!h.backups.delete("bob", &fin.backup_id).await?);
        h.backup("bob").await?;
        h.backup("bob").await?;
        h.backup("bob").await?;
        assert_eq!(
            h.backups.list_retained().await?.len(),
            2,
            "untouched by the new bob's retention"
        );

        Ok((h, fin))
    }

    #[tokio::test]
    async fn retained_backups_skip_the_count_and_outlive_their_tenant() -> Result<()> {
        retained_backup_of_deleted_bob().await.map(|_| ())
    }

    #[tokio::test]
    async fn retained_backups_are_restored_deleted_and_expired_by_the_operator() -> Result<()> {
        let (h, fin) = retained_backup_of_deleted_bob().await?;
        // The operator's restore: backup id, source and target must agree.
        h.sys.clear_calls();
        assert!(matches!(
            h.backups
                .restore_retained(&fin.backup_id, "alice", "bob", OnExisting::Overwrite)
                .await,
            Err(Error::BackupNotFound { .. })
        ));
        assert!(matches!(
            h.backups
                .restore_retained(&fin.backup_id, "bob", "carol", OnExisting::Overwrite)
                .await,
            Err(Error::TenantNotFound(_))
        ));
        assert!(h.sys.calls_to(bin::SYSTEMD_RUN).is_empty());
        let (job, started) = h
            .backups
            .restore_retained(&fin.backup_id, "bob", "alice", OnExisting::Overwrite)
            .await?;
        assert!(started && job.tenant == "alice");
        let argv = h
            .sys
            .calls_to(bin::SYSTEMD_RUN)
            .first()
            .map(args)
            .unwrap_or_default();
        let input = h.dir(&fin).join(HOME_MEMBER);
        assert!(
            argv.contains(&input.to_string_lossy().into_owned()),
            "read from where it was stored"
        );
        assert!(
            argv.windows(2).any(|w| w == ["restore", "20000"]),
            "written as alice: {argv:?}"
        );
        assert_eq!(h.finish(&job).await?.state, JobState::Succeeded);

        // Deleting one early, by the name it was kept under.
        let early = h
            .backups
            .list_retained()
            .await?
            .into_iter()
            .find(|b| b.id != fin.backup_id)
            .map(|b| b.id)
            .unwrap_or_default();
        assert!(!h.backups.delete_retained("alice", &early).await?);
        assert!(h.backups.delete_retained("bob", &early).await?);

        // Expiry: the deleted tenant's backup goes; an existing tenant's mark lapses.
        let alices = h.backups.create("alice", 1, 0).await?.0;
        h.finish(&alices).await?;
        assert_eq!(h.backups.expire_retained().await?, 0, "nothing is due yet");
        for id in [&fin.backup_id, &alices.backup_id] {
            let id = BackupId::parse(id)?;
            let mut rec = h
                .ctx
                .store
                .load_backup(&id)?
                .unwrap_or_else(|| panic!("record"));
            rec.retain_until_unix = now_unix() - 1;
            h.ctx.store.save_backup(&rec)?;
        }
        assert_eq!(h.backups.expire_retained().await?, 1);
        assert!(!h.dir(&fin).exists() && h.backups.list_retained().await?.is_empty());
        let lapsed = h.backups.list("alice").await?;
        assert!(lapsed
            .iter()
            .any(|b| b.id == alices.backup_id && b.retain_until_unix == 0));
        Ok(())
    }

    #[test]
    fn excluded_directories_are_relative_deduplicated_and_outermost() {
        let scan = b"apps/api/.venv\0/h/a\0/h/a/b\0/h/apps/api/.venv\0site/node_modules\0\0/h/z\0";
        assert_eq!(
            excluded_dirs("/h", scan),
            vec!["a", "apps/api/.venv", "site/node_modules", "z"]
        );
        // A pyvenv.cfg planted in the home itself: the whole home is left
        // out, and the manifest says so.
        assert_eq!(excluded_dirs("/h", b"/h\0x/node_modules\0"), vec!["."]);
        assert!(excluded_dirs("/h", b"").is_empty());
    }

    /// bob with a Python and a Node.js application, and one backup taken
    /// with the exclusion scan finding three directories.
    async fn bob_with_apps_backed_up() -> Result<(Harness, JobRecord)> {
        let h = harness(false).await;
        for (domain, runtime) in [
            ("api.example", AppRuntime::Python),
            ("node.example", AppRuntime::Node),
        ] {
            h.vhosts
                .configure(VHostRequest {
                    domain: domain.into(),
                    tenant: "bob".into(),
                    app: Some(crate::vhost::AppRequest {
                        runtime,
                        root: String::new(),
                        entry: String::new(),
                    }),
                    ..VHostRequest::default()
                })
                .await?;
        }
        let home = h.ctx.config.home_base.join("bob");
        let home_s = home.to_string_lossy().into_owned();
        h.sys.script_stdout(
            bin::FIND,
            &format!("apps/api.example/.venv\0apps/node.example/node_modules\0{home_s}/old-venv\0"),
        );
        h.sys.clear_calls();
        let made = h.backup("bob").await?;
        // The applications' .venv is excluded by path, and left out of the
        // estimate like every directory the scan found.
        let run = h.sys.calls_to(bin::SYSTEMD_RUN);
        let argv = run.first().map(args).unwrap_or_default();
        assert!(argv
            .windows(2)
            .any(|w| w == ["--venvs".to_owned(), "apps/api.example/.venv".to_owned()]));
        let find = h
            .sys
            .calls_to(bin::FIND)
            .first()
            .map(args)
            .unwrap_or_default();
        assert!(find
            .windows(3)
            .any(|w| w == ["-o", "-path", &format!("{home_s}/apps/api.example/.venv")]));
        let du = h
            .sys
            .calls_to(bin::DU)
            .first()
            .map(args)
            .unwrap_or_default();
        for d in [
            "apps/api.example/.venv",
            "apps/node.example/node_modules",
            "old-venv",
        ] {
            assert!(du.contains(&format!("--exclude={home_s}/{d}")), "{du:?}");
        }
        let backup = h.backups.list("bob").await?.remove(0);
        assert_eq!(
            backup.excluded,
            vec![
                "apps/api.example/.venv",
                "apps/node.example/node_modules",
                "old-venv"
            ]
        );
        assert_eq!(backup.excluded_count, 3);
        let manifest: Manifest = serde_json::from_slice(
            &std::fs::read(h.dir(&made).join(MANIFEST)).map_err(|e| Error::io("read", &home, e))?,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            (manifest.excluded, manifest.excluded_count),
            (backup.excluded.clone(), 3)
        );
        assert_eq!(manifest.exclude_rules.len(), EXCLUDE_RULES.len());
        Ok((h, made))
    }

    #[tokio::test]
    async fn exclusions_are_recorded_in_the_record_and_the_manifest() -> Result<()> {
        bob_with_apps_backed_up().await.map(|_| ())
    }

    #[tokio::test]
    async fn restores_report_counts_and_rebuild_the_applications() -> Result<()> {
        let (h, made) = bob_with_apps_backed_up().await?;
        let home = h.ctx.config.home_base.join("bob");
        let home_s = home.to_string_lossy().into_owned();

        // Restore keeping existing files; the Python app has a requirements
        // file whose installation fails, the Node.js app has nothing to install.
        let api = home.join("apps/api.example");
        std::fs::create_dir_all(&api).map_err(|e| Error::io("mkdir", &api, e))?;
        std::fs::write(api.join("requirements.txt"), "flask\n")
            .map_err(|e| Error::io("w", &api, e))?;
        h.sys.clear_calls();
        let (job, _) = h
            .backups
            .restore("bob", &made.backup_id, OnExisting::Keep)
            .await?;
        assert_eq!(job.on_existing, Some(OnExisting::Keep));
        let argv = h
            .sys
            .calls_to(bin::SYSTEMD_RUN)
            .first()
            .map(args)
            .unwrap_or_default();
        assert!(argv.ends_with(&["--existing".to_owned(), "keep".to_owned()]));
        h.sys.script_stdout(
            bin::JOURNALCTL,
            "tar: ./a: skipping existing file\noxpanel-restore-result restored=7 skipped=2\n",
        );
        h.sys.script_failure(bin::SYSTEMD_RUN, 1, "pip: no network");
        h.sys.clear_calls();
        let done = h.finish(&job).await?;
        assert_eq!(done.state, JobState::Succeeded, "the files were restored");
        assert_eq!((done.restored_entries, done.skipped_entries), (7, 2));
        assert!(
            done.message
                .contains("7 entries restored, 2 kept because they already existed"),
            "{}",
            done.message
        );
        assert!(
            done.message
                .contains("could NOT be reinstalled for api.example"),
            "{}",
            done.message
        );
        let sites: Vec<(&str, bool)> = done
            .sites
            .iter()
            .map(|s| (s.domain.as_str(), s.succeeded))
            .collect();
        assert_eq!(sites, vec![("api.example", false), ("node.example", true)]);
        assert!(done
            .sites
            .iter()
            .any(|s| s.detail == "no package.json; nothing to install"));
        // The virtualenv is recreated as the tenant, dependencies are
        // installed in a transient unit, and only then do the apps start.
        let calls = h.sys.calls();
        let venv = calls.iter().position(|c| {
            c.program == bin::PYTHON3
                && args(c)
                    == [
                        "-m",
                        "venv",
                        "--",
                        &format!("{home_s}/apps/api.example/.venv"),
                    ]
                && c.run_as
                    == Some(RunAs {
                        uid: 20001,
                        gid: 20001,
                    })
        });
        let deps = calls
            .iter()
            .position(|c| c.program == bin::SYSTEMD_RUN && args(c).iter().any(|a| a == "--wait"));
        let start = calls.iter().position(|c| {
            c.program == bin::SYSTEMCTL
                && args(c)
                    .iter()
                    .any(|a| a == "oxpanel-app-api.example.service")
                && args(c).first().is_some_and(|a| a == "enable")
        });
        assert!(
            venv.is_some() && venv < deps && deps < start,
            "{venv:?} {deps:?} {start:?}"
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

    // ---- databases in backups -------------------------------------------

    const TRIGGER: &str = "CREATE DEFINER=`alice_app`@`localhost` TRIGGER stamp BEFORE INSERT ON posts FOR EACH ROW SET NEW.id = NEW.id + 1";
    const VIEW: &str = "CREATE ALGORITHM=UNDEFINED DEFINER=`alice_app`@`localhost` SQL SECURITY DEFINER VIEW `recent` AS select `posts`.`id` AS `id` from `posts`";
    const ROOT_PROC: &str = "CREATE DEFINER=`root`@`localhost` PROCEDURE `rootly`()\nSELECT 1";

    /// MariaDB with `<tenant>_wp`: a table, a trigger and a view by the
    /// tenant's user, and a procedure whose definer is root.
    async fn with_database(h: &Harness, tenant: &str) -> Result<crate::db::DbService> {
        use crate::records::DbEngine;
        h.sys.install_mariadb();
        let db = crate::db::DbService::new(h.ctx.clone());
        let wp = format!("{tenant}_wp");
        db.create_database(tenant, &wp, DbEngine::Mariadb).await?;
        db.create_user(
            tenant,
            &format!("{tenant}_app"),
            "Secret-pass-123",
            DbEngine::Mariadb,
        )
        .await?;
        let mut script = format!("CREATE TABLE `{wp}`.`posts` (id INT);\nUSE `{wp}`;\n");
        for o in [TRIGGER, VIEW, ROOT_PROC] {
            script.push_str("DELIMITER $$\n");
            script.push_str(&o.replace("alice_app", &format!("{tenant}_app")));
            script.push_str("\n$$\n");
        }
        h.sys.mariadb_admin(&script)?;
        h.sys.clear_calls();
        Ok(db)
    }

    #[tokio::test]
    async fn backups_include_each_database_as_a_dump_and_its_objects() -> Result<()> {
        let h = harness(false).await;
        with_database(&h, "alice").await?;
        let (job, _) = h.backups.create("alice", 0, 0).await?;
        let argv = h
            .sys
            .calls_to(bin::SYSTEMD_RUN)
            .first()
            .map(args)
            .unwrap_or_default();
        assert!(
            argv.ends_with(&[
                "--databases".to_owned(),
                "alice_wp".to_owned(),
                "--socket".to_owned(),
                "/var/lib/mysql/mysql.sock".to_owned(),
            ]),
            "{argv:?}"
        );
        // The stored objects are taken by the daemon, never from the dump:
        // triggers and routines, not views (the dump has those).
        let objects_script =
            "USE `alice_wp`;\nSHOW CREATE TRIGGER `stamp`;\nSHOW CREATE PROCEDURE `rootly`;\n";
        let sent = h.sys.calls_to(bin::MARIADB);
        let capture = sent
            .iter()
            .find(|c| c.stdin.as_deref() == Some(objects_script.as_bytes()))
            .unwrap_or_else(|| panic!("no capture"));
        assert!(args(capture).ends_with(&["--binary-mode".to_owned(), "--sandbox".to_owned()]));
        let dir = h.dir(&job);
        let member: ObjectsMember = serde_json::from_slice(
            &std::fs::read(dir.join("db-alice_wp.objects.json"))
                .map_err(|e| Error::io("read", &dir, e))?,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(member.database, "alice_wp");
        let defs: Vec<(&str, &str)> = member
            .objects
            .iter()
            .map(|o| (o.name.as_str(), o.definition.as_str()))
            .collect();
        assert_eq!(defs, vec![("stamp", TRIGGER), ("rootly", ROOT_PROC)]);

        let done = h.finish(&job).await?;
        assert_eq!(done.state, JobState::Succeeded, "{}", done.message);
        let backup = h
            .ctx
            .store
            .load_backup(&BackupId::parse(&job.backup_id)?)?
            .unwrap_or_else(|| panic!("record"));
        let kinds: Vec<(&str, &str)> = backup
            .members
            .iter()
            .map(|m| (m.name.as_str(), m.kind.as_str()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("db-alice_wp.objects.json", KIND_MARIADB_OBJECTS),
                ("db-alice_wp.sql.gz", worker::KIND_MARIADB),
                ("home.tar.gz", "home"),
                ("records.json", "records"),
            ]
        );
        for m in &backup.members {
            let (size, sha) = worker::hash_file(&dir.join(&m.name))?;
            assert_eq!((m.size_bytes, m.sha256.as_str()), (size, sha.as_str()));
        }
        let expected = vec![BackupDatabase {
            name: "alice_wp".into(),
            engine: crate::records::DbEngine::Mariadb,
            size_bytes: 16_384,
            dump_member: "db-alice_wp.sql.gz".into(),
            objects_member: "db-alice_wp.objects.json".into(),
        }];
        assert_eq!(backup.databases, expected);
        let manifest: Manifest = serde_json::from_slice(
            &std::fs::read(dir.join(MANIFEST)).map_err(|e| Error::io("read", &dir, e))?,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(manifest.databases, expected);
        Ok(())
    }

    #[tokio::test]
    async fn a_missing_dump_fails_the_backup_and_leaves_nothing() -> Result<()> {
        let h = harness(false).await;
        with_database(&h, "alice").await?;
        let (job, _) = h.backups.create("alice", 0, 0).await?;
        let result = h.dir(&job).join("db-alice_wp.sql.gz.result.json");
        std::fs::remove_file(&result).map_err(|e| Error::io("rm", &result, e))?;
        let done = h.finish(&job).await?;
        assert_eq!(done.state, JobState::Failed);
        assert_eq!(
            done.message,
            "the dump of database alice_wp is missing or incomplete"
        );
        assert!(!h.dir(&job).exists());
        assert!(h.backups.list("alice").await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn without_mariadb_a_tenant_with_databases_is_not_backed_up() -> Result<()> {
        let h = harness(false).await;
        with_database(&h, "alice").await?;
        h.sys.set_mariadb_running(false);
        assert!(matches!(
            h.backups.create("alice", 0, 0).await,
            Err(Error::DbUnavailable(_))
        ));
        assert!(h.ctx.store.list_backups()?.is_empty());
        assert!(h.ctx.store.list_jobs()?.is_empty());
        assert!(h.sys.calls_to(bin::SYSTEMD_RUN).is_empty());
        // A tenant without databases does not need MariaDB.
        let done = h.backup("bob").await?;
        assert_eq!(done.state, JobState::Succeeded);
        Ok(())
    }

    /// The `systemd-run` argv of a database restore job.
    fn restore_db_argv(job: &JobRecord, input: &str, sha: &str, size: u64) -> Vec<String> {
        let mut expected: Vec<String> =
            vec!["--quiet".into(), format!("--unit=oxpanel-job-{}", job.id)];
        for property in [
            format!(
                "Description=OxPanel database restore job {} (tenant alice)",
                job.id
            ),
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
            // It writes no file at all.
            "ReadOnlyPaths=/".into(),
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
        expected.extend(
            [
                "--",
                "/usr/sbin/oxpanel-daemon",
                "worker",
                "restore-db",
                "--input",
                input,
                "--sha256",
                sha,
                "--size",
                &size.to_string(),
                "--socket",
                "/var/lib/mysql/mysql.sock",
                "--database",
                "alice_old",
            ]
            .map(str::to_owned),
        );
        expected
    }

    #[tokio::test]
    async fn a_database_is_restored_from_a_backup_only_under_a_new_name() -> Result<()> {
        let h = harness(false).await;
        with_database(&h, "alice").await?;
        let backup = h.backup("alice").await?;
        let id = backup.backup_id.clone();
        h.sys.clear_calls();
        // Refused before anything: an existing name, another tenant's name,
        // a database the backup does not hold, another tenant's backup.
        for (tenant, database, new_name) in [
            ("alice", "alice_wp", "alice_wp"),
            ("alice", "alice_wp", "bob_x"),
            ("alice", "alice_nope", "alice_old"),
            ("bob", "alice_wp", "bob_x"),
        ] {
            let refused = h
                .backups
                .restore_database(tenant, &id, database, new_name)
                .await;
            assert!(
                matches!(
                    refused,
                    Err(Error::DbObjectUnusable { .. }
                        | Error::InvalidInput { .. }
                        | Error::BackupNotFound { .. })
                ),
                "{tenant} {database} {new_name}: {refused:?}"
            );
        }
        assert!(h.sys.calls_to(bin::SYSTEMD_RUN).is_empty());
        assert_eq!(h.ctx.store.list_databases()?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_database_restore_runs_a_sandboxed_loader_and_replays_the_objects() -> Result<()> {
        let h = harness(false).await;
        with_database(&h, "alice").await?;
        let backup = h.backup("alice").await?;
        let id = backup.backup_id.clone();
        h.sys.clear_calls();

        let (job, started) = h
            .backups
            .restore_database("alice", &id, "alice_wp", "alice_old")
            .await?;
        assert!(started);
        assert_eq!(
            (job.kind, job.database.as_str(), job.new_name.as_str()),
            (JobKind::RestoreDatabase, "alice_wp", "alice_old")
        );
        let old = crate::validate::DbName::parse("alice_old", "n")?;
        let rec = h.ctx.store.load_database(&old)?;
        assert_eq!(rec.map(|r| r.state), Some(DbState::Provisioning));
        // The empty database is created before the worker starts.
        let calls = h.sys.calls();
        let created = calls.iter().position(|c| {
            c.program == bin::MARIADB
                && c.stdin
                    .as_deref()
                    .is_some_and(|s| s.starts_with(b"CREATE DATABASE IF NOT EXISTS `alice_old`"))
        });
        let worker = calls.iter().position(|c| c.program == bin::SYSTEMD_RUN);
        assert!(
            created.is_some() && created < worker,
            "{created:?} {worker:?}"
        );
        let dump = h
            .ctx
            .store
            .load_backup(&BackupId::parse(&id)?)?
            .and_then(|b| {
                b.members
                    .into_iter()
                    .find(|m| m.name == "db-alice_wp.sql.gz")
            })
            .unwrap_or_else(|| panic!("dump member"));
        let input = h.dir(&backup).join("db-alice_wp.sql.gz");
        assert_eq!(
            h.sys.calls_to(bin::SYSTEMD_RUN).first().map(args),
            Some(restore_db_argv(
                &job,
                &input.to_string_lossy(),
                &dump.sha256,
                dump.size_bytes
            ))
        );
        // Repeated: the same job; another restore meanwhile: refused.
        let (again, started) = h
            .backups
            .restore_database("alice", &id, "alice_wp", "alice_old")
            .await?;
        assert!(!started && again.id == job.id);
        assert!(matches!(
            h.backups
                .restore_database("alice", &id, "alice_wp", "alice_older")
                .await,
            Err(Error::JobRunning { .. })
        ));

        let done = h.finish(&job).await?;
        assert_eq!(done.state, JobState::Succeeded, "{}", done.message);
        assert_eq!(
            done.message,
            format!("database alice_wp of backup {id} restored as alice_old (1 stored objects were not re-created, see object_issues); it has no grants yet")
        );
        let [issue] = done.object_issues.as_slice() else {
            panic!("{:?}", done.object_issues);
        };
        assert_eq!(
            (issue.name.as_str(), issue.definition.as_str()),
            ("rootly", ROOT_PROC)
        );
        let rec = h.ctx.store.load_database(&old)?;
        assert_eq!(rec.map(|r| r.state), Some(DbState::Ready));
        let (tables, objects) = h
            .sys
            .mariadb_schema("alice_old")
            .unwrap_or_else(|| panic!("schema"));
        assert_eq!(tables, ["from_dump"], "loaded by the worker");
        assert_eq!(
            objects,
            vec![(
                "TRIGGER".to_owned(),
                "stamp".to_owned(),
                "alice_app@localhost".to_owned()
            )]
        );
        let replay = crate::db::objects::replay_script(
            &Schema::of_db(&old),
            member_def(&h, &backup, "stamp")?
                .as_ref()
                .unwrap_or_else(|| panic!("stamp")),
        )
        .unwrap_or_default();
        assert!(h.sys.mariadb_scripts().contains(&replay));
        no_drift(&h).await?;
        Ok(())
    }

    async fn no_drift(h: &Harness) -> Result<()> {
        let drifts = crate::host::HostService::new(h.ctx.clone())
            .reconcile()
            .await?;
        assert!(drifts.is_empty(), "{drifts:?}");
        Ok(())
    }

    fn member_def(
        h: &Harness,
        backup: &JobRecord,
        name: &str,
    ) -> Result<Option<crate::records::DbObjectDef>> {
        let path = h.dir(backup).join("db-alice_wp.objects.json");
        let member: ObjectsMember =
            serde_json::from_slice(&std::fs::read(&path).map_err(|e| Error::io("read", &path, e))?)
                .unwrap_or_else(|e| panic!("{e}"));
        Ok(member.objects.into_iter().find(|o| o.name == name))
    }

    #[tokio::test]
    async fn a_failed_load_removes_the_new_database_again() -> Result<()> {
        let h = harness(false).await;
        with_database(&h, "alice").await?;
        let backup = h.backup("alice").await?;
        let (job, _) = h
            .backups
            .restore_database("alice", &backup.backup_id, "alice_wp", "alice_old")
            .await?;
        assert!(h.sys.mariadb_schema("alice_old").is_some());
        h.sys
            .script_stdout(bin::SYSTEMCTL, &failed("exit-code", worker::EXIT_LOAD));
        let done = h.finish(&job).await?;
        assert_eq!(done.state, JobState::Failed);
        assert_eq!(
            done.message,
            "the dump could not be loaded into the new database, which was removed again (see output)"
        );
        assert_eq!(h.sys.mariadb_schema("alice_old"), None);
        let old = crate::validate::DbName::parse("alice_old", "n")?;
        assert_eq!(h.ctx.store.load_database(&old)?, None);
        assert!(crate::host::HostService::new(h.ctx.clone())
            .reconcile()
            .await?
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn a_deleted_tenants_database_is_restored_into_its_new_account() -> Result<()> {
        let h = harness(false).await;
        let db = with_database(&h, "bob").await?;
        // A final backup kept for 5 days, then bob is deleted.
        let before = now_unix();
        let (fin, _) = h.backups.create("bob", 0, 5).await?;
        let fin = h.finish(&fin).await?;
        let rec = h.ctx.store.load_backup(&BackupId::parse(&fin.backup_id)?)?;
        let until = rec.map_or(0, |r| r.retain_until_unix);
        assert!(until >= before + 5 * 86_400 && until <= now_unix() + 5 * 86_400);
        db.delete_user("bob_app").await?;
        db.delete_database("bob_wp").await?;
        db.purge_trash("bob", "").await?;
        assert!(h.tenants.delete("bob", true).await?);
        h.tenants.create("bob", Limits::default(), "").await?;
        h.sys.clear_calls();
        // Only the operator's call reaches it, naming backup, source and target.
        assert!(matches!(
            h.backups
                .restore_database("bob", &fin.backup_id, "bob_wp", "bob_old")
                .await,
            Err(Error::BackupNotFound { .. })
        ));
        assert!(matches!(
            h.backups
                .restore_retained_database(&fin.backup_id, "alice", "bob", "bob_wp", "bob_old")
                .await,
            Err(Error::BackupNotFound { .. })
        ));
        assert!(matches!(
            h.backups
                .restore_retained_database(&fin.backup_id, "bob", "bob", "bob_wp", "alice_old")
                .await,
            Err(Error::InvalidInput {
                field: "new_name",
                ..
            })
        ));
        assert!(matches!(
            h.backups
                .restore_retained_database(&fin.backup_id, "bob", "carol", "bob_wp", "carol_old")
                .await,
            Err(Error::TenantNotFound(_))
        ));
        assert!(h.sys.calls_to(bin::SYSTEMD_RUN).is_empty());
        let (job, started) = h
            .backups
            .restore_retained_database(&fin.backup_id, "bob", "bob", "bob_wp", "bob_old")
            .await?;
        assert!(started && job.tenant == "bob");
        let argv = h
            .sys
            .calls_to(bin::SYSTEMD_RUN)
            .first()
            .map(args)
            .unwrap_or_default();
        let input = h.dir(&fin).join("db-bob_wp.sql.gz");
        assert!(argv.contains(&input.to_string_lossy().into_owned()));
        assert_eq!(h.finish(&job).await?.state, JobState::Succeeded);
        let old = crate::validate::DbName::parse("bob_old", "n")?;
        assert_eq!(
            h.ctx.store.load_database(&old)?.map(|r| r.state),
            Some(DbState::Ready)
        );
        Ok(())
    }

    #[tokio::test]
    async fn retention_can_be_given_in_days() -> Result<()> {
        let h = harness(false).await;
        for (months, days) in [(1, 1), (0, 367), (13, 0)] {
            assert!(matches!(
                h.backups.create("alice", months, days).await,
                Err(Error::InvalidInput { .. })
            ));
        }
        assert!(h.ctx.store.list_backups()?.is_empty());
        let before = now_unix();
        let (job, _) = h.backups.create("alice", 0, 10).await?;
        h.finish(&job).await?;
        let until = |h: &Harness| -> Result<u64> {
            Ok(h.ctx
                .store
                .load_backup(&BackupId::parse(&job.backup_id)?)?
                .map_or(0, |b| b.retain_until_unix))
        };
        let got = until(&h)?;
        assert!(got >= before + 10 * 86_400 && got <= now_unix() + 10 * 86_400);
        let before = now_unix();
        let rec = h.backups.retain("alice", &job.backup_id, 0, 3).await?;
        assert!(
            rec.retain_until_unix >= before + 3 * 86_400
                && rec.retain_until_unix <= now_unix() + 3 * 86_400
        );
        for (months, days) in [(1, 3), (0, 0), (0, 367)] {
            assert!(matches!(
                h.backups
                    .retain("alice", &job.backup_id, months, days)
                    .await,
                Err(Error::InvalidInput { .. })
            ));
        }
        Ok(())
    }
}
