//! Deleting a tenant with everything it has (`DeleteTenant` with `cascade`),
//! as a job.
//!
//! The owner wants the panel to delete a customer in one go, after one
//! prompt with friction. The engine keeps refusing by default; the cascade
//! is explicit, needs the `delete` scope, and the request must repeat the
//! tenant's name (`confirm_username`), so that a stray or forged call cannot
//! wipe a customer.
//!
//! Optionally a **final backup** (files and databases) is taken first and
//! kept for 1–366 days after the deletion. Nothing is destroyed until that
//! backup is complete, sealed and retained; if it fails, the job fails and
//! the tenant is untouched.
//!
//! The work is a job (`JobKind::DeleteTenant`) because it can be long (the
//! final backup) and must survive a restart: its record says where it stands
//! (`phase`), the daemon re-drives every running deletion at start-up, and a
//! repeated request returns the running job or — for a tenant left in
//! `deleting` by a failed one — starts a new one that completes it. The
//! removal itself runs in the daemon, under the mutation lock
//! ([`crate::tenant::TenantService::remove_everything`]); every step is
//! idempotent and driven by records.

use std::time::Duration;

use tracing::{error, info, warn};

use crate::backup::{BackupService, MAX_RUNNING_JOBS};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::records::{now_unix, BackupState, JobKind, JobRecord, JobState, TenantState};
use crate::tenant::TenantService;
use crate::validate::{retain_days, BackupId, JobId, Username};

/// The final backup is being taken (nothing has been deleted).
pub const PHASE_FINAL_BACKUP: &str = "final-backup";
/// Everything is being removed.
pub const PHASE_REMOVING: &str = "removing";

const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Consecutive faults after which a driver stops looking at its job.
const MAX_DRIVER_FAULTS: u32 = 30;

#[derive(Debug, Clone)]
pub struct LifecycleService {
    ctx: Ctx,
    backups: BackupService,
    tenants: TenantService,
    poll: Duration,
}

/// A fresh job identifier (the caller holds the mutation lock).
fn new_job_id(ctx: &Ctx) -> Result<JobId> {
    let mut millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    loop {
        let id = JobId::from_millis(millis);
        if ctx.store.load_job(&id)?.is_none() {
            return Ok(id);
        }
        millis += 1;
    }
}

impl LifecycleService {
    pub fn new(ctx: Ctx, backups: BackupService) -> Self {
        Self {
            tenants: TenantService::new(ctx.clone()),
            ctx,
            backups,
            poll: POLL_INTERVAL,
        }
    }

    /// How often a running deletion is looked at (tests shorten it).
    #[must_use]
    pub fn with_poll_interval(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }

    /// Start the deletion of `username` with everything it has, or return
    /// the one already running. `None`: there is no such tenant.
    pub async fn delete_cascade(
        &self,
        username: &str,
        confirm_username: &str,
        final_backup_retain_days: u32,
    ) -> Result<Option<(JobRecord, bool)>> {
        let name = Username::parse(username)?;
        // The friction: the request names the tenant twice.
        if confirm_username != name.as_str() {
            return Err(Error::invalid(
                "confirm_username",
                "must repeat the tenant's name exactly to delete it with everything it has",
            ));
        }
        if final_backup_retain_days != 0 {
            retain_days(final_backup_retain_days, "final_backup_retain_days")?;
        }
        let guard = self.ctx.lock.lock().await;
        let Some(rec) = self.ctx.store.load_tenant(&name)? else {
            if self.ctx.sys.user_by_name(name.as_str()).await?.is_some() {
                return Err(Error::NotManaged(name.to_string()));
            }
            return Ok(None);
        };
        let running: Vec<JobRecord> = self
            .ctx
            .store
            .list_jobs()?
            .into_iter()
            .filter(|j| j.state == JobState::Running)
            .collect();
        if let Some(job) = running.iter().find(|j| j.tenant == name.as_str()) {
            return if job.kind == JobKind::DeleteTenant {
                Ok(Some((job.clone(), false)))
            } else {
                Err(Error::JobRunning {
                    tenant: name.to_string(),
                    job: job.id.clone(),
                })
            };
        }
        if running.len() >= MAX_RUNNING_JOBS {
            return Err(Error::TooManyJobs);
        }
        let id = new_job_id(&self.ctx)?;
        let mut job = JobRecord::start(&id, JobKind::DeleteTenant, name.as_str(), "", String::new());
        job.final_backup_retain_days = final_backup_retain_days;
        // Once the tenant is being deleted, no final backup is taken any more
        // (it was either complete before, or not asked for).
        job.phase = if final_backup_retain_days != 0 && rec.state == TenantState::Ready {
            PHASE_FINAL_BACKUP
        } else {
            PHASE_REMOVING
        }
        .to_owned();
        self.ctx.store.save_job(&job)?;
        drop(guard);
        info!(job = %id, tenant = %name, final_backup_days = final_backup_retain_days, "tenant deletion started");
        self.spawn_driver(id);
        Ok(Some((job, true)))
    }

    /// Pick up every deletion that was running when the daemon last stopped.
    pub async fn resume_all(&self) -> Result<usize> {
        let jobs: Vec<JobRecord> = self
            .ctx
            .store
            .list_jobs()?
            .into_iter()
            .filter(|j| j.state == JobState::Running && j.kind == JobKind::DeleteTenant)
            .collect();
        for job in &jobs {
            info!(job = %job.id, tenant = %job.tenant, phase = %job.phase, "resuming tenant deletion");
            self.spawn_driver(JobId::parse(&job.id)?);
        }
        Ok(jobs.len())
    }

    fn spawn_driver(&self, id: JobId) {
        tokio::spawn(self.clone().drive(id));
    }

    async fn drive(self, id: JobId) {
        let mut faults = 0;
        loop {
            match self.step(&id).await {
                Ok(true) => return,
                Ok(false) => faults = 0,
                Err(e) => {
                    faults += 1;
                    warn!(job = %id, error = %e, faults, "could not advance the tenant deletion; will retry");
                    if faults >= MAX_DRIVER_FAULTS {
                        error!(job = %id, "giving up on the tenant deletion until the next start; repeat the request");
                        return;
                    }
                }
            }
            tokio::time::sleep(self.poll).await;
        }
    }

    /// Advance a deletion by one step. Returns whether it is finished.
    pub async fn step(&self, id: &JobId) -> Result<bool> {
        let Some(job) = self.ctx.store.load_job(id)? else {
            return Ok(true);
        };
        if job.state != JobState::Running || job.kind != JobKind::DeleteTenant {
            return Ok(true);
        }
        let name = Username::parse_field(&job.tenant, "tenant")?;
        if job.phase == PHASE_FINAL_BACKUP {
            return self.final_backup(job, id, &name).await;
        }
        let _guard = self.ctx.lock.lock().await;
        match self.tenants.remove_everything(&name, id).await {
            Ok(()) => {
                let kept = if job.backup_id.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; the final backup {} is kept for {} days (ListRetainedBackups)",
                        job.backup_id, job.final_backup_retain_days
                    )
                };
                info!(job = %id, tenant = %name, "tenant deleted with everything it had");
                self.finish(
                    job,
                    JobState::Succeeded,
                    format!("tenant {name} and everything it had were deleted{kept}"),
                )?;
            }
            Err(e) => {
                error!(job = %id, tenant = %name, error = %e, "tenant deletion stopped");
                self.finish(
                    job,
                    JobState::Failed,
                    format!("the deletion stopped at a step that failed ({e}); repeat DeleteTenant with cascade to complete it"),
                )?;
            }
        }
        Ok(true)
    }

    /// The final-backup phase: start the backup, wait for it, and go on to
    /// the removal only when it is complete and retained.
    async fn final_backup(&self, mut job: JobRecord, id: &JobId, name: &Username) -> Result<bool> {
        let child = self
            .ctx
            .store
            .list_jobs()?
            .into_iter()
            .find(|j| j.parent_job == job.id && j.kind == JobKind::Backup);
        let Some(child) = child else {
            let secs = u64::from(job.final_backup_retain_days) * 86_400;
            return match self.backups.create_job(name, secs, Some(id)).await {
                Ok((child, _)) => {
                    info!(job = %id, backup_job = %child.id, tenant = %name, "final backup started");
                    Ok(false)
                }
                Err(e) => {
                    let _guard = self.ctx.lock.lock().await;
                    self.finish(
                        job,
                        JobState::Failed,
                        format!("the final backup could not be started ({e}); nothing was deleted"),
                    )?;
                    Ok(true)
                }
            };
        };
        match child.state {
            JobState::Running => Ok(false),
            JobState::Failed => {
                let _guard = self.ctx.lock.lock().await;
                self.finish(
                    job,
                    JobState::Failed,
                    format!("the final backup failed ({}); nothing was deleted", child.message),
                )?;
                Ok(true)
            }
            JobState::Succeeded => {
                let _guard = self.ctx.lock.lock().await;
                let backup = self.ctx.store.load_backup(&BackupId::parse(&child.backup_id)?)?;
                let kept = backup.is_some_and(|b| {
                    b.state == BackupState::Ready && b.retain_until_unix > now_unix()
                });
                if !kept {
                    self.finish(
                        job,
                        JobState::Failed,
                        format!("the final backup {} is not complete and retained; nothing was deleted", child.backup_id),
                    )?;
                    return Ok(true);
                }
                job.backup_id = child.backup_id;
                job.phase = PHASE_REMOVING.to_owned();
                self.ctx.store.save_job(&job)?;
                info!(job = %id, tenant = %name, backup = %job.backup_id, "final backup complete and retained; removing the tenant");
                Ok(false)
            }
        }
    }

    fn finish(&self, mut job: JobRecord, state: JobState, message: String) -> Result<()> {
        job.state = state;
        job.message = message;
        job.finished_at_unix = now_unix();
        self.ctx.store.save_job(&job)
    }
}
