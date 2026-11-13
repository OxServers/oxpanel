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

/// The running deletion (cascade) job of `tenant`, if there is one. Other
/// features refuse to start work for a tenant that is being deleted.
pub fn running_deletion(ctx: &Ctx, tenant: &Username) -> Result<Option<JobRecord>> {
    Ok(ctx.store.list_jobs()?.into_iter().find(|j| {
        j.tenant == tenant.as_str()
            && j.state == JobState::Running
            && j.kind == JobKind::DeleteTenant
    }))
}

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
        // A file job working in the home: wait for it (or suspend the tenant,
        // which stops it), like for a backup or restore. Refused before
        // anything is written.
        crate::files::refuse_tenant_deletion(&self.ctx, &name)?;
        if running.len() >= MAX_RUNNING_JOBS {
            return Err(Error::TooManyJobs);
        }
        let id = new_job_id(&self.ctx)?;
        let mut job =
            JobRecord::start(&id, JobKind::DeleteTenant, name.as_str(), "", String::new());
        job.final_backup_retain_days = final_backup_retain_days;
        // Once the tenant is being deleted, no final backup is taken any more
        // (it was either complete before, or not asked for).
        if final_backup_retain_days != 0 && rec.state == TenantState::Ready {
            PHASE_FINAL_BACKUP
        } else {
            PHASE_REMOVING
        }
        .clone_into(&mut job.phase);
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
                // Reported in the job (and completed by repeating the
                // request), like a failed backup: a warning, not an error.
                warn!(job = %id, tenant = %name, error = %e, "tenant deletion stopped");
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
                    format!(
                        "the final backup failed ({}); nothing was deleted",
                        child.message
                    ),
                )?;
                Ok(true)
            }
            JobState::Succeeded => {
                let _guard = self.ctx.lock.lock().await;
                let backup = self
                    .ctx
                    .store
                    .load_backup(&BackupId::parse(&child.backup_id)?)?;
                let kept = backup.is_some_and(|b| {
                    b.state == BackupState::Ready && b.retain_until_unix > now_unix()
                });
                if !kept {
                    self.finish(
                        job,
                        JobState::Failed,
                        format!(
                            "the final backup {} is not complete and retained; nothing was deleted",
                            child.backup_id
                        ),
                    )?;
                    return Ok(true);
                }
                job.backup_id = child.backup_id;
                PHASE_REMOVING.clone_into(&mut job.phase);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::DbEngine;
    use crate::system::{bin, CommandSpec};
    use crate::tenant::tests::{everything, running_file_job, upload_in_progress, Everything};

    /// alice with every feature (see `tenant::tests::everything`) plus a
    /// database in her trash, and the deletion service.
    async fn setup() -> Result<(Everything, LifecycleService)> {
        let all = everything().await?;
        all.db
            .create_database("alice", "alice_old", DbEngine::Mariadb)
            .await?;
        all.db.delete_database("alice_old").await?;
        let life = LifecycleService::new(all.ctx.clone(), all.backups.clone())
            .with_poll_interval(Duration::from_secs(3600));
        all.sys.clear_calls();
        Ok((all, life))
    }

    fn alice() -> Username {
        Username::parse("alice").unwrap_or_else(|e| panic!("{e}"))
    }

    async fn start(life: &LifecycleService, days: u32) -> Result<(JobRecord, JobId)> {
        let (job, started) = life
            .delete_cascade("alice", "alice", days)
            .await?
            .unwrap_or_else(|| panic!("no tenant"));
        assert!(started);
        let id = JobId::parse(&job.id)?;
        Ok((job, id))
    }

    fn load(all: &Everything, id: &JobId) -> Result<JobRecord> {
        Ok(all
            .ctx
            .store
            .load_job(id)?
            .unwrap_or_else(|| panic!("job {id}")))
    }

    /// The tenant still has everything it had.
    fn intact(all: &Everything) -> Result<()> {
        let rec = all.ctx.store.load_tenant(&alice())?;
        assert_eq!(rec.map(|r| r.state), Some(TenantState::Ready));
        assert_eq!(all.ctx.store.list_vhosts()?.len(), 2);
        assert_eq!(all.ctx.store.list_databases()?.len(), 1);
        assert_eq!(all.ctx.store.list_db_users()?.len(), 1);
        assert_eq!(all.ctx.store.list_trash()?.len(), 1);
        assert!(all.sys.mariadb_schema("alice_wp").is_some());
        Ok(())
    }

    /// Nothing of the tenant is left, apart from retained backups.
    async fn gone(all: &Everything) -> Result<()> {
        let store = &all.ctx.store;
        assert_eq!(store.load_tenant(&alice())?, None);
        assert!(store.list_vhosts()?.is_empty());
        assert!(store.list_databases()?.is_empty());
        assert!(store.list_db_users()?.is_empty());
        assert!(store.list_trash()?.is_empty());
        assert!(store
            .list_backups()?
            .iter()
            .all(|b| b.tenant_deleted && b.retain_until_unix != 0));
        assert!(all.sys.users().iter().all(|u| u.name != "alice"));
        assert_eq!(all.sys.mariadb_schema("alice_wp"), None);
        assert!(all.host.reconcile().await?.is_empty());
        Ok(())
    }

    fn position(calls: &[CommandSpec], what: impl Fn(&CommandSpec) -> bool, label: &str) -> usize {
        calls
            .iter()
            .position(what)
            .unwrap_or_else(|| panic!("no {label}"))
    }

    fn has(c: &CommandSpec, word: &str) -> bool {
        c.args.iter().any(|a| a == word)
    }

    #[tokio::test]
    async fn a_cascade_needs_the_name_twice_and_a_valid_retention() -> Result<()> {
        let (all, life) = setup().await?;
        let jobs = all.ctx.store.list_jobs()?.len();
        for confirm in ["", "Alice", "alice ", "bob"] {
            assert!(matches!(
                life.delete_cascade("alice", confirm, 0).await,
                Err(Error::InvalidInput {
                    field: "confirm_username",
                    ..
                })
            ));
        }
        for days in [367, u32::MAX] {
            assert!(matches!(
                life.delete_cascade("alice", "alice", days).await,
                Err(Error::InvalidInput {
                    field: "final_backup_retain_days",
                    ..
                })
            ));
        }
        assert!(matches!(
            life.delete_cascade("Alice!", "Alice!", 0).await,
            Err(Error::InvalidInput { .. })
        ));
        assert!(all.sys.calls().is_empty(), "nothing ran");
        assert_eq!(all.ctx.store.list_jobs()?.len(), jobs, "no job");
        intact(&all)?;
        assert_eq!(life.delete_cascade("ghost", "ghost", 0).await?, None);
        Ok(())
    }

    #[tokio::test]
    async fn a_cascade_removes_everything_in_order() -> Result<()> {
        let (all, life) = setup().await?;
        let (job, id) = start(&life, 0).await?;
        assert_eq!(
            (job.kind, job.phase.as_str(), job.backup_id.as_str()),
            (JobKind::DeleteTenant, PHASE_REMOVING, "")
        );
        assert!(life.step(&id).await?);
        let done = load(&all, &id)?;
        assert_eq!(done.state, JobState::Succeeded, "{}", done.message);
        assert_eq!(
            done.message,
            "tenant alice and everything it had were deleted"
        );
        let calls = all.sys.calls();
        let systemctl = |verb: &'static str, unit: &'static str| {
            move |c: &CommandSpec| c.program == bin::SYSTEMCTL && has(c, verb) && has(c, unit)
        };
        let order = [
            position(
                &calls,
                systemctl("disable", "oxpanel-php-alice.service"),
                "PHP stop",
            ),
            position(
                &calls,
                systemctl("disable", "oxpanel-app-app.example.com.service"),
                "application stop",
            ),
            position(&calls, |c| has(c, "reload-or-restart"), "nginx reload"),
            position(
                &calls,
                systemctl("stop", "user-20000.slice"),
                "SFTP sessions",
            ),
            position(
                &calls,
                |c| {
                    c.program == bin::MARIADB
                        && c.stdin.as_deref().is_some_and(|s| {
                            String::from_utf8_lossy(s).contains("DROP USER IF EXISTS 'alice_app'")
                        })
                },
                "database drop",
            ),
            position(
                &calls,
                |c| c.program == bin::USERDEL && has(c, "--remove"),
                "userdel",
            ),
        ];
        assert!(order.is_sorted(), "removal order {order:?}");
        gone(&all).await?;
        // Its own job stays to report the outcome; the tenant's others go.
        let jobs: Vec<String> = all
            .ctx
            .store
            .list_jobs()?
            .into_iter()
            .map(|j| j.id)
            .collect();
        assert_eq!(jobs, vec![job.id.clone()]);
        assert!(all.ctx.store.list_backups()?.is_empty(), "no final backup");
        // Repeating it finds no tenant.
        assert_eq!(life.delete_cascade("alice", "alice", 0).await?, None);
        Ok(())
    }

    /// The file manager and a cascade: the deletion waits for a running file
    /// job (refused before anything is written, like for a backup); while the
    /// final backup is taken, the tenant's files are not changed any more;
    /// a file job found running when the removal starts (a deletion resumed
    /// after a crash) is stopped before anything else; the file manager's job
    /// history and upload records go with the tenant.
    #[tokio::test]
    async fn a_cascade_waits_for_file_jobs_and_takes_the_file_managers_state_along() -> Result<()> {
        let (all, life) = setup().await?;
        let files = crate::files::FileService::new(all.ctx.clone());
        let running = running_file_job(&all.ctx, "alice", 1_794_000_000_001)?;
        assert!(matches!(
            life.delete_cascade("alice", "alice", 3).await,
            Err(Error::FileJobRunning { .. })
        ));
        assert!(all.sys.calls().is_empty(), "nothing ran");
        assert!(all
            .ctx
            .store
            .list_jobs()?
            .iter()
            .all(|j| j.kind != JobKind::DeleteTenant));
        intact(&all)?;
        let mut finished = running;
        finished.state = JobState::Succeeded;
        finished.finished_at_unix = now_unix();
        all.ctx.store.save_file_job(&finished)?;
        upload_in_progress(&all.ctx, "alice", 1_794_000_000_002)?;

        let (_, id) = start(&life, 3).await?;
        assert!(!life.step(&id).await?, "the final backup starts");
        all.sys.clear_calls();
        assert!(matches!(
            files.write("alice", "public_html/x.html", b"x", true).await,
            Err(Error::JobRunning { .. })
        ));
        assert!(matches!(
            files
                .start_upload("alice", "public_html/y.bin", false)
                .await,
            Err(Error::JobRunning { .. })
        ));
        assert!(
            all.sys.calls().is_empty(),
            "no worker ran for a refused change"
        );
        let child = all
            .ctx
            .store
            .list_jobs()?
            .into_iter()
            .find(|j| j.parent_job == id.as_str())
            .unwrap_or_else(|| panic!("no final backup job"));
        assert!(all.backups.step(&JobId::parse(&child.id)?).await?);
        assert!(!life.step(&id).await?, "on to the removal");
        // As if the daemon had stopped here and a file job had been left running.
        let stray = running_file_job(&all.ctx, "alice", 1_794_000_000_003)?;
        all.sys.clear_calls();
        assert!(life.step(&id).await?);
        let done = load(&all, &id)?;
        assert_eq!(done.state, JobState::Succeeded, "{}", done.message);
        let calls = all.sys.calls();
        let unit = format!("{}.service", stray.unit);
        let order = [
            position(
                &calls,
                |c| c.program == bin::SYSTEMCTL && has(c, "stop") && has(c, &unit),
                "file job stop",
            ),
            position(
                &calls,
                |c| {
                    c.program == bin::SYSTEMCTL
                        && has(c, "disable")
                        && has(c, "oxpanel-php-alice.service")
                },
                "PHP stop",
            ),
            position(
                &calls,
                |c| c.program == bin::USERDEL && has(c, "--remove"),
                "userdel",
            ),
        ];
        assert!(order.is_sorted(), "removal order {order:?}");
        gone(&all).await?;
        assert!(
            all.ctx.store.list_file_jobs()?.is_empty(),
            "file job history gone"
        );
        assert!(
            all.ctx.store.list_uploads()?.is_empty(),
            "upload records gone"
        );
        Ok(())
    }

    #[tokio::test]
    async fn nothing_is_deleted_when_the_final_backup_fails() -> Result<()> {
        let (all, life) = setup().await?;
        all.sys.set_worker_writes_nothing(true);
        let (job, id) = start(&life, 3).await?;
        assert_eq!(job.phase, PHASE_FINAL_BACKUP);
        assert!(!life.step(&id).await?, "the final backup starts");
        let child = all
            .ctx
            .store
            .list_jobs()?
            .into_iter()
            .find(|j| j.parent_job == job.id)
            .unwrap_or_else(|| panic!("no final backup job"));
        assert_eq!(child.kind, JobKind::Backup);
        intact(&all)?;
        assert!(!life.step(&id).await?, "waits for it");
        assert!(all.backups.step(&JobId::parse(&child.id)?).await?);
        assert!(life.step(&id).await?);
        let done = load(&all, &id)?;
        assert_eq!(done.state, JobState::Failed);
        assert!(
            done.message.contains("nothing was deleted"),
            "{}",
            done.message
        );
        intact(&all)?;
        assert!(all.host.reconcile().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn a_complete_final_backup_is_kept_and_then_everything_goes() -> Result<()> {
        let (all, life) = setup().await?;
        let before = now_unix();
        let (_, id) = start(&life, 3).await?;
        assert!(!life.step(&id).await?);
        let child = all
            .ctx
            .store
            .list_jobs()?
            .into_iter()
            .find(|j| j.parent_job == id.as_str())
            .unwrap_or_else(|| panic!("no final backup job"));
        intact(&all)?;
        assert!(all.backups.step(&JobId::parse(&child.id)?).await?);
        assert!(!life.step(&id).await?, "on to the removal");
        let job = load(&all, &id)?;
        assert_eq!(
            (job.phase.as_str(), job.backup_id.as_str()),
            (PHASE_REMOVING, child.backup_id.as_str())
        );
        assert!(life.step(&id).await?);
        let done = load(&all, &id)?;
        assert_eq!(done.state, JobState::Succeeded, "{}", done.message);
        assert!(done.message.contains(&format!(
            "the final backup {} is kept for 3 days",
            child.backup_id
        )));
        gone(&all).await?;
        let retained = all.backups.list_retained().await?;
        let [fin] = retained.as_slice() else {
            panic!("{retained:?}");
        };
        assert_eq!(fin.id, child.backup_id);
        assert!(fin.tenant_deleted && fin.state == BackupState::Ready);
        assert!(
            fin.retain_until_unix >= before + 3 * 86_400
                && fin.retain_until_unix <= now_unix() + 3 * 86_400
        );
        let dbs: Vec<&str> = fin.databases.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(dbs, vec!["alice_wp"], "the trash is not backed up");
        Ok(())
    }

    #[tokio::test]
    async fn one_job_at_a_time_and_the_refusing_delete_waits() -> Result<()> {
        let (all, life) = setup().await?;
        let (job, _) = start(&life, 3).await?;
        let (again, started) = life
            .delete_cascade("alice", "alice", 3)
            .await?
            .unwrap_or_else(|| panic!("no tenant"));
        assert!(!started && again.id == job.id);
        assert!(all.tenants.delete("alice", true).await.is_err());
        assert!(matches!(
            all.backups.create("alice", 0, 0).await,
            Err(Error::JobRunning { .. })
        ));
        intact(&all)?;
        // A tenant with nothing left is still not deleted under a cascade's feet.
        all.tenants
            .create("bob", crate::validate::Limits::default(), "")
            .await?;
        let (bobs, started) = life
            .delete_cascade("bob", "bob", 3)
            .await?
            .unwrap_or_else(|| panic!("no tenant"));
        assert!(started);
        assert!(matches!(
            all.tenants.delete("bob", true).await,
            Err(Error::JobRunning { job, .. }) if job == bobs.id
        ));

        // Another job of the tenant in flight: no cascade.
        let (other, life) = setup().await?;
        let (backup, _) = other.backups.create("alice", 0, 0).await?;
        assert!(matches!(
            life.delete_cascade("alice", "alice", 0).await,
            Err(Error::JobRunning { job, .. }) if job == backup.id
        ));
        intact(&other)?;
        Ok(())
    }

    #[tokio::test]
    async fn a_half_done_deletion_is_completed_by_repeating_the_request() -> Result<()> {
        let (all, life) = setup().await?;
        let (_, id) = start(&life, 0).await?;
        // The database step cannot run: the job stops there.
        all.sys.set_mariadb_running(false);
        assert!(life.step(&id).await?);
        let failed = load(&all, &id)?;
        assert_eq!(failed.state, JobState::Failed);
        assert!(
            failed.message.contains("repeat DeleteTenant with cascade"),
            "{}",
            failed.message
        );
        let rec = all.ctx.store.load_tenant(&alice())?;
        assert_eq!(rec.map(|r| r.state), Some(TenantState::Deleting));
        assert!(
            all.ctx.store.list_vhosts()?.is_empty(),
            "sites already gone"
        );
        assert_eq!(
            all.ctx.store.list_databases()?.len(),
            1,
            "databases not yet"
        );
        // MariaDB is back; the same request (even asking for a final backup,
        // which a tenant being deleted no longer gets) finishes it.
        all.sys.set_mariadb_running(true);
        let (job, started) = life
            .delete_cascade("alice", "alice", 3)
            .await?
            .unwrap_or_else(|| panic!("no tenant"));
        assert!(started && job.id != id.as_str());
        assert_eq!(job.phase, PHASE_REMOVING);
        assert!(life.step(&JobId::parse(&job.id)?).await?);
        assert_eq!(
            load(&all, &JobId::parse(&job.id)?)?.state,
            JobState::Succeeded
        );
        gone(&all).await
    }

    #[tokio::test]
    async fn a_deletion_left_running_is_resumed_at_start_up() -> Result<()> {
        let (all, _) = setup().await?;
        // As if the daemon had died in the middle of a deletion.
        let id = JobId::from_millis(1_731_500_000_123);
        let mut job = JobRecord::start(&id, JobKind::DeleteTenant, "alice", "", String::new());
        PHASE_REMOVING.clone_into(&mut job.phase);
        all.ctx.store.save_job(&job)?;
        let life = LifecycleService::new(all.ctx.clone(), all.backups.clone())
            .with_poll_interval(Duration::from_millis(10));
        assert_eq!(life.resume_all().await?, 1);
        for _ in 0..500 {
            if load(&all, &id)?.state != JobState::Running {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(load(&all, &id)?.state, JobState::Succeeded);
        gone(&all).await?;
        assert_eq!(life.resume_all().await?, 0);
        Ok(())
    }
}
