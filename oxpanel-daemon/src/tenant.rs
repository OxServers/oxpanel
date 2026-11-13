//! Tenant lifecycle: create / get / list / delete.
//!
//! A tenant is a dedicated POSIX account (login disabled) with a private
//! `0700` home and a systemd slice carrying its resource limits. The workflow
//! is resumable: the record is written as soon as the account exists, so a
//! crash half-way through leaves a `Provisioning` record that the next
//! identical `CreateTenant` call completes.

use tracing::{info, warn};

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::records::{now_unix, TenantRecord, TenantState, RECORD_VERSION};
use crate::system::{bin, CommandSpec};
use crate::systemd;
use crate::validate::{Limits, OwnerLabel, Username};
use crate::vhost;
use crate::{quota, sftp};

const GECOS: &str = "OxPanel tenant";

/// A point-in-time measurement of what a tenant consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TenantUsage {
    pub memory_current_bytes: u64,
    pub cpu_usage_nsec: u64,
    pub tasks_current: u64,
    pub disk_usage_bytes: u64,
    pub measured_at_unix: u64,
}

/// Sum `MemoryCurrent`, `CPUUsageNSec` and `TasksCurrent` over the units in a
/// `systemctl show` listing. Units with nothing running report `[not set]`
/// (or 2^64-1 on older systemd); both count as zero.
pub(crate) fn parse_cgroup_usage(show_output: &str) -> (u64, u64, u64) {
    let (mut mem, mut cpu, mut tasks) = (0u64, 0u64, 0u64);
    for line in show_output.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let Some(n) = value.trim().parse::<u64>().ok().filter(|n| *n != u64::MAX) else {
            continue;
        };
        match key {
            "MemoryCurrent" => mem = mem.saturating_add(n),
            "CPUUsageNSec" => cpu = cpu.saturating_add(n),
            "TasksCurrent" => tasks = tasks.saturating_add(n),
            _ => {}
        }
    }
    (mem, cpu, tasks)
}

#[derive(Debug, Clone)]
pub struct TenantService {
    ctx: Ctx,
}

impl TenantService {
    pub fn new(ctx: Ctx) -> Self {
        Self { ctx }
    }

    /// Create a tenant, or confirm an identical existing one.
    /// Returns the record and whether it was newly created.
    pub async fn create(
        &self,
        username: &str,
        limits: Limits,
        owner: &str,
    ) -> Result<(TenantRecord, bool)> {
        let name = Username::parse(username)?;
        let owner = OwnerLabel::parse_optional(owner)?.map_or_else(String::new, |o| o.to_string());
        let _guard = self.ctx.lock.lock().await;

        if let Some(rec) = self.ctx.store.load_tenant(&name)? {
            return match rec.state {
                TenantState::Deleting => Err(Error::TenantNotReady(name.to_string())),
                TenantState::Ready | TenantState::Provisioning
                    if rec.limits != limits || rec.owner != owner =>
                {
                    Err(Error::SpecMismatch(name.to_string()))
                }
                TenantState::Ready => {
                    // Idempotent replay: confirm the account still exists.
                    if self.ctx.sys.user_by_name(name.as_str()).await?.is_none() {
                        return Err(Error::Internal(format!(
                            "record for '{name}' exists but the account is gone; manual repair needed"
                        )));
                    }
                    Ok((rec, false))
                }
                TenantState::Provisioning => {
                    info!(tenant = %name, "resuming interrupted provisioning");
                    let rec = self.ensure_account(rec).await?;
                    let rec = self.finalize(rec).await?;
                    Ok((rec, true))
                }
            };
        }

        // A disk limit this host cannot enforce is refused before anything exists.
        quota::require_available(&self.ctx, &limits).await?;
        // No record: the name must be entirely unused. Never adopt an account
        // OxPanel did not create.
        if self.ctx.sys.user_by_name(name.as_str()).await?.is_some() {
            return Err(Error::NotManaged(name.to_string()));
        }
        if self.ctx.sys.group_by_name(name.as_str()).await?.is_some() {
            return Err(Error::NotManaged(name.to_string()));
        }

        let uid = self.allocate_uid().await?;
        let rec = TenantRecord {
            version: RECORD_VERSION,
            username: name.to_string(),
            uid,
            gid: uid,
            home: self.ctx.config.home_base.join(name.as_str()),
            limits,
            slice_unit: systemd::slice_unit_name(&name),
            created_at_unix: now_unix(),
            state: TenantState::Provisioning,
            owner,
            suspended: false,
            sftp_keys: Vec::new(),
            sftp_password: false,
        };
        // Claim the name and uid *before* the irreversible step, so a crash
        // can never leave behind an account the daemon refuses to recognise.
        self.ctx.store.save_tenant(&rec)?;
        let rec = self.ensure_account(rec).await?;
        let rec = self.finalize(rec).await?;
        Ok((rec, true))
    }

    /// Run `useradd` for a claimed record unless the account already exists,
    /// then make the record match the account database.
    async fn ensure_account(&self, mut rec: TenantRecord) -> Result<TenantRecord> {
        let name = Username::parse(&rec.username)?;
        let timeout = self.ctx.config.command_timeout;
        let user = if let Some(u) = self.ctx.sys.user_by_name(name.as_str()).await? {
            u
        } else {
            let cmd = CommandSpec::new(bin::USERADD, timeout)
                .arg("--uid")
                .arg(rec.uid.to_string())
                .arg("--user-group")
                .arg("--home-dir")
                .arg(&rec.home)
                .arg("--create-home")
                .arg("--shell")
                .arg(bin::NOLOGIN)
                .arg("--comment")
                .arg(GECOS)
                .arg("--key")
                .arg("HOME_MODE=0700")
                .arg(name.as_str());
            self.ctx.sys.run_ok(cmd).await?;
            let u = self
                .ctx
                .sys
                .user_by_name(name.as_str())
                .await?
                .ok_or_else(|| {
                    Error::Internal(format!("useradd succeeded but '{name}' cannot be resolved"))
                })?;
            info!(tenant = %name, uid = u.uid, gid = u.gid, home = %u.home.display(), "account created");
            u
        };
        if user.uid != rec.uid {
            warn!(tenant = %name, requested = rec.uid, actual = user.uid, "account has a different uid than claimed");
        }
        if (rec.uid, rec.gid, rec.home.as_path()) != (user.uid, user.gid, user.home.as_path()) {
            rec.uid = user.uid;
            rec.gid = user.gid;
            rec.home = user.home;
            self.ctx.store.save_tenant(&rec)?;
        }
        Ok(rec)
    }

    /// Idempotent post-`useradd` steps.
    async fn finalize(&self, mut rec: TenantRecord) -> Result<TenantRecord> {
        let name = Username::parse(&rec.username)?;
        let timeout = self.ctx.config.command_timeout;
        self.ctx
            .sys
            .ensure_private_dir(&rec.home, rec.uid, rec.gid)
            .await?;
        // Every tenant is a member of the group sshd confines to SFTP.
        sftp::ensure_membership(&self.ctx, &rec).await?;
        // Also without a disk limit: the uid may have had one before.
        quota::apply(&self.ctx, &rec).await?;
        systemd::apply_tenant_limits(
            self.ctx.sys.as_ref(),
            &self.ctx.config.systemd_unit_dir,
            &name,
            rec.uid,
            &rec.limits,
            timeout,
        )
        .await?;
        if self.ctx.selinux {
            self.ctx
                .sys
                .run_ok(
                    CommandSpec::new(bin::RESTORECON, timeout)
                        .arg("-R")
                        .arg(&rec.home),
                )
                .await?;
        }
        rec.state = TenantState::Ready;
        self.ctx.store.save_tenant(&rec)?;
        info!(tenant = %name, "tenant ready");
        Ok(rec)
    }

    /// Lowest free uid in the configured range that neither a record nor the
    /// account database claims.
    async fn allocate_uid(&self) -> Result<u32> {
        let (min, max) = (self.ctx.config.uid_min, self.ctx.config.uid_max);
        let taken: std::collections::BTreeSet<u32> = self
            .ctx
            .store
            .list_tenants()?
            .into_iter()
            .map(|t| t.uid)
            .collect();
        for uid in min..=max {
            if taken.contains(&uid) {
                continue;
            }
            if self.ctx.sys.user_by_uid(uid).await?.is_none() {
                return Ok(uid);
            }
        }
        Err(Error::UidExhausted { min, max })
    }

    pub async fn get(&self, username: &str) -> Result<TenantRecord> {
        let name = Username::parse(username)?;
        self.ctx
            .store
            .load_tenant(&name)?
            .ok_or_else(|| Error::TenantNotFound(name.to_string()))
    }

    /// All tenants, optionally only those with the given owner label.
    pub async fn list(&self, owner: Option<&str>) -> Result<Vec<TenantRecord>> {
        let filter = match owner {
            Some(o) if !o.is_empty() => OwnerLabel::parse_optional(o)?.map(|o| o.to_string()),
            _ => None,
        };
        let mut all = self.ctx.store.list_tenants()?;
        if let Some(o) = filter {
            all.retain(|t| t.owner == o);
        }
        Ok(all)
    }

    /// A tenant that exists and is fully provisioned, for the update RPCs.
    fn load_ready(&self, name: &Username) -> Result<TenantRecord> {
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

    /// Replace the tenant's limits. The record is written first, so a failed
    /// `daemon-reload` is completed by repeating the request: the unit files
    /// are re-applied even when the record already carries these limits.
    pub async fn update_limits(
        &self,
        username: &str,
        limits: Limits,
    ) -> Result<(TenantRecord, bool)> {
        let name = Username::parse(username)?;
        let _guard = self.ctx.lock.lock().await;
        let mut rec = self.load_ready(&name)?;
        quota::require_available(&self.ctx, &limits).await?;
        let changed = rec.limits != limits;
        if changed {
            rec.limits = limits;
            self.ctx.store.save_tenant(&rec)?;
        }
        systemd::apply_tenant_limits(
            self.ctx.sys.as_ref(),
            &self.ctx.config.systemd_unit_dir,
            &name,
            rec.uid,
            &rec.limits,
            self.ctx.config.command_timeout,
        )
        .await?;
        quota::apply(&self.ctx, &rec).await?;
        if changed {
            info!(tenant = %name, "limits updated");
        }
        Ok((rec, changed))
    }

    /// Replace the tenant's owner label; an empty label clears it.
    pub async fn update_owner(&self, username: &str, owner: &str) -> Result<(TenantRecord, bool)> {
        let name = Username::parse(username)?;
        let owner = OwnerLabel::parse_optional(owner)?.map_or_else(String::new, |o| o.to_string());
        let _guard = self.ctx.lock.lock().await;
        let mut rec = self.load_ready(&name)?;
        if rec.owner == owner {
            return Ok((rec, false));
        }
        info!(tenant = %name, from = %rec.owner, to = %owner, "owner updated");
        rec.owner = owner;
        self.ctx.store.save_tenant(&rec)?;
        Ok((rec, true))
    }

    /// Suspend or resume: every virtual host of the tenant is re-rendered
    /// (503 while suspended), validated and activated; only then is the
    /// record updated, so an interrupted attempt is simply repeated.
    ///
    /// The order across features (docs/superpowers/specs/2026-11-13-integration-design.md):
    /// suspend: the sites answer 503 first, then the tenant's processes stop
    /// (PHP, applications), then its access is cut (SFTP keys, password and
    /// sessions; database accounts locked and their sessions killed, last,
    /// when nothing is left that could reconnect). Resume is the reverse:
    /// access, then processes, then the sites — so no request sees a 502 and
    /// nothing starts that cannot reach its database.
    pub async fn set_suspended(
        &self,
        username: &str,
        suspended: bool,
    ) -> Result<(TenantRecord, bool)> {
        let name = Username::parse(username)?;
        let _guard = self.ctx.lock.lock().await;
        let mut rec = self.load_ready(&name)?;
        let changed = rec.suspended != suspended;
        rec.suspended = suspended;
        if changed && !suspended {
            self.restore_access(&rec).await?;
            crate::php::set_running(&self.ctx, &rec, true).await?;
            crate::app::set_running_all(&self.ctx, &rec, true).await?;
        }
        vhost::sync_tenant_configs(&self.ctx, &rec, changed).await?;
        if changed {
            if suspended {
                crate::php::set_running(&self.ctx, &rec, false).await?;
                crate::app::set_running_all(&self.ctx, &rec, false).await?;
                // The keys file goes away, the password hash is locked and
                // running sessions are ended.
                sftp::suspend_access(&self.ctx, &rec).await?;
                // Last: nothing of the tenant's is running that could
                // reconnect; its database accounts are locked and their
                // sessions ended.
                crate::db::set_locked_all(&self.ctx, &rec, true).await?;
            }
            self.ctx.store.save_tenant(&rec)?;
            info!(tenant = %name, suspended, "suspension changed");
        }
        Ok((rec, changed))
    }

    /// Resume, first step: database accounts are unlocked (PHP and
    /// applications connect as they start) and SFTP access is given back.
    async fn restore_access(&self, rec: &TenantRecord) -> Result<()> {
        crate::db::set_locked_all(&self.ctx, rec, false).await?;
        if sftp::has_access(rec) {
            // A host whose sshd cannot take the keys right now must not keep
            // the sites down. `Reconcile` reports the missing keys file until
            // access is restored (a password stays locked until then).
            if let Err(e) = sftp::ensure_access(&self.ctx, rec).await {
                warn!(tenant = %rec.username, error = %e, "resuming, but SFTP access could not be restored");
            }
        }
        Ok(())
    }

    /// Why a tenant cannot be deleted yet, if it cannot: it still owns
    /// virtual hosts, databases or database users, backups that are not
    /// retained, or a backup or restore job is running. Reads records only.
    fn refuse_deletion(&self, name: &Username) -> Result<()> {
        if self
            .ctx
            .store
            .list_vhosts()?
            .iter()
            .any(|v| v.tenant == name.as_str())
        {
            return Err(Error::TenantHasVHosts(name.to_string()));
        }
        // Databases are data: dropping them is always an explicit request.
        if crate::db::tenant_has_objects(&self.ctx, name)? {
            return Err(Error::TenantHasDatabases(name.to_string()));
        }
        // Backups are the tenant's data too: they are deleted explicitly,
        // never as a side effect, and no job may be in flight.
        crate::backup::refuse_tenant_deletion(&self.ctx, name)
    }

    /// Memory, CPU and task counts from systemd (tenant slice plus login
    /// slice) and the disk space allocated under the home. Read-only.
    pub async fn usage(&self, username: &str) -> Result<TenantUsage> {
        let name = Username::parse(username)?;
        let rec = self.load_ready(&name)?;
        let timeout = self.ctx.config.command_timeout;
        let show = self
            .ctx
            .sys
            .run_ok(
                CommandSpec::new(bin::SYSTEMCTL, timeout)
                    .args([
                        "show",
                        "--property=MemoryCurrent",
                        "--property=CPUUsageNSec",
                        "--property=TasksCurrent",
                        "--",
                    ])
                    .arg(&rec.slice_unit)
                    .arg(format!("user-{}.slice", rec.uid)),
            )
            .await?;
        let (memory_current_bytes, cpu_usage_nsec, tasks_current) =
            parse_cgroup_usage(&show.stdout_lossy());
        // The quota system knows without walking the tree, when it is on.
        match quota::usage(&self.ctx, rec.uid).await {
            Ok(Some(row)) => {
                return Ok(TenantUsage {
                    memory_current_bytes,
                    cpu_usage_nsec,
                    tasks_current,
                    disk_usage_bytes: row.used_bytes,
                    measured_at_unix: now_unix(),
                })
            }
            Ok(None) => {}
            Err(e) => {
                warn!(tenant = %name, error = %e, "quota report failed; measuring the home instead");
            }
        }
        // -x: stay on the home's file system; du never follows symlinks.
        let du = self
            .ctx
            .sys
            .run_ok(
                CommandSpec::new(bin::DU, timeout)
                    .args(["--summarize", "--one-file-system", "--block-size=1", "--"])
                    .arg(&rec.home),
            )
            .await?;
        let disk_usage_bytes = du
            .stdout_lossy()
            .split_whitespace()
            .next()
            .and_then(|n| n.parse::<u64>().ok())
            .ok_or_else(|| Error::Internal(format!("unexpected du output for '{name}'")))?;
        Ok(TenantUsage {
            memory_current_bytes,
            cpu_usage_nsec,
            tasks_current,
            disk_usage_bytes,
            measured_at_unix: now_unix(),
        })
    }

    /// Delete a tenant OxPanel created. Returns `false` if it did not exist.
    pub async fn delete(&self, username: &str, remove_home: bool) -> Result<bool> {
        let name = Username::parse(username)?;
        let _guard = self.ctx.lock.lock().await;

        let Some(mut rec) = self.ctx.store.load_tenant(&name)? else {
            if self.ctx.sys.user_by_name(name.as_str()).await?.is_some() {
                return Err(Error::NotManaged(name.to_string()));
            }
            return Ok(false);
        };
        // Every refusal before anything is changed or destroyed.
        self.refuse_deletion(&name)?;
        if rec.state != TenantState::Deleting {
            rec.state = TenantState::Deleting;
            self.ctx.store.save_tenant(&rec)?;
        }
        // Retained backups outlive the tenant, detached from its name.
        crate::backup::detach_retained(&self.ctx, &name)?;
        self.remove_account(&rec, remove_home, None).await?;
        Ok(true)
    }

    /// The end of every deletion: SFTP access, the uid's disk quota, the
    /// account (and, with `remove_home`, its home), the slice units, the job
    /// history (except `keep_job`, the deletion's own job) and the record.
    /// The caller holds the mutation lock and has marked the record
    /// `deleting`. Idempotent.
    async fn remove_account(
        &self,
        rec: &TenantRecord,
        remove_home: bool,
        keep_job: Option<&crate::validate::JobId>,
    ) -> Result<()> {
        let name = Username::parse(&rec.username)?;
        let timeout = self.ctx.config.command_timeout;
        // SFTP first: the home must not be removed while it is still mounted
        // into the chroot directory, and userdel refuses an account that has
        // running sessions (`remove_access` ends them). The password and the
        // group memberships go with the account.
        sftp::remove_access(&self.ctx, rec, true).await?;
        // The uid will be given to another tenant one day; not its limits.
        quota::clear(&self.ctx, rec.uid).await?;
        if self.ctx.sys.user_by_name(name.as_str()).await?.is_some() {
            let mut cmd = CommandSpec::new(bin::USERDEL, timeout);
            if remove_home {
                cmd = cmd.arg("--remove");
            }
            self.ctx.sys.run_ok(cmd.arg(name.as_str())).await?;
            info!(tenant = %name, remove_home, "account deleted");
        } else {
            info!(tenant = %name, "account already gone; finishing deletion");
        }
        systemd::remove_tenant_limits(
            self.ctx.sys.as_ref(),
            &self.ctx.config.systemd_unit_dir,
            &name,
            rec.uid,
            timeout,
        )
        .await?;
        crate::backup::forget_tenant_jobs(&self.ctx, &name, keep_job)?;
        self.ctx.store.delete_tenant(&name)?;
        Ok(())
    }

    /// Delete a tenant with everything it has, in this order: PHP and
    /// applications stopped, every site removed (with its certificate,
    /// Automatic HTTPS state, logs, PHP pool and application unit), SFTP
    /// access, every database user, database and the database trash
    /// (dropped at once), the backups that are not retained, then the
    /// account with its home. Retained backups (a final one among them)
    /// outlive it, detached from the name. Every step is idempotent and
    /// driven by records, so repeating this after a crash completes it.
    /// The caller (`lifecycle`) holds the mutation lock.
    pub(crate) async fn remove_everything(
        &self,
        name: &Username,
        job: &crate::validate::JobId,
    ) -> Result<()> {
        let Some(mut rec) = self.ctx.store.load_tenant(name)? else {
            return Ok(());
        };
        if rec.state != TenantState::Deleting {
            rec.state = TenantState::Deleting;
            self.ctx.store.save_tenant(&rec)?;
            info!(tenant = %name, "deleting the tenant with everything it has");
        }
        crate::backup::detach_retained(&self.ctx, name)?;
        crate::php::set_running(&self.ctx, &rec, false).await?;
        crate::app::set_running_all(&self.ctx, &rec, false).await?;
        let vhosts = vhost::VHostService::new(self.ctx.clone());
        for v in self.ctx.store.list_vhosts()? {
            if v.tenant == rec.username {
                vhosts
                    .remove_locked(&crate::validate::Domain::parse(&v.domain)?)
                    .await?;
            }
        }
        sftp::remove_access(&self.ctx, &rec, true).await?;
        crate::db::trash::drop_everything(&self.ctx, &rec).await?;
        crate::backup::remove_unretained(&self.ctx, name)?;
        self.remove_account(&rec, true, Some(job)).await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::Config;
    use crate::system::{FakeSystem, OsUser, System};
    use std::path::PathBuf;
    use std::sync::Arc;

    struct Harness {
        #[allow(dead_code)]
        _dir: tempfile::TempDir,
        sys: Arc<FakeSystem>,
        svc: TenantService,
        config: Config,
    }

    fn harness() -> Harness {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let mut cfg = Config::default();
        crate::config::sandbox_feature_paths(&mut cfg, dir.path());
        cfg.state_dir = dir.path().join("state");
        cfg.home_base = dir.path().join("home");
        cfg.systemd_unit_dir = dir.path().join("systemd");
        cfg.nginx_log_dir = dir.path().join("log");
        cfg.php_conf_dir = dir.path().join("php");
        cfg.nginx_conf_dir = dir.path().join("nginx").join("oxpanel.d");
        cfg.nginx_include_file = dir
            .path()
            .join("nginx")
            .join("conf.d")
            .join("00-oxpanel.conf");
        cfg.uid_min = 20000;
        cfg.uid_max = 20003;
        std::fs::create_dir_all(&cfg.home_base).unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir_all(&cfg.systemd_unit_dir).unwrap_or_else(|e| panic!("{e}"));
        let sys = Arc::new(FakeSystem::new());
        let ctx = Ctx::new(cfg.clone(), sys.clone(), false);
        ctx.store.init().unwrap_or_else(|e| panic!("{e}"));
        Harness {
            _dir: dir,
            sys,
            svc: TenantService::new(ctx),
            config: cfg,
        }
    }

    fn args(c: &CommandSpec) -> Vec<String> {
        c.args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[tokio::test]
    async fn create_runs_exact_useradd_and_becomes_ready() -> Result<()> {
        let h = harness();
        let limits = Limits {
            cpu_weight: Some(100),
            ..Limits::default()
        };
        let (rec, created) = h.svc.create("alice", limits, "").await?;
        assert!(created);
        assert_eq!(rec.state, TenantState::Ready);
        assert_eq!((rec.uid, rec.gid), (20000, 20000));
        assert_eq!(rec.home, h.config.home_base.join("alice"));
        let useradd = h.sys.calls_to(bin::USERADD);
        assert_eq!(useradd.len(), 1);
        assert_eq!(
            useradd.first().map(args),
            Some(vec![
                "--uid".to_owned(),
                "20000".into(),
                "--user-group".into(),
                "--home-dir".into(),
                h.config
                    .home_base
                    .join("alice")
                    .to_string_lossy()
                    .into_owned(),
                "--create-home".into(),
                "--shell".into(),
                "/sbin/nologin".into(),
                "--comment".into(),
                GECOS.into(),
                "--key".into(),
                "HOME_MODE=0700".into(),
                "alice".into(),
            ])
        );
        assert!(
            useradd.first().is_some_and(|c| c.run_as.is_none()),
            "useradd runs as root"
        );
        assert!(h
            .config
            .systemd_unit_dir
            .join("oxpanel-tenant-alice.slice")
            .is_file());
        assert!(
            h.sys.calls_to(bin::RESTORECON).is_empty(),
            "no SELinux in this harness"
        );
        Ok(())
    }

    #[tokio::test]
    async fn create_is_idempotent_and_detects_spec_drift() -> Result<()> {
        let h = harness();
        let limits = Limits::default();
        let (a, _) = h.svc.create("alice", limits, "").await?;
        let (b, created) = h.svc.create("alice", limits, "").await?;
        assert!(!created);
        assert_eq!(a, b);
        assert_eq!(h.sys.calls_to(bin::USERADD).len(), 1);
        let drift = Limits {
            cpu_weight: Some(5),
            ..Limits::default()
        };
        assert!(matches!(
            h.svc.create("alice", drift, "").await,
            Err(Error::SpecMismatch(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn never_adopts_a_foreign_account_or_group() -> Result<()> {
        let h = harness();
        h.sys.add_user(OsUser {
            name: "legacy".into(),
            uid: 1500,
            gid: 1500,
            home: PathBuf::from("/home/legacy"),
            shell: PathBuf::from("/bin/bash"),
        });
        assert!(matches!(
            h.svc.create("legacy", Limits::default(), "").await,
            Err(Error::NotManaged(_))
        ));
        h.sys.add_group("ops-team", 1600);
        assert!(matches!(
            h.svc.create("ops-team", Limits::default(), "").await,
            Err(Error::NotManaged(_))
        ));
        assert!(matches!(
            h.svc.delete("legacy", true).await,
            Err(Error::NotManaged(_))
        ));
        assert!(h.sys.calls_to(bin::USERADD).is_empty());
        assert!(h.sys.calls_to(bin::USERDEL).is_empty());
        assert!(h.sys.user_by_name("legacy").await?.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn reserved_and_malformed_names_never_reach_the_os() {
        let h = harness();
        for bad in ["root", "nginx", "Alice", "a;b", "../x", "--uid"] {
            assert!(
                matches!(
                    h.svc.create(bad, Limits::default(), "").await,
                    Err(Error::InvalidInput { .. })
                ),
                "{bad}"
            );
        }
        assert!(h.sys.calls().is_empty());
    }

    #[tokio::test]
    async fn uid_allocation_skips_taken_ids_and_exhausts() -> Result<()> {
        let h = harness();
        // 20001 is taken by an unrelated local account.
        h.sys.add_user(OsUser {
            name: "svc".into(),
            uid: 20001,
            gid: 20001,
            home: PathBuf::from("/x"),
            shell: PathBuf::from("/sbin/nologin"),
        });
        let (a, _) = h.svc.create("alice", Limits::default(), "").await?;
        let (b, _) = h.svc.create("bob", Limits::default(), "").await?;
        let (c, _) = h.svc.create("carol", Limits::default(), "").await?;
        assert_eq!((a.uid, b.uid, c.uid), (20000, 20002, 20003));
        assert!(matches!(
            h.svc.create("dave", Limits::default(), "").await,
            Err(Error::UidExhausted { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn interrupted_provisioning_resumes() -> Result<()> {
        let h = harness();
        // systemctl fails after useradd succeeded -> record stays Provisioning.
        h.sys.script_failure(bin::SYSTEMCTL, 1, "dbus down");
        assert!(matches!(
            h.svc.create("alice", Limits::default(), "").await,
            Err(Error::CommandFailed { .. })
        ));
        let rec = h.svc.get("alice").await?;
        assert_eq!(rec.state, TenantState::Provisioning);
        // Retry completes without a second useradd.
        let (rec, created) = h.svc.create("alice", Limits::default(), "").await?;
        assert!(created);
        assert_eq!(rec.state, TenantState::Ready);
        assert_eq!(h.sys.calls_to(bin::USERADD).len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn record_is_claimed_before_useradd_so_a_crash_leaves_no_orphan() -> Result<()> {
        let h = harness();
        h.sys
            .script_failure(bin::USERADD, 1, "useradd: cannot lock /etc/passwd");
        assert!(matches!(
            h.svc.create("alice", Limits::default(), "").await,
            Err(Error::CommandFailed { .. })
        ));
        let rec = h.svc.get("alice").await?;
        assert_eq!((rec.state, rec.uid), (TenantState::Provisioning, 20000));
        assert!(h.sys.user_by_name("alice").await?.is_none());
        // Retry: the claim is honoured, useradd runs again with the same uid, tenant becomes ready.
        let (rec, created) = h.svc.create("alice", Limits::default(), "").await?;
        assert!(created);
        assert_eq!((rec.state, rec.uid), (TenantState::Ready, 20000));
        assert_eq!(h.sys.calls_to(bin::USERADD).len(), 2);
        // A different name allocates the next uid, not the claimed one.
        let (bob, _) = h.svc.create("bob", Limits::default(), "").await?;
        assert_eq!(bob.uid, 20001);
        Ok(())
    }

    #[tokio::test]
    async fn owner_label_is_stored_filtered_and_part_of_the_spec() -> Result<()> {
        let h = harness();
        let (a, _) = h
            .svc
            .create("alice", Limits::default(), "reseller1")
            .await?;
        assert_eq!(a.owner, "reseller1");
        h.svc.create("bob", Limits::default(), "").await?;
        let (_, created) = h
            .svc
            .create("alice", Limits::default(), "reseller1")
            .await?;
        assert!(!created);
        assert!(matches!(
            h.svc.create("alice", Limits::default(), "reseller2").await,
            Err(Error::SpecMismatch(_))
        ));
        assert!(matches!(
            h.svc.create("carol", Limits::default(), "Bad Owner").await,
            Err(Error::InvalidInput { .. })
        ));
        let names = |v: Vec<TenantRecord>| v.into_iter().map(|t| t.username).collect::<Vec<_>>();
        assert_eq!(names(h.svc.list(Some("reseller1")).await?), vec!["alice"]);
        assert_eq!(names(h.svc.list(None).await?), vec!["alice", "bob"]);
        assert_eq!(names(h.svc.list(Some("")).await?), vec!["alice", "bob"]);
        assert!(matches!(
            h.svc.list(Some("no good")).await,
            Err(Error::InvalidInput { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn delete_flow() -> Result<()> {
        let h = harness();
        assert!(
            !h.svc.delete("alice", false).await?,
            "deleting a non-existent tenant is a no-op"
        );
        h.svc.create("alice", Limits::default(), "").await?;
        assert!(h.svc.delete("alice", true).await?);
        let userdel = h.sys.calls_to(bin::USERDEL);
        assert_eq!(
            userdel.first().map(args),
            Some(vec!["--remove".to_owned(), "alice".into()])
        );
        assert!(!h
            .config
            .systemd_unit_dir
            .join("oxpanel-tenant-alice.slice")
            .exists());
        assert!(matches!(
            h.svc.get("alice").await,
            Err(Error::TenantNotFound(_))
        ));
        assert!(h.sys.user_by_name("alice").await?.is_none());
        assert_eq!(
            h.sys.removed_homes(),
            vec![h.config.home_base.join("alice")]
        );
        Ok(())
    }

    #[tokio::test]
    async fn delete_refuses_while_vhosts_exist() -> Result<()> {
        use crate::records::VHostRecord;
        let h = harness();
        h.svc.create("alice", Limits::default(), "").await?;
        h.svc.ctx.store.save_vhost(&VHostRecord {
            version: 1,
            domain: "example.com".into(),
            tenant: "alice".into(),
            document_root: "public_html".into(),
            aliases: vec![],
            config_path: PathBuf::from("/x"),
            created_at_unix: 0,
            php: false,
            app: None,
            redirect_https: false,
            hsts: false,
            tls: None,
            auto_https: crate::records::AutoHttpsChoice::On,
        })?;
        assert!(matches!(
            h.svc.delete("alice", false).await,
            Err(Error::TenantHasVHosts(_))
        ));
        assert!(h.sys.calls_to(bin::USERDEL).is_empty());
        assert_eq!(
            h.svc.get("alice").await?.state,
            TenantState::Ready,
            "state untouched when refused"
        );
        Ok(())
    }

    #[tokio::test]
    async fn selinux_hosts_get_relabelled() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|e| Error::io("tempdir", "/tmp", e))?;
        let mut cfg = Config::default();
        cfg.state_dir = dir.path().join("state");
        cfg.home_base = dir.path().join("home");
        cfg.systemd_unit_dir = dir.path().join("systemd");
        cfg.nginx_log_dir = dir.path().join("log");
        cfg.php_conf_dir = dir.path().join("php");
        std::fs::create_dir_all(&cfg.home_base)
            .map_err(|e| Error::io("mkdir", &cfg.home_base, e))?;
        std::fs::create_dir_all(&cfg.systemd_unit_dir)
            .map_err(|e| Error::io("mkdir", &cfg.systemd_unit_dir, e))?;
        let sys = Arc::new(FakeSystem::new());
        let ctx = Ctx::new(cfg.clone(), sys.clone(), true);
        ctx.store.init()?;
        let svc = TenantService::new(ctx);
        svc.create("alice", Limits::default(), "").await?;
        let rc = sys.calls_to(bin::RESTORECON);
        assert_eq!(
            rc.first().map(args),
            Some(vec![
                "-R".to_owned(),
                cfg.home_base.join("alice").to_string_lossy().into_owned()
            ])
        );
        Ok(())
    }

    #[tokio::test]
    async fn update_limits_rewrites_units_and_is_idempotent() -> Result<()> {
        let h = harness();
        h.svc.create("alice", Limits::default(), "").await?;
        h.sys.clear_calls();
        let limits = Limits {
            memory_max_bytes: Some(64 << 20),
            tasks_max: Some(50),
            ..Limits::default()
        };
        let (rec, changed) = h.svc.update_limits("alice", limits).await?;
        assert!(changed);
        assert_eq!(rec.limits, limits);
        assert_eq!(h.svc.get("alice").await?.limits, limits);
        let slice = h.config.systemd_unit_dir.join("oxpanel-tenant-alice.slice");
        let unit = std::fs::read_to_string(&slice).map_err(|e| Error::io("read", &slice, e))?;
        assert!(unit.contains("MemoryMax=67108864\nMemorySwapMax=0\nTasksMax=50\n"));
        let dropin = h
            .config
            .systemd_unit_dir
            .join("user-20000.slice.d/50-oxpanel.conf");
        assert!(std::fs::read_to_string(&dropin)
            .map_err(|e| Error::io("read", &dropin, e))?
            .contains("TasksMax=50"));
        let reloads = h.sys.calls_to(bin::SYSTEMCTL);
        assert_eq!(reloads.len(), 1);
        assert_eq!(
            reloads.first().map(args),
            Some(vec!["daemon-reload".to_owned()])
        );
        // Same limits again: nothing changes, nothing reloads.
        let (_, changed) = h.svc.update_limits("alice", limits).await?;
        assert!(!changed);
        assert_eq!(h.sys.calls_to(bin::SYSTEMCTL).len(), 1);
        assert!(h.sys.calls_to(bin::USERADD).is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn update_limits_is_completed_by_a_retry_after_a_failed_reload() -> Result<()> {
        let h = harness();
        h.svc.create("alice", Limits::default(), "").await?;
        let limits = Limits {
            cpu_weight: Some(7),
            ..Limits::default()
        };
        h.sys.script_failure(bin::SYSTEMCTL, 1, "dbus down");
        assert!(matches!(
            h.svc.update_limits("alice", limits).await,
            Err(Error::CommandFailed { .. })
        ));
        // The unit file is already on disk, so the retry has nothing to write;
        // the record carries the new limits and reports no change.
        let (rec, _) = h.svc.update_limits("alice", limits).await?;
        assert_eq!(rec.limits, limits);
        Ok(())
    }

    #[tokio::test]
    async fn updates_require_a_ready_managed_tenant_and_valid_input() -> Result<()> {
        let h = harness();
        assert!(matches!(
            h.svc.update_limits("ghost", Limits::default()).await,
            Err(Error::TenantNotFound(_))
        ));
        assert!(matches!(
            h.svc.update_owner("ghost", "r1").await,
            Err(Error::TenantNotFound(_))
        ));
        assert!(matches!(
            h.svc.set_suspended("ghost", true).await,
            Err(Error::TenantNotFound(_))
        ));
        assert!(matches!(
            h.svc.usage("ghost").await,
            Err(Error::TenantNotFound(_))
        ));
        assert!(matches!(
            h.svc.update_limits("root", Limits::default()).await,
            Err(Error::InvalidInput { .. })
        ));
        h.sys.script_failure(bin::SYSTEMCTL, 1, "dbus down");
        assert!(h.svc.create("alice", Limits::default(), "").await.is_err());
        assert!(matches!(
            h.svc.update_owner("alice", "r1").await,
            Err(Error::TenantNotReady(_))
        ));
        assert!(matches!(
            h.svc.set_suspended("alice", true).await,
            Err(Error::TenantNotReady(_))
        ));
        assert!(h.sys.calls().iter().all(|c| c.program != bin::DU));
        Ok(())
    }

    #[tokio::test]
    async fn update_owner_sets_clears_and_validates() -> Result<()> {
        let h = harness();
        h.svc.create("alice", Limits::default(), "r1").await?;
        h.sys.clear_calls();
        let (rec, changed) = h.svc.update_owner("alice", "r2").await?;
        assert!(changed);
        assert_eq!(rec.owner, "r2");
        assert!(!h.svc.update_owner("alice", "r2").await?.1);
        assert_eq!(h.svc.list(Some("r2")).await?.len(), 1);
        assert!(h.svc.list(Some("r1")).await?.is_empty());
        assert!(matches!(
            h.svc.update_owner("alice", "Bad Owner").await,
            Err(Error::InvalidInput { .. })
        ));
        let (rec, changed) = h.svc.update_owner("alice", "").await?;
        assert!(changed);
        assert_eq!(rec.owner, "");
        assert!(
            h.sys.calls().is_empty(),
            "an owner label never touches the OS"
        );
        Ok(())
    }

    #[tokio::test]
    async fn usage_runs_exact_commands_and_sums_both_slices() -> Result<()> {
        let h = harness();
        h.svc.create("foo-bar", Limits::default(), "").await?;
        h.sys.clear_calls();
        let u = h.svc.usage("foo-bar").await?;
        assert_eq!(
            (u.memory_current_bytes, u.cpu_usage_nsec, u.tasks_current),
            (1_048_576, 5_000_000, 3)
        );
        assert_eq!(u.disk_usage_bytes, 8192);
        assert!(u.measured_at_unix > 1_600_000_000);
        let calls = h.sys.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls.first().map(args),
            Some(vec![
                "show".to_owned(),
                "--property=MemoryCurrent".into(),
                "--property=CPUUsageNSec".into(),
                "--property=TasksCurrent".into(),
                "--".into(),
                "oxpanel-tenant-foo\\x2dbar.slice".into(),
                "user-20000.slice".into(),
            ])
        );
        assert_eq!(calls.get(1).map(|c| c.program), Some(bin::DU));
        assert_eq!(
            calls.get(1).map(args),
            Some(vec![
                "--summarize".to_owned(),
                "--one-file-system".into(),
                "--block-size=1".into(),
                "--".into(),
                h.config
                    .home_base
                    .join("foo-bar")
                    .to_string_lossy()
                    .into_owned(),
            ])
        );
        assert!(calls.iter().all(|c| c.run_as.is_none()));
        Ok(())
    }

    /// A tenant using every feature at once, for
    /// [`one_tenant_with_every_feature_through_suspend_resume_and_delete`].
    pub(crate) struct Everything {
        _dir: tempfile::TempDir,
        pub(crate) sys: Arc<FakeSystem>,
        pub(crate) ctx: Ctx,
        pub(crate) tenants: TenantService,
        pub(crate) vhosts: crate::vhost::VHostService,
        pub(crate) db: crate::db::DbService,
        pub(crate) backups: crate::backup::BackupService,
        pub(crate) host: crate::host::HostService,
        pub(crate) backup_id: String,
    }

    /// Every external command since the last `clear_calls`, program first.
    pub(crate) fn argvs(sys: &FakeSystem) -> Vec<Vec<String>> {
        sys.calls()
            .iter()
            .map(|c| {
                std::iter::once(c.program.to_owned())
                    .chain(c.args.iter().map(|a| a.to_string_lossy().into_owned()))
                    .collect()
            })
            .collect()
    }

    /// Index of the first command `what` matches; panics with the whole list
    /// if there is none.
    pub(crate) fn first(
        calls: &[Vec<String>],
        what: impl Fn(&[String]) -> bool,
        label: &str,
    ) -> usize {
        calls
            .iter()
            .position(|c| what(c))
            .unwrap_or_else(|| panic!("no {label} in {calls:#?}"))
    }

    pub(crate) fn is_program(c: &[String], program: &str) -> bool {
        c.first().is_some_and(|p| p == program)
    }

    pub(crate) fn mentions(c: &[String], word: &str) -> bool {
        c.iter().any(|a| a == word)
    }

    /// `systemctl <verb> … <unit>`.
    pub(crate) fn systemctl(c: &[String], verb: &str, unit: &str) -> bool {
        is_program(c, bin::SYSTEMCTL) && mentions(c, verb) && mentions(c, unit)
    }

    /// alice with a PHP site (and an uploaded certificate), a Node.js
    /// application, an SFTP key and password, a database and a database
    /// user with access to it, and one finished backup.
    pub(crate) async fn everything() -> Result<Everything> {
        use crate::records::{AppRuntime, DbEngine};
        use crate::vhost::{AppRequest, VHostRequest};
        let dir = tempfile::tempdir().map_err(|e| Error::io("tempdir", "/tmp", e))?;
        let p = dir.path();
        let mut cfg = Config::default();
        cfg.state_dir = p.join("state");
        cfg.home_base = p.join("home");
        cfg.systemd_unit_dir = p.join("systemd");
        cfg.nginx_log_dir = p.join("log");
        cfg.php_conf_dir = p.join("php");
        cfg.nginx_conf_dir = p.join("nginx").join("oxpanel.d");
        cfg.nginx_include_file = p.join("nginx").join("conf.d").join("00-oxpanel.conf");
        crate::config::sandbox_feature_paths(&mut cfg, p);
        for d in [
            &cfg.home_base,
            &cfg.systemd_unit_dir,
            &p.join("nginx").join("conf.d"),
        ] {
            std::fs::create_dir_all(d).map_err(|e| Error::io("mkdir", d, e))?;
        }
        let sys = Arc::new(FakeSystem::new());
        sys.install_mariadb();
        let ctx = Ctx::new(cfg, sys.clone(), false);
        ctx.store.init()?;
        crate::sftp::converge_all(&ctx).await?;
        let tenants = TenantService::new(ctx.clone());
        let vhosts = crate::vhost::VHostService::new(ctx.clone());
        let db = crate::db::DbService::new(ctx.clone());
        let backups = crate::backup::BackupService::new(ctx.clone())
            .with_poll_interval(std::time::Duration::from_secs(3600));
        tenants.create("alice", Limits::default(), "").await?;
        let site = |domain: &str| VHostRequest {
            domain: domain.into(),
            tenant: "alice".into(),
            ..VHostRequest::default()
        };
        vhosts
            .configure(VHostRequest {
                aliases: vec!["www.example.com".into()],
                php: true,
                ..site("example.com")
            })
            .await?;
        vhosts
            .configure(VHostRequest {
                app: Some(AppRequest {
                    runtime: AppRuntime::Node,
                    root: String::new(),
                    entry: String::new(),
                }),
                ..site("app.example.com")
            })
            .await?;
        crate::tls::TlsService::new(ctx.clone())
            .install(crate::tls::tests::upload(
                &crate::tls::tests::good_cert(),
                &crate::system::fake_tls::fake_private_key("k1"),
            ))
            .await?;
        let sftp = crate::sftp::SftpService::new(ctx.clone());
        sftp.add_key("alice", crate::sftp::tests::KEY_A, "laptop")
            .await?;
        sftp.set_password("alice", "correct horse battery staple")
            .await?;
        db.create_database("alice", "alice_wp", DbEngine::Mariadb)
            .await?;
        db.create_user("alice", "alice_app", "db-password-123", DbEngine::Mariadb)
            .await?;
        db.grant("alice_app", "alice_wp").await?;
        let (job, started) = backups.create("alice", 0, 0).await?;
        assert!(started);
        assert!(
            backups
                .step(&crate::validate::JobId::parse(&job.id)?)
                .await?
        );
        let host = crate::host::HostService::new(ctx.clone());
        assert!(host.reconcile().await?.is_empty(), "everything in place");
        Ok(Everything {
            _dir: dir,
            sys,
            ctx,
            tenants,
            vhosts,
            db,
            backups,
            host,
            backup_id: job.backup_id,
        })
    }

    impl Everything {
        fn keys_file(&self) -> Result<PathBuf> {
            let rec = self
                .ctx
                .store
                .load_tenant(&Username::parse("alice")?)?
                .ok_or_else(|| Error::TenantNotFound("alice".into()))?;
            Ok(crate::sftp::SftpPaths::for_tenant(&self.ctx.config, &rec)?.keys_file)
        }

        /// Suspend: sites answer 503, then PHP and the application stop,
        /// then SFTP (password locked, sessions ended), databases last.
        async fn suspend(&self) -> Result<()> {
            self.sys.clear_calls();
            self.tenants.set_suspended("alice", true).await?;
            let calls = argvs(&self.sys);
            let order = [
                first(&calls, |c| mentions(c, "reload-or-restart"), "nginx reload"),
                first(
                    &calls,
                    |c| systemctl(c, "disable", "oxpanel-php-alice.service"),
                    "PHP stop",
                ),
                first(
                    &calls,
                    |c| systemctl(c, "disable", "oxpanel-app-app.example.com.service"),
                    "application stop",
                ),
                first(
                    &calls,
                    |c| is_program(c, bin::USERMOD) && mentions(c, "--lock"),
                    "password lock",
                ),
                first(
                    &calls,
                    |c| mentions(c, "stop") && mentions(c, "user-20000.slice"),
                    "end of sessions",
                ),
                first(&calls, |c| is_program(c, bin::MARIADB), "database lock"),
            ];
            assert!(order.is_sorted(), "suspend order {order:?}");
            assert!(
                self.sys
                    .mariadb_scripts()
                    .iter()
                    .any(|s| s.contains("ACCOUNT LOCK") && s.contains("KILL USER")),
                "database accounts locked and their sessions ended"
            );
            assert!(
                !self.keys_file()?.exists(),
                "no SFTP key works while suspended"
            );
            assert!(
                self.host.reconcile().await?.is_empty(),
                "suspended is not drift"
            );
            Ok(())
        }

        /// Resume: the reverse — access, then processes, then the sites.
        async fn resume(&self) -> Result<()> {
            self.sys.clear_calls();
            self.tenants.set_suspended("alice", false).await?;
            let calls = argvs(&self.sys);
            let order = [
                first(&calls, |c| is_program(c, bin::MARIADB), "database unlock"),
                first(
                    &calls,
                    |c| is_program(c, bin::USERMOD) && mentions(c, "--unlock"),
                    "password unlock",
                ),
                first(
                    &calls,
                    |c| systemctl(c, "enable", "oxpanel-php-alice.service"),
                    "PHP start",
                ),
                first(
                    &calls,
                    |c| systemctl(c, "enable", "oxpanel-app-app.example.com.service"),
                    "application start",
                ),
                first(&calls, |c| mentions(c, "reload-or-restart"), "nginx reload"),
            ];
            assert!(order.is_sorted(), "resume order {order:?}");
            assert!(self
                .sys
                .mariadb_scripts()
                .iter()
                .any(|s| s.contains("ACCOUNT UNLOCK")));
            assert!(self.keys_file()?.exists(), "SFTP keys work again");
            assert!(self.host.reconcile().await?.is_empty(), "resumed: no drift");
            Ok(())
        }

        /// A deletion that must be refused, changing and running nothing.
        async fn refused(&self, expect: fn(&Error) -> bool) -> Result<()> {
            self.sys.clear_calls();
            match self.tenants.delete("alice", true).await {
                Err(e) => assert!(expect(&e), "{e}"),
                Ok(deleted) => panic!("deletion went through: {deleted}"),
            }
            assert!(
                self.sys.calls().is_empty(),
                "a refused deletion runs nothing"
            );
            let rec = self.ctx.store.load_tenant(&Username::parse("alice")?)?;
            assert!(rec.is_some_and(|r| r.state == TenantState::Ready));
            Ok(())
        }

        /// Delete: every refusal (sites, databases, backups) before anything
        /// is destroyed; then SFTP access goes before the account, and the
        /// retained backup outlives the tenant.
        async fn delete(&self) -> Result<()> {
            self.refused(|e| matches!(e, Error::TenantHasVHosts(_)))
                .await?;
            self.vhosts.remove("example.com").await?;
            self.vhosts.remove("app.example.com").await?;
            self.refused(|e| matches!(e, Error::TenantHasDatabases(_)))
                .await?;
            self.db.delete_user("alice_app").await?;
            self.db.delete_database("alice_wp").await?;
            // The deleted database waits in the trash: still refused.
            self.refused(|e| matches!(e, Error::TenantHasDatabases(_)))
                .await?;
            assert_eq!(self.db.purge_trash("alice", "").await?, 1);
            self.refused(|e| matches!(e, Error::TenantHasBackups(_)))
                .await?;
            self.backups.retain("alice", &self.backup_id, 1, 0).await?;
            self.sys.clear_calls();
            assert!(self.tenants.delete("alice", true).await?);
            let calls = argvs(&self.sys);
            let sessions = first(
                &calls,
                |c| mentions(c, "stop") && mentions(c, "user-20000.slice"),
                "end of sessions",
            );
            let userdel = first(&calls, |c| is_program(c, bin::USERDEL), "userdel");
            assert!(sessions < userdel, "SFTP access goes before the account");
            assert!(self
                .ctx
                .store
                .load_tenant(&Username::parse("alice")?)?
                .is_none());
            assert!(
                self.backups
                    .list_retained()
                    .await?
                    .iter()
                    .any(|b| b.id == self.backup_id && b.tenant_deleted),
                "the retained backup outlives the tenant, detached"
            );
            assert!(
                self.host.reconcile().await?.is_empty(),
                "nothing left behind"
            );
            Ok(())
        }
    }

    /// One tenant using every feature at once — a PHP site with an uploaded
    /// certificate, a Node.js application, an SFTP key and password, a
    /// database and a database user, and a backup — through suspension,
    /// resumption and deletion, with the order across the feature modules
    /// asserted (see `TenantService::set_suspended`).
    #[tokio::test]
    async fn one_tenant_with_every_feature_through_suspend_resume_and_delete() -> Result<()> {
        let all = everything().await?;
        all.suspend().await?;
        all.resume().await?;
        all.delete().await
    }

    #[test]
    fn cgroup_usage_parsing_tolerates_unset_and_garbage() {
        assert_eq!(parse_cgroup_usage(""), (0, 0, 0));
        assert_eq!(
            parse_cgroup_usage(
                "MemoryCurrent=10\nCPUUsageNSec=[not set]\nTasksCurrent=2\n\nMemoryCurrent=5\nCPUUsageNSec=7\nTasksCurrent=18446744073709551615\nOther=9\nnonsense\n"
            ),
            (15, 7, 2)
        );
        assert_eq!(
            parse_cgroup_usage("MemoryCurrent=18446744073709551614\nMemoryCurrent=5\n").0,
            u64::MAX,
            "saturates instead of overflowing"
        );
    }
}
