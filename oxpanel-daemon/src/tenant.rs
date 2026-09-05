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

const GECOS: &str = "OxPanel tenant";

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
        if self
            .ctx
            .store
            .list_vhosts()?
            .iter()
            .any(|v| v.tenant == rec.username)
        {
            return Err(Error::TenantHasVHosts(name.to_string()));
        }
        if rec.state != TenantState::Deleting {
            rec.state = TenantState::Deleting;
            self.ctx.store.save_tenant(&rec)?;
        }

        let timeout = self.ctx.config.command_timeout;
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
        self.ctx.store.delete_tenant(&name)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
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
        cfg.state_dir = dir.path().join("state");
        cfg.home_base = dir.path().join("home");
        cfg.systemd_unit_dir = dir.path().join("systemd");
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
}
