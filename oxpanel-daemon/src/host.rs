//! Host-level read-only operations: engine/host information and
//! reconciliation of the records against the operating system.
//!
//! Reconciliation never repairs anything. It reports where reality differs
//! from what the records say OxPanel owns, so an operator (or the panel) can
//! decide: most findings are healed by repeating the original request, and
//! orphans are deliberately left alone ("own it or leave it").

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::ctx::Ctx;
use crate::error::Result;
use crate::fsutil;
use crate::records::{TenantRecord, TenantState, VHostRecord};
use crate::system::HostStats;
use crate::systemd::{self, TenantUnits};
use crate::validate::Username;
use crate::vhost;

/// What kind of difference a [`Drift`] describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DriftKind {
    TenantIncomplete,
    TenantAccountMissing,
    TenantAccountMismatch,
    TenantHomeInvalid,
    TenantUnitDrift,
    VHostTenantMissing,
    VHostConfigDrift,
    OrphanNginxConfig,
    OrphanSliceUnit,
}

/// One difference between a record and the operating system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drift {
    pub kind: DriftKind,
    /// Tenant name, domain or file path.
    pub subject: String,
    pub detail: String,
}

impl Drift {
    fn new(kind: DriftKind, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            kind,
            subject: subject.into(),
            detail: detail.into(),
        }
    }
}

/// Engine and host facts for the panel's overview.
#[derive(Debug, Clone, PartialEq)]
pub struct HostInfo {
    pub selinux: bool,
    pub dry_run: bool,
    pub tenant_count: u32,
    pub vhost_count: u32,
    pub uid_min: u32,
    pub uid_max: u32,
    pub stats: HostStats,
}

#[derive(Debug, Clone)]
pub struct HostService {
    ctx: Ctx,
}

impl HostService {
    pub fn new(ctx: Ctx) -> Self {
        Self { ctx }
    }

    pub async fn info(&self) -> Result<HostInfo> {
        let cfg = &self.ctx.config;
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        Ok(HostInfo {
            selinux: self.ctx.selinux,
            dry_run: cfg.dry_run,
            tenant_count: count(self.ctx.store.list_tenants()?.len()),
            vhost_count: count(self.ctx.store.list_vhosts()?.len()),
            uid_min: cfg.uid_min,
            uid_max: cfg.uid_max,
            stats: self.ctx.sys.host_stats(&cfg.home_base).await?,
        })
    }

    /// Compare every record with the OS. Holds the mutation lock so a
    /// workflow in flight is never reported as drift.
    pub async fn reconcile(&self) -> Result<Vec<Drift>> {
        let _guard = self.ctx.lock.lock().await;
        let cfg = &self.ctx.config;
        let tenants = self.ctx.store.list_tenants()?;
        let vhosts = self.ctx.store.list_vhosts()?;
        let mut out = Vec::new();

        for t in &tenants {
            self.check_tenant(t, &mut out).await?;
        }
        let by_name: BTreeMap<&str, &TenantRecord> =
            tenants.iter().map(|t| (t.username.as_str(), t)).collect();
        for v in &vhosts {
            check_vhost(v, by_name.get(v.tenant.as_str()).copied(), &mut out)?;
        }

        let known_confs: BTreeSet<&Path> = vhosts.iter().map(|v| v.config_path.as_path()).collect();
        for path in fsutil::list_files_with_suffix(&cfg.nginx_conf_dir, ".conf")? {
            if !known_confs.contains(path.as_path()) {
                out.push(Drift::new(
                    DriftKind::OrphanNginxConfig,
                    path.to_string_lossy(),
                    "no virtual-host record refers to this file",
                ));
            }
        }
        let known_slices: BTreeSet<PathBuf> = tenants
            .iter()
            .map(|t| cfg.systemd_unit_dir.join(&t.slice_unit))
            .collect();
        for path in fsutil::list_files_with_suffix(&cfg.systemd_unit_dir, ".slice")? {
            let ours = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("oxpanel-tenant-"));
            if ours && !known_slices.contains(&path) {
                out.push(Drift::new(
                    DriftKind::OrphanSliceUnit,
                    path.to_string_lossy(),
                    "no tenant record refers to this unit",
                ));
            }
        }
        Ok(out)
    }

    async fn check_tenant(&self, t: &TenantRecord, out: &mut Vec<Drift>) -> Result<()> {
        let subject = t.username.as_str();
        if t.state != TenantState::Ready {
            let what = match t.state {
                TenantState::Deleting => "deletion was interrupted; repeat DeleteTenant",
                _ => "provisioning was interrupted; repeat CreateTenant",
            };
            out.push(Drift::new(DriftKind::TenantIncomplete, subject, what));
            return Ok(());
        }
        match self.ctx.sys.user_by_name(subject).await? {
            None => {
                out.push(Drift::new(
                    DriftKind::TenantAccountMissing,
                    subject,
                    "the POSIX account no longer exists",
                ));
                return Ok(());
            }
            Some(u) if (u.uid, u.gid, u.home.as_path()) != (t.uid, t.gid, t.home.as_path()) => {
                out.push(Drift::new(
                    DriftKind::TenantAccountMismatch,
                    subject,
                    format!(
                        "account is uid={} gid={} home={}, record says uid={} gid={} home={}",
                        u.uid,
                        u.gid,
                        u.home.display(),
                        t.uid,
                        t.gid,
                        t.home.display()
                    ),
                ));
            }
            Some(_) => {}
        }
        if let Some(problem) = self
            .ctx
            .sys
            .inspect_private_dir(&t.home, t.uid, t.gid)
            .await?
        {
            out.push(Drift::new(
                DriftKind::TenantHomeInvalid,
                subject,
                format!("{}: {problem}", t.home.display()),
            ));
        }
        let name = Username::parse(&t.username)?;
        let units = TenantUnits::for_tenant(&self.ctx.config.systemd_unit_dir, &name, t.uid);
        for (path, expected) in [
            (
                &units.slice_unit,
                systemd::render_slice_unit(&name, &t.limits),
            ),
            (
                &units.user_slice_dropin,
                systemd::render_user_slice_dropin(&name, &t.limits),
            ),
        ] {
            if let Some(problem) = compare_file(path, &expected)? {
                out.push(Drift::new(
                    DriftKind::TenantUnitDrift,
                    subject,
                    format!("{} {problem}", path.display()),
                ));
            }
        }
        Ok(())
    }
}

fn check_vhost(v: &VHostRecord, tenant: Option<&TenantRecord>, out: &mut Vec<Drift>) -> Result<()> {
    let Some(tenant) = tenant else {
        out.push(Drift::new(
            DriftKind::VHostTenantMissing,
            v.domain.as_str(),
            format!("tenant '{}' has no record", v.tenant),
        ));
        return Ok(());
    };
    let expected = vhost::render_vhost(tenant, v)?;
    if let Some(problem) = compare_file(&v.config_path, &expected)? {
        out.push(Drift::new(
            DriftKind::VHostConfigDrift,
            v.domain.as_str(),
            format!("{} {problem}", v.config_path.display()),
        ));
    }
    Ok(())
}

/// `None` when the file holds exactly `expected`.
fn compare_file(path: &Path, expected: &str) -> Result<Option<&'static str>> {
    Ok(match fsutil::read_optional(path)? {
        None => Some("is missing"),
        Some(bytes) if bytes != expected.as_bytes() => Some("differs from the record"),
        Some(_) => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::system::{bin, FakeSystem, System as _};
    use crate::tenant::TenantService;
    use crate::validate::Limits;
    use crate::vhost::{VHostRequest, VHostService};
    use crate::Error;
    use std::sync::Arc;

    struct Harness {
        _dir: tempfile::TempDir,
        sys: Arc<FakeSystem>,
        ctx: Ctx,
        tenants: TenantService,
        vhosts: VHostService,
        host: HostService,
    }

    /// Two tenants, one site each, everything consistent.
    async fn harness() -> Harness {
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
        for d in [
            &cfg.home_base,
            &cfg.systemd_unit_dir,
            &dir.path().join("nginx").join("conf.d"),
        ] {
            std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("{e}"));
        }
        let sys = Arc::new(FakeSystem::new());
        let ctx = Ctx::new(cfg, sys.clone(), false);
        ctx.store.init().unwrap_or_else(|e| panic!("{e}"));
        let h = Harness {
            _dir: dir,
            sys,
            tenants: TenantService::new(ctx.clone()),
            vhosts: VHostService::new(ctx.clone()),
            host: HostService::new(ctx.clone()),
            ctx,
        };
        let limits = Limits {
            cpu_weight: Some(50),
            ..Limits::default()
        };
        for (tenant, domain) in [("alice", "example.com"), ("foo-bar", "example.net")] {
            h.tenants
                .create(tenant, limits, "")
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            h.vhosts
                .configure(VHostRequest {
                    domain: domain.into(),
                    tenant: tenant.into(),
                    ..VHostRequest::default()
                })
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        }
        h.sys.clear_calls();
        h
    }

    fn kinds(d: &[Drift]) -> Vec<(DriftKind, &str)> {
        d.iter().map(|d| (d.kind, d.subject.as_str())).collect()
    }

    #[tokio::test]
    async fn a_consistent_host_has_no_drift_and_reconcile_runs_nothing() -> Result<()> {
        let h = harness().await;
        assert_eq!(h.host.reconcile().await?, vec![]);
        h.tenants.set_suspended("alice", true).await?;
        h.sys.clear_calls();
        assert_eq!(h.host.reconcile().await?, vec![], "suspension is not drift");
        assert!(h.sys.calls().is_empty(), "reconcile is read-only");
        Ok(())
    }

    #[tokio::test]
    async fn reports_account_unit_and_config_drift() -> Result<()> {
        let h = harness().await;
        let cfg = &h.ctx.config;
        // alice: unit edited by hand, site config removed.
        let slice = cfg.systemd_unit_dir.join("oxpanel-tenant-alice.slice");
        std::fs::write(&slice, "[Slice]\nCPUWeight=9999\n")
            .map_err(|e| Error::io("write", &slice, e))?;
        let conf = cfg.nginx_conf_dir.join("example.com.conf");
        std::fs::remove_file(&conf).map_err(|e| Error::io("unlink", &conf, e))?;
        // foo-bar: account deleted behind the daemon's back.
        h.sys
            .run_ok(
                crate::system::CommandSpec::new(bin::USERDEL, cfg.command_timeout).arg("foo-bar"),
            )
            .await?;
        let drifts = h.host.reconcile().await?;
        assert_eq!(
            kinds(&drifts),
            vec![
                (DriftKind::TenantUnitDrift, "alice"),
                (DriftKind::TenantAccountMissing, "foo-bar"),
                (DriftKind::VHostConfigDrift, "example.com"),
            ]
        );
        assert!(drifts
            .first()
            .is_some_and(|d| d.detail.ends_with("differs from the record")));
        assert!(drifts
            .get(2)
            .is_some_and(|d| d.detail.ends_with("is missing")));
        // Repeating the original request heals what it can.
        h.vhosts
            .configure(VHostRequest {
                domain: "example.com".into(),
                tenant: "alice".into(),
                ..VHostRequest::default()
            })
            .await?;
        h.tenants
            .update_limits(
                "alice",
                Limits {
                    cpu_weight: Some(50),
                    ..Limits::default()
                },
            )
            .await?;
        assert_eq!(
            kinds(&h.host.reconcile().await?),
            vec![(DriftKind::TenantAccountMissing, "foo-bar")]
        );
        Ok(())
    }

    #[tokio::test]
    async fn reports_home_incomplete_tenants_and_orphans() -> Result<()> {
        let h = harness().await;
        let cfg = &h.ctx.config;
        let home = cfg.home_base.join("alice");
        std::fs::remove_dir_all(&home).map_err(|e| Error::io("rm", &home, e))?;
        // Interrupted provisioning.
        h.sys.script_failure(bin::SYSTEMCTL, 1, "dbus down");
        assert!(h
            .tenants
            .create("carol", Limits::default(), "")
            .await
            .is_err());
        // Files nobody recorded; foreign files are not ours to report.
        let stray_conf = cfg.nginx_conf_dir.join("stray.example.conf");
        let stray_slice = cfg.systemd_unit_dir.join("oxpanel-tenant-ghost.slice");
        for p in [
            &stray_conf,
            &stray_slice,
            &cfg.systemd_unit_dir.join("machine.slice"),
            &cfg.nginx_conf_dir.join("README"),
        ] {
            std::fs::write(p, "x").map_err(|e| Error::io("write", p, e))?;
        }
        // A site whose tenant record vanished.
        let orphan_site = crate::records::VHostRecord {
            version: 1,
            domain: "lost.example".into(),
            tenant: "nobody".into(),
            document_root: "public_html".into(),
            aliases: vec![],
            config_path: cfg.nginx_conf_dir.join("lost.example.conf"),
            created_at_unix: 0,
        };
        h.ctx.store.save_vhost(&orphan_site)?;

        let drifts = h.host.reconcile().await?;
        let stray_conf = stray_conf.to_string_lossy().into_owned();
        let stray_slice = stray_slice.to_string_lossy().into_owned();
        assert_eq!(
            kinds(&drifts),
            vec![
                (DriftKind::TenantHomeInvalid, "alice"),
                (DriftKind::TenantIncomplete, "carol"),
                (DriftKind::VHostTenantMissing, "lost.example"),
                (DriftKind::OrphanNginxConfig, stray_conf.as_str()),
                (DriftKind::OrphanSliceUnit, stray_slice.as_str()),
            ]
        );
        assert!(
            std::path::Path::new(&stray_conf).exists(),
            "orphans are reported, never removed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn info_counts_records_and_reports_host_stats() -> Result<()> {
        let h = harness().await;
        let i = h.host.info().await?;
        assert_eq!((i.tenant_count, i.vhost_count), (2, 2));
        assert_eq!((i.uid_min, i.uid_max), (20_000, 29_999));
        assert!(!i.selinux && !i.dry_run);
        assert_eq!(i.stats.memory_total_bytes, 8 << 30);
        assert!(i.stats.disk_free_bytes <= i.stats.disk_total_bytes);
        Ok(())
    }
}
