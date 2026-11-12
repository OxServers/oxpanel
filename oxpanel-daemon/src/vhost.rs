//! Virtual-host lifecycle: configure / remove / list.
//!
//! A virtual host maps a domain (plus aliases) to a document root inside a
//! tenant's home. Making that safe in a multi-tenant box means:
//!
//! - the document root is created *as the tenant* (`setpriv` → `mkdir`), so a
//!   hostile path can only ever affect the tenant's own files;
//! - the web-server account gets traverse/read rights through POSIX ACLs set
//!   with `--physical`, so a planted symlink is skipped rather than followed;
//! - the generated server block carries `disable_symlinks if_not_owner`, so
//!   Nginx refuses to serve through a symlink whose target the tenant does not own;
//! - on SELinux hosts the document root is labelled `httpd_sys_content_t` through a
//!   persistent `semanage fcontext` *path equivalence* to `/usr/share/nginx/html`
//!   plus `restorecon`. An equivalence, not a regex rule: libselinux applies the
//!   generated `file_contexts.homedirs` (which labels `~/public_html`, `~/www`
//!   and `~/web` as `httpd_user_content_t`) after `file_contexts.local`, so a
//!   local rule for a path under `/home` is silently overridden, whereas a
//!   substitution is applied before any rule is matched. `-N`: no kernel policy
//!   reload is needed for file contexts, and `/sys` is read-only inside the unit.
//!   `restorecon -F`: the policy creates `~/public_html` as `httpd_user_content_t`
//!   through a named file transition, and that type is *customizable*, which a
//!   plain `restorecon` refuses to touch;
//! - the new configuration is validated with `nginx -t` and rolled back on failure.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::nginx;
use crate::records::{now_unix, TenantRecord, TenantState, VHostRecord, RECORD_VERSION};
use crate::system::{bin, CommandSpec};
use crate::validate::{Domain, RelPath, Username};

pub const MAX_ALIASES: usize = 50;
/// Document roots are made label-equivalent to this path (`httpd_sys_content_t`,
/// no `cgi-bin` sub-rules).
const SELINUX_EQUIV_SOURCE: &str = "/usr/share/nginx/html";

/// Raw request as received on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VHostRequest {
    pub domain: String,
    pub tenant: String,
    pub document_root: String,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VHostService {
    ctx: Ctx,
}

impl VHostService {
    pub fn new(ctx: Ctx) -> Self {
        Self { ctx }
    }

    /// Create or update the virtual host. Returns the record and whether
    /// anything on the system changed.
    pub async fn configure(&self, req: VHostRequest) -> Result<(VHostRecord, bool)> {
        let domain = Domain::parse(&req.domain)?;
        let tenant = Username::parse_field(&req.tenant, "tenant")?;
        let docroot = if req.document_root.is_empty() {
            RelPath::default_document_root()
        } else {
            RelPath::parse(&req.document_root)?
        };
        if req.aliases.len() > MAX_ALIASES {
            return Err(Error::invalid(
                "aliases",
                format!("at most {MAX_ALIASES} aliases"),
            ));
        }
        let mut aliases: BTreeSet<Domain> = BTreeSet::new();
        for a in &req.aliases {
            let a = Domain::parse_field(a, "aliases")?;
            if a == domain {
                return Err(Error::invalid("aliases", "alias must differ from domain"));
            }
            aliases.insert(a);
        }
        let aliases: Vec<Domain> = aliases.into_iter().collect();

        let _guard = self.ctx.lock.lock().await;
        let cfg = &self.ctx.config;
        let timeout = cfg.command_timeout;

        let tenant_rec = self
            .ctx
            .store
            .load_tenant(&tenant)?
            .ok_or_else(|| Error::TenantNotFound(tenant.to_string()))?;
        if tenant_rec.state != TenantState::Ready {
            return Err(Error::TenantNotReady(tenant.to_string()));
        }

        let existing = self.ctx.store.load_vhost(&domain)?;
        if let Some(e) = &existing {
            if e.tenant != tenant.as_str() {
                return Err(Error::VHostOwnedByOther {
                    domain: domain.to_string(),
                    owner: e.tenant.clone(),
                });
            }
        }
        self.check_names_unique(&domain, &aliases, &tenant)?;

        nginx::ensure_include(
            self.ctx.sys.as_ref(),
            &cfg.nginx_conf_dir,
            &cfg.nginx_include_file,
            cfg.nginx_default_server,
            timeout,
        )
        .await?;

        let abs_root = tenant_rec.home.join(docroot.as_str());
        self.create_document_root(&tenant_rec, &abs_root).await?;
        self.grant_web_access(&tenant_rec.home, &docroot, &abs_root)
            .await?;

        if self.ctx.selinux {
            self.label_docroot(&abs_root).await?;
        }

        let block = nginx::render_server_block(&nginx::ServerBlock {
            domain: &domain,
            aliases: &aliases,
            tenant: &tenant,
            document_root: &abs_root,
            suspended: tenant_rec.suspended,
        })?;
        let path = nginx::conf_path(&cfg.nginx_conf_dir, &domain);
        let changed = nginx::install_config(self.ctx.sys.as_ref(), &path, &block, timeout).await?;

        let rec = VHostRecord {
            version: RECORD_VERSION,
            domain: domain.to_string(),
            tenant: tenant.to_string(),
            document_root: docroot.to_string(),
            aliases: aliases.iter().map(ToString::to_string).collect(),
            config_path: path,
            created_at_unix: existing
                .as_ref()
                .map_or_else(now_unix, |e| e.created_at_unix),
        };
        let record_changed = existing.as_ref() != Some(&rec);
        if record_changed {
            self.ctx.store.save_vhost(&rec)?;
        }
        if changed || record_changed {
            info!(%domain, %tenant, root = %abs_root.display(), "virtual host configured");
        }
        Ok((rec, changed || record_changed))
    }

    /// Every server name must be unique across the whole host.
    fn check_names_unique(
        &self,
        domain: &Domain,
        aliases: &[Domain],
        tenant: &Username,
    ) -> Result<()> {
        let ours: Vec<&str> = std::iter::once(domain.as_str())
            .chain(aliases.iter().map(Domain::as_str))
            .collect();
        for other in self
            .ctx
            .store
            .list_vhosts()?
            .iter()
            .filter(|v| v.domain != domain.as_str())
        {
            for name in &ours {
                if other.all_names().any(|n| n == *name) {
                    return if other.tenant == tenant.as_str() {
                        Err(Error::invalid(
                            "aliases",
                            format!(
                                "'{name}' is already used by virtual host '{}'",
                                other.domain
                            ),
                        ))
                    } else {
                        Err(Error::VHostOwnedByOther {
                            domain: (*name).to_owned(),
                            owner: other.tenant.clone(),
                        })
                    };
                }
            }
        }
        Ok(())
    }

    /// Create the document root *as the tenant*, with no privileges, then
    /// confirm it is a real directory the tenant owns.
    async fn create_document_root(&self, tenant: &TenantRecord, abs_root: &Path) -> Result<()> {
        let timeout = self.ctx.config.command_timeout;
        self.ctx
            .sys
            .run_ok(
                CommandSpec::new(bin::MKDIR, timeout)
                    .args(["-p", "--"])
                    .arg(abs_root)
                    .as_user(tenant.uid, tenant.gid),
            )
            .await?;
        self.ctx.sys.verify_owned_dir(abs_root, tenant.uid).await
    }

    /// Grant the web-server account traverse on every directory from the
    /// home down to the document root, and read on the root itself (plus a
    /// default ACL so new files inherit it). `--physical`: never follow a
    /// symlink the tenant may have planted.
    async fn grant_web_access(
        &self,
        home: &Path,
        docroot: &RelPath,
        abs_root: &Path,
    ) -> Result<()> {
        let timeout = self.ctx.config.command_timeout;
        let web = &self.ctx.config.web_user;
        let mut traverse: Vec<PathBuf> = vec![home.to_owned()];
        let mut cur = home.to_owned();
        let comps: Vec<&str> = docroot.as_str().split('/').collect();
        for comp in comps.iter().take(comps.len().saturating_sub(1)) {
            cur = cur.join(comp);
            traverse.push(cur.clone());
        }
        self.ctx
            .sys
            .run_ok(
                CommandSpec::new(bin::SETFACL, timeout)
                    .args(["--physical", "-m"])
                    .arg(format!("u:{web}:--x"))
                    .arg("--")
                    .args(&traverse),
            )
            .await?;
        self.ctx
            .sys
            .run_ok(
                CommandSpec::new(bin::SETFACL, timeout)
                    .args(["--physical", "-m"])
                    .arg(format!("u:{web}:r-x"))
                    .args(["-d", "-m"])
                    .arg(format!("u:{web}:r-x"))
                    .arg("--")
                    .arg(abs_root),
            )
            .await?;
        Ok(())
    }

    /// Remove a virtual host OxPanel created. Returns `false` if none existed.
    pub async fn remove(&self, domain: &str) -> Result<bool> {
        let domain = Domain::parse(domain)?;
        let _guard = self.ctx.lock.lock().await;
        let cfg = &self.ctx.config;
        let Some(rec) = self.ctx.store.load_vhost(&domain)? else {
            let stray = nginx::conf_path(&cfg.nginx_conf_dir, &domain);
            if stray.exists() {
                warn!(path = %stray.display(), "configuration file without a record; leaving it alone");
            }
            return Ok(false);
        };
        nginx::remove_config(self.ctx.sys.as_ref(), &rec.config_path, cfg.command_timeout).await?;

        if self.ctx.selinux {
            let shared = self.ctx.store.list_vhosts()?.iter().any(|v| {
                v.domain != rec.domain
                    && v.tenant == rec.tenant
                    && v.document_root == rec.document_root
            });
            if !shared {
                if let Some(t) = self.ctx.store.load_tenant(&Username::parse(&rec.tenant)?)? {
                    self.unlabel_docroot(&t.home.join(&rec.document_root))
                        .await?;
                }
            }
        }
        self.ctx.store.delete_vhost(&domain)?;
        info!(%domain, tenant = %rec.tenant, "virtual host removed");
        Ok(true)
    }

    pub async fn list(&self, tenant: Option<&str>) -> Result<Vec<VHostRecord>> {
        let filter = match tenant {
            Some(t) if !t.is_empty() => Some(Username::parse_field(t, "tenant")?),
            _ => None,
        };
        let mut all = self.ctx.store.list_vhosts()?;
        if let Some(t) = filter {
            all.retain(|v| v.tenant == t.as_str());
        }
        Ok(all)
    }

    /// Persistent SELinux label for the document root, then apply it.
    async fn label_docroot(&self, root: &Path) -> Result<()> {
        let timeout = self.ctx.config.command_timeout;
        let out = self
            .ctx
            .sys
            .run(
                CommandSpec::new(bin::SEMANAGE, timeout)
                    .args(["fcontext", "-a", "-N", "-e", SELINUX_EQUIV_SOURCE, "--"])
                    .arg(root),
            )
            .await?;
        if !out.success() && !already_present(&out.stderr_lossy()) {
            return out.into_result().map(|_| ());
        }
        self.ctx
            .sys
            .run_ok(
                CommandSpec::new(bin::RESTORECON, timeout)
                    .args(["-RF", "--"])
                    .arg(root),
            )
            .await?;
        Ok(())
    }

    async fn unlabel_docroot(&self, root: &Path) -> Result<()> {
        let timeout = self.ctx.config.command_timeout;
        let out = self
            .ctx
            .sys
            .run(
                CommandSpec::new(bin::SEMANAGE, timeout)
                    .args(["fcontext", "-d", "-N", "--"])
                    .arg(root),
            )
            .await?;
        if !out.success() && !already_absent(&out.stderr_lossy()) {
            return out.into_result().map(|_| ());
        }
        self.ctx
            .sys
            .run_ok(
                CommandSpec::new(bin::RESTORECON, timeout)
                    .args(["-RF", "--"])
                    .arg(root),
            )
            .await?;
        Ok(())
    }
}

/// The server block a virtual-host record renders to for its tenant — the
/// single definition of "what should be on disk", shared by suspension and
/// reconciliation.
pub(crate) fn render_vhost(tenant: &TenantRecord, vhost: &VHostRecord) -> Result<String> {
    let domain = Domain::parse(&vhost.domain)?;
    let name = Username::parse_field(&tenant.username, "tenant")?;
    let docroot = RelPath::parse(&vhost.document_root)?;
    let aliases = vhost
        .aliases
        .iter()
        .map(|a| Domain::parse_field(a, "aliases"))
        .collect::<Result<Vec<Domain>>>()?;
    nginx::render_server_block(&nginx::ServerBlock {
        domain: &domain,
        aliases: &aliases,
        tenant: &name,
        document_root: &tenant.home.join(docroot.as_str()),
        suspended: tenant.suspended,
    })
}

/// Rewrite every virtual host of `tenant` from its records (used when the
/// tenant is suspended or resumed), validate once and activate. All files are
/// restored if Nginx rejects the result. With `force` the configuration is
/// validated and reloaded even when no file changed, which completes an
/// earlier attempt that wrote the files but failed before the reload.
///
/// The caller holds the mutation lock. Returns whether Nginx was reloaded.
pub(crate) async fn sync_tenant_configs(
    ctx: &Ctx,
    tenant: &TenantRecord,
    force: bool,
) -> Result<bool> {
    let timeout = ctx.config.command_timeout;
    let mut written: Vec<(PathBuf, Option<Vec<u8>>)> = Vec::new();
    let mut any = false;
    for v in ctx
        .store
        .list_vhosts()?
        .iter()
        .filter(|v| v.tenant == tenant.username)
    {
        any = true;
        let block = render_vhost(tenant, v)?;
        let previous = fsutil::read_optional(&v.config_path)?;
        if fsutil::write_atomic(&v.config_path, block.as_bytes(), nginx::CONF_MODE)? {
            written.push((v.config_path.clone(), previous));
        }
    }
    if !any || (written.is_empty() && !force) {
        return Ok(false);
    }
    match nginx::test_config(ctx.sys.as_ref(), timeout).await? {
        Ok(()) => {
            nginx::reload(ctx.sys.as_ref(), timeout).await?;
            Ok(true)
        }
        Err(output) => {
            warn!(tenant = %tenant.username, %output, "nginx rejected re-rendered virtual hosts; rolling back");
            for (path, previous) in &written {
                nginx::rollback(path, previous.as_deref())?;
            }
            Err(Error::NginxInvalid(output))
        }
    }
}

/// `semanage` says this when the rule is already in the store (idempotent replay).
fn already_present(stderr: &str) -> bool {
    stderr.contains("already defined") || stderr.contains("already exists")
}

/// `semanage` says this when there is nothing to delete.
fn already_absent(stderr: &str) -> bool {
    stderr.contains("not defined")
        || stderr.contains("does not exist")
        || stderr.contains("is not defined")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::system::FakeSystem;
    use crate::tenant::TenantService;
    use crate::validate::Limits;
    use std::sync::Arc;

    struct Harness {
        dir: tempfile::TempDir,
        sys: Arc<FakeSystem>,
        tenants: TenantService,
        vhosts: VHostService,
        config: Config,
    }

    async fn harness(selinux: bool) -> Harness {
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
        let ctx = Ctx::new(cfg.clone(), sys.clone(), selinux);
        ctx.store.init().unwrap_or_else(|e| panic!("{e}"));
        let tenants = TenantService::new(ctx.clone());
        tenants
            .create("alice", Limits::default(), "")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        tenants
            .create("bob", Limits::default(), "")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        nginx::ensure_include(
            sys.as_ref(),
            &cfg.nginx_conf_dir,
            &cfg.nginx_include_file,
            true,
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
        sys.clear_calls();
        Harness {
            dir,
            sys,
            tenants,
            vhosts: VHostService::new(ctx),
            config: cfg,
        }
    }

    fn req(domain: &str, tenant: &str) -> VHostRequest {
        VHostRequest {
            domain: domain.into(),
            tenant: tenant.into(),
            ..VHostRequest::default()
        }
    }

    fn args(c: &CommandSpec) -> Vec<String> {
        c.args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[tokio::test]
    async fn configure_creates_root_as_tenant_sets_acls_and_activates() -> Result<()> {
        let h = harness(false).await;
        let (rec, changed) = h
            .vhosts
            .configure(VHostRequest {
                aliases: vec!["www.example.com".into()],
                ..req("example.com", "alice")
            })
            .await?;
        assert!(changed);
        assert_eq!(rec.document_root, "public_html");
        assert_eq!(rec.aliases, vec!["www.example.com"]);
        let home = h.config.home_base.join("alice");
        let root = home.join("public_html");
        assert!(root.is_dir());
        // mkdir ran as the tenant with privileges dropped.
        let mk = h.sys.calls_to(bin::MKDIR);
        assert_eq!(mk.len(), 1);
        assert_eq!(
            mk.first().and_then(|c| c.run_as).map(|r| (r.uid, r.gid)),
            Some((20000, 20000))
        );
        assert_eq!(
            mk.first().map(args),
            Some(vec![
                "-p".to_owned(),
                "--".into(),
                root.to_string_lossy().into_owned()
            ])
        );
        // ACLs: traverse on home, read on root, with --physical.
        let acl = h.sys.calls_to(bin::SETFACL);
        assert_eq!(acl.len(), 2);
        assert_eq!(
            acl.first().map(args),
            Some(vec![
                "--physical".to_owned(),
                "-m".into(),
                "u:nginx:--x".into(),
                "--".into(),
                home.to_string_lossy().into_owned()
            ])
        );
        assert_eq!(
            acl.get(1).map(args),
            Some(vec![
                "--physical".to_owned(),
                "-m".into(),
                "u:nginx:r-x".into(),
                "-d".into(),
                "-m".into(),
                "u:nginx:r-x".into(),
                "--".into(),
                root.to_string_lossy().into_owned()
            ])
        );
        assert!(acl.iter().all(|c| c.run_as.is_none()));
        // Config on disk, include present, nginx tested then reloaded.
        let conf = std::fs::read_to_string(&rec.config_path)
            .map_err(|e| Error::io("read", &rec.config_path, e))?;
        assert!(conf.contains("server_name example.com www.example.com;"));
        assert!(conf.contains(&format!("root {};", root.display())));
        assert!(conf.contains("disable_symlinks if_not_owner;"));
        assert!(h.config.nginx_include_file.is_file());
        assert_eq!(h.sys.calls_to(bin::NGINX).len(), 1);
        assert!(h
            .sys
            .calls_to(bin::SYSTEMCTL)
            .iter()
            .any(|c| args(c) == ["reload-or-restart", "nginx.service"]));
        assert!(h.sys.calls_to(bin::SEMANAGE).is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn configure_is_idempotent() -> Result<()> {
        let h = harness(false).await;
        h.vhosts.configure(req("example.com", "alice")).await?;
        let nginx_calls = h.sys.calls_to(bin::NGINX).len();
        let (_, changed) = h.vhosts.configure(req("example.com", "alice")).await?;
        assert!(!changed);
        assert_eq!(
            h.sys.calls_to(bin::NGINX).len(),
            nginx_calls,
            "no re-test when nothing changed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn ownership_and_name_uniqueness_are_enforced() -> Result<()> {
        let h = harness(false).await;
        h.vhosts
            .configure(VHostRequest {
                aliases: vec!["www.example.com".into()],
                ..req("example.com", "alice")
            })
            .await?;
        // Bob cannot take Alice's domain or alias.
        assert!(matches!(
            h.vhosts.configure(req("example.com", "bob")).await,
            Err(Error::VHostOwnedByOther { .. })
        ));
        assert!(matches!(
            h.vhosts.configure(req("www.example.com", "bob")).await,
            Err(Error::VHostOwnedByOther { .. })
        ));
        assert!(matches!(
            h.vhosts
                .configure(VHostRequest {
                    aliases: vec!["www.example.com".into()],
                    ..req("bob.example", "bob")
                })
                .await,
            Err(Error::VHostOwnedByOther { .. })
        ));
        // Alice cannot reuse her own alias on a second vhost either.
        assert!(matches!(
            h.vhosts
                .configure(VHostRequest {
                    aliases: vec!["www.example.com".into()],
                    ..req("two.example.com", "alice")
                })
                .await,
            Err(Error::InvalidInput { .. })
        ));
        // Alias equal to the domain is rejected; too many aliases rejected.
        assert!(matches!(
            h.vhosts
                .configure(VHostRequest {
                    aliases: vec!["x.example.com".into()],
                    ..req("x.example.com", "alice")
                })
                .await,
            Err(Error::InvalidInput { .. })
        ));
        let many: Vec<String> = (0..=MAX_ALIASES)
            .map(|i| format!("a{i}.example.com"))
            .collect();
        assert!(matches!(
            h.vhosts
                .configure(VHostRequest {
                    aliases: many,
                    ..req("y.example.com", "alice")
                })
                .await,
            Err(Error::InvalidInput { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn rejects_unknown_or_unready_tenant_and_bad_paths() -> Result<()> {
        let h = harness(false).await;
        assert!(matches!(
            h.vhosts.configure(req("example.com", "zed")).await,
            Err(Error::TenantNotFound(_))
        ));
        assert!(
            matches!(
                h.vhosts.configure(req("example.com", "nobody")).await,
                Err(Error::InvalidInput { .. })
            ),
            "reserved name"
        );
        for bad in ["../etc", "/etc", "a//b", "pub lic", "x;y"] {
            let r = h
                .vhosts
                .configure(VHostRequest {
                    document_root: bad.into(),
                    ..req("example.com", "alice")
                })
                .await;
            assert!(matches!(r, Err(Error::InvalidInput { .. })), "{bad}");
        }
        assert!(
            h.sys.calls_to(bin::MKDIR).is_empty(),
            "nothing touched the filesystem"
        );
        Ok(())
    }

    #[tokio::test]
    async fn symlinked_document_root_is_refused() -> Result<()> {
        let h = harness(false).await;
        let home = h.config.home_base.join("alice");
        let target = h.dir.path().join("elsewhere");
        std::fs::create_dir_all(&target).map_err(|e| Error::io("mkdir", &target, e))?;
        std::os::unix::fs::symlink(&target, home.join("public_html"))
            .map_err(|e| Error::io("symlink", &home, e))?;
        let r = h.vhosts.configure(req("example.com", "alice")).await;
        assert!(matches!(r, Err(Error::InvalidInput { .. })), "{r:?}");
        assert!(
            h.sys.calls_to(bin::SETFACL).is_empty(),
            "no ACL granted through a symlink"
        );
        assert!(h.sys.calls_to(bin::NGINX).is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn invalid_nginx_config_rolls_back_and_leaves_no_record() -> Result<()> {
        let h = harness(false).await;
        h.sys.script_failure(bin::NGINX, 1, "nginx: [emerg] bad");
        let r = h.vhosts.configure(req("example.com", "alice")).await;
        assert!(matches!(r, Err(Error::NginxInvalid(_))));
        assert!(h.vhosts.list(None).await?.is_empty());
        assert!(
            !nginx::conf_path(&h.config.nginx_conf_dir, &Domain::parse("example.com")?).exists()
        );
        Ok(())
    }

    #[tokio::test]
    async fn remove_and_list() -> Result<()> {
        let h = harness(false).await;
        h.vhosts.configure(req("a.example.com", "alice")).await?;
        h.vhosts.configure(req("b.example.com", "bob")).await?;
        assert_eq!(h.vhosts.list(None).await?.len(), 2);
        assert_eq!(h.vhosts.list(Some("bob")).await?.len(), 1);
        assert!(h.vhosts.remove("a.example.com").await?);
        assert!(!h.vhosts.remove("a.example.com").await?);
        assert!(
            !nginx::conf_path(&h.config.nginx_conf_dir, &Domain::parse("a.example.com")?).exists()
        );
        assert_eq!(h.vhosts.list(Some("alice")).await?.len(), 0);
        // Tenant deletion now succeeds for alice but still fails for bob.
        assert!(h.tenants.delete("alice", true).await?);
        assert!(matches!(
            h.tenants.delete("bob", true).await,
            Err(Error::TenantHasVHosts(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn selinux_hosts_get_persistent_labels() -> Result<()> {
        let h = harness(true).await;
        h.vhosts
            .configure(VHostRequest {
                document_root: "www/site.v2".into(),
                ..req("example.com", "alice")
            })
            .await?;
        let root = h.config.home_base.join("alice").join("www").join("site.v2");
        let sem = h.sys.calls_to(bin::SEMANAGE);
        assert_eq!(sem.len(), 1);
        let expected_target = root.to_string_lossy().into_owned();
        assert_eq!(
            sem.first().map(args),
            Some(vec![
                "fcontext".to_owned(),
                "-a".into(),
                "-N".into(),
                "-e".into(),
                SELINUX_EQUIV_SOURCE.into(),
                "--".into(),
                expected_target.clone()
            ])
        );
        assert!(h
            .sys
            .calls_to(bin::RESTORECON)
            .iter()
            .any(|c| args(c) == ["-RF", "--", root.to_string_lossy().as_ref()]));
        // Intermediate directory got traverse too.
        let acl = h.sys.calls_to(bin::SETFACL);
        let first = acl.first().map(args).unwrap_or_default();
        assert!(first.contains(
            &h.config
                .home_base
                .join("alice")
                .join("www")
                .to_string_lossy()
                .into_owned()
        ));
        // "already defined" from semanage is not an error on replay.
        h.sys.script_failure(
            bin::SEMANAGE,
            1,
            "ValueError: Equivalence class for /home/alice/www/site.v2 already exists",
        );
        h.vhosts
            .configure(VHostRequest {
                document_root: "www/site.v2".into(),
                ..req("example.com", "alice")
            })
            .await?;
        // Removal drops the rule.
        h.vhosts.remove("example.com").await?;
        let sem = h.sys.calls_to(bin::SEMANAGE);
        assert_eq!(
            sem.last().map(args),
            Some(vec![
                "fcontext".to_owned(),
                "-d".into(),
                "-N".into(),
                "--".into(),
                expected_target
            ])
        );
        Ok(())
    }

    #[tokio::test]
    async fn config_paths_stay_within_the_managed_directory() -> Result<()> {
        let h = harness(false).await;
        let (rec, _) = h.vhosts.configure(req("example.com", "alice")).await?;
        assert!(rec.config_path.starts_with(&h.config.nginx_conf_dir));
        assert_eq!(
            rec.config_path.file_name().and_then(|n| n.to_str()),
            Some("example.com.conf")
        );
        Ok(())
    }

    #[tokio::test]
    async fn suspend_turns_every_site_of_the_tenant_into_503_and_resume_restores() -> Result<()> {
        let h = harness(false).await;
        let (a, _) = h.vhosts.configure(req("example.com", "alice")).await?;
        let (b, _) = h.vhosts.configure(req("example.net", "alice")).await?;
        let (other, _) = h.vhosts.configure(req("bob.example", "bob")).await?;
        let read = |p: &Path| std::fs::read_to_string(p).map_err(|e| Error::io("read", p, e));
        let before = read(&a.config_path)?;
        let bob_before = read(&other.config_path)?;
        h.sys.clear_calls();

        let (rec, changed) = h.tenants.set_suspended("alice", true).await?;
        assert!(changed && rec.suspended);
        for p in [&a.config_path, &b.config_path] {
            let conf = read(p)?;
            assert!(conf.contains("return 503;"), "{conf}");
            assert!(!conf.contains("root "));
        }
        assert_eq!(
            read(&other.config_path)?,
            bob_before,
            "other tenants untouched"
        );
        assert_eq!(
            h.sys.calls_to(bin::NGINX).len(),
            1,
            "one validation for all sites"
        );
        assert_eq!(h.sys.calls_to(bin::SYSTEMCTL).len(), 1);
        assert!(h.tenants.get("alice").await?.suspended);

        // Idempotent: nothing to write, nothing to reload.
        let (_, changed) = h.tenants.set_suspended("alice", true).await?;
        assert!(!changed);
        assert_eq!(h.sys.calls_to(bin::NGINX).len(), 1);

        // A site added while suspended is born suspended.
        let (c, _) = h.vhosts.configure(req("example.org", "alice")).await?;
        assert!(read(&c.config_path)?.contains("return 503;"));

        let (rec, changed) = h.tenants.set_suspended("alice", false).await?;
        assert!(changed && !rec.suspended);
        assert_eq!(read(&a.config_path)?, before);
        assert!(read(&c.config_path)?.contains("try_files"));
        assert!(!h.tenants.set_suspended("alice", false).await?.1);
        Ok(())
    }

    #[tokio::test]
    async fn suspend_rolls_back_every_file_when_nginx_rejects() -> Result<()> {
        let h = harness(false).await;
        let (a, _) = h.vhosts.configure(req("example.com", "alice")).await?;
        let (b, _) = h.vhosts.configure(req("example.net", "alice")).await?;
        let read = |p: &Path| std::fs::read_to_string(p).map_err(|e| Error::io("read", p, e));
        let (before_a, before_b) = (read(&a.config_path)?, read(&b.config_path)?);
        h.sys
            .script_failure(bin::NGINX, 1, "nginx: [emerg] broken elsewhere");
        assert!(matches!(
            h.tenants.set_suspended("alice", true).await,
            Err(Error::NginxInvalid(_))
        ));
        assert_eq!(read(&a.config_path)?, before_a);
        assert_eq!(read(&b.config_path)?, before_b);
        assert!(!h.tenants.get("alice").await?.suspended, "record unchanged");
        Ok(())
    }

    #[tokio::test]
    async fn suspend_retry_reloads_even_when_files_are_already_written() -> Result<()> {
        let h = harness(false).await;
        h.vhosts.configure(req("example.com", "alice")).await?;
        h.sys.clear_calls();
        // nginx -t passes (default), the reload fails: files are on disk, not active.
        h.sys
            .script_failure(bin::SYSTEMCTL, 1, "Job for nginx.service failed");
        assert!(matches!(
            h.tenants.set_suspended("alice", true).await,
            Err(Error::CommandFailed { .. })
        ));
        assert!(!h.tenants.get("alice").await?.suspended);
        let (rec, changed) = h.tenants.set_suspended("alice", true).await?;
        assert!(changed && rec.suspended);
        assert_eq!(
            h.sys.calls_to(bin::SYSTEMCTL).len(),
            2,
            "the retry reloads although no file changed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn suspending_a_tenant_without_sites_touches_nothing() -> Result<()> {
        let h = harness(false).await;
        let (rec, changed) = h.tenants.set_suspended("alice", true).await?;
        assert!(changed && rec.suspended);
        assert!(h.sys.calls().is_empty());
        Ok(())
    }
}
