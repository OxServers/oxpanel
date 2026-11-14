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

use crate::app;
use crate::config::Config;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::nginx;
use crate::php;
use crate::records::{
    now_unix, AppRecord, AppRuntime, TenantRecord, TenantState, VHostRecord, RECORD_VERSION,
};
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
    pub php: bool,
    pub app: Option<AppRequest>,
    /// Redirect plain HTTP to HTTPS / send HSTS, once a certificate is installed.
    pub redirect_https: bool,
    pub hsts: bool,
    /// Whether Automatic HTTPS looks after the site.
    pub auto_https: crate::records::AutoHttpsChoice,
    /// Whether DNS hosting gives the site's names address records.
    pub dns: crate::records::DnsChoice,
}

/// An application as requested on the wire; empty strings mean "default".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRequest {
    pub runtime: AppRuntime,
    pub root: String,
    pub entry: String,
}

/// Which of a virtual host's two logs to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    Access,
    Error,
    /// Output of the virtual host's application.
    App,
}

/// Default and upper bound for [`VHostService::read_log`].
pub const LOG_DEFAULT_BYTES: u64 = 32 * 1024;
pub const LOG_MAX_BYTES: u64 = 128 * 1024;
const LOG_DIR_MODE: u32 = 0o750;

/// `<log_dir>/<domain>.access.log` and `<log_dir>/<domain>.error.log`.
pub fn log_paths(cfg: &Config, domain: &Domain) -> (PathBuf, PathBuf) {
    (
        cfg.nginx_log_dir.join(format!("{domain}.access.log")),
        cfg.nginx_log_dir.join(format!("{domain}.error.log")),
    )
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
        let aliases = parse_aliases(&req.aliases, &domain)?;
        let app_rec = parse_app(req.app.as_ref(), req.php, &domain, &docroot)?;

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

        // A runtime the host cannot provide is refused before anything is created.
        if req.php && !self.ctx.sys.is_installed(bin::PHP_FPM).await {
            return Err(Error::PhpUnavailable);
        }
        if let Some(a) = &app_rec {
            app::preflight(&self.ctx, a.runtime).await?;
        }

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

        let path = nginx::conf_path(&cfg.nginx_conf_dir, &domain);
        let rec = VHostRecord {
            version: RECORD_VERSION,
            domain: domain.to_string(),
            tenant: tenant.to_string(),
            document_root: docroot.to_string(),
            aliases: aliases.iter().map(ToString::to_string).collect(),
            config_path: path.clone(),
            created_at_unix: existing
                .as_ref()
                .map_or_else(now_unix, |e| e.created_at_unix),
            php: req.php,
            app: app_rec,
            redirect_https: req.redirect_https,
            hsts: req.hsts,
            // The certificate is not part of the request: it stays as it is.
            tls: existing.as_ref().and_then(|e| e.tls.clone()),
            auto_https: req.auto_https,
            // Not part of the request either (SetPhpSettings): kept.
            php_settings: existing
                .as_ref()
                .map(|e| e.php_settings.clone())
                .unwrap_or_default(),
            dns: req.dns,
        };
        // The pool must be listening before Nginx is told to use it.
        let pool_changed = if rec.php {
            php::ensure_pool(&self.ctx, &tenant_rec, Some(&rec)).await?
        } else if rec.app.is_some() {
            app::ensure_app(&self.ctx, &tenant_rec, &rec).await?
        } else {
            false
        };
        fsutil::ensure_dir(&cfg.nginx_log_dir, LOG_DIR_MODE)?;
        let block = render_vhost(cfg, &tenant_rec, &rec)?;
        let changed = nginx::install_config(self.ctx.sys.as_ref(), &path, &block, timeout).await?
            || pool_changed;
        let record_changed = existing.as_ref() != Some(&rec);
        if record_changed {
            self.ctx.store.save_vhost(&rec)?;
        }
        let switched_off = self
            .follow_up(&tenant_rec, &domain, existing.as_ref(), &rec)
            .await?;
        let changed = changed || record_changed || switched_off;
        if changed {
            info!(%domain, %tenant, root = %abs_root.display(), php = rec.php, app = rec.app.as_ref().map_or("-", |a| a.runtime.as_str()), "virtual host configured");
        }
        Ok((rec, changed))
    }

    /// After a site is configured: what it no longer uses is dropped (the
    /// tenant's pool or the application, and the site's own PHP pool — both
    /// always looked at, never one instead of the other), then DNS hosting
    /// follows its names (best effort). Returns whether anything was removed.
    async fn follow_up(
        &self,
        tenant_rec: &TenantRecord,
        domain: &Domain,
        existing: Option<&VHostRecord>,
        rec: &VHostRecord,
    ) -> Result<bool> {
        let switched_off = self.drop_switched_off(tenant_rec, domain, rec).await?;
        let pool_dropped = self.drop_site_pool(tenant_rec, existing, rec).await?;
        dns_follows(&self.ctx, domain, existing, Some(rec)).await;
        Ok(switched_off || pool_dropped)
    }

    /// Stop what `rec` does not use: the tenant's PHP pool (if no other site
    /// needs it) and the site's application. Decided by what is on disk, not
    /// by what the previous record said: a request that switched PHP or the
    /// application off may have been interrupted after the record was saved,
    /// and repeating it must still remove them. Returns whether anything was
    /// removed.
    async fn drop_switched_off(
        &self,
        tenant_rec: &TenantRecord,
        domain: &Domain,
        rec: &VHostRecord,
    ) -> Result<bool> {
        let pool_removed = if rec.php {
            false
        } else {
            self.remove_pool_if_unused(tenant_rec, None).await?
        };
        // Likewise for the application: a unit for a site without one goes.
        let app_removed = if rec.app.is_some() {
            false
        } else {
            app::remove_app(&self.ctx, domain).await?
        };
        Ok(pool_removed || app_removed)
    }

    /// A site that had its own PHP pool (settings) and no longer runs PHP:
    /// its pool section goes from the tenant's FPM configuration, if the
    /// instance stays for other sites. Returns whether anything changed.
    async fn drop_site_pool(
        &self,
        tenant_rec: &TenantRecord,
        before: Option<&VHostRecord>,
        rec: &VHostRecord,
    ) -> Result<bool> {
        let had_pool = before.is_some_and(|b| b.php && !b.php_settings.is_empty());
        let cfg = &self.ctx.config;
        let name = Username::parse(&tenant_rec.username)?;
        let files = php::PoolFiles::for_tenant(&cfg.php_conf_dir, &cfg.systemd_unit_dir, &name);
        if !had_pool || rec.php || !files.unit.exists() {
            return Ok(false);
        }
        php::ensure_pool(&self.ctx, tenant_rec, Some(rec)).await
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
        self.remove_locked(&domain).await
    }

    /// [`Self::remove`] for a caller that holds the mutation lock (the
    /// deletion of a whole tenant).
    pub(crate) async fn remove_locked(&self, domain: &Domain) -> Result<bool> {
        let domain = domain.clone();
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
        // Nginx no longer refers to the certificate: it goes with the site.
        crate::tls::remove_material(&self.ctx, &domain)?;
        crate::auto_https::forget(&self.ctx.config, &domain)?;
        // Nginx has reloaded and no longer holds the logs open for this name.
        let (access_log, error_log) = log_paths(cfg, &domain);
        fsutil::remove_if_exists(&access_log)?;
        fsutil::remove_if_exists(&error_log)?;
        if rec.php {
            if let Some(t) = self.ctx.store.load_tenant(&Username::parse(&rec.tenant)?)? {
                let removed = self.remove_pool_if_unused(&t, Some(&domain)).await?;
                // The instance stays for other sites: this site's own pool goes.
                let gone = VHostRecord {
                    php: false,
                    ..rec.clone()
                };
                if !removed {
                    self.drop_site_pool(&t, Some(&rec), &gone).await?;
                }
            }
        }
        // Whatever the record says: a unit for this name must not outlive the site.
        app::remove_app(&self.ctx, &domain).await?;
        // The record goes last. Until then a repeated request finds it and
        // finishes whatever an interrupted attempt left behind; deleting it
        // first would strand a running PHP pool or application with nothing
        // left that says OxPanel owns it.
        self.ctx.store.delete_vhost(&domain)?;
        // Its address records go; a zone created for it goes too unless the
        // tenant added records to it.
        if let Err(e) = crate::dns::site_changed(&self.ctx, Some(&rec), None).await {
            warn!(%domain, error = %e, "the site's DNS records could not be removed; see `oxpanel-ctl host reconcile`");
        }
        info!(%domain, tenant = %rec.tenant, "virtual host removed");
        Ok(true)
    }

    /// The virtual host and its (ready) tenant, for the application RPCs.
    fn load_app_vhost(&self, domain: &Domain) -> Result<(TenantRecord, VHostRecord)> {
        let rec = self
            .ctx
            .store
            .load_vhost(domain)?
            .ok_or_else(|| Error::VHostNotFound(domain.to_string()))?;
        if rec.app.is_none() {
            return Err(Error::NoApp(domain.to_string()));
        }
        let name = Username::parse_field(&rec.tenant, "tenant")?;
        let tenant = self
            .ctx
            .store
            .load_tenant(&name)?
            .ok_or_else(|| Error::TenantNotFound(name.to_string()))?;
        if tenant.state != TenantState::Ready || tenant.suspended {
            return Err(Error::TenantNotReady(name.to_string()));
        }
        Ok((tenant, rec))
    }

    /// Restart the virtual host's application.
    pub async fn restart_app(&self, domain: &str) -> Result<()> {
        let domain = Domain::parse(domain)?;
        let _guard = self.ctx.lock.lock().await;
        let (_, rec) = self.load_app_vhost(&domain)?;
        app::restart(&self.ctx, &rec).await
    }

    /// Install the application's dependencies as the tenant. Returns whether
    /// the installer succeeded and the end of its output.
    ///
    /// Deliberately *not* under the mutation lock: an installation may take
    /// minutes and touches only the tenant's own files.
    pub async fn install_app_dependencies(&self, domain: &str) -> Result<(bool, String)> {
        let domain = Domain::parse(domain)?;
        let (tenant, rec) = self.load_app_vhost(&domain)?;
        let (succeeded, output) = app::run_installer(&self.ctx, &tenant, &rec).await?;
        if succeeded {
            // Minutes may have passed without the lock. Restart only what the
            // records call for *now*: a tenant suspended or a site removed
            // while the installer ran must stay stopped.
            let _guard = self.ctx.lock.lock().await;
            match self.load_app_vhost(&domain) {
                Ok((_, current)) => app::restart(&self.ctx, &current).await?,
                Err(
                    e @ (Error::TenantNotReady(_)
                    | Error::TenantNotFound(_)
                    | Error::VHostNotFound(_)
                    | Error::NoApp(_)),
                ) => {
                    info!(%domain, reason = %e, "dependencies installed; application not restarted");
                }
                Err(e) => return Err(e),
            }
        }
        Ok((succeeded, output))
    }

    /// Remove the tenant's PHP-FPM pool once none of its virtual hosts uses
    /// PHP. `except` names a virtual host that is being removed and therefore
    /// no longer counts, although its record still exists.
    async fn remove_pool_if_unused(
        &self,
        tenant: &TenantRecord,
        except: Option<&Domain>,
    ) -> Result<bool> {
        let cfg = &self.ctx.config;
        let name = Username::parse(&tenant.username)?;
        let files = php::PoolFiles::for_tenant(&cfg.php_conf_dir, &cfg.systemd_unit_dir, &name);
        if !files.unit.exists() && !files.conf.exists() {
            // Nothing to remove: skip reading every virtual-host record.
            return Ok(false);
        }
        let still_used = self.ctx.store.list_vhosts()?.iter().any(|v| {
            v.tenant == tenant.username && v.php && except.is_none_or(|d| v.domain != d.as_str())
        });
        if still_used {
            return Ok(false);
        }
        php::remove_pool(&self.ctx, tenant).await
    }

    /// The end of one of the virtual host's logs: at most `max_bytes`
    /// (0 = default), starting at a line boundary. Returns the text and
    /// whether the file holds more than was returned.
    pub async fn read_log(
        &self,
        domain: &str,
        kind: LogKind,
        max_bytes: u64,
    ) -> Result<(String, bool)> {
        let domain = Domain::parse(domain)?;
        let Some(rec) = self.ctx.store.load_vhost(&domain)? else {
            return Err(Error::VHostNotFound(domain.to_string()));
        };
        let (access_log, error_log) = log_paths(&self.ctx.config, &domain);
        let path = match kind {
            LogKind::Access => access_log,
            LogKind::Error => error_log,
            LogKind::App => return Ok((app::read_log(&self.ctx, &rec).await?, false)),
        };
        let limit = match max_bytes {
            0 => LOG_DEFAULT_BYTES,
            n => n.min(LOG_MAX_BYTES),
        };
        tokio::task::spawn_blocking(move || tail_file(&path, limit))
            .await
            .map_err(|e| Error::Internal(format!("read_log task: {e}")))?
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

    /// Replace the PHP settings of a PHP-enabled site (empty = PHP's
    /// defaults again). Validated against the tenant's caps before anything
    /// is touched; then the tenant's FPM configuration (the site's own pool)
    /// and the site's server block are rendered, validated and activated,
    /// and only then is the record saved — repeating the request completes
    /// an interrupted one. Returns the record and whether anything changed.
    pub async fn set_php_settings(
        &self,
        domain: &str,
        raw: &crate::php_settings::RawSettings,
    ) -> Result<(VHostRecord, bool)> {
        let domain = Domain::parse(domain)?;
        let _guard = self.ctx.lock.lock().await;
        let cfg = &self.ctx.config;
        let current = self
            .ctx
            .store
            .load_vhost(&domain)?
            .ok_or_else(|| Error::VHostNotFound(domain.to_string()))?;
        let name = Username::parse_field(&current.tenant, "tenant")?;
        let tenant = self
            .ctx
            .store
            .load_tenant(&name)?
            .ok_or_else(|| Error::TenantNotFound(name.to_string()))?;
        if tenant.state != TenantState::Ready {
            return Err(Error::TenantNotReady(name.to_string()));
        }
        let caps = tenant.php_limits.resolve(&cfg.essentials.php_max);
        let settings = crate::php_settings::parse(raw, &caps, &cfg.essentials.zoneinfo_dir)?;
        if !current.php {
            return Err(Error::PhpNotEnabled(domain.to_string()));
        }
        let rec = VHostRecord {
            php_settings: settings,
            ..current.clone()
        };
        let pool_changed = php::ensure_pool(&self.ctx, &tenant, Some(&rec)).await?;
        let block = render_vhost(cfg, &tenant, &rec)?;
        let conf_changed = nginx::install_config(
            self.ctx.sys.as_ref(),
            &rec.config_path,
            &block,
            cfg.command_timeout,
        )
        .await?;
        let record_changed = rec != current;
        if record_changed {
            self.ctx.store.save_vhost(&rec)?;
            info!(%domain, tenant = %name, "PHP settings changed");
        }
        Ok((rec, pool_changed || conf_changed || record_changed))
    }

    /// Replace a tenant's caps on PHP settings (0 = the host maximum; each
    /// within the host maxima). Sites keep the values they asked for; what
    /// is rendered is clamped to the new caps at once (the tenant's FPM
    /// configuration and server blocks are re-rendered and activated).
    pub async fn set_tenant_php_limits(
        &self,
        username: &str,
        raw: &crate::php_settings::PhpLimits,
    ) -> Result<(TenantRecord, bool)> {
        let name = Username::parse(username)?;
        let limits =
            crate::php_settings::PhpLimits::parse_caps(raw, &self.ctx.config.essentials.php_max)?;
        let _guard = self.ctx.lock.lock().await;
        let mut tenant = self
            .ctx
            .store
            .load_tenant(&name)?
            .ok_or_else(|| Error::TenantNotFound(name.to_string()))?;
        if tenant.state != TenantState::Ready {
            return Err(Error::TenantNotReady(name.to_string()));
        }
        let changed = tenant.php_limits != limits;
        tenant.php_limits = limits;
        // Rendered first, saved last: a failure leaves the old caps in force
        // and the request can simply be repeated.
        let cfg = &self.ctx.config;
        let files = php::PoolFiles::for_tenant(&cfg.php_conf_dir, &cfg.systemd_unit_dir, &name);
        if files.unit.exists() {
            php::ensure_pool(&self.ctx, &tenant, None).await?;
        }
        sync_tenant_configs(&self.ctx, &tenant, false).await?;
        if changed {
            self.ctx.store.save_tenant(&tenant)?;
            info!(tenant = %name, "PHP caps changed");
        }
        Ok((tenant, changed))
    }

    /// After a restore replaced files in the tenant's home: give every
    /// document root of the tenant what `configure` gives it — it exists and
    /// is the tenant's own directory, the web server may traverse to it and
    /// read it, and on SELinux hosts it carries the web-content label.
    /// The caller holds the mutation lock.
    pub(crate) async fn restore_web_access(&self, tenant: &TenantRecord) -> Result<()> {
        for v in self
            .ctx
            .store
            .list_vhosts()?
            .iter()
            .filter(|v| v.tenant == tenant.username)
        {
            let docroot = RelPath::parse(&v.document_root)?;
            let abs_root = tenant.home.join(docroot.as_str());
            self.create_document_root(tenant, &abs_root).await?;
            self.grant_web_access(&tenant.home, &docroot, &abs_root)
                .await?;
            if self.ctx.selinux {
                self.label_docroot(&abs_root).await?;
            }
        }
        Ok(())
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
        // The tenant owns this directory and may have deleted it (or renamed
        // it away): there is then nothing to relabel, and `restorecon` would
        // fail on the missing path, making the site impossible to remove and
        // the tenant impossible to delete.
        if root.symlink_metadata().is_err() {
            return Ok(());
        }
        // That check is only a shortcut: the tenant can remove, replace or
        // flip the path between it and `restorecon` (acceptance phase 80,
        // section 4c, made removal fail in most attempts that way). The rule
        // is gone by now, so the label is only the tenant's own business:
        // whatever `restorecon` could not reset is never served again (the
        // site's configuration is gone) and is relabelled with the home or
        // removed with it. A failure here must not make the site impossible
        // to remove, nor the tenant impossible to delete.
        let out = self
            .ctx
            .sys
            .run(
                CommandSpec::new(bin::RESTORECON, timeout)
                    .args(["-RF", "--"])
                    .arg(root),
            )
            .await?;
        if !out.success() {
            warn!(path = %root.display(), stderr = %out.stderr_lossy().trim(), "the document root changed while it was being relabelled; its label is left as it is");
        }
        Ok(())
    }
}

/// DNS hosting follows a site's names (old and new). The site is served
/// whatever happens there: a failure is logged and reported by `Reconcile`,
/// never returned (best effort by design, like Automatic HTTPS).
async fn dns_follows(
    ctx: &crate::ctx::Ctx,
    domain: &Domain,
    before: Option<&VHostRecord>,
    after: Option<&VHostRecord>,
) {
    if let Err(e) = crate::dns::site_changed(ctx, before, after).await {
        warn!(%domain, error = %e, "the site's DNS records could not be brought up to date; see `oxpanel-ctl host reconcile`");
    }
}

/// Validate, de-duplicate and sort the aliases of `domain`.
fn parse_aliases(raw: &[String], domain: &Domain) -> Result<Vec<Domain>> {
    if raw.len() > MAX_ALIASES {
        return Err(Error::invalid(
            "aliases",
            format!("at most {MAX_ALIASES} aliases"),
        ));
    }
    let mut aliases: BTreeSet<Domain> = BTreeSet::new();
    for a in raw {
        let a = Domain::parse_field(a, "aliases")?;
        if &a == domain {
            return Err(Error::invalid("aliases", "alias must differ from domain"));
        }
        aliases.insert(a);
    }
    Ok(aliases.into_iter().collect())
}

/// Validate an application request and fill in its defaults.
fn parse_app(
    req: Option<&AppRequest>,
    php: bool,
    domain: &Domain,
    docroot: &RelPath,
) -> Result<Option<AppRecord>> {
    let Some(a) = req else {
        return Ok(None);
    };
    if php {
        return Err(Error::invalid("app", "cannot be combined with php"));
    }
    let root = if a.root.is_empty() {
        RelPath::parse_field(&format!("apps/{domain}"), "app.root")?
    } else {
        RelPath::parse_field(&a.root, "app.root")?
    };
    let entry = if a.entry.is_empty() {
        RelPath::parse_field(a.runtime.default_entry(), "app.entry")?
    } else {
        RelPath::parse_field(&a.entry, "app.entry")?
    };
    // Source code must never sit where Nginx serves files from. (A document
    // root *inside* the application directory, such as apps/shop/public, is
    // the normal layout and fine.)
    if Path::new(root.as_str()).starts_with(docroot.as_str()) {
        return Err(Error::invalid(
            "app.root",
            "must not be the document root or inside it",
        ));
    }
    Ok(Some(AppRecord {
        runtime: a.runtime,
        root: root.to_string(),
        entry: entry.to_string(),
    }))
}

/// The server block a virtual-host record renders to for its tenant — the
/// single definition of "what should be on disk", shared by suspension and
/// reconciliation.
pub(crate) fn render_vhost(
    cfg: &Config,
    tenant: &TenantRecord,
    vhost: &VHostRecord,
) -> Result<String> {
    let domain = Domain::parse(&vhost.domain)?;
    let name = Username::parse_field(&tenant.username, "tenant")?;
    let docroot = RelPath::parse(&vhost.document_root)?;
    let aliases = vhost
        .aliases
        .iter()
        .map(|a| Domain::parse_field(a, "aliases"))
        .collect::<Result<Vec<Domain>>>()?;
    let (access_log, error_log) = log_paths(cfg, &domain);
    // A site with PHP settings is served by its own pool (php::site_pools).
    let own_pool = vhost.php && !vhost.php_settings.is_empty();
    let socket = vhost.php.then(|| {
        if own_pool {
            php::site_socket_path(&name, &domain)
        } else {
            php::socket_path(&name)
        }
    });
    let php_tuning = if own_pool {
        let caps = tenant.php_limits.resolve(&cfg.essentials.php_max);
        crate::php_settings::nginx_tuning(&crate::php_settings::effective(
            &vhost.php_settings,
            &caps,
        ))
    } else {
        None
    };
    let app_socket = vhost.app.as_ref().map(|_| app::socket_path(&domain));
    let challenges = crate::acme::challenge_dir(cfg);
    let certificate = crate::tls::cert_path(&cfg.tls_dir, &domain);
    let key = crate::tls::key_path(&cfg.tls_dir, &domain);
    let tls = vhost.tls.as_ref().map(|_| nginx::TlsBlock {
        certificate: &certificate,
        key: &key,
        redirect: vhost.redirect_https,
        hsts: vhost.hsts,
    });
    nginx::render_server_block(&nginx::ServerBlock {
        domain: &domain,
        aliases: &aliases,
        tenant: &name,
        document_root: &tenant.home.join(docroot.as_str()),
        suspended: tenant.suspended,
        access_log: &access_log,
        error_log: &error_log,
        php_socket: socket.as_deref(),
        app_socket: app_socket.as_deref(),
        acme_challenge_dir: &challenges,
        tls,
        php_tuning,
    })
}

/// Read up to `limit` bytes from the end of `path`, dropping a leading
/// partial line. A log that does not exist yet (no request so far) is empty.
pub(crate) fn tail_file(path: &Path, limit: u64) -> Result<(String, bool)> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((String::new(), false)),
        Err(e) => return Err(Error::io("open", path, e)),
    };
    let len = file
        .metadata()
        .map_err(|e| Error::io("stat", path, e))?
        .len();
    let truncated = len > limit;
    if truncated {
        file.seek(SeekFrom::Start(len - limit))
            .map_err(|e| Error::io("seek", path, e))?;
    }
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::io("read", path, e))?;
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if truncated {
        // The first line is almost certainly cut in half.
        match text.find('\n') {
            Some(i) => drain_to(&mut text, i + 1),
            None => text.clear(),
        }
    }
    Ok((text, truncated))
}

fn drain_to(text: &mut String, end: usize) {
    if text.is_char_boundary(end) {
        text.drain(..end);
    }
}

/// Bring every virtual-host file in line with its record. Run once at
/// start-up so configuration written by an older daemon version picks up
/// what this version renders. A rejected result is rolled back per tenant
/// and returned to the caller to log; it never prevents the daemon starting.
pub async fn converge_all(ctx: &Ctx) -> Result<usize> {
    let _guard = ctx.lock.lock().await;
    if ctx.store.list_vhosts()?.is_empty() {
        return Ok(0);
    }
    fsutil::ensure_dir(&ctx.config.nginx_log_dir, LOG_DIR_MODE)?;
    let mut reloaded = 0;
    for tenant in ctx.store.list_tenants()? {
        if tenant.state == TenantState::Ready && sync_tenant_configs(ctx, &tenant, false).await? {
            reloaded += 1;
        }
    }
    Ok(reloaded)
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
        let block = render_vhost(&ctx.config, tenant, v)?;
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

    /// Defect found by acceptance phase 80: a tenant that deletes its own
    /// document root (by mistake, or on purpose) made `RemoveVirtualHost` fail
    /// on SELinux hosts, because `restorecon` was run on the missing path. The
    /// site could then never be removed, nor the tenant deleted.
    #[tokio::test]
    async fn a_site_whose_document_root_the_tenant_deleted_can_still_be_removed() -> Result<()> {
        let h = harness(true).await;
        h.vhosts.configure(req("example.com", "alice")).await?;
        let root = h.config.home_base.join("alice").join("public_html");
        // The fake OS creates directories for real inside the sandbox.
        if root.exists() {
            std::fs::remove_dir_all(&root).map_err(|e| Error::io("rm", &root, e))?;
        } else {
            std::fs::create_dir_all(&root).map_err(|e| Error::io("mkdir", &root, e))?;
            std::fs::remove_dir_all(&root).map_err(|e| Error::io("rm", &root, e))?;
        }
        let before = h.sys.calls_to(bin::RESTORECON).len();
        // A real `restorecon` exits 255 on a missing path.
        h.sys.script_failure(
            bin::RESTORECON,
            255,
            "restorecon: lstat(/x) failed: No such file or directory",
        );
        assert!(h.vhosts.remove("example.com").await?);
        assert_eq!(
            h.sys.calls_to(bin::RESTORECON).len(),
            before,
            "nothing to relabel: restorecon must not be run on a missing path"
        );
        assert!(h
            .sys
            .calls_to(bin::SEMANAGE)
            .iter()
            .any(|c| args(c).starts_with(&["fcontext".to_owned(), "-d".to_owned()])));
        assert!(h.vhosts.list(None).await?.is_empty(), "the record is gone");
        Ok(())
    }

    /// Defect found while investigating acceptance phase 80, section 4c: the
    /// tenant flips its document root between a directory and a link while
    /// the operator removes the site. The root exists when the daemon looks,
    /// and is gone (or a link) when `restorecon` walks it, which then fails;
    /// on the VM that made `RemoveVirtualHost` fail in 12 of 15 attempts, and
    /// a tenant running such a loop could keep its site, and itself, from
    /// ever being removed. The relabel is now best effort; the parts that
    /// matter (the configuration, the labelling rule, the record) are not.
    #[tokio::test]
    async fn a_site_can_be_removed_while_the_tenant_flips_its_document_root() -> Result<()> {
        let h = harness(true).await;
        h.vhosts.configure(req("example.com", "alice")).await?;
        let root = h.config.home_base.join("alice").join("public_html");
        std::fs::create_dir_all(&root).map_err(|e| Error::io("mkdir", &root, e))?;
        let config = nginx::conf_path(&h.config.nginx_conf_dir, &Domain::parse("example.com")?);
        assert!(config.exists());
        let before = h.sys.calls_to(bin::RESTORECON).len();
        // The path is there when looked at, and gone when restorecon walks it.
        h.sys.script_failure(
            bin::RESTORECON,
            255,
            "restorecon: lstat(/home/alice/public_html) failed: No such file or directory",
        );
        assert!(
            h.vhosts.remove("example.com").await?,
            "removed despite the race"
        );
        assert_eq!(
            h.sys.calls_to(bin::RESTORECON).len(),
            before + 1,
            "the relabel was attempted (and lost the race)"
        );
        assert!(h
            .sys
            .calls_to(bin::SEMANAGE)
            .iter()
            .any(|c| args(c).starts_with(&["fcontext".to_owned(), "-d".to_owned()])));
        assert!(!config.exists(), "the configuration is gone");
        assert!(h.vhosts.list(None).await?.is_empty(), "the record is gone");
        // And the tenant can be deleted afterwards.
        assert!(h.tenants.delete("alice", true).await?);
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

    fn php_req(domain: &str, tenant: &str) -> VHostRequest {
        VHostRequest {
            php: true,
            ..req(domain, tenant)
        }
    }

    fn systemctl_calls(h: &Harness) -> Vec<Vec<String>> {
        h.sys.calls_to(bin::SYSTEMCTL).iter().map(args).collect()
    }

    fn pool_files(h: &Harness, tenant: &str) -> (PathBuf, PathBuf) {
        (
            h.config.php_conf_dir.join(format!("{tenant}.conf")),
            h.config
                .systemd_unit_dir
                .join(format!("oxpanel-php-{tenant}.service")),
        )
    }

    #[tokio::test]
    async fn php_site_gets_a_pool_started_before_nginx_uses_it() -> Result<()> {
        let h = harness(false).await;
        let (rec, changed) = h.vhosts.configure(php_req("example.com", "alice")).await?;
        assert!(changed && rec.php);
        let (conf, unit) = pool_files(&h, "alice");
        assert!(conf.is_file() && unit.is_file());
        assert_eq!(
            systemctl_calls(&h),
            vec![
                vec!["daemon-reload".to_owned()],
                vec![
                    "enable".into(),
                    "--".into(),
                    "oxpanel-php-alice.service".into()
                ],
                vec![
                    "restart".into(),
                    "--".into(),
                    "oxpanel-php-alice.service".into()
                ],
                vec!["reload-or-restart".into(), "nginx.service".into()],
            ],
            "pool is up before nginx is reloaded"
        );
        let site = std::fs::read_to_string(&rec.config_path)
            .map_err(|e| Error::io("read", &rec.config_path, e))?;
        assert!(site.contains("fastcgi_pass unix:/run/oxpanel-php/alice/php.sock;"));
        assert!(h
            .sys
            .calls()
            .iter()
            .all(|c| c.run_as.is_none() || c.program == bin::MKDIR));

        // Replay: nothing changes; the unit is only confirmed enabled and running.
        h.sys.clear_calls();
        let (_, changed) = h.vhosts.configure(php_req("example.com", "alice")).await?;
        assert!(!changed);
        assert_eq!(
            systemctl_calls(&h),
            vec![vec![
                "enable".to_owned(),
                "--now".into(),
                "--".into(),
                "oxpanel-php-alice.service".into()
            ]]
        );
        Ok(())
    }

    #[tokio::test]
    async fn php_is_refused_cleanly_when_not_installed() -> Result<()> {
        let h = harness(false).await;
        h.sys.set_missing(bin::PHP_FPM);
        assert!(matches!(
            h.vhosts.configure(php_req("example.com", "alice")).await,
            Err(Error::PhpUnavailable)
        ));
        let (conf, unit) = pool_files(&h, "alice");
        assert!(!conf.exists() && !unit.exists());
        assert!(h.vhosts.list(None).await?.is_empty(), "no record, no site");
        assert!(h.sys.calls_to(bin::NGINX).is_empty());
        // A static site still works on such a host.
        h.vhosts.configure(req("example.com", "alice")).await?;
        Ok(())
    }

    #[tokio::test]
    async fn pool_lives_exactly_as_long_as_a_php_site_needs_it() -> Result<()> {
        let h = harness(false).await;
        h.vhosts.configure(php_req("example.com", "alice")).await?;
        h.vhosts.configure(php_req("example.net", "alice")).await?;
        h.vhosts.configure(req("bob.example", "bob")).await?;
        let (conf, unit) = pool_files(&h, "alice");
        assert!(
            !pool_files(&h, "bob").1.exists(),
            "static tenants get no pool"
        );

        // One of two PHP sites goes: the pool stays.
        assert!(h.vhosts.remove("example.net").await?);
        assert!(conf.is_file() && unit.is_file());

        // PHP switched off on the last one: the pool goes, the site stays.
        h.sys.clear_calls();
        let (rec, changed) = h.vhosts.configure(req("example.com", "alice")).await?;
        assert!(changed && !rec.php);
        assert!(!conf.exists() && !unit.exists());
        assert!(systemctl_calls(&h).contains(&vec![
            "disable".to_owned(),
            "--now".into(),
            "--".into(),
            "oxpanel-php-alice.service".into()
        ]));
        let site = std::fs::read_to_string(&rec.config_path)
            .map_err(|e| Error::io("read", &rec.config_path, e))?;
        assert!(!site.contains("fastcgi_pass"));

        // Switched on again and then the site removed: gone again.
        h.vhosts.configure(php_req("example.com", "alice")).await?;
        assert!(unit.is_file());
        assert!(h.vhosts.remove("example.com").await?);
        assert!(!conf.exists() && !unit.exists());
        Ok(())
    }

    #[tokio::test]
    async fn suspension_stops_php_after_the_sites_and_resume_starts_it_first() -> Result<()> {
        let h = harness(false).await;
        h.vhosts.configure(php_req("example.com", "alice")).await?;
        h.sys.clear_calls();
        h.tenants.set_suspended("alice", true).await?;
        assert_eq!(
            systemctl_calls(&h),
            vec![
                vec!["reload-or-restart".to_owned(), "nginx.service".into()],
                vec![
                    "disable".into(),
                    "--now".into(),
                    "--".into(),
                    "oxpanel-php-alice.service".into()
                ],
            ]
        );
        // A PHP site added while suspended does not start PHP.
        h.sys.clear_calls();
        h.vhosts.configure(php_req("example.net", "alice")).await?;
        assert!(systemctl_calls(&h)
            .iter()
            .all(|c| c.first().is_some_and(|v| v == "reload-or-restart")));
        h.sys.clear_calls();
        h.tenants.set_suspended("alice", false).await?;
        assert_eq!(
            systemctl_calls(&h),
            vec![
                vec![
                    "enable".to_owned(),
                    "--now".into(),
                    "--".into(),
                    "oxpanel-php-alice.service".into()
                ],
                vec!["reload-or-restart".into(), "nginx.service".into()],
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn logs_are_per_site_readable_by_tail_and_removed_with_the_site() -> Result<()> {
        let h = harness(false).await;
        let (rec, _) = h.vhosts.configure(req("example.com", "alice")).await?;
        let site = std::fs::read_to_string(&rec.config_path)
            .map_err(|e| Error::io("read", &rec.config_path, e))?;
        let (access, error) = log_paths(&h.config, &Domain::parse("example.com")?);
        assert!(site.contains(&format!("access_log {};", access.display())));
        assert!(site.contains(&format!("error_log {};", error.display())));
        assert!(h.config.nginx_log_dir.is_dir());

        // No request yet: empty, not an error.
        assert_eq!(
            h.vhosts.read_log("example.com", LogKind::Access, 0).await?,
            (String::new(), false)
        );
        let lines = (0..200)
            .map(|i| format!("line {i:03}"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&access, &lines).map_err(|e| Error::io("write", &access, e))?;
        std::fs::write(&error, "boom\n").map_err(|e| Error::io("write", &error, e))?;
        let (all, truncated) = h.vhosts.read_log("example.com", LogKind::Access, 0).await?;
        assert_eq!((all.as_str(), truncated), (lines.as_str(), false));
        // 25 bytes from the end = 2 full lines and a partial one, which is dropped.
        let (tail, truncated) = h
            .vhosts
            .read_log("example.com", LogKind::Access, 25)
            .await?;
        assert_eq!((tail.as_str(), truncated), ("line 198\nline 199\n", true));
        assert_eq!(
            h.vhosts.read_log("example.com", LogKind::Error, 0).await?.0,
            "boom\n"
        );
        // Only sites with a record; names are validated (no path traversal).
        assert!(matches!(
            h.vhosts.read_log("other.example", LogKind::Access, 0).await,
            Err(Error::VHostNotFound(_))
        ));
        assert!(matches!(
            h.vhosts
                .read_log("../../etc/shadow", LogKind::Access, 0)
                .await,
            Err(Error::InvalidInput { .. })
        ));
        assert!(h.vhosts.remove("example.com").await?);
        assert!(!access.exists() && !error.exists());
        Ok(())
    }

    #[tokio::test]
    async fn start_up_convergence_rewrites_stale_files_once() -> Result<()> {
        let h = harness(false).await;
        let (rec, _) = h.vhosts.configure(req("example.com", "alice")).await?;
        // As written by an older version of the daemon.
        std::fs::write(&rec.config_path, "server { listen 80; }\n")
            .map_err(|e| Error::io("write", &rec.config_path, e))?;
        h.sys.clear_calls();
        assert_eq!(converge_all(&h.vhosts.ctx).await?, 1);
        assert!(std::fs::read_to_string(&rec.config_path)
            .map_err(|e| Error::io("read", &rec.config_path, e))?
            .contains("access_log"));
        assert_eq!(h.sys.calls_to(bin::NGINX).len(), 1);
        assert_eq!(
            converge_all(&h.vhosts.ctx).await?,
            0,
            "second run is a no-op"
        );
        assert_eq!(h.sys.calls_to(bin::NGINX).len(), 1);
        Ok(())
    }

    fn app_req(domain: &str, tenant: &str, runtime: AppRuntime) -> VHostRequest {
        VHostRequest {
            app: Some(AppRequest {
                runtime,
                root: String::new(),
                entry: String::new(),
            }),
            ..req(domain, tenant)
        }
    }

    fn app_unit(h: &Harness, domain: &str) -> PathBuf {
        h.config
            .systemd_unit_dir
            .join(format!("oxpanel-app-{domain}.service"))
    }

    #[tokio::test]
    async fn node_app_is_created_as_the_tenant_and_started_before_nginx_uses_it() -> Result<()> {
        let h = harness(false).await;
        let (rec, changed) = h
            .vhosts
            .configure(app_req("example.com", "alice", AppRuntime::Node))
            .await?;
        assert!(changed);
        assert_eq!(
            rec.app,
            Some(AppRecord {
                runtime: AppRuntime::Node,
                root: "apps/example.com".into(),
                entry: "app.js".into()
            })
        );
        let home = h.config.home_base.join("alice");
        let root = home.join("apps/example.com");
        assert!(root.is_dir());
        // Both directories were created as the tenant; only the document
        // root is opened to the web server.
        let mk = h.sys.calls_to(bin::MKDIR);
        assert_eq!(mk.len(), 2);
        assert!(mk
            .iter()
            .all(|c| c.run_as.map(|r| (r.uid, r.gid)) == Some((20000, 20000))));
        let root_s = root.to_string_lossy().into_owned();
        assert!(
            h.sys
                .calls_to(bin::SETFACL)
                .iter()
                .all(|c| !args(c).contains(&root_s)),
            "the application directory gets no web-server ACL"
        );
        assert!(h.sys.calls_to(bin::PYTHON3).is_empty());
        assert_eq!(
            systemctl_calls(&h),
            vec![
                vec!["daemon-reload".to_owned()],
                vec![
                    "enable".into(),
                    "--".into(),
                    "oxpanel-app-example.com.service".into()
                ],
                vec![
                    "restart".into(),
                    "--".into(),
                    "oxpanel-app-example.com.service".into()
                ],
                vec!["reload-or-restart".into(), "nginx.service".into()],
            ]
        );
        let unit = std::fs::read_to_string(app_unit(&h, "example.com"))
            .map_err(|e| Error::io("read", "unit", e))?;
        assert!(unit.contains(&format!("ExecStart=/usr/bin/node {root_s}/app.js\n")));
        let site = std::fs::read_to_string(&rec.config_path)
            .map_err(|e| Error::io("read", &rec.config_path, e))?;
        assert!(site.contains("proxy_pass http://unix:/run/oxpanel-app/example.com/app.sock:;"));

        // Replay changes nothing.
        h.sys.clear_calls();
        let (_, changed) = h
            .vhosts
            .configure(app_req("example.com", "alice", AppRuntime::Node))
            .await?;
        assert!(!changed);
        assert_eq!(
            systemctl_calls(&h),
            vec![vec![
                "enable".to_owned(),
                "--now".into(),
                "--".into(),
                "oxpanel-app-example.com.service".into()
            ]]
        );
        Ok(())
    }

    #[tokio::test]
    async fn python_app_gets_its_own_virtualenv_created_as_the_tenant() -> Result<()> {
        let h = harness(false).await;
        let (rec, _) = h
            .vhosts
            .configure(VHostRequest {
                app: Some(AppRequest {
                    runtime: AppRuntime::Python,
                    root: "apps/api".into(),
                    entry: "src/main.py".into(),
                }),
                ..req("example.com", "alice")
            })
            .await?;
        let root = h.config.home_base.join("alice/apps/api");
        let venv = h.sys.calls_to(bin::PYTHON3);
        assert_eq!(venv.len(), 1);
        assert_eq!(
            venv.first().map(args),
            Some(vec![
                "-m".to_owned(),
                "venv".into(),
                "--".into(),
                root.join(".venv").to_string_lossy().into_owned()
            ])
        );
        assert_eq!(
            venv.first().and_then(|c| c.run_as).map(|r| (r.uid, r.gid)),
            Some((20000, 20000)),
            "the virtualenv is created by the tenant, never by root"
        );
        let unit = std::fs::read_to_string(app_unit(&h, "example.com"))
            .map_err(|e| Error::io("read", "unit", e))?;
        assert!(unit.contains(&format!(
            "ExecStart=/usr/bin/env {0}/.venv/bin/python {0}/src/main.py\n",
            root.display()
        )));
        assert_eq!(rec.app.map(|a| a.entry).as_deref(), Some("src/main.py"));
        Ok(())
    }

    #[tokio::test]
    async fn app_requests_are_validated_before_anything_happens() -> Result<()> {
        let h = harness(false).await;
        let with = |root: &str, entry: &str| VHostRequest {
            app: Some(AppRequest {
                runtime: AppRuntime::Node,
                root: root.into(),
                entry: entry.into(),
            }),
            ..req("example.com", "alice")
        };
        for bad in [
            with("../other", ""),
            with("/etc", ""),
            with("apps/x", "../../../etc/passwd"),
            with("apps/x", "app.js --inspect"),
            with("apps/x; rm -rf /", ""),
            // Source code where Nginx serves files from.
            with("public_html", ""),
            with("public_html/app", ""),
        ] {
            assert!(
                matches!(
                    h.vhosts.configure(bad.clone()).await,
                    Err(Error::InvalidInput { .. })
                ),
                "{bad:?}"
            );
        }
        assert!(matches!(
            h.vhosts
                .configure(VHostRequest {
                    php: true,
                    ..app_req("example.com", "alice", AppRuntime::Node)
                })
                .await,
            Err(Error::InvalidInput { .. })
        ));
        assert!(h.sys.calls().is_empty(), "nothing reached the OS");
        // The document root may live inside the application directory.
        h.vhosts
            .configure(VHostRequest {
                document_root: "apps/shop/public".into(),
                ..with("apps/shop", "")
            })
            .await?;
        // A missing runtime is refused cleanly.
        h.sys.set_missing(bin::NODE);
        assert!(matches!(
            h.vhosts
                .configure(app_req("example.net", "alice", AppRuntime::Node))
                .await,
            Err(Error::RuntimeUnavailable(_))
        ));
        assert!(!app_unit(&h, "example.net").exists());
        Ok(())
    }

    #[tokio::test]
    async fn app_lifecycle_follows_the_site_and_the_tenant() -> Result<()> {
        let h = harness(false).await;
        h.vhosts
            .configure(app_req("example.com", "alice", AppRuntime::Node))
            .await?;
        h.vhosts
            .configure(app_req("example.net", "alice", AppRuntime::Python))
            .await?;
        let stop = |d: &str| {
            vec![
                "disable".to_owned(),
                "--now".into(),
                "--".into(),
                format!("oxpanel-app-{d}.service"),
            ]
        };
        let start = |d: &str| {
            vec![
                "enable".to_owned(),
                "--now".into(),
                "--".into(),
                format!("oxpanel-app-{d}.service"),
            ]
        };

        // Suspend: sites go 503 first, then both applications stop.
        h.sys.clear_calls();
        h.tenants.set_suspended("alice", true).await?;
        assert_eq!(
            systemctl_calls(&h),
            vec![
                vec!["reload-or-restart".to_owned(), "nginx.service".into()],
                stop("example.com"),
                stop("example.net"),
            ]
        );
        // The application RPCs are refused while suspended.
        assert!(matches!(
            h.vhosts.restart_app("example.com").await,
            Err(Error::TenantNotReady(_))
        ));
        assert!(matches!(
            h.vhosts.install_app_dependencies("example.com").await,
            Err(Error::TenantNotReady(_))
        ));
        // Resume: applications start before the sites return.
        h.sys.clear_calls();
        h.tenants.set_suspended("alice", false).await?;
        assert_eq!(
            systemctl_calls(&h),
            vec![
                start("example.com"),
                start("example.net"),
                vec!["reload-or-restart".into(), "nginx.service".into()],
            ]
        );

        // Switching the application off removes its unit; the code stays.
        h.sys.clear_calls();
        let (rec, changed) = h.vhosts.configure(req("example.com", "alice")).await?;
        assert!(changed && rec.app.is_none());
        assert!(!app_unit(&h, "example.com").exists());
        assert!(systemctl_calls(&h).contains(&stop("example.com")));
        assert!(h.config.home_base.join("alice/apps/example.com").is_dir());
        // Removing the site removes its unit too.
        assert!(h.vhosts.remove("example.net").await?);
        assert!(!app_unit(&h, "example.net").exists());
        Ok(())
    }

    #[tokio::test]
    async fn application_units_of_an_older_version_are_rewritten_at_start_up() -> Result<()> {
        let h = harness(false).await;
        h.vhosts
            .configure(app_req("example.com", "alice", AppRuntime::Node))
            .await?;
        h.vhosts
            .configure(app_req("example.net", "bob", AppRuntime::Node))
            .await?;
        h.sys.clear_calls();
        assert_eq!(crate::app::converge_units(&h.vhosts.ctx).await?, 0);
        assert!(systemctl_calls(&h).is_empty(), "nothing to do");
        // An older version's wording, which reached the account's journal.
        let path = app_unit(&h, "example.com");
        let old = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{e}"))
            .replace("(account alice)", "(tenant alice)");
        std::fs::write(&path, old).unwrap_or_else(|e| panic!("{e}"));
        // A suspended tenant's unit is rewritten but its application not started.
        h.tenants.set_suspended("bob", true).await?;
        let path_b = app_unit(&h, "example.net");
        std::fs::write(
            &path_b,
            std::fs::read_to_string(&path_b)
                .unwrap_or_else(|e| panic!("{e}"))
                .replace("(account bob)", "(tenant bob)"),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        h.sys.clear_calls();
        assert_eq!(crate::app::converge_units(&h.vhosts.ctx).await?, 2);
        assert_eq!(
            systemctl_calls(&h),
            vec![
                vec!["daemon-reload".to_owned()],
                vec![
                    "try-restart".to_owned(),
                    "--".into(),
                    "oxpanel-app-example.com.service".into()
                ],
            ]
        );
        assert!(std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{e}"))
            .contains("Description=OxPanel node application for example.com (account alice)\n"));
        assert!(std::fs::read_to_string(&path_b)
            .unwrap_or_else(|e| panic!("{e}"))
            .contains("(account bob)"));
        Ok(())
    }

    #[tokio::test]
    async fn restart_and_dependency_installation_run_exact_commands() -> Result<()> {
        let h = harness(false).await;
        h.vhosts
            .configure(app_req("my-app.example.com", "alice", AppRuntime::Node))
            .await?;
        h.vhosts.configure(req("static.example", "alice")).await?;
        h.sys.clear_calls();

        h.vhosts.restart_app("my-app.example.com").await?;
        let unit = "oxpanel-app-my\\x2dapp.example.com.service";
        assert_eq!(
            systemctl_calls(&h),
            vec![
                vec!["reset-failed".to_owned(), "--".into(), unit.into()],
                vec!["restart".into(), "--".into(), unit.into()],
            ]
        );
        for rpc_on_static in [
            h.vhosts.restart_app("static.example").await.err(),
            h.vhosts
                .install_app_dependencies("static.example")
                .await
                .err(),
        ] {
            assert!(matches!(rpc_on_static, Some(Error::NoApp(_))));
        }
        assert!(matches!(
            h.vhosts.restart_app("nosuch.example").await,
            Err(Error::VHostNotFound(_))
        ));

        h.sys.clear_calls();
        let (ok, _) = h
            .vhosts
            .install_app_dependencies("my-app.example.com")
            .await?;
        assert!(ok);
        let run = h.sys.calls_to(bin::SYSTEMD_RUN);
        assert_eq!(run.len(), 1);
        let argv = run.first().map(args).unwrap_or_default();
        let home = h.config.home_base.join("alice");
        let expect_props = [
            "User=alice".to_owned(),
            "Group=alice".into(),
            "Slice=oxpanel-tenant-alice.slice".into(),
            format!(
                "WorkingDirectory={}/apps/my-app.example.com",
                home.display()
            ),
            format!("ReadWritePaths={}", home.display()),
            "NoNewPrivileges=yes".into(),
            "CapabilityBoundingSet=".into(),
            "ProtectSystem=strict".into(),
        ];
        for p in &expect_props {
            assert!(
                argv.windows(2)
                    .any(|w| w == ["--property".to_owned(), p.clone()]),
                "missing property {p}: {argv:?}"
            );
        }
        assert!(argv.contains(&"--unit=oxpanel-appdeps-my\\x2dapp.example.com".to_owned()));
        assert!(
            !argv.contains(&"--pipe".to_owned()),
            "output is read from the journal; SELinux forbids systemd writing to our pipes"
        );
        let journal = h.sys.calls_to(bin::JOURNALCTL);
        assert_eq!(journal.len(), 1);
        let jargv = journal.first().map(args).unwrap_or_default();
        assert!(jargv.ends_with(&[
            "--unit".to_owned(),
            "oxpanel-appdeps-my\\x2dapp.example.com.service".to_owned()
        ]));
        assert!(
            jargv.iter().any(|a| a.starts_with('@')),
            "bounded to this run: {jargv:?}"
        );
        let tail: Vec<&str> = argv
            .iter()
            .skip_while(|a| a.as_str() != "--")
            .map(String::as_str)
            .collect();
        assert_eq!(
            tail,
            [
                "--",
                "/usr/bin/npm",
                "install",
                "--omit=dev",
                "--no-audit",
                "--no-fund"
            ]
        );
        assert!(
            run.first().is_some_and(|c| c.run_as.is_none()),
            "systemd-run itself is root; the unit it creates is the tenant"
        );
        // A successful installation restarts the application.
        assert!(systemctl_calls(&h).contains(&vec![
            "restart".to_owned(),
            "--".into(),
            unit.into()
        ]));

        Ok(())
    }

    #[tokio::test]
    async fn a_failing_installer_is_a_result_and_restarts_nothing() -> Result<()> {
        let h = harness(false).await;
        h.vhosts
            .configure(app_req("my-app.example.com", "alice", AppRuntime::Node))
            .await?;
        // A failing installer is a result, and does not restart anything.
        h.sys.clear_calls();
        h.sys
            .script_failure(bin::SYSTEMD_RUN, 1, "npm ERR! code E404");
        let (ok, output) = h
            .vhosts
            .install_app_dependencies("my-app.example.com")
            .await?;
        assert!(!ok);
        assert!(output.contains("E404"));
        assert!(systemctl_calls(&h).is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn python_dependencies_install_into_the_virtualenv() -> Result<()> {
        let h = harness(false).await;
        h.vhosts
            .configure(app_req("example.com", "alice", AppRuntime::Python))
            .await?;
        h.sys.clear_calls();
        h.vhosts.install_app_dependencies("example.com").await?;
        let run = h.sys.calls_to(bin::SYSTEMD_RUN);
        let argv = run.first().map(args).unwrap_or_default();
        let tail: Vec<String> = argv
            .iter()
            .skip_while(|a| a.as_str() != "--")
            .cloned()
            .collect();
        let python = h
            .config
            .home_base
            .join("alice/apps/example.com/.venv/bin/python")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            tail,
            [
                "--",
                "/usr/bin/env",
                python.as_str(),
                "-m",
                "pip",
                "install",
                "--no-input",
                "--disable-pip-version-check",
                "--requirement",
                "requirements.txt"
            ]
        );
        // The application log comes from the journal of exactly this unit.
        h.sys.clear_calls();
        h.vhosts.read_log("example.com", LogKind::App, 0).await?;
        assert_eq!(
            h.sys.calls_to(bin::JOURNALCTL).first().map(args),
            Some(vec![
                "--no-pager".to_owned(),
                "--output=short-iso".into(),
                "--lines".into(),
                "200".into(),
                "--unit".into(),
                "oxpanel-app-example.com.service".into()
            ])
        );
        Ok(())
    }

    #[tokio::test]
    async fn selinux_hosts_run_apps_in_their_own_domain_and_need_the_module() -> Result<()> {
        let h = harness(true).await;
        h.vhosts
            .configure(app_req("example.com", "alice", AppRuntime::Node))
            .await?;
        let unit = std::fs::read_to_string(app_unit(&h, "example.com"))
            .map_err(|e| Error::io("read", "unit", e))?;
        assert!(unit.contains("SELinuxContext=system_u:system_r:oxpanel_app_t:s0\n"));
        assert_eq!(
            h.sys.calls_to(bin::SEMODULE).first().map(args),
            Some(vec!["--list-modules".to_owned()])
        );
        // Without the module nothing is created and the error says what to do.
        h.sys.set_missing(bin::SEMODULE);
        let err = h
            .vhosts
            .configure(app_req("example.net", "alice", AppRuntime::Node))
            .await;
        assert!(matches!(err, Err(Error::AppPolicyMissing)));
        assert!(!app_unit(&h, "example.net").exists());
        assert!(h
            .vhosts
            .list(None)
            .await?
            .iter()
            .all(|v| v.domain != "example.net"));
        Ok(())
    }

    #[tokio::test]
    async fn node_older_than_22_is_refused_before_anything_is_created() -> Result<()> {
        let h = harness(false).await;
        for old in ["v16.20.2", "v20.18.0", "v21.7.3", "garbage", ""] {
            h.sys.set_node_version(old);
            let err = h
                .vhosts
                .configure(app_req("example.com", "alice", AppRuntime::Node))
                .await;
            assert!(
                matches!(err, Err(Error::RuntimeTooOld { minimum: 22, .. })),
                "{old:?}: {err:?}"
            );
        }
        assert!(!app_unit(&h, "example.com").exists());
        assert!(h.vhosts.list(None).await?.is_empty());
        assert!(
            h.sys.calls_to(bin::MKDIR).is_empty(),
            "not even the directory"
        );
        let msg = Error::RuntimeTooOld {
            runtime: "Node.js",
            found: "16.20.2".into(),
            minimum: 22,
        }
        .to_string();
        assert_eq!(
            msg,
            "Node.js 16.20.2 is installed, but version 22 or newer is required (dnf module switch-to nodejs:22)"
        );
        // Python is unaffected by the Node.js version; 22 and newer are accepted.
        h.vhosts
            .configure(app_req("example.net", "alice", AppRuntime::Python))
            .await?;
        for ok in ["v22.0.0", "v24.1.0"] {
            h.sys.set_node_version(ok);
            h.vhosts
                .configure(app_req("example.com", "alice", AppRuntime::Node))
                .await?;
        }
        Ok(())
    }

    fn systemctl_and_nginx(h: &Harness) -> Vec<Vec<String>> {
        h.sys
            .calls()
            .iter()
            .filter(|c| c.program == bin::SYSTEMCTL || c.program == bin::NGINX)
            .map(|c| {
                let mut v = vec![c.program.to_owned()];
                v.extend(args(c));
                v
            })
            .collect()
    }

    #[tokio::test]
    async fn php_settings_get_their_own_pool_and_nginx_follows() -> Result<()> {
        use crate::php_settings::RawSettings;
        let h = harness(false).await;
        for d in ["shop.example.com", "blog.example.com"] {
            h.vhosts
                .configure(VHostRequest {
                    php: true,
                    ..req(d, "alice")
                })
                .await?;
        }
        let conf = h.config.php_conf_dir.join("alice.conf");
        let site = h.config.nginx_conf_dir.join("shop.example.com.conf");
        let blog = h.config.nginx_conf_dir.join("blog.example.com.conf");
        let read = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
        let (pool_before, site_before, blog_before) = (read(&conf), read(&site), read(&blog));
        h.sys.clear_calls();
        let (rec, changed) = h
            .vhosts
            .set_php_settings(
                "shop.example.com",
                &RawSettings {
                    memory_limit_mb: 256,
                    upload_max_filesize_mb: 64,
                    max_execution_time_secs: 120,
                    ..RawSettings::default()
                },
            )
            .await?;
        assert!(changed);
        assert_eq!(rec.php_settings.memory_limit_mb, Some(256));
        // The instance restarts with the new pool; Nginx is validated, then reloaded.
        assert_eq!(
            systemctl_and_nginx(&h),
            vec![
                vec![
                    "/usr/bin/systemctl",
                    "enable",
                    "--",
                    "oxpanel-php-alice.service"
                ],
                vec![
                    "/usr/bin/systemctl",
                    "restart",
                    "--",
                    "oxpanel-php-alice.service"
                ],
                vec!["/usr/sbin/nginx", "-t", "-q"],
                vec!["/usr/bin/systemctl", "reload-or-restart", "nginx.service"],
            ]
        );
        let pool = read(&conf);
        assert!(
            pool.starts_with(&pool_before),
            "the default pool is unchanged"
        );
        assert!(pool.contains(
            "\n[shop.example.com]\nlisten = /run/oxpanel-php/alice/shop.example.com.sock\n"
        ));
        assert!(pool.ends_with(
            "php_value[memory_limit] = 256M\nphp_value[upload_max_filesize] = 64M\nphp_value[post_max_size] = 65M\nphp_value[max_execution_time] = 120\n"
        ));
        let block = read(&site);
        assert!(block.contains("fastcgi_pass unix:/run/oxpanel-php/alice/shop.example.com.sock;"));
        assert!(block.contains("    client_max_body_size 65m;\n"));
        assert!(block.contains("        fastcgi_read_timeout 150s;\n"));
        assert_ne!(block, site_before);
        assert_eq!(read(&blog), blog_before, "the other site is untouched");
        // Repeating it changes nothing.
        h.sys.clear_calls();
        let (_, changed) = h
            .vhosts
            .set_php_settings(
                "shop.example.com",
                &RawSettings {
                    memory_limit_mb: 256,
                    upload_max_filesize_mb: 64,
                    max_execution_time_secs: 120,
                    ..RawSettings::default()
                },
            )
            .await?;
        assert!(!changed);
        Ok(())
    }

    #[tokio::test]
    async fn php_settings_survive_reconfiguration_and_follow_the_plan() -> Result<()> {
        use crate::php_settings::{PhpLimits, RawSettings};
        let h = harness(false).await;
        h.vhosts
            .configure(VHostRequest {
                php: true,
                ..req("shop.example.com", "alice")
            })
            .await?;
        let conf = h.config.php_conf_dir.join("alice.conf");
        let site = h.config.nginx_conf_dir.join("shop.example.com.conf");
        let read = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
        let (pool_before, site_before) = (read(&conf), read(&site));
        h.vhosts
            .set_php_settings(
                "shop.example.com",
                &RawSettings {
                    memory_limit_mb: 256,
                    ..RawSettings::default()
                },
            )
            .await?;
        // ConfigureVirtualHost keeps the settings.
        let (rec, _) = h
            .vhosts
            .configure(VHostRequest {
                php: true,
                ..req("shop.example.com", "alice")
            })
            .await?;
        assert_eq!(rec.php_settings.memory_limit_mb, Some(256));
        // A plan's cap clamps what is rendered at once; the request stays.
        let (t, changed) = h
            .vhosts
            .set_tenant_php_limits(
                "alice",
                &PhpLimits {
                    memory_limit_mb: 128,
                    ..PhpLimits::default()
                },
            )
            .await?;
        assert!(changed && t.php_limits.memory_limit_mb == 128);
        assert!(read(&conf).contains("php_value[memory_limit] = 128M\n"));
        assert!(h
            .vhosts
            .set_php_settings(
                "shop.example.com",
                &RawSettings {
                    memory_limit_mb: 256,
                    ..RawSettings::default()
                },
            )
            .await
            .is_err());
        // Clearing them restores exactly the configuration of before.
        h.vhosts
            .set_php_settings("shop.example.com", &RawSettings::default())
            .await?;
        assert_eq!(read(&conf), pool_before);
        assert_eq!(read(&site), site_before);
        Ok(())
    }

    #[tokio::test]
    async fn php_settings_are_refused_before_anything_changes() -> Result<()> {
        use crate::php_settings::RawSettings;
        let h = harness(false).await;
        h.vhosts
            .configure(req("static.example.com", "alice"))
            .await?;
        h.sys.clear_calls();
        let some = RawSettings {
            memory_limit_mb: 64,
            ..RawSettings::default()
        };
        assert!(matches!(
            h.vhosts.set_php_settings("static.example.com", &some).await,
            Err(Error::PhpNotEnabled(_))
        ));
        assert!(matches!(
            h.vhosts.set_php_settings("nope.example.com", &some).await,
            Err(Error::VHostNotFound(_))
        ));
        h.vhosts
            .configure(VHostRequest {
                php: true,
                ..req("static.example.com", "alice")
            })
            .await?;
        h.sys.clear_calls();
        for bad in [
            RawSettings {
                memory_limit_mb: 1_000_000,
                ..RawSettings::default()
            },
            RawSettings {
                date_timezone: "Europe/Berlin\nphp_admin_value[open_basedir]=/".into(),
                ..RawSettings::default()
            },
        ] {
            assert!(matches!(
                h.vhosts.set_php_settings("static.example.com", &bad).await,
                Err(Error::InvalidInput { .. })
            ));
        }
        assert!(h.sys.calls().is_empty(), "nothing was run");
        // Switching PHP off drops the site's pool; removing the site too.
        h.vhosts
            .set_php_settings("static.example.com", &some)
            .await?;
        h.vhosts
            .configure(VHostRequest {
                php: true,
                ..req("other.example.com", "alice")
            })
            .await?;
        let conf = h.config.php_conf_dir.join("alice.conf");
        assert!(std::fs::read_to_string(&conf)
            .unwrap_or_default()
            .contains("[static.example.com]"));
        h.vhosts
            .configure(req("static.example.com", "alice"))
            .await?;
        assert!(!std::fs::read_to_string(&conf)
            .unwrap_or_default()
            .contains("[static.example.com]"));
        h.vhosts
            .configure(VHostRequest {
                php: true,
                ..req("static.example.com", "alice")
            })
            .await?;
        assert!(std::fs::read_to_string(&conf)
            .unwrap_or_default()
            .contains("[static.example.com]"));
        h.vhosts.remove("static.example.com").await?;
        assert!(!std::fs::read_to_string(&conf)
            .unwrap_or_default()
            .contains("[static.example.com]"));
        Ok(())
    }
}
