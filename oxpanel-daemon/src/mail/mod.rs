//! Email: mailboxes, forwarders and autoresponders of the accounts' domains,
//! on this host's own mail servers.
//!
//! - **The servers** are Postfix (SMTP), Dovecot (IMAPS, POP3S, LMTP
//!   delivery, Sieve autoresponders, logins for Postfix) and Rspamd (spam
//!   filter and DKIM signer), from the distribution and Rspamd's own
//!   repository, plus OxPanel's mail policy service ([`policy`]) and, if
//!   installed, Roundcube ([`webmail`]). OxPanel renders their configuration
//!   entirely from records ([`render`]) and owns it while email is on.
//! - **A mail domain** belongs to one account and must be a name that
//!   account already holds here: one of its sites' names, or a name inside
//!   one of its DNS zones (and no other account's site or mail domain). Its
//!   mode is `local` (mail is here), `external` (another provider; only MX
//!   records) or `off`.
//! - **Mail is the account's**: stored in `~/mail/<domain>/<local>/`, owned
//!   by the account's uid (Dovecot accepts no other uid for a mailbox), so
//!   it counts against the account's disk quota, and each mailbox has its
//!   own size limit inside that (Dovecot's quota). Nothing touches a
//!   mailbox's files with another identity: delivery, Sieve, IMAP and POP3
//!   run as the account; the engine creates and removes the directories as
//!   the account.
//! - **Sending**: a mailbox may send only as its own address (envelope:
//!   Postfix; From: header: the filter); sites send through OxPanel's
//!   sendmail ([`sendmail`]) as an address at one of the account's domains;
//!   both count against per-hour limits of the account and the mailbox.
//!   Port 25 accepts mail for this host's domains only (never a relay).
//! - **Passwords** are stored as bcrypt hashes only ([`password`]).
//! - **Suspension**: the account's mailboxes cannot log in or send, and
//!   mail for its domains is deferred (450), not bounced.
//! - **DNS**: MX, SPF, DKIM, DMARC, autoconfiguration and webmail records
//!   ([`records`]) are engine-kept records of the domain's zone when this
//!   host serves it, otherwise returned as records to create.

pub mod certs;
pub mod config;
pub mod hostcheck;
pub mod limits;
pub mod ops;
pub mod password;
pub mod policy;
pub mod queue;
pub mod records;
pub mod render;
pub mod sendmail;
pub mod store;
pub mod webmail;

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests;

pub use config::MailConfig;

use tracing::{info, warn};

use crate::ctx::Ctx;
use crate::error::{Error, MailCode, Result};
use crate::records::{now_unix, TenantRecord, TenantState};
use crate::system::bin;
use crate::validate::{Domain, MailLocalPart, Username};
use records::MailRecord;
use store::{ForwarderRecord, MailDomainRecord, MailMode, MailStore, MailboxRecord, RecordState};

pub use queue::QueueEntry;

/// Smallest mailbox size limit (when there is one).
pub const MIN_QUOTA_BYTES: u64 = 1024 * 1024;
/// Most external MX hosts of a domain.
pub const MAX_EXTERNAL_MX: usize = 10;

/// Obtain the mail certificates that are missing or due (logged, never fatal).
pub async fn certificates_sweep(ctx: &Ctx, force: bool) {
    match certs::sweep(ctx, force).await {
        Ok(0) => {}
        Ok(n) => info!(certificates = n, "mail certificates installed"),
        Err(e) => warn!(error = %e, "mail certificates could not be checked"),
    }
}

/// Look for a certificate soon (after a mail domain was set up).
fn certificates_soon(ctx: &Ctx) {
    if !ctx.config.auto_https.is_on() || ctx.config.dry_run {
        return;
    }
    let ctx = ctx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(crate::auto_https::AFTER_CHANGE_DELAY).await;
        certificates_sweep(&ctx, true).await;
    });
}

/// Effective email limits of an account (0 = unlimited).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Limits {
    pub max_mailboxes: u32,
    pub max_mailbox_bytes: u64,
    pub rate_account: u32,
    pub rate_mailbox: u32,
}

/// Why email cannot be used now; `None` when it can.
pub async fn unavailable_reason(ctx: &Ctx) -> Option<String> {
    let cfg = &ctx.config.mail;
    if !cfg.enabled {
        return Some("email is off on this host (install the mail component with install.sh --mail, which sets OXPANEL_MAIL=true and OXPANEL_MAIL_HOSTNAME)".to_owned());
    }
    for (program, package) in [
        (bin::POSTFIX, "postfix"),
        (bin::DOVECOT, "dovecot"),
        (bin::RSPAMD, "rspamd"),
    ] {
        if !ctx.sys.is_installed(program).await {
            return Some(format!(
                "email is on but {package} is not installed (run install.sh --mail)"
            ));
        }
    }
    None
}

async fn require_available(ctx: &Ctx) -> Result<Domain> {
    if let Some(why) = unavailable_reason(ctx).await {
        return Err(Error::mail(MailCode::Unavailable, why));
    }
    ctx.config
        .mail
        .hostname
        .clone()
        .ok_or_else(|| Error::mail(MailCode::Unavailable, "no mail host name is set"))
}

// ---- Views -----------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Published {
    Unknown,
    Yes,
    No,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimView {
    pub selector: String,
    pub record: String,
    pub published: Published,
    /// A new key waiting to be seen in public DNS before it signs.
    pub pending: Option<PendingDkimView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDkimView {
    pub selector: String,
    pub record: String,
    /// `Unknown` unless this answer looked (a rotation's second step).
    pub published: Published,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainView {
    pub domain: String,
    pub tenant: String,
    pub mode: MailMode,
    pub external_mx: Vec<String>,
    pub catch_all: String,
    pub dkim: Option<DkimView>,
    pub dns_hosted: bool,
    pub required_records: Vec<MailRecord>,
    pub mailbox_count: u32,
    pub forwarder_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxView {
    pub address: String,
    pub local_part: String,
    pub domain: String,
    pub quota_bytes: u64,
    pub used_bytes: u64,
    pub messages: u64,
    pub enabled: bool,
    /// Last IMAP/POP3 (or webmail) login; `None`: never, or not recorded.
    pub last_login_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwarderView {
    pub address: String,
    pub local_part: String,
    pub domain: String,
    pub destinations: Vec<String>,
    pub keep_copy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AutoreplyView {
    pub address: String,
    pub enabled: bool,
    pub subject: String,
    pub body: String,
    pub starts_at_unix: Option<u64>,
    pub ends_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningKind {
    ReverseDns,
    Port25,
    NoCertificate,
    ServiceDown,
    /// The filter's own resolver is configured but not running.
    FilterResolverDown,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct Components {
    pub postfix: bool,
    pub dovecot: bool,
    pub filter: bool,
    pub antivirus: bool,
    pub webmail: bool,
    pub filter_resolver: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostView {
    pub enabled: bool,
    pub host_name: String,
    pub components: Components,
    pub warnings: Vec<(WarningKind, String)>,
    pub webmail_url_pattern: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    pub mailboxes: u32,
    pub bytes_used: u64,
    pub sent_this_hour: u32,
}

// ---- Ownership of names -------------------------------------------------------------

fn within(name: &str, zone: &str) -> bool {
    name == zone || name.ends_with(&format!(".{zone}"))
}

/// The DNS zone of this host that holds `domain` for `tenant`, if any.
pub fn hosted_zone(ctx: &Ctx, tenant: &str, domain: &str) -> Result<Option<Domain>> {
    if !ctx.config.dns.enabled {
        return Ok(None);
    }
    for z in crate::dns::store::ZoneStore::new(&ctx.config).list()? {
        if z.tenant == tenant
            && z.state != crate::dns::store::ZoneState::Deleting
            && within(domain, &z.zone)
        {
            return Ok(Some(z.domain()?));
        }
    }
    Ok(None)
}

/// Whether `tenant` holds `domain` here: a name of one of its sites, or a
/// name inside one of its DNS zones that no other account's site uses.
fn check_owned(ctx: &Ctx, tenant: &str, domain: &Domain) -> Result<()> {
    let d = domain.as_str();
    let not_owned = |why: String| Err(Error::mail(MailCode::DomainNotOwned, why));
    if ctx.config.mail.hostname.as_ref() == Some(domain) {
        return not_owned(format!("{d} is this host's mail host name"));
    }
    if let Some(other) = MailStore::new(&ctx.config)
        .load(domain)?
        .filter(|r| r.tenant != tenant)
    {
        let _ = other;
        return not_owned(format!("{d} is another account's mail domain"));
    }
    let vhosts = ctx.store.list_vhosts()?;
    if vhosts
        .iter()
        .any(|v| v.tenant != tenant && v.all_names().any(|n| n == d))
    {
        return not_owned(format!("{d} is another account's site"));
    }
    let own_site = vhosts
        .iter()
        .any(|v| v.tenant == tenant && v.all_names().any(|n| n == d));
    let own_zone = crate::dns::store::ZoneStore::new(&ctx.config)
        .list()?
        .iter()
        .any(|z| {
            z.tenant == tenant
                && z.state != crate::dns::store::ZoneState::Deleting
                && within(d, &z.zone)
        });
    if own_site || own_zone {
        Ok(())
    } else {
        not_owned(format!(
            "{d} is not a name of this account: add it as a site (or an alias of one), or create a DNS zone for it, first"
        ))
    }
}

/// Whether a site of `tenant` may be called `name`: never the mail host
/// name, and not `webmail.`/`autoconfig.`/`autodiscover.` of another
/// account's local mail domain (those names are served for that account).
pub fn check_site_name(ctx: &Ctx, name: &str, tenant: &str) -> Result<()> {
    let cfg = &ctx.config.mail;
    if !cfg.enabled {
        return Ok(());
    }
    if cfg.hostname.as_ref().is_some_and(|h| h.as_str() == name) {
        return Err(Error::invalid(
            "domain",
            format!("'{name}' is this host's mail host name"),
        ));
    }
    for prefix in ["webmail.", "autoconfig.", "autodiscover."] {
        let Some(base) = name.strip_prefix(prefix) else {
            continue;
        };
        let Ok(base) = Domain::parse(base) else {
            continue;
        };
        if let Some(rec) = MailStore::new(&ctx.config).load(&base)? {
            if rec.tenant != tenant && rec.mode == MailMode::Local && render::live(&rec) {
                return Err(Error::VHostOwnedByOther {
                    domain: name.to_owned(),
                    owner: rec.tenant,
                });
            }
        }
    }
    Ok(())
}

// ---- The service ------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MailService {
    ctx: Ctx,
}

/// A local part or an address of `domain` (for catch-alls).
fn local_of(raw: &str, domain: &Domain, field: &'static str) -> Result<MailLocalPart> {
    match raw.split_once('@') {
        Some((l, d)) if d == domain.as_str() => MailLocalPart::parse_field(l, field),
        Some(_) => Err(Error::invalid(
            field,
            format!("must be an address of {domain}"),
        )),
        None => MailLocalPart::parse_field(raw, field),
    }
}

impl MailService {
    pub fn new(ctx: Ctx) -> Self {
        Self { ctx }
    }

    fn store(&self) -> MailStore {
        MailStore::new(&self.ctx.config)
    }

    /// The account, which must be ready; for a change it must also not be
    /// suspended.
    fn tenant(&self, tenant: &Username, change: bool) -> Result<TenantRecord> {
        let t = self
            .ctx
            .store
            .load_tenant(tenant)?
            .ok_or_else(|| Error::TenantNotFound(tenant.to_string()))?;
        if t.state != TenantState::Ready {
            return Err(Error::TenantNotReady(tenant.to_string()));
        }
        if change && t.suspended {
            return Err(Error::mail(
                MailCode::AccountSuspended,
                format!("account '{tenant}' is suspended: its email can be read but not changed"),
            ));
        }
        Ok(t)
    }

    /// The account's mail domain.
    fn domain(&self, tenant: &Username, domain: &Domain) -> Result<MailDomainRecord> {
        match self.store().load(domain)? {
            Some(r) if r.tenant == tenant.as_str() && r.state != RecordState::Deleting => Ok(r),
            _ => Err(Error::mail(
                MailCode::DomainNotFound,
                format!("{domain} is not a mail domain of '{tenant}'"),
            )),
        }
    }

    /// The account's mail domain, which must be local, for a change.
    fn local_domain(&self, tenant: &Username, domain: &Domain) -> Result<MailDomainRecord> {
        let r = self.domain(tenant, domain)?;
        if r.mode != MailMode::Local {
            return Err(Error::mail(
                MailCode::DomainNotLocal,
                format!(
                    "the mail of {domain} is not handled here (mode {})",
                    r.mode.as_str()
                ),
            ));
        }
        if r.state != RecordState::Ready {
            return Err(Error::mail(
                MailCode::DomainNotLocal,
                format!("{domain} is still being set up; repeat SetMailDomain"),
            ));
        }
        Ok(r)
    }

    pub fn limits(&self, tenant: &Username) -> Result<Limits> {
        Ok(self.resolved_limits(tenant)?.flat())
    }

    /// The account's limits with their layers and sources.
    pub fn resolved_limits(&self, tenant: &Username) -> Result<limits::Resolved> {
        let store = self.store();
        let defaults = ops::host_defaults(&self.ctx.config.mail, &store)?;
        Ok(ops::limits_of(&defaults, &store.load_limits(tenant)?))
    }

    fn domain_view(&self, r: &MailDomainRecord, host: &Domain) -> Result<DomainView> {
        let zone = hosted_zone(&self.ctx, &r.tenant, &r.domain)?;
        let dkim = (r.mode == MailMode::Local)
            .then_some(r.dkim.as_ref())
            .flatten()
            .map(|k| DkimView {
                selector: k.selector.clone(),
                record: records::dkim_txt(&k.public_key),
                published: if zone.is_some() {
                    Published::Yes
                } else {
                    Published::Unknown
                },
                pending: r.dkim_pending.as_ref().map(|p| PendingDkimView {
                    selector: p.selector.clone(),
                    record: records::dkim_txt(&p.public_key),
                    published: if zone.is_some() {
                        Published::Yes
                    } else {
                        Published::Unknown
                    },
                }),
            });
        let required_records = if zone.is_some() {
            Vec::new()
        } else {
            records::required(r, host, now_unix())
        };
        Ok(DomainView {
            domain: r.domain.clone(),
            tenant: r.tenant.clone(),
            mode: r.mode,
            external_mx: r.external_mx.clone(),
            catch_all: r
                .catch_all
                .as_ref()
                .map(|c| format!("{c}@{}", r.domain))
                .unwrap_or_default(),
            dkim,
            dns_hosted: zone.is_some(),
            required_records,
            mailbox_count: u32::try_from(r.live_mailboxes().count()).unwrap_or(u32::MAX),
            forwarder_count: u32::try_from(r.forwarders.len()).unwrap_or(u32::MAX),
        })
    }

    /// Apply the records to the servers and the domain's zone.
    async fn apply(&self, domain: Option<&Domain>) -> Result<()> {
        ops::apply(&self.ctx).await?;
        if let Some(d) = domain {
            if let Err(e) = crate::dns::mail_changed(&self.ctx, d).await {
                // The mail works whatever DNS does; Reconcile shows the zone.
                warn!(domain = %d, error = %e, "the zone could not be updated with the mail records");
            }
        }
        Ok(())
    }

    // -- host --

    pub async fn host(&self) -> Result<HostView> {
        let ctx = &self.ctx;
        let cfg = &ctx.config.mail;
        let mut v = HostView {
            enabled: cfg.enabled,
            host_name: cfg
                .hostname
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            components: Components {
                postfix: ctx.sys.is_installed(bin::POSTFIX).await,
                dovecot: ctx.sys.is_installed(bin::DOVECOT).await,
                filter: ctx.sys.is_installed(bin::RSPAMD).await,
                antivirus: cfg.antivirus,
                webmail: ops::webmail_offered(ctx),
                filter_resolver: cfg.resolver_offered(),
            },
            ..HostView::default()
        };
        if v.components.webmail && cfg.enabled {
            "https://webmail.{domain}/".clone_into(&mut v.webmail_url_pattern);
        }
        let Some(host) = cfg.hostname.clone().filter(|_| cfg.enabled) else {
            return Ok(v);
        };
        if !ops::certificate(ctx, &host).2 {
            v.warnings.push((
                WarningKind::NoCertificate,
                format!("{host} has no certificate yet: mail clients are shown a self-signed one (it is requested through Automatic HTTPS once the name resolves to this host)"),
            ));
        }
        for unit in ops::services(ctx) {
            if !ops::unit_active(ctx, unit).await? {
                v.warnings.push(if unit == ops::RESOLVER_SERVICE {
                    (
                        WarningKind::FilterResolverDown,
                        format!("{unit} (the mail filter's DNS resolver) is not running: the filter's DNS lookups fail, so blocklist checks are skipped and mail is filtered less well; see journalctl -u {unit}"),
                    )
                } else {
                    (WarningKind::ServiceDown, format!("{unit} is not running"))
                });
            }
        }
        // The network checks come from the last background run (a few
        // seconds after the first call, then every few hours).
        if let Some(c) = hostcheck::cached(ctx, &host) {
            if let Some(w) = c.reverse_dns {
                v.warnings.push((WarningKind::ReverseDns, w));
            }
            if let Some(w) = c.port25 {
                v.warnings.push((WarningKind::Port25, w));
            }
        }
        hostcheck::refresh_if_stale(ctx, &host);
        Ok(v)
    }

    pub async fn queue(&self, page: u32, size: u32) -> Result<(Vec<QueueEntry>, u32)> {
        require_available(&self.ctx).await?;
        queue::list(&self.ctx, page, size).await
    }

    pub async fn delete_queued(&self, id: &str) -> Result<bool> {
        let id = crate::validate::QueueId::parse(id)?;
        require_available(&self.ctx).await?;
        let _guard = self.ctx.lock.lock().await;
        queue::delete(&self.ctx, &id).await
    }

    pub async fn flush_queue(&self) -> Result<u32> {
        require_available(&self.ctx).await?;
        queue::flush(&self.ctx).await
    }

    pub async fn check(&self, domain: &str) -> Result<Vec<Check>> {
        let domain = Domain::parse(domain)?;
        let host = require_available(&self.ctx).await?;
        let rec = self.store().load(&domain)?.ok_or_else(|| {
            Error::mail(
                MailCode::DomainNotFound,
                format!("{domain} is not a mail domain"),
            )
        })?;
        certs::deliverability(&self.ctx, &rec, &host).await
    }

    // -- domains --

    /// Create a mail domain or change its mode, MX hosts and catch-all.
    pub async fn set_domain(
        &self,
        tenant: &str,
        domain: &str,
        mode: MailMode,
        external_mx: &[String],
        catch_all: &str,
    ) -> Result<(DomainView, bool)> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let domain = Domain::parse_field(domain.trim_end_matches('.'), "domain")?;
        let mx: Vec<String> = external_mx
            .iter()
            .map(|m| {
                Domain::parse_field(m.trim_end_matches('.'), "external_mx").map(|d| d.to_string())
            })
            .collect::<Result<_>>()?;
        match mode {
            MailMode::External if mx.is_empty() || mx.len() > MAX_EXTERNAL_MX => {
                return Err(Error::invalid(
                    "external_mx",
                    format!("an external domain needs 1..={MAX_EXTERNAL_MX} mail servers"),
                ))
            }
            MailMode::Local | MailMode::Off if !mx.is_empty() => {
                return Err(Error::invalid("external_mx", "only for mode EXTERNAL"))
            }
            _ => {}
        }
        let catch = (!catch_all.is_empty())
            .then(|| local_of(catch_all, &domain, "catch_all"))
            .transpose()?;
        if catch.is_some() && mode != MailMode::Local {
            return Err(Error::invalid("catch_all", "only for mode LOCAL"));
        }
        let host = require_available(&self.ctx).await?;
        let _guard = self.ctx.lock.lock().await;
        let t = self.tenant(&tenant, true)?;
        check_owned(&self.ctx, tenant.as_str(), &domain)?;
        let existing = self.store().load(&domain)?;
        let created = existing.is_none();
        let mut rec = existing.unwrap_or_else(|| MailDomainRecord {
            version: 1,
            domain: domain.to_string(),
            tenant: tenant.to_string(),
            created_at_unix: now_unix(),
            state: RecordState::Provisioning,
            mode,
            external_mx: Vec::new(),
            catch_all: None,
            dkim: None,
            dkim_retired: Vec::new(),
            dkim_pending: None,
            mailboxes: std::collections::BTreeMap::default(),
            forwarders: std::collections::BTreeMap::default(),
        });
        if rec.state == RecordState::Deleting {
            return Err(Error::mail(
                MailCode::DomainNotLocal,
                format!("{domain} is being removed"),
            ));
        }
        if let Some(c) = &catch {
            if !rec.live_mailboxes().any(|(l, _)| l == c.as_str()) {
                return Err(Error::invalid(
                    "catch_all",
                    format!("{c}@{domain} is not a mailbox of the domain (a catch-all delivers to a mailbox, never elsewhere)"),
                ));
            }
        }
        rec.mode = mode;
        rec.external_mx = mx;
        rec.catch_all = catch.map(|c| c.to_string());
        // The record first, then what depends on it.
        self.store().save(&rec)?;
        let rec = self.finish_domain(rec, &t).await?;
        self.apply(Some(&domain)).await?;
        info!(tenant = %tenant, %domain, mode = rec.mode.as_str(), created, "mail domain set");
        if rec.mode == MailMode::Local {
            certificates_soon(&self.ctx);
        }
        Ok((self.domain_view(&rec, &host)?, created))
    }

    /// Finish setting a domain up: its DKIM key (local mode) and its
    /// directory under `~/mail`; then it is ready. Idempotent.
    async fn finish_domain(
        &self,
        mut rec: MailDomainRecord,
        t: &TenantRecord,
    ) -> Result<MailDomainRecord> {
        if rec.mode == MailMode::Local && rec.dkim.is_none() {
            let key = ops::new_dkim_key(&self.ctx, &rec.domain, now_unix()).await?;
            rec.dkim = Some(key);
            self.store().save(&rec)?;
        }
        if rec.mode == MailMode::Local {
            for (local, _) in rec.live_mailboxes() {
                ops::ensure_maildir(&self.ctx, t, &rec.domain, local).await?;
            }
        }
        if rec.state == RecordState::Provisioning {
            rec.state = RecordState::Ready;
            self.store().save(&rec)?;
        }
        Ok(rec)
    }

    pub async fn get_domain(&self, tenant: &str, domain: &str) -> Result<DomainView> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let domain = Domain::parse(domain.trim_end_matches('.'))?;
        let host = require_available(&self.ctx).await?;
        let rec = self.domain(&tenant, &domain)?;
        self.domain_view(&rec, &host)
    }

    pub async fn list_domains(&self, tenant: &str) -> Result<Vec<DomainView>> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let host = require_available(&self.ctx).await?;
        self.tenant(&tenant, false)?;
        self.store()
            .list_tenant(tenant.as_str())?
            .iter()
            .filter(|r| r.state != RecordState::Deleting)
            .map(|r| self.domain_view(r, &host))
            .collect()
    }

    /// Rotate the domain's DKIM key in two steps, so that mail is never
    /// signed with a key receivers cannot find yet:
    ///
    /// 1. A new key is made under a new selector and kept *pending*: its
    ///    record is returned (and published, when this host serves the
    ///    zone); the current key keeps signing.
    /// 2. The pending key takes over once its record is seen: at once when
    ///    the zone is hosted here (after the zone was updated), otherwise
    ///    on a later call that finds it in public DNS, or on any call with
    ///    `force`. The old key's record stays published for a week.
    ///
    /// A call while a key is pending never makes another one.
    pub async fn rotate_dkim(&self, tenant: &str, domain: &str, force: bool) -> Result<DomainView> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let domain = Domain::parse(domain.trim_end_matches('.'))?;
        let host = require_available(&self.ctx).await?;
        // Look in public DNS first, without the mutation lock (it can take
        // seconds); the answer only counts for the key it was asked about.
        let seen = {
            let rec = self.local_domain(&tenant, &domain)?;
            match rec.dkim_pending.as_ref() {
                Some(p)
                    if !force && hosted_zone(&self.ctx, &rec.tenant, &rec.domain)?.is_none() =>
                {
                    let s = certs::dkim_published(&self.ctx, &rec.domain, p).await?;
                    Some((p.selector.clone(), s))
                }
                _ => None,
            }
        };
        let _guard = self.ctx.lock.lock().await;
        self.tenant(&tenant, true)?;
        let mut rec = self.local_domain(&tenant, &domain)?;
        let hosted = hosted_zone(&self.ctx, &rec.tenant, &rec.domain)?.is_some();
        if rec.dkim_pending.is_none() {
            let mut now = now_unix();
            if let Some(last) = rec.dkim_keys().map(|k| k.created_at_unix).max() {
                // Two rotations in one second still get two selectors.
                now = now.max(last + 1);
            }
            rec.dkim_pending = Some(ops::new_dkim_key(&self.ctx, &rec.domain, now).await?);
            // The record first: an interrupted rotation goes on from here.
            self.store().save(&rec)?;
        }
        if hosted && !force {
            // Publish the new key in the zone before it signs anything.
            if let Err(e) = crate::dns::mail_changed(&self.ctx, &domain).await {
                warn!(%domain, error = %e, "the zone could not be updated with the new DKIM key; it does not sign yet");
                return self.domain_view(&rec, &host);
            }
        }
        let pending_selector = rec.dkim_pending.as_ref().map(|p| p.selector.clone());
        let seen_now = seen
            .filter(|(s, _)| Some(s) == pending_selector.as_ref())
            .and_then(|(_, s)| s);
        let switch = force || hosted || seen_now == Some(true);
        if switch {
            if let Some(key) = rec.dkim_pending.take() {
                if let Some(mut old) = rec.dkim.replace(key) {
                    old.retire_at_unix = Some(now_unix() + ops::DKIM_RETIRE_SECS);
                    rec.dkim_retired.push(old);
                }
            }
        }
        rec.dkim_retired
            .retain(|k| k.retire_at_unix.is_some_and(|t| t > now_unix()));
        self.store().save(&rec)?;
        ops::prune_dkim_keys(&self.ctx, Some(&rec), &rec.domain)?;
        self.apply(Some(&domain)).await?;
        if switch {
            info!(tenant = %tenant, %domain, forced = force, "DKIM key rotated: the new key signs");
        } else {
            info!(tenant = %tenant, %domain, "DKIM key rotation waits for the new record in public DNS");
        }
        let mut v = self.domain_view(&rec, &host)?;
        if let Some(p) = v.dkim.as_mut().and_then(|d| d.pending.as_mut()) {
            p.published = match seen_now {
                Some(true) => Published::Yes,
                Some(false) => Published::No,
                None => p.published,
            };
        }
        Ok(v)
    }
}

mod lifecycle;
mod mailboxes;
pub use lifecycle::{
    accounts_changed, converge, drifts, refuse_tenant_deletion, remove_tenant_mail, tenant_changed,
    zone_records,
};
pub use mailboxes::LimitsChange;

/// Mailboxes, forwarders and autoresponders as they are listed.
pub(crate) fn mailbox_view(rec: &MailDomainRecord, local: &str, m: &MailboxRecord) -> MailboxView {
    MailboxView {
        address: format!("{local}@{}", rec.domain),
        local_part: local.to_owned(),
        domain: rec.domain.clone(),
        quota_bytes: m.quota_bytes,
        used_bytes: 0,
        messages: 0,
        enabled: m.enabled,
        last_login_unix: None,
    }
}

pub(crate) fn forwarder_view(
    rec: &MailDomainRecord,
    local: &str,
    f: &ForwarderRecord,
) -> ForwarderView {
    ForwarderView {
        address: format!("{local}@{}", rec.domain),
        local_part: local.to_owned(),
        domain: rec.domain.clone(),
        destinations: f.destinations.clone(),
        keep_copy: f.keep_copy,
    }
}
