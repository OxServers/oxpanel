//! Mailboxes, forwarders, autoresponders, limits and usage.

use std::collections::{BTreeMap, BTreeSet};

use tracing::{info, warn};

use super::limits::{Layer, Resolved, Setting};
use super::store::{
    AutoreplyRecord, ForwarderRecord, MailDomainRecord, MailMode, MailStore, MailboxRecord,
    RecordState,
};
use super::{
    forwarder_view, mailbox_view, ops, password, require_available, AutoreplyView, ForwarderView,
    Limits, MailService, MailboxView, Usage, MIN_QUOTA_BYTES,
};
use crate::ctx::Ctx;
use crate::error::{Error, MailCode, Result};
use crate::records::{now_unix, TenantRecord};
use crate::system::{bin, CommandSpec};
use crate::validate::{
    AutoreplyBody, AutoreplySubject, Domain, MailAddress, MailDestination, MailLocalPart,
    MailPassword, Username, MAX_FORWARD_DESTINATIONS,
};

/// Autoresponder dates end with the year 9999: the script compares ISO 8601
/// text, which only orders correctly with four-digit years.
/// A change of an account's email limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitsChange {
    /// Replace the plan layer.
    Plan(Layer),
    /// Replace the account layer.
    Account(Layer),
    /// A client older than engine 0.3.1: flat values (0 = inherit) for the
    /// account layer; the plan layer is cleared.
    Legacy(Limits),
}

const LAST_AUTOREPLY_TIME: u64 = 253_402_300_799;

/// Space used and messages of a mailbox, from Dovecot's quota (`doveadm -f
/// tab quota get`; STORAGE is in KiB). Zero when Dovecot cannot tell.
pub(super) async fn quota_usage(ctx: &Ctx, address: &str) -> (u64, u64) {
    let out = ctx
        .sys
        .run(
            CommandSpec::new(bin::DOVEADM, ctx.config.command_timeout)
                .args(["-f", "tab", "quota", "get", "-u"])
                .arg(address),
        )
        .await;
    let Ok(out) = out.map(|o| o.stdout_lossy()) else {
        return (0, 0);
    };
    parse_quota(&out)
}

pub(super) fn parse_quota(text: &str) -> (u64, u64) {
    let (mut bytes, mut messages) = (0, 0);
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let value = f
            .get(2)
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);
        match f.get(1).map(|t| t.trim()) {
            Some("STORAGE") => bytes = value.saturating_mul(1024),
            Some("MESSAGE") => messages = value,
            _ => {}
        }
    }
    (bytes, messages)
}

/// Last logins by address, from Dovecot's dict file (`key` and `value`
/// lines; keys `shared/last-login/<address>`). Empty when there is none.
pub(super) fn last_logins(ctx: &Ctx) -> BTreeMap<String, u64> {
    let path = super::render::last_login_file(&ctx.config.mail);
    match crate::fsutil::read_untrusted(&path, 32 * 1024 * 1024) {
        Ok(Some(bytes)) => parse_last_logins(&String::from_utf8_lossy(&bytes)),
        Ok(None) => BTreeMap::new(),
        Err(e) => {
            warn!(error = %e, "last logins could not be read");
            BTreeMap::new()
        }
    }
}

pub(super) fn parse_last_logins(text: &str) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    let mut lines = text.lines();
    while let (Some(k), Some(v)) = (lines.next(), lines.next()) {
        let k = k
            .strip_prefix("shared/")
            .or_else(|| k.strip_prefix("priv/"))
            .unwrap_or(k);
        if let (Some(addr), Ok(t)) = (k.strip_prefix("last-login/"), v.trim().parse::<u64>()) {
            out.insert(addr.to_ascii_lowercase(), t);
        }
    }
    out
}

/// End a mailbox's IMAP/POP3 sessions (disabled, password changed,
/// removed, suspended). Best effort: Dovecot may not be running.
pub(super) async fn kick(ctx: &Ctx, user_mask: &str) {
    let out = ctx
        .sys
        .run(CommandSpec::new(bin::DOVEADM, ctx.config.command_timeout).args(["kick", user_mask]))
        .await;
    if let Ok(o) = out {
        // doveadm kick exits 68 when nobody was logged in.
        if !o.success() && o.code != Some(68) {
            warn!(user = user_mask, output = %o.combined_lossy(), "sessions could not be ended");
        }
    }
}

/// Every forwarder of local domains: address -> destinations.
fn forward_graph(store: &MailStore) -> Result<BTreeMap<String, Vec<String>>> {
    let mut g = BTreeMap::new();
    for d in store.list()? {
        if d.mode != MailMode::Local || d.state == RecordState::Deleting {
            continue;
        }
        for (local, f) in &d.forwarders {
            g.insert(format!("{local}@{}", d.domain), f.destinations.clone());
        }
    }
    Ok(g)
}

/// Whether forwarding `from` to `dests` would bring mail back to `from`
/// through this host's forwarders.
pub(super) fn makes_loop(g: &BTreeMap<String, Vec<String>>, from: &str, dests: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    let mut todo: Vec<String> = dests.to_vec();
    while let Some(a) = todo.pop() {
        if a == from {
            return true;
        }
        if seen.insert(a.clone()) {
            if let Some(next) = g.get(&a) {
                todo.extend(next.iter().cloned());
            }
        }
    }
    false
}

impl MailService {
    /// Mailboxes of the account across its domains.
    fn mailbox_count(&self, tenant: &Username) -> Result<usize> {
        Ok(self
            .store()
            .list_tenant(tenant.as_str())?
            .iter()
            .map(|d| d.live_mailboxes().count())
            .sum())
    }

    /// The size limit a mailbox gets for `quota`: 0 means "none of its
    /// own", which under an account maximum is that maximum.
    fn check_quota(limits: &Limits, quota: u64) -> Result<u64> {
        if quota > 0 && quota < MIN_QUOTA_BYTES {
            return Err(Error::invalid(
                "quota_bytes",
                format!("must be 0 (no limit of its own) or at least {MIN_QUOTA_BYTES}"),
            ));
        }
        let max = limits.max_mailbox_bytes;
        if max > 0 && quota > max {
            return Err(Error::mail(
                MailCode::MailboxQuotaAboveLimit,
                format!("a mailbox of this account may hold at most {max} bytes"),
            ));
        }
        Ok(if quota == 0 { max } else { quota })
    }

    /// Create or update a mailbox.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_mailbox(
        &self,
        tenant: &str,
        domain: &str,
        local: &str,
        quota_bytes: u64,
        password: &str,
        enabled: bool,
    ) -> Result<(MailboxView, bool)> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let domain = Domain::parse(domain.trim_end_matches('.'))?;
        let local = MailLocalPart::parse(local)?;
        let hash = if password.is_empty() {
            None
        } else {
            // Hashing is slow on purpose: done before the lock is taken.
            Some(password::hash_with_cost(
                &MailPassword::parse(password, &local, &domain)?,
                self.ctx.config.mail.password_cost,
            )?)
        };
        require_available(&self.ctx).await?;
        let _guard = self.ctx.lock.lock().await;
        let t = self.tenant(&tenant, true)?;
        let mut rec = self.local_domain(&tenant, &domain)?;
        let limits = self.limits(&tenant)?;
        let quota_bytes = Self::check_quota(&limits, quota_bytes)?;
        let created = match rec.mailboxes.get_mut(local.as_str()) {
            Some(m) if m.state == RecordState::Deleting => {
                return Err(Error::mail(
                    MailCode::MailboxExists,
                    format!("{local}@{domain} is still being removed; try again in a moment"),
                ))
            }
            Some(m) => {
                m.quota_bytes = quota_bytes;
                m.enabled = enabled;
                if let Some(h) = hash {
                    m.password_hash = h;
                }
                false
            }
            None => {
                if rec
                    .forwarders
                    .get(local.as_str())
                    .is_some_and(|f| !f.keep_copy)
                {
                    return Err(Error::mail(
                        MailCode::AddressInUse,
                        format!("{local}@{domain} is a forwarder"),
                    ));
                }
                let max = limits.max_mailboxes;
                if max > 0 && self.mailbox_count(&tenant)? >= max as usize {
                    return Err(Error::mail(
                        MailCode::MailboxLimitReached,
                        format!("account '{tenant}' has {max} of {max} mailboxes"),
                    ));
                }
                let Some(h) = hash else {
                    return Err(Error::invalid("password", "a new mailbox needs a password"));
                };
                rec.mailboxes.insert(
                    local.to_string(),
                    MailboxRecord {
                        state: RecordState::Ready,
                        quota_bytes,
                        password_hash: h,
                        enabled,
                        created_at_unix: now_unix(),
                        autoreply: None,
                    },
                );
                true
            }
        };
        self.store().save(&rec)?;
        ops::ensure_maildir(&self.ctx, &t, &rec.domain, local.as_str()).await?;
        self.apply(None).await?;
        let addr = format!("{local}@{domain}");
        if !enabled || (!created && !password.is_empty()) {
            kick(&self.ctx, &addr).await;
        }
        info!(tenant = %tenant, mailbox = %addr, created, enabled, quota_bytes, "mailbox set");
        let m = rec
            .mailboxes
            .get(local.as_str())
            .ok_or_else(|| Error::Internal("mailbox vanished".into()))?;
        let mut v = mailbox_view(&rec, local.as_str(), m);
        (v.used_bytes, v.messages) = quota_usage(&self.ctx, &addr).await;
        Ok((v, created))
    }

    pub async fn list_mailboxes(&self, tenant: &str, domain: &str) -> Result<Vec<MailboxView>> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let domain = Domain::parse(domain.trim_end_matches('.'))?;
        require_available(&self.ctx).await?;
        let rec = self.domain(&tenant, &domain)?;
        let logins = last_logins(&self.ctx);
        let mut out = Vec::new();
        for (local, m) in rec.live_mailboxes() {
            let mut v = mailbox_view(&rec, local, m);
            (v.used_bytes, v.messages) = quota_usage(&self.ctx, &v.address).await;
            v.last_login_unix = logins.get(&v.address).copied();
            out.push(v);
        }
        Ok(out)
    }

    pub async fn set_mailbox_password(
        &self,
        tenant: &str,
        domain: &str,
        local: &str,
        password: &str,
    ) -> Result<()> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let domain = Domain::parse(domain.trim_end_matches('.'))?;
        let local = MailLocalPart::parse(local)?;
        let hash = password::hash_with_cost(
            &MailPassword::parse(password, &local, &domain)?,
            self.ctx.config.mail.password_cost,
        )?;
        require_available(&self.ctx).await?;
        let _guard = self.ctx.lock.lock().await;
        self.tenant(&tenant, true)?;
        let mut rec = self.local_domain(&tenant, &domain)?;
        let m = rec
            .mailboxes
            .get_mut(local.as_str())
            .filter(|m| m.state != RecordState::Deleting)
            .ok_or_else(|| Error::mail(MailCode::MailboxNotFound, format!("{local}@{domain}")))?;
        m.password_hash = hash;
        self.store().save(&rec)?;
        self.apply(None).await?;
        kick(&self.ctx, &format!("{local}@{domain}")).await;
        info!(tenant = %tenant, mailbox = %format!("{local}@{domain}"), "mailbox password changed");
        Ok(())
    }

    /// Remove a mailbox: at once from the servers; its mail is removed in
    /// the background, as the account. Returns `false` if there was none.
    pub async fn delete_mailbox(&self, tenant: &str, domain: &str, local: &str) -> Result<bool> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let domain = Domain::parse(domain.trim_end_matches('.'))?;
        let local = MailLocalPart::parse(local)?;
        require_available(&self.ctx).await?;
        let _guard = self.ctx.lock.lock().await;
        let t = self.tenant(&tenant, true)?;
        let mut rec = self.domain(&tenant, &domain)?;
        let Some(m) = rec.mailboxes.get_mut(local.as_str()) else {
            return Ok(false);
        };
        m.state = RecordState::Deleting;
        if rec.catch_all.as_deref() == Some(local.as_str()) {
            rec.catch_all = None;
        }
        self.store().save(&rec)?;
        self.apply(Some(&domain)).await?;
        kick(&self.ctx, &format!("{local}@{domain}")).await;
        info!(tenant = %tenant, mailbox = %format!("{local}@{domain}"), "mailbox removed; its mail is being deleted");
        spawn_removal(self.ctx.clone(), t, domain, local);
        Ok(true)
    }

    // -- forwarders --

    pub async fn put_forwarder(
        &self,
        tenant: &str,
        domain: &str,
        local: &str,
        destinations: &[String],
        keep_copy: bool,
    ) -> Result<(ForwarderView, bool)> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let domain = Domain::parse(domain.trim_end_matches('.'))?;
        let local = MailLocalPart::parse(local)?;
        if destinations.len() > MAX_FORWARD_DESTINATIONS {
            return Err(Error::mail(
                MailCode::TooManyDestinations,
                format!("a forwarder may have at most {MAX_FORWARD_DESTINATIONS} destinations"),
            ));
        }
        let mut dests: Vec<String> = Vec::new();
        for d in destinations {
            let d = MailDestination::parse(d)?.to_string();
            if !dests.contains(&d) {
                dests.push(d);
            }
        }
        if dests.is_empty() {
            return Err(Error::invalid(
                "destinations",
                "at least one destination is needed",
            ));
        }
        require_available(&self.ctx).await?;
        let _guard = self.ctx.lock.lock().await;
        self.tenant(&tenant, true)?;
        let mut rec = self.local_domain(&tenant, &domain)?;
        let addr = format!("{local}@{domain}");
        let has_mailbox = rec.live_mailboxes().any(|(l, _)| l == local.as_str());
        if has_mailbox && !keep_copy {
            return Err(Error::mail(
                MailCode::AddressInUse,
                format!(
                    "{addr} is a mailbox: forward from it with keep_copy, or remove the mailbox"
                ),
            ));
        }
        if keep_copy && !has_mailbox {
            return Err(Error::invalid(
                "keep_copy",
                format!("{addr} has no mailbox to keep a copy in"),
            ));
        }
        if makes_loop(&forward_graph(&self.store())?, &addr, &dests) {
            return Err(Error::mail(
                MailCode::ForwardLoop,
                format!("forwarding {addr} there would bring the mail back to {addr}"),
            ));
        }
        let created = rec
            .forwarders
            .insert(
                local.to_string(),
                ForwarderRecord {
                    destinations: dests,
                    keep_copy,
                },
            )
            .is_none();
        self.store().save(&rec)?;
        self.apply(None).await?;
        info!(tenant = %tenant, forwarder = %addr, created, "forwarder set");
        let f = rec
            .forwarders
            .get(local.as_str())
            .ok_or_else(|| Error::Internal("forwarder vanished".into()))?;
        Ok((forwarder_view(&rec, local.as_str(), f), created))
    }

    pub async fn list_forwarders(&self, tenant: &str, domain: &str) -> Result<Vec<ForwarderView>> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let domain = Domain::parse(domain.trim_end_matches('.'))?;
        require_available(&self.ctx).await?;
        let rec = self.domain(&tenant, &domain)?;
        Ok(rec
            .forwarders
            .iter()
            .map(|(l, f)| forwarder_view(&rec, l, f))
            .collect())
    }

    pub async fn delete_forwarder(&self, tenant: &str, domain: &str, local: &str) -> Result<bool> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let domain = Domain::parse(domain.trim_end_matches('.'))?;
        let local = MailLocalPart::parse(local)?;
        require_available(&self.ctx).await?;
        let _guard = self.ctx.lock.lock().await;
        self.tenant(&tenant, true)?;
        let mut rec = self.domain(&tenant, &domain)?;
        if rec.forwarders.remove(local.as_str()).is_none() {
            return Ok(false);
        }
        self.store().save(&rec)?;
        self.apply(None).await?;
        info!(tenant = %tenant, forwarder = %format!("{local}@{domain}"), "forwarder removed");
        Ok(true)
    }

    // -- autoresponders --

    fn mailbox_of(&self, tenant: &Username, address: &MailAddress) -> Result<MailDomainRecord> {
        let rec = self.local_domain(tenant, &address.domain)?;
        if !rec
            .live_mailboxes()
            .any(|(l, _)| l == address.local.as_str())
        {
            return Err(Error::mail(MailCode::MailboxNotFound, address.to_string()));
        }
        Ok(rec)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn set_autoresponder(
        &self,
        tenant: &str,
        address: &str,
        enabled: bool,
        subject: &str,
        body: &str,
        starts_at_unix: Option<u64>,
        ends_at_unix: Option<u64>,
    ) -> Result<AutoreplyView> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let address = MailAddress::parse(address)?;
        if starts_at_unix.is_some_and(|t| t > LAST_AUTOREPLY_TIME)
            || ends_at_unix.is_some_and(|t| t > LAST_AUTOREPLY_TIME)
        {
            return Err(Error::invalid("starts_at", "must be before the year 10000"));
        }
        if let (Some(s), Some(e)) = (starts_at_unix, ends_at_unix) {
            if e <= s {
                return Err(Error::invalid("ends_at", "must be after starts_at"));
            }
        }
        // Text is checked whenever it is given, and required to switch on.
        let subject = (!subject.is_empty() || enabled)
            .then(|| AutoreplySubject::parse(subject))
            .transpose()?;
        let body = (!body.is_empty() || enabled)
            .then(|| AutoreplyBody::parse(body))
            .transpose()?;
        require_available(&self.ctx).await?;
        let _guard = self.ctx.lock.lock().await;
        self.tenant(&tenant, true)?;
        let mut rec = self.mailbox_of(&tenant, &address)?;
        let m = rec
            .mailboxes
            .get_mut(address.local.as_str())
            .ok_or_else(|| Error::mail(MailCode::MailboxNotFound, address.to_string()))?;
        let previous = m.autoreply.take();
        m.autoreply = Some(AutoreplyRecord {
            enabled,
            subject: subject
                .map(|s| s.as_str().to_owned())
                .or_else(|| previous.as_ref().map(|p| p.subject.clone()))
                .unwrap_or_default(),
            body: body
                .map(|b| b.as_str().to_owned())
                .or_else(|| previous.as_ref().map(|p| p.body.clone()))
                .unwrap_or_default(),
            starts_at_unix,
            ends_at_unix,
        });
        let view = autoreply_view(&address, m.autoreply.as_ref());
        self.store().save(&rec)?;
        self.apply(None).await?;
        info!(tenant = %tenant, mailbox = %address, enabled, "autoresponder set");
        Ok(view)
    }

    pub async fn get_autoresponder(&self, tenant: &str, address: &str) -> Result<AutoreplyView> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let address = MailAddress::parse(address)?;
        require_available(&self.ctx).await?;
        let rec = self.mailbox_of(&tenant, &address)?;
        let m = rec.mailboxes.get(address.local.as_str());
        Ok(autoreply_view(
            &address,
            m.and_then(|m| m.autoreply.as_ref()),
        ))
    }

    // -- limits and usage --

    pub async fn get_limits(&self, tenant: &str) -> Result<Resolved> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        require_available(&self.ctx).await?;
        self.tenant(&tenant, false)?;
        self.resolved_limits(&tenant)
    }

    /// Replace one layer of the account's limits (or, for a client older
    /// than engine 0.3.1, its account layer from flat values, 0 = inherit).
    pub async fn set_limits(&self, tenant: &str, change: LimitsChange) -> Result<Resolved> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        match &change {
            LimitsChange::Plan(l) | LimitsChange::Account(l) => l.validate()?,
            LimitsChange::Legacy(_) => {}
        }
        require_available(&self.ctx).await?;
        let _guard = self.ctx.lock.lock().await;
        self.tenant(&tenant, false)?;
        let mut rec = self.store().load_limits(&tenant)?;
        match change {
            LimitsChange::Plan(l) => rec.plan = l,
            LimitsChange::Account(l) => rec.account = l,
            LimitsChange::Legacy(l) => {
                let s = |v: u64| {
                    if v == 0 {
                        Setting::Inherit
                    } else {
                        Setting::Value(v)
                    }
                };
                let account = Layer {
                    max_mailboxes: s(u64::from(l.max_mailboxes)),
                    max_mailbox_bytes: s(l.max_mailbox_bytes),
                    rate_account: s(u64::from(l.rate_account)),
                    rate_mailbox: s(u64::from(l.rate_mailbox)),
                };
                account.validate()?;
                rec.account = account;
                rec.plan = Layer::default();
            }
        }
        self.store().save_limits(&rec)?;
        self.apply(None).await?;
        info!(tenant = %tenant, plan = ?rec.plan, account = ?rec.account, "mail limits set");
        self.resolved_limits(&tenant)
    }

    /// The host's default limits and the built-in ones.
    pub async fn get_defaults(&self) -> Result<(Layer, Layer)> {
        require_available(&self.ctx).await?;
        let cfg = &self.ctx.config.mail;
        Ok((
            super::ops::host_defaults(cfg, &self.store())?,
            super::limits::builtin(cfg),
        ))
    }

    /// Change the host's default limits (a limit left `inherit` stays as it
    /// is). Every account that follows a default follows the new one at once.
    pub async fn set_defaults(&self, update: Layer) -> Result<(Layer, Layer)> {
        update.validate()?;
        require_available(&self.ctx).await?;
        let _guard = self.ctx.lock.lock().await;
        let cfg = &self.ctx.config.mail;
        let next = super::ops::host_defaults(cfg, &self.store())?.merged(&update);
        self.store().save_defaults(&next)?;
        self.apply(None).await?;
        info!(defaults = ?next, "host default mail limits set");
        Ok((next, super::limits::builtin(cfg)))
    }

    pub async fn usage(&self, tenant: &str) -> Result<Usage> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        require_available(&self.ctx).await?;
        self.tenant(&tenant, false)?;
        let mut u = Usage {
            sent_this_hour: super::policy::sent_this_hour(
                &self.ctx.config.mail.state_dir,
                tenant.as_str(),
            ),
            ..Usage::default()
        };
        for d in self.store().list_tenant(tenant.as_str())? {
            for (local, _) in d.live_mailboxes() {
                u.mailboxes += 1;
                u.bytes_used += quota_usage(&self.ctx, &format!("{local}@{}", d.domain))
                    .await
                    .0;
            }
        }
        Ok(u)
    }
}

fn autoreply_view(address: &MailAddress, r: Option<&AutoreplyRecord>) -> AutoreplyView {
    match r {
        Some(r) => AutoreplyView {
            address: address.to_string(),
            enabled: r.enabled,
            subject: r.subject.clone(),
            body: r.body.clone(),
            starts_at_unix: r.starts_at_unix,
            ends_at_unix: r.ends_at_unix,
        },
        None => AutoreplyView {
            address: address.to_string(),
            ..AutoreplyView::default()
        },
    }
}

/// Remove a mailbox's mail as the account, then its record entry.
fn spawn_removal(ctx: Ctx, t: TenantRecord, domain: Domain, local: MailLocalPart) {
    tokio::spawn(async move {
        if let Err(e) = finish_removal(&ctx, &t, &domain, local.as_str()).await {
            warn!(mailbox = %format!("{local}@{domain}"), error = %e, "the mail of a removed mailbox could not be deleted yet; retried at the next start");
        }
    });
}

pub(super) async fn finish_removal(
    ctx: &Ctx,
    t: &TenantRecord,
    domain: &Domain,
    local: &str,
) -> Result<()> {
    ops::remove_maildir(ctx, t, domain.as_str(), Some(local)).await?;
    let _guard = ctx.lock.lock().await;
    let store = MailStore::new(&ctx.config);
    if let Some(mut rec) = store.load(domain)? {
        if rec
            .mailboxes
            .get(local)
            .is_some_and(|m| m.state == RecordState::Deleting)
        {
            rec.mailboxes.remove(local);
            store.save(&rec)?;
            info!(mailbox = %format!("{local}@{domain}"), "the mail of a removed mailbox is deleted");
        }
    }
    Ok(())
}
