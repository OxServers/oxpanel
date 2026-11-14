//! Email in the account's life: suspension, deletion, start-up convergence,
//! reconciliation, and the records email adds to a DNS zone.

use tracing::{error, info, warn};

use super::mailboxes::{finish_removal, kick};
use super::store::{MailMode, MailStore, RecordState};
use super::{ops, records, render};
use crate::ctx::Ctx;
use crate::dns::rr::{RawRr, Rr, RrType};
use crate::dns::zone::Origin;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::host::{Drift, DriftKind};
use crate::records::now_unix;
use crate::validate::{Domain, MailLocalPart, Username};

/// Deleting an account is refused while it has mail domains; a cascading
/// deletion removes them with [`remove_tenant_mail`].
pub fn refuse_tenant_deletion(ctx: &Ctx, tenant: &Username) -> Result<()> {
    if MailStore::new(&ctx.config)
        .list()?
        .iter()
        .any(|d| d.tenant == tenant.as_str())
    {
        return Err(Error::TenantHasMailDomains(tenant.to_string()));
    }
    Ok(())
}

/// After an account was suspended or resumed (the record says which): the
/// maps and the password files follow; a suspended account's sessions end.
/// The caller holds the mutation lock.
pub async fn tenant_changed(ctx: &Ctx, tenant: &Username, suspended: bool) -> Result<()> {
    let domains = MailStore::new(&ctx.config).list_tenant(tenant.as_str())?;
    if domains.is_empty() || !ctx.config.mail.enabled {
        return Ok(());
    }
    ops::apply(ctx).await?;
    if suspended {
        for d in &domains {
            kick(ctx, &format!("*@{}", d.domain)).await;
        }
    }
    info!(tenant = %tenant, suspended, "email follows the account's suspension");
    Ok(())
}

/// Remove every mail domain of `tenant` (a cascading deletion): servers
/// first, then DKIM keys, autoresponder scripts, records and limits. The
/// mail itself goes with the home. The caller holds the mutation lock.
pub async fn remove_tenant_mail(ctx: &Ctx, tenant: &Username) -> Result<usize> {
    let store = MailStore::new(&ctx.config);
    let mut domains = store.list_tenant(tenant.as_str())?;
    if domains.is_empty() {
        store.delete_limits(tenant)?;
        return Ok(0);
    }
    for d in &mut domains {
        if d.state != RecordState::Deleting {
            d.state = RecordState::Deleting;
            store.save(d)?;
        }
        kick(ctx, &format!("*@{}", d.domain)).await;
    }
    ops::apply(ctx).await?;
    for d in &domains {
        let dom = d.domain()?;
        ops::prune_dkim_keys(ctx, None, &d.domain)?;
        let sieve = ctx.config.mail.state_dir.join("sieve").join(&d.domain);
        fsutil::remove_dir_tree(&sieve)?;
        store.delete(&dom)?;
        if let Err(e) = crate::dns::mail_changed(ctx, &dom).await {
            warn!(domain = %dom, error = %e, "the zone keeps its mail records until it is re-rendered");
        }
    }
    store.delete_limits(tenant)?;
    ops::apply(ctx).await?;
    info!(tenant = %tenant, domains = domains.len(), "email of the account removed");
    Ok(domains.len())
}

/// At start-up: finish what was interrupted (domains being set up or
/// removed, mailboxes whose mail is being deleted), then render and load
/// everything and make sure the servers run.
pub async fn converge(ctx: &Ctx) {
    if !ctx.config.mail.enabled || super::unavailable_reason(ctx).await.is_some() {
        return;
    }
    if let Err(e) = converge_inner(ctx).await {
        error!(error = %e, "email could not be converged; see `oxpanel-ctl host reconcile`");
    }
}

async fn converge_inner(ctx: &Ctx) -> Result<()> {
    let removals = {
        let _guard = ctx.lock.lock().await;
        let store = MailStore::new(&ctx.config);
        let svc = super::MailService::new(ctx.clone());
        let mut removals = Vec::new();
        for rec in store.list()? {
            let Some(t) = ctx.store.load_tenant(&Username::parse(&rec.tenant)?)? else {
                continue;
            };
            match rec.state {
                RecordState::Provisioning => {
                    svc.finish_domain(rec.clone(), &t).await?;
                }
                RecordState::Deleting => {
                    store.delete(&rec.domain()?)?;
                }
                RecordState::Ready => {}
            }
            for local in ops::deleting(&rec) {
                removals.push((t.clone(), rec.domain()?, local));
            }
        }
        // Retired DKIM keys whose week is over.
        for mut rec in store.list()? {
            let before = rec.dkim_retired.len();
            rec.dkim_retired
                .retain(|k| k.retire_at_unix.is_some_and(|t| t > now_unix()));
            if rec.dkim_retired.len() != before {
                store.save(&rec)?;
                ops::prune_dkim_keys(ctx, Some(&rec), &rec.domain)?;
            }
        }
        ops::apply(ctx).await?;
        ops::enable_services(ctx).await?;
        removals
    };
    for (t, d, local) in removals {
        finish_removal(ctx, &t, &d, &local).await?;
    }
    info!("email converged");
    Ok(())
}

/// The records email keeps in `zone` (of `tenant`): those of every mail
/// domain of the tenant inside it.
pub fn zone_records(ctx: &Ctx, zone: &Domain, tenant: &str) -> Vec<(Rr, Origin)> {
    let Some(host) = ctx
        .config
        .mail
        .hostname
        .clone()
        .filter(|_| ctx.config.mail.enabled)
    else {
        return Vec::new();
    };
    let Ok(domains) = MailStore::new(&ctx.config).list_tenant(tenant) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for d in domains.iter().filter(|d| render::live(d)) {
        if !(d.domain == zone.as_str() || d.domain.ends_with(&format!(".{zone}"))) {
            continue;
        }
        for r in records::required(d, &host, now_unix()) {
            let Some(name) = records::relative_to_zone(&r.name, &d.domain, zone.as_str()) else {
                continue;
            };
            let raw = RawRr {
                name,
                rtype: Some(match r.rtype {
                    "MX" => RrType::Mx,
                    "TXT" => RrType::Txt,
                    "CNAME" => RrType::Cname,
                    _ => RrType::Srv,
                }),
                ttl: 0,
                value: r.value.clone(),
                priority: u32::from(r.priority),
                weight: u32::from(r.weight),
                port: u32::from(r.port),
                ..RawRr::default()
            };
            match Rr::parse(&raw, zone) {
                Ok(rr) => out.push((rr, Origin::Mail)),
                Err(e) => warn!(domain = %d.domain, error = %e, "a mail record could not be made"),
            }
        }
    }
    out
}

/// Reconciliation of email: files, services, records, mailbox directories,
/// orphans.
pub async fn drifts(ctx: &Ctx) -> Result<Vec<Drift>> {
    let mut out = Vec::new();
    let store = MailStore::new(&ctx.config);
    let domains = store.list()?;
    let cfg = &ctx.config.mail;
    let Some(host) = cfg.hostname.clone().filter(|_| cfg.enabled) else {
        if !domains.is_empty() {
            out.push(Drift::new(
                DriftKind::MailConfigDrift,
                "email",
                format!(
                    "{} mail domains exist while email is off on this host",
                    domains.len()
                ),
            ));
        }
        return Ok(out);
    };
    let m = ops::model(ctx, &host)?;
    for (path, text) in ops::expected(ctx, &m)? {
        if let Some(why) = crate::host::compare_file(&path, &text)? {
            out.push(Drift::new(
                DriftKind::MailConfigDrift,
                path.display().to_string(),
                why,
            ));
        }
    }
    for unit in ops::services(ctx) {
        if !ops::unit_active(ctx, unit).await? {
            out.push(Drift::new(
                DriftKind::MailConfigDrift,
                unit,
                "is not running",
            ));
        }
    }
    for d in &domains {
        domain_drifts(ctx, d, &mut out)?;
    }
    orphan_drifts(ctx, &domains, &mut out)?;
    Ok(out)
}

fn domain_drifts(
    ctx: &Ctx,
    d: &super::store::MailDomainRecord,
    out: &mut Vec<Drift>,
) -> Result<()> {
    if d.state != RecordState::Ready {
        out.push(Drift::new(
            DriftKind::MailDomainDrift,
            &d.domain,
            format!(
                "interrupted ({:?}); repeat SetMailDomain or restart the daemon",
                d.state
            ),
        ));
    }
    let Some(t) = ctx.store.load_tenant(&Username::parse(&d.tenant)?)? else {
        out.push(Drift::new(
            DriftKind::MailDomainDrift,
            &d.domain,
            format!("its account '{}' does not exist", d.tenant),
        ));
        return Ok(());
    };
    if d.mode != MailMode::Local {
        return Ok(());
    }
    for (local, m) in &d.mailboxes {
        let addr = format!("{local}@{}", d.domain);
        if m.state == RecordState::Deleting {
            out.push(Drift::new(
                DriftKind::MailDomainDrift,
                &addr,
                "removed; its mail is still being deleted",
            ));
            continue;
        }
        let dir = render::maildir(&t.home, &d.domain, local);
        match std::fs::symlink_metadata(&dir) {
            Err(_) => out.push(Drift::new(
                DriftKind::MailDomainDrift,
                &addr,
                "its mail directory is missing",
            )),
            Ok(md) if !md.is_dir() => out.push(Drift::new(
                DriftKind::MailDomainDrift,
                &addr,
                "its mail directory is not a directory (a symlink?); mail cannot be delivered",
            )),
            Ok(md) => {
                use std::os::unix::fs::MetadataExt;
                if md.uid() != t.uid && !ctx.config.dry_run {
                    out.push(Drift::new(
                        DriftKind::MailDomainDrift,
                        &addr,
                        "its mail directory is not owned by the account",
                    ));
                }
            }
        }
        let _ = MailLocalPart::parse(local)?;
    }
    Ok(())
}

fn orphan_drifts(
    ctx: &Ctx,
    domains: &[super::store::MailDomainRecord],
    out: &mut Vec<Drift>,
) -> Result<()> {
    let cfg = &ctx.config.mail;
    let dkim = cfg.state_dir.join("dkim");
    for name in fsutil::list_entry_names(&dkim)? {
        if !ops::is_key_file(&name) {
            continue;
        }
        let known = domains.iter().any(|d| {
            d.dkim
                .iter()
                .chain(&d.dkim_retired)
                .any(|k| name == format!("{}.{}.key", d.domain, k.selector))
        });
        if !known {
            out.push(Drift::new(
                DriftKind::OrphanMailFile,
                dkim.join(&name).display().to_string(),
                "a DKIM key no mail domain uses",
            ));
        }
    }
    let sieve = cfg.state_dir.join("sieve");
    for dom in fsutil::list_dirs(&sieve)? {
        if !domains.iter().any(|d| d.domain == dom) {
            out.push(Drift::new(
                DriftKind::OrphanMailFile,
                sieve.join(&dom).display().to_string(),
                "autoresponder scripts of no mail domain",
            ));
        }
    }
    Ok(())
}
