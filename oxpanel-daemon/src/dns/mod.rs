//! DNS hosting: this host as the authoritative name server of its tenants'
//! domains.
//!
//! - The operator configures the name-server names, the SOA contact and the
//!   host's public addresses once ([`DnsConfig`]); DNS hosting is off until
//!   then. The server is BIND, run by OxPanel as `oxpanel-dns.service` with
//!   a configuration OxPanel owns entirely ([`bind`]).
//! - A **zone** belongs to exactly one tenant. Sites get one by themselves:
//!   when a site's name is not inside a zone yet, a zone is created for the
//!   name's *registrable domain* (from the host's public suffix list,
//!   [`psl`]). Zones never overlap and never contain another tenant's
//!   sites, and no zone can be a public suffix — that is what stops one
//!   tenant from answering for another's names.
//! - A zone file is rendered from records only ([`zone`]): the SOA and the
//!   apex NS records (from the host settings), the address records of the
//!   tenant's sites in the zone (both **protected**: the engine maintains
//!   them), then the records the tenant added ([`rr`]). Every change is
//!   validated by the server's checker before the server sees it and the
//!   zone alone is reloaded.
//! - Secondaries learn about zones through a catalog zone and transfer them
//!   with a TSIG key; DNSSEC is the server's own key and signature
//!   maintenance, switched on per zone ([`dnssec`]).
//! - What only the network can tell (delegation, DS at the parent, serials
//!   of the secondaries) is asked by an unprivileged probe ([`probe`]).

pub mod bind;
pub mod config;
pub mod dnssec;
mod ops;
pub mod probe;
pub mod psl;
pub mod rr;
pub mod store;
pub mod wire;
pub mod zone;

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod proptests;
#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests;

pub use config::DnsConfig;

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use tracing::{info, warn};

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::host::{Drift, DriftKind};
use crate::records::{now_unix, TenantState, VHostRecord, RECORD_VERSION};
use crate::system::{bin, CommandSpec};
use crate::validate::{Domain, Username};
use bind::Layout;
use psl::SuffixList;
use rr::{RData, RawRr, RelName, Rr, RrType};
use store::{StoredRr, ZoneRecord, ZoneState, ZoneStore};
use zone::ZoneInput;

/// The primary, as the probe reaches it (the server listens everywhere).
const PRIMARY: &str = "127.0.0.1:53";

/// `name` is `zone` or below it.
fn is_within(name: &str, zone: &str) -> bool {
    name == zone || name.ends_with(&format!(".{zone}"))
}

/// Why DNS hosting cannot be used now; `None` when it can.
pub async fn unavailable_reason(ctx: &Ctx) -> Result<Option<String>> {
    let cfg = &ctx.config.dns;
    if !cfg.enabled {
        return Ok(Some(
            "DNS hosting is off (set OXPANEL_DNS=true with the name servers, SOA contact and public addresses; see the handbook)".to_owned(),
        ));
    }
    for (program, package) in [
        (bin::NAMED, "bind"),
        (bin::NAMED_CHECKZONE, "bind"),
        (bin::NAMED_CHECKCONF, "bind"),
        (bin::RNDC, "bind"),
    ] {
        if !ctx.sys.is_installed(program).await {
            return Ok(Some(format!(
                "the DNS server is not installed ({program} is missing): dnf install {package}"
            )));
        }
    }
    if psl::load(&cfg.suffix_list)?.is_none() {
        return Ok(Some(format!(
            "the public suffix list is not installed ({} is missing): dnf install publicsuffix-list",
            cfg.suffix_list.display()
        )));
    }
    Ok(None)
}

async fn require_available(ctx: &Ctx) -> Result<Arc<SuffixList>> {
    if let Some(why) = unavailable_reason(ctx).await? {
        return Err(Error::DnsUnavailable(why));
    }
    psl::load(&ctx.config.dns.suffix_list)?
        .ok_or_else(|| Error::DnsUnavailable("the public suffix list is missing".to_owned()))
}

// ---- what the API shows ----------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordView {
    pub id: u64,
    pub rr: Rr,
    pub protected: bool,
    pub origin: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecState {
    Off,
    Signing,
    Signed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnssecView {
    pub state: DnssecState,
    pub ds: Vec<String>,
    pub dnskey: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneView {
    pub record: ZoneRecord,
    /// The SOA data (after `SOA`), protected.
    pub soa: String,
    /// The engine's records then the tenant's (empty in listings).
    pub records: Vec<RecordView>,
    pub sites: Vec<String>,
    pub dnssec: DnssecView,
}

fn dnssec_view(ctx: &Ctx, rec: &ZoneRecord) -> Result<DnssecView> {
    if !rec.dnssec {
        return Ok(DnssecView {
            state: DnssecState::Off,
            ds: Vec::new(),
            dnskey: Vec::new(),
        });
    }
    let zone = rec.domain()?;
    let keys = dnssec::key_signing_keys(&Layout::new(&ctx.config.dns).key_dir(&zone))?;
    Ok(DnssecView {
        state: if keys.is_empty() {
            DnssecState::Signing
        } else {
            DnssecState::Signed
        },
        ds: keys.iter().map(|k| k.ds_record(&zone)).collect(),
        dnskey: keys.iter().map(|k| k.dnskey_record(&zone)).collect(),
    })
}

fn view(ctx: &Ctx, rec: ZoneRecord, with_records: bool) -> Result<ZoneView> {
    let zone = rec.domain()?;
    let rrs = rec.rrs()?;
    let plain: Vec<Rr> = rrs.iter().map(|(_, r)| r.clone()).collect();
    let vhosts = ctx.store.list_vhosts()?;
    let sites_in = ops::site_names(&rec, &plain, &vhosts)?;
    let mut sites: Vec<String> = sites_in.iter().map(|s| s.site.clone()).collect();
    sites.dedup();
    let mut records = Vec::new();
    if with_records {
        let input = ZoneInput {
            zone: &zone,
            cfg: &ctx.config.dns,
            sites: &sites_in,
            records: &plain,
        };
        for (rr, origin) in zone::engine_records(&input) {
            records.push(RecordView {
                id: 0,
                rr,
                protected: true,
                origin: origin.label(),
            });
        }
        for (id, rr) in rrs {
            records.push(RecordView {
                id,
                rr,
                protected: false,
                origin: "tenant".to_owned(),
            });
        }
    }
    Ok(ZoneView {
        soa: zone::soa_data(&ctx.config.dns, rec.serial),
        dnssec: dnssec_view(ctx, &rec)?,
        records,
        sites,
        record: rec,
    })
}

/// The zone holding the address records of a site's domain, if any.
pub fn zone_of_site(ctx: &Ctx, site: &VHostRecord) -> String {
    if !ctx.config.dns.enabled || !site.dns.is_on() {
        return String::new();
    }
    // Zones never overlap: the zone holding the name, if any, is the one
    // whose apex is the name or one of its parents (a handful of lookups,
    // not a scan of every zone: listings call this once per site).
    let store = ZoneStore::new(&ctx.config);
    let mut name = site.domain.as_str();
    loop {
        if let Ok(apex) = Domain::parse(name) {
            if let Ok(Some(z)) = store.load(&apex) {
                return if z.tenant == site.tenant {
                    z.zone
                } else {
                    String::new()
                };
            }
        }
        match name.split_once('.') {
            Some((_, parent)) if parent.contains('.') => name = parent,
            _ => return String::new(),
        }
    }
}

// ---- zone-level rules ------------------------------------------------------

/// Names inside the zone that the tenant's sites claim (delegated or not).
fn claimed_names(rec: &ZoneRecord, vhosts: &[VHostRecord]) -> Result<Vec<(RelName, String)>> {
    let zone = rec.domain()?;
    let mut out = Vec::new();
    for v in vhosts
        .iter()
        .filter(|v| v.tenant == rec.tenant && v.dns.is_on())
    {
        for n in v.all_names() {
            if let Some(rel) = RelName::relative_to(n, &zone) {
                out.push((rel, v.domain.clone()));
            }
        }
    }
    Ok(out)
}

/// The rules a zone's records must satisfy together, beyond each record's
/// own validation: what the engine protects, CNAME exclusivity, delegations,
/// and what the DNS forbids MX and SRV records to point at.
pub fn check_rules(zone: &Domain, rrs: &[Rr], claimed: &[(RelName, String)]) -> Result<()> {
    let conflict = |why: String| Err(Error::invalid("record", why));
    let site_at = |n: &RelName| claimed.iter().find(|(c, _)| c == n).map(|(_, s)| s.clone());
    let delegations: Vec<&RelName> = rrs
        .iter()
        .filter(|r| r.data.rtype() == RrType::Ns)
        .map(|r| &r.name)
        .collect();
    let cnames: Vec<&RelName> = rrs
        .iter()
        .filter(|r| r.data.rtype() == RrType::Cname)
        .map(|r| &r.name)
        .collect();
    for r in rrs {
        let t = r.data.rtype();
        let fq = r.name.fqdn(zone);
        if matches!(t, RrType::A | RrType::Aaaa | RrType::Cname) {
            if let Some(site) = site_at(&r.name) {
                return conflict(format!(
                    "{fq} is served by the site {site}: its address records are maintained by the engine (opt the site out of DNS hosting, or remove the name from the site, to point it elsewhere)"
                ));
            }
        }
        if t == RrType::Cname {
            if rrs.iter().filter(|o| o.name == r.name).count() > 1 {
                return conflict(format!(
                    "{fq} has a CNAME: a name with a CNAME can have no other record"
                ));
            }
            if r.data.target().is_some_and(|tg| tg.as_str() == fq) {
                return conflict(format!("the CNAME at {fq} points at itself"));
            }
        }
        if t == RrType::Ns {
            if let Some((n, site)) = claimed.iter().find(|(n, _)| n.is_at_or_below(&r.name)) {
                return conflict(format!(
                    "{fq} cannot be delegated: {} belongs to the site {site}",
                    n.fqdn(zone)
                ));
            }
        }
        for d in &delegations {
            let below = r.name != **d && r.name.is_at_or_below(d);
            if (r.name == **d && t != RrType::Ns) || (below && !t.is_address()) {
                return conflict(format!(
                    "{} is delegated to other name servers: only NS records can be at it, and only address (glue) records below it",
                    d.fqdn(zone)
                ));
            }
        }
        if let (RrType::Mx | RrType::Srv, Some(target)) = (t, r.data.target()) {
            if let Some(rel) = RelName::relative_to(target.as_str(), zone) {
                if cnames.contains(&&rel) {
                    return conflict(format!(
                        "{fq}: an {} record must not point at {}, which is a CNAME (RFC 2181); point it at the name the CNAME leads to",
                        t.as_str(),
                        target.as_str()
                    ));
                }
            }
        }
        if let RData::Mx { exchange, .. } = &r.data {
            let mxs = rrs
                .iter()
                .filter(|o| o.name == r.name && o.data.rtype() == RrType::Mx)
                .count();
            if exchange.is_root() && mxs > 1 {
                return conflict(format!(
                    "{fq}: a null MX (\".\": no mail) must be the only MX record of the name"
                ));
            }
        }
        if let Some(other) = rrs
            .iter()
            .find(|o| o.name == r.name && o.data.rtype() == t && o.ttl != r.ttl)
        {
            return conflict(format!(
                "the {} records of {fq} must all have the same TTL ({} and {})",
                t.as_str(),
                r.ttl,
                other.ttl
            ));
        }
    }
    Ok(())
}

/// Whether `zone` may be created for `tenant`: not a public suffix, not
/// overlapping any zone, and no other tenant's site inside it.
fn check_zone_free(ctx: &Ctx, list: &SuffixList, zone: &Domain, tenant: &str) -> Result<()> {
    if list.registrable(zone.as_str()).is_none() {
        return Err(Error::DnsConflict(format!(
            "'{zone}' is a public suffix (names below it belong to different owners); a zone must be a registrable domain such as example.{zone}, or a name below one"
        )));
    }
    for z in ZoneStore::new(&ctx.config).list()? {
        if z.zone != zone.as_str()
            && (is_within(zone.as_str(), &z.zone) || is_within(&z.zone, zone.as_str()))
        {
            return Err(Error::DnsConflict(if z.tenant == tenant {
                format!(
                    "'{zone}' overlaps the tenant's zone '{}': add records to that zone instead",
                    z.zone
                )
            } else {
                format!("'{zone}' overlaps a zone of another tenant ('{}')", z.zone)
            }));
        }
    }
    for v in ctx
        .store
        .list_vhosts()?
        .iter()
        .filter(|v| v.tenant != tenant)
    {
        if let Some(n) = v.all_names().find(|n| is_within(n, zone.as_str())) {
            return Err(Error::DnsConflict(format!(
                "'{n}', inside '{zone}', is a site of another tenant"
            )));
        }
    }
    Ok(())
}

fn tenant_zone_count(ctx: &Ctx, tenant: &str) -> Result<u32> {
    Ok(u32::try_from(
        ZoneStore::new(&ctx.config)
            .list()?
            .iter()
            .filter(|z| z.tenant == tenant)
            .count(),
    )
    .unwrap_or(u32::MAX))
}

fn new_record(zone: &Domain, tenant: &str, automatic: bool) -> ZoneRecord {
    ZoneRecord {
        version: RECORD_VERSION,
        zone: zone.to_string(),
        tenant: tenant.to_owned(),
        created_at_unix: now_unix(),
        state: ZoneState::Provisioning,
        automatic,
        serial: 0,
        content_sha256: String::new(),
        records: Vec::new(),
        next_id: 1,
        dnssec: false,
        loaded_serial: 0,
    }
}

/// Finish creating zones: file, then the server configuration, then Ready.
async fn finish_creation(ctx: &Ctx, recs: Vec<ZoneRecord>) -> Result<Vec<ZoneRecord>> {
    let store = ZoneStore::new(&ctx.config);
    let mut written = Vec::new();
    for rec in recs {
        written.push(ops::apply_zone(ctx, None, rec, None).await?);
    }
    ops::apply_server(ctx).await?;
    let mut out = Vec::new();
    for mut rec in written {
        rec.state = ZoneState::Ready;
        rec.loaded_serial = rec.serial;
        store.save(&rec)?;
        info!(zone = %rec.zone, tenant = %rec.tenant, automatic = rec.automatic, "DNS zone created");
        out.push(rec);
    }
    Ok(out)
}

/// Delete a zone: the server stops serving it, then its files and record go.
async fn delete_locked(ctx: &Ctx, mut rec: ZoneRecord) -> Result<()> {
    let store = ZoneStore::new(&ctx.config);
    let zone = rec.domain()?;
    rec.state = ZoneState::Deleting;
    store.save(&rec)?;
    ops::apply_server(ctx).await?;
    ops::remove_zone_files(ctx, &zone)?;
    store.delete(&zone)?;
    info!(%zone, tenant = %rec.tenant, "DNS zone deleted");
    Ok(())
}

/// Remove every zone of a tenant (for a cascading tenant deletion). The
/// caller holds the mutation lock. Returns how many were removed.
pub async fn remove_tenant_zones(ctx: &Ctx, tenant: &Username) -> Result<usize> {
    let zones: Vec<ZoneRecord> = ZoneStore::new(&ctx.config)
        .list()?
        .into_iter()
        .filter(|z| z.tenant == tenant.as_str())
        .collect();
    let n = zones.len();
    for z in zones {
        delete_locked(ctx, z).await?;
    }
    Ok(n)
}

/// `DeleteTenant` is refused while the tenant owns zones.
pub fn refuse_tenant_deletion(ctx: &Ctx, tenant: &Username) -> Result<()> {
    if ZoneStore::new(&ctx.config)
        .list()?
        .iter()
        .any(|z| z.tenant == tenant.as_str())
    {
        return Err(Error::TenantHasDnsZones(tenant.to_string()));
    }
    Ok(())
}

// ---- following the sites ---------------------------------------------------

/// Zones for the names of `site` that no zone covers yet: one per
/// registrable domain. A name that cannot get one (a public suffix, another
/// tenant's names inside, the tenant's zone limit) is logged and left
/// without DNS; the site itself is unaffected. Returns the new records
/// (Provisioning).
fn plan_site_zones(ctx: &Ctx, list: &SuffixList, site: &VHostRecord) -> Result<Vec<ZoneRecord>> {
    let zones = ZoneStore::new(&ctx.config).list()?;
    let mut count = tenant_zone_count(ctx, &site.tenant)?;
    let mut planned: Vec<ZoneRecord> = Vec::new();
    for name in site.all_names() {
        if let Some(z) = zones.iter().find(|z| is_within(name, &z.zone)) {
            if z.tenant != site.tenant {
                info!(name, zone = %z.zone, "the name is inside another tenant's zone; it gets no DNS records from the engine");
            }
            continue;
        }
        if planned.iter().any(|p| is_within(name, &p.zone)) {
            continue;
        }
        let Some(apex) = Domain::parse(name)
            .ok()
            .and_then(|d| psl::zone_apex(list, &d))
        else {
            info!(
                name,
                "the name is a public suffix; no zone is created for it"
            );
            continue;
        };
        if let Err(e) = check_zone_free(ctx, list, &apex, &site.tenant) {
            info!(name, zone = %apex, reason = %e, "no zone is created for the site's name");
            continue;
        }
        if count >= ctx.config.dns.max_zones {
            warn!(name, tenant = %site.tenant, max = ctx.config.dns.max_zones, "the tenant has the maximum number of DNS zones; none is created for the site's name");
            continue;
        }
        count += 1;
        planned.push(new_record(&apex, &site.tenant, true));
    }
    Ok(planned)
}

/// The tenant's records at names a site now serves make way for the site's
/// own address records (creating the site or adding the alias asked for
/// exactly that); each removal is logged.
fn drop_conflicting(rec: &mut ZoneRecord, vhosts: &[VHostRecord]) -> Result<()> {
    let zone = rec.domain()?;
    let rrs = rec.rrs()?;
    let plain: Vec<Rr> = rrs.iter().map(|(_, r)| r.clone()).collect();
    let served: Vec<RelName> = ops::site_names(rec, &plain, vhosts)?
        .into_iter()
        .map(|s| s.name)
        .collect();
    let drop: Vec<u64> = rrs
        .iter()
        .filter(|(_, r)| {
            matches!(r.data.rtype(), RrType::A | RrType::Aaaa | RrType::Cname)
                && served.contains(&r.name)
        })
        .map(|(id, _)| *id)
        .collect();
    for id in &drop {
        info!(%zone, id, "a record at a name a site now serves was replaced by the site's address records");
    }
    rec.records.retain(|s| !drop.contains(&s.id));
    Ok(())
}

/// A site was created, changed or removed (`after = None`): create zones
/// for its new names, bring every zone of the tenant that holds one of its
/// old or new names up to date, and remove automatic zones that no site
/// uses any more and the tenant added nothing to. Called with the mutation
/// lock held; a no-op while DNS hosting is not available.
pub async fn site_changed(
    ctx: &Ctx,
    before: Option<&VHostRecord>,
    after: Option<&VHostRecord>,
) -> Result<()> {
    if unavailable_reason(ctx).await?.is_some() {
        return Ok(());
    }
    let list = require_available(ctx).await?;
    let Some(tenant) = after.or(before).map(|v| v.tenant.clone()) else {
        return Ok(());
    };
    if let Some(site) = after.filter(|s| s.dns.is_on()) {
        let planned = plan_site_zones(ctx, &list, site)?;
        if !planned.is_empty() {
            ops::ensure_layout(ctx).await?;
            finish_creation(ctx, planned).await?;
        }
    }
    let names: BTreeSet<String> = before
        .into_iter()
        .chain(after)
        .flat_map(|v| v.all_names().map(str::to_owned).collect::<Vec<_>>())
        .collect();
    let store = ZoneStore::new(&ctx.config);
    let vhosts = ctx.store.list_vhosts()?;
    for z in store.list()?.into_iter().filter(|z| {
        z.tenant == tenant
            && z.state == ZoneState::Ready
            && names.iter().any(|n| is_within(n, &z.zone))
    }) {
        let mut next = z.clone();
        drop_conflicting(&mut next, &vhosts)?;
        let rec = ops::apply_zone(ctx, Some(&z), next, None).await?;
        let plain: Vec<Rr> = rec.rrs()?.into_iter().map(|(_, r)| r).collect();
        if rec.automatic
            && rec.records.is_empty()
            && ops::site_names(&rec, &plain, &vhosts)?.is_empty()
            && claimed_names(&rec, &vhosts)?.is_empty()
        {
            delete_locked(ctx, rec).await?;
        }
    }
    Ok(())
}

/// At start-up: finish interrupted zone work, give sites without a zone one
/// (DNS hosting may just have been switched on), re-render every zone (the
/// host settings may have changed) and the server configuration. Failures
/// are logged; they never stop the daemon.
pub async fn converge(ctx: &Ctx) {
    let _guard = ctx.lock.lock().await;
    match converge_locked(ctx).await {
        Ok(Some(n)) => info!(zones = n, "DNS hosting converged"),
        Ok(None) => {}
        Err(e) => {
            warn!(error = %e, "could not converge DNS hosting; see `oxpanel-ctl host reconcile`");
        }
    }
}

async fn converge_locked(ctx: &Ctx) -> Result<Option<usize>> {
    let store = ZoneStore::new(&ctx.config);
    if let Some(why) = unavailable_reason(ctx).await? {
        let n = store.count()?;
        if n > 0 {
            warn!(zones = n, reason = %why, "DNS hosting is not available, but zones exist; they are left as they are");
        } else {
            info!(reason = %why, "DNS hosting not available");
        }
        return Ok(None);
    }
    let list = require_available(ctx).await?;
    ops::ensure_layout(ctx).await?;
    let mut pending = Vec::new();
    for z in store.list()? {
        match z.state {
            ZoneState::Deleting => delete_locked(ctx, z).await?,
            ZoneState::Provisioning => pending.push(z),
            ZoneState::Ready => {}
        }
    }
    for v in ctx.store.list_vhosts()?.iter().filter(|v| v.dns.is_on()) {
        for p in plan_site_zones(ctx, &list, v)? {
            if !pending.iter().any(|q| q.zone == p.zone) {
                store.save(&p)?;
                pending.push(p);
            }
        }
    }
    if !pending.is_empty() {
        finish_creation(ctx, pending).await?;
    }
    for z in store
        .list()?
        .into_iter()
        .filter(|z| z.state == ZoneState::Ready)
    {
        ops::apply_zone(ctx, Some(&z), z.clone(), None).await?;
    }
    ops::apply_server(ctx).await?;
    Ok(Some(store.count()?))
}

// ---- the API -----------------------------------------------------------------

/// The result of [`DnsService::check_zone`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneCheck {
    pub zone: String,
    pub delegation: Delegation,
    pub nameservers_seen: Vec<String>,
    pub guidance: String,
    pub ds_at_parent: Vec<String>,
    pub ds_checked: bool,
    pub ds_matches: bool,
    pub serials: Vec<ServerSerial>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delegation {
    Delegated,
    Partial,
    Elsewhere,
    NotFound,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSerial {
    pub server: String,
    pub serial: u32,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct DnsService {
    ctx: Ctx,
}

impl DnsService {
    pub fn new(ctx: Ctx) -> Self {
        Self { ctx }
    }

    pub fn config(&self) -> &DnsConfig {
        &self.ctx.config.dns
    }

    /// See [`zone_of_site`].
    pub fn zone_of_site(&self, site: &VHostRecord) -> String {
        zone_of_site(&self.ctx, site)
    }

    fn store(&self) -> ZoneStore {
        ZoneStore::new(&self.ctx.config)
    }

    /// The tenant's zone, for reading.
    fn owned(&self, tenant: &Username, zone: &Domain) -> Result<ZoneRecord> {
        match self.store().load(zone)? {
            Some(r) if r.tenant == tenant.as_str() && r.state != ZoneState::Deleting => Ok(r),
            _ => Err(Error::DnsZoneNotFound(zone.to_string())),
        }
    }

    /// The tenant's zone, for changing: the tenant must be ready and not
    /// suspended (a suspended tenant's zones keep answering, unchanged).
    fn mutable(&self, tenant: &Username, zone: &Domain) -> Result<ZoneRecord> {
        let t = self
            .ctx
            .store
            .load_tenant(tenant)?
            .ok_or_else(|| Error::TenantNotFound(tenant.to_string()))?;
        if t.state != TenantState::Ready {
            return Err(Error::TenantNotReady(tenant.to_string()));
        }
        if t.suspended {
            return Err(Error::DnsConflict(format!(
                "tenant '{tenant}' is suspended: its zones keep answering, but cannot be changed until it is resumed"
            )));
        }
        let rec = self.owned(tenant, zone)?;
        if rec.state != ZoneState::Ready {
            return Err(Error::DnsConflict(format!(
                "zone '{zone}' is still being created; repeat CreateDnsZone"
            )));
        }
        Ok(rec)
    }

    pub async fn create_zone(&self, tenant: &str, zone: &str) -> Result<(ZoneView, bool)> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let zone = Domain::parse_field(zone.trim_end_matches('.'), "zone")?;
        let _guard = self.ctx.lock.lock().await;
        let list = require_available(&self.ctx).await?;
        let t = self
            .ctx
            .store
            .load_tenant(&tenant)?
            .ok_or_else(|| Error::TenantNotFound(tenant.to_string()))?;
        if t.state != TenantState::Ready {
            return Err(Error::TenantNotReady(tenant.to_string()));
        }
        if let Some(existing) = self.store().load(&zone)? {
            if existing.tenant != tenant.as_str() {
                return Err(Error::DnsConflict(format!(
                    "zone '{zone}' already exists on this host"
                )));
            }
            if existing.state == ZoneState::Ready {
                return Ok((view(&self.ctx, existing, true)?, false));
            }
            // An interrupted creation: finish it.
            let done = finish_creation(&self.ctx, vec![existing]).await?;
            let rec = done
                .into_iter()
                .next()
                .ok_or_else(|| Error::Internal("zone creation lost".into()))?;
            return Ok((view(&self.ctx, rec, true)?, true));
        }
        if t.suspended {
            return Err(Error::DnsConflict(format!(
                "tenant '{tenant}' is suspended; zones cannot be created for it"
            )));
        }
        check_zone_free(&self.ctx, &list, &zone, tenant.as_str())?;
        if tenant_zone_count(&self.ctx, tenant.as_str())? >= self.ctx.config.dns.max_zones {
            return Err(Error::DnsLimitReached(format!(
                "tenant '{tenant}' already has the maximum of {} DNS zones",
                self.ctx.config.dns.max_zones
            )));
        }
        ops::ensure_layout(&self.ctx).await?;
        let rec = new_record(&zone, tenant.as_str(), false);
        self.store().save(&rec)?;
        let done = finish_creation(&self.ctx, vec![rec]).await?;
        let rec = done
            .into_iter()
            .next()
            .ok_or_else(|| Error::Internal("zone creation lost".into()))?;
        Ok((view(&self.ctx, rec, true)?, true))
    }

    pub async fn list_zones(&self, tenant: &str) -> Result<Vec<ZoneView>> {
        let filter = if tenant.is_empty() {
            None
        } else {
            Some(Username::parse_field(tenant, "tenant")?)
        };
        self.store()
            .list()?
            .into_iter()
            .filter(|z| filter.as_ref().is_none_or(|t| z.tenant == t.as_str()))
            .map(|z| view(&self.ctx, z, false))
            .collect()
    }

    pub async fn get_zone(&self, tenant: &str, zone: &str) -> Result<ZoneView> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let zone = Domain::parse_field(zone, "zone")?;
        view(&self.ctx, self.owned(&tenant, &zone)?, true)
    }

    pub async fn delete_zone(&self, tenant: &str, zone: &str) -> Result<bool> {
        let tenant = Username::parse_field(tenant, "tenant")?;
        let zone = Domain::parse_field(zone, "zone")?;
        let _guard = self.ctx.lock.lock().await;
        // Zones can be cleaned up after DNS hosting was switched off, as long
        // as the server is there to stop serving them.
        if !self.ctx.sys.is_installed(bin::NAMED).await {
            return Err(Error::DnsUnavailable(
                "the DNS server is not installed: dnf install bind".to_owned(),
            ));
        }
        let rec = match self.store().load(&zone)? {
            Some(r) if r.tenant == tenant.as_str() => r,
            _ => return Ok(false),
        };
        delete_locked(&self.ctx, rec).await?;
        Ok(true)
    }

    /// Validate `rrs` as the zone's complete set and write it.
    async fn replace_records(
        &self,
        rec: &ZoneRecord,
        records: Vec<StoredRr>,
        next_id: u64,
    ) -> Result<ZoneRecord> {
        let zone = rec.domain()?;
        let mut next = rec.clone();
        next.records = records;
        next.next_id = next_id;
        let plain: Vec<Rr> = next.rrs()?.into_iter().map(|(_, r)| r).collect();
        let max = usize::try_from(self.ctx.config.dns.max_records).unwrap_or(usize::MAX);
        if plain.len() > max && plain.len() > rec.records.len() {
            return Err(Error::DnsLimitReached(format!(
                "zone '{zone}' already has the maximum of {max} records"
            )));
        }
        check_rules(
            &zone,
            &plain,
            &claimed_names(&next, &self.ctx.store.list_vhosts()?)?,
        )?;
        ops::apply_zone(&self.ctx, Some(rec), next, None).await
    }

    fn parse_target(tenant: &str, zone: &str) -> Result<(Username, Domain)> {
        Ok((
            Username::parse_field(tenant, "tenant")?,
            Domain::parse_field(zone, "zone")?,
        ))
    }

    pub async fn add_record(
        &self,
        tenant: &str,
        zone: &str,
        raw: &RawRr,
    ) -> Result<(RecordView, bool, u32)> {
        let (tenant, zone) = Self::parse_target(tenant, zone)?;
        let rr = Rr::parse(raw, &zone)?;
        let _guard = self.ctx.lock.lock().await;
        require_available(&self.ctx).await?;
        let rec = self.mutable(&tenant, &zone)?;
        if let Some((id, _)) = rec.rrs()?.into_iter().find(|(_, r)| *r == rr) {
            return Ok((tenant_view(id, rr), false, rec.serial));
        }
        let id = rec.next_id;
        let mut records = rec.records.clone();
        records.push(StoredRr {
            id,
            rr: rr.to_raw(),
        });
        let saved = self.replace_records(&rec, records, id + 1).await?;
        info!(%zone, %tenant, id, rtype = rr.data.rtype().as_str(), "DNS record added");
        Ok((tenant_view(id, rr), true, saved.serial))
    }

    pub async fn update_record(
        &self,
        tenant: &str,
        zone: &str,
        id: u64,
        raw: &RawRr,
    ) -> Result<(RecordView, bool, u32)> {
        let (tenant, zone) = Self::parse_target(tenant, zone)?;
        let rr = Rr::parse(raw, &zone)?;
        let _guard = self.ctx.lock.lock().await;
        require_available(&self.ctx).await?;
        let rec = self.mutable(&tenant, &zone)?;
        let current = rec.rrs()?;
        let Some((_, old)) = current.iter().find(|(i, _)| *i == id) else {
            return Err(Error::DnsRecordNotFound {
                zone: zone.to_string(),
                id,
            });
        };
        if *old == rr {
            return Ok((tenant_view(id, rr), false, rec.serial));
        }
        let records = rec
            .records
            .iter()
            .map(|s| {
                if s.id == id {
                    StoredRr {
                        id,
                        rr: rr.to_raw(),
                    }
                } else {
                    s.clone()
                }
            })
            .collect();
        let saved = self.replace_records(&rec, records, rec.next_id).await?;
        info!(%zone, %tenant, id, "DNS record changed");
        Ok((tenant_view(id, rr), true, saved.serial))
    }

    pub async fn remove_record(&self, tenant: &str, zone: &str, id: u64) -> Result<(bool, u32)> {
        let (tenant, zone) = Self::parse_target(tenant, zone)?;
        let _guard = self.ctx.lock.lock().await;
        require_available(&self.ctx).await?;
        let rec = self.mutable(&tenant, &zone)?;
        if !rec.records.iter().any(|s| s.id == id) {
            return Ok((false, rec.serial));
        }
        let records = rec.records.iter().filter(|s| s.id != id).cloned().collect();
        let saved = self.replace_records(&rec, records, rec.next_id).await?;
        info!(%zone, %tenant, id, "DNS record removed");
        Ok((true, saved.serial))
    }

    /// Back to what the engine maintains: every record the tenant added goes.
    pub async fn reset_zone(&self, tenant: &str, zone: &str) -> Result<ZoneView> {
        let (tenant, zone) = Self::parse_target(tenant, zone)?;
        let _guard = self.ctx.lock.lock().await;
        require_available(&self.ctx).await?;
        let rec = self.mutable(&tenant, &zone)?;
        let saved = if rec.records.is_empty() {
            rec
        } else {
            let n = rec.records.len();
            let saved = self.replace_records(&rec, Vec::new(), rec.next_id).await?;
            info!(%zone, %tenant, removed = n, "DNS zone reset to its defaults");
            saved
        };
        view(&self.ctx, saved, true)
    }

    /// Ask the network about the zone (outside the daemon; no lock held).
    pub async fn check_zone(&self, tenant: &str, zone: &str) -> Result<ZoneCheck> {
        let (tenant, zone) = Self::parse_target(tenant, zone)?;
        require_available(&self.ctx).await?;
        let rec = self.owned(&tenant, &zone)?;
        check(&self.ctx, &rec).await
    }

    pub async fn set_dnssec(
        &self,
        tenant: &str,
        zone: &str,
        enabled: bool,
        force: bool,
    ) -> Result<ZoneView> {
        let (tenant, zone) = Self::parse_target(tenant, zone)?;
        let rec = {
            let _guard = self.ctx.lock.lock().await;
            require_available(&self.ctx).await?;
            let rec = self.mutable(&tenant, &zone)?;
            if rec.dnssec == enabled {
                // The record says so, but an earlier request may have been
                // interrupted after saving it: finish what it left undone.
                let rec = self.finish_switch(rec, &zone).await?;
                return view(&self.ctx, rec, true);
            }
            rec
        };
        // Switching off: look at the parent first (no lock held: it takes a
        // few seconds), then decide under the lock.
        let checked = if enabled {
            None
        } else {
            Some(check(&self.ctx, &rec).await?)
        };
        let _guard = self.ctx.lock.lock().await;
        let rec = self.mutable(&tenant, &zone)?;
        if rec.dnssec == enabled {
            let rec = self.finish_switch(rec, &zone).await?;
            return view(&self.ctx, rec, true);
        }
        let floor = match &checked {
            None => {
                ops::ensure_key_dir(&self.ctx, &zone).await?;
                rec.serial
            }
            Some(c) => {
                refuse_unsigning(&zone, c, force)?;
                c.serials
                    .first()
                    .map(|s| s.serial)
                    .filter(|s| zone::serial_gt(*s, rec.serial))
                    .unwrap_or(rec.serial)
            }
        };
        let mut next = rec.clone();
        next.dnssec = enabled;
        // A serial above anything served so far, so that secondaries take the
        // newly signed (or unsigned) zone; the server loads it with its new
        // configuration, not before.
        next.loaded_serial = 0;
        let mut saved = ops::apply_zone_unloaded(&self.ctx, &rec, next, floor).await?;
        if !enabled {
            // The journal of the unsigned side describes the zone as it was
            // signed: loaded with the new file, it would be out of sync and
            // the server would refuse to load the zone at all.
            ops::remove_raw_journal(&self.ctx, &zone)?;
        }
        ops::apply_server(&self.ctx).await?;
        saved.loaded_serial = saved.serial;
        self.store().save(&saved)?;
        if !enabled {
            ops::remove_signing_state(&self.ctx, &zone)?;
        }
        info!(%zone, %tenant, dnssec = enabled, "DNSSEC switched");
        view(&self.ctx, saved, true)
    }

    /// The tail of a DNSSEC switch whose record was already saved: the
    /// server loads the zone with its new configuration (`loaded_serial` 0
    /// says it has not yet), and switching off leaves no signing state. A
    /// switch interrupted there (daemon killed, the server's reload failed)
    /// is completed by repeating the request. The caller holds the lock.
    async fn finish_switch(&self, mut rec: ZoneRecord, zone: &Domain) -> Result<ZoneRecord> {
        let keys_left = !rec.dnssec && Layout::new(&self.ctx.config.dns).key_dir(zone).exists();
        if rec.loaded_serial != 0 && !keys_left {
            return Ok(rec);
        }
        if !rec.dnssec {
            ops::remove_raw_journal(&self.ctx, zone)?;
        }
        ops::apply_server(&self.ctx).await?;
        if rec.loaded_serial == 0 {
            rec.loaded_serial = rec.serial;
            self.store().save(&rec)?;
        }
        if !rec.dnssec {
            ops::remove_signing_state(&self.ctx, zone)?;
        }
        info!(%zone, tenant = %rec.tenant, dnssec = rec.dnssec, "interrupted DNSSEC switch completed");
        Ok(rec)
    }
}

fn tenant_view(id: u64, rr: Rr) -> RecordView {
    RecordView {
        id,
        rr,
        protected: false,
        origin: "tenant".to_owned(),
    }
}

/// Switching DNSSEC off is only safe once the parent publishes no DS.
fn refuse_unsigning(zone: &Domain, c: &ZoneCheck, force: bool) -> Result<()> {
    if !c.ds_at_parent.is_empty() {
        return Err(Error::DnsConflict(format!(
            "the parent zone still publishes a DS record for {zone} ({}): unsigning now would make the domain unresolvable for validating resolvers. Remove the DS record at your registrar first, wait until it has expired from caches (at least its TTL, usually one to two days), then switch DNSSEC off",
            c.ds_at_parent.join(", ")
        )));
    }
    if !c.ds_checked && !force {
        return Err(Error::DnsConflict(format!(
            "could not check whether the parent zone publishes a DS record for {zone}: make sure there is none at your registrar, then repeat with force"
        )));
    }
    Ok(())
}

// ---- looking from outside ----------------------------------------------------

fn our_ds(ctx: &Ctx, rec: &ZoneRecord) -> Result<Vec<String>> {
    let zone = rec.domain()?;
    Ok(
        dnssec::key_signing_keys(&Layout::new(&ctx.config.dns).key_dir(&zone))?
            .iter()
            .map(|k| format!("{}/{}/2/{}", k.key_tag(), k.algorithm, k.ds_digest(&zone)))
            .collect(),
    )
}

fn primary() -> SocketAddr {
    PRIMARY
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 53)))
}

/// Delegation, DS at the parent and serials of every name server.
async fn check(ctx: &Ctx, rec: &ZoneRecord) -> Result<ZoneCheck> {
    use probe::{Outcome, Question, Server};
    let cfg = &ctx.config.dns;
    let name = rec.zone.clone();
    let q = |server: Server, qtype: u16, recursion: bool| Question {
        server,
        name: name.clone(),
        qtype,
        recursion,
    };
    let mut questions = vec![
        q(Server::Resolver, wire::TYPE_NS, true),
        q(Server::Resolver, wire::TYPE_DS, true),
        q(Server::At(primary()), wire::TYPE_SOA, false),
    ];
    for s in &cfg.secondaries {
        questions.push(q(Server::At(*s), wire::TYPE_SOA, false));
    }
    let out = probe::run(ctx, &questions).await?;
    let get = |i: usize| {
        out.get(i)
            .cloned()
            .unwrap_or(Outcome::Failed("missing".into()))
    };
    let ours: BTreeSet<String> = cfg.nameservers.iter().map(ToString::to_string).collect();
    let (delegation, seen) = match get(0) {
        Outcome::Answer(a) if a.rcode == 3 => (Delegation::NotFound, Vec::new()),
        Outcome::Answer(a) if a.rcode == 0 && !a.ns.is_empty() => {
            let seen: BTreeSet<String> = a.ns.iter().cloned().collect();
            let d = if seen == ours {
                Delegation::Delegated
            } else if seen.intersection(&ours).next().is_some() {
                Delegation::Partial
            } else {
                Delegation::Elsewhere
            };
            (d, seen.into_iter().collect())
        }
        Outcome::Answer(a) if a.rcode == 0 => (Delegation::NotFound, Vec::new()),
        _ => (Delegation::Unknown, Vec::new()),
    };
    let (ds_at_parent, ds_checked) = match get(1) {
        Outcome::Answer(a) if a.rcode == 0 || a.rcode == 3 => (a.ds, true),
        _ => (Vec::new(), false),
    };
    let ours_ds = our_ds(ctx, rec)?;
    let ds_matches = ds_at_parent.iter().any(|d| ours_ds.contains(d));
    let mut serials = Vec::new();
    let primary_serial = match get(2) {
        Outcome::Answer(a) if a.authoritative => a.soa_serial.unwrap_or(0),
        _ => 0,
    };
    serials.push(ServerSerial {
        server: "primary".to_owned(),
        serial: primary_serial,
        status: if primary_serial == 0 {
            "not serving the zone".to_owned()
        } else {
            "ok".to_owned()
        },
    });
    for (i, s) in cfg.secondaries.iter().enumerate() {
        let (serial, status) = match get(3 + i) {
            Outcome::Answer(a) if a.authoritative => {
                let serial = a.soa_serial.unwrap_or(0);
                let status = if serial == primary_serial {
                    "ok"
                } else if zone::serial_gt(primary_serial, serial) {
                    "behind"
                } else {
                    "ahead of the primary"
                };
                (serial, status.to_owned())
            }
            Outcome::Answer(_) => (0, "not serving the zone".to_owned()),
            Outcome::Failed(why) => (0, format!("no answer ({why})")),
        };
        serials.push(ServerSerial {
            server: s.to_string(),
            serial,
            status,
        });
    }
    Ok(ZoneCheck {
        zone: name.clone(),
        guidance: guidance(delegation, &name, cfg, &seen),
        delegation,
        nameservers_seen: seen,
        ds_at_parent,
        ds_checked,
        ds_matches,
        serials,
    })
}

fn guidance(d: Delegation, zone: &str, cfg: &DnsConfig, seen: &[String]) -> String {
    let ns = cfg
        .nameservers
        .iter()
        .map(Domain::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    match d {
        Delegation::Delegated => format!("{zone} is delegated to this host's name servers: the records here are what the world sees."),
        Delegation::Partial => format!("{zone} is delegated to {} — not exactly to {ns}. At the registrar, set the domain's name servers to {ns} and nothing else.", seen.join(", ")),
        Delegation::Elsewhere => format!("{zone} is delegated to {}, not to this host: the records here are not used. At the registrar, set the domain's name servers to {ns}, or keep the DNS where it is and opt the site out of DNS hosting.", seen.join(", ")),
        Delegation::NotFound => format!("{zone} does not exist in the public DNS: register it, or check its spelling, then set its name servers to {ns} at the registrar."),
        Delegation::Unknown => format!("the public delegation of {zone} could not be checked from this host (no resolver answered); the zone is served here regardless."),
    }
}

// ---- host information and reconciliation ------------------------------------

/// DNS hosting for `GetHostInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsFacts {
    pub enabled: bool,
    pub available: bool,
    pub detail: String,
    pub warnings: Vec<String>,
    pub zone_count: u32,
    pub server_version: String,
    pub server_running: bool,
}

pub async fn facts(ctx: &Ctx) -> Result<DnsFacts> {
    let cfg = &ctx.config.dns;
    let why = unavailable_reason(ctx).await?;
    let mut f = DnsFacts {
        enabled: cfg.enabled,
        available: why.is_none(),
        detail: why.unwrap_or_else(|| "DNS hosting is available".to_owned()),
        warnings: cfg.warnings(),
        zone_count: u32::try_from(ZoneStore::new(&ctx.config).count()?).unwrap_or(u32::MAX),
        ..DnsFacts::default()
    };
    if ctx.sys.is_installed(bin::NAMED).await {
        let v = ctx
            .sys
            .run(CommandSpec::new(bin::NAMED, ctx.config.command_timeout).arg("-v"))
            .await?;
        v.stdout_lossy().trim().clone_into(&mut f.server_version);
        if cfg.enabled {
            f.server_running = ops::server_active(ctx).await?;
            if ops::unit_active(ctx, bind::STOCK_SERVICE).await? {
                f.warnings.push(format!(
                    "{} is running beside OxPanel's {}: both want port 53 and the control port 953; stop and disable it (systemctl disable --now named)",
                    bind::STOCK_SERVICE,
                    bind::SERVICE
                ));
            }
        }
    }
    Ok(f)
}

/// Reconcile: zone files against the records, the server configuration,
/// keys, orphans, and (through the probe) the serials the primary and the
/// secondaries serve. Read-only. Called with the mutation lock held.
pub async fn drifts(ctx: &Ctx) -> Result<Vec<Drift>> {
    let mut out = Vec::new();
    let store = ZoneStore::new(&ctx.config);
    let zones = store.list()?;
    if zones.is_empty() && !ctx.config.dns.enabled {
        return Ok(out);
    }
    let l = Layout::new(&ctx.config.dns);
    let vhosts = ctx.store.list_vhosts()?;
    let tenants: BTreeSet<String> = ctx
        .store
        .list_tenants()?
        .into_iter()
        .map(|t| t.username)
        .collect();
    for z in &zones {
        check_zone_files(ctx, &l, z, &vhosts, &tenants, &mut out)?;
    }
    check_orphans(&l, &zones, &mut out)?;
    if unavailable_reason(ctx).await?.is_some() {
        if !zones.is_empty() {
            out.push(Drift::new(
                DriftKind::DnsServerDrift,
                "dns",
                format!(
                    "{} zones exist but DNS hosting is not available",
                    zones.len()
                ),
            ));
        }
        return Ok(out);
    }
    check_server_files(ctx, &l, &zones, &mut out)?;
    if !ops::server_active(ctx).await? {
        out.push(Drift::new(
            DriftKind::DnsServerDrift,
            bind::SERVICE,
            "the DNS server is not running",
        ));
        return Ok(out);
    }
    check_serials(ctx, &zones, &mut out).await?;
    Ok(out)
}

fn check_zone_files(
    ctx: &Ctx,
    l: &Layout,
    z: &ZoneRecord,
    vhosts: &[VHostRecord],
    tenants: &BTreeSet<String>,
    out: &mut Vec<Drift>,
) -> Result<()> {
    let subject = z.zone.clone();
    if z.state != ZoneState::Ready {
        out.push(Drift::new(
            DriftKind::DnsZoneDrift,
            &subject,
            "creation or deletion was interrupted; repeat the request (or restart the daemon)",
        ));
        return Ok(());
    }
    if !tenants.contains(&z.tenant) {
        out.push(Drift::new(
            DriftKind::DnsZoneDrift,
            &subject,
            format!("the zone's tenant '{}' does not exist", z.tenant),
        ));
    }
    let zone = z.domain()?;
    let rrs: Vec<Rr> = z.rrs()?.into_iter().map(|(_, r)| r).collect();
    let sites = ops::site_names(z, &rrs, vhosts)?;
    let input = ZoneInput {
        zone: &zone,
        cfg: &ctx.config.dns,
        sites: &sites,
        records: &rrs,
    };
    let want = zone::render(&input, z.serial);
    match crate::fsutil::read_optional(&l.zone_file(&zone))? {
        None => out.push(Drift::new(DriftKind::DnsZoneDrift, &subject, "the zone file is missing")),
        Some(b) if b != want.as_bytes() => out.push(Drift::new(
            DriftKind::DnsZoneDrift,
            &subject,
            if zone::content_hash(&input) == z.content_sha256 {
                "the zone file differs from what its record renders (edited by hand?)"
            } else {
                "the zone's sites or the host's DNS settings changed since it was rendered (restart the daemon or change a record to bring it up to date)"
            },
        )),
        Some(_) => {}
    }
    let keys = dnssec::key_signing_keys(&l.key_dir(&zone))?;
    if z.dnssec && keys.is_empty() && l.key_dir(&zone).exists() {
        out.push(Drift::new(
            DriftKind::DnssecDrift,
            &subject,
            "DNSSEC is on but the zone's key directory holds no key-signing key",
        ));
    }
    if z.dnssec && !l.key_dir(&zone).exists() {
        out.push(Drift::new(
            DriftKind::DnssecDrift,
            &subject,
            "DNSSEC is on but the zone has no key directory",
        ));
    }
    if !z.dnssec && l.key_dir(&zone).exists() {
        out.push(Drift::new(
            DriftKind::DnssecDrift,
            &subject,
            "signing keys are left for a zone that is not signed",
        ));
    }
    Ok(())
}

fn check_orphans(l: &Layout, zones: &[ZoneRecord], out: &mut Vec<Drift>) -> Result<()> {
    let mut known: BTreeSet<String> = BTreeSet::new();
    known.insert(format!("{}.zone", zone::CATALOG_ZONE));
    for z in zones {
        if let Ok(d) = z.domain() {
            for p in std::iter::once(l.zone_file(&d)).chain(l.server_artefacts(&d)) {
                if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
                    known.insert(n.to_owned());
                }
            }
        }
    }
    // The catalog's own journal.
    for ext in [".jnl", ".jbk"] {
        known.insert(format!("{}.zone{ext}", zone::CATALOG_ZONE));
    }
    for name in crate::fsutil::list_entry_names(&l.zones_dir())? {
        if !known.contains(&name) {
            out.push(Drift::new(
                DriftKind::OrphanDnsFile,
                l.zones_dir().join(&name).to_string_lossy(),
                "no zone record accounts for this file",
            ));
        }
    }
    let signed: BTreeSet<&str> = zones
        .iter()
        .filter(|z| z.dnssec)
        .map(|z| z.zone.as_str())
        .collect();
    for dir in crate::fsutil::list_dirs(&l.keys_dir())? {
        if !signed.contains(dir.as_str()) && !zones.iter().any(|z| z.zone == dir) {
            out.push(Drift::new(
                DriftKind::OrphanDnsFile,
                l.keys_dir().join(&dir).to_string_lossy(),
                "signing keys of a zone that does not exist",
            ));
        }
    }
    Ok(())
}

fn check_server_files(
    ctx: &Ctx,
    l: &Layout,
    zones: &[ZoneRecord],
    out: &mut Vec<Drift>,
) -> Result<()> {
    let active: Vec<(Domain, bool)> = zones
        .iter()
        .filter(|z| z.state != ZoneState::Deleting)
        .filter_map(|z| z.domain().ok().map(|d| (d, z.dnssec)))
        .filter(|(d, _)| l.zone_file(d).exists())
        .collect();
    for (path, want) in [
        (l.named_conf(), bind::render_named_conf(&ctx.config.dns, l)?),
        (l.zones_conf(), bind::render_zones_conf(&active, l)?),
        (l.rndc_conf(), bind::render_rndc_conf(l)?),
    ] {
        match crate::fsutil::read_optional(&path)? {
            Some(b) if b == want.as_bytes() => {}
            Some(_) => out.push(Drift::new(
                DriftKind::DnsServerDrift,
                path.to_string_lossy(),
                "differs from what OxPanel renders (restart the daemon to rewrite it)",
            )),
            None => out.push(Drift::new(
                DriftKind::DnsServerDrift,
                path.to_string_lossy(),
                "missing",
            )),
        }
    }
    for (path, name) in [
        (l.rndc_key(), bind::RNDC_KEY),
        (l.transfer_key(), bind::TRANSFER_KEY),
    ] {
        let ok = crate::fsutil::read_optional(&path)?
            .is_some_and(|b| bind::key_file_is_valid(&String::from_utf8_lossy(&b), name));
        if !ok {
            out.push(Drift::new(
                DriftKind::DnsServerDrift,
                path.to_string_lossy(),
                "the key is missing or unusable",
            ));
        }
        if let Some(mode) = std::fs::symlink_metadata(&path).ok().map(|m| {
            use std::os::unix::fs::PermissionsExt;
            m.permissions().mode() & 0o7777
        }) {
            if mode & 0o037 != 0 {
                out.push(Drift::new(
                    DriftKind::DnsServerDrift,
                    path.to_string_lossy(),
                    format!("the key file is mode {mode:o}; it must be 0640 at most"),
                ));
            }
        }
    }
    Ok(())
}

async fn check_serials(ctx: &Ctx, zones: &[ZoneRecord], out: &mut Vec<Drift>) -> Result<()> {
    use probe::{Outcome, Question, Server};
    let ready: Vec<&ZoneRecord> = zones
        .iter()
        .filter(|z| z.state == ZoneState::Ready)
        .collect();
    if ready.is_empty() {
        return Ok(());
    }
    let mut servers = vec![primary()];
    servers.extend(ctx.config.dns.secondaries.iter().copied());
    let mut questions = Vec::new();
    for z in &ready {
        for s in &servers {
            questions.push(Question {
                server: Server::At(*s),
                name: z.zone.clone(),
                qtype: wire::TYPE_SOA,
                recursion: false,
            });
        }
    }
    let answers = probe::run(ctx, &questions).await?;
    let serial_of = |o: Option<&Outcome>| match o {
        Some(Outcome::Answer(a)) if a.authoritative => a.soa_serial,
        _ => None,
    };
    for (zi, z) in ready.iter().enumerate() {
        let base = zi * servers.len();
        let primary_serial = serial_of(answers.get(base));
        match primary_serial {
            None => out.push(Drift::new(
                DriftKind::DnsZoneDrift,
                &z.zone,
                "the DNS server does not serve the zone",
            )),
            Some(s) if !(s == z.serial || (z.dnssec && zone::serial_gt(s, z.serial))) => {
                out.push(Drift::new(
                    DriftKind::DnsZoneDrift,
                    &z.zone,
                    format!(
                        "the DNS server serves serial {s}, the record says {}",
                        z.serial
                    ),
                ));
            }
            Some(_) => {}
        }
        for (si, s) in ctx.config.dns.secondaries.iter().enumerate() {
            let got = serial_of(answers.get(base + 1 + si));
            if got != primary_serial || got.is_none() {
                out.push(Drift::new(
                    DriftKind::DnsSecondaryDrift,
                    format!("{} at {s}", z.zone),
                    match got {
                        None => "the secondary does not serve the zone".to_owned(),
                        Some(g) => format!(
                            "the secondary serves serial {g}, the primary {}",
                            primary_serial.unwrap_or(0)
                        ),
                    },
                ));
            }
        }
    }
    Ok(())
}
