//! The DNS server's files and the commands that activate them. Every
//! function here runs with the mutation lock held.

use tracing::{info, warn};

use super::bind::{self, Layout};
use super::store::{CatalogRecord, ZoneRecord, ZoneState, ZoneStore};
use super::zone::{self, SiteName, ZoneInput};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::records::{now_unix, VHostRecord};
use crate::system::{bin, CommandSpec};
use crate::validate::Domain;

/// Who a file or directory belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owner {
    /// `root:named`: the server reads it through its group.
    RootServer,
    /// `named:named`: the server writes it.
    Server,
}

/// The server account's uid and gid; `None` where there is none (the fake
/// OS of the tests, or the bind package missing).
async fn server_ids(ctx: &Ctx) -> Result<Option<(u32, u32)>> {
    Ok(ctx
        .sys
        .user_by_name(bind::SERVER_GROUP)
        .await?
        .map(|u| (u.uid, u.gid)))
}

async fn own(ctx: &Ctx, path: &std::path::Path, owner: Owner) -> Result<()> {
    if ctx.config.dry_run {
        return Ok(());
    }
    if let Some((uid, gid)) = server_ids(ctx).await? {
        match owner {
            Owner::RootServer => fsutil::set_owner(path, 0, gid)?,
            Owner::Server => fsutil::set_owner(path, uid, gid)?,
        }
    }
    Ok(())
}

/// Create OxPanel's DNS directories with their owners and modes, and the
/// rndc and transfer keys if they do not exist (or are unusable). On
/// SELinux hosts newly created directories get their policy labels.
pub(super) async fn ensure_layout(ctx: &Ctx) -> Result<()> {
    let l = Layout::new(&ctx.config.dns);
    let mut created = false;
    for (dir, mode, owner) in [
        (l.conf_dir.clone(), 0o750, Some(Owner::RootServer)),
        (l.data_dir.clone(), 0o750, Some(Owner::RootServer)),
        (l.zones_dir(), 0o770, Some(Owner::RootServer)),
        (l.keys_dir(), 0o750, Some(Owner::RootServer)),
        (l.work_dir(), 0o700, Some(Owner::Server)),
        (l.staging_dir(), 0o700, None),
    ] {
        created |= !dir.exists();
        fsutil::ensure_dir(&dir, mode)?;
        if let Some(o) = owner {
            own(ctx, &dir, o).await?;
        }
    }
    for (path, name) in [
        (l.rndc_key(), bind::RNDC_KEY),
        (l.transfer_key(), bind::TRANSFER_KEY),
    ] {
        let valid = fsutil::read_optional(&path)?
            .is_some_and(|b| bind::key_file_is_valid(&String::from_utf8_lossy(&b), name));
        if !valid {
            fsutil::write_atomic(
                &path,
                bind::render_key(name, &bind::new_secret()?).as_bytes(),
                bind::CONF_MODE,
            )?;
            info!(key = name, path = %path.display(), "DNS key generated");
        }
        own(ctx, &path, Owner::RootServer).await?;
    }
    if created && ctx.selinux {
        ctx.sys
            .run_ok(
                CommandSpec::new(bin::RESTORECON, ctx.config.command_timeout)
                    .arg("-R")
                    .arg(&l.conf_dir)
                    .arg(&l.data_dir),
            )
            .await?;
    }
    Ok(())
}

/// The key directory of a zone that is (to be) signed: the server's own.
pub(super) async fn ensure_key_dir(ctx: &Ctx, zone: &Domain) -> Result<()> {
    let dir = Layout::new(&ctx.config.dns).key_dir(zone);
    fsutil::ensure_dir(&dir, 0o700)?;
    own(ctx, &dir, Owner::Server).await
}

/// Names of `zone` that the tenant's sites serve (and that the engine gives
/// address records): every server name of the tenant's sites with DNS
/// hosting on inside the zone, except names at or below a name the tenant
/// delegated with NS records.
pub(super) fn site_names(
    rec: &ZoneRecord,
    rrs: &[super::rr::Rr],
    vhosts: &[VHostRecord],
) -> Result<Vec<SiteName>> {
    let zone = rec.domain()?;
    let delegations: Vec<&super::rr::RelName> = rrs
        .iter()
        .filter(|r| r.data.rtype() == super::rr::RrType::Ns)
        .map(|r| &r.name)
        .collect();
    let mut out: Vec<SiteName> = Vec::new();
    for v in vhosts
        .iter()
        .filter(|v| v.tenant == rec.tenant && v.dns.is_on())
    {
        for n in v.all_names() {
            let Some(rel) = super::rr::RelName::relative_to(n, &zone) else {
                continue;
            };
            if delegations.iter().any(|d| rel.is_at_or_below(d)) {
                continue;
            }
            if !out.iter().any(|s| s.name == rel) {
                out.push(SiteName {
                    name: rel,
                    site: v.domain.clone(),
                });
            }
        }
    }
    Ok(out)
}

/// Bring a zone's file in line with its record, and the server with the
/// file. `previous` is restored if the server's checker rejects the result
/// (`None`: the record is removed). A new serial is issued when the content
/// changed, or when it must exceed `floor` (a serial the server already
/// served). Returns the record as saved.
pub(super) async fn apply_zone(
    ctx: &Ctx,
    previous: Option<&ZoneRecord>,
    rec: ZoneRecord,
    floor: Option<u32>,
) -> Result<ZoneRecord> {
    write_zone(ctx, previous, rec, floor, true).await
}

/// [`apply_zone`] with a serial above `floor`, without telling the server:
/// for a change the server must load together with a new configuration
/// (DNSSEC switched on or off).
pub(super) async fn apply_zone_unloaded(
    ctx: &Ctx,
    previous: &ZoneRecord,
    rec: ZoneRecord,
    floor: u32,
) -> Result<ZoneRecord> {
    write_zone(ctx, Some(previous), rec, Some(floor), false).await
}

async fn write_zone(
    ctx: &Ctx,
    previous: Option<&ZoneRecord>,
    mut rec: ZoneRecord,
    floor: Option<u32>,
    reload: bool,
) -> Result<ZoneRecord> {
    let store = ZoneStore::new(&ctx.config);
    let l = Layout::new(&ctx.config.dns);
    let zone = rec.domain()?;
    let rrs: Vec<super::rr::Rr> = rec.rrs()?.into_iter().map(|(_, r)| r).collect();
    let vhosts = ctx.store.list_vhosts()?;
    let sites = site_names(&rec, &rrs, &vhosts)?;
    let input = ZoneInput {
        zone: &zone,
        cfg: &ctx.config.dns,
        sites: &sites,
        records: &rrs,
    };
    let hash = zone::content_hash(&input);
    if hash != rec.content_sha256 || rec.serial == 0 || floor.is_some() {
        let base = match floor {
            Some(f) if zone::serial_gt(f, rec.serial) => f,
            _ => rec.serial,
        };
        rec.serial = zone::next_serial(base, now_unix());
        rec.content_sha256 = hash;
    }
    // The record first: an interrupted request finds it and finishes.
    store.save(&rec)?;
    let text = zone::render(&input, rec.serial);
    let live = l.zone_file(&zone);
    if fsutil::read_optional(&live)?.as_deref() != Some(text.as_bytes()) {
        let staged = l.staging_file(zone.as_str());
        fsutil::ensure_dir(&l.staging_dir(), 0o700)?;
        fsutil::write_atomic(&staged, text.as_bytes(), bind::ZONE_MODE)?;
        let out = ctx
            .sys
            .run(bind::checkzone(
                zone.as_str(),
                &staged,
                ctx.config.command_timeout,
            ))
            .await;
        fsutil::remove_if_exists(&staged)?;
        let out = out?;
        if !out.success() {
            let why = out.combined_lossy();
            warn!(%zone, output = %why, "the DNS server's checker rejected the zone; nothing was changed");
            match previous {
                Some(p) => store.save(p)?,
                None => {
                    store.delete(&zone)?;
                }
            }
            return Err(Error::DnsZoneRejected(why));
        }
        fsutil::write_atomic(&live, text.as_bytes(), bind::ZONE_MODE)?;
    }
    if reload && rec.state == ZoneState::Ready && rec.loaded_serial != rec.serial {
        reload_zone(ctx, zone.as_str()).await?;
        rec.loaded_serial = rec.serial;
        store.save(&rec)?;
        info!(%zone, serial = rec.serial, "zone reloaded");
    }
    Ok(rec)
}

/// Run rndc with `args`; if the server is not running, start it instead
/// (it then loads everything from its files).
async fn rndc(ctx: &Ctx, args: &[&str]) -> Result<()> {
    let out_path = bind::scratch_file(&ctx.config, "rndc")?;
    let result = ctx.sys.run(bind::rndc(&ctx.config, &out_path, args)?).await;
    let text = fsutil::read_optional(&out_path);
    fsutil::remove_if_exists(&out_path)?;
    let result = result?;
    if result.success() {
        return Ok(());
    }
    let said = String::from_utf8_lossy(&text?.unwrap_or_default())
        .trim()
        .to_owned();
    if !server_active(ctx).await? {
        warn!(output = %said, "the DNS server is not running; starting it");
        return start_server(ctx).await;
    }
    Err(Error::Internal(format!(
        "rndc {} failed: {said}",
        args.join(" ")
    )))
}

pub(super) async fn reload_zone(ctx: &Ctx, zone: &str) -> Result<()> {
    rndc(ctx, &["reload", zone]).await
}

pub(super) async fn server_active(ctx: &Ctx) -> Result<bool> {
    unit_active(ctx, bind::SERVICE).await
}

pub(super) async fn unit_active(ctx: &Ctx, unit: &str) -> Result<bool> {
    Ok(ctx
        .sys
        .run(
            CommandSpec::new(bin::SYSTEMCTL, ctx.config.command_timeout).args([
                "is-active",
                "--quiet",
                unit,
            ]),
        )
        .await?
        .success())
}

async fn start_server(ctx: &Ctx) -> Result<()> {
    ctx.sys
        .run_ok(
            CommandSpec::new(bin::SYSTEMCTL, ctx.config.command_timeout).args([
                "enable",
                "--now",
                bind::SERVICE,
            ]),
        )
        .await?;
    info!("DNS server started");
    Ok(())
}

/// The server's configuration and the catalog, from the zone records: write
/// what changed, validate with `named-checkconf` (restore the previous files
/// if rejected), then make the server pick it up — `reconfig` loads new
/// zones and drops removed ones without touching the others.
pub(super) async fn apply_server(ctx: &Ctx) -> Result<()> {
    let cfg = &ctx.config.dns;
    let l = Layout::new(cfg);
    let store = ZoneStore::new(&ctx.config);
    ensure_layout(ctx).await?;
    let mut zones: Vec<(Domain, bool)> = Vec::new();
    for z in store.list()? {
        let d = z.domain()?;
        if z.state != ZoneState::Deleting && l.zone_file(&d).exists() {
            zones.push((d, z.dnssec));
        }
    }
    let catalog_changed = apply_catalog(ctx, &store, &l, &zones).await?;
    let files = [
        (l.named_conf(), bind::render_named_conf(cfg, &l)?),
        (l.zones_conf(), bind::render_zones_conf(&zones, &l)?),
        (l.rndc_conf(), bind::render_rndc_conf(&l)?),
    ];
    let mut previous = Vec::new();
    let mut changed = false;
    for (path, text) in &files {
        previous.push((path.clone(), fsutil::read_optional(path)?));
        changed |= fsutil::write_atomic(path, text.as_bytes(), bind::CONF_MODE)?;
        own(ctx, path, Owner::RootServer).await?;
    }
    if changed {
        let out = ctx
            .sys
            .run(bind::checkconf(&l, ctx.config.command_timeout))
            .await?;
        if !out.success() {
            let why = out.combined_lossy();
            warn!(output = %why, "the DNS server's checker rejected the configuration; restoring the previous one");
            for (path, bytes) in previous {
                match bytes {
                    Some(b) => {
                        fsutil::write_atomic(&path, &b, bind::CONF_MODE)?;
                    }
                    None => {
                        fsutil::remove_if_exists(&path)?;
                    }
                }
            }
            return Err(Error::DnsZoneRejected(why));
        }
    }
    if !server_active(ctx).await? {
        return start_server(ctx).await;
    }
    if changed {
        ctx.sys
            .run_ok(
                CommandSpec::new(bin::SYSTEMCTL, ctx.config.command_timeout)
                    .args(["reload", bind::SERVICE]),
            )
            .await?;
        info!(zones = zones.len(), "DNS server configuration reloaded");
    }
    if catalog_changed {
        rndc(ctx, &["reload", zone::CATALOG_ZONE]).await?;
    }
    Ok(())
}

/// Render the catalog of `zones`; returns whether its file changed.
async fn apply_catalog(
    ctx: &Ctx,
    store: &ZoneStore,
    l: &Layout,
    zones: &[(Domain, bool)],
) -> Result<bool> {
    let members: Vec<Domain> = zones.iter().map(|(d, _)| d.clone()).collect();
    let mut cat: CatalogRecord = store.load_catalog()?;
    let hash = zone::sha256_hex(zone::render_catalog(&members, 0).as_bytes());
    if hash != cat.content_sha256 || cat.serial == 0 {
        cat.serial = zone::next_serial(cat.serial, now_unix());
        cat.content_sha256 = hash;
        store.save_catalog(&cat)?;
    }
    let text = zone::render_catalog(&members, cat.serial);
    if fsutil::read_optional(&l.catalog_file())?.as_deref() == Some(text.as_bytes()) {
        return Ok(false);
    }
    let staged = l.staging_file(zone::CATALOG_ZONE);
    fsutil::write_atomic(&staged, text.as_bytes(), bind::ZONE_MODE)?;
    let out = ctx
        .sys
        .run(bind::checkzone(
            zone::CATALOG_ZONE,
            &staged,
            ctx.config.command_timeout,
        ))
        .await;
    fsutil::remove_if_exists(&staged)?;
    let out = out?;
    if !out.success() {
        return Err(Error::Internal(format!(
            "the DNS server's checker rejected the catalog zone: {}",
            out.combined_lossy()
        )));
    }
    fsutil::write_atomic(&l.catalog_file(), text.as_bytes(), bind::ZONE_MODE)?;
    Ok(true)
}

/// Remove a zone's files: the zone file, what the server keeps next to it
/// (signed copy, journals) and its signing keys. After the server dropped it.
pub(super) fn remove_zone_files(ctx: &Ctx, zone: &Domain) -> Result<()> {
    let l = Layout::new(&ctx.config.dns);
    fsutil::remove_if_exists(&l.zone_file(zone))?;
    remove_signing_state(ctx, zone)
}

/// The signed copy, journals and keys of a zone that is no longer signed.
pub(super) fn remove_signing_state(ctx: &Ctx, zone: &Domain) -> Result<()> {
    let l = Layout::new(&ctx.config.dns);
    for p in l.server_artefacts(zone) {
        fsutil::remove_if_exists(&p)?;
    }
    fsutil::remove_dir_tree(&l.key_dir(zone))?;
    Ok(())
}
