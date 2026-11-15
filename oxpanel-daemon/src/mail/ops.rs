//! Turning the records into running mail servers: the files, their owners,
//! and telling each server about a change.
//!
//! [`apply`] renders every file from the records, writes only what changed
//! (atomically) and reloads exactly the servers whose files changed. A
//! marker written before the files and removed after the reloads makes an
//! interrupted apply reload everything the next time, so no server keeps
//! running on files it never loaded.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use tracing::info;

use super::config::MailConfig;
use super::render::{self, Account, Model, HEADER};
use super::store::{MailDomainRecord, MailStore, RecordState};
use super::webmail;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::records::{TenantRecord, TenantState};
use crate::system::{bin, CommandSpec};
use crate::validate::Domain;

/// System accounts and groups of the mail component.
pub const POLICY_USER: &str = "oxpanel-mail";
pub const WEBMAIL_USER: &str = "oxpanel-webmail";
pub const RSPAMD_USER: &str = "_rspamd";
pub const DOVECOT_GROUP: &str = "dovecot";
pub const POSTFIX_GROUP: &str = "postfix";

pub const POSTFIX_SERVICE: &str = "postfix.service";
pub const DOVECOT_SERVICE: &str = "dovecot.service";
pub const RSPAMD_SERVICE: &str = "rspamd.service";
pub const POLICY_SERVICE: &str = "oxpanel-mail-policy.service";
pub const CLAMD_SERVICE: &str = "clamd@scan.service";

/// How long a retired DKIM key stays published.
pub const DKIM_RETIRE_SECS: u64 = 7 * 86_400;

fn systemctl(ctx: &Ctx) -> CommandSpec {
    CommandSpec::new(bin::SYSTEMCTL, ctx.config.command_timeout)
}

/// gid of a group, `None` without one (the fake OS) or in a dry run.
async fn gid(ctx: &Ctx, name: &str) -> Result<Option<u32>> {
    if ctx.config.dry_run {
        return Ok(None);
    }
    ctx.sys.group_by_name(name).await
}

/// Give `path` to `root:<group>` where that group exists.
async fn own_group(ctx: &Ctx, path: &Path, group: &str) -> Result<()> {
    if let Some(g) = gid(ctx, group).await? {
        fsutil::set_owner(path, 0, g)?;
    }
    Ok(())
}

async fn own_gid(ctx: &Ctx, path: &Path, g: u32) -> Result<()> {
    if !ctx.config.dry_run {
        fsutil::set_owner(path, 0, g)?;
    }
    Ok(())
}

/// The certificate of the mail host name: the real one when it is in
/// place, otherwise the self-signed one made at first start.
pub fn certificate(ctx: &Ctx, host: &Domain) -> (PathBuf, PathBuf, bool) {
    let real = (
        crate::tls::cert_path(&ctx.config.mail.selfsigned_dir, host),
        crate::tls::key_path(&ctx.config.mail.selfsigned_dir, host),
    );
    if real.0.exists() && real.1.exists() {
        return (real.0, real.1, true);
    }
    let dir = &ctx.config.mail.selfsigned_dir;
    (
        dir.join("selfsigned.crt"),
        dir.join("selfsigned.key"),
        false,
    )
}

/// Make the self-signed certificate (RSA 2048, ten years) if there is none:
/// Postfix and Dovecot need one to start, and clients must never be offered
/// plain text while the real one is obtained.
pub async fn ensure_selfsigned(ctx: &Ctx, host: &Domain) -> Result<()> {
    let dir = &ctx.config.mail.selfsigned_dir;
    let (crt, key) = (dir.join("selfsigned.crt"), dir.join("selfsigned.key"));
    if crt.exists() && key.exists() {
        return Ok(());
    }
    fsutil::ensure_dir(dir, 0o700)?;
    ctx.sys
        .run_ok(
            CommandSpec::new(bin::OPENSSL, ctx.config.command_timeout)
                .args([
                    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                ])
                .arg("-keyout")
                .arg(&key)
                .arg("-out")
                .arg(&crt)
                .arg("-subj")
                .arg(format!("/CN={host}")),
        )
        .await?;
    // The key was written with the daemon's umask (0077); the certificate is public.
    if !ctx.config.dry_run {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&crt, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| Error::io("chmod", &crt, e))?;
    }
    info!(%host, "self-signed mail certificate made (used until the real one is in place)");
    Ok(())
}

/// The sender domains of an account: its sites' names and its mail domains.
fn sender_domains(
    tenant: &str,
    vhosts: &[crate::records::VHostRecord],
    domains: &[MailDomainRecord],
) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = vhosts
        .iter()
        .filter(|v| v.tenant == tenant)
        .flat_map(|v| v.all_names().map(str::to_owned).collect::<Vec<_>>())
        .collect();
    out.extend(
        domains
            .iter()
            .filter(|d| d.tenant == tenant)
            .map(|d| d.domain.clone()),
    );
    out
}

/// Effective limits of an account: its own, or the host's.
pub fn limits_of(cfg: &MailConfig, rec: &super::store::MailLimitsRecord) -> super::Limits {
    super::Limits {
        max_mailboxes: rec.max_mailboxes.unwrap_or(cfg.max_mailboxes),
        max_mailbox_bytes: rec.max_mailbox_bytes.unwrap_or(cfg.max_mailbox_bytes),
        rate_account: rec.rate_account.unwrap_or(cfg.rate_account),
        rate_mailbox: rec.rate_mailbox.unwrap_or(cfg.rate_mailbox),
    }
}

/// Gather the model the files are rendered from.
pub async fn model(ctx: &Ctx, host: &Domain) -> Result<Model> {
    let mut m = records_model(ctx, host)?;
    m.last_login = gid(ctx, render::LAST_LOGIN_GROUP).await?.is_some();
    Ok(m)
}

/// The model from the records alone (no look at the host's groups).
pub fn records_model(ctx: &Ctx, host: &Domain) -> Result<Model> {
    let cfg = &ctx.config;
    let store = MailStore::new(cfg);
    let tenants: Vec<TenantRecord> = ctx
        .store
        .list_tenants()?
        .into_iter()
        .filter(|t| t.state != TenantState::Deleting)
        .collect();
    let all = store.list()?;
    let domains: Vec<MailDomainRecord> = all
        .iter()
        .filter(|d| render::live(d) && tenants.iter().any(|t| t.username == d.tenant))
        .cloned()
        .collect();
    let vhosts = ctx.store.list_vhosts()?;
    let mut accounts = BTreeMap::new();
    for t in &tenants {
        let name = crate::validate::Username::parse(&t.username)?;
        let limits = limits_of(&cfg.mail, &store.load_limits(&name)?);
        accounts.insert(
            t.username.clone(),
            Account {
                name: t.username.clone(),
                uid: t.uid,
                gid: t.gid,
                home: t.home.clone(),
                suspended: t.suspended,
                rate_account: limits.rate_account,
                rate_mailbox: limits.rate_mailbox,
                sender_domains: sender_domains(&t.username, &vhosts, &domains),
            },
        );
    }
    let (cert, key, _) = certificate(ctx, host);
    Ok(Model {
        hostname: host.clone(),
        accounts,
        domains,
        cert,
        key,
        uid_min: cfg.uid_min,
        uid_max: cfg.uid_max,
        last_login: false,
    })
}

/// One file the mail component writes.
struct File {
    path: PathBuf,
    contents: String,
    mode: u32,
    /// Group that must read it (`root:<group>`); `None`: root's.
    group: Option<Group>,
}

#[derive(Debug, Clone, Copy)]
enum Group {
    Named(&'static str),
    Gid(u32),
}

/// What changed, by server.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Changed {
    pub postfix: bool,
    pub dovecot: bool,
    pub dovecot_auth: bool,
    pub rspamd: bool,
    pub policy: bool,
    pub nginx: bool,
    pub webmail: bool,
}

impl Changed {
    fn all() -> Self {
        Self {
            postfix: true,
            dovecot: true,
            dovecot_auth: true,
            rspamd: true,
            policy: true,
            nginx: true,
            webmail: true,
        }
    }
}

fn file(path: PathBuf, contents: String, mode: u32, group: Option<Group>) -> File {
    File {
        path,
        contents,
        mode,
        group,
    }
}

fn postfix_files(cfg: &MailConfig, m: &Model) -> Result<Vec<File>> {
    let dir = cfg.postfix_dir.join("oxpanel");
    let mut out = vec![
        file(
            cfg.postfix_dir.join("main.cf"),
            render::postfix_main(cfg, m)?,
            0o644,
            None,
        ),
        file(
            cfg.postfix_dir.join("master.cf"),
            render::postfix_master(cfg)?,
            0o644,
            None,
        ),
    ];
    for (name, text) in render::postfix_maps(m) {
        out.push(file(
            dir.join(name),
            text,
            0o640,
            Some(Group::Named(POSTFIX_GROUP)),
        ));
    }
    Ok(out)
}

fn dovecot_files(cfg: &MailConfig, m: &Model) -> Result<(File, Vec<File>)> {
    let conf = file(
        cfg.dovecot_dir.join("dovecot.conf"),
        render::dovecot_conf(cfg, m)?,
        0o644,
        None,
    );
    let dir = cfg.dovecot_dir.join("oxpanel");
    let auth = render::dovecot_files(m)?
        .into_iter()
        .map(|(name, text)| {
            file(
                dir.join(name),
                text,
                0o640,
                Some(Group::Named(DOVECOT_GROUP)),
            )
        })
        .collect();
    Ok((conf, auth))
}

/// Keep the distribution's file once, before OxPanel's replaces it.
fn keep_original(path: &Path) -> Result<()> {
    let orig = PathBuf::from(format!("{}.oxpanel-orig", path.display()));
    if orig.exists() {
        return Ok(());
    }
    if let Some(bytes) = fsutil::read_optional(path)? {
        if !bytes.starts_with(HEADER.as_bytes()) {
            fsutil::write_atomic(&orig, &bytes, 0o644)?;
        }
    }
    Ok(())
}

/// Write `f`; whether its contents or owner changed.
async fn write(ctx: &Ctx, f: &File) -> Result<bool> {
    let changed = fsutil::write_atomic(&f.path, f.contents.as_bytes(), f.mode)?;
    match f.group {
        Some(Group::Named(g)) => own_group(ctx, &f.path, g).await?,
        Some(Group::Gid(g)) => own_gid(ctx, &f.path, g).await?,
        None => {}
    }
    Ok(changed)
}

async fn write_all(ctx: &Ctx, files: &[File]) -> Result<bool> {
    let mut changed = false;
    for f in files {
        changed |= write(ctx, f).await?;
    }
    Ok(changed)
}

fn marker(ctx: &Ctx) -> PathBuf {
    ctx.config.mail.state_dir.join("apply.pending")
}

/// The directories, with their owners and modes.
pub async fn ensure_layout(ctx: &Ctx) -> Result<()> {
    let cfg = &ctx.config.mail;
    let mut created = false;
    for (dir, mode, group) in [
        (cfg.state_dir.clone(), 0o755, None),
        (cfg.state_dir.join("dkim"), 0o750, Some(RSPAMD_USER)),
        (cfg.state_dir.join("sieve"), 0o755, None),
        (cfg.state_dir.join("usage"), 0o750, Some(POLICY_USER)),
        (cfg.postfix_dir.join("oxpanel"), 0o750, Some(POSTFIX_GROUP)),
        (cfg.dovecot_dir.join("oxpanel"), 0o750, Some(DOVECOT_GROUP)),
        (cfg.rspamd_dir.join("local.d"), 0o755, None),
        (cfg.webmail_dir.clone(), 0o755, None),
        (webmail::roundcube_conf_dir(cfg), 0o750, Some(WEBMAIL_USER)),
    ] {
        created |= !dir.exists();
        fsutil::ensure_dir(&dir, mode)?;
        if let Some(g) = group {
            own_group(ctx, &dir, g).await?;
        }
    }
    // The filter's milter socket: Rspamd creates it, only Postfix may reach it.
    fsutil::ensure_dir(&cfg.milter_dir, 0o750)?;
    if !ctx.config.dry_run {
        if let (Some(u), Some(g)) = (
            ctx.sys.user_by_name(RSPAMD_USER).await?,
            ctx.sys.group_by_name(POSTFIX_GROUP).await?,
        ) {
            fsutil::set_owner(&cfg.milter_dir, u.uid, g)?;
        }
    }
    // Dovecot's dict service (its own user) writes the last logins here.
    let ll = cfg.state_dir.join("lastlogin");
    created |= !ll.exists();
    fsutil::ensure_dir(&ll, 0o700)?;
    if !ctx.config.dry_run {
        if let (Some(u), Some(g)) = (
            ctx.sys.user_by_name(DOVECOT_GROUP).await?,
            ctx.sys.group_by_name(DOVECOT_GROUP).await?,
        ) {
            fsutil::set_owner(&ll, u.uid, g)?;
        }
    }
    // The policy service writes its counters here.
    if let (Some(g), false) = (gid(ctx, POLICY_USER).await?, ctx.config.dry_run) {
        if let Some(u) = ctx.sys.user_by_name(POLICY_USER).await? {
            fsutil::set_owner(&cfg.state_dir.join("usage"), u.uid, g)?;
        }
    }
    if created && ctx.selinux {
        ctx.sys
            .run_ok(
                CommandSpec::new(bin::RESTORECON, ctx.config.command_timeout)
                    .arg("-R")
                    .arg(&cfg.state_dir),
            )
            .await?;
    }
    Ok(())
}

/// The webmail is offered: switched on and Roundcube installed.
pub fn webmail_offered(ctx: &Ctx) -> bool {
    ctx.config.mail.webmail && ctx.config.mail.roundcube_index.exists()
}

/// Roundcube's key, made once.
fn des_key(ctx: &Ctx) -> Result<String> {
    let path = ctx.config.mail.state_dir.join("webmail.deskey");
    if let Some(bytes) = fsutil::read_optional(&path)? {
        let k = String::from_utf8_lossy(&bytes).trim().to_owned();
        if webmail::is_des_key(&k) {
            return Ok(k);
        }
    }
    let k = random_alnum(24)?;
    fsutil::write_atomic(&path, k.as_bytes(), 0o600)?;
    Ok(k)
}

/// `n` random letters and digits from the kernel.
pub fn random_alnum(n: usize) -> Result<String> {
    use std::io::Read as _;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(n);
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| Error::io("open", Path::new("/dev/urandom"), e))?;
    let mut buf = [0u8; 1];
    while out.len() < n {
        f.read_exact(&mut buf)
            .map_err(|e| Error::io("read", Path::new("/dev/urandom"), e))?;
        // 62 * 4 = 248: reject the rest, so every character is equally likely.
        if let Some(c) = (buf[0] < 248)
            .then(|| CHARS.get(usize::from(buf[0] % 62)))
            .flatten()
        {
            out.push(char::from(*c));
        }
    }
    Ok(out)
}

/// The webmail names that are served, and whether each has a certificate.
pub fn webmail_sites(ctx: &Ctx, m: &Model) -> Result<Vec<webmail::WebmailSite>> {
    if !webmail_offered(ctx) {
        return Ok(Vec::new());
    }
    let vhosts = ctx.store.list_vhosts()?;
    let mut out = Vec::new();
    for d in m.local() {
        let name = webmail::webmail_name(&d.domain);
        // A site of that name (anyone's) keeps it; the webmail is not offered there.
        if vhosts.iter().any(|v| v.all_names().any(|n| n == name)) {
            continue;
        }
        let Ok(dn) = Domain::parse(&name) else {
            continue;
        };
        let crt = crate::tls::cert_path(&ctx.config.mail.selfsigned_dir, &dn);
        let key = crate::tls::key_path(&ctx.config.mail.selfsigned_dir, &dn);
        let tls = (crt.exists() && key.exists()).then_some((crt, key));
        out.push(webmail::WebmailSite { name, tls });
    }
    Ok(out)
}

fn web_files(ctx: &Ctx, m: &Model) -> Result<(File, Vec<File>)> {
    let cfg = &ctx.config.mail;
    let vhosts = ctx.store.list_vhosts()?;
    let autoconfig: Vec<String> = m
        .local()
        .map(|d| format!("autoconfig.{}", d.domain))
        .filter(|n| !vhosts.iter().any(|v| v.all_names().any(|x| x == n)))
        .collect();
    let nginx = file(
        cfg.nginx_file.clone(),
        webmail::nginx_conf(
            cfg,
            &m.hostname,
            &autoconfig,
            &webmail_sites(ctx, m)?,
            &crate::acme::challenge_dir(&ctx.config),
        )?,
        0o644,
        None,
    );
    let mut fpm = Vec::new();
    if webmail_offered(ctx) {
        fpm.push(file(
            webmail::fpm_conf_path(cfg),
            webmail::fpm_conf(cfg, &ctx.config.web_user)?,
            0o644,
            None,
        ));
        fpm.push(file(
            webmail::roundcube_conf_path(cfg),
            webmail::roundcube_conf(cfg, &des_key(ctx)?)?,
            0o640,
            Some(Group::Named(WEBMAIL_USER)),
        ));
    }
    Ok((nginx, fpm))
}

/// Autoresponder scripts: one per mailbox with an autoresponder that is on,
/// in a directory per domain readable by the account's group only; scripts
/// no mailbox accounts for are removed.
async fn sieve_files(ctx: &Ctx, m: &Model) -> Result<bool> {
    let cfg = &ctx.config.mail;
    let root = cfg.state_dir.join("sieve");
    let mut wanted: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut changed = false;
    for d in m.local() {
        let Some(account) = m.accounts.get(&d.tenant) else {
            continue;
        };
        let dir = root.join(&d.domain);
        let mut scripts = BTreeSet::new();
        for (local, mb) in d.live_mailboxes() {
            let Some(r) = mb.autoreply.as_ref().filter(|r| r.enabled) else {
                continue;
            };
            fsutil::ensure_dir(&dir, 0o750)?;
            own_gid(ctx, &dir, account.gid).await?;
            let path = render::sieve_path(cfg, &d.domain, local);
            let text = render::sieve_script(&format!("{local}@{}", d.domain), r);
            let f = file(path.clone(), text, 0o640, Some(Group::Gid(account.gid)));
            if write(ctx, &f).await? {
                changed = true;
                compile_sieve(ctx, &path, account.gid).await?;
            }
            scripts.insert(format!("{local}.sieve"));
            scripts.insert(format!("{local}.svbin"));
        }
        wanted.insert(d.domain.clone(), scripts);
    }
    for dom in fsutil::list_dirs(&root)? {
        let keep = wanted.get(&dom);
        let dir = root.join(&dom);
        for name in fsutil::list_entry_names(&dir)? {
            if keep.is_none_or(|k| !k.contains(&name)) {
                fsutil::remove_if_exists(&dir.join(&name))?;
                changed = true;
            }
        }
        if keep.is_none_or(BTreeSet::is_empty) {
            fsutil::remove_empty_dir(&dir)?;
        }
    }
    Ok(changed)
}

/// Compile a script ahead (the account cannot write next to it), readable
/// by the account's group.
async fn compile_sieve(ctx: &Ctx, path: &Path, gid: u32) -> Result<()> {
    if !ctx.sys.is_installed(bin::SIEVEC).await {
        return Ok(());
    }
    ctx.sys
        .run_ok(CommandSpec::new(bin::SIEVEC, ctx.config.command_timeout).arg(path))
        .await?;
    let bin_path = path.with_extension("svbin");
    if bin_path.exists() && !ctx.config.dry_run {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o640))
            .map_err(|e| Error::io("chmod", &bin_path, e))?;
        fsutil::set_owner(&bin_path, 0, gid)?;
    }
    Ok(())
}

/// DKIM selector map and the keys' owner.
async fn dkim_files(ctx: &Ctx, m: &Model) -> Result<bool> {
    let cfg = &ctx.config.mail;
    let map = file(
        cfg.state_dir.join("dkim").join("selectors.map"),
        render::dkim_selectors(m),
        0o640,
        Some(Group::Named(RSPAMD_USER)),
    );
    write(ctx, &map).await
}

/// Render and write everything; reload what changed. The caller holds the
/// mutation lock. Nothing happens while email is off.
pub async fn apply(ctx: &Ctx) -> Result<Changed> {
    let cfg = &ctx.config.mail;
    let Some(host) = cfg.hostname.clone().filter(|_| cfg.enabled) else {
        return Ok(Changed::default());
    };
    ensure_layout(ctx).await?;
    ensure_selfsigned(ctx, &host).await?;
    let m = model(ctx, &host).await?;
    let pending = marker(ctx);
    let was_pending = pending.exists();
    fsutil::write_atomic(&pending, b"", 0o600)?;

    keep_original(&cfg.postfix_dir.join("main.cf"))?;
    keep_original(&cfg.postfix_dir.join("master.cf"))?;
    keep_original(&cfg.dovecot_dir.join("dovecot.conf"))?;

    let mut c = if was_pending {
        Changed::all()
    } else {
        Changed::default()
    };
    c.postfix |= write_all(ctx, &postfix_files(cfg, &m)?).await?;
    let (conf, auth) = dovecot_files(cfg, &m)?;
    c.dovecot |= write(ctx, &conf).await?;
    c.dovecot_auth |= write_all(ctx, &auth).await?;
    c.dovecot_auth |= sieve_files(ctx, &m).await?;
    let rspamd: Vec<File> = render::rspamd_files(cfg)?
        .into_iter()
        .map(|(name, text)| file(cfg.rspamd_dir.join(name), text, 0o644, None))
        .collect();
    c.rspamd |= write_all(ctx, &rspamd).await?;
    c.rspamd |= dkim_files(ctx, &m).await?;
    let policy = serde_json::to_vec_pretty(&render::policy_map(&m))
        .map_err(|e| Error::Internal(format!("policy map: {e}")))?;
    c.policy |= write(
        ctx,
        &file(
            cfg.state_dir.join("policy.json"),
            String::from_utf8_lossy(&policy).into_owned(),
            0o640,
            Some(Group::Named(POLICY_USER)),
        ),
    )
    .await?;
    let (nginx, fpm) = web_files(ctx, &m)?;
    let previous_nginx = fsutil::read_optional(&nginx.path)?;
    c.nginx |= write(ctx, &nginx).await?;
    c.webmail |= write_all(ctx, &fpm).await?;

    if c.nginx {
        if let Err(e) =
            crate::nginx::test_config(ctx.sys.as_ref(), ctx.config.command_timeout).await
        {
            // Never leave Nginx unable to load: put the previous file back.
            match previous_nginx {
                Some(p) => {
                    fsutil::write_atomic(&nginx.path, &p, 0o644)?;
                }
                None => {
                    fsutil::remove_if_exists(&nginx.path)?;
                }
            }
            return Err(e);
        }
    }
    reload(ctx, c).await?;
    fsutil::remove_if_exists(&pending)?;
    Ok(c)
}

/// Make each server pick up its changed files. `reload-or-restart` also
/// starts a server that is not running.
pub async fn reload(ctx: &Ctx, c: Changed) -> Result<()> {
    let mut units: Vec<&str> = Vec::new();
    if c.postfix {
        units.push(POSTFIX_SERVICE);
    }
    // Passwords, disabled mailboxes, suspension: Dovecot re-reads its
    // password files by itself, but only when it sees their time stamp
    // change (two changes within one second can go unnoticed — found with a
    // suspension right after a mailbox change) and it caches logins. A
    // reload re-reads everything and forgets the cache; open sessions stay
    // (those that must end are ended with `doveadm kick`).
    if c.dovecot || c.dovecot_auth {
        units.push(DOVECOT_SERVICE);
    }
    if c.rspamd {
        units.push(RSPAMD_SERVICE);
    }
    if c.policy {
        units.push(POLICY_SERVICE);
    }
    for unit in units {
        ctx.sys
            .run_ok(systemctl(ctx).args(["reload-or-restart", "--", unit]))
            .await?;
    }
    if c.nginx {
        crate::nginx::reload(ctx.sys.as_ref(), ctx.config.command_timeout).await?;
    }
    if c.webmail && webmail_offered(ctx) {
        ctx.sys
            .run_ok(systemctl(ctx).args(["enable", "--", webmail::SERVICE]))
            .await?;
        ctx.sys
            .run_ok(systemctl(ctx).args(["restart", "--", webmail::SERVICE]))
            .await?;
    }
    Ok(())
}

/// The servers the mail component runs, enabled and started.
pub fn services(ctx: &Ctx) -> Vec<&'static str> {
    let mut out = vec![
        POSTFIX_SERVICE,
        DOVECOT_SERVICE,
        RSPAMD_SERVICE,
        POLICY_SERVICE,
    ];
    if ctx.config.mail.antivirus {
        out.push(CLAMD_SERVICE);
    }
    if webmail_offered(ctx) {
        out.push(webmail::SERVICE);
    }
    out
}

pub async fn enable_services(ctx: &Ctx) -> Result<()> {
    for unit in services(ctx) {
        ctx.sys
            .run_ok(systemctl(ctx).args(["enable", "--now", "--", unit]))
            .await?;
    }
    Ok(())
}

pub async fn unit_active(ctx: &Ctx, unit: &str) -> Result<bool> {
    Ok(ctx
        .sys
        .run(systemctl(ctx).args(["is-active", "--quiet", "--", unit]))
        .await?
        .success())
}

// ---- Mailbox directories, as the account ------------------------------------

/// Create `~/mail/<domain>/<local>` as the account (mode 0700), so no root
/// process ever creates anything inside a directory the account controls.
pub async fn ensure_maildir(ctx: &Ctx, t: &TenantRecord, domain: &str, local: &str) -> Result<()> {
    let dir = render::maildir(&t.home, domain, local);
    ctx.sys
        .run_ok(
            CommandSpec::new(bin::MKDIR, ctx.config.command_timeout)
                .args(["-p", "-m", "0700", "--"])
                .arg(&dir)
                .as_user(t.uid, t.gid),
        )
        .await?;
    if ctx.selinux {
        // restorecon never follows a symlink, so a link planted by the
        // account relabels nothing outside.
        ctx.sys
            .run_ok(
                CommandSpec::new(bin::RESTORECON, ctx.config.command_timeout)
                    .arg("-R")
                    .arg(t.home.join("mail")),
            )
            .await?;
    }
    Ok(())
}

/// Remove `~/mail/<domain>/<local>` (or the whole domain with `local` =
/// `None`) as the account: `rm` does not follow symlinks and the account's
/// identity cannot reach anything that is not its own.
pub async fn remove_maildir(
    ctx: &Ctx,
    t: &TenantRecord,
    domain: &str,
    local: Option<&str>,
) -> Result<()> {
    let dir = match local {
        Some(l) => render::maildir(&t.home, domain, l),
        None => t.home.join("mail").join(domain),
    };
    ctx.sys
        .run_ok(
            CommandSpec::new(bin::RM, REMOVE_TIMEOUT)
                .args(["-rf", "--one-file-system", "--"])
                .arg(&dir)
                .as_user(t.uid, t.gid),
        )
        .await?;
    Ok(())
}

/// Removing a large mailbox can take a while.
const REMOVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3600);

// ---- DKIM keys ---------------------------------------------------------------

/// Make a new 2048-bit RSA key for `domain` with a fresh selector and
/// return its record. The private key goes from OpenSSL's output straight
/// into a file only root and the signer can read; it is never logged.
pub async fn new_dkim_key(ctx: &Ctx, domain: &str, now: u64) -> Result<super::store::DkimKey> {
    let cfg = &ctx.config.mail;
    let timeout = ctx.config.command_timeout;
    let selector = format!("ox{now}");
    let path = render::dkim_key_path(cfg, domain, &selector);
    fsutil::ensure_dir(&cfg.state_dir.join("dkim"), 0o750)?;
    let key = ctx
        .sys
        .run_ok(CommandSpec::new(bin::OPENSSL, timeout).args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
        ]))
        .await?;
    if !key.stdout.starts_with(b"-----BEGIN") {
        return Err(Error::Internal("openssl produced no key".into()));
    }
    fsutil::write_atomic(&path, &key.stdout, 0o640)?;
    own_group(ctx, &path, RSPAMD_USER).await?;
    let public = ctx
        .sys
        .run_ok(
            CommandSpec::new(bin::OPENSSL, timeout)
                .args(["pkey", "-in"])
                .arg(&path)
                .arg("-pubout"),
        )
        .await?;
    let public_key = pem_body(&public.stdout_lossy())
        .ok_or_else(|| Error::Internal("openssl printed no public key".into()))?;
    info!(%domain, %selector, "DKIM key made");
    Ok(super::store::DkimKey {
        selector,
        public_key,
        created_at_unix: now,
        retire_at_unix: None,
    })
}

/// The base64 body of the first PEM block in `text`.
pub fn pem_body(text: &str) -> Option<String> {
    let mut lines = text.lines().map(str::trim);
    lines.find(|l| l.starts_with("-----BEGIN"))?;
    let mut body = String::new();
    for l in lines {
        if l.starts_with("-----END") {
            let ok = !body.is_empty()
                && body
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
            return ok.then_some(body);
        }
        body.push_str(l);
    }
    None
}

/// Remove the key files of `domain` that its record no longer names.
pub fn prune_dkim_keys(ctx: &Ctx, rec: Option<&MailDomainRecord>, domain: &str) -> Result<()> {
    let dir = ctx.config.mail.state_dir.join("dkim");
    let keep: BTreeSet<String> = rec
        .map(|r| {
            r.dkim_keys()
                .map(|k| format!("{domain}.{}.key", k.selector))
                .collect()
        })
        .unwrap_or_default();
    let prefix = format!("{domain}.ox");
    for name in fsutil::list_entry_names(&dir)? {
        if name.starts_with(&prefix) && is_key_file(&name) && !keep.contains(&name) {
            fsutil::remove_if_exists(&dir.join(&name))?;
        }
    }
    Ok(())
}

/// `*.key`
pub fn is_key_file(name: &str) -> bool {
    std::path::Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("key"))
}

/// Mailboxes in the `deleting` state of a record.
pub fn deleting(rec: &MailDomainRecord) -> Vec<String> {
    rec.mailboxes
        .iter()
        .filter(|(_, m)| m.state == RecordState::Deleting)
        .map(|(l, _)| l.clone())
        .collect()
}

/// Every file the records render to, as `(path, contents)`, without
/// writing anything (Reconcile compares them). Roundcube's configuration is
/// left out while its key has not been made.
pub fn expected(ctx: &Ctx, m: &Model) -> Result<Vec<(PathBuf, String)>> {
    let cfg = &ctx.config.mail;
    let mut files: Vec<File> = postfix_files(cfg, m)?;
    let (conf, auth) = dovecot_files(cfg, m)?;
    files.push(conf);
    files.extend(auth);
    for (name, text) in render::rspamd_files(cfg)? {
        files.push(file(cfg.rspamd_dir.join(name), text, 0o644, None));
    }
    files.push(file(
        cfg.state_dir.join("dkim").join("selectors.map"),
        render::dkim_selectors(m),
        0o640,
        None,
    ));
    let policy = serde_json::to_vec_pretty(&render::policy_map(m))
        .map_err(|e| Error::Internal(format!("policy map: {e}")))?;
    files.push(file(
        cfg.state_dir.join("policy.json"),
        String::from_utf8_lossy(&policy).into_owned(),
        0o640,
        None,
    ));
    let vhosts = ctx.store.list_vhosts()?;
    let autoconfig: Vec<String> = m
        .local()
        .map(|d| format!("autoconfig.{}", d.domain))
        .filter(|n| !vhosts.iter().any(|v| v.all_names().any(|x| x == n)))
        .collect();
    files.push(file(
        cfg.nginx_file.clone(),
        webmail::nginx_conf(
            cfg,
            &m.hostname,
            &autoconfig,
            &webmail_sites(ctx, m)?,
            &crate::acme::challenge_dir(&ctx.config),
        )?,
        0o644,
        None,
    ));
    if webmail_offered(ctx) {
        files.push(file(
            webmail::fpm_conf_path(cfg),
            webmail::fpm_conf(cfg, &ctx.config.web_user)?,
            0o644,
            None,
        ));
        let key = fsutil::read_optional(&cfg.state_dir.join("webmail.deskey"))?
            .map(|b| String::from_utf8_lossy(&b).trim().to_owned())
            .filter(|k| webmail::is_des_key(k));
        if let Some(k) = key {
            files.push(file(
                webmail::roundcube_conf_path(cfg),
                webmail::roundcube_conf(cfg, &k)?,
                0o640,
                None,
            ));
        }
    }
    for d in m.local() {
        for (local, mb) in d.live_mailboxes() {
            if let Some(r) = mb.autoreply.as_ref().filter(|r| r.enabled) {
                files.push(file(
                    render::sieve_path(cfg, &d.domain, local),
                    render::sieve_script(&format!("{local}@{}", d.domain), r),
                    0o640,
                    None,
                ));
            }
        }
    }
    Ok(files.into_iter().map(|f| (f.path, f.contents)).collect())
}
