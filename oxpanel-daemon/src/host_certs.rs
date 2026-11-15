//! Host certificates: certificates for host names that belong to no site,
//! obtained and renewed for *consumers* that register a name (the panel's
//! own host name is the first). The engine knows nothing else about them.
//!
//! - **Registration.** A root-owned file
//!   `<registry_dir>/<consumer>.conf` (`/etc/oxpanel/host-certificates.d`),
//!   consumer `[a-z][a-z0-9-]{0,30}`, not writable by group or others, no
//!   symlink, at most 4 KiB. Lines: `name=<host name>` and
//!   `challenges=engine|consumer` (both required), `redirect_port=<1024-65535>`
//!   (only with `engine`), `#` comments. Anything else makes the
//!   registration INVALID and nothing is done for it.
//! - **Challenges.** `engine`: the engine answers HTTP-01 for the name on
//!   port 80 itself, in `nginx_file` (one server per name that no
//!   engine-rendered server answers already); other paths answer 404, or a
//!   redirect to `https://$host:<redirect_port>`. `consumer`: the consumer's
//!   own port-80 server serves the challenge directory.
//! - **Certificates.** Through the machinery of the mail host name
//!   ([`crate::named_cert`]): pre-check first (a name that does not resolve
//!   here never reaches the authority), back-off, renewal 30 days ahead; from
//!   the periodic task and from `RunAutoHttps` without a domain; nothing
//!   while Automatic HTTPS is off or ACME is unavailable (DISABLED).
//! - **Output.** `<cert_dir>/<consumer>.crt` (chain, 0644) and `.key` (0600),
//!   root-owned, written atomically once verified; then `nginx -t` (the
//!   previous pair is put back if it refuses) and a reload. No placeholder is
//!   ever written: until a real certificate exists the files do not exist.
//!   When a registration is removed, the engine removes the pair it wrote.
//! - **State.** `<state_dir>/host-certificates.json` (root-only): per
//!   consumer the name, the back-off and what was installed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::Config;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::host::{Drift, DriftKind};
use crate::named_cert::{self, Backoff, Material};
use crate::nginx;
use crate::records::now_unix;
use crate::validate::{Domain, HostCertConsumer};

/// Where registrations, certificates and the challenge file live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCertConfig {
    /// One `<consumer>.conf` per registration.
    pub registry_dir: PathBuf,
    /// `<consumer>.crt` and `<consumer>.key`.
    pub cert_dir: PathBuf,
    /// The challenge-only Nginx servers.
    pub nginx_file: PathBuf,
}

impl Default for HostCertConfig {
    fn default() -> Self {
        Self {
            registry_dir: PathBuf::from("/etc/oxpanel/host-certificates.d"),
            cert_dir: PathBuf::from("/etc/pki/oxpanel-host"),
            nginx_file: PathBuf::from("/etc/nginx/conf.d/oxpanel-host-certificates.conf"),
        }
    }
}

const MAX_REGISTRATION_BYTES: u64 = 4096;
const CERT_DIR_MODE: u32 = 0o755;
const STATE_MODE: u32 = 0o600;
/// Shown and kept per invalid registration.
const MAX_REASON_CHARS: usize = 200;

/// Who answers the HTTP-01 challenge for the name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Challenges {
    Engine,
    Consumer,
}

/// A valid registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub consumer: HostCertConsumer,
    pub name: Domain,
    pub challenges: Challenges,
    pub redirect_port: Option<u16>,
}

/// A registration file, valid or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Valid(Registration),
    /// `consumer` as found (made printable), and why it is not valid.
    Invalid {
        consumer: String,
        reason: String,
    },
}

/// `<cert_dir>/<consumer>.crt`
pub fn cert_path(cfg: &HostCertConfig, consumer: &HostCertConsumer) -> PathBuf {
    cfg.cert_dir.join(format!("{consumer}.crt"))
}

/// `<cert_dir>/<consumer>.key`
pub fn key_path(cfg: &HostCertConfig, consumer: &HostCertConsumer) -> PathBuf {
    cfg.cert_dir.join(format!("{consumer}.key"))
}

fn registration_path(cfg: &HostCertConfig, consumer: &HostCertConsumer) -> PathBuf {
    cfg.registry_dir.join(format!("{consumer}.conf"))
}

fn printable(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_REASON_CHARS)
        .collect()
}

/// The contents of a registration file: name, challenges, redirect port.
pub fn parse_registration(
    text: &str,
) -> std::result::Result<(Domain, Challenges, Option<u16>), String> {
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {}: expected key=value", n + 1));
        };
        let key = key.trim();
        if !matches!(key, "name" | "challenges" | "redirect_port") {
            return Err(format!(
                "line {}: unknown setting '{}'",
                n + 1,
                printable(key)
            ));
        }
        if seen.insert(key, value.trim()).is_some() {
            return Err(format!("{key} is given twice"));
        }
    }
    let name = seen.get("name").ok_or("name= is missing")?;
    let name = Domain::parse_field(name, "name").map_err(|e| e.to_string())?;
    let challenges = match seen.get("challenges").copied() {
        Some("engine") => Challenges::Engine,
        Some("consumer") => Challenges::Consumer,
        Some(_) => return Err("challenges= must be engine or consumer".into()),
        None => return Err("challenges= is missing".into()),
    };
    let redirect_port = match seen.get("redirect_port") {
        None => None,
        Some(_) if challenges == Challenges::Consumer => {
            return Err("redirect_port= is only allowed with challenges=engine".into())
        }
        Some(p) => Some(
            p.parse::<u16>()
                .ok()
                .filter(|p| *p >= 1024)
                .ok_or("redirect_port= must be a port number from 1024 to 65535")?,
        ),
    };
    Ok((name, challenges, redirect_port))
}

/// Read a registration file: a regular file (never a symlink), owned by
/// the daemon's own account (root), not writable by group or others.
fn read_registration(path: &Path) -> std::result::Result<String, String> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)
        .map_err(|_| "the file cannot be opened (a symlink is not accepted)".to_owned())?;
    let md = file
        .metadata()
        .map_err(|_| "the file cannot be examined".to_owned())?;
    if !md.is_file() {
        return Err("not a regular file".into());
    }
    if md.uid() != nix::unistd::geteuid().as_raw() || md.mode() & 0o022 != 0 {
        return Err("must be owned by root and writable by root only".into());
    }
    if md.len() > MAX_REGISTRATION_BYTES {
        return Err(format!("larger than {MAX_REGISTRATION_BYTES} bytes"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_REGISTRATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "the file cannot be read".to_owned())?;
    String::from_utf8(bytes).map_err(|_| "not text (UTF-8)".to_owned())
}

/// Every registration, by consumer. Files not ending in `.conf` are not
/// registrations (an editor's backup, a package manager's `.rpmsave`).
pub fn registrations(cfg: &HostCertConfig) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    for file in fsutil::list_entry_names(&cfg.registry_dir)? {
        let Some(stem) = file.strip_suffix(".conf") else {
            continue;
        };
        let consumer = match HostCertConsumer::parse(stem) {
            Ok(c) => c,
            Err(e) => {
                out.push(Entry::Invalid {
                    consumer: printable(stem),
                    reason: e.to_string(),
                });
                continue;
            }
        };
        let parsed = read_registration(&registration_path(cfg, &consumer))
            .and_then(|text| parse_registration(&text));
        out.push(match parsed {
            Ok((name, challenges, redirect_port)) => Entry::Valid(Registration {
                consumer,
                name,
                challenges,
                redirect_port,
            }),
            Err(reason) => Entry::Invalid {
                consumer: consumer.to_string(),
                reason: printable(&reason),
            },
        });
    }
    Ok(out)
}

fn valid(entries: Vec<Entry>) -> Vec<Registration> {
    entries
        .into_iter()
        .filter_map(|e| match e {
            Entry::Valid(r) => Some(r),
            Entry::Invalid { .. } => None,
        })
        .collect()
}

// ---- State -------------------------------------------------------------------

/// What was installed for a consumer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issued {
    pub issuer: String,
    pub not_after_unix: u64,
    pub names: Vec<String>,
}

/// What the engine remembers about one consumer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerState {
    /// The name the back-off and the certificate are for.
    pub name: String,
    #[serde(default)]
    pub backoff: Option<Backoff>,
    #[serde(default)]
    pub issued: Option<Issued>,
}

fn state_path(cfg: &Config) -> PathBuf {
    cfg.state_dir.join("host-certificates.json")
}

/// The state; a missing or unreadable file is a fresh start (it holds the
/// back-off and what is shown, both rebuilt by the next sweep).
pub fn load_state(cfg: &Config) -> BTreeMap<String, ConsumerState> {
    fsutil::read_optional(&state_path(cfg))
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_state(cfg: &Config, state: &BTreeMap<String, ConsumerState>) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|e| Error::Internal(format!("host certificate state: {e}")))?;
    fsutil::ensure_dir(&cfg.state_dir, 0o700)?;
    fsutil::write_atomic(&state_path(cfg), &bytes, STATE_MODE).map(|_| ())
}

// ---- Status --------------------------------------------------------------------

/// Where one registration stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Issued,
    Renewing,
    Pending,
    Disabled,
    Invalid,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Renewing => "renewing",
            Self::Pending => "pending",
            Self::Disabled => "disabled",
            Self::Invalid => "invalid",
        }
    }
}

/// One registration, for `HostInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub consumer: String,
    pub name: String,
    pub state: State,
    pub issuer: String,
    pub not_after_unix: Option<u64>,
    pub reason: String,
    pub next_attempt_unix: Option<u64>,
    pub certificate_path: String,
    pub key_path: String,
}

/// Why no host certificate can be obtained now, or `None`.
async fn disabled_reason(ctx: &Ctx) -> Result<Option<String>> {
    if !ctx.config.auto_https.is_on() {
        return Ok(Some(
            "Automatic HTTPS is off on this host (OXPANEL_AUTO_HTTPS=false)".into(),
        ));
    }
    Ok(crate::acme::unavailable_reason(ctx)
        .await?
        .map(|r| format!("certificates cannot be requested on this host: {r}")))
}

/// Every registration and where it stands. Read-only.
pub async fn status(ctx: &Ctx) -> Result<Vec<Status>> {
    let cfg = &ctx.config.host_certs;
    let entries = registrations(cfg)?;
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let disabled = disabled_reason(ctx).await?;
    let state = load_state(&ctx.config);
    let due = now_unix().saturating_add(ctx.config.acme_renew_before.as_secs());
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        let reg = match e {
            Entry::Valid(r) => r,
            Entry::Invalid { consumer, reason } => {
                out.push(Status {
                    consumer,
                    name: String::new(),
                    state: State::Invalid,
                    issuer: String::new(),
                    not_after_unix: None,
                    reason,
                    next_attempt_unix: None,
                    certificate_path: String::new(),
                    key_path: String::new(),
                });
                continue;
            }
        };
        let (crt, key) = (cert_path(cfg, &reg.consumer), key_path(cfg, &reg.consumer));
        let st = state
            .get(reg.consumer.as_str())
            .filter(|s| s.name == reg.name.as_str());
        let issued = st
            .and_then(|s| s.issued.as_ref())
            .filter(|_| crt.is_file() && key.is_file());
        let backoff = st.and_then(|s| s.backoff.as_ref());
        let covers = issued.is_some_and(|i| crate::tls::covers(&i.names, reg.name.as_str()));
        let (state, reason) = match (&disabled, issued) {
            (Some(why), _) => (State::Disabled, why.clone()),
            (None, Some(i)) if covers && i.not_after_unix > due => (State::Issued, String::new()),
            (None, Some(_)) if covers => (
                State::Renewing,
                backoff.map_or_else(|| "due for renewal".to_owned(), |b| b.reason.clone()),
            ),
            (None, _) => (
                State::Pending,
                backoff.map_or_else(
                    || "waiting for the first attempt".to_owned(),
                    |b| b.reason.clone(),
                ),
            ),
        };
        out.push(Status {
            consumer: reg.consumer.to_string(),
            name: reg.name.to_string(),
            state,
            issuer: issued.map(|i| i.issuer.clone()).unwrap_or_default(),
            not_after_unix: issued.map(|i| i.not_after_unix),
            reason,
            next_attempt_unix: backoff
                .filter(|b| b.waiting() && state != State::Issued)
                .map(|b| b.next_attempt_unix),
            certificate_path: crt.to_string_lossy().into_owned(),
            key_path: key.to_string_lossy().into_owned(),
        });
    }
    Ok(out)
}

// ---- The challenge-only Nginx servers ----------------------------------------------

/// Every name an engine-rendered server answers on port 80: the sites'
/// names and aliases, and email's names while email is on.
fn served_names(ctx: &Ctx) -> Result<BTreeSet<String>> {
    let mut out: BTreeSet<String> = ctx
        .store
        .list_vhosts()?
        .iter()
        .flat_map(|v| v.all_names().map(str::to_owned).collect::<Vec<_>>())
        .collect();
    out.extend(crate::mail::certs::port80_names(ctx)?);
    Ok(out)
}

/// The challenge file, or `None` when no registration needs one.
pub fn render_challenges(ctx: &Ctx) -> Result<Option<String>> {
    let served = served_names(ctx)?;
    let regs = valid(registrations(&ctx.config.host_certs)?);
    let challenges = crate::acme::challenge_dir(&ctx.config);
    let challenges = nginx::safe_path_str(&challenges)?;
    let mut done = BTreeSet::new();
    let mut out = String::new();
    for r in regs.iter().filter(|r| r.challenges == Challenges::Engine) {
        if served.contains(r.name.as_str()) || !done.insert(r.name.as_str()) {
            continue;
        }
        let rest = match r.redirect_port {
            Some(port) => format!("return 301 https://$host:{port}$request_uri;"),
            None => "return 404;".to_owned(),
        };
        let _ = write!(
            out,
            "
# Host certificate of '{consumer}': certificate challenges for {name}.
server {{
    listen 80;
    listen [::]:80;
    server_name {name};
    server_tokens off;
    location ^~ /.well-known/acme-challenge/ {{
        alias {challenges}/;
        default_type text/plain;
        disable_symlinks on;
    }}
    location / {{
        {rest}
    }}
}}
",
            consumer = r.consumer,
            name = r.name,
        );
    }
    if out.is_empty() {
        return Ok(None);
    }
    Ok(Some(format!(
        "# Managed by oxpanel-daemon (host certificates). Manual edits will be overwritten.\n{out}"
    )))
}

/// Bring the challenge file in line with the registrations (validated,
/// rolled back if Nginx refuses). The caller holds the mutation lock.
async fn apply_challenges(ctx: &Ctx) -> Result<bool> {
    let path = &ctx.config.host_certs.nginx_file;
    let timeout = ctx.config.command_timeout;
    match render_challenges(ctx)? {
        Some(text) => nginx::install_config(ctx.sys.as_ref(), path, &text, timeout).await,
        None => nginx::remove_config(ctx.sys.as_ref(), path, timeout).await,
    }
}

// ---- Installing ------------------------------------------------------------------------

/// Files as they were before a change: path, contents (`None`: absent), mode.
type Saved = Vec<(PathBuf, Option<Vec<u8>>, u32)>;

/// Put `files` back as they were.
fn restore(files: &Saved) -> Result<()> {
    for (path, previous, mode) in files {
        match previous {
            Some(bytes) => fsutil::write_atomic(path, bytes, *mode).map(|_| ())?,
            None => fsutil::remove_if_exists(path).map(|_| ())?,
        }
    }
    Ok(())
}

/// The consumer's key and chain, before a change.
fn previous_pair(cfg: &HostCertConfig, consumer: &HostCertConsumer) -> Result<Saved> {
    let (crt, key) = (cert_path(cfg, consumer), key_path(cfg, consumer));
    Ok(vec![
        (
            key.clone(),
            fsutil::read_optional(&key)?,
            crate::tls::KEY_MODE,
        ),
        (
            crt.clone(),
            fsutil::read_optional(&crt)?,
            crate::tls::CERT_MODE,
        ),
    ])
}

/// `nginx -t`, then a reload; if Nginx refuses, `previous` is restored.
async fn activate(ctx: &Ctx, previous: &Saved) -> Result<()> {
    let timeout = ctx.config.command_timeout;
    if let Err(output) = nginx::test_config(ctx.sys.as_ref(), timeout).await? {
        warn!(%output, "nginx refused the host certificate; putting the previous one back");
        restore(previous)?;
        return Err(Error::NginxInvalid(output));
    }
    nginx::reload(ctx.sys.as_ref(), timeout).await
}

/// Write a verified certificate for `consumer` and make Nginx load it. The
/// caller holds the mutation lock.
async fn install(ctx: &Ctx, consumer: &HostCertConsumer, m: &Material) -> Result<()> {
    let cfg = &ctx.config.host_certs;
    fsutil::ensure_dir(&cfg.cert_dir, CERT_DIR_MODE)?;
    let previous = previous_pair(cfg, consumer)?;
    let written = fsutil::write_atomic(
        &key_path(cfg, consumer),
        m.key.as_bytes(),
        crate::tls::KEY_MODE,
    )
    .and_then(|_| {
        fsutil::write_atomic(
            &cert_path(cfg, consumer),
            m.chain.as_bytes(),
            crate::tls::CERT_MODE,
        )
    });
    if let Err(e) = written {
        restore(&previous)?;
        return Err(e);
    }
    activate(ctx, &previous).await?;
    info!(%consumer, issuer = %m.info.issuer, "host certificate installed");
    Ok(())
}

/// Remove the pair of every consumer whose registration file is gone. A
/// pair Nginx still needs (it refuses the configuration without it) is put
/// back and kept until the next sweep. The caller holds the mutation lock.
async fn forget_unregistered(
    ctx: &Ctx,
    state: &mut BTreeMap<String, ConsumerState>,
) -> Result<bool> {
    let cfg = &ctx.config.host_certs;
    let mut changed = false;
    for consumer in state.keys().cloned().collect::<Vec<_>>() {
        let Ok(c) = HostCertConsumer::parse(&consumer) else {
            state.remove(&consumer);
            changed = true;
            continue;
        };
        if std::fs::symlink_metadata(registration_path(cfg, &c)).is_ok() {
            continue;
        }
        let previous = previous_pair(cfg, &c)?;
        let mut removed = false;
        for (path, _, _) in &previous {
            removed |= fsutil::remove_if_exists(path)?;
        }
        if removed {
            if let Err(e) = activate(ctx, &previous).await {
                warn!(%consumer, error = %e, "the certificate of a removed registration is still in use; kept");
                continue;
            }
            info!(%consumer, "host certificate of a removed registration removed");
        }
        state.remove(&consumer);
        changed = true;
    }
    Ok(changed)
}

// ---- The sweep -------------------------------------------------------------------------

/// The challenge file and the removal of unregistered pairs: done whether or
/// not certificates can be requested. Never fatal.
pub async fn converge(ctx: &Ctx) {
    let _guard = ctx.lock.lock().await;
    if let Err(e) = apply_challenges(ctx).await {
        warn!(error = %e, "host certificates: the challenge configuration could not be applied");
    }
    let mut state = load_state(&ctx.config);
    match forget_unregistered(ctx, &mut state).await {
        Ok(true) => {
            if let Err(e) = save_state(&ctx.config, &state) {
                warn!(error = %e, "host certificates: state not saved");
            }
        }
        Ok(false) => {}
        Err(e) => warn!(error = %e, "host certificates: removed registrations not cleaned up"),
    }
}

/// Obtain or renew every registered name that needs it (back-off is
/// respected). Waits for a mail-certificate sweep that is running: the
/// periodic tasks start together, and skipping would skip every time.
/// Returns how many certificates were installed.
pub async fn sweep(ctx: &Ctx) -> Result<usize> {
    converge(ctx).await;
    if disabled_reason(ctx).await?.is_some() {
        return Ok(0);
    }
    let _running = named_cert::SWEEPING.lock().await;
    let regs = {
        let _guard = ctx.lock.lock().await;
        valid(registrations(&ctx.config.host_certs)?)
    };
    let mut installed = 0;
    for reg in regs {
        if sweep_one(ctx, &reg).await? {
            installed += 1;
        }
    }
    Ok(installed)
}

/// One registration: nothing if its certificate is current or it is backing
/// off; otherwise an attempt, booked into the state. Returns whether a
/// certificate was installed.
async fn sweep_one(ctx: &Ctx, reg: &Registration) -> Result<bool> {
    let cfg = &ctx.config.host_certs;
    let (crt, key) = (cert_path(cfg, &reg.consumer), key_path(cfg, &reg.consumer));
    let mut st = load_state(&ctx.config)
        .remove(reg.consumer.as_str())
        .filter(|s| s.name == reg.name.as_str())
        .unwrap_or_else(|| ConsumerState {
            name: reg.name.to_string(),
            ..ConsumerState::default()
        });
    let current = named_cert::current(ctx, &reg.name, &crt, &key).await;
    let installed = if let Some(info) = current {
        // Current already (e.g. the state file was lost): just remembered.
        st.issued = Some(Issued {
            issuer: info.issuer,
            not_after_unix: info.not_after_unix,
            names: info.names,
        });
        st.backoff = None;
        false
    } else if st.backoff.as_ref().is_some_and(Backoff::waiting) {
        return Ok(false);
    } else {
        match named_cert::obtain(ctx, &reg.name).await {
            Ok(m) => {
                let _guard = ctx.lock.lock().await;
                match install(ctx, &reg.consumer, &m).await {
                    Ok(()) => {
                        st.issued = Some(Issued {
                            issuer: m.info.issuer.clone(),
                            not_after_unix: m.info.not_after_unix,
                            names: m.info.names.clone(),
                        });
                        st.backoff = None;
                        true
                    }
                    Err(e) => {
                        st.backoff = Some(Backoff::after(st.backoff.as_ref(), &e.to_string()));
                        false
                    }
                }
            }
            Err(why) => {
                info!(consumer = %reg.consumer, name = %reg.name, reason = %why, "no host certificate yet");
                st.backoff = Some(Backoff::after(st.backoff.as_ref(), &why));
                false
            }
        }
    };
    let _guard = ctx.lock.lock().await;
    // The registration may have been removed meanwhile: then nothing is kept.
    if std::fs::symlink_metadata(registration_path(cfg, &reg.consumer)).is_ok() {
        let mut all = load_state(&ctx.config);
        all.insert(reg.consumer.to_string(), st);
        save_state(&ctx.config, &all)?;
    }
    Ok(installed)
}

// ---- Reconciliation -------------------------------------------------------------------

/// Host-certificate findings: a key that is not root-only, a file no
/// registration accounts for, the challenge file differing from what the
/// registrations render. The caller holds the mutation lock.
pub fn drifts(ctx: &Ctx) -> Result<Vec<Drift>> {
    use std::os::unix::fs::MetadataExt as _;
    let cfg = &ctx.config.host_certs;
    let mut out = Vec::new();
    let registered: BTreeSet<String> = registrations(cfg)?
        .into_iter()
        .filter_map(|e| match e {
            Entry::Valid(r) => Some(r.consumer.to_string()),
            Entry::Invalid { consumer, .. } => HostCertConsumer::parse(&consumer)
                .ok()
                .map(|c| c.to_string()),
        })
        .collect();
    for file in fsutil::list_entry_names(&cfg.cert_dir)? {
        let path = cfg.cert_dir.join(&file);
        let key = file.strip_suffix(".key");
        let consumer = file.strip_suffix(".crt").or(key);
        if !consumer.is_some_and(|c| registered.contains(c)) {
            out.push(Drift::new(
                DriftKind::OrphanHostCertificateFile,
                path.to_string_lossy(),
                "no host-certificate registration accounts for this file",
            ));
            continue;
        }
        if key.is_some() {
            let md = std::fs::symlink_metadata(&path).map_err(|e| Error::io("lstat", &path, e))?;
            if !md.is_file()
                || md.uid() != nix::unistd::geteuid().as_raw()
                || md.mode() & 0o077 != 0
            {
                out.push(Drift::new(
                    DriftKind::HostCertificateKeyExposed,
                    path.to_string_lossy(),
                    "the private key is not a regular file readable by root only",
                ));
            }
        }
    }
    let path = &cfg.nginx_file;
    let problem = match render_challenges(ctx)? {
        Some(text) => crate::host::compare_file(path, &text)?,
        None => std::fs::symlink_metadata(path)
            .is_ok()
            .then_some("exists, but no registration needs it"),
    };
    if let Some(problem) = problem {
        out.push(Drift::new(
            DriftKind::HostCertificateChallengeDrift,
            path.to_string_lossy(),
            problem,
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::host::HostService;
    use crate::records::AutoHttpsChoice;
    use crate::system::bin;
    use crate::system::fake_tls::FAKE_ACME_ISSUER;
    use crate::tls::tests::{args, harness_with, Harness};
    use std::os::unix::fs::PermissionsExt as _;

    const DAY: u64 = 86_400;

    async fn harness() -> Harness {
        harness_with(|c| {
            let p = c.state_dir.with_file_name("host");
            c.host_certs = HostCertConfig {
                registry_dir: p.join("host-certificates.d"),
                cert_dir: p.join("pki-host"),
                nginx_file: p.join("nginx-host-certificates.conf"),
            };
        })
        .await
    }

    fn register(h: &Harness, consumer: &str, text: &str) -> PathBuf {
        let dir = &h.ctx.config.host_certs.registry_dir;
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(format!("{consumer}.conf"));
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        path
    }

    fn one(statuses: &[Status]) -> &Status {
        assert_eq!(statuses.len(), 1, "{statuses:?}");
        &statuses[0]
    }

    /// The ACME client's runs: (pre-check?, names).
    fn client_runs(h: &Harness) -> Vec<(bool, Vec<String>)> {
        h.sys
            .calls_to(bin::SYSTEMD_RUN)
            .iter()
            .map(args)
            .map(|a| {
                let names = a
                    .iter()
                    .enumerate()
                    .filter(|(_, x)| *x == "--domain")
                    .filter_map(|(i, _)| a.get(i + 1).cloned())
                    .collect();
                (a.iter().any(|x| x == "precheck"), names)
            })
            .collect()
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn registrations_are_read_strictly() {
        let ok = parse_registration(
            "# the panel\nname=panel.example.org\nchallenges=engine\nredirect_port=8443\n",
        )
        .unwrap();
        assert_eq!(ok.0.as_str(), "panel.example.org");
        assert_eq!((ok.1, ok.2), (Challenges::Engine, Some(8443)));
        let ok = parse_registration(" name = a.example \n\nchallenges=consumer").unwrap();
        assert_eq!((ok.1, ok.2), (Challenges::Consumer, None));
        for (bad, why) in [
            ("challenges=engine", "name= is missing"),
            ("name=a.example", "challenges= is missing"),
            ("name=a.example\nchallenges=both", "engine or consumer"),
            (
                "name=a.example\nchallenges=engine\nport=1",
                "unknown setting",
            ),
            ("name=a.example\nname=b.example\nchallenges=engine", "twice"),
            (
                "name=a.example\nchallenges=consumer\nredirect_port=8443",
                "only allowed",
            ),
            (
                "name=a.example\nchallenges=engine\nredirect_port=80",
                "1024 to 65535",
            ),
            (
                "name=a.example\nchallenges=engine\nredirect_port=x",
                "1024 to 65535",
            ),
            ("name=localhost\nchallenges=engine", "fully-qualified"),
            ("name=A.example\nchallenges=engine", "lower-case"),
            ("just a line", "key=value"),
        ] {
            let err = parse_registration(bad).unwrap_err();
            assert!(err.contains(why), "{bad:?}: {err}");
        }
    }

    #[tokio::test]
    async fn invalid_registration_files_are_reported_and_nothing_is_done() {
        let h = harness().await;
        let p = register(&h, "loose", "name=a.example\nchallenges=engine\n");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        register(&h, "Bad_Name", "name=b.example\nchallenges=engine\n");
        register(&h, "broken", "name=c.example\n");
        let dir = h.ctx.config.host_certs.registry_dir.clone();
        std::os::unix::fs::symlink(dir.join("broken.conf"), dir.join("link.conf")).unwrap();
        std::fs::write(dir.join("panel.conf.rpmsave"), "anything").unwrap();
        let s = status(&h.ctx).await.unwrap();
        let by: Vec<(&str, State, &str)> = s
            .iter()
            .map(|s| (s.consumer.as_str(), s.state, s.reason.as_str()))
            .collect();
        assert_eq!(by.len(), 4, "{by:?}");
        assert!(by.iter().all(|(_, st, _)| *st == State::Invalid), "{by:?}");
        assert!(by[0].0 == "Bad_Name" && by[0].2.contains("lower-case letter"));
        assert!(by[1].0 == "broken" && by[1].2.contains("challenges= is missing"));
        assert!(by[2].0 == "link" && by[2].2.contains("symlink"));
        assert!(by[3].0 == "loose" && by[3].2.contains("writable by root only"));
        h.sys.clear_calls();
        assert_eq!(sweep(&h.ctx).await.unwrap(), 0);
        assert!(client_runs(&h).is_empty());
        assert!(!h.ctx.config.host_certs.nginx_file.exists());
    }

    #[tokio::test]
    async fn a_registered_name_gets_a_certificate_and_the_challenge_server() {
        let h = harness().await;
        register(
            &h,
            "panel",
            "name=panel.example.org\nchallenges=engine\nredirect_port=8443\n",
        );
        let before = one(&status(&h.ctx).await.unwrap()).clone();
        assert_eq!(
            (before.state, before.reason.as_str()),
            (State::Pending, "waiting for the first attempt")
        );
        h.sys.clear_calls();
        assert_eq!(sweep(&h.ctx).await.unwrap(), 1);
        let cfg = &h.ctx.config.host_certs;
        let consumer = HostCertConsumer::parse("panel").unwrap();
        let (crt, key) = (cert_path(cfg, &consumer), key_path(cfg, &consumer));
        assert_eq!((mode(&crt), mode(&key)), (0o644, 0o600));
        assert_eq!(mode(&cfg.cert_dir), 0o755);
        let s = one(&status(&h.ctx).await.unwrap()).clone();
        assert_eq!(s.state, State::Issued, "{s:?}");
        assert_eq!(s.issuer, FAKE_ACME_ISSUER);
        assert!(s.not_after_unix.unwrap() > now_unix() + 60 * DAY);
        assert_eq!(s.certificate_path, crt.to_string_lossy());
        // Pre-check, then the order, for the one name.
        let name = vec!["panel.example.org".to_owned()];
        assert_eq!(client_runs(&h), vec![(true, name.clone()), (false, name)]);
        // The challenge server, then nginx -t and a reload after the files.
        let conf = std::fs::read_to_string(&cfg.nginx_file).unwrap();
        assert!(conf.contains("server_name panel.example.org;"), "{conf}");
        assert!(
            conf.contains("return 301 https://$host:8443$request_uri;"),
            "{conf}"
        );
        let challenges = h.ctx.config.acme_dir.join("challenges");
        assert!(
            conf.contains(&format!("alias {}/;", challenges.display())),
            "{conf}"
        );
        let nginx: Vec<Vec<String>> = h.sys.calls_to(bin::NGINX).iter().map(args).collect();
        assert_eq!(nginx, vec![vec!["-t", "-q"]; 2]);
        let reloads = h
            .sys
            .calls_to(bin::SYSTEMCTL)
            .iter()
            .map(args)
            .filter(|a| a.contains(&"reload-or-restart".to_owned()))
            .count();
        assert_eq!(reloads, 2);
        assert!(HostService::new(h.ctx.clone())
            .reconcile()
            .await
            .unwrap()
            .is_empty());
        // Nothing to do the next time.
        h.sys.clear_calls();
        assert_eq!(sweep(&h.ctx).await.unwrap(), 0);
        assert!(client_runs(&h).is_empty());
    }

    #[tokio::test]
    async fn an_unresolvable_name_never_reaches_the_authority_and_backs_off() {
        let h = harness().await;
        register(
            &h,
            "panel",
            "name=nx-panel.example.org\nchallenges=engine\n",
        );
        h.sys.clear_calls();
        assert_eq!(sweep(&h.ctx).await.unwrap(), 0);
        assert_eq!(
            client_runs(&h),
            vec![(true, vec!["nx-panel.example.org".to_owned()])]
        );
        assert!(h.sys.calls_to(bin::OPENSSL).is_empty(), "no key, no order");
        let s = one(&status(&h.ctx).await.unwrap()).clone();
        assert_eq!(
            (s.state, s.reason.as_str()),
            (State::Pending, "the name does not resolve")
        );
        assert!(s.next_attempt_unix.unwrap() >= now_unix() + 3500);
        assert!(!cert_path(
            &h.ctx.config.host_certs,
            &HostCertConsumer::parse("panel").unwrap()
        )
        .exists());
        h.sys.clear_calls();
        sweep(&h.ctx).await.unwrap();
        assert!(client_runs(&h).is_empty(), "backing off");
        // Another name starts afresh.
        register(&h, "panel", "name=panel.example.org\nchallenges=engine\n");
        assert_eq!(sweep(&h.ctx).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn names_a_site_answers_get_no_second_server_and_consumers_none() {
        let h = harness().await;
        register(&h, "site", "name=example.com\nchallenges=engine\n");
        register(&h, "own", "name=own.example.org\nchallenges=consumer\n");
        assert_eq!(render_challenges(&h.ctx).unwrap(), None);
        register(&h, "panel", "name=panel.example.org\nchallenges=engine\n");
        register(&h, "twin", "name=panel.example.org\nchallenges=engine\n");
        let conf = render_challenges(&h.ctx).unwrap().unwrap();
        assert_eq!(conf.matches("server_name").count(), 1, "{conf}");
        assert!(conf.contains("return 404;"));
        assert_eq!(sweep(&h.ctx).await.unwrap(), 4);
    }

    #[tokio::test]
    async fn a_certificate_nginx_refuses_is_rolled_back() {
        let h = harness().await;
        register(&h, "panel", "name=panel.example.org\nchallenges=consumer\n");
        h.sys
            .script_failure(bin::NGINX, 1, "nginx: [emerg] cannot load certificate");
        assert_eq!(sweep(&h.ctx).await.unwrap(), 0);
        let consumer = HostCertConsumer::parse("panel").unwrap();
        let cfg = &h.ctx.config.host_certs;
        assert!(!cert_path(cfg, &consumer).exists() && !key_path(cfg, &consumer).exists());
        let s = one(&status(&h.ctx).await.unwrap()).clone();
        assert_eq!(s.state, State::Pending);
        assert!(s.reason.contains("cannot load certificate"), "{s:?}");
    }

    #[tokio::test]
    async fn due_certificates_are_renewed_and_removed_registrations_cleaned_up() {
        let h = harness().await;
        let reg = register(&h, "panel", "name=panel.example.org\nchallenges=engine\n");
        h.sys.set_acme_lifetime(10 * DAY);
        sweep(&h.ctx).await.unwrap();
        let s = one(&status(&h.ctx).await.unwrap()).clone();
        assert_eq!(
            (s.state, s.reason.as_str()),
            (State::Renewing, "due for renewal")
        );
        h.sys.set_acme_lifetime(90 * DAY);
        h.sys.clear_calls();
        assert_eq!(sweep(&h.ctx).await.unwrap(), 1);
        assert_eq!(client_runs(&h).len(), 2);
        assert_eq!(one(&status(&h.ctx).await.unwrap()).state, State::Issued);

        std::fs::remove_file(&reg).unwrap();
        sweep(&h.ctx).await.unwrap();
        let cfg = &h.ctx.config.host_certs;
        assert!(fsutil::list_entry_names(&cfg.cert_dir).unwrap().is_empty());
        assert!(!cfg.nginx_file.exists());
        assert!(load_state(&h.ctx.config).is_empty());
        assert!(status(&h.ctx).await.unwrap().is_empty());
        assert!(HostService::new(h.ctx.clone())
            .reconcile()
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn exposed_keys_strays_and_an_edited_challenge_file_are_drift() {
        let h = harness().await;
        register(&h, "panel", "name=panel.example.org\nchallenges=engine\n");
        sweep(&h.ctx).await.unwrap();
        let cfg = h.ctx.config.host_certs.clone();
        let key = key_path(&cfg, &HostCertConsumer::parse("panel").unwrap());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(cfg.cert_dir.join("other.crt"), "x").unwrap();
        std::fs::write(&cfg.nginx_file, "# edited\n").unwrap();
        let mut kinds: Vec<DriftKind> = HostService::new(h.ctx.clone())
            .reconcile()
            .await
            .unwrap()
            .into_iter()
            .map(|d| d.kind)
            .collect();
        kinds.sort();
        assert_eq!(
            kinds,
            vec![
                DriftKind::HostCertificateKeyExposed,
                DriftKind::OrphanHostCertificateFile,
                DriftKind::HostCertificateChallengeDrift
            ]
        );
    }

    #[tokio::test]
    async fn nothing_is_requested_while_automatic_https_is_off() {
        let h = harness_with(|c| {
            let p = c.state_dir.with_file_name("host");
            c.host_certs = HostCertConfig {
                registry_dir: p.join("host-certificates.d"),
                cert_dir: p.join("pki-host"),
                nginx_file: p.join("nginx-host-certificates.conf"),
            };
            c.auto_https = AutoHttpsChoice::Off;
        })
        .await;
        register(&h, "panel", "name=panel.example.org\nchallenges=engine\n");
        h.sys.clear_calls();
        assert_eq!(sweep(&h.ctx).await.unwrap(), 0);
        assert!(client_runs(&h).is_empty());
        let s = one(&status(&h.ctx).await.unwrap()).clone();
        assert_eq!(s.state, State::Disabled);
        assert!(s.reason.contains("OXPANEL_AUTO_HTTPS"));
        // The challenge server is there all the same (it also redirects).
        assert!(h.ctx.config.host_certs.nginx_file.exists());
    }
}
