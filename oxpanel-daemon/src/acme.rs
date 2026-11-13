//! Certificates from an ACME certificate authority (Let's Encrypt), HTTP-01.
//!
//! The daemon has no network and must not get one, so the conversation with
//! the certificate authority is held by a separate program, `oxpanel-acme`,
//! which the daemon starts in a transient systemd unit. That program is given
//! as little as the protocol allows:
//!
//! - it runs as the unprivileged account `oxpanel-acme`, with no capabilities,
//!   a read-only file system and no view of tenant homes;
//! - it never sees a private key of any site. The daemon generates the key
//!   and the signing request (CSR) itself and hands over only the CSR, which
//!   is public; the client returns the certificate chain, which is public too.
//!   The only secret the client holds is its own ACME account key;
//! - it can write three directories and nothing else: its account, the
//!   challenge directory the web server answers
//!   `/.well-known/acme-challenge/` from, and the directory it delivers
//!   issued chains to;
//! - what it delivers is not trusted: the daemon reads it without following
//!   symlinks and validates it exactly like an uploaded certificate, against
//!   the key only the daemon has.
//!
//! Layout below `acme_dir` (created by the package, not by the daemon):
//!
//! | directory     | owner          | purpose                                   |
//! |---------------|----------------|-------------------------------------------|
//! | `account/`    | `oxpanel-acme` | ACME account key (0700)                   |
//! | `challenges/` | `oxpanel-acme` | HTTP-01 tokens, read by the web server    |
//! | `issued/`     | `oxpanel-acme` | `<domain>.pem`, issued chains             |
//! | `csr/`        | root           | `<domain>.csr`, written by the daemon     |

use std::path::PathBuf;
use std::time::Duration;

use tracing::info;

use crate::config::Config;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::nginx::safe_path_str;
use crate::records::VHostRecord;
use crate::system::{bin, CommandSpec};
use crate::systemd;
use crate::tls::{self, PemKind};
use crate::validate::Domain;

/// The account the ACME client runs as.
pub const ACME_USER: &str = "oxpanel-acme";
/// Name of the systemd credential carrying the External Account Binding.
pub const EAB_CREDENTIAL: &str = "oxpanel-acme-eab";
/// Upper bound for one certificate request (the gRPC deadline is 300 s).
const CLIENT_TIMEOUT: Duration = Duration::from_secs(270);
/// What the transient unit is told; a little under ours so systemd ends it first.
const CLIENT_RUNTIME_MAX_SEC: u32 = 240;
/// Lines of client output returned to the caller.
const LOG_LINES: &str = "200";
const CSR_MODE: u32 = 0o644;

/// Where the web server finds HTTP-01 challenge files.
pub fn challenge_dir(cfg: &Config) -> PathBuf {
    cfg.acme_dir.join("challenges")
}

fn account_dir(cfg: &Config) -> PathBuf {
    cfg.acme_dir.join("account")
}

fn csr_dir(cfg: &Config) -> PathBuf {
    cfg.acme_dir.join("csr")
}

fn issued_dir(cfg: &Config) -> PathBuf {
    cfg.acme_dir.join("issued")
}

/// The signing request the daemon writes for the client.
pub fn csr_path(cfg: &Config, domain: &Domain) -> PathBuf {
    csr_dir(cfg).join(format!("{domain}.csr"))
}

/// The certificate chain the client delivers.
pub fn issued_path(cfg: &Config, domain: &Domain) -> PathBuf {
    issued_dir(cfg).join(format!("{domain}.pem"))
}

/// Name of the transient unit one request runs in (without `.service`).
pub fn unit_name(domain: &Domain) -> String {
    format!(
        "oxpanel-acme-{}",
        systemd::escape_unit_component(domain.as_str())
    )
}

/// Why certificates cannot be requested on this host, or `None` if they can.
/// Read-only.
pub async fn unavailable_reason(ctx: &Ctx) -> Result<Option<String>> {
    let cfg = &ctx.config;
    if !ctx.sys.is_installed(bin::OPENSSL).await {
        return Ok(Some("OpenSSL is not installed (install openssl)".into()));
    }
    if !ctx.sys.is_installed(bin::OXPANEL_ACME).await {
        return Ok(Some(format!(
            "the ACME client {} is not installed",
            bin::OXPANEL_ACME
        )));
    }
    if ctx.sys.user_by_name(ACME_USER).await?.is_none() {
        return Ok(Some(format!("the account '{ACME_USER}' does not exist")));
    }
    for dir in [
        account_dir(cfg),
        challenge_dir(cfg),
        csr_dir(cfg),
        issued_dir(cfg),
    ] {
        if !std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
            return Ok(Some(format!("the directory {} is missing", dir.display())));
        }
    }
    if let Some(file) = &cfg.acme_eab_file {
        if let Some(problem) = eab_file_problem(file) {
            return Ok(Some(format!(
                "OXPANEL_ACME_EAB_FILE {}: {problem}",
                file.display()
            )));
        }
    }
    Ok(None)
}

/// The External Account Binding file holds a secret: it must be a regular
/// file that only the daemon's own account (root) can read.
fn eab_file_problem(file: &std::path::Path) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt as _;
    match std::fs::symlink_metadata(file) {
        Err(_) => Some("is missing"),
        Ok(md) if !md.is_file() => Some("is not a regular file"),
        Ok(md) if md.uid() != nix::unistd::geteuid().as_raw() || md.mode() & 0o077 != 0 => {
            Some("must be owned by root and readable by root only (chmod 600)")
        }
        Ok(_) => None,
    }
}

/// Refuse a request the host cannot serve before anything is created.
pub async fn preflight(ctx: &Ctx) -> Result<()> {
    match unavailable_reason(ctx).await? {
        None => Ok(()),
        Some(reason) => Err(Error::AcmeUnavailable(reason)),
    }
}

/// The domain of `vhost` followed by its aliases.
pub fn server_names(vhost: &VHostRecord) -> Result<Vec<Domain>> {
    let mut names = vec![Domain::parse(&vhost.domain)?];
    for alias in &vhost.aliases {
        names.push(Domain::parse_field(alias, "aliases")?);
    }
    Ok(names)
}

/// Generate a fresh private key for `domain` (kept aside until the
/// certificate arrives) and the signing request for `names` (the domain
/// first). The caller holds the mutation lock.
pub async fn prepare(ctx: &Ctx, domain: &Domain, names: &[Domain]) -> Result<()> {
    let cfg = &ctx.config;
    let timeout = cfg.command_timeout;
    let internal = |what: &str| Error::Internal(format!("openssl produced an unusable {what}"));

    fsutil::ensure_dir(&cfg.tls_dir, tls::DIR_MODE)?;
    // ECDSA P-256: accepted by every ACME authority and every browser that
    // speaks TLS 1.2. The key leaves OpenSSL on its standard output, straight
    // into a root-only file; it is never an argument and never logged.
    let key = ctx
        .sys
        .run_ok(CommandSpec::new(bin::OPENSSL, timeout).args([
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
        ]))
        .await?;
    let key = String::from_utf8(key.stdout).map_err(|_| internal("key"))?;
    let key = tls::normalise_pem(&key, PemKind::Key).map_err(|_| internal("key"))?;
    let pending = tls::pending_key_path(&cfg.tls_dir, domain);
    fsutil::write_atomic(&pending, key.as_bytes(), tls::KEY_MODE)?;

    // An empty subject: the names are in the subjectAltName extension, and a
    // common name could not hold a host name longer than 64 characters.
    let san = names
        .iter()
        .map(|n| format!("DNS:{n}"))
        .collect::<Vec<_>>()
        .join(",");
    let csr = ctx
        .sys
        .run_ok(
            CommandSpec::new(bin::OPENSSL, timeout)
                .args(["req", "-new", "-key"])
                .arg(&pending)
                .args(["-subj", "/", "-addext"])
                .arg(format!("subjectAltName={san}")),
        )
        .await?;
    let csr = String::from_utf8(csr.stdout).map_err(|_| internal("signing request"))?;
    let csr = tls::normalise_pem(&csr, PemKind::Csr).map_err(|_| internal("signing request"))?;
    fsutil::write_atomic(&csr_path(cfg, domain), csr.as_bytes(), CSR_MODE)?;
    // A reply left over from an earlier request must not be taken for this one's.
    fsutil::remove_if_exists(&issued_path(cfg, domain))?;
    Ok(())
}

/// `systemd-run` for one run of the ACME client for `domain`, up to the
/// program: an unprivileged, sandboxed transient unit that can write only the
/// client's own directories. `extra` properties are appended.
fn unit_command(ctx: &Ctx, domain: &Domain, extra: &[String]) -> Result<CommandSpec> {
    let cfg = &ctx.config;
    let writable = format!(
        "ReadWritePaths={} {} {}",
        safe_path_str(&account_dir(cfg))?,
        safe_path_str(&challenge_dir(cfg))?,
        safe_path_str(&issued_dir(cfg))?
    );
    // No `--pipe` (see app::install_dependencies): output goes to the journal.
    let mut cmd = CommandSpec::new(bin::SYSTEMD_RUN, CLIENT_TIMEOUT)
        .args(["--wait", "--collect", "--quiet"])
        .arg(format!("--unit={}", unit_name(domain)));
    for property in [
        format!("User={ACME_USER}"),
        format!("Group={ACME_USER}"),
        format!("RuntimeMaxSec={CLIENT_RUNTIME_MAX_SEC}"),
        writable,
        "UMask=0022".to_owned(),
        "NoNewPrivileges=yes".to_owned(),
        "CapabilityBoundingSet=".to_owned(),
        "AmbientCapabilities=".to_owned(),
        "PrivateTmp=yes".to_owned(),
        "PrivateDevices=yes".to_owned(),
        "ProtectSystem=strict".to_owned(),
        "ProtectHome=yes".to_owned(),
        "ProtectKernelTunables=yes".to_owned(),
        "ProtectKernelModules=yes".to_owned(),
        "ProtectKernelLogs=yes".to_owned(),
        "ProtectControlGroups=yes".to_owned(),
        "ProtectClock=yes".to_owned(),
        "ProtectHostname=yes".to_owned(),
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX".to_owned(),
        "RestrictNamespaces=yes".to_owned(),
        "RestrictRealtime=yes".to_owned(),
        "RestrictSUIDSGID=yes".to_owned(),
        "LockPersonality=yes".to_owned(),
        "MemoryDenyWriteExecute=yes".to_owned(),
        "SystemCallArchitectures=native".to_owned(),
    ]
    .iter()
    .chain(extra)
    {
        cmd = cmd.arg("--property").arg(property);
    }
    Ok(cmd.arg("--").arg(bin::OXPANEL_ACME))
}

/// Run a prepared client command and wait for it. Returns whether it
/// succeeded and what it printed (read back from the journal).
async fn run_unit(ctx: &Ctx, domain: &Domain, cmd: CommandSpec) -> Result<(bool, String)> {
    let unit = unit_name(domain);
    let started_at = crate::records::now_unix();
    let out = ctx.sys.run(cmd).await?;
    let succeeded = out.success();
    let journal = ctx
        .sys
        .run(
            CommandSpec::new(bin::JOURNALCTL, ctx.config.command_timeout)
                .args(["--no-pager", "--output=cat", "--lines"])
                .arg(LOG_LINES)
                .arg("--since")
                .arg(format!("@{started_at}"))
                .arg("--unit")
                .arg(format!("{unit}.service")),
        )
        .await?;
    // What the client printed, then anything systemd-run itself said.
    let mut output = journal.stdout_lossy();
    let own = out.combined_lossy();
    if !own.is_empty() {
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
        output.push_str(&own);
    }
    Ok((succeeded, output))
}

/// Run the ACME client for `domain` in a transient unit and wait for it.
/// Returns whether it reported success and what it printed; a refusal by the
/// certificate authority is a result, not an error.
pub async fn run_client(ctx: &Ctx, domain: &Domain, names: &[Domain]) -> Result<(bool, String)> {
    let cfg = &ctx.config;
    // The binding's secret reaches the client as a systemd credential: systemd
    // (root) reads the root-only file and shows it to this unit alone.
    let extra = match &cfg.acme_eab_file {
        Some(file) => vec![format!(
            "LoadCredential={EAB_CREDENTIAL}:{}",
            safe_path_str(file)?
        )],
        None => Vec::new(),
    };
    let mut cmd = unit_command(ctx, domain, &extra)?
        .arg("--directory")
        .arg(&cfg.acme_directory_url);
    if let Some(ca) = &cfg.acme_ca_file {
        cmd = cmd.arg("--ca-file").arg(safe_path_str(ca)?);
    }
    if let Some(email) = &cfg.acme_email {
        cmd = cmd.arg("--email").arg(email);
    }
    if cfg.acme_eab_file.is_some() {
        cmd = cmd.arg("--eab");
    }
    cmd = cmd
        .arg("--account-dir")
        .arg(account_dir(cfg))
        .arg("--challenge-dir")
        .arg(challenge_dir(cfg))
        .arg("--csr")
        .arg(csr_path(cfg, domain))
        .arg("--out")
        .arg(issued_path(cfg, domain));
    for name in names {
        cmd = cmd.arg("--domain").arg(name.as_str());
    }
    let (succeeded, output) = run_unit(ctx, domain, cmd).await?;
    info!(%domain, succeeded, "ACME client finished");
    Ok((succeeded, output))
}

/// Outcome of a pre-check: which names would pass HTTP-01 from here.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Precheck {
    pub passed: Vec<Domain>,
    /// Names that would fail, with the reason in plain words.
    pub skipped: Vec<(Domain, String)>,
}

/// The pre-check report the client writes for `domain`.
fn precheck_path(cfg: &Config, domain: &Domain) -> PathBuf {
    issued_dir(cfg).join(format!("{domain}.precheck"))
}

/// Upper bound for a pre-check report and for one reason in it.
const MAX_PRECHECK_BYTES: u64 = 64 * 1024;
const MAX_REASON_CHARS: usize = 200;

/// Ask the client (which has the network the daemon lacks) whether each of
/// `names` resolves and reaches this server under the challenge path, the way
/// the authority would check it. Nothing is sent to the authority. A name the
/// report does not mention counts as skipped.
pub async fn run_precheck(ctx: &Ctx, domain: &Domain, names: &[Domain]) -> Result<Precheck> {
    let cfg = &ctx.config;
    let out = precheck_path(cfg, domain);
    fsutil::remove_if_exists(&out)?;
    let mut cmd = unit_command(ctx, domain, &[])?
        .args(["--mode", "precheck", "--challenge-dir"])
        .arg(challenge_dir(cfg))
        .arg("--out")
        .arg(&out);
    for name in names {
        cmd = cmd.arg("--domain").arg(name.as_str());
    }
    let (succeeded, output) = run_unit(ctx, domain, cmd).await?;
    let report = fsutil::read_untrusted(&out, MAX_PRECHECK_BYTES)?;
    fsutil::remove_if_exists(&out)?;
    let Some(bytes) = report.filter(|_| succeeded) else {
        let why = output.lines().last().unwrap_or("the pre-check did not run");
        return Err(Error::AcmeUnavailable(format!(
            "the reachability check failed: {}",
            printable(why)
        )));
    };
    let report = String::from_utf8_lossy(&bytes).into_owned();
    Ok(parse_precheck(&report, names))
}

/// Control characters out, length bounded: the text came from an
/// unprivileged process.
fn printable(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_REASON_CHARS)
        .collect()
}

/// Read a pre-check report, believing it only about the names that were asked.
fn parse_precheck(report: &str, names: &[Domain]) -> Precheck {
    let mut verdicts: std::collections::BTreeMap<&str, Option<String>> =
        std::collections::BTreeMap::new();
    for line in report.lines() {
        let mut parts = line.splitn(3, ' ');
        match (parts.next(), parts.next(), parts.next()) {
            (Some("ok"), Some(name), None) => {
                verdicts.entry(name).or_insert(None);
            }
            (Some("skip"), Some(name), reason) => {
                verdicts.insert(name, Some(printable(reason.unwrap_or("no reason given"))));
            }
            _ => {}
        }
    }
    let mut result = Precheck::default();
    for name in names {
        match verdicts.get(name.as_str()) {
            Some(None) => result.passed.push(name.clone()),
            Some(Some(reason)) => result.skipped.push((name.clone(), reason.clone())),
            None => result.skipped.push((
                name.clone(),
                "the reachability check did not report it".into(),
            )),
        }
    }
    result
}

/// The chain the client delivered for `domain`, if any. The file belongs to
/// an unprivileged account: never follow a symlink, never read without bound.
pub fn read_issued(ctx: &Ctx, domain: &Domain) -> Result<Option<String>> {
    let path = issued_path(&ctx.config, domain);
    let Some(bytes) = fsutil::read_untrusted(&path, tls::MAX_CHAIN_BYTES as u64)? else {
        return Ok(None);
    };
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| Error::CertificateInvalid("the issued certificate is not text".into()))
}

/// Remove what a certificate request leaves behind: the pending key, the
/// signing request and the delivered chain.
pub fn discard(ctx: &Ctx, domain: &Domain) -> Result<()> {
    let cfg = &ctx.config;
    fsutil::remove_if_exists(&tls::pending_key_path(&cfg.tls_dir, domain))?;
    fsutil::remove_if_exists(&csr_path(cfg, domain))?;
    fsutil::remove_if_exists(&issued_path(cfg, domain))?;
    Ok(())
}
