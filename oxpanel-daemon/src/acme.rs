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
    Ok(None)
}

/// Refuse a request the host cannot serve before anything is created.
pub async fn preflight(ctx: &Ctx) -> Result<()> {
    match unavailable_reason(ctx).await? {
        None => Ok(()),
        Some(reason) => Err(Error::AcmeUnavailable(reason)),
    }
}

/// Generate a fresh private key for `vhost` (kept aside until the certificate
/// arrives) and the signing request for its domain and aliases. The caller
/// holds the mutation lock. Returns the names the certificate is requested for.
pub async fn prepare(ctx: &Ctx, vhost: &VHostRecord) -> Result<Vec<Domain>> {
    let cfg = &ctx.config;
    let timeout = cfg.command_timeout;
    let domain = Domain::parse(&vhost.domain)?;
    let mut names = vec![domain.clone()];
    for alias in &vhost.aliases {
        names.push(Domain::parse_field(alias, "aliases")?);
    }
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
    let pending = tls::pending_key_path(&cfg.tls_dir, &domain);
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
    fsutil::write_atomic(&csr_path(cfg, &domain), csr.as_bytes(), CSR_MODE)?;
    // A reply left over from an earlier request must not be taken for this one's.
    fsutil::remove_if_exists(&issued_path(cfg, &domain))?;
    Ok(names)
}

/// Run the ACME client for `domain` in a transient unit and wait for it.
/// Returns whether it reported success and what it printed; a refusal by the
/// certificate authority is a result, not an error.
pub async fn run_client(ctx: &Ctx, domain: &Domain, names: &[Domain]) -> Result<(bool, String)> {
    let cfg = &ctx.config;
    let unit = unit_name(domain);
    let (account, challenges, issued) = (account_dir(cfg), challenge_dir(cfg), issued_dir(cfg));
    let writable = format!(
        "ReadWritePaths={} {} {}",
        safe_path_str(&account)?,
        safe_path_str(&challenges)?,
        safe_path_str(&issued)?
    );
    let started_at = crate::records::now_unix();
    // No `--pipe` (see app::install_dependencies): output goes to the journal.
    let mut cmd = CommandSpec::new(bin::SYSTEMD_RUN, CLIENT_TIMEOUT)
        .args(["--wait", "--collect", "--quiet"])
        .arg(format!("--unit={unit}"));
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
    ] {
        cmd = cmd.arg("--property").arg(property);
    }
    cmd = cmd
        .arg("--")
        .arg(bin::OXPANEL_ACME)
        .arg("--directory")
        .arg(&cfg.acme_directory_url);
    if let Some(ca) = &cfg.acme_ca_file {
        cmd = cmd.arg("--ca-file").arg(safe_path_str(ca)?);
    }
    if let Some(email) = &cfg.acme_email {
        cmd = cmd.arg("--email").arg(email);
    }
    cmd = cmd
        .arg("--account-dir")
        .arg(&account)
        .arg("--challenge-dir")
        .arg(&challenges)
        .arg("--csr")
        .arg(csr_path(cfg, domain))
        .arg("--out")
        .arg(issued_path(cfg, domain));
    for name in names {
        cmd = cmd.arg("--domain").arg(name.as_str());
    }
    let out = ctx.sys.run(cmd).await?;
    let succeeded = out.success();
    info!(%domain, succeeded, "ACME client finished");
    let journal = ctx
        .sys
        .run(
            CommandSpec::new(bin::JOURNALCTL, cfg.command_timeout)
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
