//! HTTPS for virtual hosts: certificates and their private keys.
//!
//! A virtual host gets a certificate in one of two ways: it is installed
//! through the API ("bring your own"), or it is requested from an ACME
//! certificate authority (see [`crate::acme`]). Either way the same rules hold:
//!
//! - nothing is activated before OpenSSL has confirmed that the key belongs
//!   to the certificate, and the daemon has checked that the certificate
//!   covers the virtual host's domain and is inside its validity period;
//! - the private key lives in exactly one place, a root-only file in a
//!   root-only directory (`tls_dir`). It is never logged, never put on a
//!   command line (OpenSSL is given the *path* of a root-only file) and never
//!   part of a record or a response;
//! - the certificate chain is public. It is kept in the virtual-host record,
//!   so the certificate file is rendered from the record like every other
//!   file the daemon writes, and `Reconcile` can tell when it was changed;
//! - what is stored is rebuilt from the validated PEM blocks, never the bytes
//!   that were sent: anything outside the blocks is dropped;
//! - a certificate that Nginx rejects is rolled back, like any other
//!   configuration change.
//!
//! The certificate is not part of `ConfigureVirtualHost`: reconfiguring a site
//! keeps it, removing the site removes it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::{info, warn};

use crate::acme;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::nginx;
use crate::records::{now_unix, CertSource, TenantRecord, TenantState, TlsRecord, VHostRecord};
use crate::system::{bin, CommandSpec};
use crate::validate::{Domain, Username};
use crate::vhost;

/// Upper bounds for what `InstallCertificate` accepts.
pub const MAX_CHAIN_BYTES: usize = 64 * 1024;
pub const MAX_KEY_BYTES: usize = 16 * 1024;
/// A leaf and its intermediates; nobody needs more.
const MAX_CHAIN_CERTS: usize = 8;
const MAX_NAMES: usize = 200;
const MAX_ISSUER_CHARS: usize = 256;

pub const DIR_MODE: u32 = 0o700;
/// The chain is public; the directory around it is not.
pub const CERT_MODE: u32 = 0o644;
pub const KEY_MODE: u32 = 0o600;

/// `<tls_dir>/<domain>.crt`
pub fn cert_path(dir: &Path, domain: &Domain) -> PathBuf {
    dir.join(format!("{domain}.crt"))
}

/// `<tls_dir>/<domain>.key`
pub fn key_path(dir: &Path, domain: &Domain) -> PathBuf {
    dir.join(format!("{domain}.key"))
}

/// The key of a certificate that has been requested but not issued yet.
pub fn pending_key_path(dir: &Path, domain: &Domain) -> PathBuf {
    dir.join(format!("{domain}.key.pending"))
}

/// Where material is held while OpenSSL examines it.
fn staged_paths(dir: &Path, domain: &Domain) -> (PathBuf, PathBuf) {
    (
        dir.join(format!("{domain}.crt.new")),
        dir.join(format!("{domain}.key.new")),
    )
}

/// What a PEM document is expected to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PemKind {
    /// One to eight certificates, leaf first.
    Chain,
    /// Exactly one unencrypted private key.
    Key,
    /// Exactly one certificate signing request.
    Csr,
}

impl PemKind {
    fn field(self) -> &'static str {
        match self {
            Self::Chain => "certificate_chain_pem",
            Self::Key => "private_key_pem",
            Self::Csr => "csr",
        }
    }

    fn labels(self) -> &'static [&'static str] {
        match self {
            Self::Chain => &["CERTIFICATE"],
            Self::Key => &["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"],
            Self::Csr => &["CERTIFICATE REQUEST"],
        }
    }

    fn max_blocks(self) -> usize {
        match self {
            Self::Chain => MAX_CHAIN_CERTS,
            Self::Key | Self::Csr => 1,
        }
    }
}

/// Check that `input` is a well-formed PEM document of `kind` and return it
/// in canonical form: only the expected blocks, base64 re-wrapped at 64
/// columns, nothing in between. Text around the blocks (comments, "bag
/// attributes") is dropped; a block of any other type is refused.
pub(crate) fn normalise_pem(input: &str, kind: PemKind) -> Result<String> {
    let field = kind.field();
    let bad = |why: &str| Error::invalid(field, why.to_owned());
    let mut out = String::new();
    let mut blocks = 0usize;
    // The label and base64 body of the block being read.
    let mut open: Option<(&str, String)> = None;
    for line in input.lines().map(str::trim) {
        let boundary = line
            .strip_prefix("-----")
            .and_then(|l| l.strip_suffix("-----"));
        match (&mut open, boundary) {
            (None, Some(b)) => {
                let Some(label) = b.strip_prefix("BEGIN ") else {
                    return Err(bad("an END line without a BEGIN line"));
                };
                if kind == PemKind::Key && label == "EC PARAMETERS" {
                    // Written by `openssl ecparam -genkey` in front of the key; redundant.
                    open = Some((label, String::new()));
                } else if kind == PemKind::Key && label == "ENCRYPTED PRIVATE KEY" {
                    return Err(bad(
                        "the private key is encrypted; supply it without a passphrase",
                    ));
                } else if kind.labels().contains(&label) {
                    open = Some((label, String::new()));
                } else {
                    return Err(bad("contains a PEM block of an unexpected type"));
                }
            }
            (None, None) => {}
            (Some((label, body)), Some(b)) => {
                if b.strip_prefix("END ") != Some(*label) {
                    return Err(bad("a PEM block is not closed by its own END line"));
                }
                if body.is_empty() {
                    return Err(bad("contains an empty PEM block"));
                }
                if *label != "EC PARAMETERS" {
                    blocks += 1;
                    if blocks > kind.max_blocks() {
                        return Err(bad("contains too many PEM blocks"));
                    }
                    push_block(&mut out, label, body);
                }
                open = None;
            }
            (Some((_, body)), None) => {
                // Also refuses the header lines of a legacy encrypted key.
                if !line
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'='))
                {
                    return Err(bad("contains a PEM block that is not plain base64"));
                }
                body.push_str(line);
            }
        }
    }
    if open.is_some() {
        return Err(bad("ends inside a PEM block"));
    }
    if blocks == 0 {
        return Err(bad(match kind {
            PemKind::Chain => "contains no certificate",
            PemKind::Key => "contains no private key",
            PemKind::Csr => "contains no signing request",
        }));
    }
    Ok(out)
}

fn push_block(out: &mut String, label: &str, body: &str) {
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    let mut rest = body;
    while !rest.is_empty() {
        // The body is ASCII (checked by the caller), so any index is a boundary.
        let (line, tail) = rest.split_at(rest.len().min(64));
        out.push_str(line);
        out.push('\n');
        rest = tail;
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Parse `YYYY-MM-DD HH:MM:SSZ` (what `openssl x509 -dateopt iso_8601`
/// prints) into seconds since the epoch. Dates before 1970 are refused.
pub(crate) fn parse_utc(s: &str) -> Option<u64> {
    let (date, time) = s.trim().strip_suffix('Z')?.split_once(' ')?;
    let mut d = date.splitn(3, '-').map(str::parse::<i64>);
    let mut t = time.splitn(3, ':').map(str::parse::<i64>);
    let (year, month, day) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let (hour, minute, second) = (t.next()?.ok()?, t.next()?.ok()?, t.next()?.ok()?);
    let in_range = (1970..=9999).contains(&year)
        && (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && (0..24).contains(&hour)
        && (0..60).contains(&minute)
        && (0..=60).contains(&second);
    if !in_range {
        return None;
    }
    let secs = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    u64::try_from(secs).ok()
}

/// The inverse of [`parse_utc`].
pub(crate) fn format_utc(unix: u64) -> String {
    let secs = i64::try_from(unix).unwrap_or(i64::MAX);
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    let rest = secs.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// What the daemon needs to know about a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CertInfo {
    pub(crate) issuer: String,
    pub(crate) not_before_unix: u64,
    pub(crate) not_after_unix: u64,
    pub(crate) names: Vec<String>,
}

fn openssl(ctx: &Ctx) -> CommandSpec {
    CommandSpec::new(bin::OPENSSL, ctx.config.command_timeout)
}

fn unreadable() -> Error {
    Error::CertificateInvalid("the certificate could not be read".into())
}

/// Issuer, validity and DNS names of the first certificate in `cert`.
pub(crate) async fn inspect(ctx: &Ctx, cert: &Path) -> Result<CertInfo> {
    let out = ctx
        .sys
        .run(
            openssl(ctx)
                .args(["x509", "-in"])
                .arg(cert)
                .args(["-noout", "-issuer", "-startdate", "-enddate"])
                .args(["-nameopt", "RFC2253", "-dateopt", "iso_8601"]),
        )
        .await?;
    if !out.success() {
        return Err(unreadable());
    }
    let text = out.stdout_lossy();
    let value = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key))
            .map(str::trim)
    };
    // The issuer comes out of the certificate: bound it and keep it printable.
    let issuer: String = value("issuer=")
        .ok_or_else(unreadable)?
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_ISSUER_CHARS)
        .collect();
    let not_before_unix = value("notBefore=")
        .and_then(parse_utc)
        .ok_or_else(unreadable)?;
    let not_after_unix = value("notAfter=")
        .and_then(parse_utc)
        .ok_or_else(unreadable)?;
    // A certificate without the extension prints nothing here.
    let san = ctx
        .sys
        .run(openssl(ctx).args(["x509", "-in"]).arg(cert).args([
            "-noout",
            "-ext",
            "subjectAltName",
        ]))
        .await?;
    let names = if san.success() {
        parse_san(&san.stdout_lossy())
    } else {
        Vec::new()
    };
    Ok(CertInfo {
        issuer,
        not_before_unix,
        not_after_unix,
        names,
    })
}

/// The `DNS:` entries of OpenSSL's rendering of a subjectAltName extension.
fn parse_san(text: &str) -> Vec<String> {
    let mut names: Vec<String> = text
        .lines()
        .flat_map(|l| l.split(','))
        .filter_map(|entry| entry.trim().strip_prefix("DNS:"))
        .map(str::to_ascii_lowercase)
        .filter(|n| {
            !n.is_empty()
                && n.len() <= 253
                && n.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'*')
                })
        })
        .take(MAX_NAMES)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Confirm that `key` is the private key of the first certificate in `cert`,
/// by comparing the public keys OpenSSL derives from each.
pub(crate) async fn check_pair(ctx: &Ctx, cert: &Path, key: &Path) -> Result<()> {
    let from_cert = ctx
        .sys
        .run(
            openssl(ctx)
                .args(["x509", "-in"])
                .arg(cert)
                .args(["-noout", "-pubkey"]),
        )
        .await?;
    if !from_cert.success() || from_cert.stdout.is_empty() {
        return Err(unreadable());
    }
    // `-passin pass:`: an encrypted key fails at once instead of asking.
    let from_key = ctx
        .sys
        .run(
            openssl(ctx)
                .args(["pkey", "-in"])
                .arg(key)
                .args(["-pubout", "-passin", "pass:"]),
        )
        .await?;
    if !from_key.success() || from_key.stdout.is_empty() {
        return Err(Error::CertificateInvalid(
            "the private key could not be read (it must be an unencrypted RSA or EC key)".into(),
        ));
    }
    if from_cert.stdout != from_key.stdout {
        return Err(Error::CertificateInvalid(
            "the private key does not belong to the certificate".into(),
        ));
    }
    Ok(())
}

/// Whether a certificate valid for `names` is valid for `host`. A wildcard
/// stands for exactly one label, as browsers apply it.
pub fn covers(names: &[String], host: &str) -> bool {
    names.iter().any(|n| {
        n == host
            || n.strip_prefix("*.").is_some_and(|suffix| {
                host.split_once('.')
                    .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix)
            })
    })
}

/// Server names of `vhost` that its certificate does not cover.
pub fn uncovered_names(vhost: &VHostRecord) -> Vec<String> {
    let Some(tls) = &vhost.tls else {
        return Vec::new();
    };
    vhost
        .all_names()
        .filter(|n| !covers(&tls.names, n))
        .map(str::to_owned)
        .collect()
}

/// A certificate as received on the wire.
#[derive(Clone, PartialEq, Eq)]
pub struct CertificateUpload {
    pub domain: String,
    pub chain_pem: String,
    pub key_pem: String,
}

/// Never prints the key (nor, for brevity, the chain).
impl std::fmt::Debug for CertificateUpload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateUpload")
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

/// Result of [`TlsService::request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeOutcome {
    /// `false` when the certificate authority did not issue.
    pub succeeded: bool,
    /// What the ACME client reported.
    pub output: String,
    pub vhost: VHostRecord,
}

/// One entry of [`TlsService::renew_due`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Renewal {
    pub domain: String,
    pub succeeded: bool,
    pub output: String,
}

/// What was in place before a certificate was installed, for rolling back.
struct Previous {
    record: VHostRecord,
    cert: Option<Vec<u8>>,
    key: Option<Vec<u8>>,
}

impl Previous {
    fn restore(&self, ctx: &Ctx, domain: &Domain) -> Result<()> {
        let dir = &ctx.config.tls_dir;
        restore_file(&cert_path(dir, domain), self.cert.as_deref(), CERT_MODE)?;
        restore_file(&key_path(dir, domain), self.key.as_deref(), KEY_MODE)?;
        ctx.store.save_vhost(&self.record)
    }
}

fn restore_file(path: &Path, previous: Option<&[u8]>, mode: u32) -> Result<()> {
    match previous {
        Some(bytes) => fsutil::write_atomic(path, bytes, mode).map(|_| ()),
        None => fsutil::remove_if_exists(path).map(|_| ()),
    }
}

/// One lock per site: requests for one site (by hand, by Automatic HTTPS or
/// by renewal) run one after the other, since they would overwrite each
/// other's pending key. Clones of a [`TlsService`] share them.
type SiteLocks =
    Arc<std::sync::Mutex<std::collections::BTreeMap<String, Arc<tokio::sync::Mutex<()>>>>>;

/// At most this many conversations with the certificate authority (or
/// reachability checks) run at the same time, whatever started them.
pub const MAX_CONCURRENT_ORDERS: usize = 2;

#[derive(Debug, Clone)]
pub struct TlsService {
    pub(crate) ctx: Ctx,
    sites: SiteLocks,
    orders: Arc<tokio::sync::Semaphore>,
}

impl TlsService {
    pub fn new(ctx: Ctx) -> Self {
        Self {
            ctx,
            sites: SiteLocks::default(),
            orders: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_ORDERS)),
        }
    }

    /// Wait until no other certificate work runs for `domain`.
    pub(crate) async fn site_lock(&self, domain: &Domain) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut sites = self
                .sites
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Arc::clone(sites.entry(domain.to_string()).or_default())
        };
        lock.lock_owned().await
    }

    /// One of the [`MAX_CONCURRENT_ORDERS`] slots for talking to the outside.
    pub(crate) async fn order_slot(&self) -> Result<tokio::sync::SemaphorePermit<'_>> {
        self.orders
            .acquire()
            .await
            .map_err(|_| Error::Internal("the certificate order queue is closed".into()))
    }

    /// The virtual host and its tenant, which must be ready. A suspended
    /// tenant qualifies: installing or removing a certificate is an
    /// operator's action and changes nothing the tenant can use meanwhile.
    pub(crate) fn load(&self, domain: &Domain) -> Result<(TenantRecord, VHostRecord)> {
        let vhost = self
            .ctx
            .store
            .load_vhost(domain)?
            .ok_or_else(|| Error::VHostNotFound(domain.to_string()))?;
        let name = Username::parse_field(&vhost.tenant, "tenant")?;
        let tenant = self
            .ctx
            .store
            .load_tenant(&name)?
            .ok_or_else(|| Error::TenantNotFound(name.to_string()))?;
        if tenant.state != TenantState::Ready {
            return Err(Error::TenantNotReady(name.to_string()));
        }
        Ok((tenant, vhost))
    }

    /// Like [`Self::load`], for requesting certificates: not for suspended tenants.
    fn load_active(&self, domain: &Domain) -> Result<(TenantRecord, VHostRecord)> {
        let (tenant, vhost) = self.load(domain)?;
        if tenant.suspended {
            return Err(Error::TenantNotReady(tenant.username));
        }
        Ok((tenant, vhost))
    }

    /// Install a certificate chain and its key for a virtual host. Returns
    /// the record and whether anything changed.
    pub async fn install(&self, req: CertificateUpload) -> Result<(VHostRecord, bool)> {
        let domain = Domain::parse(&req.domain)?;
        if req.chain_pem.len() > MAX_CHAIN_BYTES {
            return Err(Error::invalid("certificate_chain_pem", "is too large"));
        }
        if req.key_pem.len() > MAX_KEY_BYTES {
            return Err(Error::invalid("private_key_pem", "is too large"));
        }
        let chain = normalise_pem(&req.chain_pem, PemKind::Chain)?;
        let key = normalise_pem(&req.key_pem, PemKind::Key)?;

        let _guard = self.ctx.lock.lock().await;
        let (tenant, vhost) = self.load(&domain)?;
        if !self.ctx.sys.is_installed(bin::OPENSSL).await {
            return Err(Error::TlsUnavailable);
        }
        install_material(
            &self.ctx,
            &tenant,
            vhost,
            &chain,
            &key,
            CertSource::Uploaded,
        )
        .await
    }

    /// Remove a virtual host's certificate and key. Returns the record and
    /// whether there was a certificate.
    pub async fn remove(&self, domain: &str) -> Result<(VHostRecord, bool)> {
        let domain = Domain::parse(domain)?;
        let _guard = self.ctx.lock.lock().await;
        let (tenant, vhost) = self.load(&domain)?;
        if vhost.tls.is_none() {
            // Completes an earlier removal that was interrupted.
            remove_material(&self.ctx, &domain)?;
            return Ok((vhost, false));
        }
        let cfg = &self.ctx.config;
        let mut rec = vhost.clone();
        rec.tls = None;
        self.ctx.store.save_vhost(&rec)?;
        // Nginx must stop using the files before they go.
        let block = vhost::render_vhost(cfg, &tenant, &rec)?;
        let installed = nginx::install_config(
            self.ctx.sys.as_ref(),
            &rec.config_path,
            &block,
            cfg.command_timeout,
        )
        .await;
        if let Err(e) = installed {
            if matches!(e, Error::NginxInvalid(_)) {
                self.ctx.store.save_vhost(&vhost)?;
            }
            return Err(e);
        }
        remove_material(&self.ctx, &domain)?;
        info!(%domain, tenant = %rec.tenant, "certificate removed");
        Ok((rec, true))
    }

    /// Request a certificate for the virtual host's domain and aliases from
    /// the ACME certificate authority and install it.
    ///
    /// The mutation lock is held while the key and signing request are made
    /// and again while the result is installed, but not while the ACME client
    /// runs: that takes as long as the certificate authority does, and
    /// touches nothing but its own directories.
    pub async fn request(&self, domain: &str) -> Result<AcmeOutcome> {
        let domain = Domain::parse(domain)?;
        let _site = self.site_lock(&domain).await;
        self.order(&domain, None).await
    }

    /// Order a certificate for `names` (default: the domain and every alias)
    /// and install it. The caller holds the site's lock.
    pub(crate) async fn order(
        &self,
        domain: &Domain,
        names: Option<&[Domain]>,
    ) -> Result<AcmeOutcome> {
        let domain = domain.clone();
        let names = {
            let _guard = self.ctx.lock.lock().await;
            let (_, vhost) = self.load_active(&domain)?;
            acme::preflight(&self.ctx).await?;
            let names = match names {
                Some(n) => n.to_vec(),
                None => acme::server_names(&vhost)?,
            };
            acme::prepare(&self.ctx, &domain, &names).await?;
            names
        };
        let ran = {
            let _slot = self.order_slot().await?;
            acme::run_client(&self.ctx, &domain, &names).await
        };

        let _guard = self.ctx.lock.lock().await;
        let finished = match ran {
            Ok((true, output)) => self.finish(&domain, output).await,
            Ok((false, output)) => self.load(&domain).map(|(_, vhost)| AcmeOutcome {
                succeeded: false,
                output,
                vhost,
            }),
            Err(e) => Err(e),
        };
        // Whatever happened: no key, request or reply is left lying around.
        acme::discard(&self.ctx, &domain)?;
        let outcome = finished?;
        info!(%domain, succeeded = outcome.succeeded, "certificate request finished");
        Ok(outcome)
    }

    /// Validate and install what the ACME client delivered. The reply is
    /// checked exactly like an uploaded certificate: the client runs outside
    /// the daemon and is not trusted to have got it right.
    async fn finish(&self, domain: &Domain, mut output: String) -> Result<AcmeOutcome> {
        let (tenant, vhost) = self.load_active(domain)?;
        let key = fsutil::read_optional(&pending_key_path(&self.ctx.config.tls_dir, domain))?
            .and_then(|k| String::from_utf8(k).ok())
            .ok_or_else(|| Error::Internal("the key of the pending request is gone".into()))?;
        let installed = match acme::read_issued(&self.ctx, domain)? {
            None => Err(Error::CertificateInvalid(
                "the ACME client delivered no certificate".into(),
            )),
            Some(reply) => match normalise_pem(&reply, PemKind::Chain) {
                Ok(chain) => {
                    install_material(
                        &self.ctx,
                        &tenant,
                        vhost.clone(),
                        &chain,
                        &key,
                        CertSource::Acme,
                    )
                    .await
                }
                Err(e) => Err(e),
            },
        };
        match installed {
            Ok((vhost, _)) => Ok(AcmeOutcome {
                succeeded: true,
                output,
                vhost,
            }),
            // A reply we refuse is a failed request, not a failed RPC.
            Err(e @ (Error::CertificateInvalid(_) | Error::InvalidInput { .. })) => {
                warn!(%domain, error = %e, "issued certificate refused");
                if !output.is_empty() && !output.ends_with('\n') {
                    output.push('\n');
                }
                output.push_str("the issued certificate was not installed: ");
                output.push_str(&e.to_string());
                Ok(AcmeOutcome {
                    succeeded: false,
                    output,
                    vhost,
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Renew every ACME certificate that expires within the configured time.
    /// Sites of suspended tenants are skipped; they are caught up with after
    /// the tenant is resumed. One failure does not stop the others.
    pub async fn renew_due(&self) -> Result<Vec<Renewal>> {
        let deadline = now_unix().saturating_add(self.ctx.config.acme_renew_before.as_secs());
        let active: Vec<String> = self
            .ctx
            .store
            .list_tenants()?
            .into_iter()
            .filter(|t| t.state == TenantState::Ready && !t.suspended)
            .map(|t| t.username)
            .collect();
        let due: Vec<String> = self
            .ctx
            .store
            .list_vhosts()?
            .into_iter()
            .filter(|v| {
                active.contains(&v.tenant)
                    && v.tls.as_ref().is_some_and(|t| {
                        t.source == CertSource::Acme && t.not_after_unix <= deadline
                    })
            })
            .map(|v| v.domain)
            .collect();
        let mut renewals = Vec::with_capacity(due.len());
        for domain in due {
            // Sites under Automatic HTTPS renew through it: names that no
            // longer validate are left out instead of failing the renewal.
            let renewed = match Domain::parse(&domain) {
                Ok(d) if self.auto_https_applies(&d)? => self.auto_https_renew(&d).await,
                _ => self.request(&domain).await,
            };
            let (succeeded, output) = match renewed {
                Ok(outcome) => (outcome.succeeded, outcome.output),
                Err(e) => {
                    warn!(%domain, error = %e, "certificate renewal failed");
                    // Redacted exactly as an RPC error would be.
                    (false, tonic::Status::from(e).message().to_owned())
                }
            };
            renewals.push(Renewal {
                domain,
                succeeded,
                output,
            });
        }
        Ok(renewals)
    }
}

/// Have OpenSSL examine the material in a staging area and check what the
/// daemon itself is responsible for: the name and the validity period.
async fn verify_material(ctx: &Ctx, domain: &Domain, chain: &str, key: &str) -> Result<CertInfo> {
    let (cert_file, key_file) = staged_paths(&ctx.config.tls_dir, domain);
    fsutil::write_atomic(&cert_file, chain.as_bytes(), KEY_MODE)?;
    fsutil::write_atomic(&key_file, key.as_bytes(), KEY_MODE)?;
    let examined = async {
        let info = inspect(ctx, &cert_file).await?;
        check_pair(ctx, &cert_file, &key_file).await?;
        Ok::<_, Error>(info)
    }
    .await;
    fsutil::remove_if_exists(&cert_file)?;
    fsutil::remove_if_exists(&key_file)?;
    let info = examined?;
    let now = now_unix();
    if now < info.not_before_unix {
        return Err(Error::CertificateInvalid(format!(
            "the certificate is not valid before {}",
            format_utc(info.not_before_unix)
        )));
    }
    if now >= info.not_after_unix {
        return Err(Error::CertificateInvalid(format!(
            "the certificate expired on {}",
            format_utc(info.not_after_unix)
        )));
    }
    if !covers(&info.names, domain.as_str()) {
        return Err(Error::CertificateInvalid(format!(
            "the certificate is not valid for {domain} (its names: {})",
            if info.names.is_empty() {
                "none".to_owned()
            } else {
                info.names.join(", ")
            }
        )));
    }
    Ok(info)
}

/// Verify, record, write and activate a certificate for `vhost`. The caller
/// holds the mutation lock. Returns the new record and whether anything changed.
async fn install_material(
    ctx: &Ctx,
    tenant: &TenantRecord,
    vhost: VHostRecord,
    chain: &str,
    key: &str,
    source: CertSource,
) -> Result<(VHostRecord, bool)> {
    let domain = Domain::parse(&vhost.domain)?;
    let dir = &ctx.config.tls_dir;
    fsutil::ensure_dir(dir, DIR_MODE)?;
    let info = verify_material(ctx, &domain, chain, key).await?;
    let previous = Previous {
        cert: fsutil::read_optional(&cert_path(dir, &domain))?,
        key: fsutil::read_optional(&key_path(dir, &domain))?,
        record: vhost,
    };
    let installed_at_unix = match &previous.record.tls {
        Some(t) if t.chain_pem == chain => t.installed_at_unix,
        _ => now_unix(),
    };
    let mut rec = previous.record.clone();
    rec.tls = Some(TlsRecord {
        source,
        issuer: info.issuer,
        not_before_unix: info.not_before_unix,
        not_after_unix: info.not_after_unix,
        names: info.names,
        chain_pem: chain.to_owned(),
        installed_at_unix,
    });
    let record_changed = rec != previous.record;
    if record_changed {
        ctx.store.save_vhost(&rec)?;
    }
    let changed = activate(ctx, tenant, &rec, key, &previous).await? || record_changed;
    if changed {
        info!(%domain, tenant = %rec.tenant, source = ?source, not_after = %format_utc(rec.tls.as_ref().map_or(0, |t| t.not_after_unix)), "certificate installed");
    }
    Ok((rec, changed))
}

/// Write the certificate and key files of `rec` and make Nginx use them.
/// Anything Nginx refuses is undone; a reload that fails leaves everything in
/// place, and repeating the request completes it (which is why Nginx is
/// reloaded even when nothing on disk changed).
async fn activate(
    ctx: &Ctx,
    tenant: &TenantRecord,
    rec: &VHostRecord,
    key: &str,
    previous: &Previous,
) -> Result<bool> {
    let cfg = &ctx.config;
    let timeout = cfg.command_timeout;
    let domain = Domain::parse(&rec.domain)?;
    let chain = rec.tls.as_ref().map_or("", |t| t.chain_pem.as_str());
    let written = (|| {
        let cert = fsutil::write_atomic(
            &cert_path(&cfg.tls_dir, &domain),
            chain.as_bytes(),
            CERT_MODE,
        )?;
        let key = fsutil::write_atomic(&key_path(&cfg.tls_dir, &domain), key.as_bytes(), KEY_MODE)?;
        let block = vhost::render_vhost(cfg, tenant, rec)?;
        Ok::<_, Error>((cert || key, block))
    })();
    let (files_changed, block) = match written {
        Ok(w) => w,
        Err(e) => {
            previous.restore(ctx, &domain)?;
            return Err(e);
        }
    };
    let conf_changed =
        match nginx::install_config(ctx.sys.as_ref(), &rec.config_path, &block, timeout).await {
            Ok(changed) => changed,
            Err(e) => {
                if matches!(e, Error::NginxInvalid(_)) {
                    previous.restore(ctx, &domain)?;
                }
                return Err(e);
            }
        };
    if !conf_changed {
        if let Err(output) = nginx::test_config(ctx.sys.as_ref(), timeout).await? {
            warn!(%domain, %output, "nginx rejected the certificate; rolling back");
            previous.restore(ctx, &domain)?;
            return Err(Error::NginxInvalid(output));
        }
        nginx::reload(ctx.sys.as_ref(), timeout).await?;
    }
    Ok(files_changed || conf_changed)
}

/// Delete everything kept for `domain`'s certificate: the files Nginx used,
/// anything staged, and what a certificate request left behind. For removing
/// a certificate or its virtual host, after Nginx has stopped using the files.
pub(crate) fn remove_material(ctx: &Ctx, domain: &Domain) -> Result<()> {
    let dir = &ctx.config.tls_dir;
    let (staged_cert, staged_key) = staged_paths(dir, domain);
    for path in [
        cert_path(dir, domain),
        key_path(dir, domain),
        staged_cert,
        staged_key,
    ] {
        fsutil::remove_if_exists(&path)?;
    }
    acme::discard(ctx, domain)
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::config::Config;
    use crate::host::{DriftKind, HostService};
    use crate::system::fake_tls::{fake_certificate, fake_private_key, FAKE_ACME_ISSUER};
    use crate::system::{FakeSystem, OsUser};
    use crate::tenant::TenantService;
    use crate::validate::Limits;
    use crate::vhost::{VHostRequest, VHostService};
    use std::os::unix::fs::PermissionsExt as _;

    const DAY: u64 = 86_400;

    pub(crate) struct Harness {
        pub(crate) _dir: tempfile::TempDir,
        pub(crate) sys: Arc<FakeSystem>,
        pub(crate) ctx: Ctx,
        pub(crate) tls: TlsService,
        pub(crate) vhosts: VHostService,
        pub(crate) tenants: TenantService,
    }

    impl Harness {
        pub(crate) fn cfg(&self) -> &Config {
            &self.ctx.config
        }
        pub(crate) fn conf(&self, domain: &str) -> String {
            let d = Domain::parse(domain).unwrap();
            std::fs::read_to_string(nginx::conf_path(&self.cfg().nginx_conf_dir, &d)).unwrap()
        }
        pub(crate) fn cert_file(&self, domain: &str) -> PathBuf {
            cert_path(&self.cfg().tls_dir, &Domain::parse(domain).unwrap())
        }
        pub(crate) fn key_file(&self, domain: &str) -> PathBuf {
            key_path(&self.cfg().tls_dir, &Domain::parse(domain).unwrap())
        }
        pub(crate) fn record(&self, domain: &str) -> VHostRecord {
            self.ctx
                .store
                .load_vhost(&Domain::parse(domain).unwrap())
                .unwrap()
                .unwrap()
        }
    }

    pub(crate) async fn harness() -> Harness {
        harness_with(|_| {}).await
    }

    /// The harness with `adjust` applied to the configuration.
    pub(crate) async fn harness_with(adjust: impl FnOnce(&mut Config)) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        let mut cfg = Config::default();
        cfg.state_dir = p.join("state");
        cfg.home_base = p.join("home");
        cfg.systemd_unit_dir = p.join("systemd");
        cfg.nginx_log_dir = p.join("log");
        cfg.php_conf_dir = p.join("php");
        cfg.nginx_conf_dir = p.join("nginx").join("oxpanel.d");
        cfg.nginx_include_file = p.join("nginx").join("conf.d").join("00-oxpanel.conf");
        cfg.tls_dir = p.join("pki");
        cfg.acme_dir = p.join("acme");
        cfg.sftp_keys_dir = p.join("sftp-keys");
        cfg.sshd_dropin_file = p.join("sshd_config.d").join("60-oxpanel.conf");
        cfg.socket_path = p.join("run").join("oxpanel.sock");
        adjust(&mut cfg);
        for d in [
            cfg.home_base.clone(),
            cfg.systemd_unit_dir.clone(),
            p.join("nginx").join("conf.d"),
            p.join("sshd_config.d"),
            cfg.acme_dir.join("account"),
            cfg.acme_dir.join("challenges"),
            cfg.acme_dir.join("csr"),
            cfg.acme_dir.join("issued"),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        let sys = Arc::new(FakeSystem::new());
        sys.add_user(OsUser {
            name: acme::ACME_USER.into(),
            uid: 990,
            gid: 990,
            home: "/".into(),
            shell: "/sbin/nologin".into(),
        });
        let ctx = Ctx::new(cfg, sys.clone(), false);
        ctx.store.init().unwrap();
        let tenants = TenantService::new(ctx.clone());
        tenants
            .create("alice", Limits::default(), "")
            .await
            .unwrap();
        let vhosts = VHostService::new(ctx.clone());
        vhosts
            .configure(VHostRequest {
                domain: "example.com".into(),
                tenant: "alice".into(),
                aliases: vec!["www.example.com".into(), "shop.example.net".into()],
                ..VHostRequest::default()
            })
            .await
            .unwrap();
        // As the daemon does at start: the sshd drop-in is in place.
        crate::sftp::converge_all(&ctx).await.unwrap();
        sys.clear_calls();
        Harness {
            _dir: dir,
            sys,
            tls: TlsService::new(ctx.clone()),
            ctx,
            vhosts,
            tenants,
        }
    }

    /// A virtual-host record that exists only in memory.
    pub(crate) fn bare_vhost(domain: &str, aliases: &[&str]) -> VHostRecord {
        VHostRecord {
            version: crate::records::RECORD_VERSION,
            domain: domain.into(),
            tenant: "alice".into(),
            document_root: "public_html".into(),
            aliases: aliases.iter().map(|a| (*a).to_owned()).collect(),
            config_path: PathBuf::from("/x.conf"),
            created_at_unix: 0,
            php: false,
            app: None,
            redirect_https: false,
            hsts: false,
            tls: None,
            auto_https: crate::records::AutoHttpsChoice::On,
        }
    }

    pub(crate) fn upload(chain: &str, key: &str) -> CertificateUpload {
        CertificateUpload {
            domain: "example.com".into(),
            chain_pem: chain.into(),
            key_pem: key.into(),
        }
    }

    /// A certificate for key `k1`, valid now, for example.com and www.
    pub(crate) fn good_cert() -> String {
        let now = now_unix();
        fake_certificate(
            "k1",
            "CN=Test CA,O=Test",
            now - DAY,
            now + 60 * DAY,
            &["example.com", "*.example.com"],
        )
    }

    pub(crate) fn args(c: &CommandSpec) -> Vec<String> {
        c.args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    pub(crate) fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// No command line may ever carry key material.
    pub(crate) fn assert_no_key_in_argv(h: &Harness) {
        for c in h.sys.calls() {
            for a in args(&c) {
                assert!(!a.contains("PRIVATE KEY"), "key material in argv: {a}");
                assert!(!a.contains("ZmFrZS1rZXk"), "key material in argv: {a}");
            }
        }
    }

    #[test]
    fn pem_is_normalised_and_foreign_blocks_are_refused() {
        let key = "Bag Attributes\n  localKeyID: 01\n-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n-----BEGIN EC PRIVATE KEY-----\n  QUJD\nREVG  \n-----END EC PRIVATE KEY-----\ntrailing junk\n";
        assert_eq!(
            normalise_pem(key, PemKind::Key).unwrap(),
            "-----BEGIN EC PRIVATE KEY-----\nQUJDREVG\n-----END EC PRIVATE KEY-----\n"
        );
        let long = "A".repeat(100);
        let chain = format!(
            "-----BEGIN CERTIFICATE-----\n{long}\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n"
        );
        let n = normalise_pem(&chain, PemKind::Chain).unwrap();
        assert!(n.starts_with(&format!(
            "-----BEGIN CERTIFICATE-----\n{}\n{}\n-----END",
            &long[..64],
            &long[64..]
        )));
        assert_eq!(n.matches("BEGIN CERTIFICATE").count(), 2);

        let enc =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nQQ==\n-----END ENCRYPTED PRIVATE KEY-----\n";
        let legacy = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nQQ==\n-----END RSA PRIVATE KEY-----\n";
        let two = "-----BEGIN PRIVATE KEY-----\nQQ==\n-----END PRIVATE KEY-----\n-----BEGIN PRIVATE KEY-----\nQQ==\n-----END PRIVATE KEY-----\n";
        let cert_as_key = "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n";
        for bad in [enc, legacy, two, cert_as_key, "", "no pem here"] {
            assert!(normalise_pem(bad, PemKind::Key).is_err(), "{bad:?}");
        }
        let key_in_chain =
            format!("{chain}-----BEGIN PRIVATE KEY-----\nQQ==\n-----END PRIVATE KEY-----\n");
        let unclosed = "-----BEGIN CERTIFICATE-----\nQQ==\n";
        let mismatched = "-----BEGIN CERTIFICATE-----\nQQ==\n-----END X509 CRL-----\n";
        let empty = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n";
        let directive =
            "-----BEGIN CERTIFICATE-----\nQQ==; include /etc/shadow\n-----END CERTIFICATE-----\n";
        let nine = "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n".repeat(9);
        for bad in [
            key_in_chain.as_str(),
            unclosed,
            mismatched,
            empty,
            directive,
            &nine,
        ] {
            assert!(normalise_pem(bad, PemKind::Chain).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn dates_round_trip() {
        assert_eq!(parse_utc("1970-01-01 00:00:00Z"), Some(0));
        assert_eq!(parse_utc("2000-03-01 00:00:00Z"), Some(951_868_800));
        assert_eq!(
            parse_utc("2026-11-13 12:34:56Z").map(format_utc).as_deref(),
            Some("2026-11-13 12:34:56Z")
        );
        for bad in [
            "",
            "Nov 13 12:00:00 2026 GMT",
            "1969-12-31 23:59:59Z",
            "2026-13-01 00:00:00Z",
            "2026-11-13 12:00:00",
        ] {
            assert_eq!(parse_utc(bad), None, "{bad}");
        }
    }

    #[test]
    fn wildcards_cover_exactly_one_label() {
        let names = vec!["example.com".to_owned(), "*.example.com".to_owned()];
        assert!(covers(&names, "example.com"));
        assert!(covers(&names, "www.example.com"));
        assert!(!covers(&names, "a.b.example.com"));
        assert!(!covers(&names, "example.net"));
        assert!(!covers(&names, "badexample.com"));
        assert_eq!(
            parse_san("X509v3 Subject Alternative Name: \n    DNS:Example.com, IP Address:127.0.0.1, DNS:*.example.com, DNS:bad;name\n"),
            vec!["*.example.com".to_owned(), "example.com".to_owned()]
        );
    }

    /// The site is served on 443 with its files, with defaults for redirect and HSTS.
    fn assert_https_block(h: &Harness) {
        let conf = h.conf("example.com");
        assert!(conf.contains("listen 443 ssl http2;\n    listen [::]:443 ssl http2;"));
        assert!(conf.contains(&format!(
            "ssl_certificate {};",
            h.cert_file("example.com").display()
        )));
        assert!(conf.contains(&format!(
            "ssl_certificate_key {};",
            h.key_file("example.com").display()
        )));
        assert!(conf.contains("ssl_protocols TLSv1.2 TLSv1.3;"));
        assert!(
            !conf.contains("Strict-Transport-Security"),
            "HSTS is off by default"
        );
        assert!(!conf.contains("return 301"), "no redirect unless asked");
        assert_eq!(
            conf.matches("root ").count(),
            2,
            "the site is served on both ports"
        );
        assert_eq!(h.sys.calls_to(bin::NGINX).len(), 1);
    }

    #[tokio::test]
    async fn install_verifies_with_openssl_writes_root_only_key_and_serves_https() -> Result<()> {
        let h = harness().await;
        let (rec, changed) = h
            .tls
            .install(upload(&good_cert(), &fake_private_key("k1")))
            .await?;
        assert!(changed);
        let tls = rec.tls.as_ref().unwrap();
        assert_eq!(tls.source, CertSource::Uploaded);
        assert_eq!(tls.issuer, "CN=Test CA,O=Test");
        assert_eq!(tls.names, vec!["*.example.com", "example.com"]);
        assert_eq!(uncovered_names(&rec), vec!["shop.example.net"]);

        // OpenSSL saw paths of staged files, never the material itself.
        let dir = &h.cfg().tls_dir;
        let staged_cert = dir
            .join("example.com.crt.new")
            .to_string_lossy()
            .into_owned();
        let staged_key = dir
            .join("example.com.key.new")
            .to_string_lossy()
            .into_owned();
        let calls: Vec<Vec<String>> = h.sys.calls_to(bin::OPENSSL).iter().map(args).collect();
        assert_eq!(
            calls,
            vec![
                vec![
                    "x509".to_owned(),
                    "-in".into(),
                    staged_cert.clone(),
                    "-noout".into(),
                    "-issuer".into(),
                    "-startdate".into(),
                    "-enddate".into(),
                    "-nameopt".into(),
                    "RFC2253".into(),
                    "-dateopt".into(),
                    "iso_8601".into()
                ],
                vec![
                    "x509".to_owned(),
                    "-in".into(),
                    staged_cert.clone(),
                    "-noout".into(),
                    "-ext".into(),
                    "subjectAltName".into()
                ],
                vec![
                    "x509".to_owned(),
                    "-in".into(),
                    staged_cert,
                    "-noout".into(),
                    "-pubkey".into()
                ],
                vec![
                    "pkey".to_owned(),
                    "-in".into(),
                    staged_key,
                    "-pubout".into(),
                    "-passin".into(),
                    "pass:".into()
                ],
            ]
        );
        assert_no_key_in_argv(&h);
        assert!(
            !dir.join("example.com.key.new").exists(),
            "staging is cleaned up"
        );
        assert_eq!(mode(dir), 0o700);
        assert_eq!(mode(&h.key_file("example.com")), 0o600);
        assert_eq!(mode(&h.cert_file("example.com")), 0o644);
        assert_eq!(
            std::fs::read_to_string(h.cert_file("example.com")).unwrap(),
            tls.chain_pem
        );

        // The key is nowhere in the record.
        let record =
            std::fs::read_to_string(h.cfg().state_dir.join("vhosts").join("example.com.json"))
                .unwrap();
        assert!(!record.contains("PRIVATE KEY") && !record.contains("ZmFrZS1rZXk"));

        assert_https_block(&h);

        // Same material again: nothing changes, Nginx is still made current.
        h.sys.clear_calls();
        let (_, changed) = h
            .tls
            .install(upload(&good_cert(), &fake_private_key("k1")))
            .await?;
        assert!(!changed);
        assert_eq!(
            h.record("example.com").tls.unwrap().installed_at_unix,
            tls.installed_at_unix
        );
        Ok(())
    }

    #[tokio::test]
    async fn unusable_certificates_are_refused_before_anything_changes() -> Result<()> {
        let h = harness().await;
        let now = now_unix();
        let cases = [
            (good_cert(), fake_private_key("other"), "does not belong"),
            (
                fake_certificate("k1", "CN=CA", now - 90 * DAY, now - DAY, &["example.com"]),
                fake_private_key("k1"),
                "expired",
            ),
            (
                fake_certificate("k1", "CN=CA", now + DAY, now + 90 * DAY, &["example.com"]),
                fake_private_key("k1"),
                "not valid before",
            ),
            (
                fake_certificate("k1", "CN=CA", now - DAY, now + 90 * DAY, &["other.org"]),
                fake_private_key("k1"),
                "not valid for example.com",
            ),
            (
                fake_certificate("k1", "CN=CA", now - DAY, now + 90 * DAY, &[]),
                fake_private_key("k1"),
                "its names: none",
            ),
        ];
        for (cert, key, why) in cases {
            let err = h.tls.install(upload(&cert, &key)).await.unwrap_err();
            assert!(matches!(err, Error::CertificateInvalid(_)), "{err}");
            assert!(err.to_string().contains(why), "{err} / {why}");
            // A client error: the message reaches the caller.
            assert_eq!(
                tonic::Status::from(err).code(),
                tonic::Code::InvalidArgument
            );
        }
        assert!(h.record("example.com").tls.is_none());
        assert!(!h.cert_file("example.com").exists() && !h.key_file("example.com").exists());
        assert_eq!(
            std::fs::read_dir(&h.cfg().tls_dir).unwrap().count(),
            0,
            "nothing staged is left"
        );
        assert!(!h.conf("example.com").contains("443"));
        assert!(
            h.sys.calls_to(bin::SYSTEMCTL).is_empty(),
            "Nginx was never reloaded"
        );

        // Malformed input never reaches OpenSSL.
        h.sys.clear_calls();
        let enc =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nQQ==\n-----END ENCRYPTED PRIVATE KEY-----\n";
        assert!(matches!(
            h.tls.install(upload(&good_cert(), enc)).await,
            Err(Error::InvalidInput { .. })
        ));
        assert!(matches!(
            h.tls
                .install(upload(&"x".repeat(MAX_CHAIN_BYTES + 1), ""))
                .await,
            Err(Error::InvalidInput { .. })
        ));
        assert!(matches!(
            h.tls
                .install(CertificateUpload {
                    domain: "nosuch.example".into(),
                    ..upload(&good_cert(), &fake_private_key("k1"))
                })
                .await,
            Err(Error::VHostNotFound(_))
        ));
        assert!(h.sys.calls_to(bin::OPENSSL).is_empty());

        // Without OpenSSL nothing can be checked, so nothing is accepted.
        h.sys.set_missing(bin::OPENSSL);
        assert!(matches!(
            h.tls
                .install(upload(&good_cert(), &fake_private_key("k1")))
                .await,
            Err(Error::TlsUnavailable)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn a_certificate_nginx_rejects_is_rolled_back() -> Result<()> {
        let h = harness().await;
        h.tls
            .install(upload(&good_cert(), &fake_private_key("k1")))
            .await?;
        let before = h.record("example.com");
        let conf_before = h.conf("example.com");
        let now = now_unix();
        let replacement = fake_certificate(
            "k2",
            "CN=Other CA",
            now - DAY,
            now + 30 * DAY,
            &["example.com"],
        );
        // A different key changes only the files, not the configuration:
        // the explicit `nginx -t` must catch it.
        h.sys.script_failure(
            bin::NGINX,
            1,
            "nginx: [emerg] SSL_CTX_use_PrivateKey failed",
        );
        let err = h
            .tls
            .install(upload(&replacement, &fake_private_key("k2")))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::NginxInvalid(_)), "{err}");
        assert_eq!(h.record("example.com"), before);
        assert_eq!(h.conf("example.com"), conf_before);
        assert_eq!(
            std::fs::read_to_string(h.cert_file("example.com")).unwrap(),
            before.tls.unwrap().chain_pem
        );
        assert_eq!(
            std::fs::read_to_string(h.key_file("example.com")).unwrap(),
            normalise_pem(&fake_private_key("k1"), PemKind::Key)?
        );
        Ok(())
    }

    #[tokio::test]
    async fn redirect_hsts_and_reconfiguration_keep_the_certificate() -> Result<()> {
        let h = harness().await;
        h.tls
            .install(upload(&good_cert(), &fake_private_key("k1")))
            .await?;
        let (rec, changed) = h
            .vhosts
            .configure(VHostRequest {
                domain: "example.com".into(),
                tenant: "alice".into(),
                aliases: vec!["www.example.com".into(), "shop.example.net".into()],
                redirect_https: true,
                hsts: true,
                ..VHostRequest::default()
            })
            .await?;
        assert!(changed);
        assert!(rec.tls.is_some(), "reconfiguring keeps the certificate");
        let conf = h.conf("example.com");
        let (http, https) = conf.split_once("listen 443").unwrap();
        assert!(http.contains("return 301 https://$host$request_uri;"));
        assert!(
            http.contains("location ^~ /.well-known/acme-challenge/"),
            "challenges still answered over HTTP"
        );
        assert!(
            !http.contains("root "),
            "HTTP serves nothing from the site while redirecting"
        );
        assert!(
            !http.contains("Strict-Transport-Security"),
            "HSTS only over HTTPS"
        );
        assert!(https.contains("add_header Strict-Transport-Security \"max-age=31536000\" always;"));
        assert!(!https.contains("return 301"));
        assert!(!https.contains("acme-challenge"));
        Ok(())
    }

    #[tokio::test]
    async fn suspension_and_removal() -> Result<()> {
        let h = harness().await;
        h.tls
            .install(upload(&good_cert(), &fake_private_key("k1")))
            .await?;
        h.tenants.set_suspended("alice", true).await?;
        let conf = h.conf("example.com");
        assert_eq!(conf.matches("return 503;").count(), 2, "503 on both ports");
        assert!(
            conf.contains("ssl_certificate "),
            "with its own certificate, not an error page"
        );
        assert!(
            !conf.contains("acme-challenge"),
            "a suspended site answers no challenges"
        );
        assert!(!conf.contains("root "));
        // An operator may still replace or remove the certificate; nobody may request one.
        assert!(matches!(
            h.tls.request("example.com").await,
            Err(Error::TenantNotReady(_))
        ));
        assert!(h.sys.calls_to(bin::SYSTEMD_RUN).is_empty());
        h.tenants.set_suspended("alice", false).await?;

        let (rec, removed) = h.tls.remove("example.com").await?;
        assert!(removed && rec.tls.is_none());
        assert!(!h.conf("example.com").contains("443"));
        assert!(!h.cert_file("example.com").exists() && !h.key_file("example.com").exists());
        let (_, removed) = h.tls.remove("example.com").await?;
        assert!(!removed);

        // Removing the site removes its certificate.
        h.tls
            .install(upload(&good_cert(), &fake_private_key("k1")))
            .await?;
        assert!(h.vhosts.remove("example.com").await?);
        assert!(!h.cert_file("example.com").exists() && !h.key_file("example.com").exists());
        assert_eq!(std::fs::read_dir(&h.cfg().tls_dir).unwrap().count(), 0);
        Ok(())
    }

    /// The `systemd-run` argument vector for example.com's certificate request.
    fn expected_client_argv(acme_dir: &Path) -> Vec<String> {
        let acme = acme_dir.to_string_lossy().into_owned();
        let mut expected: Vec<String> = [
            "--wait",
            "--collect",
            "--quiet",
            "--unit=oxpanel-acme-example.com",
        ]
        .map(String::from)
        .to_vec();
        for p in [
            "User=oxpanel-acme".to_owned(),
            "Group=oxpanel-acme".into(),
            "RuntimeMaxSec=240".into(),
            format!("ReadWritePaths={acme}/account {acme}/challenges {acme}/issued"),
            "UMask=0022".into(),
            "NoNewPrivileges=yes".into(),
            "CapabilityBoundingSet=".into(),
            "AmbientCapabilities=".into(),
            "PrivateTmp=yes".into(),
            "PrivateDevices=yes".into(),
            "ProtectSystem=strict".into(),
            "ProtectHome=yes".into(),
            "ProtectKernelTunables=yes".into(),
            "ProtectKernelModules=yes".into(),
            "ProtectKernelLogs=yes".into(),
            "ProtectControlGroups=yes".into(),
            "ProtectClock=yes".into(),
            "ProtectHostname=yes".into(),
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX".into(),
            "RestrictNamespaces=yes".into(),
            "RestrictRealtime=yes".into(),
            "RestrictSUIDSGID=yes".into(),
            "LockPersonality=yes".into(),
            "MemoryDenyWriteExecute=yes".into(),
            "SystemCallArchitectures=native".into(),
        ] {
            expected.push("--property".into());
            expected.push(p);
        }
        for a in [
            "--",
            bin::OXPANEL_ACME,
            "--directory",
            crate::config::DEFAULT_ACME_DIRECTORY_URL,
            "--account-dir",
            &format!("{acme}/account"),
            "--challenge-dir",
            &format!("{acme}/challenges"),
            "--csr",
            &format!("{acme}/csr/example.com.csr"),
            "--out",
            &format!("{acme}/issued/example.com.pem"),
            "--domain",
            "example.com",
            "--domain",
            "shop.example.net",
            "--domain",
            "www.example.com",
        ] {
            expected.push(a.to_owned());
        }
        expected
    }

    #[tokio::test]
    async fn acme_request_runs_the_client_unprivileged_and_never_shows_it_a_key() -> Result<()> {
        let h = harness().await;
        let outcome = h.tls.request("example.com").await?;
        assert!(outcome.succeeded, "{}", outcome.output);
        let tls = outcome.vhost.tls.as_ref().unwrap();
        assert_eq!(tls.source, CertSource::Acme);
        assert_eq!(tls.issuer, FAKE_ACME_ISSUER);
        assert_eq!(
            tls.names,
            vec!["example.com", "shop.example.net", "www.example.com"]
        );
        assert!(uncovered_names(&outcome.vhost).is_empty());

        let cfg = h.cfg();
        let pending = cfg
            .tls_dir
            .join("example.com.key.pending")
            .to_string_lossy()
            .into_owned();
        let openssl: Vec<Vec<String>> = h.sys.calls_to(bin::OPENSSL).iter().map(args).collect();
        assert_eq!(
            openssl[0],
            [
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256"
            ]
        );
        assert_eq!(
            openssl[1],
            [
                "req",
                "-new",
                "-key",
                &pending,
                "-subj",
                "/",
                "-addext",
                "subjectAltName=DNS:example.com,DNS:shop.example.net,DNS:www.example.com"
            ]
        );
        let run = h.sys.calls_to(bin::SYSTEMD_RUN);
        assert_eq!(run.len(), 1);
        assert_eq!(args(&run[0]), expected_client_argv(&cfg.acme_dir));
        assert!(
            run[0].run_as.is_none(),
            "systemd, not the daemon, drops to the ACME account"
        );
        assert_no_key_in_argv(&h);

        // The key moved into place; nothing of the request is left behind.
        assert_eq!(mode(&h.key_file("example.com")), 0o600);
        for leftover in [
            cfg.tls_dir.join("example.com.key.pending"),
            cfg.acme_dir.join("csr").join("example.com.csr"),
            cfg.acme_dir.join("issued").join("example.com.pem"),
        ] {
            assert!(!leftover.exists(), "{}", leftover.display());
        }
        assert!(h.conf("example.com").contains("listen 443 ssl"));
        Ok(())
    }

    #[tokio::test]
    async fn acme_failures_are_results_and_preflight_refuses_early() -> Result<()> {
        let h = harness().await;
        h.sys
            .script_failure(bin::SYSTEMD_RUN, 1, "no certificate: connection refused");
        let outcome = h.tls.request("example.com").await?;
        assert!(!outcome.succeeded);
        assert!(
            outcome.output.contains("connection refused"),
            "{}",
            outcome.output
        );
        assert!(outcome.vhost.tls.is_none());
        assert!(!h.cfg().tls_dir.join("example.com.key.pending").exists());

        // A delivered chain that cannot be used (here: already expired) is not installed.
        h.sys.set_acme_lifetime(0);
        let outcome = h.tls.request("example.com").await?;
        assert!(!outcome.succeeded);
        assert!(
            outcome.output.contains("was not installed"),
            "{}",
            outcome.output
        );
        assert!(h.record("example.com").tls.is_none());

        h.sys.clear_calls();
        std::fs::remove_dir(h.cfg().acme_dir.join("issued")).unwrap();
        let err = h.tls.request("example.com").await.unwrap_err();
        assert!(matches!(err, Error::AcmeUnavailable(_)), "{err}");
        assert_eq!(
            tonic::Status::from(err).code(),
            tonic::Code::FailedPrecondition
        );
        assert!(
            h.sys.calls_to(bin::OPENSSL).is_empty(),
            "refused before a key was made"
        );
        Ok(())
    }

    #[tokio::test]
    async fn only_due_acme_certificates_of_active_tenants_are_renewed() -> Result<()> {
        let h = harness().await;
        assert!(h.tls.renew_due().await?.is_empty());
        // Uploaded certificates are never renewed by the engine.
        let now = now_unix();
        h.tls
            .install(upload(
                &fake_certificate("k1", "CN=CA", now - DAY, now + DAY, &["example.com"]),
                &fake_private_key("k1"),
            ))
            .await?;
        assert!(h.tls.renew_due().await?.is_empty());

        h.sys.set_acme_lifetime(10 * DAY);
        assert!(h.tls.request("example.com").await?.succeeded);
        let first = h.record("example.com").tls.unwrap();
        h.tenants.set_suspended("alice", true).await?;
        assert!(
            h.tls.renew_due().await?.is_empty(),
            "suspended tenants wait"
        );
        h.tenants.set_suspended("alice", false).await?;

        h.sys.set_acme_lifetime(90 * DAY);
        let renewals = h.tls.renew_due().await?;
        assert_eq!(renewals.len(), 1);
        assert!(renewals[0].succeeded && renewals[0].domain == "example.com");
        let second = h.record("example.com").tls.unwrap();
        assert!(second.not_after_unix > first.not_after_unix);
        assert!(h.tls.renew_due().await?.is_empty(), "not due any more");
        Ok(())
    }

    #[tokio::test]
    async fn reconcile_covers_certificate_files() -> Result<()> {
        let h = harness().await;
        let host = HostService::new(h.ctx.clone());
        h.tls
            .install(upload(&good_cert(), &fake_private_key("k1")))
            .await?;
        assert!(host.reconcile().await?.is_empty());

        std::fs::write(h.cert_file("example.com"), "edited").unwrap();
        std::fs::set_permissions(
            h.key_file("example.com"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        std::fs::write(h.cfg().tls_dir.join("stray.key"), "x").unwrap();
        let drifts = host.reconcile().await?;
        let kinds: Vec<(DriftKind, String)> =
            drifts.iter().map(|d| (d.kind, d.subject.clone())).collect();
        assert_eq!(kinds.len(), 3, "{drifts:?}");
        assert_eq!(
            kinds
                .iter()
                .filter(|(k, s)| *k == DriftKind::TlsCertificateDrift && s == "example.com")
                .count(),
            2
        );
        assert!(kinds
            .iter()
            .any(|(k, s)| *k == DriftKind::OrphanTlsFile && s.ends_with("stray.key")));

        // Repeating the request heals it.
        std::fs::remove_file(h.cfg().tls_dir.join("stray.key")).unwrap();
        std::fs::remove_file(h.key_file("example.com")).unwrap();
        h.tls
            .install(upload(&good_cert(), &fake_private_key("k1")))
            .await?;
        assert!(host.reconcile().await?.is_empty());
        Ok(())
    }
}
