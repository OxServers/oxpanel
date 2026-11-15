//! Certificates for single host names that are not sites: the mail host
//! name and the webmail names ([`crate::mail`]), and the names host-level
//! consumers register ([`crate::host_certs`]). One machinery for all of them:
//!
//! - the unprivileged ACME client's reachability pre-check runs first, so a
//!   name that does not resolve to this host (or does not serve the probe)
//!   never reaches the authority ([`crate::acme::run_precheck`]);
//! - the key and signing request are made by the daemon, the client only
//!   sees the request; what it delivers is verified like an upload
//!   ([`crate::tls::verify_material`]);
//! - failures back off (1 h, 6 h, then daily, [`crate::auto_https::backoff_secs`]);
//! - a certificate is renewed once it expires within `acme_renew_before`;
//! - one sweep at a time over all of them ([`SWEEPING`]): each name's client
//!   runs in a transient unit named after the name.

use serde::{Deserialize, Serialize};

use crate::ctx::Ctx;
use crate::records::now_unix;
use crate::tls::CertInfo;
use crate::validate::Domain;

/// Mail and host-certificate sweeps never run at the same time (they could
/// share a name, and the client's unit and files are named after it).
pub static SWEEPING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Upper bound for a failure reason that is kept and shown.
const MAX_REASON_CHARS: usize = 300;

/// A name that failed and when it may be tried again.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backoff {
    pub failures: u32,
    pub next_attempt_unix: u64,
    pub reason: String,
}

impl Backoff {
    /// One more failure after `previous`, now.
    pub fn after(previous: Option<&Self>, why: &str) -> Self {
        let failures = previous.map_or(0, |b| b.failures).saturating_add(1);
        Self {
            failures,
            next_attempt_unix: now_unix().saturating_add(crate::auto_https::backoff_secs(failures)),
            reason: why
                .chars()
                .filter(|c| !c.is_control())
                .take(MAX_REASON_CHARS)
                .collect(),
        }
    }

    /// Whether it is still waiting.
    pub fn waiting(&self) -> bool {
        self.next_attempt_unix > now_unix()
    }
}

/// A verified certificate chain and its key, ready to be written.
#[derive(Clone)]
pub(crate) struct Material {
    pub chain: String,
    /// Never logged, never shown.
    pub key: String,
    pub info: CertInfo,
}

impl std::fmt::Debug for Material {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Material")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

/// What the certificate at `crt` (with its key at `key`) is, if both exist,
/// it covers `name` and it is not due for renewal.
pub(crate) async fn current(
    ctx: &Ctx,
    name: &Domain,
    crt: &std::path::Path,
    key: &std::path::Path,
) -> Option<CertInfo> {
    if !crt.exists() || !key.exists() {
        return None;
    }
    let due = now_unix().saturating_add(ctx.config.acme_renew_before.as_secs());
    crate::tls::inspect(ctx, crt)
        .await
        .ok()
        .filter(|i| i.not_after_unix > due && crate::tls::covers(&i.names, name.as_str()))
}

/// One certificate for `name`: pre-check, order, verify. Nothing is
/// installed; whatever the request left behind is removed. The error is a
/// reason in plain words (the pre-check's, the authority's, or why the
/// delivered certificate was refused).
pub(crate) async fn obtain(ctx: &Ctx, name: &Domain) -> std::result::Result<Material, String> {
    let names = vec![name.clone()];
    let pre = crate::acme::run_precheck(ctx, name, &names)
        .await
        .map_err(|e| e.to_string())?;
    if let Some((_, why)) = pre.skipped.first() {
        return Err(why.clone());
    }
    {
        let _guard = ctx.lock.lock().await;
        crate::acme::prepare(ctx, name, &names)
            .await
            .map_err(|e| e.to_string())?;
    }
    let ran = crate::acme::run_client(ctx, name, &names).await;
    let _guard = ctx.lock.lock().await;
    let result = async {
        let (ok, output) = ran.map_err(|e| e.to_string())?;
        if !ok {
            return Err(output
                .lines()
                .last()
                .unwrap_or("the ACME client failed")
                .to_owned());
        }
        verified(ctx, name).await.map_err(|e| e.to_string())
    }
    .await;
    let _ = crate::acme::discard(ctx, name);
    result
}

/// The pending key and the delivered chain, verified against each other and
/// against `name`. The caller holds the mutation lock.
async fn verified(ctx: &Ctx, name: &Domain) -> crate::error::Result<Material> {
    let key =
        crate::fsutil::read_optional(&crate::tls::pending_key_path(&ctx.config.tls_dir, name))?
            .and_then(|k| String::from_utf8(k).ok())
            .ok_or_else(|| {
                crate::Error::Internal("the key of the pending request is gone".into())
            })?;
    let chain = crate::acme::read_issued(ctx, name)?
        .ok_or_else(|| crate::Error::CertificateInvalid("no certificate was delivered".into()))?;
    let chain = crate::tls::normalise_pem(&chain, crate::tls::PemKind::Chain)?;
    let info = crate::tls::verify_material(ctx, name, &chain, &key).await?;
    Ok(Material { chain, key, info })
}
