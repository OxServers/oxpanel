//! The host checks behind `GetMailHost`'s warnings that need the network:
//! whether the mail host name's address has it as its reverse name, and
//! whether outbound connections to port 25 work (many cloud providers block
//! them; mail then never leaves). Both are asked through the DNS probe
//! (`dns::probe`, its own transient unit: the daemon has no network) and
//! cached in `<state>/host-checks.json` for [`MAX_AGE`]: `GetMailHost`,
//! which a dashboard polls, only reads the cache and starts a refresh in
//! the background when it is missing, stale or about another host name.
//! A check that could not be made gives no warning (unknown is not a
//! fault of the host).

use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::certs;
use super::CheckStatus;
use crate::ctx::Ctx;
use crate::dns::probe::{self, Outcome, Question, Server};
use crate::dns::wire;
use crate::error::Result;
use crate::fsutil;
use crate::records::now_unix;
use crate::validate::Domain;

/// How long a result is used before it is looked at again.
pub const MAX_AGE: u64 = 6 * 3600;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostChecks {
    /// The mail host name the checks were made for.
    pub host: String,
    pub checked_at_unix: u64,
    /// A warning about the reverse name; `None`: it matches, or unknown.
    #[serde(default)]
    pub reverse_dns: Option<String>,
    /// A warning about outbound port 25; `None`: it works, or unknown.
    #[serde(default)]
    pub port25: Option<String>,
}

static REFRESHING: AtomicBool = AtomicBool::new(false);

fn path(ctx: &Ctx) -> std::path::PathBuf {
    ctx.config.mail.state_dir.join("host-checks.json")
}

/// The last result for `host`, however old.
pub fn cached(ctx: &Ctx, host: &Domain) -> Option<HostChecks> {
    let bytes = fsutil::read_optional(&path(ctx)).ok()??;
    serde_json::from_slice::<HostChecks>(&bytes)
        .ok()
        .filter(|c| c.host == host.as_str())
}

/// Start a refresh in the background unless one runs or the cache is fresh.
pub fn refresh_if_stale(ctx: &Ctx, host: &Domain) {
    let fresh =
        cached(ctx, host).is_some_and(|c| now_unix().saturating_sub(c.checked_at_unix) < MAX_AGE);
    if fresh || ctx.config.dry_run || REFRESHING.swap(true, Ordering::SeqCst) {
        return;
    }
    let ctx = ctx.clone();
    let host = host.clone();
    tokio::spawn(async move {
        if let Err(e) = refresh(&ctx, &host).await {
            warn!(error = %e, "the mail host checks (reverse DNS, port 25) could not be made");
        }
        REFRESHING.store(false, Ordering::SeqCst);
    });
}

/// Make both checks now and keep the result.
pub async fn refresh(ctx: &Ctx, host: &Domain) -> Result<HostChecks> {
    let target = ctx.config.mail.port25_check.clone();
    let mut qs = vec![certs::q(host.as_str(), wire::TYPE_A)];
    if let Some(t) = &target {
        qs.push(certs::q(t.as_str(), wire::TYPE_A));
    }
    let out = probe::run(ctx, &qs).await?;
    let rev = certs::reverse_check(ctx, host, certs::answer(out.first())).await?;
    let reverse_dns =
        matches!(rev.status, CheckStatus::Warn | CheckStatus::Fail).then_some(rev.detail);
    let mut port25 = None;
    if let (Some(t), Some(addr)) = (
        &target,
        certs::answer(out.get(1))
            .and_then(|a| a.addrs.first())
            .and_then(|a| a.parse::<std::net::IpAddr>().ok()),
    ) {
        let q = Question {
            server: Server::At(std::net::SocketAddr::new(addr, 25)),
            name: t.to_string(),
            qtype: probe::TYPE_SMTP_GREETING,
            recursion: false,
        };
        port25 = match probe::run(ctx, &[q]).await?.first() {
            Some(Outcome::Failed(why)) => Some(format!(
                "outbound connections to port 25 fail ({t}: {why}): mail to other servers stays in the queue; ask the provider of this host to unblock port 25 (OXPANEL_MAIL_PORT25_CHECK names the server tried)"
            )),
            _ => None,
        };
    }
    let checks = HostChecks {
        host: host.to_string(),
        checked_at_unix: now_unix(),
        reverse_dns,
        port25,
    };
    let json = serde_json::to_vec_pretty(&checks)
        .map_err(|e| crate::error::Error::Internal(format!("host checks: {e}")))?;
    fsutil::ensure_dir(&ctx.config.mail.state_dir, 0o755)?;
    fsutil::write_atomic(&path(ctx), &json, 0o600)?;
    info!(
        %host,
        reverse_dns_ok = checks.reverse_dns.is_none(),
        port25_ok = checks.port25.is_none(),
        "mail host checks made"
    );
    Ok(checks)
}
