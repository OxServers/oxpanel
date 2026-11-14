//! What email needs from outside the daemon: certificates for the mail host
//! name and the webmail names (through the same ACME client, pre-check and
//! back-off as Automatic HTTPS), and the deliverability checks (through the
//! DNS probe).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::records::{self, MailRecord};
use super::store::{MailDomainRecord, MailMode};
use super::{Check, CheckStatus};
use crate::ctx::Ctx;
use crate::dns::probe::{self, Outcome, Question, Server};
use crate::dns::wire;
use crate::error::Result;
use crate::fsutil;
use crate::records::now_unix;
use crate::validate::Domain;

// ---- Certificates -----------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Backoff {
    failures: u32,
    next_attempt_unix: u64,
    reason: String,
}

fn backoff_path(ctx: &Ctx) -> std::path::PathBuf {
    ctx.config.state_dir.join("mail").join("certificates.json")
}

fn load_backoff(ctx: &Ctx) -> BTreeMap<String, Backoff> {
    fsutil::read_optional(&backoff_path(ctx))
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_backoff(ctx: &Ctx, b: &BTreeMap<String, Backoff>) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(b)
        .map_err(|e| crate::Error::Internal(format!("backoff: {e}")))?;
    fsutil::ensure_dir(&ctx.config.state_dir.join("mail"), 0o700)?;
    fsutil::write_atomic(&backoff_path(ctx), &bytes, 0o600)?;
    Ok(())
}

/// The names that should have a certificate: the mail host name and the
/// webmail name of every local mail domain.
pub fn wanted_names(ctx: &Ctx) -> Result<Vec<Domain>> {
    let cfg = &ctx.config.mail;
    let Some(host) = cfg.hostname.clone().filter(|_| cfg.enabled) else {
        return Ok(Vec::new());
    };
    let m = super::ops::model(ctx, &host)?;
    let mut out = vec![host];
    for s in super::ops::webmail_sites(ctx, &m)? {
        out.push(Domain::parse(&s.name)?);
    }
    Ok(out)
}

/// Whether `name` has a certificate that is not due for renewal.
async fn current(ctx: &Ctx, name: &Domain) -> bool {
    let crt = crate::tls::cert_path(&ctx.config.mail.selfsigned_dir, name);
    if !crt.exists() || !crate::tls::key_path(&ctx.config.mail.selfsigned_dir, name).exists() {
        return false;
    }
    let due = now_unix().saturating_add(ctx.config.acme_renew_before.as_secs());
    crate::tls::inspect(ctx, &crt)
        .await
        .is_ok_and(|i| i.not_after_unix > due)
}

/// Obtain or renew the certificates email needs. Runs from the daemon's
/// periodic task; does nothing while email or Automatic HTTPS is off.
pub async fn sweep(ctx: &Ctx) -> Result<usize> {
    if !ctx.config.auto_https.is_on() || crate::acme::unavailable_reason(ctx).await?.is_some() {
        return Ok(0);
    }
    let names = {
        let _guard = ctx.lock.lock().await;
        wanted_names(ctx)?
    };
    let mut installed = 0;
    for name in names {
        if current(ctx, &name).await {
            continue;
        }
        let mut backoff = load_backoff(ctx);
        if backoff
            .get(name.as_str())
            .is_some_and(|b| b.next_attempt_unix > now_unix())
        {
            continue;
        }
        match obtain(ctx, &name).await {
            Ok(()) => {
                backoff.remove(name.as_str());
                installed += 1;
            }
            Err(why) => {
                let failures = backoff.get(name.as_str()).map_or(0, |b| b.failures) + 1;
                warn!(%name, reason = %why, "no certificate for the mail name yet");
                backoff.insert(
                    name.to_string(),
                    Backoff {
                        failures,
                        next_attempt_unix: now_unix() + crate::auto_https::backoff_secs(failures),
                        reason: why.chars().take(300).collect(),
                    },
                );
            }
        }
        save_backoff(ctx, &backoff)?;
    }
    if installed > 0 {
        let _guard = ctx.lock.lock().await;
        super::ops::apply(ctx).await?;
        // Same paths, new contents: the servers must load them again.
        super::ops::reload(
            ctx,
            super::ops::Changed {
                postfix: true,
                dovecot: true,
                nginx: true,
                ..super::ops::Changed::default()
            },
        )
        .await?;
    }
    Ok(installed)
}

/// One certificate for `name`: pre-check, order, verify, install.
async fn obtain(ctx: &Ctx, name: &Domain) -> std::result::Result<(), String> {
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
        install(ctx, name).await.map_err(|e| e.to_string())
    }
    .await;
    let _ = crate::acme::discard(ctx, name);
    result
}

async fn install(ctx: &Ctx, name: &Domain) -> Result<()> {
    let cfg = &ctx.config;
    let key = fsutil::read_optional(&crate::tls::pending_key_path(&cfg.tls_dir, name))?
        .and_then(|k| String::from_utf8(k).ok())
        .ok_or_else(|| crate::Error::Internal("the key of the pending request is gone".into()))?;
    let chain = crate::acme::read_issued(ctx, name)?
        .ok_or_else(|| crate::Error::CertificateInvalid("no certificate was delivered".into()))?;
    let chain = crate::tls::normalise_pem(&chain, crate::tls::PemKind::Chain)?;
    crate::tls::verify_material(ctx, name, &chain, &key).await?;
    fsutil::write_atomic(
        &crate::tls::key_path(&cfg.mail.selfsigned_dir, name),
        key.as_bytes(),
        crate::tls::KEY_MODE,
    )?;
    fsutil::write_atomic(
        &crate::tls::cert_path(&cfg.mail.selfsigned_dir, name),
        chain.as_bytes(),
        crate::tls::CERT_MODE,
    )?;
    info!(%name, "mail certificate installed");
    Ok(())
}

// ---- Deliverability -----------------------------------------------------------------

fn q(name: &str, qtype: u16) -> Question {
    Question {
        server: Server::Resolver,
        name: name.to_owned(),
        qtype,
        recursion: true,
    }
}

fn answer(o: Option<&Outcome>) -> Option<&probe::Answer> {
    match o {
        Some(Outcome::Answer(a)) if a.rcode == 0 || a.rcode == 3 => Some(a),
        _ => None,
    }
}

fn check(name: &'static str, status: CheckStatus, detail: impl Into<String>) -> Check {
    Check {
        name,
        status,
        detail: detail.into(),
    }
}

/// The reverse name of an address.
fn reverse_name(addr: &str) -> Option<String> {
    match addr.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]))
        }
        std::net::IpAddr::V6(v6) => {
            let mut s = String::new();
            for b in v6.octets().iter().rev() {
                let _ = write!(s, "{:x}.{:x}.", b & 0x0f, b >> 4);
            }
            s.push_str("ip6.arpa");
            Some(s)
        }
    }
}

/// Look at `rec`'s domain from outside: MX, SPF, DKIM, DMARC, and the
/// reverse DNS of the mail host name.
pub async fn deliverability(
    ctx: &Ctx,
    rec: &MailDomainRecord,
    host: &Domain,
) -> Result<Vec<Check>> {
    let d = &rec.domain;
    let selector = rec.dkim.as_ref().map(|k| k.selector.clone());
    let mut qs = vec![
        q(d, wire::TYPE_MX),
        q(d, wire::TYPE_TXT),
        q(&format!("_dmarc.{d}"), wire::TYPE_TXT),
        q(host.as_str(), wire::TYPE_A),
    ];
    if let Some(s) = &selector {
        qs.push(q(&format!("{s}._domainkey.{d}"), wire::TYPE_TXT));
    }
    let out = probe::run(ctx, &qs).await?;
    let mut checks = vec![
        mx_check(rec, host, answer(out.first())),
        spf_check(rec, host, answer(out.get(1))),
    ];
    checks.push(match (rec.mode, &rec.dkim, answer(out.get(4))) {
        (MailMode::Local, Some(k), Some(a)) => {
            let want = records::dkim_txt(&k.public_key);
            if a.txt.iter().any(|t| t.replace(' ', "") == want.replace(' ', "")) {
                check("dkim", CheckStatus::Ok, format!("{}._domainkey.{d} publishes the signing key", k.selector))
            } else {
                check("dkim", CheckStatus::Fail, format!("{}._domainkey.{d} does not publish the signing key: create the TXT record \"{want}\"", k.selector))
            }
        }
        (MailMode::Local, _, None) => check("dkim", CheckStatus::Unknown, "the DKIM record could not be looked up"),
        _ => check("dkim", CheckStatus::Unknown, "the domain's mail is not sent from here"),
    });
    checks.push(match answer(out.get(2)) {
        Some(a) if a.txt.iter().any(|t| t.starts_with("v=DMARC1")) => {
            check("dmarc", CheckStatus::Ok, "a DMARC policy is published")
        }
        Some(_) => check(
            "dmarc",
            CheckStatus::Warn,
            format!(
                "no DMARC policy: create the TXT record _dmarc.{d} \"{}\"",
                records::DMARC_TXT
            ),
        ),
        None => check(
            "dmarc",
            CheckStatus::Unknown,
            "the DMARC record could not be looked up",
        ),
    });
    checks.push(reverse_check(ctx, host, answer(out.get(3))).await?);
    Ok(checks)
}

fn mx_check(rec: &MailDomainRecord, host: &Domain, a: Option<&probe::Answer>) -> Check {
    let Some(a) = a else {
        return check(
            "mx",
            CheckStatus::Unknown,
            "the MX records could not be looked up",
        );
    };
    let seen: Vec<String> = a.mx.iter().map(|(_, n)| n.clone()).collect();
    let want: Vec<String> = records::required(rec, host, now_unix())
        .into_iter()
        .filter(|r: &MailRecord| r.rtype == "MX")
        .map(|r| r.value)
        .collect();
    if rec.mode == MailMode::Off {
        return check("mx", CheckStatus::Unknown, "the domain has no mail");
    }
    if !want.is_empty() && want.iter().all(|w| seen.contains(w)) && seen.len() == want.len() {
        check(
            "mx",
            CheckStatus::Ok,
            format!("mail for {} goes to {}", rec.domain, want.join(", ")),
        )
    } else if seen.is_empty() {
        check(
            "mx",
            CheckStatus::Fail,
            format!(
                "{} has no MX record: create MX {}",
                rec.domain,
                want.join(", ")
            ),
        )
    } else {
        check(
            "mx",
            CheckStatus::Fail,
            format!(
                "{} sends its mail to {}, not to {}",
                rec.domain,
                seen.join(", "),
                want.join(", ")
            ),
        )
    }
}

fn spf_check(rec: &MailDomainRecord, host: &Domain, a: Option<&probe::Answer>) -> Check {
    let Some(a) = a else {
        return check(
            "spf",
            CheckStatus::Unknown,
            "the SPF record could not be looked up",
        );
    };
    let spf: Vec<&String> = a.txt.iter().filter(|t| t.starts_with("v=spf1")).collect();
    match spf.as_slice() {
        [] => check(
            "spf",
            CheckStatus::Fail,
            format!(
                "no SPF record: create the TXT record \"{}\"",
                records::spf_txt(host)
            ),
        ),
        [one] if rec.mode != MailMode::Local || one.contains(host.as_str()) => {
            check("spf", CheckStatus::Ok, format!("SPF: {one}"))
        }
        [one] => check(
            "spf",
            CheckStatus::Warn,
            format!("the SPF record does not name {host}: {one}"),
        ),
        _ => check(
            "spf",
            CheckStatus::Fail,
            "more than one SPF record (receivers treat that as an error)",
        ),
    }
}

async fn reverse_check(ctx: &Ctx, host: &Domain, a: Option<&probe::Answer>) -> Result<Check> {
    let Some(addr) = a.and_then(|a| a.addrs.first()).cloned() else {
        return Ok(check(
            "reverse_dns",
            CheckStatus::Fail,
            format!("{host} does not resolve to an address"),
        ));
    };
    let Some(rev) = reverse_name(&addr) else {
        return Ok(check("reverse_dns", CheckStatus::Unknown, "bad address"));
    };
    let out = probe::run(ctx, &[q(&rev, wire::TYPE_PTR)]).await?;
    Ok(match answer(out.first()) {
        Some(a) if a.ptr.iter().any(|p| p == host.as_str()) => check(
            "reverse_dns",
            CheckStatus::Ok,
            format!("{addr} has the reverse name {host}"),
        ),
        Some(a) => check(
            "reverse_dns",
            CheckStatus::Warn,
            format!(
                "the reverse name of {addr} is {} instead of {host}; ask the provider of the address to set it (many receivers reject mail otherwise)",
                if a.ptr.is_empty() { "missing".to_owned() } else { a.ptr.join(", ") }
            ),
        ),
        None => check("reverse_dns", CheckStatus::Unknown, "the reverse name could not be looked up"),
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn reverse_names_are_built_for_both_families() {
        assert_eq!(
            reverse_name("192.0.2.10").as_deref(),
            Some("10.2.0.192.in-addr.arpa")
        );
        let v6 = reverse_name("2001:db8::1").unwrap();
        assert!(v6.starts_with("1.0.0.0."), "{v6}");
        assert!(v6.ends_with(".8.b.d.0.1.0.0.2.ip6.arpa"), "{v6}");
        assert_eq!(reverse_name("nope"), None);
    }
}
