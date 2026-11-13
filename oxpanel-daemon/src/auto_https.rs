//! Automatic HTTPS: every site gets a certificate from the ACME authority
//! without anyone asking, and keeps one that covers all of its names.
//!
//! - **When.** A few seconds after a site is created or its names change
//!   (after Nginx has reloaded), and by a sweep every 15 minutes that also
//!   retries failures. `RunAutoHttps` runs it at once.
//! - **What is never touched.** A valid uploaded certificate. An uploaded
//!   certificate that has *expired* is replaced, because the site would
//!   otherwise be broken for every visitor. Sites that opted out, every site
//!   while the host-wide switch is off, and sites of suspended tenants.
//! - **Rate limits.** Before the authority is asked, the unprivileged ACME
//!   client checks from outside the daemon that each name resolves and that a
//!   probe file under the challenge path is served by this host (see
//!   [`acme::run_precheck`]). Names that fail are left out of the order and
//!   backed off (1 h, 6 h, then every 24 h); if the domain itself fails,
//!   nothing is ordered. A refusal by the authority backs off the names it
//!   was asked for in the same way. At most [`crate::tls::MAX_CONCURRENT_ORDERS`]
//!   checks or orders run at once, and one site's work is serialised.
//! - **State.** Back-off and the last outcome per site live in
//!   `<state_dir>/auto-https/<domain>.json` (root-only), so they survive a
//!   restart. The file goes with the site.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::acme;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::records::{now_unix, CertSource, TenantState, VHostRecord};
use crate::tls::{covers, AcmeOutcome, TlsService};
use crate::validate::{Domain, Username};

/// The first sweep after start-up, then every [`SWEEP_EVERY`].
pub const FIRST_SWEEP_AFTER: Duration = Duration::from_secs(60);
pub const SWEEP_EVERY: Duration = Duration::from_secs(15 * 60);
/// How long after a change to wait before checking the site: Nginx's reload
/// returns before the new workers serve it.
pub const AFTER_CHANGE_DELAY: Duration = Duration::from_secs(3);
/// Waits after the 1st, 2nd and 3rd consecutive failure; later ones wait as
/// long as the last.
const BACKOFF_SECS: [u64; 3] = [3600, 6 * 3600, 24 * 3600];
const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const MAX_ERROR_CHARS: usize = 300;

/// How long to wait after `failures` consecutive failures.
pub fn backoff_secs(failures: u32) -> u64 {
    let i = usize::try_from(failures.saturating_sub(1)).unwrap_or(usize::MAX);
    BACKOFF_SECS
        .get(i)
        .or(BACKOFF_SECS.last())
        .copied()
        .unwrap_or(86_400)
}

/// A name that failed and when it may be tried again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameBackoff {
    pub failures: u32,
    pub next_attempt_unix: u64,
    pub reason: String,
}

/// What Automatic HTTPS remembers about one site.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoHttpsRecord {
    #[serde(default)]
    pub last_attempt_unix: Option<u64>,
    /// Plain words; `None` after a success.
    #[serde(default)]
    pub last_error: Option<String>,
    /// Names that failed, by name.
    #[serde(default)]
    pub names: BTreeMap<String, NameBackoff>,
}

impl AutoHttpsRecord {
    /// Record one more failure of `name`.
    fn fail(&mut self, name: &str, reason: &str, now: u64) {
        let failures = self.names.get(name).map_or(0, |b| b.failures) + 1;
        self.names.insert(
            name.to_owned(),
            NameBackoff {
                failures,
                next_attempt_unix: now.saturating_add(backoff_secs(failures)),
                reason: bounded(reason),
            },
        );
    }
}

fn bounded(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_ERROR_CHARS)
        .collect()
}

fn state_dir(cfg: &Config) -> PathBuf {
    cfg.state_dir.join("auto-https")
}

/// `<state_dir>/auto-https/<domain>.json`
pub fn state_path(cfg: &Config, domain: &Domain) -> PathBuf {
    state_dir(cfg).join(format!("{domain}.json"))
}

/// Every state file, for reconciliation.
pub fn state_files(cfg: &Config) -> Result<Vec<PathBuf>> {
    fsutil::list_files_with_suffix(&state_dir(cfg), ".json")
}

/// The site's state; a missing or unreadable file is a fresh start (it only
/// holds back-off, so losing it costs at most an early retry).
pub fn load(cfg: &Config, domain: &Domain) -> AutoHttpsRecord {
    match fsutil::read_optional(&state_path(cfg, domain)) {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            warn!(%domain, error = %e, "unreadable Automatic HTTPS state; starting afresh");
            AutoHttpsRecord::default()
        }),
        Ok(None) => AutoHttpsRecord::default(),
        Err(e) => {
            warn!(%domain, error = %e, "cannot read Automatic HTTPS state; starting afresh");
            AutoHttpsRecord::default()
        }
    }
}

fn save(cfg: &Config, domain: &Domain, rec: &AutoHttpsRecord) -> Result<()> {
    fsutil::ensure_dir(&cfg.state_dir, DIR_MODE)?;
    fsutil::ensure_dir(&state_dir(cfg), DIR_MODE)?;
    let json = serde_json::to_vec_pretty(rec)
        .map_err(|e| Error::Internal(format!("cannot serialise Automatic HTTPS state: {e}")))?;
    fsutil::write_atomic(&state_path(cfg, domain), &json, FILE_MODE).map(|_| ())
}

/// Drop a removed site's state.
pub fn forget(cfg: &Config, domain: &Domain) -> Result<()> {
    fsutil::remove_if_exists(&state_path(cfg, domain)).map(|_| ())
}

/// Whether Automatic HTTPS looks after `vhost` at all.
pub fn enabled(cfg: &Config, vhost: &VHostRecord) -> bool {
    cfg.auto_https.is_on() && vhost.auto_https.is_on()
}

/// The names a certificate should be ordered for now, the domain first;
/// empty when nothing is to be done. `renew` orders even when nothing new is
/// to be covered (the current certificate is due).
pub fn plan(
    vhost: &VHostRecord,
    rec: &AutoHttpsRecord,
    now: u64,
    ignore_backoff: bool,
    renew: bool,
) -> Result<Vec<Domain>> {
    if vhost
        .tls
        .as_ref()
        .is_some_and(|t| t.source == CertSource::Uploaded && t.not_after_unix > now)
    {
        // A valid uploaded certificate is the operator's choice.
        return Ok(Vec::new());
    }
    let cert = vhost
        .tls
        .as_ref()
        .filter(|t| t.source == CertSource::Acme && t.not_after_unix > now);
    let covered = |n: &Domain| cert.is_some_and(|t| covers(&t.names, n.as_str()));
    let eligible = |n: &Domain| {
        ignore_backoff
            || rec
                .names
                .get(n.as_str())
                .is_none_or(|b| b.next_attempt_unix <= now)
    };
    let names = acme::server_names(vhost)?;
    let Some(main) = names.first() else {
        return Ok(Vec::new());
    };
    let new_names = names.iter().any(|n| !covered(n) && eligible(n));
    if (!new_names && !renew) || (!covered(main) && !eligible(main)) {
        return Ok(Vec::new());
    }
    Ok(names
        .iter()
        .filter(|n| covered(n) || eligible(n))
        .cloned()
        .collect())
}

/// Where a site stands, for the panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Disabled,
    Pending,
    Covered,
    Partial,
    Failed,
    Uploaded,
    Suspended,
}

/// A name waiting out its back-off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub name: String,
    pub reason: String,
    pub next_attempt_unix: u64,
    pub failures: u32,
}

/// Automatic HTTPS status of one site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub domain: String,
    pub state: State,
    pub covered: Vec<String>,
    pub skipped: Vec<Skipped>,
    pub pending: Vec<String>,
    pub last_attempt_unix: Option<u64>,
    pub next_attempt_unix: Option<u64>,
    pub last_error: Option<String>,
}

/// Compute the status of `vhost` (of a tenant that is `suspended` or not).
pub fn status(
    cfg: &Config,
    vhost: &VHostRecord,
    suspended: bool,
    rec: &AutoHttpsRecord,
    now: u64,
) -> Status {
    let valid = vhost.tls.as_ref().filter(|t| t.not_after_unix > now);
    let names: Vec<String> = vhost.all_names().map(str::to_owned).collect();
    let (covered, uncovered): (Vec<String>, Vec<String>) = names
        .into_iter()
        .partition(|n| valid.is_some_and(|t| covers(&t.names, n)));
    let mut skipped = Vec::new();
    let mut pending = Vec::new();
    for n in uncovered {
        match rec.names.get(&n).filter(|b| b.next_attempt_unix > now) {
            Some(b) => skipped.push(Skipped {
                name: n,
                reason: b.reason.clone(),
                next_attempt_unix: b.next_attempt_unix,
                failures: b.failures,
            }),
            None => pending.push(n),
        }
    }
    let main_covered = covered.contains(&vhost.domain);
    let state = if !enabled(cfg, vhost) {
        State::Disabled
    } else if suspended {
        State::Suspended
    } else if valid.is_some_and(|t| t.source == CertSource::Uploaded) {
        State::Uploaded
    } else if skipped.is_empty() && pending.is_empty() {
        State::Covered
    } else if main_covered {
        if pending.is_empty() {
            State::Partial
        } else {
            State::Pending
        }
    } else if rec.last_error.is_some() || skipped.iter().any(|s| s.name == vhost.domain) {
        State::Failed
    } else {
        State::Pending
    };
    Status {
        domain: vhost.domain.clone(),
        state,
        next_attempt_unix: skipped.iter().map(|s| s.next_attempt_unix).min(),
        covered,
        skipped,
        pending,
        last_attempt_unix: rec.last_attempt_unix,
        last_error: rec.last_error.clone(),
    }
}

/// A failed attempt, as an outcome.
fn not_issued(vhost: VHostRecord, output: String) -> AcmeOutcome {
    AcmeOutcome {
        succeeded: false,
        output,
        vhost,
    }
}

impl TlsService {
    /// The host-wide switch (`OXPANEL_AUTO_HTTPS`).
    pub fn auto_https_enabled(&self) -> bool {
        self.ctx.config.auto_https.is_on()
    }

    /// Whether Automatic HTTPS looks after the site `domain`.
    pub(crate) fn auto_https_applies(&self, domain: &Domain) -> Result<bool> {
        Ok(self
            .ctx
            .store
            .load_vhost(domain)?
            .is_some_and(|v| enabled(&self.ctx.config, &v)))
    }

    /// Check `domain` shortly, after a change to it (the RPC that made the
    /// change does not wait for this).
    pub fn auto_https_soon(&self, domain: String) {
        if !self.ctx.config.auto_https.is_on() {
            return;
        }
        let tls = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(AFTER_CHANGE_DELAY).await;
            let Ok(d) = Domain::parse(&domain) else {
                return;
            };
            if let Err(e) = tls.auto_https_site(&d, false, false).await {
                warn!(%domain, error = %e, "automatic HTTPS failed");
            }
        });
    }

    /// Renew a due certificate of a site under Automatic HTTPS.
    pub(crate) async fn auto_https_renew(&self, domain: &Domain) -> Result<AcmeOutcome> {
        if let Some(outcome) = self.auto_https_site(domain, false, true).await? {
            return Ok(outcome);
        }
        let (_, vhost) = self.load(domain)?;
        Ok(not_issued(
            vhost,
            "nothing to renew now (names are backing off)".into(),
        ))
    }

    /// Run Automatic HTTPS now: for `domain` ignoring back-off, or for every
    /// site (empty `domain`) respecting it. Returns the resulting status.
    pub async fn auto_https_run(&self, domain: &str) -> Result<Vec<Status>> {
        if domain.is_empty() {
            self.auto_https_sweep().await;
        } else {
            let d = Domain::parse(domain)?;
            // A site that does not exist is an error; one that is not
            // eligible just reports why.
            self.load(&d)?;
            self.auto_https_site(&d, true, false).await?;
        }
        self.auto_https_status(domain)
    }

    /// One pass over every site, at most [`crate::tls::MAX_CONCURRENT_ORDERS`]
    /// talking to the outside at a time. Failures are recorded per site.
    pub async fn auto_https_sweep(&self) {
        if !self.ctx.config.auto_https.is_on() {
            return;
        }
        let vhosts = match self.ctx.store.list_vhosts() {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "automatic HTTPS: cannot list virtual hosts");
                return;
            }
        };
        let mut tasks = Vec::new();
        for v in vhosts {
            let Ok(domain) = Domain::parse(&v.domain) else {
                continue;
            };
            let tls = self.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = tls.auto_https_site(&domain, false, false).await {
                    warn!(%domain, error = %e, "automatic HTTPS failed");
                }
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
    }

    /// Status of `domain`, or of every site when it is empty. Read-only.
    pub fn auto_https_status(&self, domain: &str) -> Result<Vec<Status>> {
        let cfg = &self.ctx.config;
        let vhosts = if domain.is_empty() {
            self.ctx.store.list_vhosts()?
        } else {
            vec![self.load(&Domain::parse(domain)?)?.1]
        };
        let now = now_unix();
        let mut out = Vec::with_capacity(vhosts.len());
        for v in vhosts {
            let d = Domain::parse(&v.domain)?;
            let suspended = Username::parse_field(&v.tenant, "tenant")
                .ok()
                .and_then(|t| self.ctx.store.load_tenant(&t).ok().flatten())
                .is_none_or(|t| t.suspended || t.state != TenantState::Ready);
            out.push(status(cfg, &v, suspended, &load(cfg, &d), now));
        }
        Ok(out)
    }

    /// Save the site's state, unless the site was removed while this run
    /// waited for its pre-check or order (minutes, without the mutation
    /// lock). Its removal, under that lock, already dropped the state;
    /// writing it now would leave an orphan (`ORPHAN_AUTO_HTTPS_STATE`, found
    /// by acceptance phase 20 when a site was removed within seconds of
    /// being configured).
    async fn save_if_site_exists(&self, domain: &Domain, rec: &AutoHttpsRecord) -> Result<()> {
        let _guard = self.ctx.lock.lock().await;
        if self.ctx.store.load_vhost(domain)?.is_some() {
            save(&self.ctx.config, domain, rec)?;
        }
        Ok(())
    }

    /// Do what `domain` needs. `None` when nothing was attempted (not
    /// eligible, nothing to do, or everything backing off).
    async fn auto_https_site(
        &self,
        domain: &Domain,
        ignore_backoff: bool,
        renew: bool,
    ) -> Result<Option<AcmeOutcome>> {
        let cfg = &self.ctx.config;
        let _site = self.site_lock(domain).await;
        let (tenant, vhost) = match self.load(domain) {
            Ok(found) => found,
            // Removed meanwhile, or its tenant is not ready: nothing to do.
            Err(Error::VHostNotFound(_) | Error::TenantNotReady(_) | Error::TenantNotFound(_)) => {
                return Ok(None)
            }
            Err(e) => return Err(e),
        };
        if !enabled(cfg, &vhost) || tenant.suspended {
            return Ok(None);
        }
        let now = now_unix();
        let mut rec = load(cfg, domain);
        let wanted = plan(&vhost, &rec, now, ignore_backoff, renew)?;
        if wanted.is_empty() {
            return Ok(None);
        }
        rec.last_attempt_unix = Some(now);
        if let Some(reason) = acme::unavailable_reason(&self.ctx).await? {
            rec.last_error = Some(bounded(&format!(
                "certificates cannot be requested on this host: {reason}"
            )));
            self.save_if_site_exists(domain, &rec).await?;
            return Ok(Some(not_issued(vhost, reason)));
        }
        let checked = {
            let _slot = self.order_slot().await?;
            acme::run_precheck(&self.ctx, domain, &wanted).await
        };
        let checked = match checked {
            Ok(c) => c,
            Err(e) => {
                rec.last_error = Some(bounded(&e.to_string()));
                self.save_if_site_exists(domain, &rec).await?;
                return Ok(Some(not_issued(vhost, e.to_string())));
            }
        };
        let mut output = String::new();
        for (name, why) in &checked.skipped {
            rec.fail(name.as_str(), why, now);
            let _ = writeln!(output, "{name}: skipped: {why}");
        }
        if !checked.passed.iter().any(|n| n == domain) {
            let why = checked
                .skipped
                .iter()
                .find(|(n, _)| n == domain)
                .map_or("not checked", |(_, w)| w.as_str());
            rec.last_error = Some(bounded(&format!("{domain}: {why}")));
            self.save_if_site_exists(domain, &rec).await?;
            info!(%domain, reason = why, "automatic HTTPS: the domain does not validate yet; nothing ordered");
            return Ok(Some(not_issued(vhost, output)));
        }
        // Everything that passed is covered already (the new names all
        // failed): a new certificate would gain nothing, so the authority is
        // not asked.
        let current = vhost
            .tls
            .as_ref()
            .filter(|t| t.source == CertSource::Acme && t.not_after_unix > now);
        if !renew
            && current.is_some_and(|t| checked.passed.iter().all(|n| covers(&t.names, n.as_str())))
        {
            rec.last_error = None;
            rec.names.retain(|n, _| vhost.all_names().any(|m| m == n));
            self.save_if_site_exists(domain, &rec).await?;
            return Ok(Some(not_issued(vhost, output)));
        }
        let ordered = self.order(domain, Some(&checked.passed)).await;
        let outcome = record_order(domain, &mut rec, &checked.passed, ordered, now, output);
        rec.names.retain(|n, _| vhost.all_names().any(|m| m == n));
        self.save_if_site_exists(domain, &rec).await?;
        outcome.map(Some)
    }
}

/// Book the result of an order into the site's state.
fn record_order(
    domain: &Domain,
    rec: &mut AutoHttpsRecord,
    passed: &[Domain],
    ordered: Result<AcmeOutcome>,
    now: u64,
    mut output: String,
) -> Result<AcmeOutcome> {
    match ordered {
        Ok(mut o) if o.succeeded => {
            for n in passed {
                rec.names.remove(n.as_str());
            }
            rec.last_error = None;
            info!(%domain, names = passed.len(), "automatic HTTPS: certificate obtained");
            output.push_str(&o.output);
            o.output = output;
            Ok(o)
        }
        Ok(mut o) => {
            let why = o
                .output
                .lines()
                .rev()
                .find(|l| l.contains("no certificate") || l.contains("not installed"))
                .or_else(|| o.output.lines().last())
                .unwrap_or("the certificate authority did not issue")
                .to_owned();
            for n in passed {
                rec.fail(
                    n.as_str(),
                    &format!("the certificate authority refused: {why}"),
                    now,
                );
            }
            rec.last_error = Some(bounded(&why));
            warn!(%domain, reason = %why, "automatic HTTPS: no certificate");
            output.push_str(&o.output);
            o.output = output;
            Ok(o)
        }
        Err(e) => {
            rec.last_error = Some(if e.is_client_error() {
                bounded(&e.to_string())
            } else {
                "internal error; see the oxpanel-daemon journal".to_owned()
            });
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::host::{DriftKind, HostService};
    use crate::records::{AutoHttpsChoice, TlsRecord};
    use crate::system::bin;
    use crate::system::fake_tls::fake_private_key;
    use crate::tls::tests::{args, good_cert, harness, harness_with, upload, Harness};
    use crate::vhost::VHostRequest;
    use std::os::unix::fs::PermissionsExt as _;

    const DAY: u64 = 86_400;

    fn site(h: &Harness) -> Status {
        h.tls
            .auto_https_status("example.com")
            .unwrap()
            .pop()
            .unwrap()
    }

    async fn set_aliases(h: &Harness, aliases: &[&str], choice: AutoHttpsChoice) {
        h.vhosts
            .configure(VHostRequest {
                domain: "example.com".into(),
                tenant: "alice".into(),
                aliases: aliases.iter().map(|a| (*a).to_owned()).collect(),
                auto_https: choice,
                ..VHostRequest::default()
            })
            .await
            .unwrap();
        h.sys.clear_calls();
    }

    /// The `systemd-run` calls of the ACME client, as (is it a pre-check, names).
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

    #[test]
    fn back_off_grows_then_stays_daily() {
        assert_eq!(
            [1, 2, 3, 4, 10].map(backoff_secs),
            [3600, 6 * 3600, DAY, DAY, DAY]
        );
    }

    #[tokio::test]
    async fn a_new_site_gets_a_certificate_without_asking() -> Result<()> {
        let h = harness().await;
        assert_eq!(site(&h).state, State::Pending);
        let statuses = h.tls.auto_https_run("").await?;
        assert_eq!(statuses.len(), 1);
        let s = &statuses[0];
        assert_eq!(s.state, State::Covered, "{s:?}");
        assert_eq!(
            s.covered,
            vec!["example.com", "shop.example.net", "www.example.com"]
        );
        assert!(s.last_attempt_unix.is_some() && s.last_error.is_none());
        let rec = h.record("example.com");
        assert_eq!(rec.tls.unwrap().source, CertSource::Acme);

        // First the reachability check, then the order; exact argv of the check.
        let names = ["example.com", "shop.example.net", "www.example.com"]
            .map(String::from)
            .to_vec();
        assert_eq!(client_runs(&h), vec![(true, names.clone()), (false, names)]);
        let run = h.sys.calls_to(bin::SYSTEMD_RUN);
        let check = args(&run[0]);
        let acme = h.cfg().acme_dir.to_string_lossy().into_owned();
        let tail: Vec<String> = check.iter().skip_while(|a| *a != "--").cloned().collect();
        assert_eq!(
            tail,
            [
                "--",
                bin::OXPANEL_ACME,
                "--mode",
                "precheck",
                "--challenge-dir",
                &format!("{acme}/challenges"),
                "--out",
                &format!("{acme}/issued/example.com.precheck"),
                "--domain",
                "example.com",
                "--domain",
                "shop.example.net",
                "--domain",
                "www.example.com",
            ]
            .map(String::from)
        );
        assert!(check.contains(&"User=oxpanel-acme".to_owned()));
        assert!(!h
            .cfg()
            .acme_dir
            .join("issued")
            .join("example.com.precheck")
            .exists());

        // Nothing left to do: nothing runs.
        h.sys.clear_calls();
        h.tls.auto_https_run("").await?;
        assert!(client_runs(&h).is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn names_added_later_are_covered_and_bad_names_are_skipped_and_backed_off() -> Result<()>
    {
        let h = harness().await;
        h.tls.auto_https_run("").await?;
        set_aliases(
            &h,
            &[
                "www.example.com",
                "shop.example.net",
                "new.example.com",
                "nx.example.com",
            ],
            AutoHttpsChoice::On,
        )
        .await;
        assert_eq!(site(&h).state, State::Pending);
        let before = now_unix();
        h.tls.auto_https_run("").await?;
        let s = site(&h);
        assert_eq!(s.state, State::Partial, "{s:?}");
        assert!(s.covered.contains(&"new.example.com".to_owned()));
        assert_eq!(s.skipped.len(), 1);
        let nx = &s.skipped[0];
        assert_eq!(
            (nx.name.as_str(), nx.reason.as_str(), nx.failures),
            ("nx.example.com", "the name does not resolve", 1)
        );
        assert!((before + 3600..=now_unix() + 3600).contains(&nx.next_attempt_unix));
        assert_eq!(s.next_attempt_unix, Some(nx.next_attempt_unix));
        // The order left the failing name out.
        let runs = client_runs(&h);
        assert_eq!(runs.len(), 2);
        assert!(runs[1].1.contains(&"new.example.com".to_owned()));
        assert!(runs[0].1.contains(&"nx.example.com".to_owned()));
        assert!(!runs[1].1.contains(&"nx.example.com".to_owned()));

        // A restart (a fresh service reading the same state) remembers it, and
        // a sweep respects the back-off: nothing runs.
        let restarted = TlsService::new(h.ctx.clone());
        assert_eq!(restarted.auto_https_status("example.com")?[0], s);
        h.sys.clear_calls();
        restarted.auto_https_run("").await?;
        assert!(client_runs(&h).is_empty());

        // Asking for the one site ignores the back-off; the next wait is
        // longer. Only the failing name is new, so only the check runs: the
        // authority is not asked for a certificate that would gain nothing.
        h.sys.clear_calls();
        restarted.auto_https_run("example.com").await?;
        assert_eq!(client_runs(&h).len(), 1);
        let again = restarted.auto_https_status("example.com")?.pop().unwrap();
        assert_eq!(again.skipped[0].failures, 2);
        assert!(again.skipped[0].next_attempt_unix >= before + 6 * 3600);
        Ok(())
    }

    #[tokio::test]
    async fn nothing_is_ordered_when_the_domain_itself_does_not_validate() -> Result<()> {
        let h = harness().await;
        h.vhosts
            .configure(VHostRequest {
                domain: "nxsite.example".into(),
                tenant: "alice".into(),
                ..VHostRequest::default()
            })
            .await?;
        h.sys.clear_calls();
        let s = h.tls.auto_https_run("nxsite.example").await?.pop().unwrap();
        assert_eq!(s.state, State::Failed);
        assert_eq!(
            s.last_error.as_deref(),
            Some("nxsite.example: the name does not resolve")
        );
        assert_eq!(client_runs(&h).len(), 1, "only the check ran");
        assert!(h.sys.calls_to(bin::OPENSSL).is_empty(), "no key was made");
        Ok(())
    }

    #[tokio::test]
    async fn opt_out_host_switch_and_suspension_leave_sites_alone() -> Result<()> {
        let h = harness().await;
        set_aliases(&h, &["www.example.com"], AutoHttpsChoice::Off).await;
        h.tls.auto_https_run("").await?;
        h.tls.auto_https_run("example.com").await?;
        assert!(client_runs(&h).is_empty());
        assert_eq!(site(&h).state, State::Disabled);

        set_aliases(&h, &["www.example.com"], AutoHttpsChoice::On).await;
        h.tenants.set_suspended("alice", true).await?;
        h.sys.clear_calls();
        h.tls.auto_https_run("").await?;
        h.tls.auto_https_run("example.com").await?;
        assert!(client_runs(&h).is_empty());
        assert_eq!(site(&h).state, State::Suspended);

        let off = harness_with(|c| c.auto_https = AutoHttpsChoice::Off).await;
        assert!(!off.tls.auto_https_enabled());
        off.tls.auto_https_run("").await?;
        off.tls.auto_https_run("example.com").await?;
        assert!(client_runs(&off).is_empty());
        assert_eq!(site(&off).state, State::Disabled);
        Ok(())
    }

    #[tokio::test]
    async fn uploaded_certificates_are_kept_until_they_expire() -> Result<()> {
        let h = harness().await;
        h.tls
            .install(upload(&good_cert(), &fake_private_key("k1")))
            .await?;
        h.sys.clear_calls();
        h.tls.auto_https_run("example.com").await?;
        assert!(client_runs(&h).is_empty());
        assert_eq!(site(&h).state, State::Uploaded);
        assert_eq!(
            h.record("example.com").tls.unwrap().source,
            CertSource::Uploaded
        );

        // Expired (simulated in the record): the site would be broken, so it
        // is replaced — only because Automatic HTTPS is on for it.
        let mut rec = h.record("example.com");
        let now = now_unix();
        rec.tls = Some(TlsRecord {
            not_before_unix: now - 90 * DAY,
            not_after_unix: now - DAY,
            ..rec.tls.unwrap()
        });
        h.ctx.store.save_vhost(&rec)?;
        set_aliases(&h, &["www.example.com"], AutoHttpsChoice::Off).await;
        h.tls.auto_https_run("").await?;
        assert_eq!(
            h.record("example.com").tls.unwrap().source,
            CertSource::Uploaded,
            "opted out: untouched"
        );
        set_aliases(&h, &["www.example.com"], AutoHttpsChoice::On).await;
        h.tls.auto_https_run("").await?;
        assert_eq!(
            h.record("example.com").tls.unwrap().source,
            CertSource::Acme
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_refusal_by_the_authority_backs_off_every_ordered_name() -> Result<()> {
        let h = harness().await;
        h.sys.set_acme_refuses(true);
        let s = h.tls.auto_https_run("").await?.pop().unwrap();
        assert_eq!(s.state, State::Failed);
        assert!(
            s.last_error.as_deref().unwrap().contains("rateLimited"),
            "{s:?}"
        );
        assert_eq!(s.skipped.len(), 3);
        assert!(s
            .skipped
            .iter()
            .all(|k| k.failures == 1 && k.reason.contains("refused")));
        assert!(h.record("example.com").tls.is_none());
        h.sys.set_acme_refuses(false);
        h.sys.clear_calls();
        h.tls.auto_https_run("").await?;
        assert!(client_runs(&h).is_empty(), "backing off");
        Ok(())
    }

    #[tokio::test]
    async fn renewal_of_a_site_under_automatic_https_leaves_out_names_that_fail() -> Result<()> {
        let h = harness().await;
        h.sys.set_acme_lifetime(10 * DAY);
        h.tls.auto_https_run("").await?;
        // An alias that no longer resolves would fail the whole renewal.
        let mut rec = h.record("example.com");
        rec.aliases = vec!["nx.example.com".into(), "www.example.com".into()];
        h.ctx.store.save_vhost(&rec)?;
        // ...and is backing off already.
        let d = Domain::parse("example.com")?;
        let mut state = load(h.cfg(), &d);
        state.fail("nx.example.com", "the name does not resolve", now_unix());
        save(h.cfg(), &d, &state)?;
        h.sys.set_acme_lifetime(90 * DAY);
        h.sys.clear_calls();
        let renewals = h.tls.renew_due().await?;
        assert_eq!(renewals.len(), 1);
        assert!(renewals[0].succeeded, "{}", renewals[0].output);
        let runs = client_runs(&h);
        assert_eq!(
            runs.last().unwrap().1,
            vec!["example.com", "www.example.com"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn external_account_binding_is_a_credential_never_an_argument() -> Result<()> {
        let h = harness_with(|c| c.acme_eab_file = Some(c.state_dir.with_file_name("eab"))).await;
        let file = h.cfg().acme_eab_file.clone().unwrap();
        std::fs::write(&file, "kid=kid-1\nhmac_key=c2VjcmV0LWhtYWMta2V5\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = h.tls.request("example.com").await.unwrap_err();
        assert!(err.to_string().contains("readable by root only"), "{err}");

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(h.tls.request("example.com").await?.succeeded);
        let run = h.sys.calls_to(bin::SYSTEMD_RUN);
        let argv = args(run.last().unwrap());
        let credential = format!("LoadCredential=oxpanel-acme-eab:{}", file.display());
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--property" && w[1] == credential));
        assert!(argv.contains(&"--eab".to_owned()));
        for c in h.sys.calls() {
            for a in args(&c) {
                assert!(
                    !a.contains("c2VjcmV0") && !a.contains("kid-1"),
                    "EAB secret in argv: {a}"
                );
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_run_that_outlives_its_site_leaves_no_state_behind() -> Result<()> {
        let h = harness().await;
        let d = Domain::parse("example.com")?;
        let rec = AutoHttpsRecord::default();
        h.tls.save_if_site_exists(&d, &rec).await?;
        assert!(state_path(&h.ctx.config, &d).exists());
        h.vhosts.remove("example.com").await?;
        assert!(!state_path(&h.ctx.config, &d).exists(), "removal drops it");
        // What a pre-check that finished after the removal used to do.
        h.tls.save_if_site_exists(&d, &rec).await?;
        assert!(
            !state_path(&h.ctx.config, &d).exists(),
            "a late run does not bring it back"
        );
        assert!(HostService::new(h.ctx.clone())
            .reconcile()
            .await?
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn state_goes_with_the_site_and_strays_are_drift() -> Result<()> {
        let h = harness().await;
        let host = HostService::new(h.ctx.clone());
        set_aliases(&h, &["nx.example.com"], AutoHttpsChoice::On).await;
        h.tls.auto_https_run("").await?;
        let d = Domain::parse("example.com")?;
        let path = state_path(h.cfg(), &d);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(host.reconcile().await?.is_empty());
        let stray = state_path(h.cfg(), &Domain::parse("gone.example")?);
        std::fs::copy(&path, &stray).unwrap();
        let drifts = host.reconcile().await?;
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].kind, DriftKind::OrphanAutoHttpsState);
        std::fs::remove_file(&stray).unwrap();
        assert!(h.vhosts.remove("example.com").await?);
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn plan_orders_covered_and_due_names_with_the_domain_first() {
        let now = now_unix();
        let mut v =
            crate::tls::tests::bare_vhost("example.com", &["www.example.com", "a.example.net"]);
        let fresh = AutoHttpsRecord::default();
        let names = |p: Vec<Domain>| p.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert_eq!(
            names(plan(&v, &fresh, now, false, false).unwrap()),
            ["example.com", "www.example.com", "a.example.net"]
        );
        let mut waiting = AutoHttpsRecord::default();
        waiting.fail("example.com", "x", now);
        assert!(
            plan(&v, &waiting, now, false, false).unwrap().is_empty(),
            "the domain is backing off"
        );
        assert_eq!(
            plan(&v, &waiting, now, true, false).unwrap().len(),
            3,
            "unless asked"
        );
        v.tls = Some(TlsRecord {
            source: CertSource::Acme,
            issuer: "CN=x".into(),
            not_before_unix: now - DAY,
            not_after_unix: now + 60 * DAY,
            names: vec!["example.com".into(), "www.example.com".into()],
            chain_pem: String::new(),
            installed_at_unix: now,
        });
        let mut alias_waits = AutoHttpsRecord::default();
        alias_waits.fail("a.example.net", "x", now);
        assert!(plan(&v, &alias_waits, now, false, false)
            .unwrap()
            .is_empty());
        assert_eq!(
            names(plan(&v, &alias_waits, now, false, true).unwrap()),
            ["example.com", "www.example.com"],
            "renewal"
        );
    }
}
