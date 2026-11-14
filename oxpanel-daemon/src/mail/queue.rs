//! The mail queue: what Postfix still holds, read with `postqueue -j` (one
//! JSON object per message), removed with `postsuper -d`, retried with
//! `postqueue -f`. Each message is attributed to the account whose domain
//! sent it (a mail domain, or a site's name).
//!
//! Postfix's tools list the host's network interfaces when they start and
//! stop if there are none; the daemon has no network (`PrivateNetwork=yes`),
//! so they run in a transient unit, started through the daemon's own binary
//! (`oxpanel-daemon mail-tool`: systemd itself may not run Postfix's
//! programs under SELinux, found on the enforcing VM), and their output is
//! read back from the journal.

use super::store::MailStore;
use crate::ctx::Ctx;
use crate::error::{Error, MailCode, Result};
use crate::system::{bin, CommandSpec};
use crate::validate::QueueId;

pub const DEFAULT_PAGE: u32 = 100;
pub const MAX_PAGE: u32 = 1000;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueueEntry {
    pub queue_id: String,
    pub tenant: String,
    pub sender: String,
    pub recipients_count: u32,
    pub size_bytes: u64,
    pub arrived_at_unix: u64,
    pub reason: String,
}

fn bounded(s: &str, n: usize) -> String {
    s.chars()
        .take(n)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Read `postqueue -j`'s lines; lines that are not such objects are skipped.
pub fn parse(text: &str) -> Vec<QueueEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(id) = v.get("queue_id").and_then(|x| x.as_str()) else {
            continue;
        };
        if QueueId::parse(id).is_err() {
            continue;
        }
        let recipients = v
            .get("recipients")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default();
        let reason = recipients
            .iter()
            .find_map(|r| r.get("delay_reason").and_then(|x| x.as_str()))
            .unwrap_or_else(|| v.get("queue_name").and_then(|x| x.as_str()).unwrap_or(""));
        out.push(QueueEntry {
            queue_id: id.to_owned(),
            tenant: String::new(),
            sender: bounded(v.get("sender").and_then(|x| x.as_str()).unwrap_or(""), 254),
            recipients_count: u32::try_from(recipients.len()).unwrap_or(u32::MAX),
            size_bytes: v
                .get("message_size")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            arrived_at_unix: v
                .get("arrival_time")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            reason: bounded(reason, 500),
        });
    }
    out
}

/// `oxpanel-daemon mail-tool <program> <args…>` (see [`tool_main`]).
pub const TOOL_SUBCOMMAND: &str = "mail-tool";

/// `oxpanel-daemon mail-tool …`, in the transient unit: run exactly one of
/// `postqueue -j`, `postqueue -f`, `postsuper -d <queue id>` and pass its
/// output on. Anything else is refused.
pub fn tool_main(args: &[String]) -> u8 {
    use std::io::Write as _;
    let argv: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    let spec = match argv.as_slice() {
        [p, "-j"] if *p == bin::POSTQUEUE => (bin::POSTQUEUE, vec!["-j".to_owned()]),
        [p, "-f"] if *p == bin::POSTQUEUE => (bin::POSTQUEUE, vec!["-f".to_owned()]),
        [p, "-d", id] if *p == bin::POSTSUPER && QueueId::parse(id).is_ok() => {
            (bin::POSTSUPER, vec!["-d".to_owned(), (*id).to_owned()])
        }
        _ => {
            let _ = writeln!(std::io::stderr(), "mail-tool: refused");
            return 64;
        }
    };
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return 70;
    };
    let cmd = CommandSpec::new(spec.0, std::time::Duration::from_secs(120)).args(&spec.1);
    match rt.block_on(crate::system::System::run(
        &crate::system::RealSystem::new(),
        cmd,
    )) {
        Ok(out) => {
            let _ = std::io::stdout().write_all(&out.stdout);
            let _ = std::io::stderr().write_all(&out.stderr);
            u8::try_from(out.code.unwrap_or(1)).unwrap_or(1)
        }
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "mail-tool: {e}");
            70
        }
    }
}

static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Run a Postfix tool in a transient unit and return what it printed.
pub(super) async fn tool(ctx: &Ctx, program: &'static str, args: &[&str]) -> Result<String> {
    let unit = format!(
        "oxpanel-mailq-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let timeout = ctx.config.command_timeout;
    let started = crate::records::now_unix();
    let ran = ctx
        .sys
        .run(
            CommandSpec::new(bin::SYSTEMD_RUN, timeout)
                .args(["--wait", "--collect", "--quiet"])
                .arg(format!("--unit={unit}"))
                .arg("--")
                .arg(&ctx.config.worker_exe)
                .arg(TOOL_SUBCOMMAND)
                .arg(program)
                .args(args),
        )
        .await?;
    let journal = ctx
        .sys
        .run(
            CommandSpec::new(bin::JOURNALCTL, timeout)
                .args(["--no-pager", "--output=cat", "--since"])
                .arg(format!("@{started}"))
                .arg("--unit")
                .arg(format!("{unit}.service")),
        )
        .await?;
    if !ran.success() {
        return Err(Error::Internal(format!(
            "{program} failed: {}",
            journal.stdout_lossy().lines().last().unwrap_or("")
        )));
    }
    Ok(journal.stdout_lossy())
}

async fn read(ctx: &Ctx) -> Result<Vec<QueueEntry>> {
    let mut entries = parse(&tool(ctx, bin::POSTQUEUE, &["-j"]).await?);
    let domains = MailStore::new(&ctx.config).list()?;
    let vhosts = ctx.store.list_vhosts()?;
    for e in &mut entries {
        let Some((_, dom)) = e.sender.rsplit_once('@') else {
            continue;
        };
        let dom = dom.to_ascii_lowercase();
        e.tenant = domains
            .iter()
            .find(|d| d.domain == dom)
            .map(|d| d.tenant.clone())
            .or_else(|| {
                vhosts
                    .iter()
                    .find(|v| v.all_names().any(|n| n == dom))
                    .map(|v| v.tenant.clone())
            })
            .unwrap_or_default();
    }
    entries.sort_by(|a, b| {
        b.arrived_at_unix
            .cmp(&a.arrived_at_unix)
            .then(a.queue_id.cmp(&b.queue_id))
    });
    Ok(entries)
}

pub async fn list(ctx: &Ctx, page: u32, size: u32) -> Result<(Vec<QueueEntry>, u32)> {
    let size = match size {
        0 => DEFAULT_PAGE,
        n => n.min(MAX_PAGE),
    };
    let all = read(ctx).await?;
    let total = u32::try_from(all.len()).unwrap_or(u32::MAX);
    let start = usize::try_from(u64::from(page) * u64::from(size)).unwrap_or(usize::MAX);
    Ok((
        all.into_iter().skip(start).take(size as usize).collect(),
        total,
    ))
}

/// Remove one message (it must be in the queue).
pub async fn delete(ctx: &Ctx, id: &QueueId) -> Result<bool> {
    if !read(ctx).await?.iter().any(|e| e.queue_id == id.as_str()) {
        return Err(Error::mail(
            MailCode::QueuedMailNotFound,
            format!("{} is not in the mail queue", id.as_str()),
        ));
    }
    tool(ctx, bin::POSTSUPER, &["-d", id.as_str()]).await?;
    tracing::info!(queue_id = id.as_str(), "queued message removed");
    Ok(true)
}

/// Try to deliver everything now; returns how many messages were queued.
pub async fn flush(ctx: &Ctx) -> Result<u32> {
    let n = u32::try_from(read(ctx).await?.len()).unwrap_or(u32::MAX);
    tool(ctx, bin::POSTQUEUE, &["-f"]).await?;
    Ok(n)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn postqueue_json_is_read_and_bounded() {
        let text = r#"{"queue_name": "deferred", "queue_id": "4F2A1C0E3B", "arrival_time": 1763200000, "message_size": 2048, "forced_expire": false, "sender": "info@example.com", "recipients": [{"address": "a@gmail.com", "delay_reason": "connect to gmail-smtp-in.l.google.com: Connection timed out"}, {"address": "b@x.test"}]}
not json
{"queue_name": "active", "queue_id": "bad id!", "recipients": []}
{"queue_name": "hold", "queue_id": "9ABCDEF012", "arrival_time": 5, "sender": "", "recipients": []}"#;
        let e = parse(text);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].queue_id, "4F2A1C0E3B");
        assert_eq!(e[0].recipients_count, 2);
        assert_eq!(e[0].size_bytes, 2048);
        assert!(e[0].reason.contains("timed out"));
        assert_eq!(e[1].reason, "hold");
    }
}
