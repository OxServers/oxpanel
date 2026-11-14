//! The mail policy service: `oxpanel-daemon mail-policy`, run by
//! `oxpanel-mail-policy.service` as the unprivileged account `oxpanel-mail`.
//!
//! It is the one place that counts what accounts send, and it answers two
//! kinds of clients on two UNIX sockets in `/run/oxpanel-mail`:
//!
//! - **Postfix** (`policy.sock`, group `postfix` only), at the end of every
//!   message a mailbox sends through submission: is the mailbox enabled, is
//!   its account suspended, would the message (counted per recipient) go
//!   over the mailbox's or the account's hourly limit? Postfix defers (4xx)
//!   or refuses accordingly; the counters only grow when it may go.
//! - **Sites** (`sendmail.sock`, open to every local process), through
//!   OxPanel's sendmail (`oxpanel-daemon sendmail`, PHP's `sendmail_path`).
//!   The account is the uid the kernel reports for the connection
//!   (`SO_PEERCRED`), never something the client says. The sender must be
//!   at one of the account's domains (its sites' names, its mail domains),
//!   in the envelope and in `From:`; the account must not be suspended and
//!   the recipients must fit in its hourly limit. The message is then handed
//!   to Postfix through `public/oxinject` (reachable by the `postdrop` group
//!   only) under the login `site.<account>`, so the filter signs it with the
//!   domain's DKIM key and the log names the account.
//!
//! What it knows comes from `policy.json`, which the daemon renders from
//! the records (re-read when it changes). Counters are per clock hour (UTC)
//! and kept in `usage/usage.json`, so a restart does not reset a limit.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use super::render::{site_login, PolicyMap};
use crate::fsutil;

pub const SUBCOMMAND: &str = "mail-policy";
/// Postfix's socket for mail the policy service hands in.
pub const INJECT_SOCKET: &str = "/var/spool/postfix/public/oxinject";
/// Most recipients one site message may have.
pub const MAX_SITE_RECIPIENTS: usize = 100;
/// Largest header line or request the service reads.
const MAX_LINE: usize = 64 * 1024;
const MAX_POLICY_ATTRS: usize = 100;

/// Counters of the current hour.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// Hours since the epoch (UTC).
    pub hour: u64,
    pub accounts: BTreeMap<String, u32>,
    pub mailboxes: BTreeMap<String, u32>,
}

impl Usage {
    fn roll(&mut self, hour: u64) {
        if self.hour != hour {
            *self = Self {
                hour,
                ..Self::default()
            };
        }
    }
}

pub fn current_hour() -> u64 {
    crate::records::now_unix() / 3600
}

/// Where the counters are, below the mail state directory.
pub fn usage_path(state_dir: &Path) -> PathBuf {
    state_dir.join("usage").join("usage.json")
}

/// Recipients `account` sent to in the current hour, as the service last
/// wrote it (0 when unknown).
pub fn sent_this_hour(state_dir: &Path, account: &str) -> u32 {
    fsutil::read_untrusted(&usage_path(state_dir), 4 * 1024 * 1024)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice::<Usage>(&b).ok())
        .filter(|u| u.hour == current_hour())
        .and_then(|u| u.accounts.get(account).copied())
        .unwrap_or(0)
}

/// The decision about one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Temporary: try again later (a limit).
    Defer(String),
    /// Permanent.
    Refuse(String),
}

/// The service's state.
#[derive(Debug, Default)]
pub struct Policy {
    pub map: PolicyMap,
    pub usage: Usage,
}

impl Policy {
    /// A mailbox (a login) wants to send to `recipients`.
    pub fn mailbox(&mut self, login: &str, recipients: u32, hour: u64) -> Verdict {
        let login = login.to_ascii_lowercase();
        let Some(mb) = self.map.mailboxes.get(&login).cloned() else {
            return Verdict::Refuse(format!("5.7.1 {login} is not a mailbox of this host"));
        };
        let Some(acct) = self.map.accounts.get(&mb.account).cloned() else {
            return Verdict::Refuse("5.7.1 unknown account".to_owned());
        };
        if acct.suspended {
            return Verdict::Refuse("5.7.1 the account is suspended".to_owned());
        }
        if !mb.enabled {
            return Verdict::Refuse("5.7.1 the mailbox is disabled".to_owned());
        }
        self.usage.roll(hour);
        let n = recipients.max(1);
        let a = self.usage.accounts.get(&mb.account).copied().unwrap_or(0);
        let m = self.usage.mailboxes.get(&login).copied().unwrap_or(0);
        if acct.rate_mailbox > 0 && m.saturating_add(n) > acct.rate_mailbox {
            return Verdict::Defer(format!(
                "4.7.1 this mailbox may send to {} recipients per hour; try again later",
                acct.rate_mailbox
            ));
        }
        if acct.rate_account > 0 && a.saturating_add(n) > acct.rate_account {
            return Verdict::Defer(format!(
                "4.7.1 this account may send to {} recipients per hour; try again later",
                acct.rate_account
            ));
        }
        self.usage
            .accounts
            .insert(mb.account.clone(), a.saturating_add(n));
        self.usage.mailboxes.insert(login, m.saturating_add(n));
        Verdict::Allow
    }

    /// The account of `uid`, if it is one.
    pub fn account_of(&self, uid: u32) -> Option<String> {
        self.map
            .accounts
            .iter()
            .find(|(_, a)| a.uid == uid)
            .map(|(n, _)| n.clone())
    }

    /// A site of `account` wants to send as `sender` (and `from`, the
    /// header's addresses) to `recipients`.
    pub fn site(
        &mut self,
        account: &str,
        sender: &str,
        from: &[String],
        recipients: u32,
        hour: u64,
    ) -> Verdict {
        let Some(acct) = self.map.accounts.get(account).cloned() else {
            return Verdict::Refuse("not a hosting account".to_owned());
        };
        if acct.suspended {
            return Verdict::Refuse("the account is suspended".to_owned());
        }
        let owned = |addr: &str| {
            addr.rsplit_once('@').is_some_and(|(_, d)| {
                let d = d.to_ascii_lowercase();
                acct.sender_domains
                    .iter()
                    .any(|o| d == *o || d.ends_with(&format!(".{o}")))
            })
        };
        if !owned(sender) {
            return Verdict::Refuse(format!(
                "the sender {sender} is not at one of this account's domains"
            ));
        }
        if let Some(bad) = from.iter().find(|f| !owned(f)) {
            return Verdict::Refuse(format!(
                "From: {bad} is not at one of this account's domains"
            ));
        }
        self.usage.roll(hour);
        let n = recipients.max(1);
        let a = self.usage.accounts.get(account).copied().unwrap_or(0);
        if acct.rate_account > 0 && a.saturating_add(n) > acct.rate_account {
            return Verdict::Defer(format!(
                "this account may send to {} recipients per hour; try again later",
                acct.rate_account
            ));
        }
        self.usage
            .accounts
            .insert(account.to_owned(), a.saturating_add(n));
        Verdict::Allow
    }
}

// ---- Postfix's policy protocol ------------------------------------------------

/// The answer to one policy request (`name=value` lines, then an empty line).
pub fn answer(policy: &mut Policy, attrs: &BTreeMap<String, String>, hour: u64) -> String {
    let login = attrs.get("sasl_username").map_or("", String::as_str);
    let action = if login.is_empty() {
        "DUNNO".to_owned()
    } else {
        let n = attrs
            .get("recipient_count")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(1);
        match policy.mailbox(login, n, hour) {
            Verdict::Allow => "DUNNO".to_owned(),
            Verdict::Defer(why) => format!("DEFER_IF_PERMIT {why}"),
            Verdict::Refuse(why) => format!("REJECT {why}"),
        }
    };
    format!("action={action}\n\n")
}

/// Read one request; `None` at the end of the connection.
async fn read_request<R: AsyncBufReadExt + Unpin>(r: &mut R) -> Option<BTreeMap<String, String>> {
    let mut attrs = BTreeMap::new();
    loop {
        let mut line = String::new();
        let n = r.read_line(&mut line).await.ok()?;
        if n == 0 || line.len() > MAX_LINE {
            return None;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            return Some(attrs);
        }
        if attrs.len() >= MAX_POLICY_ATTRS {
            return None;
        }
        if let Some((k, v)) = line.split_once('=') {
            attrs.insert(k.to_owned(), v.to_owned());
        }
    }
}

// ---- Site mail -----------------------------------------------------------------

/// What OxPanel's sendmail sends before the message.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitRequest {
    /// `-f`, if given.
    #[serde(default)]
    pub sender: Option<String>,
    #[serde(default)]
    pub recipients: Vec<String>,
    /// `-t`: take recipients from To:, Cc: and Bcc: (Bcc: is removed).
    #[serde(default)]
    pub extract: bool,
}

/// An address OxPanel will put in an SMTP command: printable, no spaces, no
/// angle brackets, one `@` with something on both sides, at most 254 bytes.
pub fn plain_address(a: &str) -> bool {
    a.len() <= 254
        && a.bytes().all(|b| {
            b.is_ascii_graphic()
                && !matches!(b, b'<' | b'>' | b'"' | b'(' | b')' | b',' | b';' | b'\\')
        })
        && a.split_once('@')
            .is_some_and(|(l, d)| !l.is_empty() && !d.is_empty() && !d.contains('@'))
}

/// The header block and the body of a message (`\n` or `\r\n` lines).
pub fn split_message(msg: &[u8]) -> (&[u8], &[u8]) {
    for (i, w) in msg.windows(2).enumerate() {
        if w == b"\n\n" {
            return (
                msg.get(..=i).unwrap_or_default(),
                msg.get(i + 2..).unwrap_or_default(),
            );
        }
        if i + 3 < msg.len() && msg.get(i..i + 4) == Some(b"\r\n\r\n") {
            return (
                msg.get(..i + 2).unwrap_or_default(),
                msg.get(i + 4..).unwrap_or_default(),
            );
        }
    }
    (msg, &[])
}

/// Unfolded headers, `(lower-case name, value)`.
pub fn headers(block: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(block);
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.split('\n').map(|l| l.trim_end_matches('\r')) {
        if line.starts_with([' ', '\t']) {
            if let Some(last) = out.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
        } else if let Some((n, v)) = line.split_once(':') {
            out.push((n.trim().to_ascii_lowercase(), v.trim().to_owned()));
        }
    }
    out
}

/// The addresses in an address-list header value: `<...>` where present,
/// otherwise the bare words with an `@`; display names, quoted strings and
/// comments are skipped.
pub fn addresses(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0u32;
    let mut quoted = false;
    let mut current = String::new();
    let mut parts = Vec::new();
    for c in value.chars() {
        match c {
            '"' if depth == 0 => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => depth = depth.saturating_sub(1),
            ',' if !quoted && depth == 0 => parts.push(std::mem::take(&mut current)),
            _ if quoted || depth > 0 => {}
            _ => current.push(c),
        }
    }
    parts.push(current);
    for p in parts {
        let p = p.trim();
        let addr = match (p.rfind('<'), p.rfind('>')) {
            (Some(a), Some(b)) if a < b => p.get(a + 1..b).unwrap_or("").trim().to_owned(),
            _ => p
                .split_whitespace()
                .find(|w| w.contains('@'))
                .unwrap_or("")
                .to_owned(),
        };
        if !addr.is_empty() {
            out.push(addr);
        }
    }
    out
}

/// A site's message, checked: envelope sender, header senders, recipients,
/// and the message to hand in (Bcc: removed with `-t`, From: added when
/// missing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteMessage {
    pub sender: String,
    pub from: Vec<String>,
    pub recipients: Vec<String>,
    pub message: Vec<u8>,
}

pub fn prepare(req: &SubmitRequest, msg: &[u8]) -> Result<SiteMessage, String> {
    let (block, body) = split_message(msg);
    let hs = headers(block);
    let from: Vec<String> = hs
        .iter()
        .filter(|(n, _)| n == "from")
        .flat_map(|(_, v)| addresses(v))
        .collect();
    let sender = match (&req.sender, from.first()) {
        (Some(s), _) if !s.is_empty() => s.clone(),
        (_, Some(f)) => f.clone(),
        _ => {
            return Err(
                "no sender: give a From: header (or -f) with an address at one of your domains"
                    .to_owned(),
            )
        }
    };
    if !plain_address(&sender) {
        return Err(format!(
            "the sender '{}' is not a plain address",
            printable(&sender)
        ));
    }
    let mut recipients = req.recipients.clone();
    if req.extract {
        for (n, v) in &hs {
            if matches!(n.as_str(), "to" | "cc" | "bcc") {
                recipients.extend(addresses(v));
            }
        }
    }
    recipients.dedup();
    if recipients.is_empty() {
        return Err("no recipients".to_owned());
    }
    if recipients.len() > MAX_SITE_RECIPIENTS {
        return Err(format!(
            "at most {MAX_SITE_RECIPIENTS} recipients per message"
        ));
    }
    if let Some(bad) = recipients.iter().find(|r| !plain_address(r)) {
        return Err(format!("'{}' is not a plain address", printable(bad)));
    }
    // Rebuild the header block: Bcc: dropped with -t, From: added if missing.
    let mut out = Vec::with_capacity(msg.len() + 64);
    if from.is_empty() {
        out.extend_from_slice(format!("From: <{sender}>\n").as_bytes());
    }
    let text = String::from_utf8_lossy(block);
    let mut skipping = false;
    for line in text.split_inclusive('\n') {
        let cont = line.starts_with([' ', '\t']);
        if !cont {
            skipping = req.extract && line.to_ascii_lowercase().starts_with("bcc:");
        }
        if !skipping {
            out.extend_from_slice(line.as_bytes());
        }
    }
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    out.push(b'\n');
    out.extend_from_slice(body);
    Ok(SiteMessage {
        sender,
        from,
        recipients,
        message: out,
    })
}

fn printable(s: &str) -> String {
    s.chars()
        .take(80)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// The message as SMTP DATA: CRLF line ends, dot-stuffed, terminated.
pub fn smtp_data(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + msg.len() / 40 + 8);
    for line in msg.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.first() == Some(&b'.') {
            out.push(b'.');
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    // `split` yields an empty last piece after a final newline.
    if msg.ends_with(b"\n") {
        out.truncate(out.len() - 2);
    }
    out.extend_from_slice(b".\r\n");
    out
}

async fn reply<R: AsyncBufReadExt + Unpin>(r: &mut R) -> Result<(u16, String), String> {
    let mut text = String::new();
    loop {
        let mut line = String::new();
        let n = r.read_line(&mut line).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("the mail server closed the connection".to_owned());
        }
        text.push_str(line.trim_end());
        text.push(' ');
        if line.as_bytes().get(3) != Some(&b'-') {
            let code = line.get(..3).and_then(|c| c.parse().ok()).unwrap_or(0);
            return Ok((code, text.trim().to_owned()));
        }
    }
}

/// Hand a checked message to Postfix as `site.<account>`. Returns Postfix's
/// last answer (with the queue id).
pub async fn inject(socket: &Path, account: &str, m: &SiteMessage) -> Result<String, String> {
    let stream = UnixStream::connect(socket)
        .await
        .map_err(|e| format!("cannot reach the mail server: {e}"))?;
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);
    let expect = |got: (u16, String), want: u16| {
        if got.0 == want {
            Ok(got.1)
        } else {
            Err(format!("the mail server refused: {}", got.1))
        }
    };
    expect(reply(&mut rd).await?, 220)?;
    let mut commands = vec![
        ("EHLO localhost".to_owned(), 250),
        (format!("XCLIENT LOGIN={}", site_login(account)), 220),
        ("EHLO localhost".to_owned(), 250),
        (format!("MAIL FROM:<{}>", m.sender), 250),
    ];
    for r in &m.recipients {
        commands.push((format!("RCPT TO:<{r}>"), 250));
    }
    commands.push(("DATA".to_owned(), 354));
    for (cmd, want) in commands {
        wr.write_all(format!("{cmd}\r\n").as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let got = reply(&mut rd).await?;
        // RCPT may answer 251 too.
        if !(got.0 == want || (want == 250 && got.0 == 251)) {
            return Err(format!("the mail server refused: {}", got.1));
        }
    }
    wr.write_all(&smtp_data(&m.message))
        .await
        .map_err(|e| e.to_string())?;
    let done = expect(reply(&mut rd).await?, 250)?;
    let _ = wr.write_all(b"QUIT\r\n").await;
    Ok(done)
}

// ---- The service -----------------------------------------------------------------

struct Service {
    map_path: PathBuf,
    usage_path: PathBuf,
    inject_socket: PathBuf,
    max_message: u64,
    state: Mutex<(Policy, Option<std::time::SystemTime>)>,
}

impl Service {
    /// Re-read the map if it changed. A map that cannot be read leaves the
    /// previous one (an empty one at start: nothing is allowed).
    async fn refresh(&self) {
        let mtime = std::fs::metadata(&self.map_path)
            .and_then(|m| m.modified())
            .ok();
        let mut st = self.state.lock().await;
        if mtime.is_some() && mtime != st.1 {
            if let Some(map) = fsutil::read_untrusted(&self.map_path, 64 * 1024 * 1024)
                .ok()
                .flatten()
                .and_then(|b| serde_json::from_slice::<PolicyMap>(&b).ok())
            {
                st.0.map = map;
                st.1 = mtime;
            } else {
                tracing::error!(path = %self.map_path.display(), "the policy map cannot be read; keeping the previous one");
            }
        }
    }

    async fn save_usage(&self, usage: &Usage) {
        if let Ok(bytes) = serde_json::to_vec(usage) {
            if let Err(e) = fsutil::write_atomic(&self.usage_path, &bytes, 0o640) {
                tracing::warn!(error = %e, "counters not saved");
            }
        }
    }

    async fn postfix(self: Arc<Self>, stream: UnixStream) {
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);
        while let Some(attrs) = read_request(&mut rd).await {
            self.refresh().await;
            let (text, usage) = {
                let mut st = self.state.lock().await;
                let text = answer(&mut st.0, &attrs, current_hour());
                (text, st.0.usage.clone())
            };
            if text.starts_with("action=DUNNO") && attrs.contains_key("sasl_username") {
                self.save_usage(&usage).await;
            }
            if wr.write_all(text.as_bytes()).await.is_err() {
                return;
            }
        }
    }

    async fn site(self: Arc<Self>, stream: UnixStream) {
        let uid = stream.peer_cred().ok().map(|c| c.uid());
        let (rd, mut wr) = stream.into_split();
        let result = self.site_inner(uid, rd).await;
        let line = match result {
            Ok(done) => format!("OK {done}\n"),
            Err((code, why)) => format!("{code} {}\n", printable(&why)),
        };
        let _ = wr.write_all(line.as_bytes()).await;
    }

    async fn site_inner(
        &self,
        uid: Option<u32>,
        rd: tokio::net::unix::OwnedReadHalf,
    ) -> Result<String, (&'static str, String)> {
        self.refresh().await;
        let Some(uid) = uid else {
            return Err(("ERR", "no peer credentials".to_owned()));
        };
        let account = self.state.lock().await.0.account_of(uid);
        let Some(account) = account else {
            return Err(("NOTACCOUNT", "not a hosting account".to_owned()));
        };
        let mut rd = BufReader::new(rd);
        let mut head = String::new();
        rd.read_line(&mut head)
            .await
            .map_err(|e| ("ERR", e.to_string()))?;
        let req: SubmitRequest =
            serde_json::from_str(head.trim()).map_err(|_| ("ERR", "bad request".to_owned()))?;
        let mut msg = Vec::new();
        let limit = self.max_message + 1;
        (&mut rd)
            .take(limit)
            .read_to_end(&mut msg)
            .await
            .map_err(|e| ("ERR", e.to_string()))?;
        if msg.len() as u64 >= limit {
            return Err(("ERR", "the message is too large".to_owned()));
        }
        let m = prepare(&req, &msg).map_err(|e| ("ERR", e))?;
        let n = u32::try_from(m.recipients.len()).unwrap_or(u32::MAX);
        let (verdict, usage) = {
            let mut st = self.state.lock().await;
            let v = st.0.site(&account, &m.sender, &m.from, n, current_hour());
            (v, st.0.usage.clone())
        };
        match verdict {
            Verdict::Allow => self.save_usage(&usage).await,
            Verdict::Defer(why) => return Err(("TEMP", why)),
            Verdict::Refuse(why) => return Err(("ERR", why)),
        }
        let done = inject(&self.inject_socket, &account, &m)
            .await
            .map_err(|e| ("TEMP", e))?;
        tracing::info!(account, sender = %m.sender, recipients = n, "site mail handed in");
        Ok(done)
    }
}

/// Bind a socket, replacing a stale one, with `mode` and (if given) the
/// group `group`, of which the service must be a member.
fn bind(path: &Path, mode: u32, group: Option<&str>) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path)?;
    if let Some(g) = group {
        let gid = nix::unistd::Group::from_name(g)
            .map_err(std::io::Error::other)?
            .ok_or_else(|| std::io::Error::other(format!("no group {g}")))?
            .gid;
        nix::unistd::chown(path, None, Some(gid)).map_err(std::io::Error::other)?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(l)
}

/// `oxpanel-daemon mail-policy`: serve until stopped.
pub fn main(args: &[String]) -> u8 {
    let cfg = super::config::MailConfig::default();
    let mut state_dir = cfg.state_dir.clone();
    let mut run_dir = cfg.run_dir.clone();
    let mut inject_socket = PathBuf::from(INJECT_SOCKET);
    let mut max_message = cfg.message_max_bytes;
    // Postfix's group may ask; tests run without it.
    let mut policy_group = Some("postfix".to_owned());
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        let v = it.next().cloned().unwrap_or_default();
        match a.as_str() {
            "--state-dir" => state_dir = PathBuf::from(v),
            "--run-dir" => run_dir = PathBuf::from(v),
            "--inject-socket" => inject_socket = PathBuf::from(v),
            "--max-message" => max_message = v.parse().unwrap_or(max_message),
            "--policy-group" => policy_group = (!v.is_empty()).then_some(v),
            _ => {
                tracing::error!(argument = %a, "unknown argument");
                return 64;
            }
        }
    }
    let usage_path = usage_path(&state_dir);
    let usage = fsutil::read_untrusted(&usage_path, 64 * 1024 * 1024)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice::<Usage>(&b).ok())
        .unwrap_or_default();
    let service = Arc::new(Service {
        map_path: state_dir.join("policy.json"),
        usage_path,
        inject_socket,
        max_message,
        state: Mutex::new((
            Policy {
                map: PolicyMap::default(),
                usage,
            },
            None,
        )),
    });
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "no runtime");
            return 1;
        }
    };
    rt.block_on(async move {
        let postfix = match bind(&run_dir.join("policy.sock"), 0o660, policy_group.as_deref()) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, "cannot listen for Postfix");
                return 1;
            }
        };
        let sites = match bind(&run_dir.join("sendmail.sock"), 0o666, None) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, "cannot listen for sites");
                return 1;
            }
        };
        service.refresh().await;
        let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
        tracing::info!("mail policy service ready");
        loop {
            tokio::select! {
                Ok((s, _)) = postfix.accept() => { tokio::spawn(Arc::clone(&service).postfix(s)); }
                Ok((s, _)) = sites.accept() => { tokio::spawn(Arc::clone(&service).site(s)); }
                _ = tokio::signal::ctrl_c() => return 0,
            }
        }
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::mail::render::{PolicyAccount, PolicyMailbox};

    fn policy() -> Policy {
        let mut map = PolicyMap::default();
        map.accounts.insert(
            "alice".into(),
            PolicyAccount {
                uid: 20000,
                suspended: false,
                rate_account: 5,
                rate_mailbox: 3,
                sender_domains: vec!["example.com".into(), "shop.test".into()],
            },
        );
        map.accounts.insert(
            "bob".into(),
            PolicyAccount {
                uid: 20001,
                suspended: true,
                rate_account: 0,
                rate_mailbox: 0,
                sender_domains: vec!["bob.test".into()],
            },
        );
        for (addr, account, enabled) in [
            ("info@example.com", "alice", true),
            ("sales@example.com", "alice", true),
            ("off@example.com", "alice", false),
            ("me@bob.test", "bob", true),
        ] {
            map.mailboxes.insert(
                addr.into(),
                PolicyMailbox {
                    account: account.into(),
                    enabled,
                },
            );
        }
        Policy {
            map,
            usage: Usage::default(),
        }
    }

    #[test]
    fn mailbox_and_account_limits_count_recipients_per_hour() {
        let mut p = policy();
        assert_eq!(p.mailbox("info@example.com", 2, 10), Verdict::Allow);
        assert!(
            matches!(p.mailbox("INFO@example.com", 2, 10), Verdict::Defer(w) if w.contains("3 recipients"))
        );
        assert_eq!(p.mailbox("info@example.com", 1, 10), Verdict::Allow);
        assert_eq!(p.mailbox("sales@example.com", 2, 10), Verdict::Allow);
        // The account has used 5 of 5: another mailbox is held back too.
        assert!(
            matches!(p.mailbox("sales@example.com", 1, 10), Verdict::Defer(w) if w.contains("account"))
        );
        // A new hour starts afresh.
        assert_eq!(p.mailbox("sales@example.com", 1, 11), Verdict::Allow);
        assert!(matches!(
            p.mailbox("off@example.com", 1, 11),
            Verdict::Refuse(_)
        ));
        assert!(
            matches!(p.mailbox("me@bob.test", 1, 11), Verdict::Refuse(w) if w.contains("suspended"))
        );
        assert!(matches!(
            p.mailbox("nobody@example.com", 1, 11),
            Verdict::Refuse(_)
        ));
    }

    #[test]
    fn policy_answers_in_postfixs_words() {
        let mut p = policy();
        let attrs = |user: &str, n: &str| {
            BTreeMap::from([
                ("request".to_owned(), "smtpd_access_policy".to_owned()),
                ("sasl_username".to_owned(), user.to_owned()),
                ("recipient_count".to_owned(), n.to_owned()),
            ])
        };
        assert_eq!(answer(&mut p, &attrs("", "1"), 1), "action=DUNNO\n\n");
        assert_eq!(
            answer(&mut p, &attrs("info@example.com", "3"), 1),
            "action=DUNNO\n\n"
        );
        assert!(answer(&mut p, &attrs("info@example.com", "1"), 1)
            .starts_with("action=DEFER_IF_PERMIT 4.7.1"));
        assert!(answer(&mut p, &attrs("me@bob.test", "1"), 1).starts_with("action=REJECT 5.7.1"));
    }

    #[test]
    fn sites_send_only_from_their_own_domains_within_the_limit() {
        let mut p = policy();
        assert_eq!(p.account_of(20000).as_deref(), Some("alice"));
        assert_eq!(p.account_of(0), None);
        assert_eq!(
            p.site(
                "alice",
                "wordpress@shop.test",
                &["wordpress@shop.test".into()],
                2,
                1
            ),
            Verdict::Allow
        );
        assert_eq!(
            p.site("alice", "x@www.example.com", &[], 1, 1),
            Verdict::Allow
        );
        assert!(matches!(
            p.site("alice", "ceo@bob.test", &[], 1, 1),
            Verdict::Refuse(_)
        ));
        assert!(
            matches!(p.site("alice", "a@example.com", &["ceo@bank.test".into()], 1, 1), Verdict::Refuse(w) if w.contains("From"))
        );
        assert!(matches!(
            p.site("alice", "a@notexample.com", &[], 1, 1),
            Verdict::Refuse(_)
        ));
        assert!(matches!(
            p.site("alice", "a@example.com", &[], 3, 1),
            Verdict::Defer(_)
        ));
        assert!(
            matches!(p.site("bob", "me@bob.test", &[], 1, 1), Verdict::Refuse(w) if w.contains("suspended"))
        );
    }

    #[test]
    fn messages_are_parsed_and_rebuilt_safely() {
        let msg = b"From: \"Shop, Inc\" <shop@shop.test>\nTo: a@x.test, \"B (b)\" <b@y.test>\nBcc: secret@z.test,\n  hidden@z.test\nSubject: hi\n\n.leading dot\nbody\n";
        let req = SubmitRequest {
            sender: None,
            recipients: vec![],
            extract: true,
        };
        let m = prepare(&req, msg).unwrap();
        assert_eq!(m.sender, "shop@shop.test");
        assert_eq!(
            m.recipients,
            ["a@x.test", "b@y.test", "secret@z.test", "hidden@z.test"]
        );
        let out = String::from_utf8(m.message.clone()).unwrap();
        assert!(!out.to_ascii_lowercase().contains("bcc"), "{out}");
        assert!(!out.contains("hidden@"), "{out}");
        let data = String::from_utf8(smtp_data(&m.message)).unwrap();
        assert!(data.contains("\r\n..leading dot\r\n"), "{data}");
        assert!(data.ends_with("body\r\n.\r\n"), "{data}");
        // No From: and no -f: refused; -f alone adds the header.
        let bare = b"To: a@x.test\n\nhi\n";
        assert!(prepare(&req, bare).is_err());
        let with_f = SubmitRequest {
            sender: Some("noreply@shop.test".into()),
            ..req.clone()
        };
        let m = prepare(&with_f, bare).unwrap();
        assert!(m.message.starts_with(b"From: <noreply@shop.test>\n"));
        // Injection through an address is impossible.
        for bad in ["a@b.test>\r\nRCPT TO:<x@y", "a b@c.test", "nobody", "a@b@c"] {
            assert!(!plain_address(bad), "{bad}");
        }
        let evil = SubmitRequest {
            sender: Some("x@shop.test>\r\nDATA".into()),
            ..req
        };
        assert!(prepare(&evil, bare).is_err());
    }
}
