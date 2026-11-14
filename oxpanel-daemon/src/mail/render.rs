//! Every file of the mail servers, rendered from records only.
//!
//! The inputs are the mail domain records, the account records and the host
//! settings, gathered once into a [`Model`]. Every value that reaches a file
//! was validated (domains, local parts, destinations, selectors, hashes,
//! paths through [`crate::nginx::safe_path_str`]); the renderers add only
//! constant text. Each file has one header line saying who manages it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::config::MailConfig;
use super::store::{MailDomainRecord, MailMode, RecordState};
use crate::error::Result;
use crate::nginx::safe_path_str;
use crate::validate::Domain;

pub const HEADER: &str = "# Managed by oxpanel-daemon. Manual edits will be overwritten.\n";

/// The login name site mail is injected under (`site.<account>`): no `@`,
/// so it can never be a mailbox's login.
pub fn site_login(account: &str) -> String {
    format!("site.{account}")
}

/// An account as the mail servers see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    pub suspended: bool,
    /// Recipients per hour (0 = unlimited).
    pub rate_account: u32,
    pub rate_mailbox: u32,
    /// Domains the account's sites may send from: its sites' names and its
    /// mail domains (and the names below them).
    pub sender_domains: BTreeSet<String>,
}

/// Everything the mail files are rendered from.
#[derive(Debug, Clone)]
pub struct Model {
    pub hostname: Domain,
    pub accounts: BTreeMap<String, Account>,
    /// Mail domains not being removed whose account exists, by name.
    pub domains: Vec<MailDomainRecord>,
    /// The certificate and key of the mail host name.
    pub cert: PathBuf,
    pub key: PathBuf,
    pub uid_min: u32,
    pub uid_max: u32,
}

impl Model {
    /// Local mail domains.
    pub fn local(&self) -> impl Iterator<Item = &MailDomainRecord> {
        self.domains.iter().filter(|d| d.mode == MailMode::Local)
    }

    fn account(&self, d: &MailDomainRecord) -> Option<&Account> {
        self.accounts.get(&d.tenant)
    }
}

/// `<home>/mail/<domain>/<local>`: where a mailbox's mail lives, inside the
/// account's home (owned by the account, counted by its disk quota).
pub fn maildir(home: &Path, domain: &str, local: &str) -> PathBuf {
    home.join("mail").join(domain).join(local)
}

/// `<state>/sieve/<domain>/<local>.sieve`: a mailbox's autoresponder.
pub fn sieve_path(cfg: &MailConfig, domain: &str, local: &str) -> PathBuf {
    cfg.state_dir
        .join("sieve")
        .join(domain)
        .join(format!("{local}.sieve"))
}

/// `<state>/dkim/<domain>.<selector>.key`
pub fn dkim_key_path(cfg: &MailConfig, domain: &str, selector: &str) -> PathBuf {
    cfg.state_dir
        .join("dkim")
        .join(format!("{domain}.{selector}.key"))
}

pub fn policy_socket(cfg: &MailConfig) -> PathBuf {
    cfg.run_dir.join("policy.sock")
}

pub fn sendmail_socket(cfg: &MailConfig) -> PathBuf {
    cfg.run_dir.join("sendmail.sock")
}

pub fn milter_socket(cfg: &MailConfig) -> PathBuf {
    cfg.milter_dir.join("milter.sock")
}

// ---- Postfix ---------------------------------------------------------------

pub fn postfix_main(cfg: &MailConfig, m: &Model) -> Result<String> {
    let dir = safe_path_str(&cfg.postfix_dir)?;
    let maps = format!("{dir}/oxpanel");
    let cert = safe_path_str(&m.cert)?;
    let key = safe_path_str(&m.key)?;
    let milter_path = milter_socket(cfg);
    let milter = safe_path_str(&milter_path)?;
    let host = &m.hostname;
    let size = cfg.message_max_bytes;
    Ok(format!(
        "{HEADER}# OxPanel's mail server. The original main.cf is kept as main.cf.oxpanel-orig.
compatibility_level = 2
queue_directory = /var/spool/postfix
command_directory = /usr/sbin
daemon_directory = /usr/libexec/postfix
data_directory = /var/lib/postfix
mail_owner = postfix
setgid_group = postdrop
sendmail_path = /usr/sbin/sendmail.postfix
newaliases_path = /usr/bin/newaliases.postfix
mailq_path = /usr/bin/mailq.postfix
manpage_directory = /usr/share/man
shlib_directory = /usr/lib64/postfix
meta_directory = /etc/postfix

myhostname = {host}
myorigin = $myhostname
mydestination = $myhostname, localhost.$mydomain, localhost
# Only the aliases (postmaster, abuse, ...) are local recipients from outside.
local_recipient_maps = $alias_maps
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
inet_interfaces = all
inet_protocols = all
# Nothing is trusted by its address: every rule below says what it allows.
mynetworks = 127.0.0.1/32 [::1]/128
recipient_delimiter = +
smtpd_banner = $myhostname ESMTP
disable_vrfy_command = yes
smtpd_helo_required = yes
message_size_limit = {size}
mailbox_size_limit = 0
biff = no
append_dot_mydomain = no
# Sites' mail often lacks Date: and Message-ID:; receivers penalise that.
always_add_missing_headers = yes

# Only root may use sendmail(1) directly. Sites send through OxPanel's
# sendmail, which attributes, checks and limits their mail (the policy
# service) and hands it in as their account.
authorized_submit_users = root
authorized_mailq_users = root
authorized_flush_users = root

# The accounts' mail: domains, mailboxes, forwarders and catch-alls.
virtual_mailbox_domains = texthash:{maps}/domains
virtual_mailbox_maps = texthash:{maps}/mailboxes
virtual_alias_maps = texthash:{maps}/aliases
virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_alias_expansion_limit = 100
virtual_alias_recursion_limit = 10

# Logins come from Dovecot; a mailbox may send only as its own address.
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = no
smtpd_sasl_security_options = noanonymous
smtpd_sender_login_maps = texthash:{maps}/senders
broken_sasl_auth_clients = no

# Port 25 relays nothing: it accepts mail for this host's domains only.
smtpd_relay_restrictions = reject_unauth_destination
smtpd_recipient_restrictions = check_recipient_access texthash:{maps}/recipient_access, reject_unauth_destination, reject_unlisted_recipient
smtpd_sender_restrictions = reject_non_fqdn_sender
smtpd_data_restrictions = reject_unauth_pipelining

# Spam filtering and DKIM signing (Rspamd, through its milter socket).
smtpd_milters = unix:{milter}
non_smtpd_milters = $smtpd_milters
milter_protocol = 6
milter_default_action = accept
milter_mail_macros = i {{mail_addr}} {{client_addr}} {{client_name}} {{auth_authen}}

# TLS: offered on port 25, required for clients (master.cf).
smtpd_tls_cert_file = {cert}
smtpd_tls_key_file = {key}
smtpd_tls_security_level = may
smtpd_tls_auth_only = yes
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_ciphers = medium
smtpd_tls_mandatory_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, eNULL, MD5, RC4, 3DES
tls_preempt_cipherlist = yes
smtpd_tls_loglevel = 1
smtpd_tls_session_cache_database = btree:${{data_directory}}/smtpd_scache
smtp_tls_security_level = may
smtp_tls_CAfile = /etc/pki/tls/certs/ca-bundle.crt
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_loglevel = 1
smtp_tls_session_cache_database = btree:${{data_directory}}/smtp_scache
"
    ))
}

pub fn postfix_master(cfg: &MailConfig) -> Result<String> {
    let maps = format!("{}/oxpanel", safe_path_str(&cfg.postfix_dir)?);
    let policy_path = policy_socket(cfg);
    let policy = safe_path_str(&policy_path)?;
    // What submission (587, STARTTLS required) and submissions (465, TLS
    // from the first byte) share: a login, the own address, the policy
    // service (limits, suspension) at the end of each message.
    let client = format!(
        "  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_sender_restrictions=reject_sender_login_mismatch,permit_sasl_authenticated,reject
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o smtpd_recipient_restrictions=check_recipient_access,texthash:{maps}/recipient_access,permit_sasl_authenticated,reject
  -o smtpd_end_of_data_restrictions=check_policy_service,unix:{policy}
  -o milter_macro_daemon_name=ORIGINATING
"
    );
    Ok(format!(
        "{HEADER}# service type  private unpriv  chroot  wakeup  maxproc command + args
smtp      inet  n       -       n       -       -       smtpd
  -o smtpd_sasl_auth_enable=no
# Ports by number: AlmaLinux's /etc/services has no name for 465.
587       inet  n       -       n       -       -       smtpd
  -o syslog_name=postfix/submission
{client}465       inet  n       -       n       -       -       smtpd
  -o syslog_name=postfix/submissions
  -o smtpd_tls_wrappermode=yes
{client}# Site mail from OxPanel's policy service only: the socket is in public/,
# which only the postdrop group may enter; the service names the account
# with XCLIENT LOGIN=site.<account> after checking it.
oxinject  unix  n       -       n       -       -       smtpd
  -o syslog_name=postfix/oxinject
  -o smtpd_authorized_xclient_hosts=static:all
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=no
  -o smtpd_tls_security_level=none
  -o smtpd_client_restrictions=
  -o smtpd_sender_restrictions=
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o smtpd_recipient_restrictions=check_recipient_access,texthash:{maps}/recipient_access,permit_sasl_authenticated,reject
pickup    unix  n       -       n       60      1       pickup
cleanup   unix  n       -       n       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       n       1000?   1       tlsmgr
rewrite   unix  -       -       n       -       -       trivial-rewrite
bounce    unix  -       -       n       -       0       bounce
defer     unix  -       -       n       -       0       bounce
trace     unix  -       -       n       -       0       bounce
verify    unix  -       -       n       -       1       verify
flush     unix  n       -       n       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       n       -       -       smtp
relay     unix  -       -       n       -       -       smtp
  -o syslog_name=postfix/$service_name
showq     unix  n       -       n       -       -       showq
error     unix  -       -       n       -       -       error
retry     unix  -       -       n       -       -       error
discard   unix  -       -       n       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       n       -       -       lmtp
anvil     unix  -       -       n       -       1       anvil
scache    unix  -       -       n       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd
"
    ))
}

/// The maps (`texthash`, read at start and reload): domains, mailboxes,
/// aliases, senders, recipient access.
pub fn postfix_maps(m: &Model) -> BTreeMap<&'static str, String> {
    let mut domains = String::from(HEADER);
    let mut mailboxes = String::from(HEADER);
    let mut aliases = String::from(HEADER);
    let mut senders = String::from(HEADER);
    let mut access = String::from(HEADER);
    for d in m.local() {
        let Some(account) = m.account(d) else {
            continue;
        };
        let dom = &d.domain;
        let _ = writeln!(domains, "{dom} OK");
        if account.suspended {
            // Deferred, not bounced: the sender keeps it until the account is resumed.
            let _ = writeln!(access, "{dom} 450 4.2.1 mailbox temporarily unavailable");
        }
        for (local, mb) in d.live_mailboxes() {
            let addr = format!("{local}@{dom}");
            let _ = writeln!(mailboxes, "{addr} {dom}/{local}/");
            if !d.forwarders.contains_key(local) {
                // Listed for itself, so that a catch-all does not take it.
                let _ = writeln!(aliases, "{addr} {addr}");
            }
            if mb.enabled && !account.suspended {
                let _ = writeln!(senders, "{addr} {addr}");
            }
        }
        for (local, f) in &d.forwarders {
            let addr = format!("{local}@{dom}");
            let mut targets = f.destinations.clone();
            if f.keep_copy && d.live_mailboxes().any(|(l, _)| l == local) {
                targets.push(addr.clone());
            }
            if !targets.is_empty() {
                let _ = writeln!(aliases, "{addr} {}", targets.join(","));
            }
        }
        if let Some(c) = &d.catch_all {
            if d.live_mailboxes().any(|(l, _)| l == c) {
                let _ = writeln!(aliases, "@{dom} {c}@{dom}");
            }
        }
    }
    BTreeMap::from([
        ("domains", domains),
        ("mailboxes", mailboxes),
        ("aliases", aliases),
        ("senders", senders),
        ("recipient_access", access),
    ])
}

// ---- Dovecot ---------------------------------------------------------------

pub fn dovecot_conf(cfg: &MailConfig, m: &Model) -> Result<String> {
    let dir = format!("{}/oxpanel", safe_path_str(&cfg.dovecot_dir)?);
    let cert = safe_path_str(&m.cert)?;
    let key = safe_path_str(&m.key)?;
    let state = safe_path_str(&cfg.state_dir)?;
    let host = &m.hostname;
    let (uid_min, uid_max) = (m.uid_min, m.uid_max);
    let services = dovecot_services(state, host);
    Ok(format!(
        "{HEADER}# OxPanel's IMAP/POP3/LMTP server. The original is kept as dovecot.conf.oxpanel-orig.
protocols = imap pop3 lmtp
listen = *, ::
# Clients: TLS only (IMAPS 993, POP3S 995); no plain-text port is opened.
ssl = required
ssl_cert = <{cert}
ssl_key = <{key}
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
ssl_prefer_server_ciphers = yes
disable_plaintext_auth = yes
auth_mechanisms = plain login
auth_failure_delay = 2 secs
auth_cache_size = 10M
auth_cache_ttl = 1 hour
auth_cache_negative_ttl = 0
login_greeting = {host} ready.

# Mail lives in the account's home and is handled only with the account's
# identity; no other uid is accepted for a mailbox.
mail_location = maildir:~/
first_valid_uid = {uid_min}
last_valid_uid = {uid_max}
first_valid_gid = {uid_min}
last_valid_gid = {uid_max}
mail_access_groups =
mail_plugins = $mail_plugins quota
mail_max_userip_connections = 20

namespace inbox {{
  inbox = yes
  separator = /
  mailbox Drafts {{
    special_use = \\Drafts
    auto = subscribe
  }}
  mailbox Sent {{
    special_use = \\Sent
    auto = subscribe
  }}
  mailbox Junk {{
    special_use = \\Junk
    auto = subscribe
  }}
  mailbox Trash {{
    special_use = \\Trash
    auto = subscribe
  }}
}}

# Disabled mailboxes and those of suspended accounts cannot log in.
passdb {{
  driver = passwd-file
  args = {dir}/deny
  deny = yes
}}
passdb {{
  driver = passwd-file
  args = scheme=BLF-CRYPT {dir}/passwd
}}
userdb {{
  driver = passwd-file
  args = {dir}/users
}}

{services}"
    ))
}

/// Listeners, protocols and plugins of Dovecot.
fn dovecot_services(state: &str, host: &Domain) -> String {
    format!(
        "service imap-login {{
  inet_listener imap {{
    port = 0
  }}
  inet_listener imaps {{
    port = 993
    ssl = yes
  }}
}}
service pop3-login {{
  inet_listener pop3 {{
    port = 0
  }}
  inet_listener pop3s {{
    port = 995
    ssl = yes
  }}
}}
service lmtp {{
  unix_listener /var/spool/postfix/private/dovecot-lmtp {{
    mode = 0600
    user = postfix
    group = postfix
  }}
}}
service auth {{
  unix_listener /var/spool/postfix/private/auth {{
    mode = 0660
    user = postfix
    group = postfix
  }}
  unix_listener auth-userdb {{
    mode = 0600
    user = root
  }}
}}

protocol lmtp {{
  mail_plugins = $mail_plugins sieve
  postmaster_address = postmaster@{host}
}}
protocol imap {{
  mail_plugins = $mail_plugins imap_quota
}}
lmtp_rcpt_check_quota = yes

plugin {{
  quota = maildir:Mailbox
  quota_exceeded_message = 552 5.2.2 The mailbox is full.
  # Autoresponders only: one script per mailbox, written by the engine and
  # not writable by the account.
  sieve = {state}/sieve/%d/%n.sieve
  sieve_user_log = /dev/null
  sieve_extensions = +vacation +date +relational
  sieve_global_extensions =
  sieve_max_redirects = 0
  sieve_vacation_min_period = 1d
  sieve_vacation_default_period = 1d
  sieve_vacation_max_period = 30d
  sieve_vacation_dont_check_recipient = no
  sieve_vacation_send_from_recipient = yes
}}
"
    )
}

/// The password file (`address:hash`), the deny list and the user database
/// (`address::uid:gid::home::quota_rule=…`).
pub fn dovecot_files(m: &Model) -> Result<BTreeMap<&'static str, String>> {
    let mut passwd = String::new();
    let mut deny = String::new();
    let mut users = String::new();
    for d in m.local() {
        let Some(account) = m.account(d) else {
            continue;
        };
        for (local, mb) in d.live_mailboxes() {
            let addr = format!("{local}@{}", d.domain);
            let _ = writeln!(passwd, "{addr}:{}", mb.password_hash);
            if !mb.enabled || account.suspended {
                let _ = writeln!(deny, "{addr}");
            }
            let home = maildir(&account.home, &d.domain, local);
            let home = safe_path_str(&home)?;
            let quota = if mb.quota_bytes > 0 {
                format!("quota_rule=*:storage={}B", mb.quota_bytes)
            } else {
                "quota_rule=*:storage=0".to_owned()
            };
            let _ = writeln!(
                users,
                "{addr}::{}:{}::{home}::{quota}",
                account.uid, account.gid
            );
        }
    }
    Ok(BTreeMap::from([
        ("passwd", passwd),
        ("deny", deny),
        ("users", users),
    ]))
}

/// A string for Sieve: `"` and `\` escaped (line breaks are allowed inside).
fn sieve_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn iso(unix: u64) -> String {
    let t = crate::tls::format_utc(unix);
    // "2026-11-15 10:00:00 UTC" -> "2026-11-15T10:00:00Z"
    t.trim_end_matches(" UTC").replacen(' ', "T", 1) + "Z"
}

/// A mailbox's autoresponder as a Sieve script: never to lists, bulk or
/// automatic mail, nor to mail the filter marked as spam (no backscatter);
/// at most one reply per sender per day; only between the dates.
pub fn sieve_script(addr: &str, r: &super::store::AutoreplyRecord) -> String {
    let mut out = String::from(
        "# Managed by oxpanel-daemon. Manual edits will be overwritten.\nrequire [\"vacation\", \"date\", \"relational\"];\n",
    );
    out.push_str("if anyof (exists \"list-id\", exists \"list-unsubscribe\", header :contains \"precedence\" [\"bulk\", \"list\", \"junk\"], header :contains \"x-spam\" \"yes\", header :contains \"x-spam-status\" \"yes\") { stop; }\n");
    let mut conds = Vec::new();
    if let Some(s) = r.starts_at_unix {
        conds.push(format!(
            "currentdate :zone \"+0000\" :value \"ge\" \"iso8601\" {}",
            sieve_str(&iso(s))
        ));
    }
    if let Some(e) = r.ends_at_unix {
        conds.push(format!(
            "currentdate :zone \"+0000\" :value \"lt\" \"iso8601\" {}",
            sieve_str(&iso(e))
        ));
    }
    let vacation = format!(
        "vacation :days 1 :addresses [{}] :subject {} {};\n",
        sieve_str(addr),
        sieve_str(&r.subject),
        sieve_str(&r.body)
    );
    if conds.is_empty() {
        out.push_str(&vacation);
    } else {
        let _ = write!(out, "if allof ({}) {{\n  {vacation}}}\n", conds.join(", "));
    }
    out
}

// ---- Rspamd ----------------------------------------------------------------

/// `local.d` files of the filter, and its Lua rule.
pub fn rspamd_files(cfg: &MailConfig) -> Result<BTreeMap<&'static str, String>> {
    let milter_path = milter_socket(cfg);
    let milter = safe_path_str(&milter_path)?;
    let state = safe_path_str(&cfg.state_dir)?;
    let mut files = BTreeMap::from([
        (
            "local.d/worker-proxy.inc",
            format!(
                "{HEADER}# The milter Postfix talks to, on a socket only Postfix can reach.
bind_socket = \"{milter} mode=0666\";
milter = yes;
timeout = 120s;
upstream \"local\" {{
  default = yes;
  self_scan = yes;
}}
"
            ),
        ),
        // No TCP listeners: nothing on the loopback a site could talk to.
        (
            "local.d/worker-normal.inc",
            format!("{HEADER}enabled = false;\n"),
        ),
        (
            "local.d/worker-controller.inc",
            format!("{HEADER}enabled = false;\n"),
        ),
        (
            "local.d/worker-fuzzy.inc",
            format!("{HEADER}enabled = false;\n"),
        ),
        (
            "local.d/options.inc",
            format!("{HEADER}local_addrs = [\"127.0.0.0/8\", \"::1\"];\n"),
        ),
        (
            "local.d/dkim_signing.conf",
            format!(
                "{HEADER}# Sign what an account sends (logged-in mailboxes, and its sites
# through OxPanel's sendmail), with the key of the From domain.
enabled = true;
sign_authenticated = true;
sign_local = false;
sign_inbound = false;
use_domain = \"header\";
use_esld = false;
allow_username_mismatch = true;
allow_hdrfrom_mismatch = false;
allow_hdrfrom_multiple = false;
try_fallback = false;
path = \"{state}/dkim/$domain.$selector.key\";
selector_map = \"{state}/dkim/selectors.map\";
"
            ),
        ),
        ("local.d/arc.conf", format!("{HEADER}enabled = false;\n")),
        ("local.d/greylist.conf", format!("{HEADER}enabled = false;\n")),
        ("local.d/ratelimit.conf", format!("{HEADER}enabled = false;\n")),
        (
            "local.d/milter_headers.conf",
            format!(
                "{HEADER}use = [\"x-spam-status\", \"authentication-results\"];\nskip_local = false;\nskip_authenticated = true;\n"
            ),
        ),
        (
            "local.d/actions.conf",
            format!("{HEADER}reject = 15;\nadd_header = 6;\ngreylist = null;\n"),
        ),
        (
            "local.d/logging.inc",
            format!("{HEADER}type = \"console\";\nlevel = \"notice\";\n"),
        ),
        ("rspamd.local.lua", RSPAMD_LUA.to_owned()),
    ]);
    files.insert(
        "local.d/antivirus.conf",
        if cfg.antivirus {
            format!(
                "{HEADER}clamav {{
  type = \"clamav\";
  servers = \"/run/clamd.scan/clamd.sock\";
  action = \"reject\";
  scan_mime_parts = true;
  symbol = \"CLAM_VIRUS\";
  log_clean = false;
}}
"
            )
        } else {
            format!("{HEADER}# ClamAV is off (OXPANEL_MAIL_ANTIVIRUS).\n")
        },
    );
    Ok(files)
}

/// A logged-in mailbox may only put its own address in From: (Postfix
/// checks the envelope; this checks the header the reader sees).
const RSPAMD_LUA: &str = r"-- Managed by oxpanel-daemon. Manual edits will be overwritten.
rspamd_config:register_symbol({
  name = 'OXPANEL_FROM_NOT_LOGIN',
  type = 'prefilter',
  priority = 10,
  callback = function(task)
    local user = task:get_user()
    if not user or not string.find(user, '@', 1, true) then
      return
    end
    local from = task:get_from('mime')
    local ok = from and #from == 1 and from[1].addr and string.lower(from[1].addr) == string.lower(user)
    if not ok then
      task:set_pre_result('reject', 'From: must be your own address (' .. user .. ')', 'oxpanel')
    end
  end,
})
";

/// `domain selector` per signing domain.
pub fn dkim_selectors(m: &Model) -> String {
    let mut out = String::from(HEADER);
    for d in m.local() {
        if let Some(k) = &d.dkim {
            let _ = writeln!(out, "{} {}", d.domain, k.selector);
        }
    }
    out
}

// ---- The policy service ----------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize, Default)]
pub struct PolicyAccount {
    pub uid: u32,
    pub suspended: bool,
    pub rate_account: u32,
    pub rate_mailbox: u32,
    pub sender_domains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize, Default)]
pub struct PolicyMailbox {
    pub account: String,
    pub enabled: bool,
}

/// What the policy service knows: accounts and mailboxes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize, Default)]
pub struct PolicyMap {
    pub version: u32,
    pub accounts: BTreeMap<String, PolicyAccount>,
    pub mailboxes: BTreeMap<String, PolicyMailbox>,
}

pub fn policy_map(m: &Model) -> PolicyMap {
    let mut map = PolicyMap {
        version: 1,
        ..PolicyMap::default()
    };
    for a in m.accounts.values() {
        map.accounts.insert(
            a.name.clone(),
            PolicyAccount {
                uid: a.uid,
                suspended: a.suspended,
                rate_account: a.rate_account,
                rate_mailbox: a.rate_mailbox,
                sender_domains: a.sender_domains.iter().cloned().collect(),
            },
        );
    }
    for d in m.local() {
        for (local, mb) in d.live_mailboxes() {
            map.mailboxes.insert(
                format!("{local}@{}", d.domain),
                PolicyMailbox {
                    account: d.tenant.clone(),
                    enabled: mb.enabled,
                },
            );
        }
    }
    map
}

/// Whether a record takes part in rendering.
pub fn live(d: &MailDomainRecord) -> bool {
    d.state != RecordState::Deleting
}
