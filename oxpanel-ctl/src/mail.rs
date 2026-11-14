//! `oxpanel-ctl mail …`: email of tenants (mail domains, mailboxes,
//! forwarders, autoresponders, limits) and of the host (queue, checks).
//! Mailbox passwords are read from standard input, never from arguments.

use std::process::ExitCode;

use clap::{Subcommand, ValueEnum};
use tonic::transport::Channel;

use oxpanel_proto::v1 as pb;
use oxpanel_proto::v1::ox_panel_engine_client::OxPanelEngineClient;

use crate::emit;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum Mode {
    Local,
    External,
    Off,
}

#[derive(Subcommand, Debug)]
pub(crate) enum MailCmd {
    /// The mail component: enabled, host name, components, warnings.
    Host,
    /// Messages Postfix still holds.
    Queue {
        #[arg(long, default_value_t = 0)]
        page: u32,
        #[arg(long, default_value_t = 0)]
        page_size: u32,
    },
    /// Remove one message from the queue.
    QueueDelete {
        queue_id: String,
    },
    /// Try to deliver everything in the queue now.
    QueueFlush,
    /// Look at a mail domain from outside: MX, SPF, DKIM, DMARC, reverse DNS.
    Check {
        domain: String,
    },
    /// Create a mail domain or change its mode.
    DomainSet {
        domain: String,
        #[arg(long)]
        tenant: String,
        #[arg(long, value_enum, default_value_t = Mode::Local)]
        mode: Mode,
        /// EXTERNAL: the provider's mail servers, most preferred first.
        #[arg(long = "mx")]
        external_mx: Vec<String>,
        /// A mailbox of the domain that gets mail for unknown addresses.
        #[arg(long, default_value = "")]
        catch_all: String,
    },
    DomainShow {
        domain: String,
        #[arg(long)]
        tenant: String,
    },
    DomainList {
        #[arg(long)]
        tenant: String,
    },
    /// A new DKIM key (the old one stays published for a week).
    DkimRotate {
        domain: String,
        #[arg(long)]
        tenant: String,
    },
    /// Create or update a mailbox. A new mailbox, or --password, reads the
    /// password from standard input (one line).
    MailboxSet {
        address: String,
        #[arg(long)]
        tenant: String,
        /// Size limit in bytes (0: none of its own).
        #[arg(long, default_value_t = 0)]
        quota: u64,
        /// Read a new password from standard input.
        #[arg(long)]
        password: bool,
        #[arg(long)]
        disabled: bool,
    },
    MailboxList {
        domain: String,
        #[arg(long)]
        tenant: String,
    },
    MailboxDelete {
        address: String,
        #[arg(long)]
        tenant: String,
    },
    /// Set a mailbox's password, read from standard input (one line).
    MailboxPassword {
        address: String,
        #[arg(long)]
        tenant: String,
    },
    ForwarderSet {
        address: String,
        #[arg(long)]
        tenant: String,
        #[arg(long = "to", required = true)]
        destinations: Vec<String>,
        #[arg(long)]
        keep_copy: bool,
    },
    ForwarderList {
        domain: String,
        #[arg(long)]
        tenant: String,
    },
    ForwarderDelete {
        address: String,
        #[arg(long)]
        tenant: String,
    },
    /// Switch a mailbox's autoresponder on (with --subject and --body) or off.
    Autoreply {
        address: String,
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        off: bool,
        #[arg(long, default_value = "")]
        subject: String,
        #[arg(long, default_value = "")]
        body: String,
        /// Unix time it starts / ends (0: now / never).
        #[arg(long, default_value_t = 0)]
        starts: i64,
        #[arg(long, default_value_t = 0)]
        ends: i64,
    },
    AutoreplyShow {
        address: String,
        #[arg(long)]
        tenant: String,
    },
    Limits {
        tenant: String,
    },
    /// Set an account's limits (0 = unlimited).
    LimitsSet {
        tenant: String,
        #[arg(long)]
        max_mailboxes: u32,
        #[arg(long)]
        max_mailbox_bytes: u64,
        #[arg(long)]
        per_hour_account: u32,
        #[arg(long)]
        per_hour_mailbox: u32,
    },
    Usage {
        tenant: String,
    },
}

fn split(address: &str) -> Result<(String, String), tonic::Status> {
    address
        .split_once('@')
        .map(|(l, d)| (l.to_owned(), d.to_owned()))
        .ok_or_else(|| tonic::Status::invalid_argument("give the address as local@domain"))
}

fn mode_name(m: i32) -> &'static str {
    match pb::MailMode::try_from(m) {
        Ok(pb::MailMode::Local) => "local",
        Ok(pb::MailMode::External) => "external",
        Ok(pb::MailMode::Off) => "off",
        _ => "unspecified",
    }
}

fn print_domain(d: &pb::MailDomain) {
    emit(&format!(
        "domain={} tenant={} mode={} mailboxes={} forwarders={} catch_all={} dns_hosted={} external_mx={}",
        d.domain,
        d.tenant,
        mode_name(d.mode),
        d.mailbox_count,
        d.forwarder_count,
        if d.catch_all.is_empty() { "-" } else { &d.catch_all },
        d.dns_hosted,
        if d.external_mx.is_empty() { "-".to_owned() } else { d.external_mx.join(",") },
    ));
    if let Some(k) = &d.dkim {
        emit(&format!(
            "  dkim selector={} published={} record={}",
            k.selector,
            match pb::DkimPublished::try_from(k.published) {
                Ok(pb::DkimPublished::Yes) => "yes",
                Ok(pb::DkimPublished::No) => "no",
                _ => "unknown",
            },
            k.public_key_record
        ));
    }
    for r in &d.required_records {
        emit(&format!(
            "  create {} {} {}{}",
            r.name,
            r.r#type,
            if r.priority > 0 {
                format!("{} ", r.priority)
            } else {
                String::new()
            },
            r.value
        ));
    }
}

fn print_mailbox(m: &pb::Mailbox) {
    emit(&format!(
        "mailbox={} quota_bytes={} used_bytes={} messages={} enabled={}",
        m.address, m.quota_bytes, m.used_bytes, m.messages, m.enabled
    ));
}

fn print_forwarder(f: &pb::Forwarder) {
    emit(&format!(
        "forwarder={} to={} keep_copy={}",
        f.address,
        f.destinations.join(","),
        f.keep_copy
    ));
}

fn print_autoreply(a: &pb::Autoresponder) {
    emit(&format!(
        "autoreply={} enabled={} subject={:?} starts={} ends={}",
        a.address,
        a.enabled,
        a.subject,
        a.starts_at.as_ref().map_or(0, |t| t.seconds),
        a.ends_at.as_ref().map_or(0, |t| t.seconds)
    ));
}

fn print_limits(l: &pb::MailLimits) {
    emit(&format!(
        "tenant={} max_mailboxes={} max_mailbox_bytes={} per_hour_account={} per_hour_mailbox={}",
        l.tenant,
        l.max_mailboxes,
        l.max_mailbox_bytes,
        l.max_messages_per_hour_account,
        l.max_messages_per_hour_mailbox
    ));
}

fn stamp(secs: i64) -> Option<prost_types::Timestamp> {
    (secs > 0).then_some(prost_types::Timestamp {
        seconds: secs,
        nanos: 0,
    })
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn run_mail(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: MailCmd,
) -> Result<ExitCode, tonic::Status> {
    match cmd {
        MailCmd::Host => {
            let h = c
                .get_mail_host(pb::GetMailHostRequest {})
                .await?
                .into_inner();
            let comp = h.components.unwrap_or_default();
            emit(&format!(
                "enabled={} host_name={} postfix={} dovecot={} filter={} antivirus={} webmail={} webmail_url={}",
                h.enabled, h.host_name, comp.postfix, comp.dovecot, comp.filter, comp.antivirus, comp.webmail,
                if h.webmail_url_pattern.is_empty() { "-" } else { &h.webmail_url_pattern }
            ));
            for w in &h.warnings {
                emit(&format!("warning: {}", w.detail));
            }
        }
        MailCmd::Queue { page, page_size } => {
            let q = c
                .get_mail_queue(pb::GetMailQueueRequest { page, page_size })
                .await?
                .into_inner();
            emit(&format!("total={}", q.total));
            for e in &q.entries {
                emit(&format!(
                    "queue_id={} tenant={} sender={} recipients={} size={} arrived={} reason={}",
                    e.queue_id,
                    if e.tenant.is_empty() { "-" } else { &e.tenant },
                    e.sender,
                    e.recipients_count,
                    e.size_bytes,
                    e.arrived_at.as_ref().map_or(0, |t| t.seconds),
                    e.reason
                ));
            }
        }
        MailCmd::QueueDelete { queue_id } => {
            let r = c
                .delete_queued_mail(pb::DeleteQueuedMailRequest { queue_id })
                .await?
                .into_inner();
            emit(&format!("deleted={}", r.deleted));
        }
        MailCmd::QueueFlush => {
            let r = c
                .flush_mail_queue(pb::FlushMailQueueRequest {})
                .await?
                .into_inner();
            emit(&format!("attempted={}", r.attempted));
        }
        MailCmd::Check { domain } => {
            let r = c
                .check_deliverability(pb::CheckDeliverabilityRequest { domain })
                .await?
                .into_inner();
            for ch in &r.checks {
                let st = match pb::CheckStatus::try_from(ch.status) {
                    Ok(pb::CheckStatus::Ok) => "ok",
                    Ok(pb::CheckStatus::Warn) => "warn",
                    Ok(pb::CheckStatus::Fail) => "fail",
                    _ => "unknown",
                };
                emit(&format!("{}={} {}", ch.name, st, ch.detail));
            }
        }
        MailCmd::DomainSet {
            domain,
            tenant,
            mode,
            external_mx,
            catch_all,
        } => {
            let mode = match mode {
                Mode::Local => pb::MailMode::Local,
                Mode::External => pb::MailMode::External,
                Mode::Off => pb::MailMode::Off,
            };
            let r = c
                .set_mail_domain(pb::SetMailDomainRequest {
                    tenant,
                    domain,
                    mode: mode.into(),
                    external_mx,
                    catch_all,
                })
                .await?
                .into_inner();
            emit(&format!("created={}", r.created));
            if let Some(d) = &r.domain {
                print_domain(d);
            }
        }
        MailCmd::DomainShow { domain, tenant } => {
            let d = c
                .get_mail_domain(pb::GetMailDomainRequest { tenant, domain })
                .await?
                .into_inner();
            print_domain(&d);
        }
        MailCmd::DomainList { tenant } => {
            let r = c
                .list_mail_domains(pb::ListMailDomainsRequest { tenant })
                .await?
                .into_inner();
            for d in &r.domains {
                print_domain(d);
            }
        }
        MailCmd::DkimRotate { domain, tenant } => {
            let d = c
                .rotate_dkim_key(pb::RotateDkimKeyRequest { tenant, domain })
                .await?
                .into_inner();
            print_domain(&d);
        }
        MailCmd::MailboxSet {
            address,
            tenant,
            quota,
            password,
            disabled,
        } => {
            let (local_part, domain) = split(&address)?;
            let password = if password {
                crate::read_password()?
            } else {
                String::new()
            };
            let r = c
                .put_mailbox(pb::PutMailboxRequest {
                    tenant,
                    domain,
                    local_part,
                    quota_bytes: quota,
                    password,
                    enabled: !disabled,
                })
                .await?
                .into_inner();
            emit(&format!("created={}", r.created));
            if let Some(m) = &r.mailbox {
                print_mailbox(m);
            }
        }
        MailCmd::MailboxList { domain, tenant } => {
            let r = c
                .list_mailboxes(pb::ListMailboxesRequest { tenant, domain })
                .await?
                .into_inner();
            for m in &r.mailboxes {
                print_mailbox(m);
            }
        }
        MailCmd::MailboxDelete { address, tenant } => {
            let (local_part, domain) = split(&address)?;
            let r = c
                .delete_mailbox(pb::DeleteMailboxRequest {
                    tenant,
                    domain,
                    local_part,
                })
                .await?
                .into_inner();
            emit(&format!("deleted={}", r.deleted));
        }
        MailCmd::MailboxPassword { address, tenant } => {
            let (local_part, domain) = split(&address)?;
            let password = crate::read_password()?;
            c.set_mailbox_password(pb::SetMailboxPasswordRequest {
                tenant,
                domain,
                local_part,
                password,
            })
            .await?;
            emit("password=set");
        }
        MailCmd::ForwarderSet {
            address,
            tenant,
            destinations,
            keep_copy,
        } => {
            let (local_part, domain) = split(&address)?;
            let r = c
                .put_forwarder(pb::PutForwarderRequest {
                    tenant,
                    domain,
                    local_part,
                    destinations,
                    keep_copy,
                })
                .await?
                .into_inner();
            emit(&format!("created={}", r.created));
            if let Some(f) = &r.forwarder {
                print_forwarder(f);
            }
        }
        MailCmd::ForwarderList { domain, tenant } => {
            let r = c
                .list_forwarders(pb::ListForwardersRequest { tenant, domain })
                .await?
                .into_inner();
            for f in &r.forwarders {
                print_forwarder(f);
            }
        }
        MailCmd::ForwarderDelete { address, tenant } => {
            let (local_part, domain) = split(&address)?;
            let r = c
                .delete_forwarder(pb::DeleteForwarderRequest {
                    tenant,
                    domain,
                    local_part,
                })
                .await?
                .into_inner();
            emit(&format!("deleted={}", r.deleted));
        }
        MailCmd::Autoreply {
            address,
            tenant,
            off,
            subject,
            body,
            starts,
            ends,
        } => {
            let a = c
                .set_autoresponder(pb::SetAutoresponderRequest {
                    tenant,
                    address,
                    enabled: !off,
                    subject,
                    body,
                    starts_at: stamp(starts),
                    ends_at: stamp(ends),
                })
                .await?
                .into_inner();
            print_autoreply(&a);
        }
        MailCmd::AutoreplyShow { address, tenant } => {
            let a = c
                .get_autoresponder(pb::GetAutoresponderRequest { tenant, address })
                .await?
                .into_inner();
            print_autoreply(&a);
        }
        MailCmd::Limits { tenant } => {
            let l = c
                .get_mail_limits(pb::GetMailLimitsRequest { tenant })
                .await?
                .into_inner();
            print_limits(&l);
        }
        MailCmd::LimitsSet {
            tenant,
            max_mailboxes,
            max_mailbox_bytes,
            per_hour_account,
            per_hour_mailbox,
        } => {
            let l = c
                .set_mail_limits(pb::SetMailLimitsRequest {
                    tenant,
                    max_mailboxes,
                    max_mailbox_bytes,
                    max_messages_per_hour_account: per_hour_account,
                    max_messages_per_hour_mailbox: per_hour_mailbox,
                })
                .await?
                .into_inner();
            print_limits(&l);
        }
        MailCmd::Usage { tenant } => {
            let u = c
                .get_mail_usage(pb::GetMailUsageRequest { tenant })
                .await?
                .into_inner();
            emit(&format!(
                "tenant={} mailboxes={} bytes_used={} sent_this_hour={}",
                u.tenant, u.mailboxes, u.bytes_used, u.messages_sent_this_hour
            ));
        }
    }
    Ok(ExitCode::SUCCESS)
}
