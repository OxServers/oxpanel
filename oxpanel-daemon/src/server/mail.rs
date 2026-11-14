//! gRPC surface of email: wire ↔ domain conversions and the bodies of the
//! RPCs (the trait methods in `server.rs` delegate here). Passwords are
//! never logged.

use tonic::{Request, Response, Status};
use tracing::info;

use super::{detached, fail, timestamp, Engine};
use crate::auth::Scope;
use crate::mail::store::MailMode;
use crate::mail::{
    AutoreplyView, Check, CheckStatus, DomainView, ForwarderView, HostView, Limits, MailboxView,
    Published, QueueEntry, WarningKind,
};
use oxpanel_proto::v1 as pb;

fn mode_from(m: i32) -> MailMode {
    match pb::MailMode::try_from(m) {
        Ok(pb::MailMode::External) => MailMode::External,
        Ok(pb::MailMode::Off) => MailMode::Off,
        _ => MailMode::Local,
    }
}

fn mode_to(m: MailMode) -> pb::MailMode {
    match m {
        MailMode::Local => pb::MailMode::Local,
        MailMode::External => pb::MailMode::External,
        MailMode::Off => pb::MailMode::Off,
    }
}

fn unix(t: Option<prost_types::Timestamp>) -> Option<u64> {
    t.and_then(|t| u64::try_from(t.seconds).ok())
}

fn domain_to(d: &DomainView) -> pb::MailDomain {
    pb::MailDomain {
        domain: d.domain.clone(),
        tenant: d.tenant.clone(),
        mode: mode_to(d.mode).into(),
        external_mx: d.external_mx.clone(),
        catch_all: d.catch_all.clone(),
        dkim: d.dkim.as_ref().map(|k| pb::Dkim {
            selector: k.selector.clone(),
            public_key_record: k.record.clone(),
            published: match k.published {
                Published::Yes => pb::DkimPublished::Yes,
                Published::No => pb::DkimPublished::No,
                Published::Unknown => pb::DkimPublished::Unknown,
            }
            .into(),
        }),
        dns_hosted: d.dns_hosted,
        required_records: d
            .required_records
            .iter()
            .map(|r| pb::MailDnsRecord {
                name: r.name.clone(),
                r#type: r.rtype.to_owned(),
                value: if r.rtype == "SRV" {
                    format!("{} {} {}", r.weight, r.port, r.value)
                } else {
                    r.value.clone()
                },
                priority: u32::from(r.priority),
            })
            .collect(),
        mailbox_count: d.mailbox_count,
        forwarder_count: d.forwarder_count,
    }
}

fn mailbox_to(m: &MailboxView) -> pb::Mailbox {
    pb::Mailbox {
        address: m.address.clone(),
        local_part: m.local_part.clone(),
        domain: m.domain.clone(),
        quota_bytes: m.quota_bytes,
        used_bytes: m.used_bytes,
        messages: m.messages,
        enabled: m.enabled,
        last_login: None,
    }
}

fn forwarder_to(f: &ForwarderView) -> pb::Forwarder {
    pb::Forwarder {
        address: f.address.clone(),
        local_part: f.local_part.clone(),
        domain: f.domain.clone(),
        destinations: f.destinations.clone(),
        keep_copy: f.keep_copy,
    }
}

fn autoreply_to(a: &AutoreplyView) -> pb::Autoresponder {
    pb::Autoresponder {
        address: a.address.clone(),
        enabled: a.enabled,
        subject: a.subject.clone(),
        body: a.body.clone(),
        starts_at: a.starts_at_unix.map(timestamp),
        ends_at: a.ends_at_unix.map(timestamp),
    }
}

fn limits_to(tenant: &str, l: &Limits) -> pb::MailLimits {
    pb::MailLimits {
        tenant: tenant.to_owned(),
        max_mailboxes: l.max_mailboxes,
        max_mailbox_bytes: l.max_mailbox_bytes,
        max_messages_per_hour_account: l.rate_account,
        max_messages_per_hour_mailbox: l.rate_mailbox,
    }
}

fn host_to(h: &HostView) -> pb::MailHost {
    pb::MailHost {
        enabled: h.enabled,
        host_name: h.host_name.clone(),
        components: Some(pb::MailComponents {
            postfix: h.components.postfix,
            dovecot: h.components.dovecot,
            filter: h.components.filter,
            antivirus: h.components.antivirus,
            webmail: h.components.webmail,
        }),
        warnings: h
            .warnings
            .iter()
            .map(|(k, d)| pb::MailWarning {
                kind: match k {
                    WarningKind::ReverseDns => pb::MailWarningKind::ReverseDnsMismatch,
                    WarningKind::Port25 => pb::MailWarningKind::Port25Blocked,
                    WarningKind::NoCertificate => pb::MailWarningKind::NoCertificate,
                    WarningKind::ServiceDown => pb::MailWarningKind::ServiceNotRunning,
                }
                .into(),
                detail: d.clone(),
            })
            .collect(),
        webmail_url_pattern: h.webmail_url_pattern.clone(),
    }
}

fn queue_to(e: &QueueEntry) -> pb::MailQueueEntry {
    pb::MailQueueEntry {
        queue_id: e.queue_id.clone(),
        tenant: e.tenant.clone(),
        sender: e.sender.clone(),
        recipients_count: e.recipients_count,
        size_bytes: e.size_bytes,
        arrived_at: Some(timestamp(e.arrived_at_unix)),
        reason: e.reason.clone(),
    }
}

fn check_to(c: &Check) -> pb::DeliverabilityCheck {
    pb::DeliverabilityCheck {
        name: c.name.to_owned(),
        status: match c.status {
            CheckStatus::Ok => pb::CheckStatus::Ok,
            CheckStatus::Warn => pb::CheckStatus::Warn,
            CheckStatus::Fail => pb::CheckStatus::Fail,
            CheckStatus::Unknown => pb::CheckStatus::Unknown,
        }
        .into(),
        detail: c.detail.clone(),
    }
}

impl Engine {
    pub(super) async fn get_mail_host_rpc(
        &self,
        req: Request<pb::GetMailHostRequest>,
    ) -> Result<Response<pb::MailHost>, Status> {
        const RPC: &str = "GetMailHost";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let h = self.mail.host().await.map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(host_to(&h)))
    }

    pub(super) async fn get_mail_queue_rpc(
        &self,
        req: Request<pb::GetMailQueueRequest>,
    ) -> Result<Response<pb::MailQueue>, Status> {
        const RPC: &str = "GetMailQueue";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let (entries, total) = self
            .mail
            .queue(r.page, r.page_size)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::MailQueue {
            entries: entries.iter().map(queue_to).collect(),
            total,
        }))
    }

    pub(super) async fn delete_queued_mail_rpc(
        &self,
        req: Request<pb::DeleteQueuedMailRequest>,
    ) -> Result<Response<pb::DeleteQueuedMailResponse>, Status> {
        const RPC: &str = "DeleteQueuedMail";
        let peer = self.authorise(&req, RPC, Scope::Tenant)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, queue_id = %r.queue_id, "request");
        let mail = self.mail.clone();
        let deleted = detached(async move { mail.delete_queued(&r.queue_id).await })
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::DeleteQueuedMailResponse { deleted }))
    }

    pub(super) async fn flush_mail_queue_rpc(
        &self,
        req: Request<pb::FlushMailQueueRequest>,
    ) -> Result<Response<pb::FlushMailQueueResponse>, Status> {
        const RPC: &str = "FlushMailQueue";
        let peer = self.authorise(&req, RPC, Scope::Tenant)?;
        info!(rpc = RPC, peer, "request");
        let attempted = self
            .mail
            .flush_queue()
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::FlushMailQueueResponse { attempted }))
    }

    pub(super) async fn check_deliverability_rpc(
        &self,
        req: Request<pb::CheckDeliverabilityRequest>,
    ) -> Result<Response<pb::Deliverability>, Status> {
        const RPC: &str = "CheckDeliverability";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let checks = self
            .mail
            .check(&r.domain)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::Deliverability {
            domain: r.domain,
            checks: checks.iter().map(check_to).collect(),
        }))
    }

    pub(super) async fn set_mail_domain_rpc(
        &self,
        req: Request<pb::SetMailDomainRequest>,
    ) -> Result<Response<pb::SetMailDomainResponse>, Status> {
        const RPC: &str = "SetMailDomain";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, domain = %r.domain, mode = r.mode, "request");
        let mail = self.mail.clone();
        let (d, created) = detached(async move {
            mail.set_domain(
                &r.tenant,
                &r.domain,
                mode_from(r.mode),
                &r.external_mx,
                &r.catch_all,
            )
            .await
        })
        .await
        .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::SetMailDomainResponse {
            domain: Some(domain_to(&d)),
            created,
        }))
    }

    pub(super) async fn get_mail_domain_rpc(
        &self,
        req: Request<pb::GetMailDomainRequest>,
    ) -> Result<Response<pb::MailDomain>, Status> {
        const RPC: &str = "GetMailDomain";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let d = self
            .mail
            .get_domain(&r.tenant, &r.domain)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(domain_to(&d)))
    }

    pub(super) async fn list_mail_domains_rpc(
        &self,
        req: Request<pb::ListMailDomainsRequest>,
    ) -> Result<Response<pb::ListMailDomainsResponse>, Status> {
        const RPC: &str = "ListMailDomains";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let ds = self
            .mail
            .list_domains(&r.tenant)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::ListMailDomainsResponse {
            domains: ds.iter().map(domain_to).collect(),
        }))
    }

    pub(super) async fn rotate_dkim_key_rpc(
        &self,
        req: Request<pb::RotateDkimKeyRequest>,
    ) -> Result<Response<pb::MailDomain>, Status> {
        const RPC: &str = "RotateDkimKey";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, domain = %r.domain, "request");
        let mail = self.mail.clone();
        let d = detached(async move { mail.rotate_dkim(&r.tenant, &r.domain).await })
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(domain_to(&d)))
    }

    pub(super) async fn put_mailbox_rpc(
        &self,
        req: Request<pb::PutMailboxRequest>,
    ) -> Result<Response<pb::PutMailboxResponse>, Status> {
        const RPC: &str = "PutMailbox";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        // The password is never logged; only whether one was given.
        info!(rpc = RPC, peer, tenant = %r.tenant, domain = %r.domain, local_part = %r.local_part, quota_bytes = r.quota_bytes, enabled = r.enabled, password_given = !r.password.is_empty(), "request");
        let mail = self.mail.clone();
        let (m, created) = detached(async move {
            mail.put_mailbox(
                &r.tenant,
                &r.domain,
                &r.local_part,
                r.quota_bytes,
                &r.password,
                r.enabled,
            )
            .await
        })
        .await
        .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::PutMailboxResponse {
            mailbox: Some(mailbox_to(&m)),
            created,
        }))
    }

    pub(super) async fn list_mailboxes_rpc(
        &self,
        req: Request<pb::ListMailboxesRequest>,
    ) -> Result<Response<pb::ListMailboxesResponse>, Status> {
        const RPC: &str = "ListMailboxes";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let ms = self
            .mail
            .list_mailboxes(&r.tenant, &r.domain)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::ListMailboxesResponse {
            mailboxes: ms.iter().map(mailbox_to).collect(),
        }))
    }

    pub(super) async fn delete_mailbox_rpc(
        &self,
        req: Request<pb::DeleteMailboxRequest>,
    ) -> Result<Response<pb::DeleteMailboxResponse>, Status> {
        const RPC: &str = "DeleteMailbox";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, domain = %r.domain, local_part = %r.local_part, "request");
        let mail = self.mail.clone();
        let deleted = detached(async move {
            mail.delete_mailbox(&r.tenant, &r.domain, &r.local_part)
                .await
        })
        .await
        .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::DeleteMailboxResponse { deleted }))
    }

    pub(super) async fn set_mailbox_password_rpc(
        &self,
        req: Request<pb::SetMailboxPasswordRequest>,
    ) -> Result<Response<pb::SetMailboxPasswordResponse>, Status> {
        const RPC: &str = "SetMailboxPassword";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, domain = %r.domain, local_part = %r.local_part, "request");
        let mail = self.mail.clone();
        detached(async move {
            mail.set_mailbox_password(&r.tenant, &r.domain, &r.local_part, &r.password)
                .await
        })
        .await
        .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::SetMailboxPasswordResponse {}))
    }

    pub(super) async fn put_forwarder_rpc(
        &self,
        req: Request<pb::PutForwarderRequest>,
    ) -> Result<Response<pb::PutForwarderResponse>, Status> {
        const RPC: &str = "PutForwarder";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, domain = %r.domain, local_part = %r.local_part, destinations = r.destinations.len(), keep_copy = r.keep_copy, "request");
        let mail = self.mail.clone();
        let (f, created) = detached(async move {
            mail.put_forwarder(
                &r.tenant,
                &r.domain,
                &r.local_part,
                &r.destinations,
                r.keep_copy,
            )
            .await
        })
        .await
        .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::PutForwarderResponse {
            forwarder: Some(forwarder_to(&f)),
            created,
        }))
    }

    pub(super) async fn list_forwarders_rpc(
        &self,
        req: Request<pb::ListForwardersRequest>,
    ) -> Result<Response<pb::ListForwardersResponse>, Status> {
        const RPC: &str = "ListForwarders";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let fs = self
            .mail
            .list_forwarders(&r.tenant, &r.domain)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::ListForwardersResponse {
            forwarders: fs.iter().map(forwarder_to).collect(),
        }))
    }

    pub(super) async fn delete_forwarder_rpc(
        &self,
        req: Request<pb::DeleteForwarderRequest>,
    ) -> Result<Response<pb::DeleteForwarderResponse>, Status> {
        const RPC: &str = "DeleteForwarder";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, domain = %r.domain, local_part = %r.local_part, "request");
        let mail = self.mail.clone();
        let deleted = detached(async move {
            mail.delete_forwarder(&r.tenant, &r.domain, &r.local_part)
                .await
        })
        .await
        .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::DeleteForwarderResponse { deleted }))
    }

    pub(super) async fn set_autoresponder_rpc(
        &self,
        req: Request<pb::SetAutoresponderRequest>,
    ) -> Result<Response<pb::Autoresponder>, Status> {
        const RPC: &str = "SetAutoresponder";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, address = %r.address, enabled = r.enabled, "request");
        let mail = self.mail.clone();
        let a = detached(async move {
            mail.set_autoresponder(
                &r.tenant,
                &r.address,
                r.enabled,
                &r.subject,
                &r.body,
                unix(r.starts_at),
                unix(r.ends_at),
            )
            .await
        })
        .await
        .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(autoreply_to(&a)))
    }

    pub(super) async fn get_autoresponder_rpc(
        &self,
        req: Request<pb::GetAutoresponderRequest>,
    ) -> Result<Response<pb::Autoresponder>, Status> {
        const RPC: &str = "GetAutoresponder";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let a = self
            .mail
            .get_autoresponder(&r.tenant, &r.address)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(autoreply_to(&a)))
    }

    pub(super) async fn get_mail_limits_rpc(
        &self,
        req: Request<pb::GetMailLimitsRequest>,
    ) -> Result<Response<pb::MailLimits>, Status> {
        const RPC: &str = "GetMailLimits";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let l = self
            .mail
            .get_limits(&r.tenant)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(limits_to(&r.tenant, &l)))
    }

    pub(super) async fn set_mail_limits_rpc(
        &self,
        req: Request<pb::SetMailLimitsRequest>,
    ) -> Result<Response<pb::MailLimits>, Status> {
        const RPC: &str = "SetMailLimits";
        let peer = self.authorise(&req, RPC, Scope::Tenant)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, "request");
        let mail = self.mail.clone();
        let tenant = r.tenant.clone();
        let l = detached(async move {
            mail.set_limits(
                &r.tenant,
                Limits {
                    max_mailboxes: r.max_mailboxes,
                    max_mailbox_bytes: r.max_mailbox_bytes,
                    rate_account: r.max_messages_per_hour_account,
                    rate_mailbox: r.max_messages_per_hour_mailbox,
                },
            )
            .await
        })
        .await
        .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(limits_to(&tenant, &l)))
    }

    pub(super) async fn get_mail_usage_rpc(
        &self,
        req: Request<pb::GetMailUsageRequest>,
    ) -> Result<Response<pb::MailUsage>, Status> {
        const RPC: &str = "GetMailUsage";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let u = self
            .mail
            .usage(&r.tenant)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::MailUsage {
            tenant: r.tenant,
            mailboxes: u.mailboxes,
            bytes_used: u.bytes_used,
            messages_sent_this_hour: u.sent_this_hour,
        }))
    }
}
