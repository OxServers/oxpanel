//! gRPC surface: maps `oxpanel.v1` messages onto the workflows and back.

use tonic::service::interceptor::InterceptedService;

/// Largest request the daemon will decode. Every message is a handful of
/// short strings; anything bigger is a mistake or an attack.
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

use crate::auth::PeerInfo;
use crate::ctx::Ctx;
use crate::error::Error;
use crate::records::{TenantRecord, TenantState, VHostRecord};
use crate::tenant::TenantService;
use crate::validate::Limits;
use crate::vhost::{VHostRequest, VHostService};
use oxpanel_proto::v1 as pb;
use oxpanel_proto::v1::ox_panel_engine_server::{OxPanelEngine, OxPanelEngineServer};

/// The service implementation.
#[derive(Debug, Clone)]
pub struct Engine {
    tenants: TenantService,
    vhosts: VHostService,
}

/// Interceptor type used by [`Engine::into_service`].
pub type Interceptor = fn(Request<()>) -> Result<Request<()>, Status>;

impl Engine {
    pub fn new(ctx: Ctx) -> Self {
        Self {
            tenants: TenantService::new(ctx.clone()),
            vhosts: VHostService::new(ctx),
        }
    }

    /// The tonic service, wrapped so every request must carry a verified peer.
    pub fn into_service(self) -> InterceptedService<OxPanelEngineServer<Self>, Interceptor> {
        let inner = OxPanelEngineServer::new(self).max_decoding_message_size(MAX_REQUEST_BYTES);
        InterceptedService::new(inner, require_authenticated_peer)
    }
}

/// Fail closed: a request without kernel-verified peer credentials (i.e. one
/// that did not arrive through [`crate::auth::gate`]) is refused.
pub fn require_authenticated_peer(req: Request<()>) -> Result<Request<()>, Status> {
    if req.extensions().get::<PeerInfo>().is_some() {
        Ok(req)
    } else {
        Err(Status::permission_denied(
            "request did not arrive over an authenticated transport",
        ))
    }
}

fn peer_of<T>(req: &Request<T>) -> String {
    req.extensions()
        .get::<PeerInfo>()
        .map_or_else(|| "unknown".to_owned(), ToString::to_string)
}

/// Log and convert. Operator-relevant detail stays in the journal.
fn fail(rpc: &'static str, peer: &str, err: Error) -> Status {
    let status: Status = match &err {
        Error::InvalidInput { .. }
        | Error::TenantExists(_)
        | Error::SpecMismatch(_)
        | Error::TenantNotFound(_)
        | Error::VHostNotFound(_)
        | Error::NotManaged(_)
        | Error::TenantNotReady(_)
        | Error::TenantHasVHosts(_)
        | Error::VHostOwnedByOther { .. }
        | Error::UidExhausted { .. }
        | Error::NginxInvalid(_) => {
            warn!(rpc, peer, error = %err, "request refused");
            err.into()
        }
        _ => {
            error!(rpc, peer, error = %err, "request failed");
            err.into()
        }
    };
    status
}

fn limits_from(l: Option<pb::ResourceLimits>) -> Result<Limits, Error> {
    let l = l.unwrap_or_default();
    Limits::parse(l.memory_max_bytes, l.cpu_weight, l.io_weight, l.tasks_max)
}

fn limits_to(l: &Limits) -> pb::ResourceLimits {
    pb::ResourceLimits {
        memory_max_bytes: l.memory_max_bytes.unwrap_or(0),
        cpu_weight: l.cpu_weight.unwrap_or(0),
        io_weight: l.io_weight.unwrap_or(0),
        tasks_max: l.tasks_max.unwrap_or(0),
    }
}

fn tenant_to(rec: &TenantRecord) -> pb::Tenant {
    let state = match rec.state {
        TenantState::Provisioning => pb::TenantState::Provisioning,
        TenantState::Ready => pb::TenantState::Ready,
        TenantState::Deleting => pb::TenantState::Deleting,
    };
    pb::Tenant {
        username: rec.username.clone(),
        uid: rec.uid,
        gid: rec.gid,
        home: rec.home.to_string_lossy().into_owned(),
        limits: Some(limits_to(&rec.limits)),
        slice_unit: rec.slice_unit.clone(),
        created_at: Some(prost_types::Timestamp {
            seconds: i64::try_from(rec.created_at_unix).unwrap_or(i64::MAX),
            nanos: 0,
        }),
        state: state.into(),
        owner: rec.owner.clone(),
    }
}

fn vhost_to(rec: &VHostRecord) -> pb::VirtualHost {
    pb::VirtualHost {
        domain: rec.domain.clone(),
        tenant: rec.tenant.clone(),
        document_root: rec.document_root.clone(),
        aliases: rec.aliases.clone(),
        config_path: rec.config_path.to_string_lossy().into_owned(),
    }
}

#[tonic::async_trait]
impl OxPanelEngine for Engine {
    async fn create_tenant(
        &self,
        req: Request<pb::CreateTenantRequest>,
    ) -> Result<Response<pb::CreateTenantResponse>, Status> {
        let peer = peer_of(&req);
        let r = req.into_inner();
        info!(rpc = "CreateTenant", peer, username = %r.username, "request");
        let limits = limits_from(r.limits).map_err(|e| fail("CreateTenant", &peer, e))?;
        let (rec, created) = self
            .tenants
            .create(&r.username, limits, &r.owner)
            .await
            .map_err(|e| fail("CreateTenant", &peer, e))?;
        Ok(Response::new(pb::CreateTenantResponse {
            tenant: Some(tenant_to(&rec)),
            created,
        }))
    }

    async fn get_tenant(
        &self,
        req: Request<pb::GetTenantRequest>,
    ) -> Result<Response<pb::Tenant>, Status> {
        let peer = peer_of(&req);
        let r = req.into_inner();
        let rec = self
            .tenants
            .get(&r.username)
            .await
            .map_err(|e| fail("GetTenant", &peer, e))?;
        Ok(Response::new(tenant_to(&rec)))
    }

    async fn list_tenants(
        &self,
        req: Request<pb::ListTenantsRequest>,
    ) -> Result<Response<pb::ListTenantsResponse>, Status> {
        let peer = peer_of(&req);
        let owner = req.into_inner().owner;
        let recs = self
            .tenants
            .list(Some(&owner))
            .await
            .map_err(|e| fail("ListTenants", &peer, e))?;
        Ok(Response::new(pb::ListTenantsResponse {
            tenants: recs.iter().map(tenant_to).collect(),
        }))
    }

    async fn delete_tenant(
        &self,
        req: Request<pb::DeleteTenantRequest>,
    ) -> Result<Response<pb::DeleteTenantResponse>, Status> {
        let peer = peer_of(&req);
        let r = req.into_inner();
        info!(rpc = "DeleteTenant", peer, username = %r.username, remove_home = r.remove_home, "request");
        let deleted = self
            .tenants
            .delete(&r.username, r.remove_home)
            .await
            .map_err(|e| fail("DeleteTenant", &peer, e))?;
        Ok(Response::new(pb::DeleteTenantResponse { deleted }))
    }

    async fn configure_virtual_host(
        &self,
        req: Request<pb::ConfigureVirtualHostRequest>,
    ) -> Result<Response<pb::ConfigureVirtualHostResponse>, Status> {
        let peer = peer_of(&req);
        let r = req.into_inner();
        info!(rpc = "ConfigureVirtualHost", peer, domain = %r.domain, tenant = %r.tenant, "request");
        let (rec, created) = self
            .vhosts
            .configure(VHostRequest {
                domain: r.domain,
                tenant: r.tenant,
                document_root: r.document_root,
                aliases: r.aliases,
            })
            .await
            .map_err(|e| fail("ConfigureVirtualHost", &peer, e))?;
        Ok(Response::new(pb::ConfigureVirtualHostResponse {
            vhost: Some(vhost_to(&rec)),
            created,
        }))
    }

    async fn remove_virtual_host(
        &self,
        req: Request<pb::RemoveVirtualHostRequest>,
    ) -> Result<Response<pb::RemoveVirtualHostResponse>, Status> {
        let peer = peer_of(&req);
        let r = req.into_inner();
        info!(rpc = "RemoveVirtualHost", peer, domain = %r.domain, "request");
        let removed = self
            .vhosts
            .remove(&r.domain)
            .await
            .map_err(|e| fail("RemoveVirtualHost", &peer, e))?;
        Ok(Response::new(pb::RemoveVirtualHostResponse { removed }))
    }

    async fn list_virtual_hosts(
        &self,
        req: Request<pb::ListVirtualHostsRequest>,
    ) -> Result<Response<pb::ListVirtualHostsResponse>, Status> {
        let peer = peer_of(&req);
        let r = req.into_inner();
        let recs = self
            .vhosts
            .list(Some(&r.tenant))
            .await
            .map_err(|e| fail("ListVirtualHosts", &peer, e))?;
        Ok(Response::new(pb::ListVirtualHostsResponse {
            vhosts: recs.iter().map(vhost_to).collect(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interceptor_fails_closed_without_peer_info() {
        let r = require_authenticated_peer(Request::new(()));
        assert!(matches!(r, Err(s) if s.code() == tonic::Code::PermissionDenied));
        let mut ok = Request::new(());
        ok.extensions_mut().insert(PeerInfo {
            uid: 1,
            gid: 1,
            pid: None,
        });
        assert!(require_authenticated_peer(ok).is_ok());
    }

    #[test]
    fn limits_round_trip() {
        let l = Limits {
            memory_max_bytes: Some(1 << 30),
            cpu_weight: Some(10),
            io_weight: None,
            tasks_max: Some(3),
        };
        let pbv = limits_to(&l);
        assert_eq!(limits_from(Some(pbv)).ok(), Some(l));
        assert_eq!(limits_from(None).ok(), Some(Limits::default()));
    }
}
