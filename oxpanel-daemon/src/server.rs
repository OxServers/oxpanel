//! gRPC surface: maps `oxpanel.v1` messages onto the workflows and back.

use tonic::service::interceptor::InterceptedService;

/// Largest request the daemon will decode. Every message is a handful of
/// short strings; anything bigger is a mistake or an attack.
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

use std::sync::Arc;

use crate::auth::{PeerInfo, Scope, ScopePolicy};
use crate::ctx::Ctx;
use crate::error::Error;
use crate::host::{Drift, DriftKind, HostService};
use crate::records::{AppRuntime, TenantRecord, TenantState, VHostRecord};
use crate::tenant::TenantService;
use crate::validate::Limits;
use crate::vhost::{AppRequest, LogKind, VHostRequest, VHostService};
use oxpanel_proto::v1 as pb;
use oxpanel_proto::v1::ox_panel_engine_server::{OxPanelEngine, OxPanelEngineServer};

/// The service implementation.
#[derive(Debug, Clone)]
pub struct Engine {
    tenants: TenantService,
    vhosts: VHostService,
    host: HostService,
    scopes: Arc<ScopePolicy>,
}

/// Interceptor type used by [`Engine::into_service`].
pub type Interceptor = fn(Request<()>) -> Result<Request<()>, Status>;

impl Engine {
    pub fn new(ctx: Ctx) -> Self {
        Self {
            scopes: Arc::new(ScopePolicy::new(ctx.config.peer_scopes.clone())),
            tenants: TenantService::new(ctx.clone()),
            vhosts: VHostService::new(ctx.clone()),
            host: HostService::new(ctx),
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

impl Engine {
    /// Second gate, per RPC: the verified peer must hold `scope`. Returns the
    /// peer's description for the request log.
    fn authorise<T>(
        &self,
        req: &Request<T>,
        rpc: &'static str,
        scope: Scope,
    ) -> Result<String, Status> {
        let Some(peer) = req.extensions().get::<PeerInfo>() else {
            return Err(Status::permission_denied(
                "request did not arrive over an authenticated transport",
            ));
        };
        if !self.scopes.permits(peer, scope) {
            warn!(rpc, %peer, scope = scope.as_str(), "request refused: peer lacks scope");
            return Err(Status::permission_denied(format!(
                "this peer is not permitted to call {rpc} (scope '{}' required)",
                scope.as_str()
            )));
        }
        Ok(peer.to_string())
    }
}

fn timestamp(unix: u64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: i64::try_from(unix).unwrap_or(i64::MAX),
        nanos: 0,
    }
}

fn drift_to(d: &Drift) -> pb::Drift {
    let kind = match d.kind {
        DriftKind::TenantIncomplete => pb::DriftKind::TenantIncomplete,
        DriftKind::TenantAccountMissing => pb::DriftKind::TenantAccountMissing,
        DriftKind::TenantAccountMismatch => pb::DriftKind::TenantAccountMismatch,
        DriftKind::TenantHomeInvalid => pb::DriftKind::TenantHomeInvalid,
        DriftKind::TenantUnitDrift => pb::DriftKind::TenantUnitDrift,
        DriftKind::VHostTenantMissing => pb::DriftKind::VhostTenantMissing,
        DriftKind::VHostConfigDrift => pb::DriftKind::VhostConfigDrift,
        DriftKind::OrphanNginxConfig => pb::DriftKind::OrphanNginxConfig,
        DriftKind::OrphanSliceUnit => pb::DriftKind::OrphanSliceUnit,
        DriftKind::PhpPoolDrift => pb::DriftKind::PhpPoolDrift,
        DriftKind::OrphanPhpPool => pb::DriftKind::OrphanPhpPool,
        DriftKind::AppUnitDrift => pb::DriftKind::AppUnitDrift,
        DriftKind::OrphanAppUnit => pb::DriftKind::OrphanAppUnit,
    };
    pb::Drift {
        kind: kind.into(),
        subject: d.subject.clone(),
        detail: d.detail.clone(),
    }
}

fn updated(rec: &TenantRecord, changed: bool) -> Response<pb::UpdateTenantResponse> {
    Response::new(pb::UpdateTenantResponse {
        tenant: Some(tenant_to(rec)),
        changed,
    })
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
        | Error::PhpUnavailable
        | Error::RuntimeUnavailable(_)
        | Error::NoApp(_)
        | Error::RuntimeTooOld { .. }
        | Error::AppPolicyMissing
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
        created_at: Some(timestamp(rec.created_at_unix)),
        state: state.into(),
        owner: rec.owner.clone(),
        suspended: rec.suspended,
    }
}

fn vhost_to(rec: &VHostRecord) -> pb::VirtualHost {
    pb::VirtualHost {
        domain: rec.domain.clone(),
        tenant: rec.tenant.clone(),
        document_root: rec.document_root.clone(),
        aliases: rec.aliases.clone(),
        config_path: rec.config_path.to_string_lossy().into_owned(),
        php: rec.php,
        app: rec.app.as_ref().map(|a| pb::App {
            runtime: match a.runtime {
                AppRuntime::Node => pb::AppRuntime::Node,
                AppRuntime::Python => pb::AppRuntime::Python,
            }
            .into(),
            root: a.root.clone(),
            entry: a.entry.clone(),
        }),
    }
}

#[tonic::async_trait]
impl OxPanelEngine for Engine {
    async fn create_tenant(
        &self,
        req: Request<pb::CreateTenantRequest>,
    ) -> Result<Response<pb::CreateTenantResponse>, Status> {
        let peer = self.authorise(&req, "CreateTenant", Scope::Tenant)?;
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
        let peer = self.authorise(&req, "GetTenant", Scope::Read)?;
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
        let peer = self.authorise(&req, "ListTenants", Scope::Read)?;
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
        let peer = self.authorise(&req, "DeleteTenant", Scope::Delete)?;
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
        let peer = self.authorise(&req, "ConfigureVirtualHost", Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = "ConfigureVirtualHost", peer, domain = %r.domain, tenant = %r.tenant, "request");
        let app = match r.app {
            None => None,
            Some(a) => Some(AppRequest {
                runtime: match pb::AppRuntime::try_from(a.runtime) {
                    Ok(pb::AppRuntime::Node) => AppRuntime::Node,
                    Ok(pb::AppRuntime::Python) => AppRuntime::Python,
                    _ => {
                        return Err(fail(
                            "ConfigureVirtualHost",
                            &peer,
                            Error::invalid("app.runtime", "must be NODE or PYTHON"),
                        ))
                    }
                },
                root: a.root,
                entry: a.entry,
            }),
        };
        let (rec, created) = self
            .vhosts
            .configure(VHostRequest {
                domain: r.domain,
                tenant: r.tenant,
                document_root: r.document_root,
                aliases: r.aliases,
                php: r.php,
                app,
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
        let peer = self.authorise(&req, "RemoveVirtualHost", Scope::VHost)?;
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
        let peer = self.authorise(&req, "ListVirtualHosts", Scope::Read)?;
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

    async fn restart_app(
        &self,
        req: Request<pb::RestartAppRequest>,
    ) -> Result<Response<pb::RestartAppResponse>, Status> {
        const RPC: &str = "RestartApp";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, domain = %r.domain, "request");
        self.vhosts
            .restart_app(&r.domain)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::RestartAppResponse {}))
    }

    async fn install_app_dependencies(
        &self,
        req: Request<pb::InstallAppDependenciesRequest>,
    ) -> Result<Response<pb::InstallAppDependenciesResponse>, Status> {
        const RPC: &str = "InstallAppDependencies";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, domain = %r.domain, "request");
        let (succeeded, output) = self
            .vhosts
            .install_app_dependencies(&r.domain)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::InstallAppDependenciesResponse {
            succeeded,
            output,
        }))
    }

    async fn read_virtual_host_log(
        &self,
        req: Request<pb::ReadVirtualHostLogRequest>,
    ) -> Result<Response<pb::ReadVirtualHostLogResponse>, Status> {
        const RPC: &str = "ReadVirtualHostLog";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let kind = match pb::LogKind::try_from(r.kind) {
            Ok(pb::LogKind::Error) => LogKind::Error,
            Ok(pb::LogKind::App) => LogKind::App,
            Ok(pb::LogKind::Access | pb::LogKind::Unspecified) => LogKind::Access,
            Err(_) => return Err(fail(RPC, &peer, Error::invalid("kind", "unknown log kind"))),
        };
        let (text, truncated) = self
            .vhosts
            .read_log(&r.domain, kind, u64::from(r.max_bytes))
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::ReadVirtualHostLogResponse {
            text,
            truncated,
        }))
    }

    async fn update_tenant_limits(
        &self,
        req: Request<pb::UpdateTenantLimitsRequest>,
    ) -> Result<Response<pb::UpdateTenantResponse>, Status> {
        const RPC: &str = "UpdateTenantLimits";
        let peer = self.authorise(&req, RPC, Scope::Tenant)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, username = %r.username, "request");
        let limits = limits_from(r.limits).map_err(|e| fail(RPC, &peer, e))?;
        let (rec, changed) = self
            .tenants
            .update_limits(&r.username, limits)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(updated(&rec, changed))
    }

    async fn update_tenant_owner(
        &self,
        req: Request<pb::UpdateTenantOwnerRequest>,
    ) -> Result<Response<pb::UpdateTenantResponse>, Status> {
        const RPC: &str = "UpdateTenantOwner";
        let peer = self.authorise(&req, RPC, Scope::Tenant)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, username = %r.username, owner = %r.owner, "request");
        let (rec, changed) = self
            .tenants
            .update_owner(&r.username, &r.owner)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(updated(&rec, changed))
    }

    async fn suspend_tenant(
        &self,
        req: Request<pb::SuspendTenantRequest>,
    ) -> Result<Response<pb::UpdateTenantResponse>, Status> {
        const RPC: &str = "SuspendTenant";
        let peer = self.authorise(&req, RPC, Scope::Tenant)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, username = %r.username, "request");
        let (rec, changed) = self
            .tenants
            .set_suspended(&r.username, true)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(updated(&rec, changed))
    }

    async fn resume_tenant(
        &self,
        req: Request<pb::ResumeTenantRequest>,
    ) -> Result<Response<pb::UpdateTenantResponse>, Status> {
        const RPC: &str = "ResumeTenant";
        let peer = self.authorise(&req, RPC, Scope::Tenant)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, username = %r.username, "request");
        let (rec, changed) = self
            .tenants
            .set_suspended(&r.username, false)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(updated(&rec, changed))
    }

    async fn get_tenant_usage(
        &self,
        req: Request<pb::GetTenantUsageRequest>,
    ) -> Result<Response<pb::TenantUsage>, Status> {
        const RPC: &str = "GetTenantUsage";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let u = self
            .tenants
            .usage(&r.username)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::TenantUsage {
            username: r.username,
            memory_current_bytes: u.memory_current_bytes,
            cpu_usage_nsec: u.cpu_usage_nsec,
            tasks_current: u.tasks_current,
            disk_usage_bytes: u.disk_usage_bytes,
            measured_at: Some(timestamp(u.measured_at_unix)),
        }))
    }

    async fn get_host_info(
        &self,
        req: Request<pb::GetHostInfoRequest>,
    ) -> Result<Response<pb::HostInfo>, Status> {
        const RPC: &str = "GetHostInfo";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let i = self.host.info().await.map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::HostInfo {
            daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
            selinux_enabled: i.selinux,
            dry_run: i.dry_run,
            tenant_count: i.tenant_count,
            vhost_count: i.vhost_count,
            uid_min: i.uid_min,
            uid_max: i.uid_max,
            load_1m: i.stats.load.0,
            load_5m: i.stats.load.1,
            load_15m: i.stats.load.2,
            memory_total_bytes: i.stats.memory_total_bytes,
            memory_free_bytes: i.stats.memory_free_bytes,
            home_disk_total_bytes: i.stats.disk_total_bytes,
            home_disk_free_bytes: i.stats.disk_free_bytes,
            uptime_seconds: i.stats.uptime_secs,
            php_available: i.runtimes.php,
            node_available: i.runtimes.node,
            python_available: i.runtimes.python,
            node_version: i.node_version,
        }))
    }

    async fn reconcile(
        &self,
        req: Request<pb::ReconcileRequest>,
    ) -> Result<Response<pb::ReconcileResponse>, Status> {
        const RPC: &str = "Reconcile";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let drifts = self
            .host
            .reconcile()
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        info!(rpc = RPC, peer, findings = drifts.len(), "reconciled");
        Ok(Response::new(pb::ReconcileResponse {
            drifts: drifts.iter().map(drift_to).collect(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every internal drift kind maps to the protobuf kind of the same name
    /// (a swapped arm would make panels act on the wrong finding).
    #[test]
    fn every_drift_kind_maps_to_the_protobuf_kind_of_the_same_name() {
        use crate::host::{Drift, DriftKind};
        for kind in [
            DriftKind::TenantIncomplete,
            DriftKind::TenantAccountMissing,
            DriftKind::TenantAccountMismatch,
            DriftKind::TenantHomeInvalid,
            DriftKind::TenantUnitDrift,
            DriftKind::VHostTenantMissing,
            DriftKind::VHostConfigDrift,
            DriftKind::OrphanNginxConfig,
            DriftKind::OrphanSliceUnit,
            DriftKind::PhpPoolDrift,
            DriftKind::OrphanPhpPool,
            DriftKind::AppUnitDrift,
            DriftKind::OrphanAppUnit,
        ] {
            let dbg = format!("{kind:?}");
            let mut snake = String::new();
            for (n, ch) in dbg.chars().enumerate() {
                if ch.is_ascii_uppercase() && n > 0 {
                    snake.push('_');
                }
                snake.push(ch.to_ascii_uppercase());
            }
            let wire = drift_to(&Drift {
                kind,
                subject: "x".into(),
                detail: "y".into(),
            });
            let name = pb::DriftKind::try_from(wire.kind).map(|k| k.as_str_name());
            // "VHost" is "VHOST" on the wire, not "V_HOST".
            let want = format!("DRIFT_KIND_{}", snake.replace("V_HOST", "VHOST"));
            assert_eq!(name.ok(), Some(want.as_str()), "{kind:?}");
        }
    }

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
