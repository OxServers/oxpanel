//! gRPC surface: maps `oxpanel.v1` messages onto the workflows and back.

use tonic::service::interceptor::InterceptedService;

mod essentials;

/// Largest request the daemon will decode. Every message is a handful of
/// short strings; anything bigger is a mistake or an attack.
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

use std::sync::Arc;

use crate::auth::{PeerInfo, Scope, ScopePolicy};
use crate::auto_https;
use crate::backup::BackupService;
use crate::ctx::Ctx;
use crate::db::trash::Deleted;
use crate::db::DbService;
use crate::error::Error;
use crate::host::{Drift, DriftKind, HostService};
use crate::lifecycle::LifecycleService;
use crate::records::{
    AppRuntime, BackupRecord, BackupState, CertSource, DatabaseRecord, DbEngine, DbTrashRecord,
    DbUserRecord, JobKind, JobRecord, JobState, ObjectIssue, OnExisting, SftpKeyRecord,
    TenantRecord, TenantState, VHostRecord,
};
use crate::sftp::SftpService;
use crate::tenant::TenantService;
use crate::tls::{self, CertificateUpload, TlsService};
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
    sftp: SftpService,
    databases: DbService,
    scopes: Arc<ScopePolicy>,
    tls: TlsService,
    backups: BackupService,
    lifecycle: LifecycleService,
    tasks: crate::task::TaskService,
    schedules: crate::backup_schedule::ScheduleService,
    ctx: Ctx,
}

/// Interceptor type used by [`Engine::into_service`].
pub type Interceptor = fn(Request<()>) -> Result<Request<()>, Status>;

impl Engine {
    pub fn new(ctx: Ctx) -> Self {
        Self {
            scopes: Arc::new(ScopePolicy::new(ctx.config.peer_scopes.clone())),
            tenants: TenantService::new(ctx.clone()),
            vhosts: VHostService::new(ctx.clone()),
            tls: TlsService::new(ctx.clone()),
            sftp: SftpService::new(ctx.clone()),
            databases: DbService::new(ctx.clone()),
            backups: BackupService::new(ctx.clone()),
            lifecycle: LifecycleService::new(ctx.clone(), BackupService::new(ctx.clone())),
            tasks: crate::task::TaskService::new(ctx.clone()),
            schedules: crate::backup_schedule::ScheduleService::new(
                ctx.clone(),
                BackupService::new(ctx.clone()),
            ),
            host: HostService::new(ctx.clone()),
            ctx,
        }
    }

    /// The certificate workflows, for the daemon's own renewal timer. Shares
    /// the "request in flight" bookkeeping with the RPCs.
    pub fn tls(&self) -> TlsService {
        self.tls.clone()
    }

    /// The backup service behind this engine (the daemon resumes jobs
    /// through it at start-up).
    pub fn backups(&self) -> &BackupService {
        &self.backups
    }

    /// The tenant deletions behind this engine (resumed at start-up).
    pub fn lifecycle(&self) -> &LifecycleService {
        &self.lifecycle
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

/// Run `work` on its own task, so it completes even if the RPC that started
/// it is cancelled.
async fn detached<T: Send + 'static>(
    work: impl std::future::Future<Output = Result<T, Error>> + Send + 'static,
) -> Result<T, Error> {
    tokio::spawn(work)
        .await
        .map_err(|e| Error::Internal(format!("certificate task failed: {e}")))?
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
        DriftKind::TlsCertificateDrift => pb::DriftKind::TlsCertificateDrift,
        DriftKind::OrphanTlsFile => pb::DriftKind::OrphanTlsFile,
        DriftKind::OrphanAutoHttpsState => pb::DriftKind::OrphanAutoHttpsState,
        DriftKind::SftpAccessDrift => pb::DriftKind::SftpAccessDrift,
        DriftKind::OrphanSftpAccess => pb::DriftKind::OrphanSftpAccess,
        DriftKind::SshdConfigDrift => pb::DriftKind::SshdConfigDrift,
        DriftKind::DiskQuotaDrift => pb::DriftKind::DiskQuotaDrift,
        DriftKind::DatabaseMissing => pb::DriftKind::DatabaseMissing,
        DriftKind::DatabaseUserMissing => pb::DriftKind::DatabaseUserMissing,
        DriftKind::DatabasePrivilegeDrift => pb::DriftKind::DatabasePrivilegeDrift,
        DriftKind::OrphanDatabaseObject => pb::DriftKind::OrphanDatabaseObject,
        DriftKind::BackupArchiveMissing => pb::DriftKind::BackupArchiveMissing,
        DriftKind::BackupArchiveModified => pb::DriftKind::BackupArchiveModified,
        DriftKind::OrphanBackupArchive => pb::DriftKind::OrphanBackupArchive,
        DriftKind::BackupIncomplete => pb::DriftKind::BackupIncomplete,
        DriftKind::DatabaseTrashDrift => pb::DriftKind::DatabaseTrashDrift,
        DriftKind::OrphanDatabaseTrash => pb::DriftKind::OrphanDatabaseTrash,
        DriftKind::TaskUnitDrift => pb::DriftKind::TaskUnitDrift,
        DriftKind::OrphanTaskUnit => pb::DriftKind::OrphanTaskUnit,
        DriftKind::OrphanBackupSchedule => pb::DriftKind::OrphanBackupSchedule,
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
        | Error::CertificateInvalid(_)
        | Error::TlsUnavailable
        | Error::AcmeUnavailable(_)
        | Error::SftpUnavailable(_)
        | Error::SftpKeyNotFound { .. }
        | Error::TooManySftpKeys(_)
        | Error::DiskQuotaUnavailable(_)
        | Error::DbUnavailable(_)
        | Error::DbObjectNotFound { .. }
        | Error::DbNotManaged { .. }
        | Error::DbObjectUnusable { .. }
        | Error::DbLimitReached { .. }
        | Error::TenantHasDatabases(_)
        | Error::DbTrashFull { .. }
        | Error::TrashNotFound { .. }
        | Error::BackupNotFound { .. }
        | Error::BackupNotReady(_)
        | Error::JobNotFound(_)
        | Error::JobRunning { .. }
        | Error::TooManyJobs
        | Error::BackupNoSpace { .. }
        | Error::TenantHasBackups(_)
        | Error::TaskNotFound { .. }
        | Error::TaskLimitReached { .. }
        | Error::PhpNotEnabled(_)
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
    Ok(
        Limits::parse(l.memory_max_bytes, l.cpu_weight, l.io_weight, l.tasks_max)?
            .with_disk(l.disk_max_bytes, l.inodes_max)?
            .with_db_trash(l.db_trash_max_bytes),
    )
}

fn limits_to(l: &Limits) -> pb::ResourceLimits {
    pb::ResourceLimits {
        memory_max_bytes: l.memory_max_bytes.unwrap_or(0),
        cpu_weight: l.cpu_weight.unwrap_or(0),
        io_weight: l.io_weight.unwrap_or(0),
        tasks_max: l.tasks_max.unwrap_or(0),
        disk_max_bytes: l.disk_max_bytes.unwrap_or(0),
        inodes_max: l.inodes_max.unwrap_or(0),
        db_trash_max_bytes: l.db_trash_max_bytes.unwrap_or(0),
    }
}

fn sftp_key_to(k: &SftpKeyRecord) -> pb::SftpKey {
    pb::SftpKey {
        fingerprint: k.fingerprint.clone(),
        key_type: k.key_type.clone(),
        public_key: format!("{} {}", k.key_type, k.blob),
        label: k.label.clone(),
        added_at: Some(timestamp(k.added_at_unix)),
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
        sftp_key_count: u32::try_from(rec.sftp_keys.len()).unwrap_or(u32::MAX),
        sftp_password: rec.sftp_password,
        php_limits: (!rec.php_limits.is_empty())
            .then(|| essentials::php_limits_to(&rec.php_limits)),
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
        // Everything about the certificate except its private key.
        certificate: rec.tls.as_ref().map(|t| pb::Certificate {
            source: match t.source {
                CertSource::Uploaded => pb::CertificateSource::Uploaded,
                CertSource::Acme => pb::CertificateSource::Acme,
            }
            .into(),
            issuer: t.issuer.clone(),
            not_before: Some(timestamp(t.not_before_unix)),
            not_after: Some(timestamp(t.not_after_unix)),
            names: t.names.clone(),
            uncovered_names: tls::uncovered_names(rec),
            installed_at: Some(timestamp(t.installed_at_unix)),
        }),
        redirect_https: rec.redirect_https,
        hsts: rec.hsts,
        auto_https_opt_out: !rec.auto_https.is_on(),
        php_settings: essentials::php_settings_to(&rec.php_settings),
        // Needs the tenant's caps: filled in by Engine::vhosts_out.
        php_settings_effective: None,
    }
}

fn auto_https_to(s: &auto_https::Status) -> pb::AutoHttpsStatus {
    pb::AutoHttpsStatus {
        domain: s.domain.clone(),
        state: match s.state {
            auto_https::State::Disabled => pb::AutoHttpsState::Disabled,
            auto_https::State::Pending => pb::AutoHttpsState::Pending,
            auto_https::State::Covered => pb::AutoHttpsState::Covered,
            auto_https::State::Partial => pb::AutoHttpsState::Partial,
            auto_https::State::Failed => pb::AutoHttpsState::Failed,
            auto_https::State::Uploaded => pb::AutoHttpsState::Uploaded,
            auto_https::State::Suspended => pb::AutoHttpsState::Suspended,
        }
        .into(),
        covered_names: s.covered.clone(),
        skipped: s
            .skipped
            .iter()
            .map(|k| pb::AutoHttpsSkippedName {
                name: k.name.clone(),
                reason: k.reason.clone(),
                next_attempt: Some(timestamp(k.next_attempt_unix)),
                failures: k.failures,
            })
            .collect(),
        last_attempt: s.last_attempt_unix.map(timestamp),
        next_attempt: s.next_attempt_unix.map(timestamp),
        last_error: s.last_error.clone().unwrap_or_default(),
        pending_names: s.pending.clone(),
    }
}

fn engine_to(engine: DbEngine) -> i32 {
    match engine {
        DbEngine::Mariadb => pb::DatabaseEngine::Mariadb.into(),
    }
}

/// `UNSPECIFIED` is the default engine, MariaDB.
fn engine_from(raw: i32) -> Result<DbEngine, Error> {
    match pb::DatabaseEngine::try_from(raw) {
        Ok(pb::DatabaseEngine::Unspecified | pb::DatabaseEngine::Mariadb) => Ok(DbEngine::Mariadb),
        Err(_) => Err(Error::invalid("engine", "unknown database engine")),
    }
}

fn database_to(rec: &DatabaseRecord, size_bytes: u64) -> pb::Database {
    pb::Database {
        name: rec.name.clone(),
        tenant: rec.tenant.clone(),
        size_bytes,
        created_at: Some(timestamp(rec.created_at_unix)),
        engine: engine_to(rec.engine),
    }
}

/// A database user as the API shows it: there is no secret to leave out,
/// because none is recorded.
fn db_user_to(rec: &DbUserRecord) -> pb::DatabaseUser {
    pb::DatabaseUser {
        name: rec.name.clone(),
        tenant: rec.tenant.clone(),
        databases: rec.grants.clone(),
        max_connections: rec.max_user_connections,
        created_at: Some(timestamp(rec.created_at_unix)),
        engine: engine_to(rec.engine),
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
        info!(rpc = "DeleteTenant", peer, username = %r.username, remove_home = r.remove_home, cascade = r.cascade, final_backup_days = r.final_backup_retain_days, "request");
        if r.cascade {
            let started = self
                .lifecycle
                .delete_cascade(&r.username, &r.confirm_username, r.final_backup_retain_days)
                .await
                .map_err(|e| fail("DeleteTenant", &peer, e))?;
            return Ok(Response::new(pb::DeleteTenantResponse {
                deleted: false,
                started: started.as_ref().is_some_and(|(_, s)| *s),
                job: started.map(|(job, _)| job_to(&job)),
            }));
        }
        if !r.confirm_username.is_empty() || r.final_backup_retain_days != 0 {
            return Err(fail(
                "DeleteTenant",
                &peer,
                Error::invalid(
                    "cascade",
                    "confirm_username and final_backup_retain_days only apply with cascade",
                ),
            ));
        }
        let deleted = self
            .tenants
            .delete(&r.username, r.remove_home)
            .await
            .map_err(|e| fail("DeleteTenant", &peer, e))?;
        Ok(Response::new(pb::DeleteTenantResponse {
            deleted,
            job: None,
            started: false,
        }))
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
                redirect_https: r.redirect_https,
                hsts: r.hsts,
                auto_https: crate::records::AutoHttpsChoice::from_opt_out(r.auto_https_opt_out),
            })
            .await
            .map_err(|e| fail("ConfigureVirtualHost", &peer, e))?;
        // New site or new names: Automatic HTTPS looks at it once Nginx serves it.
        if rec.auto_https.is_on() {
            self.tls.auto_https_soon(rec.domain.clone());
        }
        Ok(Response::new(pb::ConfigureVirtualHostResponse {
            vhost: self.vhosts_out(std::slice::from_ref(&rec)).pop(),
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
            vhosts: self.vhosts_out(&recs),
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
        // Catch up on what was skipped while the tenant was suspended.
        if changed {
            if let Ok(sites) = self.vhosts.list(Some(&rec.username)).await {
                for v in sites {
                    self.tls.auto_https_soon(v.domain);
                }
            }
        }
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
        let mut info = pb::HostInfo {
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
            tls_available: i.tls.available,
            acme_available: i.tls.acme,
            acme_directory_url: i.tls.acme_directory_url,
            auto_https_enabled: self.tls.auto_https_enabled(),
            sftp_available: i.facilities.sftp,
            disk_quota_available: i.facilities.disk_quota,
            disk_quota_detail: i.facilities.disk_quota_detail,
            sftp_passwords_allowed: i.facilities.sftp_passwords,
            database_engines: i
                .databases
                .into_iter()
                .map(|f| pb::DatabaseEngineInfo {
                    engine: engine_to(f.engine),
                    available: f.available,
                    version: f.version,
                    database_count: f.database_count,
                    database_user_count: f.user_count,
                })
                .collect(),
            backup_disk_total_bytes: i.backup_disk_total_bytes,
            backup_disk_free_bytes: i.backup_disk_free_bytes,
            backup_keep: i.backup_keep,
            database_trash_days: i.db_trash_days,
            ..pb::HostInfo::default()
        };
        self.essentials_info(&mut info, i.php_cli);
        Ok(Response::new(info))
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

    async fn install_certificate(
        &self,
        req: Request<pb::InstallCertificateRequest>,
    ) -> Result<Response<pb::InstallCertificateResponse>, Status> {
        const RPC: &str = "InstallCertificate";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        // Only the domain: the request carries a private key.
        info!(rpc = RPC, peer, domain = %r.domain, "request");
        let (rec, changed) = self
            .tls
            .install(CertificateUpload {
                domain: r.domain,
                chain_pem: r.certificate_chain_pem,
                key_pem: r.private_key_pem,
            })
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::InstallCertificateResponse {
            vhost: Some(vhost_to(&rec)),
            changed,
        }))
    }

    async fn remove_certificate(
        &self,
        req: Request<pb::RemoveCertificateRequest>,
    ) -> Result<Response<pb::RemoveCertificateResponse>, Status> {
        const RPC: &str = "RemoveCertificate";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, domain = %r.domain, "request");
        let (rec, removed) = self
            .tls
            .remove(&r.domain)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::RemoveCertificateResponse {
            vhost: Some(vhost_to(&rec)),
            removed,
        }))
    }

    async fn request_certificate(
        &self,
        req: Request<pb::RequestCertificateRequest>,
    ) -> Result<Response<pb::RequestCertificateResponse>, Status> {
        const RPC: &str = "RequestCertificate";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, domain = %r.domain, "request");
        // On its own task: a caller that gives up (deadline, disconnect) must
        // not cut the request off between issuing and installing.
        let tls = self.tls.clone();
        let outcome = detached(async move { tls.request(&r.domain).await })
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::RequestCertificateResponse {
            succeeded: outcome.succeeded,
            output: outcome.output,
            vhost: Some(vhost_to(&outcome.vhost)),
        }))
    }

    async fn renew_certificates(
        &self,
        req: Request<pb::RenewCertificatesRequest>,
    ) -> Result<Response<pb::RenewCertificatesResponse>, Status> {
        const RPC: &str = "RenewCertificates";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        info!(rpc = RPC, peer, "request");
        let tls = self.tls.clone();
        let renewals = detached(async move { tls.renew_due().await })
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::RenewCertificatesResponse {
            renewals: renewals
                .into_iter()
                .map(|r| pb::CertificateRenewal {
                    domain: r.domain,
                    succeeded: r.succeeded,
                    output: r.output,
                })
                .collect(),
        }))
    }

    async fn run_auto_https(
        &self,
        req: Request<pb::RunAutoHttpsRequest>,
    ) -> Result<Response<pb::RunAutoHttpsResponse>, Status> {
        const RPC: &str = "RunAutoHttps";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, domain = %r.domain, "request");
        let tls = self.tls.clone();
        let sites = detached(async move { tls.auto_https_run(&r.domain).await })
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::RunAutoHttpsResponse {
            sites: sites.iter().map(auto_https_to).collect(),
        }))
    }

    async fn get_auto_https_status(
        &self,
        req: Request<pb::GetAutoHttpsStatusRequest>,
    ) -> Result<Response<pb::GetAutoHttpsStatusResponse>, Status> {
        const RPC: &str = "GetAutoHttpsStatus";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let sites = self
            .tls
            .auto_https_status(&r.domain)
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::GetAutoHttpsStatusResponse {
            sites: sites.iter().map(auto_https_to).collect(),
        }))
    }

    async fn add_sftp_key(
        &self,
        req: Request<pb::AddSftpKeyRequest>,
    ) -> Result<Response<pb::AddSftpKeyResponse>, Status> {
        const RPC: &str = "AddSftpKey";
        // Customers manage their own SFTP access (owner decision): vhost scope.
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        // The key itself is public, but there is no reason to log it.
        info!(rpc = RPC, peer, username = %r.username, "request");
        let (_, key, changed) = self
            .sftp
            .add_key(&r.username, &r.public_key, &r.label)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::AddSftpKeyResponse {
            key: Some(sftp_key_to(&key)),
            changed,
        }))
    }

    async fn remove_sftp_key(
        &self,
        req: Request<pb::RemoveSftpKeyRequest>,
    ) -> Result<Response<pb::RemoveSftpKeyResponse>, Status> {
        const RPC: &str = "RemoveSftpKey";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, username = %r.username, fingerprint = %r.fingerprint, end_sessions = r.end_sessions, "request");
        let rec = self
            .sftp
            .remove_key(&r.username, &r.fingerprint, r.end_sessions)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::RemoveSftpKeyResponse {
            remaining: u32::try_from(rec.sftp_keys.len()).unwrap_or(u32::MAX),
        }))
    }

    async fn list_sftp_keys(
        &self,
        req: Request<pb::ListSftpKeysRequest>,
    ) -> Result<Response<pb::ListSftpKeysResponse>, Status> {
        const RPC: &str = "ListSftpKeys";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let keys = self
            .sftp
            .list_keys(&r.username)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::ListSftpKeysResponse {
            keys: keys.iter().map(sftp_key_to).collect(),
        }))
    }

    async fn set_sftp_password(
        &self,
        req: Request<pb::SetSftpPasswordRequest>,
    ) -> Result<Response<pb::SetSftpPasswordResponse>, Status> {
        const RPC: &str = "SetSftpPassword";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        // The password is never logged; only who asked for which tenant.
        info!(rpc = RPC, peer, username = %r.username, "request");
        let rec = self
            .sftp
            .set_password(&r.username, &r.password)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::SetSftpPasswordResponse {
            tenant: Some(tenant_to(&rec)),
        }))
    }

    async fn clear_sftp_password(
        &self,
        req: Request<pb::ClearSftpPasswordRequest>,
    ) -> Result<Response<pb::ClearSftpPasswordResponse>, Status> {
        const RPC: &str = "ClearSftpPassword";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, username = %r.username, end_sessions = r.end_sessions, "request");
        let (rec, cleared) = self
            .sftp
            .clear_password(&r.username, r.end_sessions)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::ClearSftpPasswordResponse {
            cleared,
            tenant: Some(tenant_to(&rec)),
        }))
    }

    async fn create_database(
        &self,
        req: Request<pb::CreateDatabaseRequest>,
    ) -> Result<Response<pb::CreateDatabaseResponse>, Status> {
        const RPC: &str = "CreateDatabase";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, database = %r.name, "request");
        let (rec, created) = self
            .databases
            .create_database(
                &r.tenant,
                &r.name,
                engine_from(r.engine).map_err(|e| fail(RPC, &peer, e))?,
            )
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::CreateDatabaseResponse {
            database: Some(database_to(&rec, 0)),
            created,
        }))
    }

    async fn list_databases(
        &self,
        req: Request<pb::ListDatabasesRequest>,
    ) -> Result<Response<pb::ListDatabasesResponse>, Status> {
        const RPC: &str = "ListDatabases";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let recs = self
            .databases
            .list_databases(&r.tenant)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::ListDatabasesResponse {
            databases: recs
                .iter()
                .map(|(rec, size)| database_to(rec, *size))
                .collect(),
        }))
    }

    async fn delete_database(
        &self,
        req: Request<pb::DeleteDatabaseRequest>,
    ) -> Result<Response<pb::DeleteDatabaseResponse>, Status> {
        const RPC: &str = "DeleteDatabase";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, database = %r.name, "request");
        let outcome = self
            .databases
            .delete_database(&r.name)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(match outcome {
            Deleted::NotFound => pb::DeleteDatabaseResponse::default(),
            Deleted::Vanished => pb::DeleteDatabaseResponse {
                deleted: true,
                ..pb::DeleteDatabaseResponse::default()
            },
            Deleted::Trashed(t) => pb::DeleteDatabaseResponse {
                deleted: true,
                trash_id: t.id.clone(),
                purge_at: Some(timestamp(t.purge_at_unix)),
            },
        }))
    }

    async fn create_database_user(
        &self,
        req: Request<pb::CreateDatabaseUserRequest>,
    ) -> Result<Response<pb::CreateDatabaseUserResponse>, Status> {
        const RPC: &str = "CreateDatabaseUser";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, user = %r.name, "request");
        let (rec, created) = self
            .databases
            .create_user(
                &r.tenant,
                &r.name,
                &r.password,
                engine_from(r.engine).map_err(|e| fail(RPC, &peer, e))?,
            )
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::CreateDatabaseUserResponse {
            user: Some(db_user_to(&rec)),
            created,
        }))
    }

    async fn list_database_users(
        &self,
        req: Request<pb::ListDatabaseUsersRequest>,
    ) -> Result<Response<pb::ListDatabaseUsersResponse>, Status> {
        const RPC: &str = "ListDatabaseUsers";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let recs = self
            .databases
            .list_users(&r.tenant)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::ListDatabaseUsersResponse {
            users: recs.iter().map(db_user_to).collect(),
        }))
    }

    async fn set_database_user_password(
        &self,
        req: Request<pb::SetDatabaseUserPasswordRequest>,
    ) -> Result<Response<pb::SetDatabaseUserPasswordResponse>, Status> {
        const RPC: &str = "SetDatabaseUserPassword";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, user = %r.name, "request");
        self.databases
            .set_password(&r.name, &r.password)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::SetDatabaseUserPasswordResponse {}))
    }

    async fn delete_database_user(
        &self,
        req: Request<pb::DeleteDatabaseUserRequest>,
    ) -> Result<Response<pb::DeleteDatabaseUserResponse>, Status> {
        const RPC: &str = "DeleteDatabaseUser";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, user = %r.name, "request");
        let deleted = self
            .databases
            .delete_user(&r.name)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::DeleteDatabaseUserResponse { deleted }))
    }

    async fn grant_database_access(
        &self,
        req: Request<pb::GrantDatabaseAccessRequest>,
    ) -> Result<Response<pb::GrantDatabaseAccessResponse>, Status> {
        const RPC: &str = "GrantDatabaseAccess";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, user = %r.user, database = %r.database, "request");
        let (rec, changed) = self
            .databases
            .grant(&r.user, &r.database)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::GrantDatabaseAccessResponse {
            user: Some(db_user_to(&rec)),
            changed,
        }))
    }

    async fn revoke_database_access(
        &self,
        req: Request<pb::RevokeDatabaseAccessRequest>,
    ) -> Result<Response<pb::RevokeDatabaseAccessResponse>, Status> {
        const RPC: &str = "RevokeDatabaseAccess";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, user = %r.user, database = %r.database, "request");
        let (rec, changed) = self
            .databases
            .revoke(&r.user, &r.database)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::RevokeDatabaseAccessResponse {
            user: Some(db_user_to(&rec)),
            changed,
        }))
    }

    async fn create_backup(
        &self,
        req: Request<pb::CreateBackupRequest>,
    ) -> Result<Response<pb::StartJobResponse>, Status> {
        const RPC: &str = "CreateBackup";
        let peer = self.authorise(&req, RPC, Scope::Tenant)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, "request");
        let (job, started) = self
            .backups
            .create(&r.tenant, r.retain_months, r.retain_days)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::StartJobResponse {
            job: Some(job_to(&job)),
            started,
        }))
    }

    async fn list_backups(
        &self,
        req: Request<pb::ListBackupsRequest>,
    ) -> Result<Response<pb::ListBackupsResponse>, Status> {
        const RPC: &str = "ListBackups";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let recs = self
            .backups
            .list(&r.tenant)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::ListBackupsResponse {
            backups: recs.iter().map(backup_to).collect(),
        }))
    }

    async fn delete_backup(
        &self,
        req: Request<pb::DeleteBackupRequest>,
    ) -> Result<Response<pb::DeleteBackupResponse>, Status> {
        const RPC: &str = "DeleteBackup";
        let peer = self.authorise(&req, RPC, Scope::Delete)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, backup = %r.backup_id, "request");
        let deleted = if r.tenant_deleted {
            self.backups.delete_retained(&r.tenant, &r.backup_id).await
        } else {
            self.backups.delete(&r.tenant, &r.backup_id).await
        }
        .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::DeleteBackupResponse { deleted }))
    }

    async fn restore_backup(
        &self,
        req: Request<pb::RestoreBackupRequest>,
    ) -> Result<Response<pb::StartJobResponse>, Status> {
        const RPC: &str = "RestoreBackup";
        let peer = self.authorise(&req, RPC, Scope::Tenant)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, backup = %r.backup_id, on_existing = r.on_existing, "request");
        let mode = on_existing(r.on_existing).map_err(|e| fail(RPC, &peer, e))?;
        let (job, started) = self
            .backups
            .restore(&r.tenant, &r.backup_id, mode)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::StartJobResponse {
            job: Some(job_to(&job)),
            started,
        }))
    }

    async fn get_job(&self, req: Request<pb::GetJobRequest>) -> Result<Response<pb::Job>, Status> {
        const RPC: &str = "GetJob";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let job = self
            .backups
            .job(&r.job_id)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(job_to(&job)))
    }

    async fn retain_backup(
        &self,
        req: Request<pb::RetainBackupRequest>,
    ) -> Result<Response<pb::Backup>, Status> {
        const RPC: &str = "RetainBackup";
        let peer = self.authorise(&req, RPC, Scope::Tenant)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, backup = %r.backup_id, months = r.retain_months, "request");
        let rec = self
            .backups
            .retain(&r.tenant, &r.backup_id, r.retain_months, r.retain_days)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(backup_to(&rec)))
    }

    async fn list_retained_backups(
        &self,
        req: Request<pb::ListRetainedBackupsRequest>,
    ) -> Result<Response<pb::ListBackupsResponse>, Status> {
        const RPC: &str = "ListRetainedBackups";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let recs = self
            .backups
            .list_retained()
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::ListBackupsResponse {
            backups: recs.iter().map(backup_to).collect(),
        }))
    }

    async fn restore_retained_backup(
        &self,
        req: Request<pb::RestoreRetainedBackupRequest>,
    ) -> Result<Response<pb::StartJobResponse>, Status> {
        const RPC: &str = "RestoreRetainedBackup";
        // Data of one (deleted) account into another: the strongest scope.
        let peer = self.authorise(&req, RPC, Scope::Delete)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, backup = %r.backup_id, from = %r.source_tenant, to = %r.target_tenant, on_existing = r.on_existing, "request");
        let mode = on_existing(r.on_existing).map_err(|e| fail(RPC, &peer, e))?;
        let (job, started) = self
            .backups
            .restore_retained(&r.backup_id, &r.source_tenant, &r.target_tenant, mode)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::StartJobResponse {
            job: Some(job_to(&job)),
            started,
        }))
    }

    async fn list_database_trash(
        &self,
        req: Request<pb::ListDatabaseTrashRequest>,
    ) -> Result<Response<pb::ListDatabaseTrashResponse>, Status> {
        const RPC: &str = "ListDatabaseTrash";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let listing = self
            .databases
            .list_trash(&r.tenant)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::ListDatabaseTrashResponse {
            databases: listing.items.iter().map(trashed_to).collect(),
            total_bytes: listing.total_bytes,
            cap_bytes: listing.cap_bytes.unwrap_or(0),
        }))
    }

    async fn restore_database_trash(
        &self,
        req: Request<pb::RestoreDatabaseTrashRequest>,
    ) -> Result<Response<pb::RestoreDatabaseTrashResponse>, Status> {
        const RPC: &str = "RestoreDatabaseTrash";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, trash = %r.trash_id, new_name = %r.new_name, "request");
        let (rec, issues) = self
            .databases
            .restore_trash(&r.tenant, &r.trash_id, &r.new_name)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::RestoreDatabaseTrashResponse {
            database: Some(database_to(&rec, 0)),
            object_issues: issues.iter().map(issue_to).collect(),
        }))
    }

    async fn purge_database_trash(
        &self,
        req: Request<pb::PurgeDatabaseTrashRequest>,
    ) -> Result<Response<pb::PurgeDatabaseTrashResponse>, Status> {
        const RPC: &str = "PurgeDatabaseTrash";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, trash = %r.trash_id, "request");
        let purged = self
            .databases
            .purge_trash(&r.tenant, &r.trash_id)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::PurgeDatabaseTrashResponse { purged }))
    }

    async fn restore_backup_database(
        &self,
        req: Request<pb::RestoreBackupDatabaseRequest>,
    ) -> Result<Response<pb::StartJobResponse>, Status> {
        const RPC: &str = "RestoreBackupDatabase";
        let peer = self.authorise(&req, RPC, Scope::Tenant)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, backup = %r.backup_id, database = %r.database, new_name = %r.new_name, "request");
        let (job, started) = self
            .backups
            .restore_database(&r.tenant, &r.backup_id, &r.database, &r.new_name)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::StartJobResponse {
            job: Some(job_to(&job)),
            started,
        }))
    }

    async fn restore_retained_backup_database(
        &self,
        req: Request<pb::RestoreRetainedBackupDatabaseRequest>,
    ) -> Result<Response<pb::StartJobResponse>, Status> {
        const RPC: &str = "RestoreRetainedBackupDatabase";
        // Data of one (deleted) account into another: the strongest scope.
        let peer = self.authorise(&req, RPC, Scope::Delete)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, backup = %r.backup_id, from = %r.source_tenant, to = %r.target_tenant, database = %r.database, new_name = %r.new_name, "request");
        let (job, started) = self
            .backups
            .restore_retained_database(
                &r.backup_id,
                &r.source_tenant,
                &r.target_tenant,
                &r.database,
                &r.new_name,
            )
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::StartJobResponse {
            job: Some(job_to(&job)),
            started,
        }))
    }

    // --- Scheduled tasks, PHP settings, scheduled backups (server/essentials.rs)

    async fn put_scheduled_task(
        &self,
        req: Request<pb::PutScheduledTaskRequest>,
    ) -> Result<Response<pb::PutScheduledTaskResponse>, Status> {
        self.put_scheduled_task_rpc(req).await
    }

    async fn delete_scheduled_task(
        &self,
        req: Request<pb::DeleteScheduledTaskRequest>,
    ) -> Result<Response<pb::DeleteScheduledTaskResponse>, Status> {
        self.delete_scheduled_task_rpc(req).await
    }

    async fn list_scheduled_tasks(
        &self,
        req: Request<pb::ListScheduledTasksRequest>,
    ) -> Result<Response<pb::ListScheduledTasksResponse>, Status> {
        self.list_scheduled_tasks_rpc(req).await
    }

    async fn run_scheduled_task(
        &self,
        req: Request<pb::RunScheduledTaskRequest>,
    ) -> Result<Response<pb::RunScheduledTaskResponse>, Status> {
        self.run_scheduled_task_rpc(req).await
    }

    async fn read_scheduled_task_log(
        &self,
        req: Request<pb::ReadScheduledTaskLogRequest>,
    ) -> Result<Response<pb::ReadScheduledTaskLogResponse>, Status> {
        self.read_scheduled_task_log_rpc(req).await
    }

    async fn set_php_settings(
        &self,
        req: Request<pb::SetPhpSettingsRequest>,
    ) -> Result<Response<pb::SetPhpSettingsResponse>, Status> {
        self.set_php_settings_rpc(req).await
    }

    async fn set_tenant_php_limits(
        &self,
        req: Request<pb::SetTenantPhpLimitsRequest>,
    ) -> Result<Response<pb::UpdateTenantResponse>, Status> {
        self.set_tenant_php_limits_rpc(req).await
    }

    async fn set_backup_schedule(
        &self,
        req: Request<pb::SetBackupScheduleRequest>,
    ) -> Result<Response<pb::BackupSchedule>, Status> {
        self.set_backup_schedule_rpc(req).await
    }

    async fn get_backup_schedule(
        &self,
        req: Request<pb::GetBackupScheduleRequest>,
    ) -> Result<Response<pb::BackupSchedule>, Status> {
        self.get_backup_schedule_rpc(req).await
    }
}

fn trashed_to(t: &DbTrashRecord) -> pb::TrashedDatabase {
    pb::TrashedDatabase {
        id: t.id.clone(),
        name: t.name.clone(),
        tenant: t.tenant.clone(),
        engine: engine_to(t.engine),
        deleted_at: Some(timestamp(t.deleted_at_unix)),
        purge_at: Some(timestamp(t.purge_at_unix)),
        size_bytes: t.size_bytes,
        object_count: u32::try_from(t.objects.len()).unwrap_or(u32::MAX),
    }
}

fn issue_to(i: &ObjectIssue) -> pb::DatabaseObjectIssue {
    pb::DatabaseObjectIssue {
        kind: i.kind.as_str().to_owned(),
        name: i.name.clone(),
        reason: i.reason.clone(),
        definition: i.definition.clone(),
    }
}

/// The caller's choice for existing files; there is no default.
fn on_existing(raw: i32) -> Result<OnExisting, Error> {
    match pb::OnExisting::try_from(raw) {
        Ok(pb::OnExisting::Overwrite) => Ok(OnExisting::Overwrite),
        Ok(pb::OnExisting::Keep) => Ok(OnExisting::Keep),
        _ => Err(Error::invalid(
            "on_existing",
            "choose ON_EXISTING_OVERWRITE or ON_EXISTING_KEEP",
        )),
    }
}

fn backup_to(rec: &BackupRecord) -> pb::Backup {
    pb::Backup {
        id: rec.id.clone(),
        tenant: rec.tenant.clone(),
        created_at: Some(timestamp(rec.created_at_unix)),
        state: match rec.state {
            BackupState::Creating => pb::BackupState::Creating,
            BackupState::Ready => pb::BackupState::Ready,
        }
        .into(),
        size_bytes: rec.size_bytes,
        members: rec
            .members
            .iter()
            .map(|m| pb::BackupMember {
                name: m.name.clone(),
                kind: m.kind.clone(),
                size_bytes: m.size_bytes,
                sha256: m.sha256.clone(),
            })
            .collect(),
        domains: rec.domains.clone(),
        retain_until: (rec.retain_until_unix != 0).then(|| timestamp(rec.retain_until_unix)),
        tenant_deleted: rec.tenant_deleted,
        exclude_rules: crate::backup::EXCLUDE_RULES
            .iter()
            .map(|r| (*r).to_owned())
            .collect(),
        excluded: rec.excluded.clone(),
        excluded_count: rec.excluded_count,
        databases: rec
            .databases
            .iter()
            .map(|d| pb::BackupDatabase {
                name: d.name.clone(),
                engine: engine_to(d.engine),
                size_bytes: d.size_bytes,
                dump_member: d.dump_member.clone(),
                objects_member: d.objects_member.clone(),
            })
            .collect(),
    }
}

fn job_to(rec: &JobRecord) -> pb::Job {
    pb::Job {
        id: rec.id.clone(),
        kind: match rec.kind {
            JobKind::Backup => pb::JobKind::Backup,
            JobKind::Restore => pb::JobKind::Restore,
            JobKind::RestoreDatabase => pb::JobKind::RestoreDatabase,
            JobKind::DeleteTenant => pb::JobKind::DeleteTenant,
        }
        .into(),
        tenant: rec.tenant.clone(),
        backup_id: rec.backup_id.clone(),
        state: match rec.state {
            JobState::Running => pb::JobState::Running,
            JobState::Succeeded => pb::JobState::Succeeded,
            JobState::Failed => pb::JobState::Failed,
        }
        .into(),
        message: rec.message.clone(),
        output: rec.output.clone(),
        started_at: Some(timestamp(rec.started_at_unix)),
        finished_at: (rec.finished_at_unix != 0).then(|| timestamp(rec.finished_at_unix)),
        on_existing: match rec.on_existing {
            None => pb::OnExisting::Unspecified,
            Some(OnExisting::Overwrite) => pb::OnExisting::Overwrite,
            Some(OnExisting::Keep) => pb::OnExisting::Keep,
        }
        .into(),
        restored_entries: rec.restored_entries,
        skipped_entries: rec.skipped_entries,
        sites: rec
            .sites
            .iter()
            .map(|s| pb::JobSiteResult {
                domain: s.domain.clone(),
                succeeded: s.succeeded,
                detail: s.detail.clone(),
            })
            .collect(),
        database: rec.database.clone(),
        new_name: rec.new_name.clone(),
        object_issues: rec.object_issues.iter().map(issue_to).collect(),
        phase: rec.phase.clone(),
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
            DriftKind::TlsCertificateDrift,
            DriftKind::OrphanTlsFile,
            DriftKind::OrphanAutoHttpsState,
            DriftKind::SftpAccessDrift,
            DriftKind::OrphanSftpAccess,
            DriftKind::SshdConfigDrift,
            DriftKind::DiskQuotaDrift,
            DriftKind::DatabaseMissing,
            DriftKind::DatabaseUserMissing,
            DriftKind::DatabasePrivilegeDrift,
            DriftKind::OrphanDatabaseObject,
            DriftKind::BackupArchiveMissing,
            DriftKind::BackupArchiveModified,
            DriftKind::OrphanBackupArchive,
            DriftKind::BackupIncomplete,
            DriftKind::DatabaseTrashDrift,
            DriftKind::OrphanDatabaseTrash,
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
            disk_max_bytes: Some(1 << 30),
            inodes_max: Some(10_000),
            db_trash_max_bytes: None,
        };
        let pbv = limits_to(&l);
        assert_eq!(pbv.disk_max_bytes, 1 << 30);
        assert_eq!(limits_from(Some(pbv)).ok(), Some(l));
        assert_eq!(limits_from(None).ok(), Some(Limits::default()));
        let too_small = pb::ResourceLimits {
            disk_max_bytes: 4096,
            ..pb::ResourceLimits::default()
        };
        assert!(matches!(
            limits_from(Some(too_small)),
            Err(Error::InvalidInput { .. })
        ));
    }
}
