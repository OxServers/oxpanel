//! gRPC surface of scheduled tasks, per-site PHP settings and scheduled
//! backups: wire ↔ domain conversions and the bodies of their RPCs (the
//! trait methods in `server.rs` delegate here).

use tonic::{Request, Response, Status};
use tracing::info;

use super::{fail, timestamp, updated, vhost_to, Engine};
use crate::auth::Scope;
use crate::backup_schedule::{self, Frequency, LastResult, View};
use crate::php_settings::{self, PhpLimits, PhpSettings, RawSettings};
use crate::records::VHostRecord;
use crate::task::{self, Form, RawSchedule, RawSpec, Schedule, TaskKind, TaskRecord, TaskStatus};
use crate::validate::Username;
use oxpanel_proto::v1 as pb;

/// 0 → unset; seconds → a timestamp.
fn stamp(unix: u64) -> Option<prost_types::Timestamp> {
    (unix != 0).then(|| timestamp(unix))
}

fn task_spec_from(spec: pb::ScheduledTaskSpec) -> RawSpec {
    let s = spec.schedule.unwrap_or_default();
    RawSpec {
        name: spec.name,
        kind: match pb::TaskKind::try_from(spec.kind) {
            Ok(pb::TaskKind::Php) => Some(TaskKind::Php),
            Ok(pb::TaskKind::Node) => Some(TaskKind::Node),
            Ok(pb::TaskKind::Python) => Some(TaskKind::Python),
            Ok(pb::TaskKind::Url) => Some(TaskKind::Url),
            _ => None,
        },
        script: spec.script,
        args: spec.args,
        virtualenv: spec.virtualenv,
        url: spec.url,
        schedule: RawSchedule {
            form: match pb::TaskScheduleForm::try_from(s.form) {
                Ok(pb::TaskScheduleForm::EveryMinutes) => Some(Form::EveryMinutes),
                Ok(pb::TaskScheduleForm::EveryHours) => Some(Form::EveryHours),
                Ok(pb::TaskScheduleForm::Daily) => Some(Form::Daily),
                Ok(pb::TaskScheduleForm::Weekly) => Some(Form::Weekly),
                Ok(pb::TaskScheduleForm::Monthly) => Some(Form::Monthly),
                _ => None,
            },
            interval: s.interval,
            minute: s.minute,
            hour: s.hour,
            weekday: s.weekday,
            day_of_month: s.day_of_month,
            time_zone: s.time_zone,
        },
        timeout_secs: spec.timeout_seconds,
        disabled: spec.disabled,
    }
}

fn schedule_to(s: Schedule, time_zone: &str) -> pb::TaskSchedule {
    let mut out = pb::TaskSchedule {
        time_zone: time_zone.to_owned(),
        ..pb::TaskSchedule::default()
    };
    let form = match s {
        Schedule::EveryMinutes { interval } => {
            out.interval = interval;
            pb::TaskScheduleForm::EveryMinutes
        }
        Schedule::EveryHours { interval, minute } => {
            (out.interval, out.minute) = (interval, minute);
            pb::TaskScheduleForm::EveryHours
        }
        Schedule::Daily { hour, minute } => {
            (out.hour, out.minute) = (hour, minute);
            pb::TaskScheduleForm::Daily
        }
        Schedule::Weekly {
            weekday,
            hour,
            minute,
        } => {
            (out.weekday, out.hour, out.minute) = (weekday, hour, minute);
            pb::TaskScheduleForm::Weekly
        }
        Schedule::Monthly { day, hour, minute } => {
            (out.day_of_month, out.hour, out.minute) = (day, hour, minute);
            pb::TaskScheduleForm::Monthly
        }
    };
    out.form = form.into();
    out
}

fn task_to(rec: &TaskRecord, status: &TaskStatus) -> pb::ScheduledTask {
    let kind = match rec.kind {
        TaskKind::Php => pb::TaskKind::Php,
        TaskKind::Node => pb::TaskKind::Node,
        TaskKind::Python => pb::TaskKind::Python,
        TaskKind::Url => pb::TaskKind::Url,
    };
    let unit = Username::parse(&rec.tenant)
        .map(|t| format!("{}.service", task::unit_base(&t, &rec.name)))
        .unwrap_or_default();
    pb::ScheduledTask {
        tenant: rec.tenant.clone(),
        spec: Some(pb::ScheduledTaskSpec {
            name: rec.name.clone(),
            kind: kind.into(),
            script: rec.script.clone(),
            args: rec.args.clone(),
            virtualenv: rec.virtualenv.clone(),
            url: rec.url.clone(),
            schedule: Some(schedule_to(rec.schedule, &rec.time_zone)),
            timeout_seconds: rec.timeout_secs,
            disabled: !rec.enabled,
        }),
        calendar: rec.schedule.calendar(&rec.time_zone),
        unit,
        running: status.running,
        last_started: stamp(status.last_started),
        last_finished: stamp(status.last_finished),
        last_result: status.last_result.clone(),
        last_exit_status: status.last_exit_status,
        next_run: stamp(status.next_run),
    }
}

pub(super) fn php_settings_to(s: &PhpSettings) -> Option<pb::PhpSettings> {
    (!s.is_empty()).then(|| pb::PhpSettings {
        memory_limit_mb: s.memory_limit_mb.unwrap_or(0),
        upload_max_filesize_mb: s.upload_max_filesize_mb.unwrap_or(0),
        post_max_size_mb: s.post_max_size_mb.unwrap_or(0),
        max_execution_time_seconds: s.max_execution_time_secs.unwrap_or(0),
        max_input_time_seconds: s.max_input_time_secs.unwrap_or(0),
        max_input_vars: s.max_input_vars.unwrap_or(0),
        display_errors: s.display_errors,
        date_timezone: s.date_timezone.clone(),
    })
}

fn php_settings_from(s: Option<pb::PhpSettings>) -> RawSettings {
    let s = s.unwrap_or_default();
    RawSettings {
        memory_limit_mb: s.memory_limit_mb,
        upload_max_filesize_mb: s.upload_max_filesize_mb,
        post_max_size_mb: s.post_max_size_mb,
        max_execution_time_secs: s.max_execution_time_seconds,
        max_input_time_secs: s.max_input_time_seconds,
        max_input_vars: s.max_input_vars,
        display_errors: s.display_errors,
        date_timezone: s.date_timezone,
    }
}

pub(super) fn php_limits_to(l: &PhpLimits) -> pb::PhpLimits {
    pb::PhpLimits {
        memory_limit_mb: l.memory_limit_mb,
        upload_max_filesize_mb: l.upload_max_mb,
        max_execution_time_seconds: l.max_execution_time_secs,
        max_input_time_seconds: l.max_input_time_secs,
        max_input_vars: l.max_input_vars,
    }
}

fn php_limits_from(l: Option<pb::PhpLimits>) -> PhpLimits {
    let l = l.unwrap_or_default();
    PhpLimits {
        memory_limit_mb: l.memory_limit_mb,
        upload_max_mb: l.upload_max_filesize_mb,
        max_execution_time_secs: l.max_execution_time_seconds,
        max_input_time_secs: l.max_input_time_seconds,
        max_input_vars: l.max_input_vars,
    }
}

pub(super) fn frequency_to(f: Frequency) -> pb::BackupFrequency {
    match f {
        Frequency::Off => pb::BackupFrequency::Off,
        Frequency::Daily => pb::BackupFrequency::Daily,
        Frequency::Weekly => pb::BackupFrequency::Weekly,
    }
}

fn schedule_view_to(v: &View) -> pb::BackupSchedule {
    let e = &v.effective;
    pb::BackupSchedule {
        tenant: v.tenant.clone(),
        frequency: frequency_to(e.frequency).into(),
        host_default: e.host_default,
        hour: e.hour,
        minute: e.minute,
        weekday: e.weekday,
        hour_assigned: e.hour_assigned,
        weekday_assigned: e.weekday_assigned,
        next_run: stamp(v.next_run),
        last_run: stamp(v.last_run),
        last_job_id: v.last_job.clone(),
        last_result: match v.last_result {
            LastResult::None => pb::ScheduledBackupResult::None,
            LastResult::Running => pb::ScheduledBackupResult::Running,
            LastResult::Succeeded => pb::ScheduledBackupResult::Succeeded,
            LastResult::Failed => pb::ScheduledBackupResult::Failed,
            LastResult::Deferred => pb::ScheduledBackupResult::Deferred,
        }
        .into(),
        last_message: v.last_message.clone(),
        enabled_on_host: v.enabled_on_host,
    }
}

impl Engine {
    /// Virtual hosts as the API shows them, with the PHP settings that
    /// apply (clamped to each tenant's caps).
    pub(super) fn vhosts_out(&self, recs: &[VHostRecord]) -> Vec<pb::VirtualHost> {
        let host = &self.ctx.config.essentials.php_max;
        recs.iter()
            .map(|rec| {
                let mut v = vhost_to(rec);
                v.dns_zone = self.dns.zone_of_site(rec);
                v.php_settings = php_settings_to(&rec.php_settings);
                if rec.php && !rec.php_settings.is_empty() {
                    let caps = Username::parse(&rec.tenant)
                        .ok()
                        .and_then(|t| self.ctx.store.load_tenant(&t).ok().flatten())
                        .map_or(*host, |t| t.php_limits.resolve(host));
                    v.php_settings_effective =
                        php_settings_to(&php_settings::effective(&rec.php_settings, &caps));
                }
                v
            })
            .collect()
    }

    pub(super) async fn put_scheduled_task_rpc(
        &self,
        req: Request<pb::PutScheduledTaskRequest>,
    ) -> Result<Response<pb::PutScheduledTaskResponse>, Status> {
        const RPC: &str = "PutScheduledTask";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        let spec = task_spec_from(r.spec.unwrap_or_default());
        info!(rpc = RPC, peer, tenant = %r.tenant, task = %spec.name, "request");
        let (rec, changed) = self
            .tasks
            .put(&r.tenant, &spec)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        let status = self
            .tasks
            .status(std::slice::from_ref(&rec))
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::PutScheduledTaskResponse {
            task: Some(task_to(
                &rec,
                status.first().unwrap_or(&TaskStatus::default()),
            )),
            changed,
        }))
    }

    pub(super) async fn delete_scheduled_task_rpc(
        &self,
        req: Request<pb::DeleteScheduledTaskRequest>,
    ) -> Result<Response<pb::DeleteScheduledTaskResponse>, Status> {
        const RPC: &str = "DeleteScheduledTask";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, task = %r.name, "request");
        let deleted = self
            .tasks
            .delete(&r.tenant, &r.name)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::DeleteScheduledTaskResponse { deleted }))
    }

    pub(super) async fn list_scheduled_tasks_rpc(
        &self,
        req: Request<pb::ListScheduledTasksRequest>,
    ) -> Result<Response<pb::ListScheduledTasksResponse>, Status> {
        const RPC: &str = "ListScheduledTasks";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let recs = self
            .tasks
            .list(&r.tenant)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        let status = self
            .tasks
            .status(&recs)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::ListScheduledTasksResponse {
            tasks: recs
                .iter()
                .zip(status.iter())
                .map(|(rec, s)| task_to(rec, s))
                .collect(),
        }))
    }

    pub(super) async fn run_scheduled_task_rpc(
        &self,
        req: Request<pb::RunScheduledTaskRequest>,
    ) -> Result<Response<pb::RunScheduledTaskResponse>, Status> {
        const RPC: &str = "RunScheduledTask";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, task = %r.name, "request");
        let started = self
            .tasks
            .run_now(&r.tenant, &r.name)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::RunScheduledTaskResponse { started }))
    }

    pub(super) async fn read_scheduled_task_log_rpc(
        &self,
        req: Request<pb::ReadScheduledTaskLogRequest>,
    ) -> Result<Response<pb::ReadScheduledTaskLogResponse>, Status> {
        const RPC: &str = "ReadScheduledTaskLog";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let text = self
            .tasks
            .read_log(&r.tenant, &r.name)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::ReadScheduledTaskLogResponse { text }))
    }

    pub(super) async fn set_php_settings_rpc(
        &self,
        req: Request<pb::SetPhpSettingsRequest>,
    ) -> Result<Response<pb::SetPhpSettingsResponse>, Status> {
        const RPC: &str = "SetPhpSettings";
        let peer = self.authorise(&req, RPC, Scope::VHost)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, domain = %r.domain, "request");
        let (rec, changed) = self
            .vhosts
            .set_php_settings(&r.domain, &php_settings_from(r.settings))
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(pb::SetPhpSettingsResponse {
            vhost: self.vhosts_out(std::slice::from_ref(&rec)).pop(),
            changed,
        }))
    }

    pub(super) async fn set_tenant_php_limits_rpc(
        &self,
        req: Request<pb::SetTenantPhpLimitsRequest>,
    ) -> Result<Response<pb::UpdateTenantResponse>, Status> {
        const RPC: &str = "SetTenantPhpLimits";
        let peer = self.authorise(&req, RPC, Scope::Tenant)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, username = %r.username, "request");
        let (rec, changed) = self
            .vhosts
            .set_tenant_php_limits(&r.username, &php_limits_from(r.limits))
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(updated(&rec, changed))
    }

    pub(super) async fn set_backup_schedule_rpc(
        &self,
        req: Request<pb::SetBackupScheduleRequest>,
    ) -> Result<Response<pb::BackupSchedule>, Status> {
        const RPC: &str = "SetBackupSchedule";
        let peer = self.authorise(&req, RPC, Scope::Tenant)?;
        let r = req.into_inner();
        info!(rpc = RPC, peer, tenant = %r.tenant, frequency = r.frequency, "request");
        let frequency = match pb::BackupFrequency::try_from(r.frequency) {
            Ok(pb::BackupFrequency::Off) => Some(Frequency::Off),
            Ok(pb::BackupFrequency::Daily) => Some(Frequency::Daily),
            Ok(pb::BackupFrequency::Weekly) => Some(Frequency::Weekly),
            Ok(pb::BackupFrequency::Unspecified) => None,
            Err(_) => {
                return Err(fail(
                    RPC,
                    &peer,
                    crate::Error::invalid("frequency", "OFF, DAILY, WEEKLY or UNSPECIFIED"),
                ))
            }
        };
        let view = self
            .schedules
            .set(&r.tenant, frequency, r.hour, r.weekday)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(schedule_view_to(&view)))
    }

    pub(super) async fn get_backup_schedule_rpc(
        &self,
        req: Request<pb::GetBackupScheduleRequest>,
    ) -> Result<Response<pb::BackupSchedule>, Status> {
        const RPC: &str = "GetBackupSchedule";
        let peer = self.authorise(&req, RPC, Scope::Read)?;
        let r = req.into_inner();
        let view = self
            .schedules
            .get(&r.tenant)
            .await
            .map_err(|e| fail(RPC, &peer, e))?;
        Ok(Response::new(schedule_view_to(&view)))
    }

    /// The essentials part of `GetHostInfo`.
    pub(super) fn essentials_info(&self, i: &mut pb::HostInfo, php_cli: bool) {
        let es = &self.ctx.config.essentials;
        i.php_cli_available = php_cli;
        i.php_limits = Some(php_limits_to(&es.php_max));
        i.task_max_per_tenant = es.task_max_per_tenant;
        i.task_min_interval_minutes = es.task_min_interval_minutes;
        i.task_max_timeout_seconds = es.task_max_timeout_secs;
        i.backup_schedules_enabled = es.backup_schedules;
        i.backup_schedule_default = frequency_to(es.backup_schedule_default).into();
    }

    /// The backup scheduler behind this engine (the daemon runs it).
    pub fn schedules(&self) -> backup_schedule::ScheduleService {
        self.schedules.clone()
    }
}
