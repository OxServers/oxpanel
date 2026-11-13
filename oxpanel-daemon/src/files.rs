//! The file manager: a tenant's files, managed on its behalf through the API
//! (browse, read, write, upload, organise, compress, extract).
//!
//! The daemon never touches a tenant's file itself. It validates the
//! request ([`FilePath`], [`FileMode`], …), checks the tenant (ready; not
//! suspended for a change) and hands the operation to the worker
//! ([`crate::files_worker`]) running **as the tenant**:
//!
//! - quick operations (list, stat, read, write, uploads, make directory,
//!   move, change access, search, size) run synchronously: this binary in
//!   `files` mode, started through `systemd-run --scope` in the tenant's
//!   slice (its memory, CPU and I/O limits apply) and `setpriv` to the
//!   tenant's uid and gid with no groups, no capabilities and
//!   `no_new_privs`. The request is JSON on its standard input (marked
//!   secret: file content never appears in a log), the answer JSON on its
//!   standard output;
//! - long operations (copy, delete, compress, extract) are **jobs**, like
//!   backups: a transient service (`oxpanel-files-<id>`) with `User=` the
//!   tenant, in its slice, sandboxed, time-limited, that outlives the
//!   request and the daemon. The record is written before the unit starts;
//!   the daemon watches the unit and concludes the job from the worker's
//!   last line in the journal. One job per tenant at a time.
//!
//! Because the worker is the tenant, the kernel refuses whatever the tenant
//! could not do itself (another home, a root file, a file the tenant made
//! unreadable), the disk quota charges every byte written, and files come
//! out owned by the tenant, with the same modes, ACL inheritance and
//! SELinux labels as over SFTP. Because it resolves every path with
//! `openat2(RESOLVE_BENEATH)` from the home, a symlink cannot lead it out.
//!
//! Decisions (see `docs/superpowers/specs/2026-11-14-files-design.md`):
//! content needs the `vhost` scope (listing only `read`); a suspended
//! tenant's files are read-only and its running job is stopped; the home,
//! document roots, application roots and the directories leading to them
//! cannot be deleted, moved or re-moded through the file manager.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{info, warn};

use crate::backup::{parse_unit_state, UnitState};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::files_worker::{
    self, parse_response, ArchiveFormat, Entry, Fault, JobSummary, ModeChange, Op, Refusal, Reply,
    Request, Response,
};
use crate::fsutil;
use crate::nginx::safe_path_str;
use crate::records::{
    now_unix, FileJobKind, FileJobRecord, JobState, TenantRecord, TenantState, UploadRecord,
    RECORD_VERSION,
};
use crate::system::command::setpriv_args;
use crate::system::{bin, CommandSpec};
use crate::validate::{
    check_new_name, FileJobId, FileMode, FilePath, UploadId, Username, FILE_NAME_MAX,
};

/// Most bytes one `ReadFile` returns.
pub const READ_MAX: u64 = 1 << 20;
/// Most bytes of content one `WriteFile` or `UploadChunk` carries (the
/// daemon decodes requests of at most 256 KiB).
pub const WRITE_MAX: usize = 192 * 1024;
pub const LIST_PAGE_DEFAULT: u64 = 500;
pub const LIST_PAGE_MAX: u64 = 1000;
pub const SEARCH_DEFAULT: u64 = 200;
pub const SEARCH_MAX: u64 = 1000;
/// Paths or names one job may be given.
pub const SELECTION_MAX: usize = 1000;
/// Uploads in progress per tenant.
pub const UPLOADS_PER_TENANT: usize = 8;
/// An upload not finished after this long is removed.
pub const UPLOAD_STALE_SECS: u64 = 24 * 3600;
/// File jobs running on the host at once, over all tenants.
pub const MAX_RUNNING_FILE_JOBS: usize = 8;
/// Finished file jobs remembered per tenant.
const JOBS_KEPT_PER_TENANT: usize = 50;
/// How long a job-starting request waits for the job to finish.
const JOB_WAIT: Duration = Duration::from_secs(2);
const JOB_WAIT_STEP: Duration = Duration::from_millis(150);
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const SWEEP_INTERVAL: Duration = Duration::from_secs(3600);
const MAX_DRIVER_FAULTS: u32 = 30;
/// How much of a job's output its record keeps.
const OUTPUT_LINES: &str = "40";
const OUTPUT_MAX_BYTES: usize = 4096;
/// Memory one synchronous worker may use (it reads at most 1 MiB of
/// content and one directory's names).
const WORKER_MEMORY_MAX: &str = "MemoryMax=256M";
/// Memory a job's worker may use (zip central directories, tar headers).
const JOB_MEMORY_MAX: &str = "MemoryMax=1G";

/// Prefix of the job worker's last line: its result as JSON. File names in
/// the lines before it are escaped, so none can forge it.
pub const JOB_RESULT: &str = "oxpanel-files-result";

/// The job worker's verdict, as its last line carries it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JobResult {
    pub summary: JobSummary,
    pub refusal: Option<Refusal>,
}

/// The unit of a file job, without `.service`.
pub fn unit_name(id: &FileJobId) -> String {
    format!("oxpanel-files-{id}")
}

/// The last result line in a job's output.
pub fn parse_job_result(output: &str) -> Option<JobResult> {
    output.lines().rev().find_map(|line| {
        let json = line
            .trim_end()
            .strip_prefix(JOB_RESULT)?
            .strip_prefix(' ')?;
        serde_json::from_str(json).ok()
    })
}

/// The output without the result line, for the record.
fn without_result(output: &str) -> String {
    let kept: Vec<&str> = output
        .lines()
        .filter(|l| !l.starts_with(JOB_RESULT))
        .collect();
    let text = kept.join("\n");
    let mut start = text.len().saturating_sub(OUTPUT_MAX_BYTES);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text.get(start..).unwrap_or_default().trim().to_owned()
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// A file job as the API asks for it (validated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobRequest {
    Copy {
        sources: Vec<FilePath>,
        destination: FilePath,
        overwrite: bool,
    },
    Delete {
        paths: Vec<FilePath>,
    },
    Compress {
        directory: FilePath,
        names: Vec<String>,
        archive: FilePath,
        format: ArchiveFormat,
        overwrite: bool,
    },
    Extract {
        archive: FilePath,
        destination: FilePath,
        overwrite: bool,
    },
}

fn selection<'a>(raw: &'a [String], field: &'static str) -> Result<&'a [String]> {
    if raw.is_empty() || raw.len() > SELECTION_MAX {
        return Err(Error::invalid(
            field,
            format!("give 1 to {SELECTION_MAX} entries"),
        ));
    }
    Ok(raw)
}

fn not_home(path: FilePath, field: &'static str) -> Result<FilePath> {
    if path.is_home() {
        return Err(Error::invalid(field, "must name an entry inside the home"));
    }
    Ok(path)
}

impl JobRequest {
    pub fn copy(sources: &[String], destination: &str, overwrite: bool) -> Result<Self> {
        Ok(Self::Copy {
            sources: selection(sources, "sources")?
                .iter()
                .map(|s| not_home(FilePath::parse(s, "sources")?, "sources"))
                .collect::<Result<_>>()?,
            destination: FilePath::parse(destination, "destination")?,
            overwrite,
        })
    }

    pub fn delete(paths: &[String]) -> Result<Self> {
        Ok(Self::Delete {
            paths: selection(paths, "paths")?
                .iter()
                .map(|s| not_home(FilePath::parse(s, "paths")?, "paths"))
                .collect::<Result<_>>()?,
        })
    }

    pub fn compress(
        directory: &str,
        names: &[String],
        archive: &str,
        format: ArchiveFormat,
        overwrite: bool,
    ) -> Result<Self> {
        for name in selection(names, "names")? {
            let plain = !name.is_empty()
                && name.len() <= FILE_NAME_MAX
                && name != "."
                && name != ".."
                && !name.contains(['/', '\0']);
            if !plain {
                return Err(Error::invalid(
                    "names",
                    "each must be the name of an entry in the directory",
                ));
            }
        }
        Ok(Self::Compress {
            directory: FilePath::parse(directory, "directory")?,
            names: names.to_vec(),
            archive: FilePath::parse_new(archive, "archive")?,
            format,
            overwrite,
        })
    }

    pub fn extract(archive: &str, destination: &str, overwrite: bool) -> Result<Self> {
        Ok(Self::Extract {
            archive: not_home(FilePath::parse(archive, "archive")?, "archive")?,
            destination: FilePath::parse(destination, "destination")?,
            overwrite,
        })
    }

    fn kind(&self) -> FileJobKind {
        match self {
            Self::Copy { .. } => FileJobKind::Copy,
            Self::Delete { .. } => FileJobKind::Delete,
            Self::Compress { .. } => FileJobKind::Compress,
            Self::Extract { .. } => FileJobKind::Extract,
        }
    }

    /// What was asked, in a few words, for the record.
    fn describe(&self) -> String {
        let one = |n: usize, first: &FilePath| {
            if n == 1 {
                format!("'{}'", files_worker::shown(first.display()))
            } else {
                format!("{n} entries")
            }
        };
        let shown = |p: &FilePath| files_worker::shown(p.display());
        match self {
            Self::Copy {
                sources,
                destination,
                ..
            } => match sources.first() {
                Some(first) => format!(
                    "copy {} into '{}'",
                    one(sources.len(), first),
                    shown(destination)
                ),
                None => "copy".to_owned(),
            },
            Self::Delete { paths } => match paths.first() {
                Some(first) => format!("delete {}", one(paths.len(), first)),
                None => "delete".to_owned(),
            },
            Self::Compress { names, archive, .. } => {
                format!("compress {} entries into '{}'", names.len(), shown(archive))
            }
            Self::Extract {
                archive,
                destination,
                ..
            } => format!("extract '{}' into '{}'", shown(archive), shown(destination)),
        }
    }

    fn into_op(self) -> Op {
        match self {
            Self::Copy {
                sources,
                destination,
                overwrite,
            } => Op::Copy {
                sources,
                destination,
                overwrite,
            },
            Self::Delete { paths } => Op::Delete { paths },
            Self::Compress {
                directory,
                names,
                archive,
                format,
                overwrite,
            } => Op::Compress {
                directory,
                names,
                archive,
                format,
                overwrite,
            },
            Self::Extract {
                archive,
                destination,
                overwrite,
            } => Op::Extract {
                archive,
                destination,
                overwrite,
            },
        }
    }
}

/// What `ReadFile` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResult {
    pub data: Vec<u8>,
    pub size: u64,
    pub modified_unix: i64,
    pub modified_nanos: u32,
    pub eof: bool,
}

#[derive(Debug, Clone)]
pub struct FileService {
    ctx: Ctx,
    poll: Duration,
}

impl FileService {
    pub fn new(ctx: Ctx) -> Self {
        Self {
            ctx,
            poll: POLL_INTERVAL,
        }
    }

    /// How often running jobs are looked at (tests shorten it).
    #[must_use]
    pub fn with_poll_interval(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }

    /// The tenant, ready; for a change (`write`), not suspended.
    fn tenant(&self, name: &str, write: bool) -> Result<TenantRecord> {
        let name = Username::parse_field(name, "tenant")?;
        let rec = self
            .ctx
            .store
            .load_tenant(&name)?
            .ok_or_else(|| Error::TenantNotFound(name.to_string()))?;
        if rec.state != TenantState::Ready {
            return Err(Error::TenantNotReady(name.to_string()));
        }
        if write && rec.suspended {
            return Err(Error::TenantSuspended(name.to_string()));
        }
        // While a deletion of the tenant runs (its final backup is being
        // taken), its files are not changed any more.
        if write {
            if let Some(job) = crate::lifecycle::running_deletion(&self.ctx, &name)? {
                return Err(Error::JobRunning {
                    tenant: name.to_string(),
                    job: job.id,
                });
            }
        }
        Ok(rec)
    }

    /// The engine's directories in the tenant's home: every document root
    /// and application root of its sites.
    fn protected(&self, tenant: &TenantRecord) -> Result<Vec<FilePath>> {
        let mut out = Vec::new();
        for v in self.ctx.store.list_vhosts()? {
            if v.tenant != tenant.username {
                continue;
            }
            out.push(FilePath::parse(&v.document_root, "document_root")?);
            if let Some(app) = &v.app {
                out.push(FilePath::parse(&app.root, "app.root")?);
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    fn request(&self, tenant: &TenantRecord, op: Op) -> Result<Request> {
        Ok(Request {
            home: tenant.home.clone(),
            protected: self.protected(tenant)?,
            limits: self.ctx.config.files,
            op,
        })
    }

    /// `systemd-run --scope` in the tenant's slice, then `setpriv` to the
    /// tenant, then this binary as the synchronous worker.
    pub fn sync_command(&self, tenant: &TenantRecord, timeout: Duration) -> Result<CommandSpec> {
        let exe = safe_path_str(&self.ctx.config.worker_exe)?;
        Ok(CommandSpec::new(bin::SYSTEMD_RUN, timeout)
            .args(["--quiet", "--scope", "--collect"])
            .arg(format!("--slice={}", tenant.slice_unit))
            .arg(format!("--property={WORKER_MEMORY_MAX}"))
            .arg("--property=TasksMax=8")
            .arg("--")
            .arg(bin::SETPRIV)
            .args(setpriv_args(tenant.uid, tenant.gid))
            .arg(exe)
            .arg(files_worker::SUBCOMMAND))
    }

    /// Run one synchronous operation as the tenant.
    async fn call(
        &self,
        tenant: &TenantRecord,
        op: Op,
        data: &[u8],
        timeout: Duration,
    ) -> Result<(Reply, Vec<u8>)> {
        let req = self.request(tenant, op)?;
        let mut input = serde_json::to_vec(&req)
            .map_err(|e| Error::Internal(format!("serialise file request: {e}")))?;
        input.push(b'\n');
        input.extend_from_slice(data);
        // Secret: the input may carry file content, which is never logged.
        let cmd = self.sync_command(tenant, timeout)?.secret_stdin(input);
        let out = self.ctx.sys.run(cmd).await?;
        match parse_response(&out.stdout) {
            Ok((Response::Ok { reply }, rest)) => Ok((reply, rest.to_vec())),
            Ok((Response::Refused { refusal }, _)) => Err(Error::FileRefused {
                fault: refusal.fault,
                message: refusal.message,
            }),
            Err(why) => Err(Error::Internal(format!(
                "the file worker of '{}' failed (status {:?}): {why}",
                tenant.username, out.code
            ))),
        }
    }

    fn timeout(&self) -> Duration {
        self.ctx.config.command_timeout
    }

    /// Searches and sizes may take their own bound plus a margin.
    fn walk_timeout(&self) -> Duration {
        Duration::from_secs(self.ctx.config.files.walk_max_secs + 30).max(self.timeout())
    }

    async fn entry(&self, tenant: &TenantRecord, op: Op) -> Result<Entry> {
        match self.call(tenant, op, &[], self.timeout()).await?.0 {
            Reply::Entry { entry } => Ok(entry),
            other => Err(unexpected(&other)),
        }
    }

    // --- synchronous operations ------------------------------------------------

    /// One page of a directory: (entries, total, truncated).
    pub async fn list(
        &self,
        tenant: &str,
        path: &str,
        offset: u32,
        limit: u32,
    ) -> Result<(Vec<Entry>, u64, bool)> {
        let t = self.tenant(tenant, false)?;
        let path = FilePath::parse(path, "path")?;
        let limit = match u64::from(limit) {
            0 => LIST_PAGE_DEFAULT,
            n if n > LIST_PAGE_MAX => {
                return Err(Error::invalid(
                    "limit",
                    format!("at most {LIST_PAGE_MAX} entries per page"),
                ))
            }
            n => n,
        };
        let op = Op::List {
            path,
            offset: u64::from(offset),
            limit,
        };
        match self.call(&t, op, &[], self.timeout()).await?.0 {
            Reply::Listing {
                entries,
                total,
                truncated,
            } => Ok((entries, total, truncated)),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn stat(&self, tenant: &str, path: &str) -> Result<Entry> {
        let t = self.tenant(tenant, false)?;
        let path = FilePath::parse(path, "path")?;
        self.entry(&t, Op::Stat { path }).await
    }

    pub async fn read(
        &self,
        tenant: &str,
        path: &str,
        offset: u64,
        length: u32,
    ) -> Result<ReadResult> {
        let t = self.tenant(tenant, false)?;
        let path = not_home(FilePath::parse(path, "path")?, "path")?;
        let length = match u64::from(length) {
            0 => READ_MAX,
            n if n > READ_MAX => {
                return Err(Error::invalid(
                    "length",
                    format!("at most {READ_MAX} bytes per read"),
                ))
            }
            n => n,
        };
        let op = Op::Read {
            path,
            offset,
            length,
        };
        match self.call(&t, op, &[], self.timeout()).await? {
            (
                Reply::Data {
                    size,
                    modified_unix,
                    modified_nanos,
                    length,
                },
                data,
            ) if data.len() as u64 == length => Ok(ReadResult {
                eof: offset.saturating_add(length) >= size,
                data,
                size,
                modified_unix,
                modified_nanos,
            }),
            (other, _) => Err(unexpected(&other)),
        }
    }

    pub async fn write(
        &self,
        tenant: &str,
        path: &str,
        data: &[u8],
        overwrite: bool,
    ) -> Result<Entry> {
        let t = self.tenant(tenant, true)?;
        let path = FilePath::parse_new(path, "path")?;
        check_size(data)?;
        let op = Op::Write {
            path,
            overwrite,
            mode: None,
        };
        match self.call(&t, op, data, self.timeout()).await?.0 {
            Reply::Entry { entry } => Ok(entry),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn make_dir(&self, tenant: &str, path: &str, parents: bool) -> Result<Entry> {
        let t = self.tenant(tenant, true)?;
        let path = FilePath::parse_new(path, "path")?;
        if parents {
            // Every directory it may create is a new name.
            for comp in path.components() {
                check_new_name(comp, "path")?;
            }
        }
        self.entry(&t, Op::MakeDir { path, parents }).await
    }

    pub async fn rename(
        &self,
        tenant: &str,
        from: &str,
        to: &str,
        overwrite: bool,
    ) -> Result<Entry> {
        let t = self.tenant(tenant, true)?;
        let from = not_home(FilePath::parse(from, "from")?, "from")?;
        let to = FilePath::parse_new(to, "to")?;
        self.entry(
            &t,
            Op::Rename {
                from,
                to,
                overwrite,
            },
        )
        .await
    }

    pub async fn chmod(&self, tenant: &str, path: &str, change: ModeChange) -> Result<Entry> {
        let t = self.tenant(tenant, true)?;
        let path = not_home(FilePath::parse(path, "path")?, "path")?;
        let change = match change {
            ModeChange::Bits(bits) => ModeChange::Bits(FileMode::parse(bits, "mode")?.bits()),
            other => other,
        };
        self.entry(&t, Op::Chmod { path, change }).await
    }

    /// (matches, scanned, truncated)
    pub async fn search(
        &self,
        tenant: &str,
        path: &str,
        needle: &str,
        max_results: u32,
    ) -> Result<(Vec<Entry>, u64, bool)> {
        let t = self.tenant(tenant, false)?;
        let path = FilePath::parse(path, "path")?;
        if needle.is_empty() || needle.len() > FILE_NAME_MAX || needle.contains(['/', '\0']) {
            return Err(Error::invalid(
                "name_contains",
                format!("must be 1 to {FILE_NAME_MAX} bytes, without '/'"),
            ));
        }
        let max_results = match u64::from(max_results) {
            0 => SEARCH_DEFAULT,
            n => n.min(SEARCH_MAX),
        };
        let op = Op::Search {
            path,
            needle: needle.to_owned(),
            max_results,
        };
        match self.call(&t, op, &[], self.walk_timeout()).await?.0 {
            Reply::Found {
                matches,
                scanned,
                truncated,
            } => Ok((matches, scanned, truncated)),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn size(&self, tenant: &str, path: &str) -> Result<Reply> {
        let t = self.tenant(tenant, false)?;
        let path = FilePath::parse(path, "path")?;
        match self
            .call(&t, Op::Size { path }, &[], self.walk_timeout())
            .await?
            .0
        {
            reply @ Reply::Size { .. } => Ok(reply),
            other => Err(unexpected(&other)),
        }
    }

    // --- uploads ------------------------------------------------------------------

    fn upload_of(&self, tenant: &TenantRecord, id: &str) -> Result<(UploadId, UploadRecord)> {
        let id = UploadId::parse(id)?;
        match self.ctx.store.load_upload(&id)? {
            Some(rec) if rec.tenant == tenant.username => Ok((id, rec)),
            // Another tenant's upload does not exist for this one.
            _ => Err(Error::UploadNotFound(id.to_string())),
        }
    }

    pub async fn start_upload(
        &self,
        tenant: &str,
        path: &str,
        overwrite: bool,
    ) -> Result<UploadRecord> {
        let t = self.tenant(tenant, true)?;
        let path = FilePath::parse_new(path, "path")?;
        let rec = {
            let _guard = self.ctx.lock.lock().await;
            let open = self
                .ctx
                .store
                .list_uploads()?
                .into_iter()
                .filter(|u| u.tenant == t.username)
                .count();
            if open >= UPLOADS_PER_TENANT {
                return Err(Error::TooManyUploads(t.username.clone()));
            }
            let mut millis = unix_millis();
            let id = loop {
                let id = UploadId::from_millis(millis);
                if self.ctx.store.load_upload(&id)?.is_none() {
                    break id;
                }
                millis += 1;
            };
            let rec = UploadRecord {
                version: RECORD_VERSION,
                id: id.to_string(),
                tenant: t.username.clone(),
                path: path.as_str().to_owned(),
                overwrite,
                created_at_unix: now_unix(),
            };
            // The record first: a partial file is never left without one.
            self.ctx.store.save_upload(&rec)?;
            rec
        };
        let id = UploadId::parse(&rec.id)?;
        let op = Op::UploadStart {
            path,
            partial: id.partial_name(),
            overwrite,
        };
        if let Err(e) = self.call(&t, op, &[], self.timeout()).await {
            self.ctx.store.delete_upload(&id)?;
            return Err(e);
        }
        info!(tenant = %t.username, upload = %id, "upload started");
        Ok(rec)
    }

    pub async fn upload_chunk(
        &self,
        tenant: &str,
        id: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<u64> {
        let t = self.tenant(tenant, true)?;
        let (id, rec) = self.upload_of(&t, id)?;
        check_size(data)?;
        let op = Op::UploadChunk {
            path: FilePath::parse(&rec.path, "path")?,
            partial: id.partial_name(),
            offset,
        };
        match self.call(&t, op, data, self.timeout()).await {
            Ok((Reply::Received { bytes }, _)) => Ok(bytes),
            Ok((other, _)) => Err(unexpected(&other)),
            Err(e) => {
                self.forget_upload_if_gone(&t, &id, &rec).await;
                Err(e)
            }
        }
    }

    pub async fn finish_upload(
        &self,
        tenant: &str,
        id: &str,
        size: u64,
        sha256: &str,
    ) -> Result<Entry> {
        let t = self.tenant(tenant, true)?;
        let (id, rec) = self.upload_of(&t, id)?;
        let sha256 = match sha256 {
            "" => None,
            s if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) => {
                Some(s.to_ascii_lowercase())
            }
            _ => {
                return Err(Error::invalid(
                    "sha256",
                    "must be 64 hexadecimal digits (or empty)",
                ))
            }
        };
        let op = Op::UploadFinish {
            path: FilePath::parse(&rec.path, "path")?,
            partial: id.partial_name(),
            size,
            sha256,
            overwrite: rec.overwrite,
        };
        match self.call(&t, op, &[], self.timeout()).await {
            Ok((Reply::Entry { entry }, _)) => {
                self.ctx.store.delete_upload(&id)?;
                info!(tenant = %t.username, upload = %id, bytes = size, "upload finished");
                Ok(entry)
            }
            Ok((other, _)) => Err(unexpected(&other)),
            Err(e) => {
                self.forget_upload_if_gone(&t, &id, &rec).await;
                Err(e)
            }
        }
    }

    /// After a refused chunk or finish: if the worker removed the partial
    /// file (quota exceeded, too large, checksum mismatch), the upload is
    /// over and its record goes too.
    async fn forget_upload_if_gone(&self, t: &TenantRecord, id: &UploadId, rec: &UploadRecord) {
        let partial = FilePath::parse(&rec.path, "path")
            .map(|p| p.parent())
            .and_then(|dir| dir.join(&id.partial_name(), "path"));
        let Ok(partial) = partial else { return };
        let gone = matches!(
            self.entry(t, Op::Stat { path: partial }).await,
            Err(Error::FileRefused {
                fault: Fault::NotFound,
                ..
            })
        );
        if gone {
            if let Err(e) = self.ctx.store.delete_upload(id) {
                warn!(upload = %id, error = %e, "could not remove the record of an ended upload");
            }
        }
    }

    pub async fn abort_upload(&self, tenant: &str, id: &str) -> Result<bool> {
        let t = self.tenant(tenant, false)?;
        let (id, rec) = match self.upload_of(&t, id) {
            Ok(found) => found,
            Err(Error::UploadNotFound(_)) => return Ok(false),
            Err(e) => return Err(e),
        };
        self.discard_upload(&t, &id, &rec).await?;
        Ok(true)
    }

    async fn discard_upload(
        &self,
        t: &TenantRecord,
        id: &UploadId,
        rec: &UploadRecord,
    ) -> Result<()> {
        let op = Op::UploadAbort {
            path: FilePath::parse(&rec.path, "path")?,
            partial: id.partial_name(),
        };
        self.call(t, op, &[], self.timeout()).await?;
        self.ctx.store.delete_upload(id)?;
        info!(tenant = %t.username, upload = %id, "upload aborted");
        Ok(())
    }

    /// Remove uploads left unfinished for longer than [`UPLOAD_STALE_SECS`]
    /// (as the tenant), and records of uploads whose tenant is gone.
    pub async fn sweep_uploads(&self) -> Result<usize> {
        let mut removed = 0;
        let now = now_unix();
        for rec in self.ctx.store.list_uploads()? {
            if now.saturating_sub(rec.created_at_unix) < UPLOAD_STALE_SECS {
                continue;
            }
            let id = UploadId::parse(&rec.id)?;
            match self.tenant(&rec.tenant, false) {
                Ok(t) => {
                    if let Err(e) = self.discard_upload(&t, &id, &rec).await {
                        warn!(upload = %id, error = %e, "stale upload could not be removed; will retry");
                        continue;
                    }
                }
                Err(_) => {
                    self.ctx.store.delete_upload(&id)?;
                }
            }
            removed += 1;
        }
        Ok(removed)
    }

    /// Sweep stale uploads now and then every hour.
    pub fn spawn_sweeper(&self) {
        let svc = self.clone();
        tokio::spawn(async move {
            loop {
                match svc.sweep_uploads().await {
                    Ok(0) => {}
                    Ok(n) => info!(removed = n, "stale uploads removed"),
                    Err(e) => warn!(error = %e, "could not sweep stale uploads; will retry"),
                }
                tokio::time::sleep(SWEEP_INTERVAL).await;
            }
        });
    }

    // --- jobs -----------------------------------------------------------------------

    /// The `systemd-run` invocation of a job: the worker as the tenant, in
    /// its slice, at a low priority, able to write the home and nothing else,
    /// without any capability, reading its request on standard input.
    pub fn job_command(&self, job: &FileJobRecord, tenant: &TenantRecord) -> Result<CommandSpec> {
        let cfg = &self.ctx.config;
        let home = safe_path_str(&tenant.home)?;
        let exe = safe_path_str(&cfg.worker_exe)?;
        let id = FileJobId::parse(&job.id)?;
        let request_path = self.ctx.store.file_job_request_path(&id);
        let request = safe_path_str(&request_path)?;
        let mut cmd = CommandSpec::new(bin::SYSTEMD_RUN, cfg.command_timeout)
            .arg("--quiet")
            .arg(format!("--unit={}", job.unit))
            .arg(format!("--uid={}", tenant.uid))
            .arg(format!("--gid={}", tenant.gid));
        for property in [
            format!(
                "Description=OxPanel file {} job {} (tenant {})",
                job.kind.as_str(),
                job.id,
                tenant.username
            ),
            format!("Slice={}", tenant.slice_unit),
            // Opened by systemd before it drops to the tenant: the request
            // stays root-only on disk.
            format!("StandardInput=file:{request}"),
            "StandardOutput=journal".to_owned(),
            "StandardError=journal".to_owned(),
            "Nice=10".to_owned(),
            "IOSchedulingClass=best-effort".to_owned(),
            "IOSchedulingPriority=6".to_owned(),
            format!("RuntimeMaxSec={}", cfg.files_job_timeout.as_secs()),
            "RemainAfterExit=yes".to_owned(),
            "UMask=0022".to_owned(),
            JOB_MEMORY_MAX.to_owned(),
            "TasksMax=16".to_owned(),
            "SupplementaryGroups=".to_owned(),
            "CapabilityBoundingSet=".to_owned(),
            "AmbientCapabilities=".to_owned(),
            "NoNewPrivileges=yes".to_owned(),
            "PrivateNetwork=yes".to_owned(),
            "PrivateTmp=yes".to_owned(),
            "PrivateDevices=yes".to_owned(),
            "ProtectSystem=strict".to_owned(),
            format!("ReadWritePaths={home}"),
            "ProtectKernelTunables=yes".to_owned(),
            "ProtectKernelModules=yes".to_owned(),
            "ProtectKernelLogs=yes".to_owned(),
            "ProtectControlGroups=yes".to_owned(),
            "ProtectClock=yes".to_owned(),
            "ProtectHostname=yes".to_owned(),
            "ProtectProc=invisible".to_owned(),
            "ProcSubset=pid".to_owned(),
            "RestrictNamespaces=yes".to_owned(),
            "RestrictRealtime=yes".to_owned(),
            "RestrictSUIDSGID=yes".to_owned(),
            "LockPersonality=yes".to_owned(),
            "MemoryDenyWriteExecute=yes".to_owned(),
            "SystemCallArchitectures=native".to_owned(),
        ] {
            cmd = cmd.arg("--property").arg(property);
        }
        Ok(cmd.arg("--").arg(exe).arg(files_worker::JOB_SUBCOMMAND))
    }

    fn running_jobs(&self) -> Result<Vec<FileJobRecord>> {
        let mut jobs = self.ctx.store.list_file_jobs()?;
        jobs.retain(|j| j.state == JobState::Running);
        Ok(jobs)
    }

    /// Start a job for `tenant`, then wait briefly for it to end.
    pub async fn start_job(&self, tenant: &str, request: JobRequest) -> Result<FileJobRecord> {
        let t = self.tenant(tenant, true)?;
        let id = {
            let _guard = self.ctx.lock.lock().await;
            let t = self.tenant(&t.username, true)?;
            let running = self.running_jobs()?;
            if let Some(job) = running.iter().find(|j| j.tenant == t.username) {
                return Err(Error::FileJobRunning {
                    tenant: t.username.clone(),
                    job: job.id.clone(),
                });
            }
            if running.len() >= MAX_RUNNING_FILE_JOBS {
                return Err(Error::TooManyFileJobs);
            }
            let mut millis = unix_millis();
            let id = loop {
                let id = FileJobId::from_millis(millis);
                if self.ctx.store.load_file_job(&id)?.is_none() {
                    break id;
                }
                millis += 1;
            };
            let job = FileJobRecord {
                version: RECORD_VERSION,
                id: id.to_string(),
                kind: request.kind(),
                tenant: t.username.clone(),
                unit: unit_name(&id),
                state: JobState::Running,
                request: request.describe(),
                message: String::new(),
                output: String::new(),
                started_at_unix: now_unix(),
                finished_at_unix: 0,
                entries: 0,
                bytes: 0,
                skipped: 0,
            };
            let req = self.request(&t, request.into_op())?;
            let mut line = serde_json::to_vec(&req)
                .map_err(|e| Error::Internal(format!("serialise file job: {e}")))?;
            line.push(b'\n');
            // Records first: whatever happens next, a restarted daemon knows
            // there is a job to finish.
            fsutil::write_atomic(&self.ctx.store.file_job_request_path(&id), &line, 0o600)?;
            self.ctx.store.save_file_job(&job)?;
            let started = match self.job_command(&job, &t) {
                Ok(cmd) => self.ctx.sys.run_ok(cmd).await.map(|_| ()),
                Err(e) => Err(e),
            };
            if let Err(e) = started {
                self.conclude(job, Err("the job could not be started".to_owned()), "")?;
                return Err(e);
            }
            info!(job = %id, tenant = %t.username, kind = request_kind_str(&req.op), "file job started");
            id
        };
        self.spawn_driver(id.clone());
        let waited = tokio::time::Instant::now();
        while waited.elapsed() < JOB_WAIT {
            if self.step(&id).await.unwrap_or(false) {
                break;
            }
            tokio::time::sleep(JOB_WAIT_STEP).await;
        }
        self.ctx
            .store
            .load_file_job(&id)?
            .ok_or_else(|| Error::JobNotFound(id.to_string()))
    }

    /// One of the tenant's jobs (another tenant's is not found).
    pub async fn job(&self, tenant: &str, id: &str) -> Result<FileJobRecord> {
        let name = Username::parse_field(tenant, "tenant")?;
        let id = FileJobId::parse(id)?;
        match self.ctx.store.load_file_job(&id)? {
            Some(job) if job.tenant == name.as_str() => Ok(job),
            _ => Err(Error::JobNotFound(id.to_string())),
        }
    }

    pub async fn jobs(&self, tenant: &str) -> Result<Vec<FileJobRecord>> {
        let name = Username::parse_field(tenant, "tenant")?;
        let mut jobs = self.ctx.store.list_file_jobs()?;
        jobs.retain(|j| j.tenant == name.as_str());
        Ok(jobs)
    }

    /// Pick up every job that was running when the daemon last stopped.
    pub async fn resume_all(&self) -> Result<usize> {
        let jobs = self.running_jobs()?;
        for job in &jobs {
            info!(job = %job.id, tenant = %job.tenant, "resuming file job");
            self.spawn_driver(FileJobId::parse(&job.id)?);
        }
        Ok(jobs.len())
    }

    fn spawn_driver(&self, id: FileJobId) {
        tokio::spawn(self.clone().drive(id));
    }

    async fn drive(self, id: FileJobId) {
        let mut faults = 0;
        loop {
            match self.step(&id).await {
                Ok(true) => return,
                Ok(false) => faults = 0,
                Err(e) => {
                    faults += 1;
                    warn!(job = %id, error = %e, faults, "could not check on file job; will retry");
                    if faults >= MAX_DRIVER_FAULTS {
                        return;
                    }
                }
            }
            tokio::time::sleep(self.poll).await;
        }
    }

    /// Look at a job once; conclude it if its unit has ended. Returns
    /// whether the job is finished.
    pub async fn step(&self, id: &FileJobId) -> Result<bool> {
        let Some(job) = self.ctx.store.load_file_job(id)? else {
            return Ok(true);
        };
        if job.state != JobState::Running {
            return Ok(true);
        }
        let state = self.unit_state(&job.unit).await?;
        if state == UnitState::Running {
            return Ok(false);
        }
        let output = self.unit_output(&job.unit).await;
        let _guard = self.ctx.lock.lock().await;
        // Another look may have concluded it meanwhile.
        let Some(job) = self.ctx.store.load_file_job(id)? else {
            return Ok(true);
        };
        if job.state != JobState::Running {
            return Ok(true);
        }
        let unit = job.unit.clone();
        let outcome = match &state {
            UnitState::Exited | UnitState::Running => Ok(()),
            UnitState::Gone => {
                Err("the job did not run to its end (was the host restarted?)".to_owned())
            }
            UnitState::Failed { result, status } => Err(match (result.as_str(), status) {
                ("timeout", _) => format!(
                    "the job exceeded its time limit of {} seconds and was stopped",
                    self.ctx.config.files_job_timeout.as_secs()
                ),
                ("oom-kill", _) => "the job ran out of memory".to_owned(),
                (r, s) => format!("the worker failed ({r}, status {s:?})"),
            }),
        };
        self.conclude(job, outcome, &output)?;
        self.forget_unit(&unit, &state).await;
        Ok(true)
    }

    async fn unit_state(&self, unit: &str) -> Result<UnitState> {
        let mut cmd = CommandSpec::new(bin::SYSTEMCTL, self.timeout()).arg("show");
        for property in [
            "LoadState",
            "ActiveState",
            "SubState",
            "Result",
            "ExecMainStatus",
        ] {
            cmd = cmd.arg(format!("--property={property}"));
        }
        let out = self
            .ctx
            .sys
            .run_ok(cmd.arg("--").arg(format!("{unit}.service")))
            .await?;
        Ok(parse_unit_state(&out.stdout_lossy()))
    }

    async fn unit_output(&self, unit: &str) -> String {
        let journal = self
            .ctx
            .sys
            .run(
                CommandSpec::new(bin::JOURNALCTL, self.timeout())
                    .args(["--no-pager", "--output=cat", "--lines"])
                    .arg(OUTPUT_LINES)
                    .arg("--unit")
                    .arg(format!("{unit}.service")),
            )
            .await;
        journal.map_or_else(|_| String::new(), |out| out.stdout_lossy())
    }

    async fn forget_unit(&self, unit: &str, state: &UnitState) {
        let verb = match state {
            UnitState::Exited => "stop",
            UnitState::Failed { .. } => "reset-failed",
            UnitState::Running | UnitState::Gone => return,
        };
        let cmd = CommandSpec::new(bin::SYSTEMCTL, self.timeout())
            .args([verb, "--"])
            .arg(format!("{unit}.service"));
        if let Err(e) = self.ctx.sys.run(cmd).await {
            warn!(unit, error = %e, "could not clean up the file job's unit");
        }
    }

    /// Record the end of a job from the worker's result line (or, without
    /// one, from how its unit ended). The caller holds the mutation lock.
    fn conclude(
        &self,
        job: FileJobRecord,
        unit_outcome: std::result::Result<(), String>,
        output: &str,
    ) -> Result<FileJobRecord> {
        conclude_job(&self.ctx, job, unit_outcome, output)
    }
}

fn request_kind_str(op: &Op) -> &'static str {
    match op {
        Op::Copy { .. } => "copy",
        Op::Delete { .. } => "delete",
        Op::Compress { .. } => "compress",
        Op::Extract { .. } => "extract",
        _ => "other",
    }
}

fn check_size(data: &[u8]) -> Result<()> {
    if data.len() > WRITE_MAX {
        return Err(Error::invalid(
            "data",
            format!("at most {WRITE_MAX} bytes per request; use the upload calls for more"),
        ));
    }
    Ok(())
}

fn unexpected(reply: &Reply) -> Error {
    Error::Internal(format!(
        "the file worker gave an unexpected reply: {reply:?}"
    ))
}

/// What a finished job says it did, in one line.
fn summary_line(kind: FileJobKind, s: &JobSummary) -> String {
    let verb = match kind {
        FileJobKind::Copy => "copied",
        FileJobKind::Delete => "removed",
        FileJobKind::Compress => "archived",
        FileJobKind::Extract => "extracted",
    };
    let bytes = if s.bytes > 0 {
        format!(" ({} bytes)", s.bytes)
    } else {
        String::new()
    };
    let skipped = if s.skipped > 0 {
        format!(", {} left out (see output)", s.skipped)
    } else {
        String::new()
    };
    format!("{} entries {verb}{bytes}{skipped}", s.entries)
}

/// Record the end of a job. The caller holds the mutation lock.
fn conclude_job(
    ctx: &Ctx,
    mut job: FileJobRecord,
    unit_outcome: std::result::Result<(), String>,
    output: &str,
) -> Result<FileJobRecord> {
    let result = parse_job_result(output);
    let (state, message) = match (&result, unit_outcome) {
        (Some(r), _) => {
            job.entries = r.summary.entries;
            job.bytes = r.summary.bytes;
            job.skipped = r.summary.skipped;
            match &r.refusal {
                None => (JobState::Succeeded, summary_line(job.kind, &r.summary)),
                Some(refusal) => (JobState::Failed, refusal.message.clone()),
            }
        }
        (None, Ok(())) => (
            JobState::Failed,
            "the worker reported no result (see output)".to_owned(),
        ),
        (None, Err(reason)) => (JobState::Failed, reason),
    };
    job.state = state;
    job.message = message;
    job.output = without_result(output);
    job.finished_at_unix = now_unix();
    let id = FileJobId::parse(&job.id)?;
    fsutil::remove_if_exists(&ctx.store.file_job_request_path(&id))?;
    ctx.store.save_file_job(&job)?;
    if state == JobState::Succeeded {
        info!(job = %job.id, tenant = %job.tenant, message = %job.message, "file job finished");
    } else {
        warn!(job = %job.id, tenant = %job.tenant, reason = %job.message, "file job failed");
    }
    let mut finished = ctx.store.list_file_jobs()?;
    finished.retain(|j| j.tenant == job.tenant && j.state != JobState::Running);
    let surplus = finished.len().saturating_sub(JOBS_KEPT_PER_TENANT);
    for old in finished.iter().take(surplus) {
        ctx.store.delete_file_job(&FileJobId::parse(&old.id)?)?;
    }
    Ok(job)
}

/// Why a running file job is stopped by the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// The tenant was suspended.
    Suspended,
    /// The tenant is being deleted with everything it has (the cascade
    /// refuses to start while a file job runs; this is the backstop for a
    /// deletion resumed after a crash).
    Deleted,
}

impl StopReason {
    fn message(self) -> &'static str {
        match self {
            Self::Suspended => "stopped because the tenant was suspended",
            Self::Deleted => "stopped because the tenant is being deleted",
        }
    }
}

/// Suspension or deletion: a running file job of the tenant is stopped (its
/// unit and processes end; a file being written is left under its temporary
/// name, never as a partial target) and recorded as failed. The caller holds
/// the mutation lock.
pub async fn stop_tenant_jobs(ctx: &Ctx, tenant: &TenantRecord, why: StopReason) -> Result<()> {
    for job in ctx.store.list_file_jobs()? {
        if job.tenant != tenant.username || job.state != JobState::Running {
            continue;
        }
        let stop = CommandSpec::new(bin::SYSTEMCTL, ctx.config.command_timeout)
            .args(["stop", "--"])
            .arg(format!("{}.service", job.unit));
        ctx.sys.run(stop).await?;
        info!(job = %job.id, tenant = %tenant.username, reason = why.message(), "file job stopped");
        conclude_job(ctx, job, Err(why.message().to_owned()), "")?;
    }
    Ok(())
}

/// `DeleteTenant` waits for a running file job.
pub fn refuse_tenant_deletion(ctx: &Ctx, tenant: &Username) -> Result<()> {
    match ctx
        .store
        .list_file_jobs()?
        .into_iter()
        .find(|j| j.tenant == tenant.as_str() && j.state == JobState::Running)
    {
        Some(job) => Err(Error::FileJobRunning {
            tenant: tenant.to_string(),
            job: job.id,
        }),
        None => Ok(()),
    }
}

/// The tenant is being deleted: its file-job history and upload records go
/// (partial files are in the home, which goes or stays with the account).
pub fn forget_tenant(ctx: &Ctx, tenant: &Username) -> Result<()> {
    for job in ctx.store.list_file_jobs()? {
        if job.tenant == tenant.as_str() {
            ctx.store.delete_file_job(&FileJobId::parse(&job.id)?)?;
        }
    }
    for up in ctx.store.list_uploads()? {
        if up.tenant == tenant.as_str() {
            ctx.store.delete_upload(&UploadId::parse(&up.id)?)?;
        }
    }
    Ok(())
}

/// The job worker's entry point (`oxpanel-daemon files-job`): run the job
/// on standard input, print what it left out and, last, its result line.
pub fn serve_job(input: &mut impl std::io::Read, out: &mut impl std::io::Write) -> u8 {
    let (req, _) = match files_worker::read_request(input) {
        Ok(r) => r,
        Err(why) => {
            let _ = writeln!(out, "{why}");
            return 64;
        }
    };
    let mut notes = crate::files_tree::Notes::default();
    let outcome = run_job(&req, &mut notes);
    for line in &notes.lines {
        let _ = writeln!(out, "{}", line.replace(['\n', '\r'], " "));
    }
    let (summary, refusal) = match outcome {
        Ok(summary) => (summary, None),
        Err(r) => (
            JobSummary {
                skipped: notes.skipped,
                ..JobSummary::default()
            },
            Some(Refusal {
                fault: r.fault,
                message: r.message.replace(['\n', '\r'], " "),
            }),
        ),
    };
    let failed = refusal.is_some();
    let result = JobResult { summary, refusal };
    match serde_json::to_string(&result) {
        Ok(json) => {
            let _ = writeln!(out, "{JOB_RESULT} {json}");
        }
        Err(_) => return 70,
    }
    let _ = out.flush();
    u8::from(failed)
}

pub(crate) fn run_job(
    req: &Request,
    notes: &mut crate::files_tree::Notes,
) -> files_worker::Res<JobSummary> {
    let mut home = files_worker::Home::at(&req.home, req.limits, req.protected.clone())?;
    match &req.op {
        Op::Copy {
            sources,
            destination,
            overwrite,
        } => crate::files_tree::copy(&home, sources, destination, *overwrite, notes),
        Op::Delete { paths } => crate::files_tree::delete(&mut home, paths, notes),
        Op::Compress {
            directory,
            names,
            archive,
            format,
            overwrite,
        } => crate::files_archive::compress(
            &home, directory, names, archive, *format, *overwrite, notes,
        ),
        Op::Extract {
            archive,
            destination,
            overwrite,
        } => crate::files_archive::extract(&home, archive, destination, *overwrite, notes),
        _ => Err(Refusal::new(Fault::Invalid, "not a job")),
    }
}
