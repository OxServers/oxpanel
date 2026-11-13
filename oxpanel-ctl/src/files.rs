//! `oxpanel-ctl files …`: a tenant's files through the engine's file
//! manager (everything runs as the tenant on the engine's side).

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;
use sha2::Digest;
use tonic::transport::Channel;

use oxpanel_proto::v1 as pb;
use oxpanel_proto::v1::ox_panel_engine_client::OxPanelEngineClient;

use crate::emit;

/// Exit status when a job waited for with `--wait` failed (as for backups).
const EXIT_JOB_FAILED: u8 = 5;
/// Bytes per upload chunk and per read (the engine's limits).
const CHUNK: usize = 192 * 1024;
const READ_CHUNK: u32 = 1 << 20;

#[derive(Subcommand, Debug)]
pub(crate) enum FilesCmd {
    /// List a directory (directories first): type, mode, size, modified, name.
    Ls {
        tenant: String,
        #[arg(default_value = "")]
        path: String,
        #[arg(long, default_value_t = 0)]
        offset: u32,
        /// Entries per page, 1-1000 (0 = 500).
        #[arg(long, default_value_t = 0)]
        limit: u32,
    },
    /// One entry.
    Stat { tenant: String, path: String },
    /// Print a file's content (read in chunks of 1 MiB).
    Cat { tenant: String, path: String },
    /// Download a file to a local path.
    Get {
        tenant: String,
        path: String,
        local: PathBuf,
    },
    /// Upload a local file (in chunks, checked with its SHA-256).
    Put {
        tenant: String,
        local: PathBuf,
        path: String,
        #[arg(long)]
        overwrite: bool,
    },
    /// Write standard input to a file in one request (at most 192 KiB), as
    /// an editor saves.
    Write {
        tenant: String,
        path: String,
        #[arg(long)]
        overwrite: bool,
    },
    Mkdir {
        tenant: String,
        path: String,
        #[arg(long)]
        parents: bool,
    },
    /// Rename or move within the home.
    Mv {
        tenant: String,
        from: String,
        to: String,
        #[arg(long)]
        overwrite: bool,
    },
    /// Change who may read an entry.
    Chmod {
        tenant: String,
        path: String,
        /// Only the tenant (0600/0700).
        #[arg(long, conflicts_with_all = ["web", "mode"])]
        private: bool,
        /// Also the web server (0644/0755).
        #[arg(long, conflicts_with = "mode")]
        web: bool,
        /// An octal mode, 0 to 0775.
        #[arg(long)]
        mode: Option<String>,
    },
    /// Entries whose name contains TEXT (case-insensitive), below PATH.
    Find {
        tenant: String,
        path: String,
        text: String,
        #[arg(long, default_value_t = 0)]
        max: u32,
    },
    /// Space used below a directory.
    Du {
        tenant: String,
        #[arg(default_value = "")]
        path: String,
    },
    /// Copy entries into a directory (a job).
    Cp {
        tenant: String,
        destination: String,
        #[arg(required = true)]
        sources: Vec<String>,
        #[arg(long)]
        overwrite: bool,
        #[arg(long)]
        wait: bool,
    },
    /// Delete entries, directories with their content (a job).
    Rm {
        tenant: String,
        #[arg(required = true)]
        paths: Vec<String>,
        #[arg(long)]
        wait: bool,
    },
    /// Compress entries of DIRECTORY into ARCHIVE (a job).
    Compress {
        tenant: String,
        directory: String,
        archive: String,
        #[arg(required = true)]
        names: Vec<String>,
        /// zip or tar-gz.
        #[arg(long, default_value = "zip")]
        format: String,
        #[arg(long)]
        overwrite: bool,
        #[arg(long)]
        wait: bool,
    },
    /// Extract a zip, tar or tar.gz archive into a directory (a job).
    Extract {
        tenant: String,
        archive: String,
        destination: String,
        #[arg(long)]
        overwrite: bool,
        #[arg(long)]
        wait: bool,
    },
    /// State of a file job.
    Job {
        tenant: String,
        job_id: String,
        #[arg(long)]
        wait: bool,
    },
    /// The tenant's file jobs, oldest first.
    Jobs { tenant: String },
}

fn type_name(raw: i32) -> &'static str {
    match pb::FileType::try_from(raw) {
        Ok(pb::FileType::File) => "file",
        Ok(pb::FileType::Directory) => "dir",
        Ok(pb::FileType::Symlink) => "link",
        Ok(pb::FileType::Fifo) => "fifo",
        Ok(pb::FileType::Socket) => "socket",
        Ok(pb::FileType::CharDevice) => "chardev",
        Ok(pb::FileType::BlockDevice) => "blockdev",
        Ok(pb::FileType::Unspecified) | Err(_) => "-",
    }
}

/// One line per entry; names are escaped so a newline in a name cannot
/// fake a second entry.
fn print_entry(e: &pb::FileEntry) {
    let name = if e.path.is_empty() { &e.name } else { &e.path };
    let link = if e.r#type == i32::from(pb::FileType::Symlink) {
        let state = match pb::SymlinkState::try_from(e.symlink_state) {
            Ok(pb::SymlinkState::Inside) => type_name(e.symlink_target_type),
            Ok(pb::SymlinkState::Outside) => "outside-home",
            Ok(pb::SymlinkState::Broken) => "broken",
            _ => "-",
        };
        format!(" -> {} ({state})", e.symlink_target.escape_debug())
    } else {
        String::new()
    };
    say!(
        "{} {:04o} {} {} {}{}{}{}",
        type_name(e.r#type),
        e.mode,
        e.size_bytes,
        e.modified.as_ref().map_or(0, |t| t.seconds),
        name.escape_debug(),
        link,
        if e.owned_by_tenant {
            ""
        } else {
            " (not owned by the tenant)"
        },
        if e.name_utf8 { "" } else { " (name not UTF-8)" },
    );
}

fn print_job(j: &pb::FileJob) {
    let kind = pb::FileJobKind::try_from(j.kind).map_or("unknown", |k| k.as_str_name());
    let state = pb::JobState::try_from(j.state).map_or("unknown", |s| s.as_str_name());
    say!(
        "job={} kind={} tenant={} state={} entries={} bytes={} skipped={} started_at={} finished_at={} request={} message={}",
        j.id,
        kind,
        j.tenant,
        state,
        j.entries,
        j.bytes,
        j.skipped,
        j.started_at.as_ref().map_or(0, |t| t.seconds),
        j.finished_at.as_ref().map_or(0, |t| t.seconds),
        j.request,
        if j.message.is_empty() { "-" } else { &j.message },
    );
}

async fn follow(
    c: &mut OxPanelEngineClient<Channel>,
    mut job: pb::FileJob,
    wait: bool,
) -> Result<ExitCode, tonic::Status> {
    let running = |j: &pb::FileJob| j.state == i32::from(pb::JobState::Running);
    while wait && running(&job) {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        job = c
            .get_file_job(pb::GetFileJobRequest {
                tenant: job.tenant.clone(),
                job_id: job.id.clone(),
            })
            .await?
            .into_inner();
    }
    for line in job.output.lines() {
        say!("{line}");
    }
    print_job(&job);
    if job.state == i32::from(pb::JobState::Failed) {
        return Ok(ExitCode::from(EXIT_JOB_FAILED));
    }
    Ok(ExitCode::SUCCESS)
}

fn local_error(what: &str, e: &std::io::Error) -> tonic::Status {
    tonic::Status::invalid_argument(format!("{what}: {e}"))
}

async fn download(
    c: &mut OxPanelEngineClient<Channel>,
    tenant: &str,
    path: &str,
    out: &mut dyn Write,
) -> Result<(), tonic::Status> {
    let mut offset = 0u64;
    let mut first: Option<(u64, i64)> = None;
    loop {
        let r = c
            .read_file(pb::ReadFileRequest {
                tenant: tenant.to_owned(),
                path: path.to_owned(),
                offset,
                length: READ_CHUNK,
            })
            .await?
            .into_inner();
        let seen = (r.size_bytes, r.modified.as_ref().map_or(0, |t| t.seconds));
        if *first.get_or_insert(seen) != seen {
            return Err(tonic::Status::aborted(
                "the file changed during the download",
            ));
        }
        out.write_all(&r.data)
            .map_err(|e| local_error("writing", &e))?;
        offset += r.data.len() as u64;
        if r.eof || r.data.is_empty() {
            return Ok(());
        }
    }
}

async fn upload(
    c: &mut OxPanelEngineClient<Channel>,
    tenant: String,
    local: PathBuf,
    path: String,
    overwrite: bool,
) -> Result<(), tonic::Status> {
    let mut file = std::fs::File::open(&local).map_err(|e| local_error("opening", &e))?;
    let started = c
        .start_upload(pb::StartUploadRequest {
            tenant: tenant.clone(),
            path,
            overwrite,
        })
        .await?
        .into_inner();
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut offset = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| local_error("reading", &e))?;
        if n == 0 {
            break;
        }
        let data = buf.get(..n).unwrap_or_default().to_vec();
        hasher.update(&data);
        let sent = c
            .upload_chunk(pb::UploadChunkRequest {
                tenant: tenant.clone(),
                upload_id: started.upload_id.clone(),
                offset,
                data,
            })
            .await;
        if let Err(e) = sent {
            let _ = c
                .abort_upload(pb::AbortUploadRequest {
                    tenant: tenant.clone(),
                    upload_id: started.upload_id.clone(),
                })
                .await;
            return Err(e);
        }
        offset += n as u64;
    }
    let entry = c
        .finish_upload(pb::FinishUploadRequest {
            tenant,
            upload_id: started.upload_id,
            size_bytes: offset,
            sha256: format!("{:x}", hasher.finalize()),
        })
        .await?
        .into_inner();
    print_entry(&entry);
    Ok(())
}

fn access(
    private: bool,
    web: bool,
    mode: Option<&str>,
) -> Result<(pb::FileAccess, u32), tonic::Status> {
    match (private, web, mode) {
        (true, _, _) => Ok((pb::FileAccess::Private, 0)),
        (_, true, _) => Ok((pb::FileAccess::WebReadable, 0)),
        (_, _, Some(m)) => u32::from_str_radix(m.trim_start_matches("0o"), 8)
            .map(|bits| (pb::FileAccess::Mode, bits))
            .map_err(|_| tonic::Status::invalid_argument("--mode must be octal, e.g. 0640")),
        _ => Err(tonic::Status::invalid_argument(
            "give --private, --web or --mode",
        )),
    }
}

fn format_of(raw: &str) -> Result<pb::ArchiveFormat, tonic::Status> {
    match raw {
        "zip" => Ok(pb::ArchiveFormat::Zip),
        "tar-gz" | "tgz" | "tar.gz" => Ok(pb::ArchiveFormat::TarGz),
        _ => Err(tonic::Status::invalid_argument(
            "--format must be zip or tar-gz",
        )),
    }
}

pub(crate) async fn run(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: FilesCmd,
) -> Result<ExitCode, tonic::Status> {
    match cmd {
        FilesCmd::Ls {
            tenant,
            path,
            offset,
            limit,
        } => {
            let r = c
                .list_files(pb::ListFilesRequest {
                    tenant,
                    path,
                    offset,
                    limit,
                })
                .await?
                .into_inner();
            r.entries.iter().for_each(print_entry);
            say!("total={} truncated={}", r.total, r.truncated);
        }
        FilesCmd::Stat { tenant, path } => {
            print_entry(
                &c.stat_file(pb::StatFileRequest { tenant, path })
                    .await?
                    .into_inner(),
            );
        }
        FilesCmd::Cat { tenant, path } => {
            download(c, &tenant, &path, &mut std::io::stdout().lock()).await?;
        }
        FilesCmd::Get {
            tenant,
            path,
            local,
        } => {
            let mut out = std::fs::File::create(&local).map_err(|e| local_error("creating", &e))?;
            download(c, &tenant, &path, &mut out).await?;
        }
        FilesCmd::Put {
            tenant,
            local,
            path,
            overwrite,
        } => upload(c, tenant, local, path, overwrite).await?,
        cmd @ (FilesCmd::Write { .. }
        | FilesCmd::Mkdir { .. }
        | FilesCmd::Mv { .. }
        | FilesCmd::Chmod { .. }) => return change(c, cmd).await,
        cmd @ (FilesCmd::Find { .. } | FilesCmd::Du { .. } | FilesCmd::Jobs { .. }) => {
            return walk(c, cmd).await
        }
        cmd => return job(c, cmd).await,
    }
    Ok(ExitCode::SUCCESS)
}

/// The commands that change one entry and print it.
async fn change(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: FilesCmd,
) -> Result<ExitCode, tonic::Status> {
    let entry = match cmd {
        FilesCmd::Write {
            tenant,
            path,
            overwrite,
        } => {
            let mut data = Vec::new();
            std::io::stdin()
                .read_to_end(&mut data)
                .map_err(|e| local_error("reading standard input", &e))?;
            c.write_file(pb::WriteFileRequest {
                tenant,
                path,
                data,
                overwrite,
            })
            .await?
        }
        FilesCmd::Mkdir {
            tenant,
            path,
            parents,
        } => {
            c.make_directory(pb::MakeDirectoryRequest {
                tenant,
                path,
                parents,
            })
            .await?
        }
        FilesCmd::Mv {
            tenant,
            from,
            to,
            overwrite,
        } => {
            c.move_file(pb::MoveFileRequest {
                tenant,
                from,
                to,
                overwrite,
            })
            .await?
        }
        FilesCmd::Chmod {
            tenant,
            path,
            private,
            web,
            mode,
        } => {
            let (access, mode) = access(private, web, mode.as_deref())?;
            c.set_file_access(pb::SetFileAccessRequest {
                tenant,
                path,
                access: access.into(),
                mode,
            })
            .await?
        }
        _ => return Err(tonic::Status::internal("not a change")),
    };
    print_entry(&entry.into_inner());
    Ok(ExitCode::SUCCESS)
}

/// Searches, sizes and job lists.
async fn walk(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: FilesCmd,
) -> Result<ExitCode, tonic::Status> {
    match cmd {
        FilesCmd::Find {
            tenant,
            path,
            text,
            max,
        } => {
            let r = c
                .search_files(pb::SearchFilesRequest {
                    tenant,
                    path,
                    name_contains: text,
                    max_results: max,
                })
                .await?
                .into_inner();
            r.matches.iter().for_each(print_entry);
            say!("scanned={} truncated={}", r.scanned, r.truncated);
        }
        FilesCmd::Du { tenant, path } => {
            let r = c
                .get_directory_size(pb::GetDirectorySizeRequest { tenant, path })
                .await?
                .into_inner();
            say!(
                "allocated={} apparent={} files={} directories={} truncated={}",
                r.allocated_bytes,
                r.apparent_bytes,
                r.files,
                r.directories,
                r.truncated
            );
        }
        FilesCmd::Jobs { tenant } => {
            for j in &c
                .list_file_jobs(pb::ListFileJobsRequest { tenant })
                .await?
                .into_inner()
                .jobs
            {
                print_job(j);
            }
        }
        _ => return Err(tonic::Status::internal("not a walk")),
    }
    Ok(ExitCode::SUCCESS)
}

/// The commands that start (or look at) a job.
async fn job(
    c: &mut OxPanelEngineClient<Channel>,
    cmd: FilesCmd,
) -> Result<ExitCode, tonic::Status> {
    let (job, wait) = match cmd {
        FilesCmd::Job {
            tenant,
            job_id,
            wait,
        } => (
            c.get_file_job(pb::GetFileJobRequest { tenant, job_id })
                .await?,
            wait,
        ),
        FilesCmd::Cp {
            tenant,
            destination,
            sources,
            overwrite,
            wait,
        } => (
            c.copy_files(pb::CopyFilesRequest {
                tenant,
                sources,
                destination,
                overwrite,
            })
            .await?,
            wait,
        ),
        FilesCmd::Rm {
            tenant,
            paths,
            wait,
        } => (
            c.delete_files(pb::DeleteFilesRequest { tenant, paths })
                .await?,
            wait,
        ),
        FilesCmd::Compress {
            tenant,
            directory,
            archive,
            names,
            format,
            overwrite,
            wait,
        } => (
            c.compress_files(pb::CompressFilesRequest {
                tenant,
                directory,
                names,
                archive,
                format: format_of(&format)?.into(),
                overwrite,
            })
            .await?,
            wait,
        ),
        FilesCmd::Extract {
            tenant,
            archive,
            destination,
            overwrite,
            wait,
        } => (
            c.extract_archive(pb::ExtractArchiveRequest {
                tenant,
                archive,
                destination,
                overwrite,
            })
            .await?,
            wait,
        ),
        _ => return Err(tonic::Status::internal("not a job")),
    };
    follow(c, job.into_inner(), wait).await
}
