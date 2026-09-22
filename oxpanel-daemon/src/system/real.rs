//! [`System`] implementation backed by the real operating system.

use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use nix::fcntl::{open, OFlag};
use nix::sys::stat::{fchmod, fstat, Mode, SFlag};
use std::ffi::CString;

use nix::unistd::{fchown, getgrouplist, Gid, Group, Uid, User};
use tracing::{debug, warn};

use super::{CommandOutput, CommandSpec, OsUser, System};
use crate::error::{Error, Result};

/// Environment handed to every child process. Nothing from the daemon's own
/// environment leaks through.
const CHILD_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Debug, Default, Clone, Copy)]
pub struct RealSystem;

impl RealSystem {
    pub fn new() -> Self {
        Self
    }
}

fn os_user(u: User) -> OsUser {
    OsUser {
        name: u.name,
        uid: u.uid.as_raw(),
        gid: u.gid.as_raw(),
        home: u.dir,
        shell: u.shell,
    }
}

#[tonic::async_trait]
impl System for RealSystem {
    async fn run(&self, spec: CommandSpec) -> Result<CommandOutput> {
        let (program, argv) = spec.exec_plan();
        debug!(command = %spec.display(), "exec");
        let mut cmd = tokio::process::Command::new(program);
        cmd.args(&argv)
            .env_clear()
            .env("PATH", CHILD_PATH)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // If we stop waiting (timeout below), the child is killed rather than orphaned.
            .kill_on_drop(true);
        let child = cmd.spawn().map_err(|e| Error::io("spawn", program, e))?;
        let secs = spec.timeout.as_secs();
        match tokio::time::timeout(spec.timeout, child.wait_with_output()).await {
            Ok(Ok(out)) => {
                let result = CommandOutput {
                    program: spec.program,
                    code: out.status.code(),
                    stdout: out.stdout,
                    stderr: out.stderr,
                };
                if !result.success() {
                    warn!(command = %spec.display(), code = ?result.code, stderr = %result.stderr_lossy(), "command failed");
                }
                Ok(result)
            }
            Ok(Err(e)) => Err(Error::io("wait", program, e)),
            Err(_) => {
                warn!(command = %spec.display(), secs, "command timed out; killed");
                Err(Error::CommandTimeout {
                    program: spec.program.to_owned(),
                    secs,
                })
            }
        }
    }

    async fn user_by_name(&self, name: &str) -> Result<Option<OsUser>> {
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || User::from_name(&name))
            .await
            .map_err(|e| Error::Internal(format!("user lookup task: {e}")))?
            .map(|u| u.map(os_user))
            .map_err(|source| Error::Sys {
                op: "getpwnam",
                source,
            })
    }

    async fn user_by_uid(&self, uid: u32) -> Result<Option<OsUser>> {
        tokio::task::spawn_blocking(move || User::from_uid(Uid::from_raw(uid)))
            .await
            .map_err(|e| Error::Internal(format!("uid lookup task: {e}")))?
            .map(|u| u.map(os_user))
            .map_err(|source| Error::Sys {
                op: "getpwuid",
                source,
            })
    }

    async fn group_by_name(&self, name: &str) -> Result<Option<u32>> {
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || Group::from_name(&name))
            .await
            .map_err(|e| Error::Internal(format!("group lookup task: {e}")))?
            .map(|g| g.map(|g| g.gid.as_raw()))
            .map_err(|source| Error::Sys {
                op: "getgrnam",
                source,
            })
    }

    async fn groups_of(&self, name: &str, primary_gid: u32) -> Result<Vec<u32>> {
        let cname =
            CString::new(name).map_err(|_| Error::Internal("account name contains NUL".into()))?;
        tokio::task::spawn_blocking(move || getgrouplist(&cname, Gid::from_raw(primary_gid)))
            .await
            .map_err(|e| Error::Internal(format!("getgrouplist task: {e}")))?
            .map(|gids| gids.into_iter().map(Gid::as_raw).collect())
            .map_err(|source| Error::Sys {
                op: "getgrouplist",
                source,
            })
    }

    async fn ensure_private_dir(&self, path: &Path, uid: u32, gid: u32) -> Result<()> {
        let path: PathBuf = path.to_owned();
        tokio::task::spawn_blocking(move || ensure_private_dir_sync(&path, uid, gid))
            .await
            .map_err(|e| Error::Internal(format!("ensure_private_dir task: {e}")))?
    }

    async fn verify_owned_dir(&self, path: &Path, uid: u32) -> Result<()> {
        let path: PathBuf = path.to_owned();
        tokio::task::spawn_blocking(move || {
            let md = std::fs::symlink_metadata(&path).map_err(|e| Error::io("lstat", &path, e))?;
            if md.file_type().is_symlink() || !md.is_dir() {
                return Err(Error::invalid(
                    "document_root",
                    "must be a directory, not a symlink or file",
                ));
            }
            if md.uid() != uid {
                return Err(Error::invalid(
                    "document_root",
                    "must be owned by the tenant",
                ));
            }
            Ok(())
        })
        .await
        .map_err(|e| Error::Internal(format!("verify_owned_dir task: {e}")))?
    }
}

/// Open the directory without following a final symlink, then operate on the
/// descriptor so the checks and fixes apply to the same inode (no TOCTOU).
fn ensure_private_dir_sync(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let fd = open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| Error::Sys {
        op: "open(O_DIRECTORY|O_NOFOLLOW)",
        source,
    })?;
    let st = fstat(fd.as_fd()).map_err(|source| Error::Sys {
        op: "fstat",
        source,
    })?;
    if SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR {
        return Err(Error::Internal(format!(
            "{} is not a directory",
            path.display()
        )));
    }
    if st.st_uid != uid || st.st_gid != gid {
        warn!(path = %path.display(), have_uid = st.st_uid, have_gid = st.st_gid, uid, gid, "fixing owner");
        fchown(
            fd.as_fd(),
            Some(Uid::from_raw(uid)),
            Some(Gid::from_raw(gid)),
        )
        .map_err(|source| Error::Sys {
            op: "fchown",
            source,
        })?;
    }
    // Owner must have rwx; "other" and the setuid/setgid/sticky bits must be
    // clear. The *group* bits are deliberately left alone: once web access has
    // been granted through POSIX ACLs they hold the ACL mask (a tenant home
    // shows as 0710), and chmod'ing them to 0 would silently revoke the
    // web server's traverse right on every resume — found by make acceptance.
    let mode = st.st_mode & 0o7777;
    if mode & 0o7707 != 0o700 {
        let fixed = 0o700 | (mode & 0o070);
        warn!(path = %path.display(), mode = format_args!("{mode:o}"), fixed = format_args!("{fixed:o}"), "fixing mode");
        fchmod(fd.as_fd(), Mode::from_bits_truncate(fixed)).map_err(|source| Error::Sys {
            op: "fchmod",
            source,
        })?;
    }
    Ok(())
}
