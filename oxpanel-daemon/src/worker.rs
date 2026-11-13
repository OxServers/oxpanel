//! The out-of-process half of a backup or restore job.
//!
//! `oxpanel-daemon worker backup|restore …` is what a job's transient systemd
//! unit runs (see [`crate::backup`]). It exists so that the two sides of an
//! archive never meet in one process:
//!
//! - the **archiver** (`tar`, with `gzip`) runs *as the tenant* through
//!   `setpriv`, so it can read, or on restore write, exactly what the tenant
//!   itself could. A symlink to `/etc/shadow` is stored as a symlink; a file
//!   the tenant may not read is not read for it;
//! - the **archive file** lives in a root-only directory and is opened only
//!   by this worker. On backup the archiver gets a pipe, never a descriptor
//!   of the file, so nothing running as the tenant can write, grow or reopen
//!   an archive; on restore it gets the archive read-only on standard input.
//!
//! The worker copies the stream, counts it against the size the daemon
//! allowed, and computes the SHA-256 on the way, so a backup is checksummed
//! without being read twice. Before a restore it verifies size and checksum
//! and only then starts the archiver.
//!
//! The unit this runs in gives the worker no `CAP_DAC_OVERRIDE`: although it
//! is root, it cannot read a tenant's files itself.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::fsutil;
use crate::records::OnExisting;
use crate::system::real::spawn_streaming;
use crate::system::{bin, CommandSpec};
use crate::validate::RelPath;

/// First argument that selects worker mode.
pub const SUBCOMMAND: &str = "worker";

/// Exit statuses the daemon turns into a job message.
pub const EXIT_USAGE: u8 = 64;
/// The archive does not have the recorded size or checksum.
pub const EXIT_INTEGRITY: u8 = 10;
/// The archive would have exceeded the size the daemon allowed.
pub const EXIT_TOO_LARGE: u8 = 11;
/// `tar` reported a failure.
pub const EXIT_ARCHIVER: u8 = 12;
/// Anything else (I/O on the archive, spawning).
pub const EXIT_INTERNAL: u8 = 13;

const RESULT_MODE: u32 = 0o600;
const ARCHIVE_MODE: u32 = 0o600;
const BUFFER: usize = 128 * 1024;

/// Member kind of the tenant's home archive.
pub const KIND_HOME: &str = "home";

/// Prefix of the line with which a restore worker reports its counts (the
/// daemon reads it back from the journal). `tar`'s own lines start with
/// its program name, so a file name in the archive cannot forge it.
pub const RESTORE_RESULT: &str = "oxpanel-restore-result";

/// What a worker reports about the member it wrote. Its presence next to the
/// member is the worker's statement that the member is complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberResult {
    pub kind: String,
    pub size_bytes: u64,
    pub sha256: String,
}

/// `<member>.result.json`
pub fn result_path(member: &Path) -> PathBuf {
    let mut name = member.as_os_str().to_owned();
    name.push(".result.json");
    PathBuf::from(name)
}

/// The result file of `member`, if its worker finished.
pub fn read_result(member: &Path) -> Result<Option<MemberResult>> {
    let path = result_path(member);
    let Some(bytes) = fsutil::read_optional(&path)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| Error::CorruptRecord {
            path,
            reason: e.to_string(),
        })
}

fn write_result(member: &Path, result: &MemberResult) -> Result<()> {
    let bytes = serde_json::to_vec(result)
        .map_err(|e| Error::Internal(format!("serialise member result: {e}")))?;
    fsutil::write_atomic(&result_path(member), &bytes, RESULT_MODE)?;
    Ok(())
}

/// What one worker invocation does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Task {
    /// Archive `home` as `uid:gid` into `output`, at most `max_bytes` long,
    /// leaving out the applications' virtualenvs `venvs` (relative to the
    /// home) besides what [`tar_create`] always leaves out.
    Backup {
        uid: u32,
        gid: u32,
        home: PathBuf,
        output: PathBuf,
        max_bytes: u64,
        venvs: Vec<String>,
    },
    /// Verify `input` against `sha256` and `size`, then extract it into
    /// `home` as `uid:gid`.
    Restore {
        uid: u32,
        gid: u32,
        home: PathBuf,
        input: PathBuf,
        sha256: String,
        size: u64,
        on_existing: OnExisting,
    },
}

impl Task {
    /// The arguments that make a worker perform this task; the inverse of
    /// [`Task::parse`].
    pub fn to_args(&self) -> Vec<OsString> {
        let mut out: Vec<OsString> = vec![SUBCOMMAND.into()];
        let mut pair = |flag: &str, value: OsString| {
            out.push(flag.into());
            out.push(value);
        };
        match self {
            Self::Backup {
                uid,
                gid,
                home,
                output,
                max_bytes,
                venvs,
            } => {
                pair("backup", uid.to_string().into());
                pair("--gid", gid.to_string().into());
                pair("--home", home.clone().into());
                pair("--output", output.clone().into());
                pair("--max-bytes", max_bytes.to_string().into());
                let venvs = if venvs.is_empty() {
                    "-".to_owned()
                } else {
                    venvs.join(",")
                };
                pair("--venvs", venvs.into());
            }
            Self::Restore {
                uid,
                gid,
                home,
                input,
                sha256,
                size,
                on_existing,
            } => {
                pair("restore", uid.to_string().into());
                pair("--gid", gid.to_string().into());
                pair("--home", home.clone().into());
                pair("--input", input.clone().into());
                pair("--sha256", sha256.clone().into());
                pair("--size", size.to_string().into());
                pair("--existing", on_existing.as_str().into());
            }
        }
        out
    }

    /// Parse the arguments after the program name: `worker backup <uid>
    /// --gid <gid> --home <dir> --output <file> --max-bytes <n>` or `worker
    /// restore <uid> --gid <gid> --home <dir> --input <file> --sha256 <hex>
    /// --size <n>`. Strict: unknown, missing or repeated arguments are errors.
    pub fn parse(args: &[String]) -> Result<Self> {
        let bad = |why: String| Error::invalid("worker", why);
        let [sub, mode, uid, rest @ ..] = args else {
            return Err(bad("expected: worker backup|restore <uid> …".into()));
        };
        if sub != SUBCOMMAND {
            return Err(bad(format!("unknown subcommand '{sub}'")));
        }
        let mut flags = std::collections::BTreeMap::new();
        for pair in rest.chunks(2) {
            let [flag, value] = pair else {
                return Err(bad("an argument has no value".into()));
            };
            if flags.insert(flag.as_str(), value.as_str()).is_some() {
                return Err(bad(format!("'{flag}' is given twice")));
            }
        }
        let mut take = |flag: &str| {
            flags
                .remove(flag)
                .ok_or_else(|| bad(format!("'{flag}' is missing")))
        };
        let number = |flag: &str, v: &str| {
            v.parse::<u64>()
                .map_err(|_| bad(format!("'{flag}' must be a number")))
        };
        let id = |flag: &str, v: &str| match v.parse::<u32>() {
            // Never root: the archiver must not run with the worker's identity.
            Ok(n) if n != 0 => Ok(n),
            _ => Err(bad(format!("'{flag}' must be a non-root numeric id"))),
        };
        let uid = id("uid", uid)?;
        let gid = id("--gid", take("--gid")?)?;
        let home = absolute(take("--home")?, "--home")?;
        let task = match mode.as_str() {
            "backup" => Self::Backup {
                uid,
                gid,
                home,
                output: absolute(take("--output")?, "--output")?,
                max_bytes: number("--max-bytes", take("--max-bytes")?)?,
                venvs: match take("--venvs")? {
                    "-" => Vec::new(),
                    list => list
                        .split(',')
                        .map(|v| RelPath::parse_field(v, "--venvs").map(|p| p.as_str().to_owned()))
                        .collect::<Result<_>>()?,
                },
            },
            "restore" => {
                let sha256 = take("--sha256")?;
                if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(bad("'--sha256' must be 64 hexadecimal digits".into()));
                }
                Self::Restore {
                    uid,
                    gid,
                    home,
                    input: absolute(take("--input")?, "--input")?,
                    sha256: sha256.to_ascii_lowercase(),
                    size: number("--size", take("--size")?)?,
                    on_existing: match take("--existing")? {
                        "overwrite" => OnExisting::Overwrite,
                        "keep" => OnExisting::Keep,
                        _ => return Err(bad("'--existing' must be overwrite or keep".into())),
                    },
                }
            }
            other => return Err(bad(format!("unknown mode '{other}'"))),
        };
        if let Some(extra) = flags.keys().next() {
            return Err(bad(format!("unknown argument '{extra}'")));
        }
        Ok(task)
    }
}

fn absolute(raw: &str, flag: &str) -> Result<PathBuf> {
    let path = PathBuf::from(raw);
    let plain = path.components().all(|c| {
        matches!(
            c,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        )
    });
    if !path.is_absolute() || !plain {
        return Err(Error::invalid(
            "worker",
            format!("'{flag}' must be an absolute path without '.' or '..'"),
        ));
    }
    Ok(path)
}

/// `tar` reading the home as the tenant and writing the archive to standard
/// output. Each option is there for a reason:
///
/// - nothing is dereferenced: symlinks are stored as symlinks, so a link to
///   `/etc/shadow` or into another home adds a link, never the target;
/// - `--hard-dereference`: every name is stored as a file of its own, so an
///   archive made here contains no hard-link members at all;
/// - `--one-file-system`: a mount point inside the home is not descended into;
/// - `--sparse`: a sparse multi-terabyte file costs what it actually occupies;
/// - `--ignore-failed-read`: a file the tenant itself cannot read (it belongs
///   to someone else, or has mode 000) is reported and skipped instead of
///   failing the whole backup. Nobody reads it *for* the tenant;
/// - `--mode=u-s,g-s`: set-uid and set-gid bits are not recorded;
/// - left out (owner decision: large, and rebuilt after a restore): `./.cache`
///   and `./.npm` (download caches), every `node_modules` at any depth, every
///   directory that contains a `pyvenv.cfg` (a Python virtualenv, recognised
///   by what it is — `--exclude-tag-all` drops the directory with its tag),
///   and the `.venv` of each Python application by path (`venvs`), even if
///   its `pyvenv.cfg` is gone. A tenant who plants a `pyvenv.cfg` can only
///   make its own directory be left out; the daemon lists every such
///   directory in the manifest;
/// - FIFOs and device nodes are recorded as such without being opened;
///   sockets are skipped.
pub fn tar_create(uid: u32, gid: u32, home: &Path, venvs: &[String]) -> CommandSpec {
    let spec = CommandSpec::new(bin::TAR, Duration::ZERO)
        .args(["--create", "--file=-", "--format=gnu"])
        .arg(format!("--use-compress-program={}", bin::GZIP))
        .arg("--directory")
        .arg(home)
        .args([
            "--one-file-system",
            "--sparse",
            "--numeric-owner",
            "--hard-dereference",
            "--ignore-failed-read",
            "--mode=u-s,g-s",
            "--no-acls",
            "--no-selinux",
            "--no-xattrs",
            "--anchored",
            "--exclude=./.cache",
            "--exclude=./.npm",
            "--no-anchored",
            "--exclude=node_modules",
            "--exclude-tag-all=pyvenv.cfg",
            "--anchored",
        ]);
    venvs
        .iter()
        .fold(spec, |spec, v| spec.arg(format!("--exclude=./{v}")))
        .args(["--", "."])
        .as_user(uid, gid)
}

/// `tar` extracting the archive on standard input into the home, as the
/// tenant. What makes a hostile archive harmless:
///
/// - it runs with the tenant's uid and gid and no capabilities, so every file
///   it creates belongs to the tenant (`--no-same-owner` says so explicitly),
///   device nodes cannot be created, and it can write nowhere the tenant
///   could not;
/// - GNU tar strips a leading `/` from member names and hard-link targets,
///   skips members whose name contains `..`, replaces an existing file or
///   symlink instead of writing through it, and does not follow a symlink
///   when it resolves the directories of a member;
/// - the unit's sandbox makes everything but the tenant's home read-only and
///   refuses set-uid and set-gid bits (`RestrictSUIDSGID`).
///
/// `--same-permissions`: modes are restored as archived instead of being
/// narrowed by the umask — the web server reads a site through its "other"
/// permission bits.
///
/// Existing files: with [`OnExisting::Overwrite`] tar's default applies (an
/// existing file or symlink is unlinked and replaced, never written
/// through); with [`OnExisting::Keep`], `--skip-old-files` leaves every
/// existing entry — file, symlink, directory — as it is. `--verbose` names
/// every member on standard output and `--warning=existing-file` reports
/// each skipped one, which is how the worker counts them.
pub fn tar_extract(uid: u32, gid: u32, home: &Path, on_existing: OnExisting) -> CommandSpec {
    let spec = CommandSpec::new(bin::TAR, Duration::ZERO)
        .args(["--extract", "--file=-"])
        .arg(format!("--use-compress-program={}", bin::GZIP))
        .arg("--directory")
        .arg(home)
        .args([
            "--no-same-owner",
            "--same-permissions",
            "--no-acls",
            "--no-selinux",
            "--no-xattrs",
            "--verbose",
            "--warning=existing-file",
        ]);
    match on_existing {
        OnExisting::Overwrite => spec,
        OnExisting::Keep => spec.arg("--skip-old-files"),
    }
    .as_user(uid, gid)
}

/// Why a stream could not be stored.
#[derive(Debug)]
enum CopyError {
    TooLarge,
    Io(std::io::Error),
}

/// Copy `from` to `to` until end of file, refusing more than `max_bytes`.
/// Returns the length and the SHA-256 of what was copied.
fn copy_hashed(
    mut from: impl Read,
    mut to: impl Write,
    max_bytes: u64,
) -> std::result::Result<(u64, String), CopyError> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; BUFFER];
    let mut total: u64 = 0;
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(CopyError::Io(e)),
        };
        let chunk = buf.get(..n).unwrap_or_default();
        total = total.saturating_add(n as u64);
        if total > max_bytes {
            return Err(CopyError::TooLarge);
        }
        hasher.update(chunk);
        to.write_all(chunk).map_err(CopyError::Io)?;
    }
    Ok((total, format!("{:x}", hasher.finalize())))
}

/// A failed task: the exit status and what to log.
#[derive(Debug)]
pub struct Failure {
    pub code: u8,
    pub message: String,
}

impl Failure {
    fn new(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn internal(e: impl std::fmt::Display) -> Self {
        Self::new(EXIT_INTERNAL, e.to_string())
    }
}

/// Run one task to completion.
pub fn run(task: &Task) -> std::result::Result<(), Failure> {
    match task {
        Task::Backup {
            uid,
            gid,
            home,
            output,
            max_bytes,
            venvs,
        } => backup(&tar_create(*uid, *gid, home, venvs), output, *max_bytes),
        Task::Restore {
            uid,
            gid,
            home,
            input,
            sha256,
            size,
            on_existing,
        } => restore(
            &tar_extract(*uid, *gid, home, *on_existing),
            input,
            sha256,
            *size,
        ),
    }
}

fn backup(tar: &CommandSpec, output: &Path, max_bytes: u64) -> std::result::Result<(), Failure> {
    // create_new: a member is written once; an existing file is not ours to reuse.
    let mut archive = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(ARCHIVE_MODE)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(output)
        .map_err(|e| Failure::internal(Error::io("create", output, e)))?;
    let discard = |why: Failure| {
        let _ = std::fs::remove_file(output);
        why
    };
    let mut child = spawn_streaming(tar, Stdio::null(), Stdio::piped(), Stdio::inherit())
        .map_err(|e| discard(Failure::internal(e)))?;
    let copied = match child.stdout.take() {
        // The pipe is closed when this returns, so an archiver that is still
        // writing (size limit reached) stops instead of blocking forever.
        Some(stream) => copy_hashed(stream, &mut archive, max_bytes),
        None => Err(CopyError::Io(std::io::Error::other("no pipe"))),
    };
    let status = child
        .wait()
        .map_err(|e| discard(Failure::internal(Error::io("wait", bin::TAR, e))))?;
    let (size_bytes, sha256) = match copied {
        Ok(done) => done,
        Err(CopyError::TooLarge) => {
            return Err(discard(Failure::new(
                EXIT_TOO_LARGE,
                format!("the archive would exceed the {max_bytes} bytes available for it"),
            )))
        }
        Err(CopyError::Io(e)) => {
            return Err(discard(Failure::internal(Error::io("write", output, e))))
        }
    };
    // 1 = "some files changed while they were read": normal for a live site.
    if !matches!(status.code(), Some(0 | 1)) {
        return Err(discard(Failure::new(
            EXIT_ARCHIVER,
            format!("tar failed ({status})"),
        )));
    }
    archive
        .sync_all()
        .map_err(|e| discard(Failure::internal(Error::io("fsync", output, e))))?;
    write_result(
        output,
        &MemberResult {
            kind: KIND_HOME.to_owned(),
            size_bytes,
            sha256,
        },
    )
    .map_err(|e| discard(Failure::internal(e)))
}

fn restore(
    tar: &CommandSpec,
    input: &Path,
    sha256: &str,
    size: u64,
) -> std::result::Result<(), Failure> {
    let mut archive = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(input)
        .map_err(|e| Failure::new(EXIT_INTEGRITY, Error::io("open", input, e).to_string()))?;
    // Verified in full before the archiver sees a single byte.
    let (found_size, found_sha256) = copy_hashed(&mut archive, std::io::sink(), u64::MAX)
        .map_err(|e| Failure::internal(format!("read {}: {e:?}", input.display())))?;
    if found_size != size || found_sha256 != sha256 {
        return Err(Failure::new(
            EXIT_INTEGRITY,
            format!(
                "the archive is damaged: expected {size} bytes with SHA-256 {sha256}, found {found_size} bytes with {found_sha256}"
            ),
        ));
    }
    archive
        .seek(SeekFrom::Start(0))
        .map_err(|e| Failure::internal(Error::io("seek", input, e)))?;
    let mut child = spawn_streaming(tar, Stdio::from(archive), Stdio::piped(), Stdio::piped())
        .map_err(Failure::internal)?;
    // Standard output names every member; it is only counted (in a thread,
    // so neither pipe can fill up and stall tar). Standard error is passed
    // on to the journal, and its "skipping existing file" lines counted.
    let members = child.stdout.take().map(|out| {
        std::thread::spawn(move || {
            std::io::BufReader::new(out)
                .split(b'\n')
                .map_while(std::result::Result::ok)
                .count() as u64
        })
    });
    let mut skipped: u64 = 0;
    if let Some(err) = child.stderr.take() {
        let mut journal = std::io::stderr().lock();
        for line in std::io::BufReader::new(err)
            .split(b'\n')
            .map_while(std::result::Result::ok)
        {
            if line.ends_with(b": skipping existing file") {
                skipped += 1;
            }
            let _ = journal.write_all(&line);
            let _ = journal.write_all(b"\n");
        }
    }
    let members = members.and_then(|t| t.join().ok()).unwrap_or(0);
    let status = child
        .wait()
        .map_err(|e| Failure::internal(Error::io("wait", bin::TAR, e)))?;
    // The last line of the worker's output, whatever the outcome.
    let _ = writeln!(
        std::io::stderr(),
        "{RESTORE_RESULT} restored={} skipped={skipped}",
        members.saturating_sub(skipped)
    );
    if status.success() {
        Ok(())
    } else {
        Err(Failure::new(
            EXIT_ARCHIVER,
            format!("tar could not restore every member ({status})"),
        ))
    }
}

/// The counts a restore worker reported, from its output: the last line
/// that is exactly `oxpanel-restore-result restored=<n> skipped=<n>`.
pub fn parse_restore_result(output: &str) -> Option<(u64, u64)> {
    output.lines().rev().find_map(|line| {
        let rest = line.trim_end().strip_prefix(RESTORE_RESULT)?;
        let (restored, skipped) = rest.strip_prefix(" restored=")?.split_once(" skipped=")?;
        Some((restored.parse().ok()?, skipped.parse().ok()?))
    })
}

/// What the in-memory fake OS leaves behind for a backup worker: a small
/// placeholder archive with a truthful result file.
pub fn write_fake_archive(output: &Path) -> Result<()> {
    const CONTENT: &[u8] = b"oxpanel dry-run archive\n";
    let mut file = File::create(output).map_err(|e| Error::io("create", output, e))?;
    let (size_bytes, sha256) = copy_hashed(CONTENT, &mut file, u64::MAX)
        .map_err(|e| Error::Internal(format!("fake archive: {e:?}")))?;
    write_result(
        output,
        &MemberResult {
            kind: KIND_HOME.to_owned(),
            size_bytes,
            sha256,
        },
    )
}

/// SHA-256 and length of a file (the small, daemon-written members).
pub fn hash_file(path: &Path) -> Result<(u64, String)> {
    let file = File::open(path).map_err(|e| Error::io("open", path, e))?;
    copy_hashed(file, std::io::sink(), u64::MAX)
        .map_err(|e| Error::Internal(format!("read {}: {e:?}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn copy_hashes_counts_and_enforces_the_limit() {
        let mut out = Vec::new();
        let (n, sha) = copy_hashed(&b"abc"[..], &mut out, 3).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!((n, out.as_slice()), (3, &b"abc"[..]));
        assert_eq!(
            sha,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let (n, sha) =
            copy_hashed(&b""[..], std::io::sink(), 0).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(n, 0);
        assert_eq!(
            sha,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let big = vec![7u8; BUFFER * 2 + 5];
        let mut out = Vec::new();
        assert!(matches!(
            copy_hashed(big.as_slice(), &mut out, (BUFFER * 2) as u64),
            Err(CopyError::TooLarge)
        ));
        assert!(
            out.len() <= BUFFER * 2,
            "nothing beyond the limit is written"
        );
        assert!(copy_hashed(big.as_slice(), std::io::sink(), big.len() as u64).is_ok());
    }

    #[test]
    fn create_reads_as_the_tenant_and_follows_nothing() {
        let venvs = vec!["apps/api/.venv".to_owned()];
        let spec = tar_create(20000, 20001, Path::new("/home/alice"), &venvs);
        assert_eq!(spec.program, bin::TAR);
        assert_eq!(
            spec.run_as,
            Some(crate::system::RunAs {
                uid: 20000,
                gid: 20001
            })
        );
        assert_eq!(
            strings(&spec.args),
            vec![
                "--create",
                "--file=-",
                "--format=gnu",
                "--use-compress-program=/usr/bin/gzip",
                "--directory",
                "/home/alice",
                "--one-file-system",
                "--sparse",
                "--numeric-owner",
                "--hard-dereference",
                "--ignore-failed-read",
                "--mode=u-s,g-s",
                "--no-acls",
                "--no-selinux",
                "--no-xattrs",
                "--anchored",
                "--exclude=./.cache",
                "--exclude=./.npm",
                "--no-anchored",
                "--exclude=node_modules",
                "--exclude-tag-all=pyvenv.cfg",
                "--anchored",
                "--exclude=./apps/api/.venv",
                "--",
                ".",
            ]
        );
        let (program, argv) = spec.exec_plan();
        assert_eq!(program, bin::SETPRIV, "never executed as root");
        let argv = strings(&argv);
        assert!(argv.starts_with(&["--reuid=20000".to_owned(), "--regid=20001".to_owned()]));
        for forbidden in ["--dereference", "-h", "-L", "--absolute-names", "-P"] {
            assert!(!argv.iter().any(|a| a == forbidden), "{forbidden}");
        }
    }

    #[test]
    fn extract_writes_as_the_tenant_into_the_home_only() {
        let keep = tar_extract(20000, 20000, Path::new("/home/alice"), OnExisting::Keep);
        let spec = tar_extract(
            20000,
            20000,
            Path::new("/home/alice"),
            OnExisting::Overwrite,
        );
        assert_eq!(
            spec.run_as,
            Some(crate::system::RunAs {
                uid: 20000,
                gid: 20000
            })
        );
        assert_eq!(
            strings(&spec.args),
            vec![
                "--extract",
                "--file=-",
                "--use-compress-program=/usr/bin/gzip",
                "--directory",
                "/home/alice",
                "--no-same-owner",
                "--same-permissions",
                "--no-acls",
                "--no-selinux",
                "--no-xattrs",
                "--verbose",
                "--warning=existing-file",
            ]
        );
        // Keeping existing files is the same plus exactly one option.
        let mut expected = strings(&spec.args);
        expected.push("--skip-old-files".into());
        assert_eq!(strings(&keep.args), expected);
        assert_eq!(keep.run_as, spec.run_as);
        for forbidden in [
            "--absolute-names",
            "-P",
            "--same-owner",
            "--keep-directory-symlink",
            "--overwrite",
            "--dereference",
        ] {
            assert!(!spec.args.iter().any(|a| a == forbidden), "{forbidden}");
        }
    }

    #[test]
    fn tasks_round_trip_through_their_arguments() -> Result<()> {
        let backup = Task::Backup {
            uid: 20000,
            gid: 20000,
            home: "/home/alice".into(),
            output: "/var/lib/oxpanel-backups/alice/b1731500000123/home.tar.gz".into(),
            max_bytes: 1 << 40,
            venvs: vec!["apps/api/.venv".into(), "apps/b/.venv".into()],
        };
        let restore = Task::Restore {
            uid: 20000,
            gid: 20000,
            home: "/home/alice".into(),
            input: "/var/lib/oxpanel-backups/alice/b1731500000123/home.tar.gz".into(),
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
            size: 42,
            on_existing: OnExisting::Keep,
        };
        assert_eq!(
            strings(&backup.to_args()),
            vec![
                "worker",
                "backup",
                "20000",
                "--gid",
                "20000",
                "--home",
                "/home/alice",
                "--output",
                "/var/lib/oxpanel-backups/alice/b1731500000123/home.tar.gz",
                "--max-bytes",
                "1099511627776",
                "--venvs",
                "apps/api/.venv,apps/b/.venv",
            ]
        );
        assert!(
            strings(&restore.to_args()).ends_with(&["--existing".to_owned(), "keep".to_owned()])
        );
        let no_venvs = Task::Backup {
            uid: 20000,
            gid: 20000,
            home: "/home/a".into(),
            output: "/b/home.tar.gz".into(),
            max_bytes: 1,
            venvs: Vec::new(),
        };
        assert!(strings(&no_venvs.to_args()).ends_with(&["--venvs".to_owned(), "-".to_owned()]));
        for task in [backup, restore, no_venvs] {
            assert_eq!(Task::parse(&strings(&task.to_args()))?, task);
        }
        Ok(())
    }

    #[test]
    fn arguments_are_parsed_strictly() {
        let ok = [
            "worker",
            "backup",
            "20000",
            "--gid",
            "20000",
            "--home",
            "/home/a",
            "--output",
            "/b/home.tar.gz",
            "--max-bytes",
            "10",
            "--venvs",
            "apps/a/.venv",
        ];
        let parse =
            |args: &[&str]| Task::parse(&args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>());
        assert!(parse(&ok).is_ok());
        let with = |i: usize, v: &'static str| {
            let mut a = ok.to_vec();
            if let Some(slot) = a.get_mut(i) {
                *slot = v;
            }
            a
        };
        for bad in [
            with(2, "0"), // the archiver never runs as root
            with(4, "0"),
            with(2, "alice"),
            with(6, "home/a"), // relative
            with(6, "/home/a/../b"),
            with(8, "/b/../etc/passwd"),
            with(10, "many"),
            with(1, "destroy"),
            with(0, "serve"),
            with(9, "--input"), // wrong flag for the mode
            with(12, "../x/.venv"),
            with(12, "/etc"),
            with(12, "a,,b"),
            with(12, "apps/a/.venv,x y"),
        ] {
            assert!(parse(&bad).is_err(), "{bad:?}");
        }
        assert!(parse(&ok[..9]).is_err(), "missing arguments");
        let mut twice = ok.to_vec();
        twice.extend(["--gid", "20001"]);
        assert!(parse(&twice).is_err());
        let mut extra = ok.to_vec();
        extra.extend(["--verbose", "1"]);
        assert!(parse(&extra).is_err());
        assert!(parse(&[
            "worker",
            "restore",
            "20000",
            "--gid",
            "20000",
            "--home",
            "/home/a",
            "--input",
            "/b/home.tar.gz",
            "--sha256",
            "abc",
            "--size",
            "1"
        ])
        .is_err());
        let restore = |existing: &'static str| {
            parse(&[
                "worker",
                "restore",
                "20000",
                "--gid",
                "20000",
                "--home",
                "/home/a",
                "--input",
                "/b/home.tar.gz",
                "--sha256",
                &"a".repeat(64),
                "--size",
                "1",
                "--existing",
                existing,
            ])
        };
        assert!(restore("keep").is_ok() && restore("overwrite").is_ok());
        for bad in ["", "merge", "KEEP"] {
            assert!(restore(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn restore_counts_are_read_from_the_workers_last_line() {
        let out = "tar: ./x: skipping existing file\noxpanel-restore-result restored=1 skipped=1\n/usr/bin/tar: oxpanel-restore-result restored=99 skipped=0\nERROR tar could not restore every member\noxpanel-restore-result restored=12 skipped=3\nsystemd: unit stopped\n";
        assert_eq!(parse_restore_result(out), Some((12, 3)));
        assert_eq!(parse_restore_result("nothing"), None);
        assert_eq!(
            parse_restore_result("oxpanel-restore-result restored=x skipped=1"),
            None
        );
    }

    #[test]
    fn result_files_sit_next_to_their_member() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|e| Error::io("tempdir", "/tmp", e))?;
        let member = dir.path().join("home.tar.gz");
        assert_eq!(
            result_path(&member),
            dir.path().join("home.tar.gz.result.json")
        );
        assert_eq!(read_result(&member)?, None);
        write_fake_archive(&member)?;
        let result = read_result(&member)?.unwrap_or_else(|| panic!("no result"));
        let (size, sha) = hash_file(&member)?;
        assert_eq!(
            (result.size_bytes, result.sha256.as_str()),
            (size, sha.as_str())
        );
        assert_eq!(result.kind, KIND_HOME);
        std::fs::write(result_path(&member), b"{").map_err(|e| Error::io("write", &member, e))?;
        assert!(matches!(
            read_result(&member),
            Err(Error::CorruptRecord { .. })
        ));
        Ok(())
    }

    /// A small home for [`a_real_archive_round_trips_and_damage_is_detected`]:
    /// a site, a cache, `node_modules` and a virtualenv; the site owned by
    /// `id` ("nobody": an identity that owns nothing, like a tenant).
    fn make_home(base: &Path, home: &Path, store: &Path, id: u32) -> Result<()> {
        let (home, store) = (home.to_path_buf(), store.to_path_buf());
        for d in [
            &home,
            &store,
            &home.join("site"),
            &home.join(".cache"),
            &home.join("site/node_modules/pkg"),
            &home.join("venv/bin"),
        ] {
            std::fs::create_dir_all(d).map_err(|e| Error::io("mkdir", d, e))?;
        }
        for f in [
            "site/node_modules/pkg/index.js",
            "venv/pyvenv.cfg",
            "venv/bin/python",
        ] {
            std::fs::write(home.join(f), "x").map_err(|e| Error::io("w", &home, e))?;
        }
        std::fs::write(home.join("site/index.html"), "one")
            .map_err(|e| Error::io("w", &home, e))?;
        std::fs::write(home.join(".cache/junk"), "x").map_err(|e| Error::io("w", &home, e))?;
        std::os::unix::fs::symlink("/etc/shadow", home.join("site/shadow"))
            .map_err(|e| Error::io("symlink", &home, e))?;
        for p in [&home, &home.join("site"), &home.join("site/index.html")] {
            nix::unistd::chown(p.as_path(), Some(id.into()), Some(id.into())).map_err(
                |source| Error::Sys {
                    op: "chown",
                    source,
                },
            )?;
        }
        std::fs::set_permissions(base, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .map_err(|e| Error::io("chmod", base, e))?;
        Ok(())
    }

    /// The real thing, with the test's own identity standing in for a tenant
    /// (only root may switch): archive a directory, damage detection, restore.
    #[test]
    fn a_real_archive_round_trips_and_damage_is_detected() -> Result<()> {
        if !nix::unistd::geteuid().is_root() || !Path::new(bin::SETPRIV).exists() {
            return Ok(()); // needs setpriv and the right to use it
        }
        let dir = tempfile::tempdir().map_err(|e| Error::io("tempdir", "/tmp", e))?;
        let (home, store) = (dir.path().join("home"), dir.path().join("store"));
        let id = 65534;
        make_home(dir.path(), &home, &store, id)?;
        let archive = store.join("home.tar.gz");
        let run_backup = |max| {
            run(&Task::Backup {
                uid: id,
                gid: id,
                home: home.clone(),
                output: archive.clone(),
                max_bytes: max,
                venvs: Vec::new(),
            })
        };
        assert_eq!(run_backup(10).map_err(|f| f.code), Err(EXIT_TOO_LARGE));
        assert!(!archive.exists(), "a refused archive leaves nothing behind");
        run_backup(u64::MAX).unwrap_or_else(|f| panic!("{f:?}"));
        let result = read_result(&archive)?.unwrap_or_else(|| panic!("no result"));

        std::fs::write(home.join("site/index.html"), "two")
            .map_err(|e| Error::io("w", &home, e))?;
        for d in ["site/node_modules", "venv"] {
            std::fs::remove_dir_all(home.join(d)).map_err(|e| Error::io("rm", &home, e))?;
        }
        let restore_as = |sha: &str, size, on_existing| {
            run(&Task::Restore {
                uid: id,
                gid: id,
                home: home.clone(),
                input: archive.clone(),
                sha256: sha.to_owned(),
                size,
                on_existing,
            })
        };
        let restore = |sha: &str, size| restore_as(sha, size, OnExisting::Overwrite);
        assert_eq!(
            restore(&"0".repeat(64), result.size_bytes).map_err(|f| f.code),
            Err(EXIT_INTEGRITY)
        );
        assert_eq!(
            restore(&result.sha256, result.size_bytes + 1).map_err(|f| f.code),
            Err(EXIT_INTEGRITY)
        );
        let content = || std::fs::read_to_string(home.join("site/index.html")).unwrap_or_default();
        assert_eq!(content(), "two", "a damaged archive restores nothing");
        std::fs::remove_file(home.join("site/shadow")).map_err(|e| Error::io("rm", &home, e))?;
        restore_as(&result.sha256, result.size_bytes, OnExisting::Keep)
            .unwrap_or_else(|f| panic!("{f:?}"));
        assert_eq!(content(), "two", "an existing file is kept");
        assert!(
            home.join("site/shadow").symlink_metadata().is_ok(),
            "a missing one comes back"
        );
        restore(&result.sha256, result.size_bytes).unwrap_or_else(|f| panic!("{f:?}"));
        assert_eq!(content(), "one");
        assert!(
            !home.join("site/node_modules").exists(),
            "node_modules is not in the archive"
        );
        assert!(
            !home.join("venv").exists(),
            "a virtualenv is not in the archive"
        );
        let link = std::fs::read_link(home.join("site/shadow")).unwrap_or_default();
        assert_eq!(link, PathBuf::from("/etc/shadow"), "stored as a link");
        Ok(())
    }
}
