//! The file manager's worker: the half of every file operation that touches
//! a tenant's files. It runs **as the tenant** — never as root — and resolves
//! every path itself, from a descriptor of the home, with
//! `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)`.
//!
//! Two layers stop a request from reaching anything outside the home:
//!
//! 1. **The kernel's permission checks.** The process has the tenant's uid
//!    and gid, no supplementary groups, no capabilities and `no_new_privs`
//!    (`setpriv`, or `User=` of a job unit): it can read, write, rename and
//!    delete exactly what the tenant could over SFTP, and nothing that
//!    belongs to another tenant or to the system.
//! 2. **Confined resolution.** A path is resolved beneath the home: an
//!    absolute symlink, a `..` that would climb out, a magic link in `/proc`
//!    or a mount point inside the home makes the resolution fail with
//!    `EXDEV`/`ELOOP` instead of following it. So a link `x -> /etc/passwd`
//!    (world-readable, which layer 1 alone would allow) is never read
//!    through, and a link into another home never even reaches layer 1.
//!
//! Names never reach an argument list — the request is JSON on standard
//! input — so a name beginning with `-`, or containing a newline, is just
//! bytes given to an `*at` system call. Nothing is opened that could block
//! or have side effects: types are checked through an `O_PATH` descriptor
//! (or `fstatat` without following) before anything is opened for reading,
//! and opens use `O_NONBLOCK | O_NOFOLLOW | O_NOCTTY`.
//!
//! Protocol (`oxpanel-daemon files`): one line of JSON ([`Request`]) on
//! standard input, followed by the bytes to write for the operations that
//! write; one line of JSON ([`Response`]) on standard output, followed by the
//! bytes read for [`Op::Read`]. The worker never logs a file's content; it
//! logs nothing at all.
//!
//! The long operations (copy, delete, compress, extract) are in
//! [`crate::files_tree`] and [`crate::files_archive`]; they run in a job unit
//! with the same [`Request`] format (`oxpanel-daemon files-job`).

use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{openat2, AtFlags, OFlag, OpenHow, RenameFlags, ResolveFlag};
use nix::sys::stat::{fstat, fstatat, mkdirat, FileStat, Mode, SFlag};
use nix::unistd::{ftruncate, unlinkat, UnlinkatFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::validate::FilePath;

/// First argument that selects the synchronous worker.
pub const SUBCOMMAND: &str = "files";
/// First argument that selects the job worker.
pub const JOB_SUBCOMMAND: &str = "files-job";

/// Longest request line (the JSON before any data).
const REQUEST_LINE_MAX: usize = 512 * 1024;
/// Mode of files and directories the worker creates, as SFTP creates them
/// with its default umask of 022. Under a document root's default ACL the
/// group bits become the mask, so the web server can read (`r--`) and
/// traverse (`r-x`) what is created.
pub const NEW_FILE_MODE: u32 = 0o644;
pub const NEW_DIR_MODE: u32 = 0o755;
/// Mode of a copied or extracted file while it is written (its own mode is
/// set when it is complete).
const PARTIAL_MODE: u32 = 0o600;
/// Longest symlink target returned in a listing.
const LINK_TARGET_MAX: usize = 1024;
/// Prefix of the temporary names the worker writes before renaming.
pub const TEMP_PREFIX: &str = ".oxpanel-tmp-";

/// Bounds the daemon passes with each request (from its configuration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Names read from one directory for a listing; beyond, it is truncated.
    pub list_max_entries: u64,
    /// Entries a search or size computation visits at most.
    pub walk_max_entries: u64,
    /// Seconds a search or size computation may take.
    pub walk_max_secs: u64,
    /// Largest file an upload may produce.
    pub upload_max_bytes: u64,
    /// Bytes a job may write (copy, compress) or extract.
    pub job_max_bytes: u64,
    /// Entries an archive may have.
    pub extract_max_entries: u64,
    /// How much larger than the archive its extracted content may be.
    pub extract_max_ratio: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            list_max_entries: 100_000,
            walk_max_entries: 200_000,
            walk_max_secs: 30,
            upload_max_bytes: 4 << 30,
            job_max_bytes: 8 << 30,
            extract_max_entries: 100_000,
            extract_max_ratio: 200,
        }
    }
}

/// One request to the worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// The tenant's home (absolute). It must belong to the uid the worker runs as.
    pub home: PathBuf,
    /// Paths of the engine (document roots, application roots) that must
    /// not be removed, moved or have their mode changed — and neither may
    /// the home or any directory between the home and one of them.
    pub protected: Vec<FilePath>,
    pub limits: Limits,
    pub op: Op,
}

/// The two archive formats the file manager writes (and, with plain tar,
/// reads).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveFormat {
    Zip,
    TarGz,
}

/// How a mode is changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModeChange {
    /// Exactly these bits (already checked by `validate::FileMode`).
    Bits(u32),
    /// Only the tenant: files 0600 (0700 if executable), directories 0700.
    Private,
    /// Readable by the web server: files 0644 (0755 if executable),
    /// directories 0755.
    WebReadable,
}

/// What the worker is asked to do. Paths are relative to the home.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    List {
        path: FilePath,
        offset: u64,
        limit: u64,
    },
    Stat {
        path: FilePath,
    },
    Read {
        path: FilePath,
        offset: u64,
        length: u64,
    },
    /// The data follows the request line.
    Write {
        path: FilePath,
        overwrite: bool,
        mode: Option<u32>,
    },
    UploadStart {
        path: FilePath,
        partial: String,
        overwrite: bool,
    },
    /// The data follows the request line.
    UploadChunk {
        path: FilePath,
        partial: String,
        offset: u64,
    },
    UploadFinish {
        path: FilePath,
        partial: String,
        size: u64,
        sha256: Option<String>,
        overwrite: bool,
    },
    UploadAbort {
        path: FilePath,
        partial: String,
    },
    MakeDir {
        path: FilePath,
        parents: bool,
    },
    Rename {
        from: FilePath,
        to: FilePath,
        overwrite: bool,
    },
    Chmod {
        path: FilePath,
        change: ModeChange,
    },
    Search {
        path: FilePath,
        needle: String,
        max_results: u64,
    },
    Size {
        path: FilePath,
    },
    // --- jobs (files-job) ---
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

impl Op {
    /// Whether this operation runs as a job (`files-job`) rather than
    /// synchronously.
    pub fn is_job(&self) -> bool {
        matches!(
            self,
            Self::Copy { .. } | Self::Delete { .. } | Self::Compress { .. } | Self::Extract { .. }
        )
    }
}

/// Why an operation was refused or failed. The daemon maps each to a gRPC
/// status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fault {
    NotFound,
    Exists,
    NotADirectory,
    IsADirectory,
    NotEmpty,
    /// The kernel refused it to the tenant.
    PermissionDenied,
    /// Resolving the path would leave the home (a symlink out, a mount point).
    OutsideHome,
    /// Not a regular file (a FIFO, socket or device) where one is needed.
    NotRegular,
    /// The engine's own directories: the home, document and application roots.
    Protected,
    /// The tenant's disk quota (or the file system) is full.
    QuotaExceeded,
    /// A size or count limit of the file manager.
    TooLarge,
    Invalid,
    Failed,
}

/// A refusal: the fault and a message for the caller. The message names
/// only paths relative to the home, as the caller gave them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub fault: Fault,
    pub message: String,
}

impl Refusal {
    pub fn new(fault: Fault, message: impl Into<String>) -> Self {
        Self {
            fault,
            message: message.into(),
        }
    }
}

pub type Res<T> = std::result::Result<T, Refusal>;

/// A path as it appears in a message: control characters escaped, `.` for
/// the home.
pub fn shown(path: &str) -> String {
    if path.is_empty() {
        ".".to_owned()
    } else {
        path.escape_debug().to_string()
    }
}

/// Turn an errno into a refusal about `path`.
pub fn os_fault(e: Errno, path: &str) -> Refusal {
    let (fault, why) = match e {
        Errno::ENOENT => (Fault::NotFound, "no such file or directory"),
        Errno::EEXIST => (Fault::Exists, "already exists"),
        Errno::ENOTDIR => (Fault::NotADirectory, "not a directory"),
        Errno::EISDIR => (Fault::IsADirectory, "is a directory"),
        Errno::ENOTEMPTY => (Fault::NotEmpty, "directory not empty"),
        Errno::EACCES | Errno::EPERM | Errno::EROFS => {
            (Fault::PermissionDenied, "permission denied")
        }
        Errno::EXDEV | Errno::ELOOP => (
            Fault::OutsideHome,
            "leads outside the home (a symbolic link or mount point)",
        ),
        Errno::EDQUOT | Errno::ENOSPC => (Fault::QuotaExceeded, "disk quota exceeded"),
        Errno::EFBIG => (Fault::TooLarge, "file too large"),
        Errno::ENAMETOOLONG => (Fault::Invalid, "name too long"),
        Errno::ENXIO | Errno::ENODEV => (Fault::NotRegular, "not a regular file"),
        Errno::EBUSY => (Fault::Failed, "in use"),
        Errno::EINVAL => (Fault::Invalid, "invalid operation"),
        _ => (Fault::Failed, e.desc()),
    };
    Refusal::new(fault, format!("'{}': {why}", shown(path)))
}

/// What a directory entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    File,
    Directory,
    Symlink,
    Fifo,
    Socket,
    CharDevice,
    BlockDevice,
}

impl Kind {
    pub fn of(st: &FileStat) -> Self {
        match SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT {
            SFlag::S_IFDIR => Self::Directory,
            SFlag::S_IFLNK => Self::Symlink,
            SFlag::S_IFIFO => Self::Fifo,
            SFlag::S_IFSOCK => Self::Socket,
            SFlag::S_IFCHR => Self::CharDevice,
            SFlag::S_IFBLK => Self::BlockDevice,
            _ => Self::File,
        }
    }
}

/// Where a symlink leads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkState {
    /// To something inside the home, of this kind.
    Inside(Kind),
    /// Out of the home (or across a mount point): never followed.
    Outside,
    /// To nothing.
    Broken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    /// The target as stored (lossy UTF-8, at most 1024 bytes).
    pub target: String,
    pub state: LinkState,
}

/// One entry of a listing, a search or a stat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The name (lossy UTF-8 if `name_utf8` is false).
    pub name: String,
    /// The name is valid UTF-8, so the entry can be addressed by its path.
    pub name_utf8: bool,
    /// Searches: the path relative to the home.
    pub path: Option<String>,
    pub kind: Kind,
    pub size: u64,
    /// Space it occupies on disk (sparse files occupy less than `size`).
    pub allocated: u64,
    pub modified_unix: i64,
    pub modified_nanos: u32,
    /// Permission bits (`0o7777`).
    pub mode: u32,
    /// Owned by the tenant (something root planted in the home is not).
    pub owned: bool,
    pub link: Option<Link>,
}

/// Successful results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Reply {
    Listing {
        entries: Vec<Entry>,
        /// Entries read from the directory (all of them unless truncated).
        total: u64,
        truncated: bool,
    },
    Entry {
        entry: Entry,
    },
    /// The data follows the response line.
    Data {
        size: u64,
        modified_unix: i64,
        modified_nanos: u32,
        length: u64,
    },
    Received {
        bytes: u64,
    },
    Done,
    Found {
        matches: Vec<Entry>,
        scanned: u64,
        truncated: bool,
    },
    Size {
        allocated: u64,
        apparent: u64,
        files: u64,
        directories: u64,
        truncated: bool,
    },
    Job {
        summary: JobSummary,
    },
}

/// What a job did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSummary {
    /// Entries copied, removed, archived or extracted.
    pub entries: u64,
    /// Bytes of file content written (copy, extract) or archived.
    pub bytes: u64,
    /// Entries left out (existing, unsupported type, unsafe name, …).
    pub skipped: u64,
}

/// The response line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok { reply: Reply },
    Refused { refusal: Refusal },
}

// --- the home and confined resolution ---------------------------------------

/// The tenant's home, opened once, and everything resolved from it.
#[derive(Debug)]
pub struct Home {
    fd: OwnedFd,
    limits: Limits,
    protected_paths: Vec<FilePath>,
    protected: Option<HashSet<(u64, u64)>>,
}

const RESOLVE: ResolveFlag = ResolveFlag::RESOLVE_BENEATH
    .union(ResolveFlag::RESOLVE_NO_MAGICLINKS)
    .union(ResolveFlag::RESOLVE_NO_XDEV);

/// `openat2` under `resolve`, retrying the `EAGAIN` the kernel returns when
/// a rename raced with a confined lookup.
pub fn open_beneath(
    dir: impl AsFd,
    path: &OsStr,
    flags: OFlag,
    mode: u32,
    resolve: ResolveFlag,
) -> std::result::Result<OwnedFd, Errno> {
    let path: &Path = if path.is_empty() {
        Path::new(".")
    } else {
        Path::new(path)
    };
    // openat2 refuses any flag besides these three with O_PATH.
    let extra = if flags.contains(OFlag::O_PATH) {
        OFlag::O_CLOEXEC
    } else {
        OFlag::O_CLOEXEC | OFlag::O_NOCTTY
    };
    let how = OpenHow::new()
        .flags(flags | extra)
        .mode(Mode::from_bits_truncate(mode))
        .resolve(resolve);
    let mut tries = 0;
    loop {
        match openat2(dir.as_fd(), path, how) {
            Err(Errno::EAGAIN) if tries < 8 => tries += 1,
            other => return other,
        }
    }
}

/// `(device, inode)` of an open file.
pub fn identity(st: &FileStat) -> (u64, u64) {
    (st.st_dev, st.st_ino)
}

fn u64_of(n: i64) -> u64 {
    u64::try_from(n).unwrap_or(0)
}

impl Home {
    /// Open the home. It must be a real directory owned by the uid this
    /// process runs as (the worker never works on anyone else's home).
    pub fn at(path: &Path, limits: Limits, protected: Vec<FilePath>) -> Res<Self> {
        let fd = nix::fcntl::open(
            path,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| os_fault(e, ""))?;
        let st = fstat(&fd).map_err(|e| os_fault(e, ""))?;
        if st.st_uid != nix::unistd::geteuid().as_raw() {
            return Err(Refusal::new(
                Fault::PermissionDenied,
                "the home does not belong to the account the worker runs as",
            ));
        }
        Ok(Self {
            fd,
            limits,
            protected_paths: protected,
            protected: None,
        })
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn fd(&self) -> &OwnedFd {
        &self.fd
    }

    /// Open `path` beneath the home. `follow`: whether a symlink as the last
    /// component is followed (beneath the home only).
    pub fn open(&self, path: &FilePath, flags: OFlag, follow: bool) -> Res<OwnedFd> {
        let flags = if follow {
            flags
        } else {
            flags | OFlag::O_NOFOLLOW
        };
        open_beneath(&self.fd, OsStr::new(path.as_str()), flags, 0, RESOLVE)
            .map_err(|e| os_fault(e, path.as_str()))
    }

    /// A directory beneath the home, opened for listing and `*at` calls.
    pub fn dir(&self, path: &FilePath) -> Res<OwnedFd> {
        self.open(path, OFlag::O_RDONLY | OFlag::O_DIRECTORY, true)
    }

    /// The directory holding `path`, and the last name. Not for the home.
    pub fn parent_of(&self, path: &FilePath) -> Res<(OwnedFd, String)> {
        let Some(name) = path.file_name() else {
            return Err(Refusal::new(
                Fault::Protected,
                "the home itself cannot be changed this way",
            ));
        };
        Ok((self.dir(&path.parent())?, name.to_owned()))
    }

    /// `lstat` of `path` (the home for `""`).
    pub fn lstat(&self, path: &FilePath) -> Res<FileStat> {
        if path.is_home() {
            return fstat(&self.fd).map_err(|e| os_fault(e, ""));
        }
        let (dir, name) = self.parent_of(path)?;
        fstatat(&dir, name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|e| os_fault(e, path.as_str()))
    }

    /// Refuse to change `st` if it is the home, an engine directory or one
    /// between them.
    pub fn check_unprotected(&mut self, st: &FileStat, path: &str) -> Res<()> {
        if self.protected_set().contains(&identity(st)) {
            return Err(Refusal::new(
                Fault::Protected,
                format!(
                    "'{}' is the home, a site's document or application root, or a directory leading to one; it is managed by the engine",
                    shown(path)
                ),
            ));
        }
        Ok(())
    }

    /// The identities of the home and of every directory from the home down
    /// to each protected path (resolved without following any symlink).
    fn protected_set(&mut self) -> &HashSet<(u64, u64)> {
        let fd = &self.fd;
        let paths = &self.protected_paths;
        self.protected.get_or_insert_with(|| {
            let mut set = HashSet::new();
            if let Ok(st) = fstat(fd) {
                set.insert(identity(&st));
            }
            for p in paths {
                let mut prefix = FilePath::home();
                for comp in p.components() {
                    let Ok(next) = prefix.join(comp, "protected") else {
                        break;
                    };
                    prefix = next;
                    let opened = open_beneath(
                        fd,
                        OsStr::new(prefix.as_str()),
                        OFlag::O_PATH | OFlag::O_NOFOLLOW,
                        0,
                        RESOLVE | ResolveFlag::RESOLVE_NO_SYMLINKS,
                    );
                    match opened.and_then(|f| fstat(&f)) {
                        Ok(st) => {
                            set.insert(identity(&st));
                        }
                        Err(_) => break,
                    }
                }
            }
            set
        })
    }

    /// The entry for `name` in `dir`, whose path relative to the home is
    /// `path` (used to tell where a symlink leads).
    pub fn entry(&self, dir: impl AsFd, name: &OsStr, path: Option<&str>) -> Res<Entry> {
        let shown_path = path.unwrap_or_default();
        let st = fstatat(&dir, name, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|e| os_fault(e, shown_path))?;
        let mut entry = entry_of(name, &st);
        if entry.kind == Kind::Symlink {
            let target = nix::fcntl::readlinkat(&dir, name).unwrap_or_default();
            let mut bytes = target.as_bytes().to_vec();
            bytes.truncate(LINK_TARGET_MAX);
            let state = match path.map(|p| FilePath::parse(p, "path")) {
                Some(Ok(p)) => match self
                    .open(&p, OFlag::O_PATH, true)
                    .and_then(|f| fstat(&f).map_err(|e| os_fault(e, p.as_str())))
                {
                    Ok(t) => LinkState::Inside(Kind::of(&t)),
                    Err(r) if r.fault == Fault::NotFound => LinkState::Broken,
                    Err(_) => LinkState::Outside,
                },
                _ => LinkState::Outside,
            };
            entry.link = Some(Link {
                target: String::from_utf8_lossy(&bytes).into_owned(),
                state,
            });
        }
        Ok(entry)
    }
}

/// An [`Entry`] from a name and its `lstat`.
pub fn entry_of(name: &OsStr, st: &FileStat) -> Entry {
    let utf8 = name.to_str();
    Entry {
        name: utf8.map_or_else(|| name.to_string_lossy().into_owned(), str::to_owned),
        name_utf8: utf8.is_some(),
        path: None,
        kind: Kind::of(st),
        size: u64_of(st.st_size),
        allocated: u64_of(st.st_blocks).saturating_mul(512),
        modified_unix: st.st_mtime,
        modified_nanos: u32::try_from(st.st_mtime_nsec).unwrap_or(0),
        mode: st.st_mode & 0o7777,
        owned: st.st_uid == nix::unistd::geteuid().as_raw(),
        link: None,
    }
}

/// Names read from a directory, with the type the directory reports.
pub type Names = Vec<(Vec<u8>, Option<Kind>)>;

/// Every name in an open directory except `.` and `..`, at most `max`
/// (and whether there were more), with the type the directory reports.
pub fn read_names(dir: &OwnedFd, max: u64) -> Res<(Names, bool)> {
    let dup = dir
        .try_clone()
        .map_err(|e| Refusal::new(Fault::Failed, format!("cannot read a directory: {e}")))?;
    let mut d = nix::dir::Dir::from_fd(dup).map_err(|e| os_fault(e, ""))?;
    let mut out = Vec::new();
    for item in d.iter() {
        let item = item.map_err(|e| os_fault(e, ""))?;
        let name = item.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if out.len() as u64 >= max {
            return Ok((out, true));
        }
        let kind = item.file_type().map(|t| match t {
            nix::dir::Type::Directory => Kind::Directory,
            nix::dir::Type::Symlink => Kind::Symlink,
            nix::dir::Type::Fifo => Kind::Fifo,
            nix::dir::Type::Socket => Kind::Socket,
            nix::dir::Type::CharacterDevice => Kind::CharDevice,
            nix::dir::Type::BlockDevice => Kind::BlockDevice,
            nix::dir::Type::File => Kind::File,
        });
        out.push((name.to_vec(), kind));
    }
    Ok((out, false))
}

/// `parent/name` as a path string (for messages and link resolution).
pub fn child_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}

// --- the operations ------------------------------------------------------------

/// Run one synchronous request. `data` is what followed the request line;
/// the bytes read by [`Op::Read`] are returned alongside the reply.
pub fn handle(req: &Request, data: &[u8]) -> Res<(Reply, Vec<u8>)> {
    let mut home = Home::at(&req.home, req.limits, req.protected.clone())?;
    let none = |reply: Reply| Ok((reply, Vec::new()));
    match &req.op {
        Op::List {
            path,
            offset,
            limit,
        } => none(list(&home, path, *offset, *limit)?),
        Op::Stat { path } => none(stat(&home, path)?),
        Op::Read {
            path,
            offset,
            length,
        } => read(&home, path, *offset, *length),
        Op::Write {
            path,
            overwrite,
            mode,
        } => none(write(&home, path, data, *overwrite, *mode)?),
        Op::UploadStart {
            path,
            partial,
            overwrite,
        } => none(upload_start(&home, path, partial, *overwrite)?),
        Op::UploadChunk {
            path,
            partial,
            offset,
        } => none(upload_chunk(&home, path, partial, *offset, data)?),
        Op::UploadFinish {
            path,
            partial,
            size,
            sha256,
            overwrite,
        } => none(upload_finish(
            &home,
            path,
            partial,
            *size,
            sha256.as_deref(),
            *overwrite,
        )?),
        Op::UploadAbort { path, partial } => none(upload_abort(&home, path, partial)?),
        Op::MakeDir { path, parents } => none(make_dir(&home, path, *parents)?),
        Op::Rename {
            from,
            to,
            overwrite,
        } => none(rename(&mut home, from, to, *overwrite)?),
        Op::Chmod { path, change } => none(chmod(&mut home, path, *change)?),
        Op::Search {
            path,
            needle,
            max_results,
        } => none(crate::files_tree::search(
            &home,
            path,
            needle,
            *max_results,
        )?),
        Op::Size { path } => none(crate::files_tree::size(&home, path)?),
        Op::Copy { .. } | Op::Delete { .. } | Op::Compress { .. } | Op::Extract { .. } => {
            Err(Refusal::new(Fault::Invalid, "this operation runs as a job"))
        }
    }
}

fn list(home: &Home, path: &FilePath, offset: u64, limit: u64) -> Res<Reply> {
    let dir = home.dir(path)?;
    let (mut names, truncated) = read_names(&dir, home.limits().list_max_entries)?;
    let total = names.len() as u64;
    // Directories first, then by name (bytes): a stable order to page through.
    let is_dir = |n: &[u8], k: Option<Kind>| match k {
        Some(k) => k == Kind::Directory,
        None => fstatat(&dir, OsStr::from_bytes(n), AtFlags::AT_SYMLINK_NOFOLLOW)
            .is_ok_and(|st| Kind::of(&st) == Kind::Directory),
    };
    let mut keyed: Vec<(bool, Vec<u8>)> =
        names.drain(..).map(|(n, k)| (!is_dir(&n, k), n)).collect();
    keyed.sort();
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    let take = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut entries = Vec::new();
    for (_, name) in keyed.iter().skip(start).take(take) {
        let name = OsStr::from_bytes(name);
        let rel = name.to_str().map(|n| child_path(path.as_str(), n));
        match home.entry(&dir, name, rel.as_deref()) {
            Ok(e) => entries.push(e),
            // Removed since the directory was read.
            Err(r) if r.fault == Fault::NotFound => {}
            Err(r) => return Err(r),
        }
    }
    Ok(Reply::Listing {
        entries,
        total,
        truncated,
    })
}

fn stat(home: &Home, path: &FilePath) -> Res<Reply> {
    if path.is_home() {
        let st = home.lstat(path)?;
        return Ok(Reply::Entry {
            entry: entry_of(OsStr::new("."), &st),
        });
    }
    let (dir, name) = home.parent_of(path)?;
    Ok(Reply::Entry {
        entry: home.entry(&dir, OsStr::new(&name), Some(path.as_str()))?,
    })
}

/// Open a regular file for reading, following a final symlink beneath the
/// home only. The type is checked through an `O_PATH` descriptor first, so
/// a FIFO or device is never opened; the second open is checked to be the
/// same file.
pub fn open_regular(home: &Home, path: &FilePath) -> Res<(OwnedFd, FileStat)> {
    let probe = home.open(path, OFlag::O_PATH, true)?;
    let st = fstat(&probe).map_err(|e| os_fault(e, path.as_str()))?;
    match Kind::of(&st) {
        Kind::File => {}
        Kind::Directory => return Err(os_fault(Errno::EISDIR, path.as_str())),
        _ => return Err(os_fault(Errno::ENXIO, path.as_str())),
    }
    let fd = home.open(path, OFlag::O_RDONLY | OFlag::O_NONBLOCK, true)?;
    let again = fstat(&fd).map_err(|e| os_fault(e, path.as_str()))?;
    if identity(&again) != identity(&st) {
        return Err(Refusal::new(
            Fault::Failed,
            format!("'{}' changed while it was opened", shown(path.as_str())),
        ));
    }
    Ok((fd, again))
}

fn read(home: &Home, path: &FilePath, offset: u64, length: u64) -> Res<(Reply, Vec<u8>)> {
    use std::os::unix::fs::FileExt;
    let (fd, st) = open_regular(home, path)?;
    let file = std::fs::File::from(fd);
    let size = u64_of(st.st_size);
    let want = usize::try_from(length.min(size.saturating_sub(offset))).unwrap_or(0);
    let mut buf = vec![0u8; want];
    let mut got = 0;
    while got < want {
        let at = offset.saturating_add(got as u64);
        let Some(slot) = buf.get_mut(got..) else {
            break;
        };
        match file.read_at(slot, at) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io_fault(&e, path.as_str())),
        }
    }
    buf.truncate(got);
    Ok((
        Reply::Data {
            size,
            modified_unix: st.st_mtime,
            modified_nanos: u32::try_from(st.st_mtime_nsec).unwrap_or(0),
            length: got as u64,
        },
        buf,
    ))
}

/// A unique temporary name in a directory the worker writes into.
pub fn temp_name() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{TEMP_PREFIX}{}-{nanos}", std::process::id())
}

/// Create `name` in `dir` exclusively, never through a symlink, readable by
/// the tenant only (its mode is set explicitly once it is complete).
pub fn create_exclusive(dir: impl AsFd, name: &str, shown_path: &str) -> Res<std::fs::File> {
    create_with_mode(dir, name, PARTIAL_MODE, shown_path)
}

/// Create `name` in `dir` exclusively with `mode`, never through a symlink.
/// The kernel applies the directory's default ACL (or the umask) exactly as
/// for a file the tenant creates over SFTP: no `chmod` afterwards, which
/// would set the "other" entry from the mode instead of the inherited ACL.
pub fn create_with_mode(
    dir: impl AsFd,
    name: &str,
    mode: u32,
    shown_path: &str,
) -> Res<std::fs::File> {
    open_beneath(
        dir,
        OsStr::new(name),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW,
        mode,
        RESOLVE | ResolveFlag::RESOLVE_NO_SYMLINKS,
    )
    .map(std::fs::File::from)
    .map_err(|e| os_fault(e, shown_path))
}

/// `fchmod` that does not depend on the process umask.
pub fn set_mode(fd: impl AsFd, mode: u32, shown_path: &str) -> Res<()> {
    nix::sys::stat::fchmod(fd, Mode::from_bits_truncate(mode)).map_err(|e| os_fault(e, shown_path))
}

/// Write all of `data` to `file`, mapping a full quota to its fault.
pub fn write_all(file: &mut std::fs::File, data: &[u8], shown_path: &str) -> Res<()> {
    file.write_all(data).map_err(|e| io_fault(&e, shown_path))
}

/// Turn an I/O error into a refusal about `path`.
pub fn io_fault(e: &std::io::Error, path: &str) -> Refusal {
    match e.raw_os_error() {
        Some(n) => os_fault(Errno::from_raw(n), path),
        None => Refusal::new(Fault::Failed, format!("'{}': {e}", shown(path))),
    }
}

/// Rename `tmp` to `name` in `dir`: refusing to replace anything unless
/// `overwrite`, and never replacing a directory.
pub fn put_in_place(
    dir: impl AsFd + Copy,
    tmp: &str,
    name: &str,
    overwrite: bool,
    shown_path: &str,
) -> Res<()> {
    let flags = if overwrite {
        RenameFlags::empty()
    } else {
        RenameFlags::RENAME_NOREPLACE
    };
    nix::fcntl::renameat2(dir, tmp, dir, name, flags).map_err(|e| os_fault(e, shown_path))
}

/// Remove a temporary file; best effort.
pub fn discard(dir: impl AsFd, name: &str) {
    let _ = unlinkat(dir, name, UnlinkatFlags::NoRemoveDir);
}

/// What may be at `name` before a file is written there: nothing, or (with
/// `overwrite`) a file or symlink — never a directory. Returns the mode a
/// replaced regular file had.
fn existing_target(
    dir: impl AsFd,
    name: &str,
    overwrite: bool,
    shown_path: &str,
) -> Res<Option<u32>> {
    match fstatat(dir, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Err(Errno::ENOENT) => Ok(None),
        Err(e) => Err(os_fault(e, shown_path)),
        Ok(st) => match Kind::of(&st) {
            Kind::Directory => Err(os_fault(Errno::EISDIR, shown_path)),
            _ if !overwrite => Err(os_fault(Errno::EEXIST, shown_path)),
            Kind::File => Ok(Some(st.st_mode & 0o777)),
            _ => Ok(None),
        },
    }
}

/// The mode a written file ends up with: what was asked, else what the
/// replaced file had, else the default — never more than `0775`.
fn final_mode(asked: Option<u32>, replaced: Option<u32>) -> u32 {
    asked.or(replaced).unwrap_or(NEW_FILE_MODE) & crate::validate::FILE_MODE_ALLOWED
}

fn write(
    home: &Home,
    path: &FilePath,
    data: &[u8],
    overwrite: bool,
    mode: Option<u32>,
) -> Res<Reply> {
    let (dir, name) = home.parent_of(path)?;
    let replaced = existing_target(&dir, &name, overwrite, path.as_str())?;
    let tmp = temp_name();
    // A new file is created with its final mode under a hidden temporary
    // name (the web server never serves dot-files); a replaced file gets the
    // replaced one's mode back exactly.
    let mut file = create_with_mode(&dir, &tmp, final_mode(mode, replaced), path.as_str())?;
    let explicit = mode.or(replaced);
    let done = write_all(&mut file, data, path.as_str())
        .and_then(|()| file.sync_all().map_err(|e| io_fault(&e, path.as_str())))
        .and_then(|()| match explicit {
            Some(m) => set_mode(&file, m & crate::validate::FILE_MODE_ALLOWED, path.as_str()),
            None => Ok(()),
        })
        .and_then(|()| put_in_place(&dir, &tmp, &name, overwrite, path.as_str()));
    if let Err(r) = done {
        discard(&dir, &tmp);
        return Err(r);
    }
    Ok(Reply::Entry {
        entry: home.entry(&dir, OsStr::new(&name), Some(path.as_str()))?,
    })
}

/// Partial files are named by the daemon (`.oxpanel-upload-<id>`); anything
/// else is refused.
fn check_partial(partial: &str) -> Res<()> {
    let ok = partial
        .strip_prefix(".oxpanel-upload-")
        .is_some_and(|id| crate::validate::UploadId::parse(id).is_ok());
    if ok {
        Ok(())
    } else {
        Err(Refusal::new(Fault::Invalid, "not an upload's partial file"))
    }
}

fn upload_start(home: &Home, path: &FilePath, partial: &str, overwrite: bool) -> Res<Reply> {
    check_partial(partial)?;
    let (dir, name) = home.parent_of(path)?;
    let replaced = existing_target(&dir, &name, overwrite, path.as_str())?;
    drop(create_with_mode(
        &dir,
        partial,
        final_mode(None, replaced),
        path.as_str(),
    )?);
    Ok(Reply::Received { bytes: 0 })
}

/// The partial file of an upload, opened for writing (never through a
/// symlink, and only a regular file).
fn open_partial(dir: &OwnedFd, partial: &str, path: &FilePath) -> Res<std::fs::File> {
    let fd = open_beneath(
        dir,
        OsStr::new(partial),
        OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
        0,
        RESOLVE | ResolveFlag::RESOLVE_NO_SYMLINKS,
    )
    .map_err(|e| match e {
        Errno::ENOENT => Refusal::new(
            Fault::NotFound,
            format!(
                "the upload to '{}' has no partial file (aborted, or removed)",
                shown(path.as_str())
            ),
        ),
        e => os_fault(e, path.as_str()),
    })?;
    let st = fstat(&fd).map_err(|e| os_fault(e, path.as_str()))?;
    if Kind::of(&st) != Kind::File {
        return Err(os_fault(Errno::ENXIO, path.as_str()));
    }
    Ok(std::fs::File::from(fd))
}

fn upload_chunk(
    home: &Home,
    path: &FilePath,
    partial: &str,
    offset: u64,
    data: &[u8],
) -> Res<Reply> {
    use std::os::unix::fs::FileExt;
    check_partial(partial)?;
    let (dir, _) = home.parent_of(path)?;
    let file = open_partial(&dir, partial, path)?;
    let have = file
        .metadata()
        .map_err(|e| io_fault(&e, path.as_str()))?
        .len();
    if offset > have {
        return Err(Refusal::new(
            Fault::Invalid,
            format!("offset {offset} is beyond the {have} bytes received so far"),
        ));
    }
    let end = offset.saturating_add(data.len() as u64);
    let fail = |r: Refusal| {
        // A refused upload leaves no partial file behind.
        discard(&dir, partial);
        Err(r)
    };
    if end > home.limits().upload_max_bytes {
        return fail(Refusal::new(
            Fault::TooLarge,
            format!(
                "an upload may be at most {} bytes",
                home.limits().upload_max_bytes
            ),
        ));
    }
    if have > offset {
        // A chunk sent again (the caller retried): what follows it goes.
        if let Err(e) = ftruncate(&file, i64::try_from(offset).unwrap_or(i64::MAX)) {
            return fail(os_fault(e, path.as_str()));
        }
    }
    if let Err(e) = file.write_all_at(data, offset) {
        return fail(io_fault(&e, path.as_str()));
    }
    Ok(Reply::Received { bytes: end })
}

fn upload_finish(
    home: &Home,
    path: &FilePath,
    partial: &str,
    size: u64,
    sha256: Option<&str>,
    overwrite: bool,
) -> Res<Reply> {
    check_partial(partial)?;
    let (dir, name) = home.parent_of(path)?;
    let mut file = open_partial(&dir, partial, path)?;
    let have = file
        .metadata()
        .map_err(|e| io_fault(&e, path.as_str()))?
        .len();
    if have != size {
        return Err(Refusal::new(
            Fault::Invalid,
            format!("{have} bytes were received, not {size}; send the rest first"),
        ));
    }
    if let Some(want) = sha256 {
        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher).map_err(|e| io_fault(&e, path.as_str()))?;
        if format!("{:x}", hasher.finalize()) != want.to_ascii_lowercase() {
            discard(&dir, partial);
            return Err(Refusal::new(
                Fault::Invalid,
                "the upload's SHA-256 does not match; it was discarded",
            ));
        }
    }
    let replaced = existing_target(&dir, &name, overwrite, path.as_str())?;
    file.sync_all().map_err(|e| io_fault(&e, path.as_str()))?;
    if let Some(m) = replaced {
        set_mode(&file, m & crate::validate::FILE_MODE_ALLOWED, path.as_str())?;
    }
    put_in_place(&dir, partial, &name, overwrite, path.as_str())?;
    Ok(Reply::Entry {
        entry: home.entry(&dir, OsStr::new(&name), Some(path.as_str()))?,
    })
}

fn upload_abort(home: &Home, path: &FilePath, partial: &str) -> Res<Reply> {
    check_partial(partial)?;
    match home.parent_of(path) {
        Ok((dir, _)) => match unlinkat(&dir, partial, UnlinkatFlags::NoRemoveDir) {
            Ok(()) | Err(Errno::ENOENT) => Ok(Reply::Done),
            Err(e) => Err(os_fault(e, path.as_str())),
        },
        // The directory is gone, and the partial file with it.
        Err(r) if r.fault == Fault::NotFound => Ok(Reply::Done),
        Err(r) => Err(r),
    }
}

/// Create one directory `name` in `dir` as SFTP does (0755, then the
/// default ACL or the umask apply).
pub fn mkdir_one(dir: &OwnedFd, name: &str, shown_path: &str) -> Res<()> {
    mkdirat(dir, name, Mode::from_bits_truncate(NEW_DIR_MODE)).map_err(|e| os_fault(e, shown_path))
}

fn make_dir(home: &Home, path: &FilePath, parents: bool) -> Res<Reply> {
    if !parents {
        let (dir, name) = home.parent_of(path)?;
        mkdir_one(&dir, &name, path.as_str())?;
        return Ok(Reply::Entry {
            entry: home.entry(&dir, OsStr::new(&name), Some(path.as_str()))?,
        });
    }
    let mut prefix = FilePath::home();
    for comp in path.components() {
        let next = prefix
            .join(comp, "path")
            .map_err(|_| Refusal::new(Fault::Invalid, "invalid path"))?;
        match home.dir(&next) {
            Ok(_) => {}
            Err(r) if r.fault == Fault::NotFound => {
                let parent = home.dir(&prefix)?;
                match mkdir_one(&parent, comp, next.as_str()) {
                    Ok(()) => {}
                    // Created meanwhile by someone else: fine if it is a directory.
                    Err(r) if r.fault == Fault::Exists => {
                        home.dir(&next)?;
                    }
                    Err(r) => return Err(r),
                }
            }
            Err(r) => return Err(r),
        }
        prefix = next;
    }
    stat(home, path)
}

fn rename(home: &mut Home, from: &FilePath, to: &FilePath, overwrite: bool) -> Res<Reply> {
    let (from_dir, from_name) = home.parent_of(from)?;
    let (to_dir, to_name) = home.parent_of(to)?;
    let st = fstatat(&from_dir, from_name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|e| os_fault(e, from.as_str()))?;
    home.check_unprotected(&st, from.as_str())?;
    match fstatat(&to_dir, to_name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(existing) => home.check_unprotected(&existing, to.as_str())?,
        Err(Errno::ENOENT) => {}
        Err(e) => return Err(os_fault(e, to.as_str())),
    }
    let flags = if overwrite {
        RenameFlags::empty()
    } else {
        RenameFlags::RENAME_NOREPLACE
    };
    nix::fcntl::renameat2(
        &from_dir,
        from_name.as_str(),
        &to_dir,
        to_name.as_str(),
        flags,
    )
    .map_err(|e| match e {
        Errno::EXDEV => Refusal::new(
            Fault::Invalid,
            format!(
                "'{}' and '{}' are on different file systems; copy instead",
                shown(from.as_str()),
                shown(to.as_str())
            ),
        ),
        Errno::EINVAL => Refusal::new(
            Fault::Invalid,
            format!("'{}' cannot be moved into itself", shown(from.as_str())),
        ),
        Errno::EEXIST | Errno::ENOTEMPTY if overwrite => os_fault(Errno::ENOTEMPTY, to.as_str()),
        e => os_fault(e, to.as_str()),
    })?;
    Ok(Reply::Entry {
        entry: home.entry(&to_dir, OsStr::new(&to_name), Some(to.as_str()))?,
    })
}

/// The mode a change produces for an entry of `kind` that has `mode` now.
pub fn changed_mode(change: ModeChange, kind: Kind, mode: u32) -> u32 {
    let exec = mode & 0o100 != 0;
    match (change, kind) {
        (ModeChange::Bits(bits), _) => bits & crate::validate::FILE_MODE_ALLOWED,
        (ModeChange::Private, Kind::Directory) => 0o700,
        (ModeChange::Private, _) if exec => 0o700,
        (ModeChange::Private, _) => 0o600,
        (ModeChange::WebReadable, Kind::Directory) => 0o755,
        (ModeChange::WebReadable, _) if exec => 0o755,
        (ModeChange::WebReadable, _) => 0o644,
    }
}

/// Change the mode of a file or directory through an `O_PATH` descriptor
/// (so it applies to the inode that was checked, and works on a file the
/// tenant cannot read). A symlink, FIFO, socket or device is refused.
pub fn chmod_opath(fd: &OwnedFd, mode: u32, shown_path: &str) -> Res<()> {
    use std::os::fd::AsRawFd;
    let magic = format!("/proc/self/fd/{}", fd.as_raw_fd());
    nix::sys::stat::fchmodat(
        nix::fcntl::AT_FDCWD,
        magic.as_str(),
        Mode::from_bits_truncate(mode),
        nix::sys::stat::FchmodatFlags::FollowSymlink,
    )
    .map_err(|e| os_fault(e, shown_path))
}

fn chmod(home: &mut Home, path: &FilePath, change: ModeChange) -> Res<Reply> {
    let fd = home.open(path, OFlag::O_PATH, false)?;
    let st = fstat(&fd).map_err(|e| os_fault(e, path.as_str()))?;
    let kind = Kind::of(&st);
    if !matches!(kind, Kind::File | Kind::Directory) {
        return Err(Refusal::new(
            Fault::NotRegular,
            format!(
                "'{}' is not a file or directory; its permissions cannot be changed",
                shown(path.as_str())
            ),
        ));
    }
    home.check_unprotected(&st, path.as_str())?;
    chmod_opath(&fd, changed_mode(change, kind, st.st_mode), path.as_str())?;
    stat(home, path)
}

// --- entry points --------------------------------------------------------------

/// Read the request line and the data after it.
pub fn read_request(input: &mut impl Read) -> std::result::Result<(Request, Vec<u8>), String> {
    let mut all = Vec::new();
    input
        .read_to_end(&mut all)
        .map_err(|e| format!("cannot read the request: {e}"))?;
    let end = all
        .iter()
        .take(REQUEST_LINE_MAX)
        .position(|b| *b == b'\n')
        .ok_or_else(|| "the request line is missing or too long".to_owned())?;
    let req: Request = serde_json::from_slice(all.get(..end).unwrap_or_default())
        .map_err(|e| format!("malformed request: {e}"))?;
    let data = all.get(end + 1..).unwrap_or_default().to_vec();
    Ok((req, data))
}

/// Serve one synchronous request from `input` to `out`: the response line,
/// then any data. Returns the exit status (non-zero only when the request
/// itself could not be read or the response not written).
pub fn serve(input: &mut impl Read, out: &mut impl Write) -> u8 {
    let (req, data) = match read_request(input) {
        Ok(r) => r,
        Err(why) => {
            let _ = writeln!(std::io::stderr().lock(), "{why}");
            return 64;
        }
    };
    let (response, payload) = match handle(&req, &data) {
        Ok((reply, payload)) => (Response::Ok { reply }, payload),
        Err(refusal) => (Response::Refused { refusal }, Vec::new()),
    };
    let Ok(mut line) = serde_json::to_vec(&response) else {
        return 70;
    };
    line.push(b'\n');
    if out.write_all(&line).is_err() || out.write_all(&payload).is_err() || out.flush().is_err() {
        return 74;
    }
    0
}

/// Split a worker's standard output into its response and the data after it.
pub fn parse_response(stdout: &[u8]) -> std::result::Result<(Response, &[u8]), String> {
    let end = stdout
        .iter()
        .position(|b| *b == b'\n')
        .ok_or_else(|| "the worker gave no response".to_owned())?;
    let response = serde_json::from_slice(stdout.get(..end).unwrap_or_default())
        .map_err(|e| format!("malformed worker response: {e}"))?;
    Ok((response, stdout.get(end + 1..).unwrap_or_default()))
}
