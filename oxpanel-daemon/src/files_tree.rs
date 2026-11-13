//! Walking a tenant's directory trees, as the tenant: search, size, delete
//! and copy. Part of the worker ([`crate::files_worker`]).
//!
//! Every walk goes from descriptor to descriptor: a subdirectory is opened
//! relative to its parent's descriptor with `O_NOFOLLOW` and
//! `RESOLVE_NO_SYMLINKS`, never by a path string. A symlink in the tree is
//! therefore never followed (copied as a link, removed as a link, not
//! descended into), a directory renamed or swapped for a symlink half-way
//! through cannot redirect the walk, and no path ever gets longer than one
//! name — a tree deeper than `PATH_MAX` is handled like any other up to
//! [`MAX_DEPTH`] levels, beyond which the walk refuses rather than running
//! out of descriptors.
//!
//! Bounds: searches and size computations stop after `walk_max_entries`
//! entries or `walk_max_secs` seconds and say so; a copy may write at most
//! `job_max_bytes` of content (holes in sparse files are kept as holes and
//! cost nothing); every job also runs under its unit's time limit and the
//! tenant's slice and disk quota.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::time::Instant;

use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, ResolveFlag};
use nix::sys::stat::{fstat, fstatat, FileStat, Mode};
use nix::unistd::{unlinkat, UnlinkatFlags, Whence};

use crate::files_worker::{
    child_path, chmod_opath, create_exclusive, discard, entry_of, identity, io_fault, open_beneath,
    os_fault, put_in_place, read_names, set_mode, shown, temp_name, Entry, Fault, Home, JobSummary,
    Kind, Refusal, Reply, Res,
};
use crate::validate::FilePath;

/// Deepest directory level a walk descends to.
pub const MAX_DEPTH: usize = 256;
/// Names read from one directory at a time while deleting or copying.
const BATCH: u64 = 10_000;
/// Problems named one by one in a job's output; the count is always complete.
const NOTES_KEPT: usize = 20;
const COPY_CHUNK: usize = 128 * 1024;

const ONE_NAME: ResolveFlag = ResolveFlag::RESOLVE_BENEATH
    .union(ResolveFlag::RESOLVE_NO_SYMLINKS)
    .union(ResolveFlag::RESOLVE_NO_XDEV);

/// What a job noticed on the way: entries it left out and entries it could
/// not handle. The first [`NOTES_KEPT`] are described.
#[derive(Debug, Default)]
pub struct Notes {
    pub lines: Vec<String>,
    pub skipped: u64,
    pub failed: u64,
    pub first_failure: Option<Refusal>,
}

impl Notes {
    fn note(&mut self, line: String) {
        if self.lines.len() < NOTES_KEPT {
            self.lines.push(line);
        }
    }

    /// An entry deliberately left out.
    pub fn skip(&mut self, path: &str, why: &str) {
        self.skipped += 1;
        self.note(format!("skipped '{}': {why}", shown(path)));
    }

    /// An entry that could not be handled; the job will fail.
    pub fn fail(&mut self, r: Refusal) {
        self.failed += 1;
        self.note(format!("failed: {}", r.message));
        if self.first_failure.is_none() {
            self.first_failure = Some(r);
        }
    }

    /// The job's verdict: `Ok` unless something failed.
    pub fn verdict(&self, what: &str) -> Res<()> {
        match &self.first_failure {
            None => Ok(()),
            Some(first) => Err(Refusal::new(
                first.fault,
                format!(
                    "{} {what} failed (the first: {})",
                    self.failed, first.message
                ),
            )),
        }
    }
}

/// How many bytes a job may still write.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub left: u64,
    limit: u64,
}

impl Budget {
    pub fn new(limit: u64) -> Self {
        Self { left: limit, limit }
    }

    /// Account for `n` more bytes, or refuse.
    pub fn take(&mut self, n: u64) -> Res<()> {
        if n > self.left {
            return Err(Refusal::new(
                Fault::TooLarge,
                format!(
                    "the job would write more than {} bytes (the file manager's limit)",
                    self.limit
                ),
            ));
        }
        self.left -= n;
        Ok(())
    }

    pub fn used(&self) -> u64 {
        self.limit - self.left
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }
}

fn name_text(name: &OsStr) -> String {
    name.to_string_lossy().into_owned()
}

/// Open the subdirectory `name` of `dir` without following a symlink.
pub fn open_subdir(dir: impl AsFd, name: &OsStr) -> std::result::Result<OwnedFd, Errno> {
    open_beneath(
        dir,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
        0,
        ONE_NAME,
    )
}

/// One directory waiting to be walked.
struct Pending {
    fd: OwnedFd,
    path: String,
    depth: usize,
}

/// Visit every entry below `root` (not following symlinks) until `visit`
/// says stop or a bound is reached. Returns (entries seen, truncated).
fn walk(
    home: &Home,
    root: &FilePath,
    mut visit: impl FnMut(&OwnedFd, &OsStr, &FileStat, &str) -> bool,
) -> Res<(u64, bool)> {
    let limits = *home.limits();
    let started = Instant::now();
    let mut stack = vec![Pending {
        fd: home.dir(root)?,
        path: root.as_str().to_owned(),
        depth: 0,
    }];
    let mut seen: u64 = 0;
    while let Some(dir) = stack.pop() {
        let remaining = limits.walk_max_entries.saturating_sub(seen);
        let (names, cut) = read_names(&dir.fd, remaining)?;
        for (name, _) in names {
            seen += 1;
            if seen.is_multiple_of(1024) && started.elapsed().as_secs() >= limits.walk_max_secs {
                return Ok((seen, true));
            }
            let name = OsStr::from_bytes(&name);
            let Ok(st) = fstatat(&dir.fd, name, AtFlags::AT_SYMLINK_NOFOLLOW) else {
                continue;
            };
            let path = child_path(&dir.path, &name_text(name));
            if !visit(&dir.fd, name, &st, &path) {
                return Ok((seen, true));
            }
            if Kind::of(&st) == Kind::Directory && dir.depth + 1 < MAX_DEPTH {
                if let Ok(fd) = open_subdir(&dir.fd, name) {
                    stack.push(Pending {
                        fd,
                        path,
                        depth: dir.depth + 1,
                    });
                }
            }
        }
        if cut || seen >= limits.walk_max_entries {
            return Ok((seen, true));
        }
    }
    Ok((seen, false))
}

/// Entries below `root` whose name contains `needle` (case-insensitive).
pub fn search(home: &Home, root: &FilePath, needle: &str, max_results: u64) -> Res<Reply> {
    let needle = needle.to_lowercase();
    let mut matches: Vec<Entry> = Vec::new();
    let mut full = false;
    let (scanned, truncated) = walk(home, root, |_, name, st, path| {
        if name_text(name).to_lowercase().contains(&needle) {
            if matches.len() as u64 >= max_results {
                full = true;
                return false;
            }
            let mut e = entry_of(name, st);
            e.path = Some(path.to_owned());
            matches.push(e);
        }
        true
    })?;
    Ok(Reply::Found {
        matches,
        scanned,
        truncated: truncated || full,
    })
}

/// Space used below `root`: allocated and apparent bytes, files and
/// directories (a file with several links in the tree counts once).
pub fn size(home: &Home, root: &FilePath) -> Res<Reply> {
    let top = home.lstat(root)?;
    let (mut allocated, mut apparent) = (0u64, 0u64);
    let (mut files, mut directories) = (0u64, 0u64);
    let mut linked: HashSet<(u64, u64)> = HashSet::new();
    let mut add = |st: &FileStat| {
        if st.st_nlink > 1 && Kind::of(st) != Kind::Directory && !linked.insert(identity(st)) {
            return;
        }
        allocated = allocated.saturating_add(u64::try_from(st.st_blocks).unwrap_or(0) * 512);
        apparent = apparent.saturating_add(u64::try_from(st.st_size).unwrap_or(0));
        if Kind::of(st) == Kind::Directory {
            directories += 1;
        } else {
            files += 1;
        }
    };
    add(&top);
    let truncated = if Kind::of(&top) == Kind::Directory {
        walk(home, root, |_, _, st, _| {
            add(st);
            true
        })?
        .1
    } else {
        false
    };
    Ok(Reply::Size {
        allocated,
        apparent,
        files,
        directories,
        truncated,
    })
}

// --- delete --------------------------------------------------------------------

/// Remove every path (files, symlinks — never what they point to — and
/// whole trees). A path that is already gone is not an error. The home,
/// document and application roots and the directories leading to them are
/// refused.
pub fn delete(home: &mut Home, paths: &[FilePath], notes: &mut Notes) -> Res<JobSummary> {
    let mut summary = JobSummary::default();
    for path in paths {
        let (dir, name) = home.parent_of(path)?;
        let st = match fstatat(&dir, name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(Errno::ENOENT) => continue,
            Err(e) => {
                notes.fail(os_fault(e, path.as_str()));
                continue;
            }
        };
        home.check_unprotected(&st, path.as_str())?;
        if Kind::of(&st) == Kind::Directory {
            remove_tree(
                &dir,
                OsStr::new(&name),
                path.as_str(),
                0,
                &mut summary,
                notes,
            );
        } else {
            match unlinkat(&dir, name.as_str(), UnlinkatFlags::NoRemoveDir) {
                Ok(()) | Err(Errno::ENOENT) => summary.entries += 1,
                Err(e) => notes.fail(os_fault(e, path.as_str())),
            }
        }
    }
    notes.verdict("entries could not be removed")?;
    Ok(summary)
}

/// Make a directory of the tenant's that it has closed to itself (mode
/// 0500, 0000) workable again, so its content can be removed.
fn reopen_writable(parent: &OwnedFd, name: &OsStr, path: &str) -> Res<OwnedFd> {
    let probe = open_beneath(
        parent,
        name,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
        0,
        ONE_NAME,
    )
    .map_err(|e| os_fault(e, path))?;
    chmod_opath(&probe, 0o700, path)?;
    open_subdir(parent, name).map_err(|e| os_fault(e, path))
}

fn remove_tree(
    parent: &OwnedFd,
    name: &OsStr,
    path: &str,
    depth: usize,
    summary: &mut JobSummary,
    notes: &mut Notes,
) {
    if depth >= MAX_DEPTH {
        notes.fail(Refusal::new(
            Fault::TooLarge,
            format!("'{}': more than {MAX_DEPTH} levels deep", shown(path)),
        ));
        return;
    }
    let dir = match open_subdir(parent, name) {
        Ok(fd) => fd,
        Err(Errno::EACCES) => match reopen_writable(parent, name, path) {
            Ok(fd) => fd,
            Err(r) => return notes.fail(r),
        },
        Err(Errno::ENOENT) => return,
        Err(e) => return notes.fail(os_fault(e, path)),
    };
    let mut made_writable = false;
    loop {
        let names = match read_names(&dir, BATCH) {
            Ok((names, _)) => names,
            Err(r) => return notes.fail(r),
        };
        if names.is_empty() {
            break;
        }
        let failed_before = notes.failed;
        let mut removed = 0;
        for (child, kind) in names {
            let child = OsStr::from_bytes(&child);
            let child_path = child_path(path, &name_text(child));
            let is_dir = kind.map_or_else(
                || {
                    fstatat(&dir, child, AtFlags::AT_SYMLINK_NOFOLLOW)
                        .is_ok_and(|st| Kind::of(&st) == Kind::Directory)
                },
                |k| k == Kind::Directory,
            );
            if is_dir {
                let before = summary.entries;
                remove_tree(&dir, child, &child_path, depth + 1, summary, notes);
                removed += usize::from(summary.entries > before);
                continue;
            }
            let mut result = unlinkat(&dir, child, UnlinkatFlags::NoRemoveDir);
            if result == Err(Errno::EACCES) && !made_writable {
                // A directory of its own the tenant made read-only.
                made_writable = true;
                let _ = set_mode(&dir, 0o700, path);
                result = unlinkat(&dir, child, UnlinkatFlags::NoRemoveDir);
            }
            match result {
                Ok(()) | Err(Errno::ENOENT) => {
                    summary.entries += 1;
                    removed += 1;
                }
                Err(e) => notes.fail(os_fault(e, &child_path)),
            }
        }
        if removed == 0 && notes.failed > failed_before {
            // Nothing more can go: do not read the same names again.
            return;
        }
    }
    match unlinkat(parent, name, UnlinkatFlags::RemoveDir) {
        Ok(()) | Err(Errno::ENOENT) => summary.entries += 1,
        Err(e) => notes.fail(os_fault(e, path)),
    }
}

// --- copy ----------------------------------------------------------------------

/// The state of one copy job.
struct Copier<'a> {
    budget: Budget,
    overwrite: bool,
    /// Directories this copy created (and the destination): never copied
    /// from, so copying a directory into itself terminates.
    created: HashSet<(u64, u64)>,
    summary: JobSummary,
    notes: &'a mut Notes,
}

/// Copy every source into `destination` under its own name. Directories
/// are copied with their content (merged into an existing directory of
/// the same name), symlinks as symlinks, files with their holes, mode
/// (without set-uid/set-gid/sticky or world-write) and modification time.
/// FIFOs, sockets and devices are left out. An existing file is replaced
/// only with `overwrite` (otherwise left and counted as skipped).
pub fn copy(
    home: &Home,
    sources: &[FilePath],
    destination: &FilePath,
    overwrite: bool,
    notes: &mut Notes,
) -> Res<JobSummary> {
    let dest = home.dir(destination)?;
    let dest_st = fstat(&dest).map_err(|e| os_fault(e, destination.as_str()))?;
    let mut copier = Copier {
        budget: Budget::new(home.limits().job_max_bytes),
        overwrite,
        created: HashSet::from([identity(&dest_st)]),
        summary: JobSummary::default(),
        notes,
    };
    for source in sources {
        let (dir, name) = home.parent_of(source)?;
        let target = child_path(destination.as_str(), &name);
        let step = Step {
            from_dir: &dir,
            to_dir: &dest,
            name: OsStr::new(&name),
            from: source.as_str(),
            to: &target,
            depth: 0,
        };
        if let Err(r) = copier.entry(&step) {
            if r.fault == Fault::TooLarge || r.fault == Fault::QuotaExceeded {
                return Err(r);
            }
            copier.notes.fail(r);
        }
    }
    copier.summary.bytes = copier.budget.used();
    copier.summary.skipped = copier.notes.skipped;
    copier.notes.verdict("entries could not be copied")?;
    Ok(copier.summary)
}

/// One entry to copy: `name` in `from_dir` to the same name in `to_dir`
/// (`from` and `to` are the paths for messages).
struct Step<'a> {
    from_dir: &'a OwnedFd,
    to_dir: &'a OwnedFd,
    name: &'a OsStr,
    from: &'a str,
    to: &'a str,
    depth: usize,
}

impl Copier<'_> {
    fn entry(&mut self, s: &Step<'_>) -> Res<()> {
        let st = fstatat(s.from_dir, s.name, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|e| os_fault(e, s.from))?;
        match Kind::of(&st) {
            Kind::File => self.file(s, &st),
            Kind::Directory => self.directory(s, &st),
            Kind::Symlink => self.symlink(s),
            _ => {
                self.notes
                    .skip(s.from, "not a file, directory or symbolic link");
                Ok(())
            }
        }
    }

    /// What is at the target now: `Ok(true)` if the copy may write it.
    fn may_replace(&mut self, s: &Step<'_>) -> Res<bool> {
        match fstatat(s.to_dir, s.name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Err(Errno::ENOENT) => Ok(true),
            Err(e) => Err(os_fault(e, s.to)),
            Ok(st) if Kind::of(&st) == Kind::Directory => {
                self.notes.skip(s.to, "a directory of that name exists");
                Ok(false)
            }
            Ok(_) if self.overwrite => Ok(true),
            Ok(_) => {
                self.notes.skip(s.to, "exists");
                Ok(false)
            }
        }
    }

    fn file(&mut self, s: &Step<'_>, st: &FileStat) -> Res<()> {
        if !self.may_replace(s)? {
            return Ok(());
        }
        let src = open_beneath(
            s.from_dir,
            s.name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
            0,
            ONE_NAME,
        )
        .map_err(|e| os_fault(e, s.from))?;
        let src_st = fstat(&src).map_err(|e| os_fault(e, s.from))?;
        if identity(&src_st) != identity(st) || Kind::of(&src_st) != Kind::File {
            return Err(Refusal::new(
                Fault::Failed,
                format!("'{}' changed while it was copied", shown(s.from)),
            ));
        }
        let tmp = temp_name();
        let mut out = create_exclusive(s.to_dir, &tmp, s.to)?;
        let src = std::fs::File::from(src);
        let done = copy_sparse(&src, &mut out, &mut self.budget, s.from, s.to)
            .and_then(|()| set_mode(&out, st.st_mode & crate::validate::FILE_MODE_ALLOWED, s.to))
            .and_then(|()| {
                let atime = nix::sys::time::TimeSpec::new(st.st_atime, st.st_atime_nsec);
                let mtime = nix::sys::time::TimeSpec::new(st.st_mtime, st.st_mtime_nsec);
                nix::sys::stat::futimens(&out, &atime, &mtime).map_err(|e| os_fault(e, s.to))
            })
            .and_then(|()| {
                put_in_place(
                    s.to_dir,
                    &tmp,
                    &s.name.to_string_lossy(),
                    self.overwrite,
                    s.to,
                )
            });
        if let Err(r) = done {
            discard(s.to_dir, &tmp);
            return Err(r);
        }
        self.summary.entries += 1;
        Ok(())
    }

    fn directory(&mut self, s: &Step<'_>, st: &FileStat) -> Res<()> {
        if self.created.contains(&identity(st)) {
            self.notes.skip(s.from, "it is the copy's own destination");
            return Ok(());
        }
        if s.depth >= MAX_DEPTH {
            return Err(Refusal::new(
                Fault::TooLarge,
                format!("'{}': more than {MAX_DEPTH} levels deep", shown(s.from)),
            ));
        }
        match nix::sys::stat::mkdirat(s.to_dir, s.name, Mode::from_bits_truncate(0o700)) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(e) => return Err(os_fault(e, s.to)),
        }
        let target = match open_subdir(s.to_dir, s.name) {
            Ok(fd) => fd,
            Err(Errno::ENOTDIR | Errno::ELOOP) => {
                self.notes
                    .skip(s.to, "something that is not a directory has that name");
                return Ok(());
            }
            Err(e) => return Err(os_fault(e, s.to)),
        };
        let target_st = fstat(&target).map_err(|e| os_fault(e, s.to))?;
        self.created.insert(identity(&target_st));
        let source = open_subdir(s.from_dir, s.name).map_err(|e| os_fault(e, s.from))?;
        let (names, _) = read_names(&source, u64::MAX)?;
        for (child, _) in names {
            let child = OsStr::from_bytes(&child);
            let text = name_text(child);
            let (from, to) = (child_path(s.from, &text), child_path(s.to, &text));
            let next = Step {
                from_dir: &source,
                to_dir: &target,
                name: child,
                from: &from,
                to: &to,
                depth: s.depth + 1,
            };
            if let Err(r) = self.entry(&next) {
                if r.fault == Fault::TooLarge || r.fault == Fault::QuotaExceeded {
                    return Err(r);
                }
                self.notes.fail(r);
            }
        }
        set_mode(
            &target,
            (st.st_mode & crate::validate::FILE_MODE_ALLOWED) | 0o700,
            s.to,
        )?;
        self.summary.entries += 1;
        Ok(())
    }

    fn symlink(&mut self, s: &Step<'_>) -> Res<()> {
        if !self.may_replace(s)? {
            return Ok(());
        }
        let target: OsString =
            nix::fcntl::readlinkat(s.from_dir, s.name).map_err(|e| os_fault(e, s.from))?;
        let tmp = temp_name();
        nix::unistd::symlinkat(target.as_os_str(), s.to_dir, tmp.as_str())
            .map_err(|e| os_fault(e, s.to))?;
        if let Err(r) = put_in_place(
            s.to_dir,
            &tmp,
            &s.name.to_string_lossy(),
            self.overwrite,
            s.to,
        ) {
            discard(s.to_dir, &tmp);
            return Err(r);
        }
        self.summary.entries += 1;
        Ok(())
    }
}

/// Copy a regular file's content, data region by data region, so holes stay
/// holes; every byte written counts against `budget`.
pub fn copy_sparse(
    src: &std::fs::File,
    out: &mut std::fs::File,
    budget: &mut Budget,
    from: &str,
    to: &str,
) -> Res<()> {
    let size = src.metadata().map_err(|e| io_fault(&e, from))?.len();
    let mut pos: u64 = 0;
    let mut buf = vec![0u8; COPY_CHUNK];
    while pos < size {
        let at = i64::try_from(pos).unwrap_or(i64::MAX);
        let data = match nix::unistd::lseek(src, at, Whence::SeekData) {
            Ok(d) => u64::try_from(d).unwrap_or(size),
            // No data after `pos`: the rest is a hole.
            Err(Errno::ENXIO) => break,
            Err(e) => return Err(os_fault(e, from)),
        };
        let hole = match nix::unistd::lseek(
            src,
            i64::try_from(data).unwrap_or(i64::MAX),
            Whence::SeekHole,
        ) {
            Ok(h) => u64::try_from(h).unwrap_or(size),
            Err(e) => return Err(os_fault(e, from)),
        }
        .min(size);
        let mut at = data;
        while at < hole {
            let want = usize::try_from((hole - at).min(COPY_CHUNK as u64)).unwrap_or(COPY_CHUNK);
            let Some(chunk) = buf.get_mut(..want) else {
                break;
            };
            let n = src.read_at(chunk, at).map_err(|e| io_fault(&e, from))?;
            if n == 0 {
                break;
            }
            budget.take(n as u64)?;
            out.write_all_at(chunk.get(..n).unwrap_or_default(), at)
                .map_err(|e| io_fault(&e, to))?;
            at += n as u64;
        }
        pos = hole.max(data + 1);
    }
    out.set_len(size).map_err(|e| io_fault(&e, to))
}
