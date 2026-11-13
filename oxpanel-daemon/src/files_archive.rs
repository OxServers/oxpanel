//! Archives in the file manager, as the tenant: compressing a selection to
//! zip or tar.gz and extracting zip, tar and tar.gz. Part of the worker
//! ([`crate::files_worker`]), always run in a job unit.
//!
//! An archive is hostile input. It is parsed by our own code (the `zip`,
//! `tar` and `flate2` crates: pure Rust, no external program, so no option
//! or locale surprises), and **nothing in it is trusted**:
//!
//! - **Names** are rebuilt component by component: an absolute name or one
//!   containing `..` is refused (the entry is skipped, never "fixed"), `.`
//!   and empty components are dropped, every remaining name must pass
//!   [`check_new_name`] (no control or invisible characters) and the depth
//!   and length bounds of [`FilePath`].
//! - **Where it lands**: every directory on the way is opened from the
//!   destination's descriptor, one name at a time, with `O_NOFOLLOW` and
//!   `RESOLVE_NO_SYMLINKS` — a symlink (from the archive or already there)
//!   is never written through, and nothing can land outside the
//!   destination. Files are written under a temporary name and renamed into
//!   place, so a refused or interrupted entry leaves no partial file.
//! - **Types**: directories, regular files and symlinks only. A symlink is
//!   created only if its target is relative and stays inside the
//!   destination; a hard link becomes a copy of a file extracted before it
//!   (inside the destination). Devices, FIFOs and anything else are skipped.
//! - **Modes**: at most `0755` (no set-uid, set-gid, sticky, group or world
//!   write); the owner always keeps read and write. Owners in the archive
//!   are ignored — everything belongs to the tenant (the worker *is* the
//!   tenant).
//! - **Bombs**: the content written may not exceed `extract_max_ratio`
//!   times the archive's size (at least 1 MiB) nor `job_max_bytes`, and the
//!   archive may not have more than `extract_max_entries` entries; the
//!   tenant's disk quota is only the backstop.
//!
//! Compression never follows a symlink (it is stored as one), leaves out
//! FIFOs, sockets and devices, and reads at most `job_max_bytes`.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;

use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, ResolveFlag};
use nix::sys::stat::{fstat, fstatat, FileStat, Mode};

use crate::files_tree::{open_subdir, Budget, Notes, MAX_DEPTH};
use crate::files_worker::{
    create_exclusive, create_with_mode, discard, identity, io_fault, open_beneath, open_regular,
    os_fault, put_in_place, read_names, set_mode, shown, temp_name, ArchiveFormat, Fault, Home,
    JobSummary, Kind, Refusal, Res, NEW_DIR_MODE, NEW_FILE_MODE,
};
use crate::validate::{check_new_name, FilePath, FILE_PATH_DEPTH_MAX, FILE_PATH_MAX};

/// Longest symlink target taken from an archive.
const LINK_MAX: u64 = 4096;
/// Content always allowed whatever the ratio (tiny archives of small files).
const RATIO_FLOOR: u64 = 1 << 20;
const CHUNK: usize = 128 * 1024;

const ONE_NAME: ResolveFlag = ResolveFlag::RESOLVE_BENEATH
    .union(ResolveFlag::RESOLVE_NO_SYMLINKS)
    .union(ResolveFlag::RESOLVE_NO_XDEV);

/// The archive formats recognised by their first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sniffed {
    Zip,
    Tar,
    TarGz,
}

/// Recognise an archive by its content, never by its name.
pub fn sniff(head: &[u8]) -> Option<Sniffed> {
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        Some(Sniffed::Zip)
    } else if head.starts_with(&[0x1f, 0x8b]) {
        Some(Sniffed::TarGz)
    } else if head.get(257..262) == Some(b"ustar") {
        Some(Sniffed::Tar)
    } else {
        None
    }
}

// --- names ----------------------------------------------------------------------

/// The components an archive entry's name stands for inside the
/// destination, or why the entry is refused. `Ok(empty)` is the archive's
/// root (`./`), which is not an entry of its own.
pub fn safe_components(raw: &[u8]) -> std::result::Result<Vec<String>, &'static str> {
    let name = std::str::from_utf8(raw).map_err(|_| "its name is not UTF-8")?;
    if name.starts_with('/') {
        return Err("absolute path");
    }
    if name.len() > FILE_PATH_MAX {
        return Err("its name is too long");
    }
    let mut out = Vec::new();
    for comp in name.split('/') {
        match comp {
            "" | "." => {}
            ".." => return Err("its name contains '..'"),
            c => {
                if check_new_name(c, "name").is_err() {
                    return Err("its name contains characters the file manager does not create");
                }
                out.push(c.to_owned());
            }
        }
    }
    if out.len() > FILE_PATH_DEPTH_MAX {
        return Err("it is nested too deeply");
    }
    Ok(out)
}

/// Whether a symlink at `entry` (components inside the destination) with
/// `target` stays inside the destination when resolved there.
pub fn link_stays_inside(entry: &[String], target: &[u8]) -> bool {
    let Ok(target) = std::str::from_utf8(target) else {
        return false;
    };
    if target.is_empty() || target.starts_with('/') || target.contains('\0') {
        return false;
    }
    // Resolved from the directory that holds the link.
    let mut depth = entry.len().saturating_sub(1);
    for comp in target.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            _ => depth += 1,
        }
    }
    true
}

// --- extract --------------------------------------------------------------------

/// What an archive entry is, as far as extraction cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    Dir,
    File,
    Symlink,
    HardLink,
    Other,
}

/// The state of one extraction.
struct Extractor<'a> {
    dest: OwnedFd,
    overwrite: bool,
    budget: Budget,
    max_entries: u64,
    ratio: u64,
    seen: u64,
    summary: JobSummary,
    notes: &'a mut Notes,
}

/// Extract the archive at `archive` into the existing directory
/// `destination`. Existing files are kept (and counted as skipped) unless
/// `overwrite`; existing directories are merged into.
pub fn extract(
    home: &Home,
    archive: &FilePath,
    destination: &FilePath,
    overwrite: bool,
    notes: &mut Notes,
) -> Res<JobSummary> {
    let (fd, st) = open_regular(home, archive)?;
    let file = std::fs::File::from(fd);
    let archive_size = u64::try_from(st.st_size).unwrap_or(0);
    let mut head = vec![0u8; 512];
    let n = file
        .read_at(&mut head, 0)
        .map_err(|e| io_fault(&e, archive.as_str()))?;
    head.truncate(n);
    let format = sniff(&head).ok_or_else(|| {
        Refusal::new(
            Fault::Invalid,
            format!(
                "'{}' is not a zip, tar or tar.gz archive",
                shown(archive.as_str())
            ),
        )
    })?;
    let limits = *home.limits();
    let cap = limits.job_max_bytes.min(
        archive_size
            .saturating_mul(limits.extract_max_ratio)
            .max(RATIO_FLOOR),
    );
    let mut x = Extractor {
        dest: home.dir(destination)?,
        overwrite,
        budget: Budget::new(cap),
        max_entries: limits.extract_max_entries,
        ratio: limits.extract_max_ratio,
        seen: 0,
        summary: JobSummary::default(),
        notes,
    };
    let result = match format {
        Sniffed::Zip => x.zip(file),
        Sniffed::Tar => x.tar(file),
        Sniffed::TarGz => x.tar(flate2::read::MultiGzDecoder::new(file)),
    };
    x.summary.bytes = x.budget.used();
    x.summary.skipped = x.notes.skipped;
    result?;
    x.notes.verdict("entries could not be extracted")?;
    Ok(x.summary)
}

/// A refusal that ends the whole extraction (the others only fail an entry).
fn is_fatal(r: &Refusal) -> bool {
    matches!(r.fault, Fault::TooLarge | Fault::QuotaExceeded)
}

impl Extractor<'_> {
    fn count(&mut self) -> Res<()> {
        self.seen += 1;
        if self.seen > self.max_entries {
            return Err(Refusal::new(
                Fault::TooLarge,
                format!(
                    "the archive has more than {} entries (the file manager's limit)",
                    self.max_entries
                ),
            ));
        }
        Ok(())
    }

    fn tar(&mut self, input: impl Read) -> Res<()> {
        let bad = |e: std::io::Error| {
            Refusal::new(Fault::Invalid, format!("the archive is damaged: {e}"))
        };
        let mut archive = tar::Archive::new(input);
        for entry in archive.entries().map_err(bad)? {
            let mut entry = entry.map_err(bad)?;
            let kind = match entry.header().entry_type() {
                tar::EntryType::Directory => EntryKind::Dir,
                tar::EntryType::Regular
                | tar::EntryType::Continuous
                | tar::EntryType::GNUSparse => EntryKind::File,
                tar::EntryType::Symlink => EntryKind::Symlink,
                tar::EntryType::Link => EntryKind::HardLink,
                // Metadata of the format itself, not entries.
                tar::EntryType::XGlobalHeader | tar::EntryType::XHeader => continue,
                _ => EntryKind::Other,
            };
            self.count()?;
            let name = entry.path_bytes().into_owned();
            let link = entry.link_name_bytes().map(std::borrow::Cow::into_owned);
            let mode = entry.header().mode().unwrap_or(NEW_FILE_MODE);
            let mtime = entry.header().mtime().ok();
            if let Err(r) = self.place(&name, kind, mode, mtime, link.as_deref(), &mut entry) {
                if is_fatal(&r) {
                    return Err(r);
                }
                self.notes.fail(r);
            }
        }
        Ok(())
    }

    fn zip(&mut self, input: std::fs::File) -> Res<()> {
        let mut archive = zip::ZipArchive::new(input)
            .map_err(|e| Refusal::new(Fault::Invalid, format!("the archive is damaged: {e}")))?;
        if archive.len() as u64 > self.max_entries {
            return Err(Refusal::new(
                Fault::TooLarge,
                format!(
                    "the archive has {} entries; at most {} are extracted",
                    archive.len(),
                    self.max_entries
                ),
            ));
        }
        for i in 0..archive.len() {
            self.count()?;
            let mut file = match archive.by_index(i) {
                Ok(f) => f,
                Err(e) => {
                    self.notes.skip(
                        &format!("entry {i}"),
                        &format!(
                            "cannot be read ({e}; encrypted or an unsupported compression method)"
                        ),
                    );
                    continue;
                }
            };
            let name = file.name_raw().to_vec();
            let name = match file.name() {
                Ok(n) => n.as_bytes().to_vec(),
                Err(_) => name,
            };
            let kind = if file.is_dir() {
                EntryKind::Dir
            } else if file.is_symlink() {
                EntryKind::Symlink
            } else if file.is_file() {
                EntryKind::File
            } else {
                EntryKind::Other
            };
            let mode = file.unix_mode().unwrap_or(NEW_FILE_MODE);
            let link = if kind == EntryKind::Symlink {
                let mut target = Vec::new();
                (&mut file)
                    .take(LINK_MAX)
                    .read_to_end(&mut target)
                    .map_err(|e| {
                        Refusal::new(Fault::Invalid, format!("the archive is damaged: {e}"))
                    })?;
                Some(target)
            } else {
                None
            };
            if let Err(r) = self.place(&name, kind, mode, None, link.as_deref(), &mut file) {
                if is_fatal(&r) {
                    return Err(r);
                }
                self.notes.fail(r);
            }
        }
        Ok(())
    }

    /// Put one entry in place.
    fn place(
        &mut self,
        raw: &[u8],
        kind: EntryKind,
        mode: u32,
        mtime: Option<u64>,
        link: Option<&[u8]>,
        data: &mut dyn Read,
    ) -> Res<()> {
        let shown_name = String::from_utf8_lossy(raw).into_owned();
        let comps = match safe_components(raw) {
            Ok(c) if c.is_empty() => return Ok(()),
            Ok(c) => c,
            Err(why) => {
                self.notes.skip(&shown_name, why);
                return Ok(());
            }
        };
        let path = comps.join("/");
        let Some((last, parents)) = comps.split_last() else {
            return Ok(());
        };
        let Some(parent) = self.parent_dir(parents, &path)? else {
            return Ok(());
        };
        match kind {
            EntryKind::Dir => self.directory(&parent, last, mode, &path),
            EntryKind::File => self.file(&parent, last, mode, mtime, data, &path),
            EntryKind::Symlink => match link {
                Some(target) if link_stays_inside(&comps, target) => {
                    self.symlink(&parent, last, target, &path)
                }
                _ => {
                    self.notes
                        .skip(&path, "a symbolic link leading outside the destination");
                    Ok(())
                }
            },
            EntryKind::HardLink => {
                let source = link.map(safe_components);
                match source {
                    Some(Ok(source)) if !source.is_empty() => {
                        self.hard_link(&parent, last, &source, mode, &path)
                    }
                    _ => {
                        self.notes
                            .skip(&path, "a hard link to something outside the destination");
                        Ok(())
                    }
                }
            }
            EntryKind::Other => {
                self.notes.skip(
                    &path,
                    "not a file, directory or symbolic link (device, FIFO, …)",
                );
                Ok(())
            }
        }
    }

    /// The directory that will hold an entry, created as needed, reached
    /// from the destination one name at a time without following any
    /// symlink. `None` (entry skipped) if something in the way is not a
    /// directory.
    fn parent_dir(&mut self, parents: &[String], path: &str) -> Res<Option<OwnedFd>> {
        let mut cur = self.dest.try_clone().map_err(|e| io_fault(&e, path))?;
        for comp in parents {
            cur = match self.subdir(&cur, comp, path)? {
                Some(fd) => fd,
                None => return Ok(None),
            };
        }
        Ok(Some(cur))
    }

    /// `name` in `dir` as a directory, created if missing.
    fn subdir(&mut self, dir: &OwnedFd, name: &str, path: &str) -> Res<Option<OwnedFd>> {
        let name_os = OsStr::new(name);
        match open_subdir(dir, name_os) {
            Ok(fd) => return Ok(Some(fd)),
            Err(Errno::ENOENT) => {}
            Err(Errno::ENOTDIR | Errno::ELOOP) => {
                self.notes.skip(
                    path,
                    "something on its way is not a directory (or is a symbolic link)",
                );
                return Ok(None);
            }
            Err(e) => return Err(os_fault(e, path)),
        }
        match nix::sys::stat::mkdirat(dir, name_os, Mode::from_bits_truncate(NEW_DIR_MODE)) {
            Ok(()) => self.summary.entries += 1,
            Err(Errno::EEXIST) => {}
            Err(e) => return Err(os_fault(e, path)),
        }
        let fd = open_subdir(dir, name_os).map_err(|e| os_fault(e, path))?;
        Ok(Some(fd))
    }

    fn directory(&mut self, parent: &OwnedFd, name: &str, mode: u32, path: &str) -> Res<()> {
        let existed = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW).is_ok();
        let Some(fd) = self.subdir(parent, name, path)? else {
            return Ok(());
        };
        if !existed || self.overwrite {
            set_mode(&fd, (mode & 0o755) | 0o700, path)?;
        }
        Ok(())
    }

    /// Whether an entry may be written at `name`: nothing there, or (with
    /// `overwrite`) something that is not a directory.
    fn may_write(&mut self, parent: &OwnedFd, name: &str, path: &str) -> Res<bool> {
        match fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Err(Errno::ENOENT) => Ok(true),
            Err(e) => Err(os_fault(e, path)),
            Ok(st) if Kind::of(&st) == Kind::Directory => {
                self.notes.skip(path, "a directory of that name exists");
                Ok(false)
            }
            Ok(_) if self.overwrite => Ok(true),
            Ok(_) => {
                self.notes.skip(path, "exists");
                Ok(false)
            }
        }
    }

    fn file(
        &mut self,
        parent: &OwnedFd,
        name: &str,
        mode: u32,
        mtime: Option<u64>,
        data: &mut dyn Read,
        path: &str,
    ) -> Res<()> {
        if !self.may_write(parent, name, path)? {
            return Ok(());
        }
        let tmp = temp_name();
        let mut out = create_exclusive(parent, &tmp, path)?;
        let done = self
            .pour(data, &mut out, path)
            .and_then(|()| set_mode(&out, (mode & 0o755) | 0o600, path))
            .and_then(|()| match mtime.and_then(|m| i64::try_from(m).ok()) {
                Some(m) => {
                    let t = nix::sys::time::TimeSpec::new(m, 0);
                    nix::sys::stat::futimens(&out, &t, &t).map_err(|e| os_fault(e, path))
                }
                None => Ok(()),
            })
            .and_then(|()| put_in_place(parent, &tmp, name, self.overwrite, path));
        if let Err(r) = done {
            discard(parent, &tmp);
            return Err(r);
        }
        self.summary.entries += 1;
        Ok(())
    }

    /// Copy an entry's content, counting every byte against the budget.
    fn pour(&mut self, data: &mut dyn Read, out: &mut std::fs::File, path: &str) -> Res<()> {
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = match data.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(Refusal::new(
                        Fault::Invalid,
                        format!("'{}': the archive is damaged: {e}", shown(path)),
                    ))
                }
            };
            self.budget.take(n as u64).map_err(|_| {
                Refusal::new(
                    Fault::TooLarge,
                    format!(
                        "the archive expands to more than {} bytes (at most {}× its size, and never more than the file manager's limit); extraction stopped",
                        self.budget.limit(),
                        self.ratio
                    ),
                )
            })?;
            out.write_all(buf.get(..n).unwrap_or_default())
                .map_err(|e| io_fault(&e, path))?;
        }
    }

    fn symlink(&mut self, parent: &OwnedFd, name: &str, target: &[u8], path: &str) -> Res<()> {
        if !self.may_write(parent, name, path)? {
            return Ok(());
        }
        let tmp = temp_name();
        nix::unistd::symlinkat(OsStr::from_bytes(target), parent, tmp.as_str())
            .map_err(|e| os_fault(e, path))?;
        if let Err(r) = put_in_place(parent, &tmp, name, self.overwrite, path) {
            discard(parent, &tmp);
            return Err(r);
        }
        self.summary.entries += 1;
        Ok(())
    }

    /// A hard link becomes a copy of the (regular) file it names, which
    /// must be inside the destination; it is reached without following
    /// any symlink.
    fn hard_link(
        &mut self,
        parent: &OwnedFd,
        name: &str,
        source: &[String],
        mode: u32,
        path: &str,
    ) -> Res<()> {
        let src = open_beneath(
            &self.dest,
            OsStr::new(&source.join("/")),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
            0,
            ONE_NAME,
        );
        let src = match src.and_then(|fd| fstat(&fd).map(|st| (fd, st))) {
            Ok((fd, st)) if Kind::of(&st) == Kind::File => fd,
            _ => {
                self.notes.skip(
                    path,
                    "a hard link to something that is not an extracted file",
                );
                return Ok(());
            }
        };
        let mut src = std::fs::File::from(src);
        self.file(parent, name, mode, None, &mut src, path)
    }
}

// --- compress -------------------------------------------------------------------

/// Where compressed entries go: a zip or a tar.gz being written.
trait Sink {
    fn dir(&mut self, path: &str, st: &FileStat) -> Res<()>;
    fn file(&mut self, path: &str, st: &FileStat, data: &mut dyn Read) -> Res<()>;
    fn symlink(&mut self, path: &str, st: &FileStat, target: &[u8]) -> Res<()>;
}

fn archive_error(e: impl std::fmt::Display) -> Refusal {
    Refusal::new(
        Fault::Failed,
        format!("the archive could not be written: {e}"),
    )
}

struct TarSink {
    builder: tar::Builder<flate2::write::GzEncoder<std::fs::File>>,
}

fn tar_header(kind: tar::EntryType, st: &FileStat, size: u64) -> tar::Header {
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(kind);
    h.set_mode(st.st_mode & 0o755);
    h.set_mtime(u64::try_from(st.st_mtime).unwrap_or(0));
    h.set_size(size);
    h.set_uid(0);
    h.set_gid(0);
    h
}

impl Sink for TarSink {
    fn dir(&mut self, path: &str, st: &FileStat) -> Res<()> {
        let mut h = tar_header(tar::EntryType::Directory, st, 0);
        self.builder
            .append_data(&mut h, format!("{path}/"), std::io::empty())
            .map_err(archive_error)
    }

    fn file(&mut self, path: &str, st: &FileStat, data: &mut dyn Read) -> Res<()> {
        let size = u64::try_from(st.st_size).unwrap_or(0);
        let mut h = tar_header(tar::EntryType::Regular, st, size);
        // Exactly `size` bytes, whatever happens to the file meanwhile.
        let exact = data.take(size).chain(std::io::repeat(0)).take(size);
        self.builder
            .append_data(&mut h, path, exact)
            .map_err(archive_error)
    }

    fn symlink(&mut self, path: &str, st: &FileStat, target: &[u8]) -> Res<()> {
        let mut h = tar_header(tar::EntryType::Symlink, st, 0);
        self.builder
            .append_link(&mut h, path, OsStr::from_bytes(target))
            .map_err(archive_error)
    }
}

struct ZipSink {
    writer: zip::ZipWriter<std::fs::File>,
}

/// Civil date of a day count since 1970-01-01 (proleptic Gregorian).
fn civil(days: i64) -> (i64, u8, u8) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u8::try_from(month).unwrap_or(1),
        u8::try_from(day).unwrap_or(1),
    )
}

/// A zip timestamp for a UNIX time (UTC), clamped to what zip can hold.
pub fn zip_time(unix: i64) -> zip::DateTime {
    let (year, month, day) = civil(unix.div_euclid(86_400));
    let secs = unix.rem_euclid(86_400);
    let part = |n: i64| u8::try_from(n).unwrap_or(0);
    let year = u16::try_from(year.clamp(1980, 2107)).unwrap_or(1980);
    zip::DateTime::from_date_and_time(
        year,
        month,
        day,
        part(secs / 3600),
        part(secs / 60 % 60),
        part(secs % 60),
    )
    .unwrap_or_default()
}

impl ZipSink {
    fn options(st: &FileStat, size: u64) -> zip::write::SimpleFileOptions {
        zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(st.st_mode & 0o755)
            .last_modified_time(zip_time(st.st_mtime))
            .large_file(size >= u64::from(u32::MAX))
    }
}

impl Sink for ZipSink {
    fn dir(&mut self, path: &str, st: &FileStat) -> Res<()> {
        self.writer
            .add_directory(format!("{path}/"), Self::options(st, 0))
            .map_err(archive_error)
    }

    fn file(&mut self, path: &str, st: &FileStat, data: &mut dyn Read) -> Res<()> {
        let size = u64::try_from(st.st_size).unwrap_or(0);
        self.writer
            .start_file(path, Self::options(st, size))
            .map_err(archive_error)?;
        std::io::copy(&mut data.take(size), &mut self.writer).map_err(archive_error)?;
        Ok(())
    }

    fn symlink(&mut self, path: &str, st: &FileStat, target: &[u8]) -> Res<()> {
        self.writer
            .add_symlink(path, String::from_utf8_lossy(target), Self::options(st, 0))
            .map_err(archive_error)
    }
}

/// The state of one compression.
struct Packer<'a> {
    budget: Budget,
    /// The archive being written: never put into itself.
    skip: (u64, u64),
    summary: JobSummary,
    notes: &'a mut Notes,
    zip_names: bool,
}

/// Compress `names` (entries of `directory`) into a new archive at
/// `archive`. Entries are named relative to `directory`.
pub fn compress(
    home: &Home,
    directory: &FilePath,
    names: &[String],
    archive: &FilePath,
    format: ArchiveFormat,
    overwrite: bool,
    notes: &mut Notes,
) -> Res<JobSummary> {
    let dir = home.dir(directory)?;
    let (out_dir, out_name) = home.parent_of(archive)?;
    match fstatat(&out_dir, out_name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW) {
        Err(Errno::ENOENT) => {}
        Ok(st) if Kind::of(&st) == Kind::Directory => {
            return Err(os_fault(Errno::EISDIR, archive.as_str()))
        }
        Ok(_) if overwrite => {}
        Ok(_) => return Err(os_fault(Errno::EEXIST, archive.as_str())),
        Err(e) => return Err(os_fault(e, archive.as_str())),
    }
    let tmp = temp_name();
    let file = create_with_mode(&out_dir, &tmp, NEW_FILE_MODE, archive.as_str())?;
    let st = fstat(&file).map_err(|e| os_fault(e, archive.as_str()))?;
    let mut packer = Packer {
        budget: Budget::new(home.limits().job_max_bytes),
        skip: identity(&st),
        summary: JobSummary::default(),
        notes,
        zip_names: format == ArchiveFormat::Zip,
    };
    let written = match format {
        ArchiveFormat::TarGz => {
            let mut sink = TarSink {
                builder: tar::Builder::new(flate2::write::GzEncoder::new(
                    file,
                    flate2::Compression::default(),
                )),
            };
            packer.all(&dir, names, &mut sink).and_then(|()| {
                let gz = sink.builder.into_inner().map_err(archive_error)?;
                gz.finish().map_err(archive_error)
            })
        }
        ArchiveFormat::Zip => {
            let mut sink = ZipSink {
                writer: zip::ZipWriter::new(file),
            };
            packer
                .all(&dir, names, &mut sink)
                .and_then(|()| sink.writer.finish().map_err(archive_error))
        }
    };
    // An archive missing entries that could not be read is not delivered.
    let written = written.and_then(|f| {
        packer
            .notes
            .verdict("entries could not be archived")
            .map(|()| f)
    });
    let done = written.and_then(|mut f| {
        f.flush().map_err(|e| io_fault(&e, archive.as_str()))?;
        f.sync_all().map_err(|e| io_fault(&e, archive.as_str()))?;
        put_in_place(&out_dir, &tmp, &out_name, overwrite, archive.as_str())
    });
    if let Err(r) = done {
        discard(&out_dir, &tmp);
        return Err(r);
    }
    packer.summary.bytes = packer.budget.used();
    packer.summary.skipped = packer.notes.skipped;
    packer.notes.verdict("entries could not be archived")?;
    Ok(packer.summary)
}

impl Packer<'_> {
    fn all(&mut self, dir: &OwnedFd, names: &[String], sink: &mut dyn Sink) -> Res<()> {
        for name in names {
            if name.contains('/') || name.is_empty() || name == "." || name == ".." {
                return Err(Refusal::new(
                    Fault::Invalid,
                    format!("'{}' is not a name in the directory", shown(name)),
                ));
            }
            self.entry(dir, OsStr::new(name), name, 0, sink)?;
        }
        Ok(())
    }

    fn entry(
        &mut self,
        dir: &OwnedFd,
        name: &OsStr,
        path: &str,
        depth: usize,
        sink: &mut dyn Sink,
    ) -> Res<()> {
        let st = match fstatat(dir, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(e) => {
                self.notes.fail(os_fault(e, path));
                return Ok(());
            }
        };
        if identity(&st) == self.skip
            || std::str::from_utf8(name.as_bytes())
                .is_ok_and(|n| n.starts_with(crate::files_worker::TEMP_PREFIX))
        {
            return Ok(());
        }
        if self.zip_names && name.to_str().is_none() {
            self.notes
                .skip(path, "its name is not UTF-8 (zip needs UTF-8 names)");
            return Ok(());
        }
        match Kind::of(&st) {
            Kind::Directory => self.directory(dir, name, &st, path, depth, sink),
            Kind::File => {
                let size = u64::try_from(st.st_size).unwrap_or(0);
                self.budget.take(size)?;
                let fd = open_beneath(
                    dir,
                    name,
                    OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
                    0,
                    ONE_NAME,
                );
                match fd.and_then(|fd| fstat(&fd).map(|again| (fd, again))) {
                    Ok((fd, again)) if identity(&again) == identity(&st) => {
                        let mut file = std::fs::File::from(fd);
                        sink.file(path, &st, &mut file)?;
                        self.summary.entries += 1;
                    }
                    Ok(_) => self.notes.skip(path, "it changed while it was archived"),
                    Err(e) => self.notes.fail(os_fault(e, path)),
                }
                Ok(())
            }
            Kind::Symlink => {
                match nix::fcntl::readlinkat(dir, name) {
                    Ok(target) => {
                        sink.symlink(path, &st, target.as_bytes())?;
                        self.summary.entries += 1;
                    }
                    Err(e) => self.notes.fail(os_fault(e, path)),
                }
                Ok(())
            }
            _ => {
                self.notes
                    .skip(path, "not a file, directory or symbolic link");
                Ok(())
            }
        }
    }

    fn directory(
        &mut self,
        dir: &OwnedFd,
        name: &OsStr,
        st: &FileStat,
        path: &str,
        depth: usize,
        sink: &mut dyn Sink,
    ) -> Res<()> {
        if depth >= MAX_DEPTH {
            return Err(Refusal::new(
                Fault::TooLarge,
                format!("'{}': more than {MAX_DEPTH} levels deep", shown(path)),
            ));
        }
        sink.dir(path, st)?;
        self.summary.entries += 1;
        let sub = match open_subdir(dir, name) {
            Ok(fd) => fd,
            Err(e) => {
                self.notes.fail(os_fault(e, path));
                return Ok(());
            }
        };
        let (names, _) = read_names(&sub, u64::MAX)?;
        for (child, _) in names {
            let child = OsStr::from_bytes(&child);
            let child_path = format!("{path}/{}", child.to_string_lossy());
            self.entry(&sub, child, &child_path, depth + 1, sink)?;
        }
        Ok(())
    }
}
