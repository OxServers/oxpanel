//! Small, careful file-system helpers used by the workflows.
//!
//! All writes are atomic (temp file + `rename`) and fsync'd, so a crash can
//! never leave a half-written Nginx config, unit file or record behind.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Create `dir` (and parents) if missing, then enforce `mode` on the leaf.
/// Refuses to operate through a symlink.
pub fn ensure_dir(dir: &Path, mode: u32) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(Error::Internal(format!(
                "{} is a symlink; refusing to use it",
                dir.display()
            )));
        }
        Ok(md) if !md.is_dir() => {
            return Err(Error::Internal(format!(
                "{} exists and is not a directory",
                dir.display()
            )));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(dir).map_err(|e| Error::io("mkdir", dir, e))?;
        }
        Err(e) => return Err(Error::io("lstat", dir, e)),
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(mode))
        .map_err(|e| Error::io("chmod", dir, e))
}

/// Atomically replace `path` with `contents` at `mode`. The parent directory
/// must already exist. Returns `true` if the on-disk content changed.
pub fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<bool> {
    if let Some(existing) = read_optional(path)? {
        if existing == contents && current_mode(path)? == Some(mode) {
            return Ok(false);
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| Error::Internal(format!("{} has no parent", path.display())))?;
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(Error::Internal(format!(
            "{} is a symlink; refusing to replace it",
            path.display()
        )));
    }
    let mut tmp = tempfile::Builder::new()
        .prefix(".oxpanel-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|e| Error::io("mktemp", parent, e))?;
    // fchmod, not open(2) mode bits: the result must not depend on the umask.
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|e| Error::io("fchmod", tmp.path(), e))?;
    tmp.write_all(contents)
        .map_err(|e| Error::io("write", tmp.path(), e))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| Error::io("fsync", tmp.path(), e))?;
    // `persist` uses rename(2), which atomically replaces the destination.
    tmp.persist(path)
        .map_err(|e| Error::io("rename", path, e.error))?;
    fsync_dir(parent)?;
    Ok(true)
}

/// Read a file if it exists.
pub fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io("read", path, e)),
    }
}

/// Read a regular file that another, less privileged account may have
/// written: the final component is never followed if it is a symlink, and
/// anything that is not a regular file or is larger than `max` is refused.
/// `None` if there is no such file.
pub fn read_untrusted(path: &Path, max: u64) -> Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::io("open", path, e)),
    };
    let md = file.metadata().map_err(|e| Error::io("stat", path, e))?;
    if !md.is_file() || md.len() > max {
        return Err(Error::Internal(format!(
            "{} is not a regular file of at most {max} bytes",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::io("read", path, e))?;
    if bytes.len() as u64 > max {
        return Err(Error::Internal(format!(
            "{} grew beyond {max} bytes while it was read",
            path.display()
        )));
    }
    Ok(Some(bytes))
}

/// Remove a file if it exists. Returns whether anything was removed.
pub fn remove_if_exists(path: &Path) -> Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                fsync_dir(parent)?;
            }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::io("unlink", path, e)),
    }
}

/// Remove a directory if it exists **and is empty**. Returns whether it was
/// removed. Never recursive: a directory that still has content (or is a
/// mount point) is an error, so nothing this daemon did not put there can be
/// deleted through it.
pub fn remove_empty_dir(dir: &Path) -> Result<bool> {
    match fs::remove_dir(dir) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::io("rmdir", dir, e)),
    }
}

/// Names of the entries directly inside `dir`, sorted; empty if it does not exist.
pub fn list_entry_names(dir: &Path) -> Result<Vec<String>> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io("readdir", dir, e)),
    };
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry.map_err(|e| Error::io("readdir", dir, e))?;
        out.push(entry.file_name().to_string_lossy().into_owned());
    }
    out.sort();
    Ok(out)
}

/// Remove a directory OxPanel created, with everything in it. Refuses a
/// symlink (the target is not ours). Returns whether anything was removed.
pub fn remove_dir_tree(dir: &Path) -> Result<bool> {
    match fs::symlink_metadata(dir) {
        Ok(md) if md.file_type().is_symlink() || !md.is_dir() => Err(Error::Internal(format!(
            "{} is not a directory; refusing to remove it",
            dir.display()
        ))),
        Ok(_) => {
            fs::remove_dir_all(dir).map_err(|e| Error::io("rm", dir, e))?;
            if let Some(parent) = dir.parent() {
                fsync_dir(parent)?;
            }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::io("lstat", dir, e)),
    }
}

/// Names of the directories directly inside `dir`, sorted. Symlinks are not
/// directories here. A missing `dir` is empty.
pub fn list_dirs(dir: &Path) -> Result<Vec<String>> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io("readdir", dir, e)),
    };
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry.map_err(|e| Error::io("readdir", dir, e))?;
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            out.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    out.sort();
    Ok(out)
}

/// Regular files directly inside `dir` whose name ends with `suffix`, sorted.
pub fn list_files_with_suffix(dir: &Path, suffix: &str) -> Result<Vec<PathBuf>> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io("readdir", dir, e)),
    };
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry.map_err(|e| Error::io("readdir", dir, e))?;
        let path = entry.path();
        let is_file = entry.file_type().is_ok_and(|t| t.is_file());
        if is_file
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(suffix))
        {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn current_mode(path: &Path) -> Result<Option<u32>> {
    match fs::symlink_metadata(path) {
        Ok(md) => Ok(Some(md.permissions().mode() & 0o7777)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io("lstat", path, e)),
    }
}

fn fsync_dir(dir: &Path) -> Result<()> {
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc_o_directory())
        .open(dir)
        .map_err(|e| Error::io("open", dir, e))?;
    f.sync_all().map_err(|e| Error::io("fsync", dir, e))
}

/// `O_DIRECTORY` without pulling in `libc` directly.
fn libc_o_directory() -> i32 {
    nix::fcntl::OFlag::O_DIRECTORY.bits()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_creates_replaces_and_reports_changes() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|e| Error::io("tempdir", "/tmp", e))?;
        let p = dir.path().join("a.conf");
        assert!(write_atomic(&p, b"one", 0o644)?);
        assert_eq!(read_optional(&p)?, Some(b"one".to_vec()));
        assert_eq!(current_mode(&p)?, Some(0o644));
        assert!(
            !write_atomic(&p, b"one", 0o644)?,
            "identical content is a no-op"
        );
        assert!(write_atomic(&p, b"two", 0o644)?);
        assert_eq!(read_optional(&p)?, Some(b"two".to_vec()));
        assert!(
            write_atomic(&p, b"two", 0o600)?,
            "mode change counts as a change"
        );
        assert_eq!(current_mode(&p)?, Some(0o600));
        // No temp files left behind.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .map_err(|e| Error::io("readdir", dir.path(), e))?
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".oxpanel-"))
            .collect();
        assert!(leftovers.is_empty());
        Ok(())
    }

    #[test]
    fn write_atomic_refuses_symlink_target() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|e| Error::io("tempdir", "/tmp", e))?;
        let victim = dir.path().join("victim");
        fs::write(&victim, b"keep").map_err(|e| Error::io("write", &victim, e))?;
        let link = dir.path().join("link.conf");
        std::os::unix::fs::symlink(&victim, &link).map_err(|e| Error::io("symlink", &link, e))?;
        assert!(write_atomic(&link, b"pwned", 0o644).is_err());
        assert_eq!(fs::read(&victim).ok(), Some(b"keep".to_vec()));
        Ok(())
    }

    #[test]
    fn ensure_dir_sets_mode_and_rejects_symlinks() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|e| Error::io("tempdir", "/tmp", e))?;
        let d = dir.path().join("state").join("tenants");
        ensure_dir(&d, 0o700)?;
        assert_eq!(current_mode(&d)?, Some(0o700));
        let link = dir.path().join("lnk");
        std::os::unix::fs::symlink(&d, &link).map_err(|e| Error::io("symlink", &link, e))?;
        assert!(ensure_dir(&link, 0o700).is_err());
        Ok(())
    }

    #[test]
    fn remove_empty_dir_never_removes_content() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|e| Error::io("tempdir", "/tmp", e))?;
        let d = dir.path().join("a");
        ensure_dir(&d.join("b"), 0o755)?;
        write_atomic(&d.join("b").join("keep"), b"x", 0o644)?;
        assert_eq!(list_entry_names(&d)?, vec!["b"]);
        assert!(remove_empty_dir(&d).is_err(), "not empty");
        assert!(remove_empty_dir(&d.join("b")).is_err(), "not empty");
        assert!(d.join("b").join("keep").exists());
        remove_if_exists(&d.join("b").join("keep"))?;
        assert!(remove_empty_dir(&d.join("b"))?);
        assert!(remove_empty_dir(&d)?);
        assert!(!remove_empty_dir(&d)?, "already gone");
        assert_eq!(list_entry_names(&d)?, Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn list_and_remove() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|e| Error::io("tempdir", "/tmp", e))?;
        for n in ["b.conf", "a.conf", "c.txt"] {
            write_atomic(&dir.path().join(n), b"x", 0o644)?;
        }
        fs::create_dir(dir.path().join("sub.conf"))
            .map_err(|e| Error::io("mkdir", dir.path(), e))?;
        let names: Vec<String> = list_files_with_suffix(dir.path(), ".conf")?
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        assert_eq!(names, vec!["a.conf", "b.conf"]);
        assert!(remove_if_exists(&dir.path().join("a.conf"))?);
        assert!(!remove_if_exists(&dir.path().join("a.conf"))?);
        assert_eq!(
            list_files_with_suffix(&dir.path().join("nope"), ".conf")?,
            Vec::<PathBuf>::new()
        );
        Ok(())
    }
}
