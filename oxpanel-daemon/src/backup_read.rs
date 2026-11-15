//! Reading one file of a sealed backup, chunk by chunk, so that a panel can
//! offer the backup as a download (`ReadBackupMember`).
//!
//! - Only a file the backup's record lists (`members[].name`) or its
//!   `manifest.json` is handed out: the request names a member, never a path.
//! - The backup is looked up *for the tenant* and must have been taken from
//!   the tenant's current uid, as for a restore; anything else does not
//!   exist (`NOT_FOUND`). Only a READY backup is read.
//! - The file is opened beneath the backup directory without following any
//!   symlink (`openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`), must be
//!   a regular file and must still have the size recorded when the backup was
//!   sealed (the manifest: exactly the manifest of the record); otherwise
//!   `FAILED_PRECONDITION`, and nothing is read.
//! - At most [`MAX_CHUNK`] bytes are read per request, with `pread`, from an
//!   offset: the file is never held in memory whole.

use std::ffi::OsStr;
use std::os::unix::fs::FileExt as _;

use nix::fcntl::{OFlag, ResolveFlag};
use nix::sys::stat::Mode;

use super::{BackupService, MANIFEST};
use crate::error::{Error, Result};
use crate::records::{BackupRecord, BackupState};
use crate::validate::{BackupId, Username};

/// Largest chunk one request returns (and the default).
pub const MAX_CHUNK: u32 = 1024 * 1024;
/// A member name is a file name the engine chose; nothing longer exists.
const MAX_MEMBER_CHARS: usize = 255;

/// One chunk of a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberChunk {
    pub data: Vec<u8>,
    /// The whole member's size.
    pub size: u64,
    /// `offset + data.len()` reached the end.
    pub eof: bool,
}

/// What a request may name: a plain file name, nothing that could be read
/// as a path. Which names exist is decided by the record afterwards.
fn member_name(raw: &str) -> Result<&str> {
    let bad = |why: &str| Error::invalid("member", why.to_owned());
    if raw.is_empty() {
        return Err(bad("must not be empty"));
    }
    if raw.chars().count() > MAX_MEMBER_CHARS {
        return Err(bad("is too long"));
    }
    if raw == "." || raw == ".." || raw.starts_with('.') {
        return Err(bad("is not a file of a backup"));
    }
    if !raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(bad(
            "is a file name of the backup (letters, digits, '.', '_', '-'), never a path",
        ));
    }
    Ok(raw)
}

/// The requested chunk length: 0 means [`MAX_CHUNK`].
fn chunk_len(length: u32) -> Result<u32> {
    match length {
        0 => Ok(MAX_CHUNK),
        n if n <= MAX_CHUNK => Ok(n),
        _ => Err(Error::invalid(
            "length",
            format!("must be at most {MAX_CHUNK} bytes"),
        )),
    }
}

/// The size the member must have, by the record. `None` for the manifest,
/// whose content is checked instead.
fn recorded_size(rec: &BackupRecord, member: &str) -> Result<Option<u64>> {
    if member == MANIFEST {
        return Ok(None);
    }
    rec.members
        .iter()
        .find(|m| m.name == member)
        .map(|m| Some(m.size_bytes))
        .ok_or_else(|| {
            Error::invalid(
                "member",
                format!("backup {} has no file '{member}'", rec.id),
            )
        })
}

impl BackupService {
    /// Read `length` bytes (0 = [`MAX_CHUNK`]) of `member` of `tenant`'s
    /// backup `backup_id` from `offset`.
    pub async fn read_member(
        &self,
        tenant: &str,
        backup_id: &str,
        member: &str,
        offset: u64,
        length: u32,
    ) -> Result<MemberChunk> {
        let name = Username::parse_field(tenant, "tenant")?;
        let id = BackupId::parse(backup_id)?;
        let member = member_name(member)?.to_owned();
        let length = chunk_len(length)?;
        let rec = {
            // Records are read under the lock so that a backup being sealed
            // or deleted is seen before or after, never half-way.
            let _guard = self.ctx.lock.lock().await;
            let tenant_rec = self.ready_tenant(&name)?;
            let rec = self.backup_of(&name, &id)?;
            if rec.uid != tenant_rec.uid {
                // Taken from an earlier account of the same name.
                return Err(Error::BackupNotFound {
                    tenant: name.to_string(),
                    id: id.to_string(),
                });
            }
            rec
        };
        if rec.state != BackupState::Ready {
            return Err(Error::BackupNotReady(id.to_string()));
        }
        let expected = recorded_size(&rec, &member)?;
        let dir = self.ctx.config.backup_dir.clone();
        tokio::task::spawn_blocking(move || {
            read_chunk(&dir, &name, &rec, &member, expected, offset, length)
        })
        .await
        .map_err(|e| Error::Internal(format!("backup read task: {e}")))?
    }
}

/// Open the member beneath `<backup_dir>` (`<tenant>/<id>/<member>`, no
/// symlink anywhere), check it and read one chunk.
fn read_chunk(
    backup_dir: &std::path::Path,
    tenant: &Username,
    rec: &BackupRecord,
    member: &str,
    expected: Option<u64>,
    offset: u64,
    length: u32,
) -> Result<MemberChunk> {
    let changed = || Error::BackupMemberChanged {
        id: rec.id.clone(),
        member: member.to_owned(),
    };
    let root = nix::fcntl::open(
        backup_dir,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| Error::io("open", backup_dir, std::io::Error::from(e)))?;
    let relative = format!("{tenant}/{}/{member}", rec.id);
    let fd = crate::files_worker::open_beneath(
        &root,
        OsStr::new(&relative),
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
        0,
        ResolveFlag::RESOLVE_BENEATH
            | ResolveFlag::RESOLVE_NO_SYMLINKS
            | ResolveFlag::RESOLVE_NO_MAGICLINKS
            | ResolveFlag::RESOLVE_NO_XDEV,
    )
    .map_err(|_| changed())?;
    let file = std::fs::File::from(fd);
    let md = file
        .metadata()
        .map_err(|e| Error::io("stat", backup_dir, e))?;
    if !md.is_file() {
        return Err(changed());
    }
    let size = md.len();
    match expected {
        Some(want) if want != size => return Err(changed()),
        Some(_) => {}
        None => {
            // The manifest is small (bounded by the record); compare it whole.
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(
                &mut std::io::Read::take(&file, u64::from(MAX_CHUNK) * 4),
                &mut bytes,
            )
            .map_err(|e| Error::io("read", backup_dir, e))?;
            if !super::manifest_matches(rec, &bytes)? {
                return Err(changed());
            }
        }
    }
    let start = offset.min(size);
    let want = usize::try_from(u64::from(length).min(size - start)).unwrap_or(0);
    let mut data = vec![0u8; want];
    let mut got = 0usize;
    while got < want {
        let at = start + got as u64;
        let n = file
            .read_at(data.get_mut(got..).unwrap_or_default(), at)
            .map_err(|e| Error::io("read", backup_dir, e))?;
        if n == 0 {
            // Shorter than it was a moment ago: changed underneath us.
            return Err(changed());
        }
        got += n;
    }
    Ok(MemberChunk {
        eof: start + got as u64 >= size,
        data,
        size,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn only_plain_file_names_are_members() {
        for ok in [
            "home.tar.gz",
            "records.json",
            "manifest.json",
            "db-shop.sql.gz",
        ] {
            assert_eq!(member_name(ok).unwrap(), ok);
        }
        for bad in [
            "",
            ".",
            "..",
            "../home.tar.gz",
            "a/b",
            "/etc/passwd",
            ".hidden",
            "home.tar.gz\0",
            "nl\n",
            "sp ace",
        ] {
            assert!(member_name(bad).is_err(), "{bad:?}");
        }
        assert!(member_name(&"a".repeat(256)).is_err());
    }

    #[test]
    fn chunks_are_at_most_one_mebibyte() {
        assert_eq!(chunk_len(0).unwrap(), MAX_CHUNK);
        assert_eq!(chunk_len(10).unwrap(), 10);
        assert_eq!(chunk_len(MAX_CHUNK).unwrap(), MAX_CHUNK);
        assert!(chunk_len(MAX_CHUNK + 1).is_err());
    }
}
