//! The daemon's boundary with the operating system.
//!
//! This is the *only* module that spawns processes or queries the account
//! database. Everything goes through the [`System`] trait so the workflows in
//! [`crate::tenant`] and [`crate::vhost`] can be exercised end-to-end against
//! [`FakeSystem`] in tests, and so a future privilege-separated helper process
//! can slot in behind the same interface.
//!
//! Security invariants enforced here:
//! - Programs are referenced by absolute path ([`bin`]); `PATH` is never searched.
//! - Arguments are passed as discrete argv entries — there is no shell anywhere.
//! - Anything executed on a tenant's behalf runs with the tenant's uid/gid,
//!   an empty supplementary-group list, an empty capability bounding set and
//!   `no_new_privs` (see [`CommandSpec::exec_plan`]).

use std::path::{Path, PathBuf};

use crate::error::Result;

pub mod command;
pub mod fake;
mod fake_mariadb;
pub mod fake_tls;
pub mod real;

pub use command::{CommandOutput, CommandSpec, RunAs, Secret};
pub use fake::FakeSystem;
pub use real::RealSystem;

/// Absolute paths of every external program the daemon is permitted to execute.
pub mod bin {
    pub const USERADD: &str = "/usr/sbin/useradd";
    pub const USERDEL: &str = "/usr/sbin/userdel";
    pub const NGINX: &str = "/usr/sbin/nginx";
    pub const SYSTEMCTL: &str = "/usr/bin/systemctl";
    pub const RESTORECON: &str = "/usr/sbin/restorecon";
    pub const SELINUXENABLED: &str = "/usr/sbin/selinuxenabled";
    pub const SETFACL: &str = "/usr/bin/setfacl";
    pub const SEMANAGE: &str = "/usr/sbin/semanage";
    pub const SEMODULE: &str = "/usr/sbin/semodule";
    pub const GETSEBOOL: &str = "/usr/sbin/getsebool";
    pub const SETPRIV: &str = "/usr/bin/setpriv";
    pub const MKDIR: &str = "/usr/bin/mkdir";
    pub const DU: &str = "/usr/bin/du";
    /// Optional: only needed once a virtual host enables PHP.
    pub const PHP_FPM: &str = "/usr/sbin/php-fpm";
    /// Optional: only needed once a virtual host runs such an application.
    pub const NODE: &str = "/usr/bin/node";
    pub const NPM: &str = "/usr/bin/npm";
    pub const PYTHON3: &str = "/usr/bin/python3";
    pub const ENV: &str = "/usr/bin/env";
    /// Runs dependency installation outside the daemon's network-less sandbox.
    pub const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
    pub const JOURNALCTL: &str = "/usr/bin/journalctl";
    /// Optional: only needed once a virtual host gets a certificate. Inspects
    /// certificates and generates the keys and signing requests for ACME.
    pub const OPENSSL: &str = "/usr/bin/openssl";
    /// OxPanel's own ACME client. Never run by the daemon itself (which has no
    /// network) but in a transient unit, as an unprivileged account.
    pub const OXPANEL_ACME: &str = "/usr/libexec/oxpanel/oxpanel-acme";
    /// Optional: the MariaDB client, only needed once tenants have databases.
    pub const MARIADB: &str = "/usr/bin/mariadb";
    /// Backups of tenant databases: run as root by the job's worker, over
    /// the UNIX socket, never with a password.
    pub const MARIADB_DUMP: &str = "/usr/bin/mariadb-dump";
    /// Backups: the archiver and its compressor, both run as the tenant.
    pub const TAR: &str = "/usr/bin/tar";
    /// Backups: finds what the archive leaves out (run as the tenant).
    pub const FIND: &str = "/usr/bin/find";
    pub const GZIP: &str = "/usr/bin/gzip";
    /// Login shell given to every tenant account.
    pub const NOLOGIN: &str = "/sbin/nologin";
    /// Membership of the group that confines tenants in sshd.
    pub const GPASSWD: &str = "/usr/bin/gpasswd";
    /// Optional: only needed for SFTP access (`sshd -t`, `sshd -T`).
    pub const SSHD: &str = "/usr/sbin/sshd";
    /// Sets a tenant's SFTP password from stdin (`user:password`), so the
    /// password is never in an argv.
    pub const CHPASSWD: &str = "/usr/sbin/chpasswd";
    /// Locks and unlocks a password hash (suspension).
    pub const USERMOD: &str = "/usr/sbin/usermod";
    /// Removes empty SFTP chroot directories (run through `systemd-run`, in
    /// the host's mount namespace).
    pub const RMDIR: &str = "/usr/bin/rmdir";
    /// Optional: only needed for disk quotas (XFS).
    pub const XFS_QUOTA: &str = "/usr/sbin/xfs_quota";
}

/// A resolved account from the system user database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    pub shell: PathBuf,
}

/// Load, memory and disk figures of the host.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct HostStats {
    /// 1, 5 and 15 minute load averages.
    pub load: (f64, f64, f64),
    pub memory_total_bytes: u64,
    pub memory_free_bytes: u64,
    pub uptime_secs: u64,
    /// Size and unprivileged-available space of the queried file system.
    pub disk_total_bytes: u64,
    pub disk_free_bytes: u64,
}

/// What the file system holding a path can do about disk quotas.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QuotaState {
    /// File-system type (`xfs`, `ext4`, …); empty if it could not be determined.
    pub fs_type: String,
    /// The block device it is mounted from, as the host names it.
    pub device: PathBuf,
    /// Per-user quotas are accounted *and* enforced by the kernel.
    pub user_quota_enforced: bool,
}

/// Find the file system with device number `major:minor` in the text of
/// `/proc/self/mountinfo` and report its type, source and quota state.
///
/// Only XFS is supported: its super-block options show `usrquota` when user
/// quotas are enforced (`uqnoenforce` when they are merely accounted, and
/// `noquota` otherwise).
pub fn parse_mountinfo(text: &str, major: u64, minor: u64) -> Option<QuotaState> {
    let wanted = format!("{major}:{minor}");
    text.lines().find_map(|line| {
        // "<id> <parent> <maj:min> <root> <mount point> <options> [tags…] - <type> <source> <super options>"
        let (mount, fs) = line.split_once(" - ")?;
        if mount.split(' ').nth(2)? != wanted {
            return None;
        }
        let mut fs = fs.split(' ');
        let (fs_type, device, options) = (fs.next()?, fs.next()?, fs.next().unwrap_or(""));
        Some(QuotaState {
            fs_type: fs_type.to_owned(),
            device: PathBuf::from(device),
            user_quota_enforced: fs_type == "xfs" && options.split(',').any(|o| o == "usrquota"),
        })
    })
}

/// What the password field of an account in `/etc/shadow` amounts to. The
/// hash itself never leaves [`System`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordState {
    /// No such account in the shadow file.
    Missing,
    /// No password can match (`!!`, `!`, `*`, …): how `useradd` leaves it.
    NoPassword,
    /// A hash that a login can match.
    Usable,
    /// A hash disabled by a leading `!` (`usermod --lock`).
    Locked,
    /// An empty field: *any* password matches. Never wanted.
    Empty,
}

/// Classify the password field of `user` in the text of `/etc/shadow`.
pub fn shadow_password_state(text: &str, user: &str) -> PasswordState {
    let Some(field) = text.lines().find_map(|line| {
        let mut f = line.splitn(3, ':');
        (f.next() == Some(user)).then(|| f.next().unwrap_or(""))
    }) else {
        return PasswordState::Missing;
    };
    if field.is_empty() {
        return PasswordState::Empty;
    }
    let unlocked = field.trim_start_matches('!');
    if unlocked.is_empty() || unlocked.starts_with('*') {
        PasswordState::NoPassword
    } else if unlocked.len() == field.len() {
        PasswordState::Usable
    } else {
        PasswordState::Locked
    }
}

/// Operating-system primitives the daemon depends on.
#[tonic::async_trait]
pub trait System: Send + Sync + 'static {
    /// Execute an external program and collect its output. Non-zero exit is
    /// *not* an error here; see [`CommandOutput::into_result`].
    async fn run(&self, spec: CommandSpec) -> Result<CommandOutput>;

    /// Execute and require exit status 0.
    async fn run_ok(&self, spec: CommandSpec) -> Result<CommandOutput> {
        self.run(spec).await?.into_result()
    }

    async fn user_by_name(&self, name: &str) -> Result<Option<OsUser>>;
    async fn user_by_uid(&self, uid: u32) -> Result<Option<OsUser>>;
    /// Returns the gid of the named group, if it exists.
    async fn group_by_name(&self, name: &str) -> Result<Option<u32>>;
    /// All groups (primary included) of the named account, as `getgrouplist(3)` reports them.
    async fn groups_of(&self, name: &str, primary_gid: u32) -> Result<Vec<u32>>;

    /// Make sure `path` is an existing directory (not a symlink) owned by
    /// `uid:gid`, owner `rwx`, nothing for `other`, no special bits; corrects
    /// owner and those bits if necessary. Group bits are left untouched
    /// because they carry the ACL mask once web access has been granted.
    async fn ensure_private_dir(&self, path: &Path, uid: u32, gid: u32) -> Result<()>;

    /// Verify `path` is a real directory (not a symlink) owned by `uid`.
    /// Returns [`crate::Error::InvalidInput`] otherwise.
    async fn verify_owned_dir(&self, path: &Path, uid: u32) -> Result<()>;

    /// Read-only counterpart of [`System::ensure_private_dir`]: `None` when
    /// `path` is a real directory owned by `uid:gid` and closed to "other",
    /// otherwise a description of what is wrong. Never changes anything.
    async fn inspect_private_dir(&self, path: &Path, uid: u32, gid: u32) -> Result<Option<String>>;

    /// Whether `program` is installed (a regular, executable file).
    async fn is_installed(&self, program: &'static str) -> bool;

    /// Host load and memory, plus the capacity of the file system holding `path`.
    async fn host_stats(&self, path: &Path) -> Result<HostStats>;

    /// Quota support of the file system holding `path`. Read-only.
    async fn quota_state(&self, path: &Path) -> Result<QuotaState>;

    /// The state of an account's password in the shadow database. Read-only.
    async fn password_state(&self, user: &str) -> Result<PasswordState>;
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTINFO: &str = "\
23 70 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc rw
70 1 252:4 / / rw,relatime shared:1 - xfs /dev/vda4 rw,seclabel,attr2,inode64,logbufs=8,logbsize=32k,usrquota
92 70 252:3 / /boot rw,relatime shared:40 - xfs /dev/vda3 rw,seclabel,attr2,inode64,noquota
95 92 252:2 / /boot/efi rw,relatime shared:47 - vfat /dev/vda2 rw,fmask=0077
99 70 252:5 / /data rw,relatime - xfs /dev/mapper/vg-data rw,attr2,uqnoenforce
100 70 252:6 / /old rw,relatime - ext4 /dev/vda6 rw,usrquota
";

    #[test]
    fn shadow_fields_are_classified_without_exposing_them() {
        let text = "root:$6$abc$def:19000:0:99999:7:::
alice:!!:20000:0:99999:7:::
bob:$6$salt$hash:20000::::::
carol:!$6$salt$hash:20000::::::
dave::20000::::::
erin:*:20000::::::
frank:!*:20000::::::
";
        for (user, want) in [
            ("alice", PasswordState::NoPassword),
            ("bob", PasswordState::Usable),
            ("carol", PasswordState::Locked),
            ("dave", PasswordState::Empty),
            ("erin", PasswordState::NoPassword),
            ("frank", PasswordState::NoPassword),
            ("ghost", PasswordState::Missing),
            ("ali", PasswordState::Missing),
        ] {
            assert_eq!(shadow_password_state(text, user), want, "{user}");
        }
    }

    #[test]
    fn mountinfo_tells_whether_user_quotas_are_enforced() {
        let root = parse_mountinfo(MOUNTINFO, 252, 4);
        assert_eq!(
            root,
            Some(QuotaState {
                fs_type: "xfs".into(),
                device: PathBuf::from("/dev/vda4"),
                user_quota_enforced: true,
            })
        );
        let enforced =
            |minor| parse_mountinfo(MOUNTINFO, 252, minor).map(|q| q.user_quota_enforced);
        assert_eq!(enforced(3), Some(false), "noquota");
        assert_eq!(enforced(5), Some(false), "accounted but not enforced");
        assert_eq!(enforced(6), Some(false), "only XFS is supported");
        assert_eq!(
            parse_mountinfo(MOUNTINFO, 252, 5).map(|q| q.device),
            Some(PathBuf::from("/dev/mapper/vg-data"))
        );
        assert_eq!(parse_mountinfo(MOUNTINFO, 8, 1), None);
        assert_eq!(parse_mountinfo("garbage\n\n", 252, 4), None);
    }
}
