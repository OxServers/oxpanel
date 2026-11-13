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
pub mod real;

pub use command::{CommandOutput, CommandSpec, RunAs};
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
    /// Backups: the archiver and its compressor, both run as the tenant.
    pub const TAR: &str = "/usr/bin/tar";
    /// Backups: finds what the archive leaves out (run as the tenant).
    pub const FIND: &str = "/usr/bin/find";
    pub const GZIP: &str = "/usr/bin/gzip";
    /// Login shell given to every tenant account.
    pub const NOLOGIN: &str = "/sbin/nologin";
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
}
