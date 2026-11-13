//! systemd integration: per-tenant slices carrying cgroups-v2 resource limits.
//!
//! systemd owns the cgroup tree on RHEL-family systems (the "single writer"
//! rule), so the daemon never touches `/sys/fs/cgroup` directly. Instead each
//! tenant gets:
//!
//! - `oxpanel-tenant-<name>.slice` — the slice future tenant services
//!   (PHP-FPM pools, cron, …) are placed in via `Slice=`;
//! - a drop-in for `user-<uid>.slice` so any login session (SFTP, SSH) the
//!   tenant may later be granted is bounded by the same limits.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::Result;
use crate::system::{bin, CommandSpec, System};
use crate::validate::{Limits, Username};

const HEADER: &str = "# Managed by oxpanel-daemon. Manual edits will be overwritten.\n";
const UNIT_MODE: u32 = 0o644;
const DIR_MODE: u32 = 0o755;

/// systemd unit-name escaping for the tenant component.
///
/// `-` is the *hierarchy separator* in slice names (`a-b.slice` is a child of
/// `a.slice`), so tenant `foo-bar` must not become a child of tenant `foo` and
/// inherit its limits. `systemd-escape` renders `-` as `\x2d`; validated
/// names contain nothing else that needs escaping.
pub fn escape_unit_component(name: &str) -> String {
    name.replace('-', "\\x2d")
}

/// The unit name systemd requires for a mount at `path` (`systemd-escape
/// --path --suffix=mount`): components joined by `-`, with a literal `-`
/// written as `\x2d` and a leading `.` as `\x2e`. Refuses anything but the
/// characters validated paths consist of, so nothing else ever needs escaping.
pub fn mount_unit_name(path: &Path) -> Result<String> {
    use std::path::Component;
    let refuse = || {
        crate::Error::Internal(format!(
            "{} cannot be used as a mount point",
            path.display()
        ))
    };
    crate::nginx::safe_path_str(path)?;
    let mut name = String::new();
    for component in path.components() {
        let part = match component {
            Component::RootDir => continue,
            Component::Normal(part) => part.to_str().ok_or_else(refuse)?,
            _ => return Err(refuse()),
        };
        if !name.is_empty() {
            name.push('-');
        }
        for (i, c) in part.chars().enumerate() {
            match c {
                '-' => name.push_str("\\x2d"),
                '.' if i == 0 && name.is_empty() => name.push_str("\\x2e"),
                c => name.push(c),
            }
        }
    }
    if name.is_empty() {
        return Err(refuse());
    }
    name.push_str(".mount");
    Ok(name)
}

/// `oxpanel-tenant-<escaped name>.slice`
pub fn slice_unit_name(name: &Username) -> String {
    format!(
        "oxpanel-tenant-{}.slice",
        escape_unit_component(name.as_str())
    )
}

/// Paths of the files written for one tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantUnits {
    pub slice_unit: PathBuf,
    pub user_slice_dropin_dir: PathBuf,
    pub user_slice_dropin: PathBuf,
}

impl TenantUnits {
    pub fn for_tenant(unit_dir: &Path, name: &Username, uid: u32) -> Self {
        let dropin_dir = unit_dir.join(format!("user-{uid}.slice.d"));
        Self {
            slice_unit: unit_dir.join(slice_unit_name(name)),
            user_slice_dropin: dropin_dir.join("50-oxpanel.conf"),
            user_slice_dropin_dir: dropin_dir,
        }
    }
}

fn slice_section(limits: &Limits) -> String {
    use std::fmt::Write as _;
    let mut s = String::from("[Slice]\n");
    if let Some(b) = limits.memory_max_bytes {
        let _ = writeln!(s, "MemoryMax={b}");
        // Disallow swapping past the limit as well; otherwise MemoryMax is porous.
        s.push_str("MemorySwapMax=0\n");
    }
    if let Some(w) = limits.cpu_weight {
        let _ = writeln!(s, "CPUWeight={w}");
    }
    if let Some(w) = limits.io_weight {
        let _ = writeln!(s, "IOWeight={w}");
    }
    if let Some(t) = limits.tasks_max {
        let _ = writeln!(s, "TasksMax={t}");
    }
    s
}

/// Contents of `oxpanel-tenant-<name>.slice`.
pub fn render_slice_unit(name: &Username, limits: &Limits) -> String {
    format!(
        "{HEADER}[Unit]\nDescription=OxPanel tenant {name}\nDocumentation=https://github.com/OxServers/oxpanel\nBefore=slices.target\n\n{}",
        slice_section(limits)
    )
}

/// Contents of `user-<uid>.slice.d/50-oxpanel.conf`.
pub fn render_user_slice_dropin(name: &Username, limits: &Limits) -> String {
    format!(
        "{HEADER}# Login-session limits for OxPanel tenant {name}\n{}",
        slice_section(limits)
    )
}

/// Write (or refresh) both unit files and reload systemd if anything changed.
pub async fn apply_tenant_limits(
    sys: &dyn System,
    unit_dir: &Path,
    name: &Username,
    uid: u32,
    limits: &Limits,
    timeout: Duration,
) -> Result<()> {
    let units = TenantUnits::for_tenant(unit_dir, name, uid);
    crate::fsutil::ensure_dir(&units.user_slice_dropin_dir, DIR_MODE)?;
    let changed_a = crate::fsutil::write_atomic(
        &units.slice_unit,
        render_slice_unit(name, limits).as_bytes(),
        UNIT_MODE,
    )?;
    let changed_b = crate::fsutil::write_atomic(
        &units.user_slice_dropin,
        render_user_slice_dropin(name, limits).as_bytes(),
        UNIT_MODE,
    )?;
    if changed_a || changed_b {
        daemon_reload(sys, timeout).await?;
    }
    Ok(())
}

/// Remove the tenant's unit files and reload systemd.
pub async fn remove_tenant_limits(
    sys: &dyn System,
    unit_dir: &Path,
    name: &Username,
    uid: u32,
    timeout: Duration,
) -> Result<()> {
    let units = TenantUnits::for_tenant(unit_dir, name, uid);
    let a = crate::fsutil::remove_if_exists(&units.slice_unit)?;
    let b = crate::fsutil::remove_if_exists(&units.user_slice_dropin)?;
    // The drop-in directory is ours alone; remove it if now empty.
    let _ = std::fs::remove_dir(&units.user_slice_dropin_dir);
    if a || b {
        daemon_reload(sys, timeout).await?;
    }
    Ok(())
}

pub async fn daemon_reload(sys: &dyn System, timeout: Duration) -> Result<()> {
    sys.run_ok(CommandSpec::new(bin::SYSTEMCTL, timeout).arg("daemon-reload"))
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::FakeSystem;

    fn alice() -> Username {
        Username::parse("alice").unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn renders_only_requested_limits() {
        let limits = Limits {
            memory_max_bytes: Some(536_870_912),
            cpu_weight: Some(50),
            io_weight: None,
            tasks_max: Some(200),
            ..Limits::default()
        };
        let unit = render_slice_unit(&alice(), &limits);
        assert!(unit.starts_with(HEADER));
        assert!(unit.contains("Description=OxPanel tenant alice\n"));
        assert!(unit.contains(
            "[Slice]\nMemoryMax=536870912\nMemorySwapMax=0\nCPUWeight=50\nTasksMax=200\n"
        ));
        assert!(!unit.contains("IOWeight"));
        let none = render_slice_unit(&alice(), &Limits::default());
        assert!(none.ends_with("[Slice]\n"));
    }

    #[test]
    fn dashes_are_escaped_so_tenants_never_nest() {
        let n = Username::parse("foo-bar-1").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            slice_unit_name(&n),
            "oxpanel-tenant-foo\\x2dbar\\x2d1.slice"
        );
        assert_eq!(slice_unit_name(&alice()), "oxpanel-tenant-alice.slice");
        assert_eq!(escape_unit_component("a_b"), "a_b");
    }

    #[test]
    fn mount_unit_names_follow_systemd_escaping() -> Result<()> {
        // Expected values are the output of `systemd-escape --path --suffix=mount`.
        for (path, unit) in [
            (
                "/var/lib/oxpanel/sftp/alice/home/alice",
                "var-lib-oxpanel-sftp-alice-home-alice.mount",
            ),
            (
                "/var/lib/oxpanel/sftp/foo-bar/srv/web-homes_v2/foo-bar",
                "var-lib-oxpanel-sftp-foo\\x2dbar-srv-web\\x2dhomes_v2-foo\\x2dbar.mount",
            ),
            ("/.hidden/a.b", "\\x2ehidden-a.b.mount"),
            ("/srv//x/", "srv-x.mount"),
        ] {
            assert_eq!(mount_unit_name(Path::new(path))?, unit, "{path}");
        }
        for bad in ["/", "relative/x", "/a b", "/a/../b", "/a\nb"] {
            assert!(mount_unit_name(Path::new(bad)).is_err(), "{bad:?}");
        }
        Ok(())
    }

    #[test]
    fn unit_paths() {
        let u = TenantUnits::for_tenant(Path::new("/etc/systemd/system"), &alice(), 20000);
        assert_eq!(
            u.slice_unit,
            PathBuf::from("/etc/systemd/system/oxpanel-tenant-alice.slice")
        );
        assert_eq!(
            u.user_slice_dropin,
            PathBuf::from("/etc/systemd/system/user-20000.slice.d/50-oxpanel.conf")
        );
    }

    #[tokio::test]
    async fn apply_writes_files_and_reloads_once_then_is_idempotent() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|e| crate::Error::io("tempdir", "/tmp", e))?;
        let sys = FakeSystem::new();
        let t = Duration::from_secs(5);
        let limits = Limits {
            cpu_weight: Some(10),
            ..Limits::default()
        };
        apply_tenant_limits(&sys, dir.path(), &alice(), 20000, &limits, t).await?;
        assert_eq!(sys.calls_to(bin::SYSTEMCTL).len(), 1);
        assert!(dir.path().join("oxpanel-tenant-alice.slice").is_file());
        assert!(dir
            .path()
            .join("user-20000.slice.d/50-oxpanel.conf")
            .is_file());
        apply_tenant_limits(&sys, dir.path(), &alice(), 20000, &limits, t).await?;
        assert_eq!(
            sys.calls_to(bin::SYSTEMCTL).len(),
            1,
            "no reload when nothing changed"
        );
        remove_tenant_limits(&sys, dir.path(), &alice(), 20000, t).await?;
        assert_eq!(sys.calls_to(bin::SYSTEMCTL).len(), 2);
        assert!(!dir.path().join("oxpanel-tenant-alice.slice").exists());
        assert!(!dir.path().join("user-20000.slice.d").exists());
        remove_tenant_limits(&sys, dir.path(), &alice(), 20000, t).await?;
        assert_eq!(
            sys.calls_to(bin::SYSTEMCTL).len(),
            2,
            "no reload when nothing removed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn reload_failure_propagates() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let sys = FakeSystem::new();
        sys.script_failure(bin::SYSTEMCTL, 1, "Failed to reload daemon");
        let r = apply_tenant_limits(
            &sys,
            dir.path(),
            &alice(),
            20000,
            &Limits::default(),
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(r, Err(crate::Error::CommandFailed { .. })));
    }
}
