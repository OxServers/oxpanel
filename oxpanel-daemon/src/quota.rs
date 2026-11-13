//! Per-tenant disk quotas, enforced by the kernel.
//!
//! A tenant's disk limit is an XFS **user quota** on the file system that
//! holds the tenant homes: everything the tenant's uid owns there counts,
//! whoever wrote it (SFTP, PHP, an application), and a write beyond the limit
//! fails with `EDQUOT`. Soft and hard limit are set to the same value; there
//! is no grace period to reason about.
//!
//! What the host must provide — and what OxPanel does not do behind the
//! operator's back — is the mount option: XFS decides at mount time whether
//! quotas are enforced (`uquota`), and for a root file system that means a
//! kernel argument and a reboot. The daemon only *looks* (the mount table)
//! and says what it sees: `GetHostInfo` reports whether quotas are enforced,
//! and a request for a disk limit on a host that cannot enforce it is refused
//! with a message that tells the operator what to change. It is never
//! accepted and silently ignored.
//!
//! `xfs_quota` talks to the kernel through the block device, which the
//! daemon's sandbox (`PrivateDevices=yes`) deliberately does not contain. The
//! tool is therefore run in a transient systemd unit outside the sandbox —
//! the same way dependency installers are — with its output directed to a
//! root-only file that the daemon reads back. Its exit status says little
//! (it is 0 for most failures), so a limit counts as set only when the
//! report that follows shows it.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use tracing::info;

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::nginx::safe_path_str;
use crate::records::TenantRecord;
use crate::system::{bin, CommandSpec, QuotaState};
use crate::validate::Limits;

/// Only root may read what the transient units write.
const SCRATCH_DIR_MODE: u32 = 0o700;
/// `xfs_quota` counts blocks in units of 1024 bytes.
const BLOCK: u64 = 1024;
/// Distinguishes the output files of concurrent requests.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// One user's row of the quota report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuotaRow {
    pub used_bytes: u64,
    /// 0 = no limit.
    pub limit_bytes: u64,
    pub inodes_used: u64,
    /// 0 = no limit.
    pub inodes_limit: u64,
}

/// Whether disk limits can be enforced for tenant homes, and if not, why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Availability {
    pub available: bool,
    /// One sentence for the operator: what was found, and what to do.
    pub detail: String,
    state: QuotaState,
}

/// Look at the file system holding the tenant homes. Read-only, no commands.
pub async fn availability(ctx: &Ctx) -> Result<Availability> {
    let home = &ctx.config.home_base;
    let state = ctx.sys.quota_state(home).await?;
    let on = format!(
        "{} is on {} ({})",
        home.display(),
        if state.device.as_os_str().is_empty() {
            "an unknown device".to_owned()
        } else {
            state.device.display().to_string()
        },
        if state.fs_type.is_empty() {
            "unknown file system"
        } else {
            state.fs_type.as_str()
        },
    );
    let (available, detail) = if state.fs_type != "xfs" {
        (
            false,
            format!("{on}; disk quotas are supported on XFS only: tenant homes must be on an XFS file system mounted with the option 'uquota' — see the handbook, \"Disk quotas\""),
        )
    } else if !state.user_quota_enforced {
        (
            false,
            format!("{on}, mounted without user quotas; add the mount option 'uquota' in /etc/fstab (for the root file system also the kernel argument rootflags=uquota) and reboot — see the handbook, \"Disk quotas\""),
        )
    } else if !ctx.sys.is_installed(bin::XFS_QUOTA).await {
        (
            false,
            format!(
                "{on} with user quotas enforced, but {} is missing (install xfsprogs)",
                bin::XFS_QUOTA
            ),
        )
    } else {
        (true, format!("{on} with user quotas enforced"))
    };
    Ok(Availability {
        available,
        detail,
        state,
    })
}

/// Refuse limits this host cannot enforce — before anything is created or
/// recorded. Limits without a disk part are always acceptable.
pub async fn require_available(ctx: &Ctx, limits: &Limits) -> Result<()> {
    if !limits.has_disk_quota() {
        return Ok(());
    }
    let a = availability(ctx).await?;
    if a.available {
        Ok(())
    } else {
        Err(Error::DiskQuotaUnavailable(a.detail))
    }
}

/// Parse `xfs_quota … report -u -n -N -b -i`: one line per uid,
/// `#<uid> <used> <soft> <hard> <warn> [<grace>] <iused> <isoft> <ihard> <warn> [<grace>]`,
/// block figures in KiB. Lines that are not such rows are ignored.
pub fn parse_report(text: &str) -> BTreeMap<u32, QuotaRow> {
    let mut rows = BTreeMap::new();
    for line in text.lines() {
        let Some(rest) = line.trim_start().strip_prefix('#') else {
            continue;
        };
        // The grace column (`[--------]`, `[6 days]`) may contain spaces, so
        // split at its closing bracket instead of counting columns.
        let mut halves = rest.split(']');
        let (Some(blocks), Some(inodes)) = (halves.next(), halves.next()) else {
            continue;
        };
        let mut b = blocks.split_whitespace();
        let mut i = inodes.split_whitespace();
        let number = |s: Option<&str>| s.and_then(|s| s.parse::<u64>().ok());
        let (Some(uid), Some(used), Some(_soft), Some(hard)) = (
            b.next().and_then(|s| s.parse::<u32>().ok()),
            number(b.next()),
            number(b.next()),
            number(b.next()),
        ) else {
            continue;
        };
        let (Some(inodes_used), Some(_isoft), Some(inodes_limit)) =
            (number(i.next()), number(i.next()), number(i.next()))
        else {
            continue;
        };
        rows.insert(
            uid,
            QuotaRow {
                used_bytes: used.saturating_mul(BLOCK),
                limit_bytes: hard.saturating_mul(BLOCK),
                inodes_used,
                inodes_limit,
            },
        );
    }
    rows
}

/// Run `xfs_quota -x -c <command>… <device>` outside the daemon's sandbox
/// and return what it printed.
async fn xfs_quota(ctx: &Ctx, state: &QuotaState, commands: &[String]) -> Result<String> {
    let cfg = &ctx.config;
    let device = safe_path_str(&state.device)?;
    let scratch = cfg.scratch_dir();
    fsutil::ensure_dir(&scratch, SCRATCH_DIR_MODE)?;
    let out: PathBuf = scratch.join(format!(
        "quota-{}-{}.out",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    // No `--pipe`: under SELinux systemd may not write to a pipe this
    // service created. systemd opens the output file itself.
    let mut cmd = CommandSpec::new(bin::SYSTEMD_RUN, cfg.command_timeout)
        .args(["--wait", "--collect", "--quiet"])
        .arg(format!(
            "--property=StandardOutput=truncate:{}",
            safe_path_str(&out)?
        ))
        .arg("--")
        .arg(bin::XFS_QUOTA)
        .arg("-x");
    for command in commands {
        cmd = cmd.arg("-c").arg(command);
    }
    let result = ctx.sys.run_ok(cmd.arg(device)).await;
    let text = fsutil::read_optional(&out);
    fsutil::remove_if_exists(&out)?;
    result?;
    Ok(String::from_utf8_lossy(&text?.unwrap_or_default()).into_owned())
}

fn report_command(uid: Option<u32>) -> String {
    match uid {
        Some(uid) => format!("report -u -n -N -b -i -L {uid} -U {uid}"),
        None => "report -u -n -N -b -i".to_owned(),
    }
}

/// Make the kernel's limits for the tenant's uid equal to the record's —
/// including "no limit", so a uid that is used again never inherits the
/// limits of the tenant that had it before. On a host without enforced
/// quotas this is a no-op for a tenant without a disk limit and an error for
/// one with. Idempotent. The caller holds the mutation lock.
pub async fn apply(ctx: &Ctx, tenant: &TenantRecord) -> Result<()> {
    let a = availability(ctx).await?;
    if !a.available {
        return if tenant.limits.has_disk_quota() {
            Err(Error::DiskQuotaUnavailable(a.detail))
        } else {
            Ok(())
        };
    }
    set_limits(ctx, &a.state, tenant.uid, &tenant.limits).await
}

/// Remove the kernel's limits for a uid that is being given up.
pub async fn clear(ctx: &Ctx, uid: u32) -> Result<()> {
    let a = availability(ctx).await?;
    if !a.available {
        return Ok(());
    }
    set_limits(ctx, &a.state, uid, &Limits::default()).await
}

async fn set_limits(ctx: &Ctx, state: &QuotaState, uid: u32, limits: &Limits) -> Result<()> {
    let blocks = limits.disk_max_bytes.map_or(0, |b| b / BLOCK);
    let inodes = limits.inodes_max.unwrap_or(0);
    let text = xfs_quota(
        ctx,
        state,
        &[
            format!("limit -u bsoft={blocks}k bhard={blocks}k isoft={inodes} ihard={inodes} {uid}"),
            report_command(Some(uid)),
        ],
    )
    .await?;
    // A uid that owns nothing and has no limits has no row at all.
    let row = parse_report(&text).get(&uid).copied().unwrap_or_default();
    if (row.limit_bytes, row.inodes_limit) != (blocks.saturating_mul(BLOCK), inodes) {
        return Err(Error::Internal(format!(
            "xfs_quota did not set the limits of uid {uid} on {}: asked for {blocks} KiB / {inodes} inodes, the kernel reports {} KiB / {} inodes; output: {}",
            state.device.display(),
            row.limit_bytes / BLOCK,
            row.inodes_limit,
            text.trim()
        )));
    }
    info!(
        uid,
        disk_max_kib = blocks,
        inodes_max = inodes,
        "disk quota set"
    );
    Ok(())
}

/// What the tenant's uid occupies according to the quota system, or `None`
/// when quotas are not enforced here (the caller measures another way).
pub async fn usage(ctx: &Ctx, uid: u32) -> Result<Option<QuotaRow>> {
    let a = availability(ctx).await?;
    if !a.available {
        return Ok(None);
    }
    let text = xfs_quota(ctx, &a.state, &[report_command(Some(uid))]).await?;
    Ok(Some(
        parse_report(&text).get(&uid).copied().unwrap_or_default(),
    ))
}

/// The whole user-quota table, or `None` when quotas are not enforced here.
pub async fn report_all(ctx: &Ctx) -> Result<Option<BTreeMap<u32, QuotaRow>>> {
    let a = availability(ctx).await?;
    if !a.available {
        return Ok(None);
    }
    let text = xfs_quota(ctx, &a.state, &[report_command(None)]).await?;
    Ok(Some(parse_report(&text)))
}

/// The kernel limits a record asks for, in the report's terms.
pub fn expected_limits(limits: &Limits) -> (u64, u64) {
    (
        limits
            .disk_max_bytes
            .map_or(0, |b| (b / BLOCK).saturating_mul(BLOCK)),
        limits.inodes_max.unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::system::fake::FAKE_DEVICE;
    use crate::system::FakeSystem;
    use crate::tenant::TenantService;
    use std::sync::Arc;

    struct Harness {
        _dir: tempfile::TempDir,
        sys: Arc<FakeSystem>,
        ctx: Ctx,
        tenants: TenantService,
    }

    fn harness(enforced: bool) -> Harness {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let mut cfg = Config::default();
        cfg.state_dir = dir.path().join("state");
        cfg.home_base = dir.path().join("home");
        cfg.systemd_unit_dir = dir.path().join("systemd");
        cfg.socket_path = dir.path().join("run").join("oxpanel.sock");
        for d in [&cfg.home_base, &cfg.systemd_unit_dir] {
            std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("{e}"));
        }
        let sys = Arc::new(FakeSystem::new());
        sys.set_quota_enforced(enforced);
        let ctx = Ctx::new(cfg, sys.clone(), false);
        ctx.store.init().unwrap_or_else(|e| panic!("{e}"));
        Harness {
            _dir: dir,
            sys,
            tenants: TenantService::new(ctx.clone()),
            ctx,
        }
    }

    fn disk(bytes: u64, inodes: u64) -> Limits {
        Limits::default()
            .with_disk(bytes, inodes)
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// The argv of every `systemd-run`, with the per-call output file masked.
    fn quota_calls(h: &Harness) -> Vec<Vec<String>> {
        h.sys
            .calls_to(bin::SYSTEMD_RUN)
            .iter()
            .map(|c| {
                c.args
                    .iter()
                    .map(|a| {
                        let a = a.to_string_lossy();
                        match a.strip_prefix("--property=StandardOutput=truncate:") {
                            Some(path) => {
                                assert!(
                                    path.starts_with(
                                        h.ctx.config.scratch_dir().to_string_lossy().as_ref()
                                    ),
                                    "{path}"
                                );
                                "--property=StandardOutput=truncate:<scratch>".to_owned()
                            }
                            None => a.into_owned(),
                        }
                    })
                    .collect()
            })
            .collect()
    }

    fn set_and_report(limit: &str) -> Vec<String> {
        [
            "--wait",
            "--collect",
            "--quiet",
            "--property=StandardOutput=truncate:<scratch>",
            "--",
            bin::XFS_QUOTA,
            "-x",
            "-c",
            limit,
            "-c",
            "report -u -n -N -b -i -L 20000 -U 20000",
            FAKE_DEVICE,
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
    }

    #[test]
    fn report_parsing_handles_real_output() {
        // Copied from xfs_quota on AlmaLinux 9.8 (xfsprogs 6.4).
        let text = "\
#0             1146068          0          0     00 [--------]      30810          0          0     00 [--------]
#998              1256          0          0     00 [--------]         10          0          0     00 [--------]
#20000            6112       6144       6144     00 [--------]         13        200        200     00 [--------]
#20001              16          0          0     00 [6 days]          6          0          0     00 [--none--]

xfs_quota: cannot setup path for mount /dev/nonexistent: No such file or directory
#bogus 1 2 3 00 [--------] 4 5 6 00 [--------]
";
        let rows = parse_report(text);
        assert_eq!(rows.len(), 4);
        assert_eq!(
            rows.get(&20000),
            Some(&QuotaRow {
                used_bytes: 6112 * 1024,
                limit_bytes: 6144 * 1024,
                inodes_used: 13,
                inodes_limit: 200,
            })
        );
        assert_eq!(
            rows.get(&20001).map(|r| (r.used_bytes, r.inodes_used)),
            Some((16 * 1024, 6))
        );
        assert_eq!(rows.get(&0).map(|r| r.limit_bytes), Some(0));
        assert!(parse_report("").is_empty());
        assert!(parse_report("\n").is_empty());
    }

    #[tokio::test]
    async fn a_disk_limit_is_refused_before_anything_exists_when_the_host_cannot_enforce_it(
    ) -> Result<()> {
        let h = harness(false);
        let r = h.tenants.create("alice", disk(1 << 30, 0), "").await;
        match &r {
            Err(Error::DiskQuotaUnavailable(m)) => {
                assert!(
                    m.contains("uquota") && m.contains("rootflags=uquota"),
                    "{m}"
                );
                assert!(m.contains(FAKE_DEVICE), "{m}");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(h.sys.calls().is_empty(), "nothing ran");
        assert!(matches!(
            h.tenants.get("alice").await,
            Err(Error::TenantNotFound(_))
        ));
        // Without a disk limit the same host is fine, and nothing quota-related runs.
        h.tenants.create("alice", Limits::default(), "").await?;
        assert!(h.sys.calls_to(bin::SYSTEMD_RUN).is_empty());
        assert!(matches!(
            h.tenants.update_limits("alice", disk(0, 5000)).await,
            Err(Error::DiskQuotaUnavailable(_))
        ));
        assert_eq!(
            h.tenants.get("alice").await?.limits,
            Limits::default(),
            "the refused limit was not recorded"
        );
        let a = availability(&h.ctx).await?;
        assert!(!a.available);
        h.sys.set_quota_enforced(true);
        h.sys.set_missing(bin::XFS_QUOTA);
        let a = availability(&h.ctx).await?;
        assert!(
            !a.available && a.detail.contains("xfsprogs"),
            "{}",
            a.detail
        );
        Ok(())
    }

    #[tokio::test]
    async fn limits_are_set_with_exact_commands_and_verified() -> Result<()> {
        let h = harness(true);
        assert!(availability(&h.ctx).await?.available);
        // 5 MiB + 512 bytes: rounded down to whole KiB.
        let (rec, _) = h
            .tenants
            .create("alice", disk(5 * 1024 * 1024 + 512, 200), "")
            .await?;
        assert_eq!(rec.uid, 20000);
        assert_eq!(
            quota_calls(&h),
            vec![set_and_report(
                "limit -u bsoft=5120k bhard=5120k isoft=200 ihard=200 20000"
            )]
        );
        assert_eq!(h.sys.quota_limits(20000), (5120, 200));
        assert!(
            fsutil::list_entry_names(&h.ctx.config.scratch_dir())?.is_empty(),
            "output files are removed"
        );

        // Changing and dropping the limit.
        h.sys.clear_calls();
        let (_, changed) = h.tenants.update_limits("alice", disk(1 << 30, 0)).await?;
        assert!(changed);
        assert_eq!(h.sys.quota_limits(20000), (1 << 20, 0));
        h.tenants.update_limits("alice", Limits::default()).await?;
        assert_eq!(h.sys.quota_limits(20000), (0, 0));
        assert_eq!(
            quota_calls(&h).last(),
            Some(&set_and_report(
                "limit -u bsoft=0k bhard=0k isoft=0 ihard=0 20000"
            ))
        );

        // A tenant without a disk limit still gets its uid's limits cleared:
        // the uid may have belonged to someone else.
        h.sys.set_quota_limits(20001, 999, 9);
        h.tenants.create("bob", Limits::default(), "").await?;
        assert_eq!(h.sys.quota_limits(20001), (0, 0));

        // Deleting gives the limits up.
        h.tenants.update_limits("alice", disk(1 << 20, 0)).await?;
        assert_eq!(h.sys.quota_limits(20000), (1024, 0));
        h.tenants.delete("alice", false).await?;
        assert_eq!(h.sys.quota_limits(20000), (0, 0));
        Ok(())
    }

    #[tokio::test]
    async fn a_limit_the_kernel_does_not_show_is_an_error() -> Result<()> {
        let h = harness(true);
        h.tenants.create("alice", Limits::default(), "").await?;
        // The tool "succeeds" (as xfs_quota does) but nothing was set: the
        // fake only honours its own device.
        let state = QuotaState {
            fs_type: "xfs".into(),
            device: PathBuf::from("/dev/other"),
            user_quota_enforced: true,
        };
        let r = set_limits(&h.ctx, &state, 20000, &disk(1 << 20, 0)).await;
        assert!(
            matches!(&r, Err(Error::Internal(m)) if m.contains("did not set")),
            "{r:?}"
        );
        // A failing transient unit is an error too, and leaves no file behind.
        h.sys.script_failure(
            bin::SYSTEMD_RUN,
            1,
            "Failed to start transient service unit",
        );
        assert!(matches!(
            h.tenants.update_limits("alice", disk(1 << 20, 0)).await,
            Err(Error::CommandFailed { .. })
        ));
        assert!(fsutil::list_entry_names(&h.ctx.config.scratch_dir())?.is_empty());
        // The record holds the new limit, so repeating the request completes it.
        let (rec, changed) = h.tenants.update_limits("alice", disk(1 << 20, 0)).await?;
        assert!(!changed);
        assert_eq!(rec.limits.disk_max_bytes, Some(1 << 20));
        assert_eq!(h.sys.quota_limits(20000), (1024, 0));
        Ok(())
    }

    #[tokio::test]
    async fn usage_comes_from_the_quota_system_when_it_is_enforced() -> Result<()> {
        let h = harness(true);
        h.tenants.create("alice", Limits::default(), "").await?;
        h.sys.set_quota_usage(20000, 6112, 13);
        h.sys.clear_calls();
        let u = h.tenants.usage("alice").await?;
        assert_eq!(u.disk_usage_bytes, 6112 * 1024);
        assert!(h.sys.calls_to(bin::DU).is_empty(), "no tree walk");
        assert_eq!(
            quota_calls(&h),
            vec![[
                "--wait",
                "--collect",
                "--quiet",
                "--property=StandardOutput=truncate:<scratch>",
                "--",
                bin::XFS_QUOTA,
                "-x",
                "-c",
                "report -u -n -N -b -i -L 20000 -U 20000",
                FAKE_DEVICE,
            ]
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<String>>()]
        );
        assert_eq!(usage(&h.ctx, 20000).await?.map(|r| r.inodes_used), Some(13));
        // A failing report degrades to the old measurement instead of failing.
        h.sys.script_failure(
            bin::SYSTEMD_RUN,
            1,
            "Failed to start transient service unit",
        );
        assert_eq!(h.tenants.usage("alice").await?.disk_usage_bytes, 8192);
        // Not enforced: the old measurement.
        h.sys.set_quota_enforced(false);
        assert_eq!(h.tenants.usage("alice").await?.disk_usage_bytes, 8192);
        assert_eq!(usage(&h.ctx, 20000).await?, None);
        assert_eq!(report_all(&h.ctx).await?, None);
        Ok(())
    }
}
