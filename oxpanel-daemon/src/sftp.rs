//! SFTP-only file access for tenants.
//!
//! A tenant account has no shell and a locked password; this module is the
//! one way in, and it gives exactly one thing: file transfer inside the
//! tenant's own home.
//!
//! **Every tenant is confined, not only those with SFTP access.** All tenant
//! accounts are members of one group (`oxpanel-tenants`), and a drop-in for
//! sshd that OxPanel owns applies to that group:
//!
//! - `AuthorizedKeysFile` points to a root-owned file outside the home. A
//!   tenant (or a compromised site running as the tenant) can therefore not
//!   give itself a key. Without this, any process of a tenant could write
//!   `~/.ssh/authorized_keys` and use the host's sshd for TCP forwarding — a
//!   login shell of `nologin` does not prevent that.
//! - `ForceCommand internal-sftp`, no forwarding of any kind, no terminal.
//! - `ChrootDirectory`: a root-owned directory per tenant that contains
//!   nothing but the tenant's home, at the same path it has on the host
//!   (`/home/<name>`), so paths look the same inside and outside.
//!
//! sshd insists that a chroot directory and everything above it belong to
//! root, which a tenant home (owned by the tenant, `0700` plus the web
//! server's ACL) is not and must not become. The home is therefore
//! bind-mounted into the chroot directory by a systemd mount unit: the same
//! inodes, so ownership, ACLs, default ACLs and SELinux labels of everything
//! uploaded are exactly what they would be for a file the tenant created any
//! other way, and nothing about the home itself changes. The unit is enabled,
//! so the mount returns after a reboot.
//!
//! SFTP access exists exactly while the tenant's record holds at least one
//! public key. Suspension removes the keys file (the record keeps the keys)
//! and ends running sessions; so does removing a key. Everything written here
//! is rendered from the records alone and checked by `Reconcile`.
//!
//! Passwords are deliberately not offered: see the design record.

use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::config::Config;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::nginx::safe_path_str;
use crate::records::{now_unix, SftpKeyRecord, TenantRecord, TenantState};
use crate::system::{bin, CommandSpec};
use crate::systemd;
use crate::validate::{KeyFingerprint, KeyLabel, SshPublicKey, Username, MAX_SFTP_KEYS};

const HEADER: &str = "# Managed by oxpanel-daemon. Manual edits will be overwritten.\n";
/// sshd reads its configuration as root.
const DROPIN_MODE: u32 = 0o600;
/// Tenants must be able to reach their own keys file, but not list the others.
const KEYS_DIR_MODE: u32 = 0o711;
/// Owned by root; the tenant reads it through an ACL entry (sshd opens the
/// file with the identity of the account that is logging in).
const KEYS_FILE_MODE: u32 = 0o640;
/// What sshd demands of a chroot directory: root-owned, writable by root only.
const CHROOT_DIR_MODE: u32 = 0o755;
const UNIT_MODE: u32 = 0o644;
const SSHD_UNIT: &str = "sshd.service";

/// The sshd drop-in: one `Match` block for the tenant group.
pub fn render_sshd_dropin(cfg: &Config) -> Result<String> {
    let keys = safe_path_str(&cfg.sftp_keys_dir)?;
    let chroot = cfg.sftp_chroot_dir();
    let chroot = safe_path_str(&chroot)?;
    let group = &cfg.tenant_group;
    Ok(format!(
        "{HEADER}# Accounts of OxPanel tenants: SFTP only, inside their own home, with keys
# that only OxPanel can change. Nothing here applies to any other account.
Match Group {group}
    AuthorizedKeysFile {keys}/%u
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    ChrootDirectory {chroot}/%u
    ForceCommand internal-sftp
    DisableForwarding yes
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitTTY no
    PermitUserRC no
# End of the block, whatever sshd reads after this file.
Match all
"
    ))
}

/// Paths of everything SFTP access puts on disk for one tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SftpPaths {
    /// The tenant's authorized-keys file.
    pub keys_file: PathBuf,
    /// The directory sshd chroots the tenant into.
    pub chroot: PathBuf,
    /// Where the home is mounted inside the chroot directory.
    pub mount_point: PathBuf,
    /// The mount unit (its name is dictated by `mount_point`).
    pub mount_unit_name: String,
    pub mount_unit: PathBuf,
}

impl SftpPaths {
    pub fn for_tenant(cfg: &Config, tenant: &TenantRecord) -> Result<Self> {
        let name = Username::parse(&tenant.username)?;
        let chroot = cfg.sftp_chroot_dir().join(name.as_str());
        let home = safe_path_str(&tenant.home)?;
        // The home keeps its absolute path inside the chroot directory.
        let mount_point = chroot.join(home.trim_start_matches('/'));
        if mount_point == chroot {
            return Err(Error::Internal(format!("{home} cannot be a tenant home")));
        }
        let mount_unit_name = systemd::mount_unit_name(&mount_point)?;
        Ok(Self {
            keys_file: cfg.sftp_keys_dir.join(name.as_str()),
            mount_unit: cfg.systemd_unit_dir.join(&mount_unit_name),
            mount_unit_name,
            mount_point,
            chroot,
        })
    }

    /// The directories OxPanel creates for the chroot, outermost first: the
    /// chroot directory itself and every directory down to the mount point.
    fn chroot_dirs(&self) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = self
            .mount_point
            .ancestors()
            .take_while(|p| p.starts_with(&self.chroot))
            .map(Path::to_owned)
            .collect();
        dirs.reverse();
        dirs
    }
}

/// A stored key is valid: a supported type, a well-formed blob, the
/// fingerprint of that blob, and a label that is safe in a keys file.
pub fn check_key_record(key: &SftpKeyRecord) -> Result<SshPublicKey> {
    let parsed = SshPublicKey::from_stored(&key.key_type, &key.blob)?;
    if parsed.fingerprint() != key.fingerprint || parsed.blob() != key.blob {
        return Err(Error::invalid(
            "public_key",
            "stored key does not match its fingerprint",
        ));
    }
    if !key.label.is_empty() {
        KeyLabel::parse(&key.label)?;
    }
    Ok(parsed)
}

/// The tenant's authorized-keys file. Every key carries `restrict`, so even
/// an sshd that ignored the drop-in would grant it no forwarding and no
/// terminal.
pub fn render_keys_file(tenant: &TenantRecord) -> Result<String> {
    let mut out = String::from(HEADER);
    for key in &tenant.sftp_keys {
        let parsed = check_key_record(key)?;
        out.push_str("restrict ");
        out.push_str(parsed.key_type());
        out.push(' ');
        out.push_str(parsed.blob());
        if !key.label.is_empty() {
            out.push(' ');
            out.push_str(&key.label);
        }
        out.push('\n');
    }
    Ok(out)
}

/// The mount unit that makes the home visible inside the chroot directory.
/// `LazyUnmount`: taking access away must not fail because something still
/// has a file open in there; logins are already impossible by then (the
/// keys file is gone) and sessions have been ended.
pub fn render_mount_unit(tenant: &TenantRecord, paths: &SftpPaths) -> Result<String> {
    let name = Username::parse(&tenant.username)?;
    let home = safe_path_str(&tenant.home)?;
    let mount_point = safe_path_str(&paths.mount_point)?;
    Ok(format!(
        "{HEADER}[Unit]
Description=OxPanel SFTP view of the home of tenant {name}
Documentation=https://github.com/OxServers/oxpanel
RequiresMountsFor={home}

[Mount]
What={home}
Where={mount_point}
Type=none
Options=bind
LazyUnmount=yes

[Install]
WantedBy=multi-user.target
"
    ))
}

fn systemctl(ctx: &Ctx) -> CommandSpec {
    CommandSpec::new(bin::SYSTEMCTL, ctx.config.command_timeout)
}

/// Whether sshd is installed and the drop-in on disk is the current one.
pub async fn is_available(ctx: &Ctx) -> Result<bool> {
    if !ctx.sys.is_installed(bin::SSHD).await {
        return Ok(false);
    }
    let expected = render_sshd_dropin(&ctx.config)?;
    Ok(fsutil::read_optional(&ctx.config.sshd_dropin_file)?
        .is_some_and(|on_disk| on_disk == expected.as_bytes()))
}

/// Install the sshd drop-in: write it, let `sshd -t` check the whole
/// configuration, and only then ask the running sshd to re-read it. If sshd
/// rejects the result the previous file (or its absence) is restored, so the
/// host's own SSH access is never put at risk. Returns whether it changed.
pub async fn ensure_sshd_config(ctx: &Ctx) -> Result<bool> {
    let cfg = &ctx.config;
    let timeout = cfg.command_timeout;
    if !ctx.sys.is_installed(bin::SSHD).await {
        return Err(Error::SftpUnavailable(
            "sshd is not installed (install openssh-server)".into(),
        ));
    }
    let path = &cfg.sshd_dropin_file;
    // Not created on purpose: if the directory is missing, the host's
    // sshd_config does not include it and a file in it would do nothing.
    if !path.parent().is_some_and(Path::is_dir) {
        return Err(Error::SftpUnavailable(format!(
            "{} cannot be written: its directory does not exist, so this host's sshd_config has no Include for it",
            path.display()
        )));
    }
    let contents = render_sshd_dropin(cfg)?;
    let previous = fsutil::read_optional(path)?;
    if !fsutil::write_atomic(path, contents.as_bytes(), DROPIN_MODE)? {
        return Ok(false);
    }
    let test = ctx
        .sys
        .run(CommandSpec::new(bin::SSHD, timeout).arg("-t"))
        .await?;
    if !test.success() {
        let output = test.combined_lossy();
        warn!(path = %path.display(), %output, "sshd rejected the OxPanel drop-in; rolling back");
        match previous {
            Some(bytes) => fsutil::write_atomic(path, &bytes, DROPIN_MODE).map(|_| ())?,
            None => fsutil::remove_if_exists(path).map(|_| ())?,
        }
        return Err(Error::SftpUnavailable(format!(
            "sshd rejected the OxPanel configuration: {output}"
        )));
    }
    // A stopped sshd is left stopped; it reads the file when it starts.
    ctx.sys
        .run_ok(systemctl(ctx).args(["try-reload-or-restart", SSHD_UNIT]))
        .await?;
    info!(path = %path.display(), "sshd drop-in installed");
    Ok(true)
}

/// Make the account a member of the tenant group (the drop-in's `Match`).
pub async fn ensure_membership(ctx: &Ctx, tenant: &TenantRecord) -> Result<()> {
    let cfg = &ctx.config;
    let name = Username::parse(&tenant.username)?;
    let Some(group) = ctx.sys.group_by_name(&cfg.tenant_group).await? else {
        return Err(Error::Internal(format!(
            "group '{}' does not exist; it is created by the package (systemd-sysusers)",
            cfg.tenant_group
        )));
    };
    if ctx
        .sys
        .groups_of(name.as_str(), tenant.gid)
        .await?
        .contains(&group)
    {
        return Ok(());
    }
    ctx.sys
        .run_ok(
            CommandSpec::new(bin::GPASSWD, cfg.command_timeout)
                .arg("--add")
                .arg(name.as_str())
                .arg(&cfg.tenant_group),
        )
        .await?;
    info!(tenant = %name, group = %cfg.tenant_group, "added to the tenant group");
    Ok(())
}

/// Ask sshd itself what it would do with a login of this account, and refuse
/// unless the answer is "SFTP only, in a chroot directory". This catches a
/// host whose `sshd_config` does not include the drop-in directory, or
/// overrides the block, before a key is handed out.
async fn verify_confined(ctx: &Ctx, name: &Username) -> Result<()> {
    let out = ctx
        .sys
        .run_ok(
            CommandSpec::new(bin::SSHD, ctx.config.command_timeout)
                .args(["-T", "-C"])
                .arg(format!("user={name},host=localhost,addr=127.0.0.1")),
        )
        .await?;
    let effective = out.stdout_lossy();
    let value = |key: &str| {
        effective.lines().find_map(|l| {
            let (k, v) = l.split_once(' ')?;
            (k == key).then(|| v.trim().to_owned())
        })
    };
    let forced = value("forcecommand").is_some_and(|v| v == "internal-sftp");
    let chrooted = value("chrootdirectory").is_some_and(|v| v != "none");
    let keys_outside_home = value("authorizedkeysfile").is_some_and(|v| v.starts_with('/'));
    if forced && chrooted && keys_outside_home {
        return Ok(());
    }
    Err(Error::SftpUnavailable(format!(
        "sshd would not confine tenant '{name}' to SFTP: check that /etc/ssh/sshd_config includes {} and that nothing overrides it (sshd -T -C user={name},host=localhost,addr=127.0.0.1)",
        ctx.config.sshd_dropin_file.display()
    )))
}

/// Everything that must hold before a key is accepted. Changes nothing that
/// belongs to the tenant's SFTP access itself.
pub async fn preflight(ctx: &Ctx, tenant: &TenantRecord) -> Result<()> {
    ensure_sshd_config(ctx).await?;
    ensure_membership(ctx, tenant).await?;
    verify_confined(ctx, &Username::parse(&tenant.username)?).await
}

/// Bring the tenant's SFTP access in line with its record: with keys, the
/// chroot directory, the mount and the keys file exist (the keys file only
/// while the tenant is not suspended); without keys, none of them do.
/// Idempotent. The caller holds the mutation lock.
pub async fn ensure_access(ctx: &Ctx, tenant: &TenantRecord) -> Result<()> {
    if tenant.sftp_keys.is_empty() {
        return remove_access(ctx, tenant).await;
    }
    let cfg = &ctx.config;
    let timeout = cfg.command_timeout;
    let name = Username::parse(&tenant.username)?;
    let paths = SftpPaths::for_tenant(cfg, tenant)?;
    preflight(ctx, tenant).await?;

    fsutil::ensure_dir(&cfg.sftp_chroot_dir(), CHROOT_DIR_MODE)?;
    for dir in paths.chroot_dirs() {
        // The mount point itself shows the home's mode once mounted; leave it.
        if dir == paths.mount_point && dir.is_dir() {
            continue;
        }
        fsutil::ensure_dir(&dir, CHROOT_DIR_MODE)?;
    }
    let unit_changed = fsutil::write_atomic(
        &paths.mount_unit,
        render_mount_unit(tenant, &paths)?.as_bytes(),
        UNIT_MODE,
    )?;
    if unit_changed {
        systemd::daemon_reload(ctx.sys.as_ref(), timeout).await?;
    }
    ctx.sys
        .run_ok(
            systemctl(ctx)
                .args(["enable", "--now", "--"])
                .arg(&paths.mount_unit_name),
        )
        .await?;

    if tenant.suspended {
        fsutil::remove_if_exists(&paths.keys_file)?;
        return Ok(());
    }
    fsutil::ensure_dir(&cfg.sftp_keys_dir, KEYS_DIR_MODE)?;
    let keys_changed = fsutil::write_atomic(
        &paths.keys_file,
        render_keys_file(tenant)?.as_bytes(),
        KEYS_FILE_MODE,
    )?;
    // Always: a crash between the write and this call must not leave a file
    // the tenant cannot read. The mask it sets equals the group bits above,
    // so the file's mode stays what `write_atomic` expects.
    ctx.sys
        .run_ok(
            CommandSpec::new(bin::SETFACL, timeout)
                .arg("-m")
                .arg(format!("u:{name}:r--"))
                .arg("--")
                .arg(&paths.keys_file),
        )
        .await?;
    if unit_changed || keys_changed {
        info!(tenant = %name, keys = tenant.sftp_keys.len(), "sftp access configured");
    }
    Ok(())
}

/// Take SFTP access away, in the order that cannot fail half-way: the keys
/// file first (no new logins), then running sessions are ended (a session
/// whose working directory is inside the home would keep the mount busy),
/// then the mount, the mount unit and the (then empty) chroot directories.
/// Never recursive — a directory that is still mounted or holds anything is
/// an error, not something to delete.
pub async fn remove_access(ctx: &Ctx, tenant: &TenantRecord) -> Result<()> {
    let cfg = &ctx.config;
    let paths = SftpPaths::for_tenant(cfg, tenant)?;
    let had_keys = fsutil::remove_if_exists(&paths.keys_file)?;
    let had_unit = paths.mount_unit.exists();
    if had_keys || had_unit {
        end_sessions(ctx, tenant).await?;
    }
    if had_unit {
        ctx.sys
            .run_ok(
                systemctl(ctx)
                    .args(["disable", "--now", "--"])
                    .arg(&paths.mount_unit_name),
            )
            .await?;
        fsutil::remove_if_exists(&paths.mount_unit)?;
        systemd::daemon_reload(ctx.sys.as_ref(), cfg.command_timeout).await?;
    }
    let mut had_dirs = false;
    for dir in paths.chroot_dirs().iter().rev() {
        had_dirs |= fsutil::remove_empty_dir(dir)?;
    }
    if had_keys || had_unit || had_dirs {
        info!(tenant = %tenant.username, "sftp access removed");
    }
    Ok(())
}

/// Suspension: no key can log in (the keys file goes; the record keeps the
/// keys) and running sessions end. Needs nothing from sshd, so it cannot be
/// blocked by a broken sshd configuration. The mount stays.
pub async fn suspend_access(ctx: &Ctx, tenant: &TenantRecord) -> Result<()> {
    let paths = SftpPaths::for_tenant(&ctx.config, tenant)?;
    let had_keys = fsutil::remove_if_exists(&paths.keys_file)?;
    if had_keys || !tenant.sftp_keys.is_empty() {
        end_sessions(ctx, tenant).await?;
    }
    Ok(())
}

/// End every login session of the tenant. Sessions live in the tenant's
/// `user-<uid>.slice` (pam_systemd), which is also what bounds them by the
/// tenant's limits; stopping the slice ends them all at once. A slice with
/// nothing in it stops successfully.
pub async fn end_sessions(ctx: &Ctx, tenant: &TenantRecord) -> Result<()> {
    ctx.sys
        .run_ok(
            systemctl(ctx)
                .args(["stop", "--"])
                .arg(format!("user-{}.slice", tenant.uid)),
        )
        .await?;
    Ok(())
}

/// Start-up convergence: the drop-in is current, every tenant is in the
/// tenant group (tenants created before SFTP existed are not), and SFTP
/// access matches the records. Failures are logged and reported by
/// `Reconcile`; they never stop the daemon. Returns how many tenants have
/// SFTP access.
pub async fn converge_all(ctx: &Ctx) -> Result<usize> {
    let _guard = ctx.lock.lock().await;
    if ctx.sys.is_installed(bin::SSHD).await {
        if let Err(e) = ensure_sshd_config(ctx).await {
            warn!(error = %e, "sshd is not confining tenants; SFTP access is unavailable");
        }
    }
    let mut with_access = 0;
    for tenant in ctx.store.list_tenants()? {
        if tenant.state != TenantState::Ready {
            continue;
        }
        if let Err(e) = ensure_membership(ctx, &tenant).await {
            warn!(tenant = %tenant.username, error = %e, "could not add the account to the tenant group");
            continue;
        }
        if tenant.sftp_keys.is_empty() {
            continue;
        }
        match ensure_access(ctx, &tenant).await {
            Ok(()) => with_access += 1,
            Err(e) => {
                warn!(tenant = %tenant.username, error = %e, "could not restore SFTP access");
            }
        }
    }
    Ok(with_access)
}

/// The SFTP part of the API: a tenant's public keys.
#[derive(Debug, Clone)]
pub struct SftpService {
    ctx: Ctx,
}

impl SftpService {
    pub fn new(ctx: Ctx) -> Self {
        Self { ctx }
    }

    fn load_ready(&self, name: &Username) -> Result<TenantRecord> {
        let rec = self
            .ctx
            .store
            .load_tenant(name)?
            .ok_or_else(|| Error::TenantNotFound(name.to_string()))?;
        if rec.state != TenantState::Ready {
            return Err(Error::TenantNotReady(name.to_string()));
        }
        Ok(rec)
    }

    /// Give `public_key` SFTP access as the tenant. The first key creates the
    /// access. `label` names the key; empty means "use the key's own comment
    /// if it has a usable one". Adding a key the tenant already has changes
    /// nothing (except a different label) and repeats the provisioning, which
    /// completes an interrupted attempt. Returns the record, the key and
    /// whether anything changed.
    pub async fn add_key(
        &self,
        username: &str,
        public_key: &str,
        label: &str,
    ) -> Result<(TenantRecord, SftpKeyRecord, bool)> {
        let name = Username::parse(username)?;
        let key = SshPublicKey::parse(public_key)?;
        let label = if label.is_empty() {
            key.comment().map_or("", KeyLabel::as_str).to_owned()
        } else {
            KeyLabel::parse(label)?.as_str().to_owned()
        };
        let _guard = self.ctx.lock.lock().await;
        let mut rec = self.load_ready(&name)?;
        let existing = rec
            .sftp_keys
            .iter()
            .position(|k| k.fingerprint == key.fingerprint());
        if existing.is_none() && rec.sftp_keys.len() >= MAX_SFTP_KEYS {
            return Err(Error::TooManySftpKeys(name.to_string()));
        }
        // Refuse before anything is recorded if this host cannot confine the tenant.
        preflight(&self.ctx, &rec).await?;
        let (stored, changed) = match existing.and_then(|i| rec.sftp_keys.get_mut(i)) {
            Some(k) if k.label == label => (k.clone(), false),
            Some(k) => {
                k.label = label;
                (k.clone(), true)
            }
            None => {
                let k = SftpKeyRecord {
                    key_type: key.key_type().to_owned(),
                    blob: key.blob().to_owned(),
                    fingerprint: key.fingerprint().to_owned(),
                    label,
                    added_at_unix: now_unix(),
                };
                rec.sftp_keys.push(k.clone());
                (k, true)
            }
        };
        if changed {
            self.ctx.store.save_tenant(&rec)?;
        }
        ensure_access(&self.ctx, &rec).await?;
        if changed {
            info!(tenant = %name, fingerprint = %stored.fingerprint, "sftp key added");
        }
        Ok((rec, stored, changed))
    }

    /// Take a key away. Running sessions of the tenant are ended, so a
    /// connection that was authenticated with the key does not outlive it.
    /// Removing the last key removes the access altogether. A key the tenant
    /// does not have is `NOT_FOUND`, except that repeating the provisioning
    /// still happens first — a removal interrupted half-way is completed by
    /// asking again.
    pub async fn remove_key(&self, username: &str, fingerprint: &str) -> Result<TenantRecord> {
        let name = Username::parse(username)?;
        let fingerprint = KeyFingerprint::parse(fingerprint)?;
        let _guard = self.ctx.lock.lock().await;
        let mut rec = self.load_ready(&name)?;
        let before = rec.sftp_keys.len();
        rec.sftp_keys
            .retain(|k| k.fingerprint != fingerprint.as_str());
        let removed = rec.sftp_keys.len() != before;
        if removed {
            self.ctx.store.save_tenant(&rec)?;
        }
        ensure_access(&self.ctx, &rec).await?;
        if !removed {
            return Err(Error::SftpKeyNotFound {
                tenant: name.to_string(),
                fingerprint: fingerprint.as_str().to_owned(),
            });
        }
        if !rec.sftp_keys.is_empty() {
            // The remaining keys stay; a session opened with the removed one
            // must not outlive it. (Without keys, `remove_access` did this.)
            end_sessions(&self.ctx, &rec).await?;
        }
        info!(tenant = %name, fingerprint = fingerprint.as_str(), "sftp key removed");
        Ok(rec)
    }

    /// The tenant's keys, oldest first.
    pub async fn list_keys(&self, username: &str) -> Result<Vec<SftpKeyRecord>> {
        let name = Username::parse(username)?;
        Ok(self
            .ctx
            .store
            .load_tenant(&name)?
            .ok_or_else(|| Error::TenantNotFound(name.to_string()))?
            .sftp_keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::{FakeSystem, System as _};
    use crate::tenant::TenantService;
    use crate::validate::Limits;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    const KEY_A: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGNQ8nctDOzq4yQ8Bix4hfkkqCQw0kkYzl6hc7hg7rRo alice@laptop";
    const BLOB_A: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIGNQ8nctDOzq4yQ8Bix4hfkkqCQw0kkYzl6hc7hg7rRo";
    const FP_A: &str = "SHA256:d61vVJ9GcopAzh14aZ3bTeCz+981/iT/jSIxXFS8pjQ";
    const KEY_B: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCPCQ5RPJL6Of0dEwqmMxFaxsEIMTgTuoqdjIkhuKJBRxt4u5xxce+n8yuTHQ+EVvhVfmIFaBrQ9IenhTvA47u8=";
    const FP_B: &str = "SHA256:WXfDgbyQ6VkZ+BgiCeSpzsvA1bZVLsX3/n4u1ddioxE";

    struct Harness {
        dir: tempfile::TempDir,
        sys: Arc<FakeSystem>,
        ctx: Ctx,
        tenants: TenantService,
        sftp: SftpService,
    }

    /// A host with sshd and one ready tenant, `foo-bar`.
    async fn harness() -> Harness {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let mut cfg = Config::default();
        cfg.state_dir = dir.path().join("state");
        cfg.home_base = dir.path().join("home");
        cfg.systemd_unit_dir = dir.path().join("systemd");
        cfg.nginx_log_dir = dir.path().join("log");
        cfg.php_conf_dir = dir.path().join("php");
        cfg.nginx_conf_dir = dir.path().join("nginx").join("oxpanel.d");
        cfg.sftp_keys_dir = dir.path().join("sftp-keys");
        cfg.sshd_dropin_file = dir.path().join("sshd_config.d").join("60-oxpanel.conf");
        for d in [
            &cfg.home_base,
            &cfg.systemd_unit_dir,
            &dir.path().join("sshd_config.d"),
        ] {
            std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("{e}"));
        }
        let sys = Arc::new(FakeSystem::new());
        let ctx = Ctx::new(cfg, sys.clone(), false);
        ctx.store.init().unwrap_or_else(|e| panic!("{e}"));
        let h = Harness {
            dir,
            sys,
            tenants: TenantService::new(ctx.clone()),
            sftp: SftpService::new(ctx.clone()),
            ctx,
        };
        h.tenants
            .create("foo-bar", Limits::default(), "")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        h.sys.clear_calls();
        h
    }

    fn argv(h: &Harness) -> Vec<Vec<String>> {
        h.sys
            .calls()
            .iter()
            .map(|c| {
                std::iter::once(c.program.to_owned())
                    .chain(c.args.iter().map(|a| a.to_string_lossy().into_owned()))
                    .collect()
            })
            .collect()
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    fn read(p: &Path) -> String {
        std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    #[test]
    fn dropin_confines_the_tenant_group_and_nobody_else() -> Result<()> {
        let cfg = Config::default();
        let d = render_sshd_dropin(&cfg)?;
        assert!(d.starts_with(HEADER));
        let directives: Vec<&str> = d
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(str::trim)
            .collect();
        assert_eq!(
            directives,
            vec![
                "Match Group oxpanel-tenants",
                "AuthorizedKeysFile /etc/oxpanel-sftp/%u",
                "AuthenticationMethods publickey",
                "PasswordAuthentication no",
                "KbdInteractiveAuthentication no",
                "ChrootDirectory /var/lib/oxpanel/sftp/%u",
                "ForceCommand internal-sftp",
                "DisableForwarding yes",
                "AllowTcpForwarding no",
                "AllowStreamLocalForwarding no",
                "AllowAgentForwarding no",
                "X11Forwarding no",
                "PermitTunnel no",
                "PermitTTY no",
                "PermitUserRC no",
                "Match all",
            ],
            "every directive is inside the Match block: nothing global"
        );
        Ok(())
    }

    #[tokio::test]
    async fn first_key_creates_the_access_with_exact_commands() -> Result<()> {
        let h = harness().await;
        let cfg = &h.ctx.config;
        let (rec, key, changed) = h.sftp.add_key("foo-bar", KEY_A, "").await?;
        assert!(changed);
        assert_eq!(key.fingerprint, FP_A);
        assert_eq!(key.label, "alice@laptop", "the key's own comment");
        assert_eq!(rec.sftp_keys, vec![key.clone()]);
        assert_eq!(h.tenants.get("foo-bar").await?.sftp_keys, vec![key]);

        let paths = SftpPaths::for_tenant(cfg, &rec)?;
        let home = cfg.home_base.join("foo-bar");
        let keys_file = cfg.sftp_keys_dir.join("foo-bar");
        assert_eq!(paths.keys_file, keys_file);
        assert_eq!(paths.chroot, cfg.state_dir.join("sftp").join("foo-bar"));
        assert_eq!(
            paths.mount_point,
            paths.chroot.join(home.strip_prefix("/").unwrap_or(&home))
        );
        let s = |p: &Path| p.to_string_lossy().into_owned();
        assert_eq!(
            argv(&h),
            vec![
                // Refused before anything is recorded unless sshd accepts the
                // drop-in and really confines this account.
                strs(&[bin::SSHD, "-t"]),
                strs(&[bin::SYSTEMCTL, "try-reload-or-restart", "sshd.service"]),
                strs(&[
                    bin::SSHD,
                    "-T",
                    "-C",
                    "user=foo-bar,host=localhost,addr=127.0.0.1"
                ]),
                // Then the access itself (the checks repeat, changing nothing).
                strs(&[
                    bin::SSHD,
                    "-T",
                    "-C",
                    "user=foo-bar,host=localhost,addr=127.0.0.1"
                ]),
                strs(&[bin::SYSTEMCTL, "daemon-reload"]),
                vec![
                    bin::SYSTEMCTL.to_owned(),
                    "enable".into(),
                    "--now".into(),
                    "--".into(),
                    paths.mount_unit_name.clone(),
                ],
                vec![
                    bin::SETFACL.to_owned(),
                    "-m".into(),
                    "u:foo-bar:r--".into(),
                    "--".into(),
                    s(&keys_file),
                ],
            ]
        );
        assert!(
            h.sys.calls().iter().all(|c| c.run_as.is_none()),
            "all of this is root's work"
        );

        assert_eq!(
            read(&cfg.sshd_dropin_file),
            render_sshd_dropin(cfg)?,
            "drop-in installed"
        );
        assert_eq!(
            read(&keys_file),
            format!("{HEADER}restrict ssh-ed25519 {BLOB_A} alice@laptop\n")
        );
        let unit = read(&paths.mount_unit);
        assert!(paths.mount_unit_name.ends_with("foo\\x2dbar.mount"));
        for line in [
            format!("What={}", s(&home)),
            format!("Where={}", s(&paths.mount_point)),
            "Type=none".to_owned(),
            "Options=bind".to_owned(),
            "LazyUnmount=yes".to_owned(),
            format!("RequiresMountsFor={}", s(&home)),
            "WantedBy=multi-user.target".to_owned(),
        ] {
            assert!(unit.lines().any(|l| l == line), "missing {line}\n{unit}");
        }
        assert!(paths.mount_point.is_dir());
        let mode = |p: &Path| std::fs::metadata(p).map(|m| m.permissions().mode() & 0o7777);
        assert_eq!(mode(&paths.chroot).ok(), Some(0o755));
        assert_eq!(mode(&cfg.sftp_keys_dir).ok(), Some(0o711));
        assert_eq!(mode(&keys_file).ok(), Some(0o640));
        assert_eq!(mode(&cfg.sshd_dropin_file).ok(), Some(0o600));
        Ok(())
    }

    #[tokio::test]
    async fn keys_are_idempotent_labelled_and_limited() -> Result<()> {
        let h = harness().await;
        h.sftp.add_key("foo-bar", KEY_A, "").await?;
        let (_, key, changed) = h.sftp.add_key("foo-bar", KEY_A, "").await?;
        assert!(!changed, "same key, same label");
        assert_eq!(key.label, "alice@laptop");
        let (_, key, changed) = h.sftp.add_key("foo-bar", KEY_A, "laptop").await?;
        assert!(changed, "a new label is a change");
        assert_eq!(key.label, "laptop");
        let (rec, key_b, changed) = h.sftp.add_key("foo-bar", KEY_B, "ci").await?;
        assert!(changed);
        assert_eq!(key_b.fingerprint, FP_B);
        assert_eq!(rec.sftp_keys.len(), 2);
        let listed: Vec<String> = h
            .sftp
            .list_keys("foo-bar")
            .await?
            .into_iter()
            .map(|k| format!("{} {}", k.fingerprint, k.label))
            .collect();
        assert_eq!(listed, vec![format!("{FP_A} laptop"), format!("{FP_B} ci")]);
        let keys_file = h.ctx.config.sftp_keys_dir.join("foo-bar");
        assert_eq!(read(&keys_file).lines().count(), 3, "header and two keys");
        assert!(read(&keys_file)
            .lines()
            .skip(1)
            .all(|l| l.starts_with("restrict ")));

        // Bad input never reaches the OS or the record.
        h.sys.clear_calls();
        for (user, key, label) in [
            ("foo-bar", "ssh-dss AAAA", ""),
            ("foo-bar", "command=\"sh\" ssh-ed25519 AAAA", ""),
            ("foo-bar", KEY_A, "two words"),
            ("root", KEY_A, ""),
        ] {
            assert!(
                matches!(
                    h.sftp.add_key(user, key, label).await,
                    Err(Error::InvalidInput { .. })
                ),
                "{user} {key} {label}"
            );
        }
        assert!(matches!(
            h.sftp.add_key("ghost", KEY_A, "").await,
            Err(Error::TenantNotFound(_))
        ));
        assert!(h.sys.calls().is_empty());

        // The limit counts keys, not requests.
        let mut rec = h.tenants.get("foo-bar").await?;
        let filler = rec.sftp_keys.first().cloned();
        while rec.sftp_keys.len() < MAX_SFTP_KEYS {
            rec.sftp_keys.extend(filler.clone());
        }
        rec.sftp_keys.retain(|k| k.fingerprint != FP_B);
        rec.sftp_keys.extend(filler);
        h.ctx.store.save_tenant(&rec)?;
        assert!(matches!(
            h.sftp.add_key("foo-bar", KEY_B, "").await,
            Err(Error::TooManySftpKeys(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn removing_a_key_ends_sessions_and_the_last_key_removes_everything() -> Result<()> {
        let h = harness().await;
        let cfg = &h.ctx.config;
        h.sftp.add_key("foo-bar", KEY_A, "").await?;
        let (rec, ..) = h.sftp.add_key("foo-bar", KEY_B, "").await?;
        let paths = SftpPaths::for_tenant(cfg, &rec)?;
        h.sys.clear_calls();

        let rec = h.sftp.remove_key("foo-bar", FP_A).await?;
        assert_eq!(rec.sftp_keys.len(), 1);
        assert!(!read(&paths.keys_file).contains(BLOB_A));
        assert_eq!(
            argv(&h).last(),
            Some(&strs(&[bin::SYSTEMCTL, "stop", "--", "user-20000.slice"])),
            "sessions authenticated with the key are ended"
        );
        assert!(paths.mount_unit.exists(), "one key left: access stays");
        assert!(matches!(
            h.sftp.remove_key("foo-bar", FP_A).await,
            Err(Error::SftpKeyNotFound { .. })
        ));
        assert!(matches!(
            h.sftp.remove_key("foo-bar", "SHA256:nope").await,
            Err(Error::InvalidInput { .. })
        ));

        h.sys.clear_calls();
        let rec = h.sftp.remove_key("foo-bar", FP_B).await?;
        assert!(rec.sftp_keys.is_empty());
        assert_eq!(
            argv(&h),
            vec![
                // Sessions end before the unmount: a session inside the home
                // would keep the mount busy.
                strs(&[bin::SYSTEMCTL, "stop", "--", "user-20000.slice"]),
                vec![
                    bin::SYSTEMCTL.to_owned(),
                    "disable".into(),
                    "--now".into(),
                    "--".into(),
                    paths.mount_unit_name.clone(),
                ],
                strs(&[bin::SYSTEMCTL, "daemon-reload"]),
            ]
        );
        assert!(!paths.keys_file.exists());
        assert!(!paths.mount_unit.exists());
        assert!(
            !paths.chroot.exists(),
            "empty chroot directories are removed"
        );
        assert!(
            cfg.home_base.join("foo-bar").is_dir(),
            "the home is untouched"
        );
        Ok(())
    }

    #[tokio::test]
    async fn removal_never_deletes_anything_inside_the_chroot_directory() -> Result<()> {
        let h = harness().await;
        let (rec, ..) = h.sftp.add_key("foo-bar", KEY_A, "").await?;
        let paths = SftpPaths::for_tenant(&h.ctx.config, &rec)?;
        // Stands in for a home that is still mounted there.
        let precious = paths.mount_point.join("index.html");
        std::fs::write(&precious, "data").map_err(|e| Error::io("write", &precious, e))?;
        assert!(matches!(
            h.sftp.remove_key("foo-bar", FP_A).await,
            Err(Error::Io { .. })
        ));
        assert_eq!(read(&precious), "data");
        // The key is gone from the record and from sshd's view all the same.
        assert!(h.tenants.get("foo-bar").await?.sftp_keys.is_empty());
        assert!(!paths.keys_file.exists());
        Ok(())
    }

    #[tokio::test]
    async fn a_host_that_cannot_confine_tenants_gets_no_keys() -> Result<()> {
        // sshd rejects the configuration: rolled back, nothing recorded.
        let h = harness().await;
        let cfg = &h.ctx.config;
        h.sys
            .script_failure(bin::SSHD, 255, "bad configuration option");
        let r = h.sftp.add_key("foo-bar", KEY_A, "").await;
        assert!(
            matches!(&r, Err(Error::SftpUnavailable(m)) if m.contains("bad configuration option")),
            "{r:?}"
        );
        assert!(!cfg.sshd_dropin_file.exists(), "rolled back");
        assert!(
            h.sys.calls_to(bin::SYSTEMCTL).is_empty(),
            "sshd was not reloaded"
        );
        assert!(h.tenants.get("foo-bar").await?.sftp_keys.is_empty());
        assert!(!is_available(&h.ctx).await?);

        // A previous drop-in survives a rejected new one.
        std::fs::write(&cfg.sshd_dropin_file, "# older version\n")
            .map_err(|e| Error::io("write", &cfg.sshd_dropin_file, e))?;
        h.sys.script_failure(bin::SSHD, 255, "no");
        assert!(h.sftp.add_key("foo-bar", KEY_A, "").await.is_err());
        assert_eq!(read(&cfg.sshd_dropin_file), "# older version\n");

        // sshd accepts the file but would not apply it to the tenant.
        h.sys.set_sshd_unconfined(true);
        let r = h.sftp.add_key("foo-bar", KEY_A, "").await;
        assert!(
            matches!(&r, Err(Error::SftpUnavailable(m)) if m.contains("would not confine")),
            "{r:?}"
        );
        assert!(h.tenants.get("foo-bar").await?.sftp_keys.is_empty());
        assert!(!cfg.sftp_keys_dir.join("foo-bar").exists());

        // No sshd at all.
        h.sys.set_sshd_unconfined(false);
        h.sys.set_missing(bin::SSHD);
        assert!(matches!(
            h.sftp.add_key("foo-bar", KEY_A, "").await,
            Err(Error::SftpUnavailable(_))
        ));

        // No drop-in directory: the host's sshd_config has no Include.
        let h = harness().await;
        let d = h.dir.path().join("sshd_config.d");
        std::fs::remove_dir(&d).map_err(|e| Error::io("rmdir", &d, e))?;
        let r = h.sftp.add_key("foo-bar", KEY_A, "").await;
        assert!(
            matches!(&r, Err(Error::SftpUnavailable(m)) if m.contains("Include")),
            "{r:?}"
        );
        assert!(!d.exists(), "never created behind the operator's back");
        Ok(())
    }

    #[tokio::test]
    async fn every_tenant_is_put_in_the_tenant_group() -> Result<()> {
        let h = harness().await;
        let tenant = h.tenants.get("foo-bar").await?;
        let group = h.sys.group_by_name("oxpanel-tenants").await?;
        assert!(group.is_some());
        let member = |sys: Arc<FakeSystem>, gid: u32| async move {
            sys.groups_of("foo-bar", gid)
                .await
                .map(|g| group.is_some_and(|x| g.contains(&x)))
        };
        assert!(
            member(h.sys.clone(), tenant.gid).await?,
            "CreateTenant did it"
        );
        // An account from before SFTP existed is caught up at start.
        h.sys
            .run_ok(
                CommandSpec::new(bin::GPASSWD, h.ctx.config.command_timeout).args([
                    "--delete",
                    "foo-bar",
                    "oxpanel-tenants",
                ]),
            )
            .await?;
        assert!(!member(h.sys.clone(), tenant.gid).await?);
        h.sys.clear_calls();
        assert_eq!(converge_all(&h.ctx).await?, 0);
        assert!(member(h.sys.clone(), tenant.gid).await?);
        assert_eq!(
            argv(&h),
            vec![
                strs(&[bin::SSHD, "-t"]),
                strs(&[bin::SYSTEMCTL, "try-reload-or-restart", "sshd.service"]),
                strs(&[bin::GPASSWD, "--add", "foo-bar", "oxpanel-tenants"]),
            ]
        );
        assert!(is_available(&h.ctx).await?);
        h.sys.clear_calls();
        assert_eq!(converge_all(&h.ctx).await?, 0);
        assert!(h.sys.calls().is_empty(), "converged: nothing to do");
        Ok(())
    }

    #[tokio::test]
    async fn start_up_restores_missing_pieces_from_the_record() -> Result<()> {
        let h = harness().await;
        let (rec, ..) = h.sftp.add_key("foo-bar", KEY_A, "").await?;
        let paths = SftpPaths::for_tenant(&h.ctx.config, &rec)?;
        for f in [&paths.keys_file, &paths.mount_unit] {
            std::fs::remove_file(f).map_err(|e| Error::io("unlink", f, e))?;
        }
        assert_eq!(converge_all(&h.ctx).await?, 1);
        assert!(paths.keys_file.exists() && paths.mount_unit.exists());
        Ok(())
    }

    #[tokio::test]
    async fn suspension_withdraws_the_keys_file_and_ends_sessions() -> Result<()> {
        let h = harness().await;
        let (rec, ..) = h.sftp.add_key("foo-bar", KEY_A, "").await?;
        let paths = SftpPaths::for_tenant(&h.ctx.config, &rec)?;
        h.sys.clear_calls();
        let (rec, changed) = h.tenants.set_suspended("foo-bar", true).await?;
        assert!(changed);
        assert!(!paths.keys_file.exists(), "no key can log in");
        assert!(paths.mount_unit.exists(), "the access itself is kept");
        assert_eq!(rec.sftp_keys.len(), 1, "and so are the keys");
        assert_eq!(
            argv(&h).last(),
            Some(&strs(&[bin::SYSTEMCTL, "stop", "--", "user-20000.slice"]))
        );
        // A key added while suspended is recorded but not usable yet.
        h.sftp.add_key("foo-bar", KEY_B, "").await?;
        assert!(!paths.keys_file.exists());
        let (_, changed) = h.tenants.set_suspended("foo-bar", false).await?;
        assert!(changed);
        assert_eq!(read(&paths.keys_file).lines().count(), 3);
        Ok(())
    }

    #[tokio::test]
    async fn deleting_a_tenant_removes_its_access_first() -> Result<()> {
        let h = harness().await;
        let (rec, ..) = h.sftp.add_key("foo-bar", KEY_A, "").await?;
        let paths = SftpPaths::for_tenant(&h.ctx.config, &rec)?;
        h.sys.clear_calls();
        assert!(h.tenants.delete("foo-bar", true).await?);
        let calls = argv(&h);
        let position = |needle: &[&str]| calls.iter().position(|c| *c == strs(needle));
        let stop = position(&[bin::SYSTEMCTL, "stop", "--", "user-20000.slice"]);
        let userdel = position(&[bin::USERDEL, "--remove", "foo-bar"]);
        let unmount = calls
            .iter()
            .position(|c| c.get(1).is_some_and(|a| a == "disable"));
        assert!(
            stop.is_some() && stop < unmount && unmount < userdel,
            "end sessions, unmount, then userdel: {calls:?}"
        );
        assert!(!paths.keys_file.exists());
        assert!(!paths.mount_unit.exists());
        assert!(!paths.chroot.exists());
        Ok(())
    }

    #[test]
    fn rendering_refuses_stored_values_that_could_inject_lines() {
        let n = Username::parse("alice").unwrap_or_else(|e| panic!("{e}"));
        let mut t = TenantRecord {
            version: crate::records::RECORD_VERSION,
            username: "alice".into(),
            uid: 20000,
            gid: 20000,
            home: PathBuf::from("/home/alice"),
            limits: Limits::default(),
            slice_unit: systemd::slice_unit_name(&n),
            created_at_unix: 0,
            state: TenantState::Ready,
            owner: String::new(),
            suspended: false,
            sftp_keys: vec![SftpKeyRecord {
                key_type: "ssh-ed25519".into(),
                blob: BLOB_A.into(),
                fingerprint: FP_A.into(),
                label: String::new(),
                added_at_unix: 0,
            }],
        };
        assert!(render_keys_file(&t).is_ok());
        let good = t.sftp_keys.clone();
        for edit in [
            |k: &mut SftpKeyRecord| k.label = "x\nssh-ed25519 AAAA".into(),
            |k: &mut SftpKeyRecord| k.key_type = "command=\"sh\" ssh-ed25519".into(),
            |k: &mut SftpKeyRecord| k.blob = format!("{BLOB_A}\nssh-ed25519 AAAA"),
            |k: &mut SftpKeyRecord| k.fingerprint = FP_B.into(),
        ] {
            t.sftp_keys.clone_from(&good);
            t.sftp_keys.iter_mut().for_each(edit);
            assert!(render_keys_file(&t).is_err());
        }
        t.sftp_keys = good;
        t.home = PathBuf::from("/home/alice\nOptions=suid");
        let cfg = Config::default();
        assert!(SftpPaths::for_tenant(&cfg, &t).is_err());
        t.home = PathBuf::from("/");
        assert!(SftpPaths::for_tenant(&cfg, &t).is_err());
    }
}
