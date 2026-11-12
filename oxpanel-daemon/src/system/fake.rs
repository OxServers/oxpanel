//! In-memory [`System`] for tests and `--dry-run`.
//!
//! It emulates just enough of `useradd`, `userdel`, `nginx -t`, `mkdir -p`
//! and friends for the provisioning workflows to run end to end without
//! privileges, and records every command so tests can assert on the exact
//! argument vectors the daemon would have executed.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::{bin, CommandOutput, CommandSpec, HostStats, OsUser, System};
use crate::error::{Error, Result};

#[derive(Debug, Default)]
struct Inner {
    users: BTreeMap<String, OsUser>,
    groups: BTreeMap<String, u32>,
    calls: Vec<CommandSpec>,
    /// Scripted outcomes consumed in order per program.
    scripted: BTreeMap<&'static str, VecDeque<(i32, String)>>,
    selinux_enabled: bool,
    /// Supplementary group memberships: account name -> gids.
    memberships: BTreeMap<String, Vec<u32>>,
    /// Home directories the fake `userdel -r` removed.
    removed_homes: Vec<PathBuf>,
    /// Optional programs reported as not installed.
    missing: Vec<&'static str>,
}

#[derive(Debug, Default)]
pub struct FakeSystem {
    inner: Mutex<Inner>,
}

impl FakeSystem {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>> {
        self.inner
            .lock()
            .map_err(|_| Error::Internal("fake system poisoned".into()))
    }

    /// Pre-populate an account that OxPanel did *not* create.
    pub fn add_user(&self, user: OsUser) {
        if let Ok(mut i) = self.inner.lock() {
            i.groups.insert(user.name.clone(), user.gid);
            i.users.insert(user.name.clone(), user);
        }
    }

    pub fn add_group(&self, name: &str, gid: u32) {
        if let Ok(mut i) = self.inner.lock() {
            i.groups.insert(name.to_owned(), gid);
        }
    }

    /// Give an existing account a supplementary group.
    pub fn add_membership(&self, user: &str, gid: u32) {
        if let Ok(mut i) = self.inner.lock() {
            i.memberships.entry(user.to_owned()).or_default().push(gid);
        }
    }

    pub fn set_selinux_enabled(&self, on: bool) {
        if let Ok(mut i) = self.inner.lock() {
            i.selinux_enabled = on;
        }
    }

    /// Make the next invocation of `program` exit with `code` and `stderr`.
    pub fn script_failure(&self, program: &'static str, code: i32, stderr: &str) {
        if let Ok(mut i) = self.inner.lock() {
            i.scripted
                .entry(program)
                .or_default()
                .push_back((code, stderr.to_owned()));
        }
    }

    /// Pretend `program` is not installed (see [`System::is_installed`]).
    pub fn set_missing(&self, program: &'static str) {
        if let Ok(mut i) = self.inner.lock() {
            i.missing.push(program);
        }
    }

    /// Forget recorded commands (tests call this after harness setup).
    pub fn clear_calls(&self) {
        if let Ok(mut i) = self.inner.lock() {
            i.calls.clear();
        }
    }

    /// Every command executed so far, in order.
    pub fn calls(&self) -> Vec<CommandSpec> {
        self.inner
            .lock()
            .map(|i| i.calls.clone())
            .unwrap_or_default()
    }

    /// Commands whose program is `program`.
    pub fn calls_to(&self, program: &'static str) -> Vec<CommandSpec> {
        self.calls()
            .into_iter()
            .filter(|c| c.program == program)
            .collect()
    }

    pub fn users(&self) -> Vec<OsUser> {
        self.inner
            .lock()
            .map(|i| i.users.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn removed_homes(&self) -> Vec<PathBuf> {
        self.inner
            .lock()
            .map(|i| i.removed_homes.clone())
            .unwrap_or_default()
    }
}

fn arg_value(args: &[OsString], flag: &str) -> Option<String> {
    let idx = args.iter().position(|a| a == flag)?;
    args.get(idx + 1).map(|v| v.to_string_lossy().into_owned())
}

fn has_flag(args: &[OsString], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn output(program: &'static str, code: i32, stdout: &str, stderr: &str) -> CommandOutput {
    CommandOutput {
        program,
        code: Some(code),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[tonic::async_trait]
impl System for FakeSystem {
    async fn run(&self, spec: CommandSpec) -> Result<CommandOutput> {
        let mut i = self.lock()?;
        i.calls.push(spec.clone());
        if let Some((code, stderr)) = i
            .scripted
            .get_mut(spec.program)
            .and_then(VecDeque::pop_front)
        {
            return Ok(output(spec.program, code, "", &stderr));
        }
        let args = &spec.args;
        let program = spec.program;
        let out = match program {
            bin::USERADD => {
                // Last non-option argument is the login name.
                let Some(name) = args.iter().rev().find(|a| !a.to_string_lossy().starts_with('-')) else {
                    return Ok(output(program, 2, "", "useradd: no login name"));
                };
                let name = name.to_string_lossy().into_owned();
                if i.users.contains_key(&name) {
                    return Ok(output(program, 9, "", &format!("useradd: user '{name}' already exists")));
                }
                if i.groups.contains_key(&name) && has_flag(args, "--user-group") {
                    return Ok(output(program, 9, "", &format!("useradd: group {name} exists - if you want to add this user to that group, use -g.")));
                }
                let Some(uid) = arg_value(args, "--uid").and_then(|v| v.parse::<u32>().ok()) else {
                    return Ok(output(program, 3, "", "useradd: invalid user ID"));
                };
                if i.users.values().any(|u| u.uid == uid) {
                    return Ok(output(program, 4, "", &format!("useradd: UID {uid} is not unique")));
                }
                let home = PathBuf::from(arg_value(args, "--home-dir").unwrap_or_else(|| format!("/home/{name}")));
                if has_flag(args, "--create-home") {
                    if let Err(e) = create_private_dir(&home) {
                        return Ok(output(program, 12, "", &format!("useradd: cannot create directory {}: {e}", home.display())));
                    }
                }
                let shell = PathBuf::from(arg_value(args, "--shell").unwrap_or_else(|| "/bin/bash".to_owned()));
                i.groups.insert(name.clone(), uid);
                i.users.insert(name.clone(), OsUser { name, uid, gid: uid, home, shell });
                output(program, 0, "", "")
            }
            bin::USERDEL => {
                let Some(name) = args.iter().rev().find(|a| !a.to_string_lossy().starts_with('-')) else {
                    return Ok(output(program, 2, "", "userdel: no login name"));
                };
                let name = name.to_string_lossy().into_owned();
                let Some(user) = i.users.remove(&name) else {
                    return Ok(output(program, 6, "", &format!("userdel: user '{name}' does not exist")));
                };
                i.groups.remove(&name);
                if has_flag(args, "--remove") || has_flag(args, "-r") {
                    let _ = std::fs::remove_dir_all(&user.home);
                    i.removed_homes.push(user.home);
                }
                output(program, 0, "", "")
            }
            bin::NGINX => output(program, 0, "", "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful"),
            bin::SELINUXENABLED => output(program, i32::from(!i.selinux_enabled), "", ""),
            bin::GETSEBOOL => {
                let name = args.last().map(|a| a.to_string_lossy().into_owned()).unwrap_or_default();
                output(program, 0, &format!("{name} --> on\n"), "")
            }
            bin::MKDIR => {
                let Some(target) = args.iter().rev().find(|a| !a.to_string_lossy().starts_with('-')) else {
                    return Ok(output(program, 1, "", "mkdir: missing operand"));
                };
                match std::fs::create_dir_all(target) {
                    Ok(()) => output(program, 0, "", ""),
                    Err(e) => output(program, 1, "", &format!("mkdir: {e}")),
                }
            }
            // The OxPanel policy module is loaded unless a test says otherwise.
            bin::SEMODULE => {
                let listing = if i.missing.contains(&bin::SEMODULE) { "abrt\nzebra\n" } else { "abrt\noxpanel\nzebra\n" };
                output(program, 0, listing, "")
            }
            bin::DU => {
                let target = args.last().map(|a| a.to_string_lossy().into_owned()).unwrap_or_default();
                output(program, 0, &format!("8192\t{target}\n"), "")
            }
            bin::SYSTEMCTL if args.first().is_some_and(|a| a == "show") => {
                // Two units are queried; only the first has anything running.
                output(program, 0, "MemoryCurrent=1048576\nCPUUsageNSec=5000000\nTasksCurrent=3\n\nMemoryCurrent=[not set]\nCPUUsageNSec=[not set]\nTasksCurrent=[not set]\n", "")
            }
            // systemctl, restorecon, setfacl and anything else: succeed silently.
            _ => output(program, 0, "", ""),
        };
        Ok(out)
    }

    async fn user_by_name(&self, name: &str) -> Result<Option<OsUser>> {
        Ok(self.lock()?.users.get(name).cloned())
    }

    async fn user_by_uid(&self, uid: u32) -> Result<Option<OsUser>> {
        Ok(self.lock()?.users.values().find(|u| u.uid == uid).cloned())
    }

    async fn group_by_name(&self, name: &str) -> Result<Option<u32>> {
        Ok(self.lock()?.groups.get(name).copied())
    }

    async fn groups_of(&self, name: &str, primary_gid: u32) -> Result<Vec<u32>> {
        let i = self.lock()?;
        let mut out = vec![primary_gid];
        out.extend(i.memberships.get(name).into_iter().flatten().copied());
        Ok(out)
    }

    async fn ensure_private_dir(&self, path: &Path, _uid: u32, _gid: u32) -> Result<()> {
        create_private_dir(path).map_err(|e| Error::io("ensure_private_dir", path, e))
    }

    /// Unprivileged fake: the directory cannot be chowned to the tenant, so
    /// only the symlink/directory checks are enforced.
    async fn verify_owned_dir(&self, path: &Path, _uid: u32) -> Result<()> {
        let md = std::fs::symlink_metadata(path).map_err(|e| Error::io("lstat", path, e))?;
        if md.file_type().is_symlink() || !md.is_dir() {
            return Err(Error::invalid(
                "document_root",
                "must be a directory, not a symlink or file",
            ));
        }
        Ok(())
    }

    /// Unprivileged fake: ownership cannot be checked, only the file type.
    async fn inspect_private_dir(
        &self,
        path: &Path,
        _uid: u32,
        _gid: u32,
    ) -> Result<Option<String>> {
        Ok(match std::fs::symlink_metadata(path) {
            Err(_) => Some("missing".to_owned()),
            Ok(md) if md.file_type().is_symlink() || !md.is_dir() => {
                Some("not a directory".to_owned())
            }
            Ok(_) => None,
        })
    }

    async fn is_installed(&self, program: &'static str) -> bool {
        self.inner
            .lock()
            .is_ok_and(|i| !i.missing.contains(&program))
    }

    async fn host_stats(&self, _path: &Path) -> Result<HostStats> {
        Ok(HostStats {
            load: (0.25, 0.5, 0.75),
            memory_total_bytes: 8 << 30,
            memory_free_bytes: 6 << 30,
            uptime_secs: 3600,
            disk_total_bytes: 100 << 30,
            disk_free_bytes: 80 << 30,
        })
    }
}
