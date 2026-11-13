//! In-memory [`System`] for tests and `--dry-run`.
//!
//! It emulates just enough of `useradd`, `userdel`, `nginx -t`, `mkdir -p`
//! and friends for the provisioning workflows to run end to end without
//! privileges, and records every command so tests can assert on the exact
//! argument vectors the daemon would have executed.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::fake_mariadb::FakeMariaDb;
use super::{
    bin, shadow_password_state, CommandOutput, CommandSpec, HostStats, OsUser, PasswordState,
    QuotaState, System,
};
use crate::error::{Error, Result};

#[derive(Debug, Default)]
struct Inner {
    users: BTreeMap<String, OsUser>,
    groups: BTreeMap<String, u32>,
    calls: Vec<CommandSpec>,
    /// Scripted outcomes consumed in order per program; `None` lets that
    /// invocation run normally.
    scripted: BTreeMap<&'static str, VecDeque<Option<(i32, String)>>>,
    selinux_enabled: bool,
    /// Supplementary group memberships: account name -> gids.
    memberships: BTreeMap<String, Vec<u32>>,
    /// Home directories the fake `userdel -r` removed.
    removed_homes: Vec<PathBuf>,
    /// Optional programs reported as not installed.
    missing: Vec<&'static str>,
    /// What `node --version` prints; `None` = a supported version.
    node_version: Option<String>,
    /// Scripted standard output, consumed in order per program.
    scripted_stdout: BTreeMap<&'static str, VecDeque<String>>,
    /// Free space reported by `host_stats`; `None` = 80 GiB.
    disk_free_bytes: Option<u64>,
    /// The emulated MariaDB server; `None` = MariaDB is not installed.
    mariadb: Option<FakeMariaDb>,
    /// Keys the fake `openssl genpkey` has handed out.
    generated_keys: u32,
    /// Lifetime of certificates the fake ACME client delivers; `None` = 90 days.
    acme_lifetime: Option<u64>,
    /// Failures the tests switch on.
    faults: FakeFaults,
    /// User quotas are enforced on the (one) fake file system.
    quota_enforced: bool,
    /// Per-uid quota state of the fake file system.
    quotas: BTreeMap<u32, FakeQuota>,
    ssh: FakeSsh,
    /// Password field per account, as `/etc/shadow` would hold it.
    shadow: BTreeMap<String, String>,
}

/// Failures the tests switch on (a struct of its own: clippy allows at most
/// three bools in one).
#[derive(Debug, Default)]
struct FakeFaults {
    /// The fake certificate authority refuses every order.
    acme_refuses: bool,
    /// Backup workers leave no archive behind (as if they had failed).
    worker_writes_nothing: bool,
}

/// sshd and login sessions on the fake host.
#[derive(Debug, Default)]
struct FakeSsh {
    /// The sshd drop-in is not in effect (`sshd -T` shows the defaults).
    unconfined: bool,
    /// Every tenant has an open login session (`user-<uid>.slice` active).
    sessions_open: bool,
}

/// Commands of the SFTP workflows: group membership, the shadow database,
/// `sshd -T` and the session check. `None` for anything else.
fn fake_ssh_and_accounts(i: &mut Inner, spec: &CommandSpec) -> Option<CommandOutput> {
    let args = &spec.args;
    let program = spec.program;
    let first = |s: &str| args.first().is_some_and(|a| a == s);
    Some(match program {
        bin::GPASSWD => fake_gpasswd(i, args),
        bin::CHPASSWD => fake_chpasswd(i, spec),
        bin::USERMOD => fake_usermod(i, args),
        // `systemd-run … -- rmdir -- <dir>…`: non-recursive, as the real one.
        bin::SYSTEMD_RUN if args.iter().any(|a| a == bin::RMDIR) => {
            let dirs = args.iter().skip_while(|a| *a != bin::RMDIR).skip(2);
            for dir in dirs {
                if let Err(e) = std::fs::remove_dir(dir) {
                    return Some(output(
                        program,
                        1,
                        "",
                        &format!("rmdir: {}: {e}", dir.to_string_lossy()),
                    ));
                }
            }
            output(program, 0, "", "")
        }
        // `sshd -T -C user=…`: the effective settings for one account.
        bin::SSHD if first("-T") => {
            let effective = if i.ssh.unconfined {
                "forcecommand none\nchrootdirectory none\nauthorizedkeysfile .ssh/authorized_keys\n"
            } else {
                "forcecommand internal-sftp\nchrootdirectory /fake/%u\nauthorizedkeysfile /fake/%u\ndisableforwarding yes\n"
            };
            output(program, 0, effective, "")
        }
        // `systemctl show --property=ActiveState --value -- user-<uid>.slice`
        bin::SYSTEMCTL
            if first("show")
                && has_flag(args, "--value")
                && args
                    .iter()
                    .any(|a| a.to_string_lossy().starts_with("user-")) =>
        {
            let state = if i.ssh.sessions_open {
                "active\n"
            } else {
                "inactive\n"
            };
            output(program, 0, state, "")
        }
        _ => return None,
    })
}

/// One user's row in the fake quota table (blocks in KiB, as `xfs_quota` prints).
#[derive(Debug, Default, Clone, Copy)]
struct FakeQuota {
    blocks_used: u64,
    blocks_hard: u64,
    inodes_used: u64,
    inodes_hard: u64,
}

#[derive(Debug, Default)]
pub struct FakeSystem {
    inner: Mutex<Inner>,
}

/// Block device of the fake file system that holds tenant homes.
pub const FAKE_DEVICE: &str = "/dev/fake0";
/// The group every tenant is put in (the default `OXPANEL_TENANT_GROUP`),
/// which exists on a fake host just as the package creates it on a real one.
pub const FAKE_TENANT_GROUP: (&str, u32) = ("oxpanel-tenants", 989);
/// The group of tenants with an SFTP password (the default
/// `OXPANEL_SFTP_PASSWORD_GROUP`), likewise created by the package.
pub const FAKE_PASSWORD_GROUP: (&str, u32) = ("oxpanel-sftp-password", 988);

impl FakeSystem {
    pub fn new() -> Self {
        let fake = Self::default();
        fake.add_group(FAKE_TENANT_GROUP.0, FAKE_TENANT_GROUP.1);
        fake.add_group(FAKE_PASSWORD_GROUP.0, FAKE_PASSWORD_GROUP.1);
        fake
    }

    /// Turn kernel-enforced user quotas on the fake file system on or off.
    pub fn set_quota_enforced(&self, on: bool) {
        if let Ok(mut i) = self.inner.lock() {
            i.quota_enforced = on;
        }
    }

    /// Pretend `uid` owns this much on the fake file system.
    pub fn set_quota_usage(&self, uid: u32, blocks_kib: u64, inodes: u64) {
        if let Ok(mut i) = self.inner.lock() {
            let q = i.quotas.entry(uid).or_default();
            q.blocks_used = blocks_kib;
            q.inodes_used = inodes;
        }
    }

    /// Change a limit behind the daemon's back (KiB, inodes).
    pub fn set_quota_limits(&self, uid: u32, blocks_hard_kib: u64, inodes_hard: u64) {
        if let Ok(mut i) = self.inner.lock() {
            let q = i.quotas.entry(uid).or_default();
            q.blocks_hard = blocks_hard_kib;
            q.inodes_hard = inodes_hard;
        }
    }

    /// The `(block limit in KiB, inode limit)` the fake kernel holds for `uid`.
    pub fn quota_limits(&self, uid: u32) -> (u64, u64) {
        self.inner
            .lock()
            .ok()
            .and_then(|i| i.quotas.get(&uid).map(|q| (q.blocks_hard, q.inodes_hard)))
            .unwrap_or_default()
    }

    /// Pretend every tenant has (or has not) an open login session.
    pub fn set_sessions_open(&self, open: bool) {
        if let Ok(mut i) = self.inner.lock() {
            i.ssh.sessions_open = open;
        }
    }

    /// Overwrite an account's shadow password field behind the daemon's back.
    pub fn set_shadow_field(&self, user: &str, field: &str) {
        if let Ok(mut i) = self.inner.lock() {
            i.shadow.insert(user.to_owned(), field.to_owned());
        }
    }

    /// Make `sshd -T` report an sshd that ignores the OxPanel drop-in.
    pub fn set_sshd_unconfined(&self, on: bool) {
        if let Ok(mut i) = self.inner.lock() {
            i.ssh.unconfined = on;
        }
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
                .push_back(Some((code, stderr.to_owned())));
        }
    }

    /// Let the next invocation of `program` run normally, so that a
    /// following [`Self::script_failure`] hits the one after it.
    pub fn script_pass_through(&self, program: &'static str) {
        if let Ok(mut i) = self.inner.lock() {
            i.scripted.entry(program).or_default().push_back(None);
        }
    }

    /// Pretend `program` is not installed (see [`System::is_installed`]).
    pub fn set_missing(&self, program: &'static str) {
        if let Ok(mut i) = self.inner.lock() {
            i.missing.push(program);
        }
    }

    /// Make `node --version` report `version` (e.g. `v16.20.2`).
    pub fn set_node_version(&self, version: &str) {
        if let Ok(mut i) = self.inner.lock() {
            i.node_version = Some(version.to_owned());
        }
    }

    /// Make the fake ACME client deliver certificates valid for `secs` seconds.
    pub fn set_acme_lifetime(&self, secs: u64) {
        if let Ok(mut i) = self.inner.lock() {
            i.acme_lifetime = Some(secs);
        }
    }

    /// Make the fake certificate authority refuse (or accept again) orders.
    /// The reachability pre-check is not affected.
    pub fn set_acme_refuses(&self, refuses: bool) {
        if let Ok(mut i) = self.inner.lock() {
            i.faults.acme_refuses = refuses;
        }
    }

    /// Install an (empty, running) emulated MariaDB server. Without this
    /// call the fake host has no MariaDB, like a host without the package.
    pub fn install_mariadb(&self) {
        if let Ok(mut i) = self.inner.lock() {
            i.mariadb.get_or_insert_with(FakeMariaDb::default);
        }
    }

    /// Start or stop the emulated server (stopped: connections are refused).
    pub fn set_mariadb_running(&self, running: bool) {
        if let Ok(mut i) = self.inner.lock() {
            if let Some(db) = i.mariadb.as_mut() {
                db.stopped = !running;
            }
        }
    }

    /// Run statements on the emulated server as its administrator would by
    /// hand, behind the daemon's back. Not recorded in [`Self::calls`].
    pub fn mariadb_admin(&self, script: &str) -> Result<String> {
        let mut i = self.lock()?;
        let db = i
            .mariadb
            .as_mut()
            .ok_or_else(|| Error::Internal("fake MariaDB is not installed".into()))?;
        match db.execute(script) {
            (0, stdout, _) => Ok(stdout),
            (_, _, stderr) => Err(Error::Internal(stderr)),
        }
    }

    /// The tables and objects of a schema on the emulated server (`None`
    /// when it does not exist): `(tables, [(KIND, name, definer)])`.
    pub fn mariadb_schema(&self, name: &str) -> Option<(Vec<String>, Vec<(String, String, String)>)> {
        let i = self.inner.lock().ok()?;
        let schema = i.mariadb.as_ref()?.schema(name)?;
        Some((
            schema.tables.into_iter().collect(),
            schema
                .objects
                .into_iter()
                .map(|((kind, name), o)| (kind, name, o.definer))
                .collect(),
        ))
    }

    /// Every script the daemon sent to the MariaDB client, in order.
    pub fn mariadb_scripts(&self) -> Vec<String> {
        self.calls_to(bin::MARIADB)
            .into_iter()
            .filter_map(|c| c.stdin)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .collect()
    }

    /// Make the next invocation of `program` succeed and print `stdout`.
    pub fn script_stdout(&self, program: &'static str, stdout: &str) {
        if let Ok(mut i) = self.inner.lock() {
            i.scripted_stdout
                .entry(program)
                .or_default()
                .push_back(stdout.to_owned());
        }
    }

    /// Free space `host_stats` reports for every file system.
    pub fn set_disk_free(&self, bytes: u64) {
        if let Ok(mut i) = self.inner.lock() {
            i.disk_free_bytes = Some(bytes);
        }
    }

    /// Whether the fake backup worker writes its archive (default) or leaves
    /// nothing behind, as a worker that failed or was killed would.
    pub fn set_worker_writes_nothing(&self, on: bool) {
        if let Ok(mut i) = self.inner.lock() {
            i.faults.worker_writes_nothing = on;
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

/// `gpasswd --add|--delete <user> <group>` on the fake account database.
fn fake_gpasswd(i: &mut Inner, args: &[OsString]) -> CommandOutput {
    let program = bin::GPASSWD;
    let arg = |n: usize| args.get(n).map(|a| a.to_string_lossy().into_owned());
    let (Some(verb), Some(user), Some(group)) = (arg(0), arg(1), arg(2)) else {
        return output(program, 2, "", "gpasswd: usage");
    };
    let Some(gid) = i.groups.get(&group).copied() else {
        return output(
            program,
            3,
            "",
            &format!("gpasswd: group '{group}' does not exist in /etc/group"),
        );
    };
    if !i.users.contains_key(&user) {
        return output(
            program,
            3,
            "",
            &format!("gpasswd: user '{user}' does not exist"),
        );
    }
    let members = i.memberships.entry(user.clone()).or_default();
    match verb.as_str() {
        "--add" => {
            if !members.contains(&gid) {
                members.push(gid);
            }
            output(program, 0, "", "")
        }
        "--delete" if members.contains(&gid) => {
            members.retain(|g| *g != gid);
            output(program, 0, "", "")
        }
        "--delete" => output(
            program,
            3,
            "",
            &format!("gpasswd: user '{user}' is not a member of '{group}'"),
        ),
        _ => output(program, 2, "", "gpasswd: usage"),
    }
}

/// `chpasswd [-e]` reading `user:password` lines from stdin. Without `-e` the
/// fake stores a stand-in hash, never the password.
fn fake_chpasswd(i: &mut Inner, spec: &CommandSpec) -> CommandOutput {
    let program = bin::CHPASSWD;
    let encrypted = has_flag(&spec.args, "-e");
    let Some(input) = spec.stdin.as_ref() else {
        return output(program, 1, "", "chpasswd: no input");
    };
    let text = String::from_utf8_lossy(input).into_owned();
    for line in text.lines() {
        let Some((user, password)) = line.split_once(':') else {
            return output(program, 1, "", "chpasswd: line 1: missing new password");
        };
        if !i.users.contains_key(user) {
            return output(
                program,
                1,
                "",
                &format!("chpasswd: line 1: user '{user}' does not exist"),
            );
        }
        let field = if encrypted {
            password.to_owned()
        } else {
            format!("$6$fake${}", password.len())
        };
        i.shadow.insert(user.to_owned(), field);
    }
    output(program, 0, "", "")
}

/// `usermod --lock|--unlock <user>` on the fake shadow database.
fn fake_usermod(i: &mut Inner, args: &[OsString]) -> CommandOutput {
    let program = bin::USERMOD;
    let Some(user) = args.last().map(|a| a.to_string_lossy().into_owned()) else {
        return output(program, 2, "", "usermod: usage");
    };
    let Some(field) = i.shadow.get(&user).cloned() else {
        return output(
            program,
            6,
            "",
            &format!("usermod: user '{user}' does not exist"),
        );
    };
    let new = if has_flag(args, "--lock") {
        if field.starts_with('!') {
            field
        } else {
            format!("!{field}")
        }
    } else if has_flag(args, "--unlock") {
        let rest = field.strip_prefix('!').unwrap_or(&field).to_owned();
        if rest.is_empty() || rest.starts_with('!') || rest.starts_with('*') {
            return output(
                program,
                1,
                "",
                "usermod: unlocking the user's password would result in a passwordless account.",
            );
        }
        rest
    } else {
        return output(program, 2, "", "usermod: usage");
    };
    i.shadow.insert(user, new);
    output(program, 0, "", "")
}

/// The value of `key=` inside an `xfs_quota` `limit` command, in the unit it
/// was given (`5120k` → 5120).
fn limit_value(command: &str, key: &str) -> Option<u64> {
    command
        .split(' ')
        .find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
        .and_then(|v| v.trim_end_matches('k').parse().ok())
}

/// `systemd-run … -- xfs_quota -x -c <command>… <device>`: apply `limit`
/// commands to the fake quota table and write what `report` commands print to
/// the file the transient unit's standard output is directed to.
/// The commands of the feature modules (SFTP, HTTPS, quotas, databases,
/// backup jobs). Order matters: the SFTP session check is a `systemctl show
/// --property=ActiveState` too, and must not be answered as a job unit.
fn fake_feature_command(i: &mut Inner, spec: &CommandSpec) -> Option<CommandOutput> {
    fake_ssh_and_accounts(i, spec)
        .or_else(|| fake_tls_quota_and_db(i, spec))
        .or_else(|| emulate_job(i, spec))
}

/// Commands of the HTTPS, disk-quota and database workflows: OpenSSL, the
/// ACME client and `xfs_quota` in their transient units, and the MariaDB
/// client. `None` for anything else.
fn fake_tls_quota_and_db(i: &mut Inner, spec: &CommandSpec) -> Option<CommandOutput> {
    let args = &spec.args;
    let program = spec.program;
    Some(match program {
        bin::OPENSSL => {
            let (code, stdout, stderr) = super::fake_tls::openssl(args, &mut i.generated_keys);
            output(program, code, &stdout, &stderr)
        }
        // The ACME client in its transient unit (other uses of systemd-run just succeed).
        bin::SYSTEMD_RUN if args.iter().any(|a| a == bin::OXPANEL_ACME) => {
            let (code, stderr) = if i.faults.acme_refuses && !args.iter().any(|a| a == "precheck") {
                (1, "no certificate: the authority refused (429): too many certificates (urn:ietf:params:acme:error:rateLimited)".to_owned())
            } else {
                super::fake_tls::acme_client(args, i.acme_lifetime.unwrap_or(90 * 86_400))
            };
            output(program, code, "", &stderr)
        }
        bin::SYSTEMD_RUN if args.iter().any(|a| a == bin::XFS_QUOTA) => fake_xfs_quota(i, args),
        bin::MARIADB => {
            let script =
                String::from_utf8_lossy(spec.stdin.as_deref().unwrap_or_default()).into_owned();
            let Some(db) = i.mariadb.as_mut() else {
                return Some(output(program, 127, "", "mariadb: not installed"));
            };
            let (code, stdout, stderr) = db.execute(&script);
            output(program, code, &stdout, &stderr)
        }
        _ => return None,
    })
}

fn fake_xfs_quota(i: &mut Inner, args: &[OsString]) -> CommandOutput {
    let program = bin::SYSTEMD_RUN;
    let args: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let Some(out_path) = args
        .iter()
        .find_map(|a| a.strip_prefix("--property=StandardOutput=truncate:"))
    else {
        return output(program, 1, "", "fake: no StandardOutput file");
    };
    let mut text = String::new();
    if !i.quota_enforced || args.last().map(String::as_str) != Some(FAKE_DEVICE) {
        // What the real tool does on a file system without quotas: nothing.
        return match std::fs::write(out_path, text) {
            Ok(()) => output(program, 0, "", ""),
            Err(e) => output(program, 1, "", &format!("fake: {e}")),
        };
    }
    let commands = args
        .iter()
        .zip(args.iter().skip(1))
        .filter(|(flag, _)| *flag == "-c")
        .map(|(_, command)| command.as_str());
    for command in commands {
        let uid = command
            .rsplit(' ')
            .next()
            .and_then(|w| w.parse::<u32>().ok());
        if command.starts_with("limit ") {
            let Some(uid) = uid else {
                return output(program, 1, "", "fake: limit without a uid");
            };
            let q = i.quotas.entry(uid).or_default();
            q.blocks_hard = limit_value(command, "bhard").unwrap_or(q.blocks_hard);
            q.inodes_hard = limit_value(command, "ihard").unwrap_or(q.inodes_hard);
        } else if command.starts_with("report ") {
            // `-L <uid> -U <uid>` restricts the report to one user.
            let only = command
                .split(' ')
                .skip_while(|w| *w != "-L")
                .nth(1)
                .and_then(|w| w.parse::<u32>().ok());
            for (uid, q) in &i.quotas {
                if only.is_none_or(|o| o == *uid) {
                    let _ = writeln!(
                        text,
                        "#{uid:<10} {:>10} {:>10} {:>10}     00 [--------] {:>10} {:>10} {:>10}     00 [--------]",
                        q.blocks_used, q.blocks_hard, q.blocks_hard, q.inodes_used, q.inodes_hard, q.inodes_hard
                    );
                }
            }
            text.push('\n');
        }
    }
    match std::fs::write(out_path, text) {
        Ok(()) => output(program, 0, "", ""),
        Err(e) => output(program, 1, "", &format!("fake: {e}")),
    }
}

/// Scripted standard output, and the transient units of backup and restore
/// jobs: the worker "runs" at once, a backup leaves a small archive with its
/// result file like the real one, and the unit reports success afterwards.
fn emulate_job(i: &mut Inner, spec: &CommandSpec) -> Option<CommandOutput> {
    let (program, args) = (spec.program, &spec.args);
    if let Some(stdout) = i
        .scripted_stdout
        .get_mut(program)
        .and_then(VecDeque::pop_front)
    {
        return Some(output(program, 0, &stdout, ""));
    }
    match program {
        bin::SYSTEMD_RUN if has_flag(args, "worker") => {
            if has_flag(args, "backup") && !i.faults.worker_writes_nothing {
                if let Some(path) = arg_value(args, "--output") {
                    let path = Path::new(&path);
                    let mut written = crate::worker::write_fake_archive(path);
                    // One dump member per database, next to the archive.
                    let databases = arg_value(args, "--databases").unwrap_or_default();
                    for db in databases.split(',').filter(|d| !d.is_empty() && *d != "-") {
                        let member = path.with_file_name(crate::worker::dump_member(db));
                        written = written.and_then(|()| {
                            crate::worker::write_fake_member(&member, crate::worker::KIND_MARIADB)
                        });
                    }
                    if let Err(e) = written {
                        return Some(output(program, 1, "", &e.to_string()));
                    }
                }
            }
            // A database restore "loads" one table into the new database.
            if has_flag(args, "restore-db") {
                if let (Some(db), Some(server)) = (arg_value(args, "--database"), i.mariadb.as_mut()) {
                    let _ = server.execute(&format!("CREATE TABLE `{db}`.`from_dump` (a INT);\n"));
                }
            }
            Some(output(program, 0, "", ""))
        }
        bin::SYSTEMCTL if has_flag(args, "--property=ActiveState") => Some(output(
            program,
            0,
            "LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nExecMainStatus=0\n",
            "",
        )),
        _ => None,
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
            .flatten()
        {
            return Ok(output(spec.program, code, "", &stderr));
        }
        if let Some(out) = fake_feature_command(&mut i, &spec) {
            return Ok(out);
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
                i.shadow.insert(name.clone(), "!!".to_owned());
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
                i.memberships.remove(&name);
                i.shadow.remove(&name);
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
            bin::NODE => {
                let version = i.node_version.clone().unwrap_or_else(|| "v22.11.0".to_owned());
                output(program, 0, &format!("{version}\n"), "")
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
        self.inner.lock().is_ok_and(|i| {
            !i.missing.contains(&program) && (program != bin::MARIADB || i.mariadb.is_some())
        })
    }

    async fn host_stats(&self, _path: &Path) -> Result<HostStats> {
        let free = self.lock()?.disk_free_bytes.unwrap_or(80 << 30);
        Ok(HostStats {
            load: (0.25, 0.5, 0.75),
            memory_total_bytes: 8 << 30,
            memory_free_bytes: 6 << 30,
            uptime_secs: 3600,
            disk_total_bytes: 100 << 30,
            disk_free_bytes: free,
        })
    }

    async fn password_state(&self, user: &str) -> Result<PasswordState> {
        let i = self.lock()?;
        Ok(i.shadow.get(user).map_or(PasswordState::Missing, |field| {
            shadow_password_state(&format!("{user}:{field}:"), user)
        }))
    }

    async fn quota_state(&self, _path: &Path) -> Result<QuotaState> {
        Ok(QuotaState {
            fs_type: "xfs".to_owned(),
            device: PathBuf::from(FAKE_DEVICE),
            user_quota_enforced: self.lock()?.quota_enforced,
        })
    }
}
