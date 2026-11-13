//! Description of an external command and its result.

use std::ffi::{OsStr, OsString};
use std::time::Duration;

use crate::error::{Error, Result};

use super::bin;

/// Identity a command should run as (instead of the daemon's root identity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunAs {
    pub uid: u32,
    pub gid: u32,
}

/// Bytes handed to a command on its standard input because they must never
/// be in its argv (which every local user can read in `/proc`) or in a log:
/// passwords. `Debug` never shows them.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// The bytes, for the one place that writes them to the child.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

/// An external program invocation: absolute program path plus discrete arguments.
#[derive(Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: &'static str,
    pub args: Vec<OsString>,
    pub run_as: Option<RunAs>,
    pub timeout: Duration,
    /// Bytes written to the program's standard input, which is then closed.
    /// `None` = `/dev/null`.
    pub stdin: Option<Vec<u8>>,
    /// The input carries a secret: it is never printed, and what the program
    /// writes to stderr is not logged (a tool may echo its input there).
    pub secret_input: bool,
}

/// A secret input is not part of the debug representation.
impl std::fmt::Debug for CommandSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stdin = match &self.stdin {
            None => None,
            Some(_) if self.secret_input => Some("<redacted>".to_owned()),
            Some(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
        };
        f.debug_struct("CommandSpec")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("run_as", &self.run_as)
            .field("timeout", &self.timeout)
            .field("stdin", &stdin)
            .finish()
    }
}

impl CommandSpec {
    pub fn new(program: &'static str, timeout: Duration) -> Self {
        Self {
            program,
            args: Vec::new(),
            run_as: None,
            timeout,
            stdin: None,
            secret_input: false,
        }
    }

    /// Feed `input` to the program's standard input.
    #[must_use]
    pub fn stdin(mut self, input: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(input.into());
        self
    }

    /// Like [`Self::stdin`] for input that carries a secret. Secrets go
    /// here and nowhere else: never into an argument (see [`Self::display`]).
    #[must_use]
    pub fn secret_stdin(mut self, input: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(input.into());
        self.secret_input = true;
        self
    }

    /// Feed `secret` to the command on its standard input, as
    /// [`Self::secret_stdin`] does (SFTP passwords to `chpasswd`). It never
    /// appears in [`Self::display`], in the argv or in `Debug`.
    #[must_use]
    pub fn stdin_secret(self, secret: Secret) -> Self {
        self.secret_stdin(secret.0)
    }

    #[must_use]
    pub fn arg(mut self, a: impl AsRef<OsStr>) -> Self {
        self.args.push(a.as_ref().to_owned());
        self
    }

    #[must_use]
    pub fn args<I, S>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(it.into_iter().map(|a| a.as_ref().to_owned()));
        self
    }

    /// Run with the given identity, all privileges dropped.
    #[must_use]
    pub fn as_user(mut self, uid: u32, gid: u32) -> Self {
        self.run_as = Some(RunAs { uid, gid });
        self
    }

    /// The `(program, argv)` that is actually executed.
    ///
    /// For root commands this is the spec itself. For [`Self::as_user`]
    /// commands the program is wrapped in `setpriv`, which switches uid/gid,
    /// clears supplementary groups, empties the capability bounding and
    /// inheritable sets and sets `no_new_privs` before exec'ing the target —
    /// so nothing run on a tenant's behalf can regain privilege.
    pub fn exec_plan(&self) -> (&'static str, Vec<OsString>) {
        match self.run_as {
            None => (self.program, self.args.clone()),
            Some(RunAs { uid, gid }) => {
                let mut argv: Vec<OsString> = vec![
                    format!("--reuid={uid}").into(),
                    format!("--regid={gid}").into(),
                    "--clear-groups".into(),
                    "--bounding-set=-all".into(),
                    "--inh-caps=-all".into(),
                    "--no-new-privs".into(),
                    "--".into(),
                    self.program.into(),
                ];
                argv.extend(self.args.iter().cloned());
                (bin::SETPRIV, argv)
            }
        }
    }

    /// Human-readable rendering for logs.
    pub fn display(&self) -> String {
        let (program, argv) = self.exec_plan();
        let mut s = String::from(program);
        for a in argv {
            s.push(' ');
            s.push_str(&a.to_string_lossy());
        }
        s
    }
}

/// Maximum number of bytes of command output retained for diagnostics.
pub const OUTPUT_CAP: usize = 16 * 1024;

/// Result of running a [`CommandSpec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub program: &'static str,
    /// Exit code, or `None` if terminated by a signal.
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    pub fn stdout_lossy(&self) -> String {
        lossy_capped(&self.stdout)
    }

    pub fn stderr_lossy(&self) -> String {
        lossy_capped(&self.stderr)
    }

    /// Both streams, stderr first — what a human wants to read when a tool fails.
    pub fn combined_lossy(&self) -> String {
        let mut s = self.stderr_lossy();
        let out = self.stdout_lossy();
        if !out.is_empty() {
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str(&out);
        }
        s
    }

    /// Turn a non-zero exit into [`Error::CommandFailed`].
    pub fn into_result(self) -> Result<Self> {
        if self.success() {
            Ok(self)
        } else {
            Err(Error::CommandFailed {
                program: self.program.to_owned(),
                status: self
                    .code
                    .map_or_else(|| "signal".to_owned(), |c| format!("status {c}")),
                stderr: self.stderr_lossy(),
            })
        }
    }
}

fn lossy_capped(bytes: &[u8]) -> String {
    let end = bytes.len().min(OUTPUT_CAP);
    let s = String::from_utf8_lossy(bytes.get(..end).unwrap_or_default());
    let mut s = s.trim_end().to_owned();
    if bytes.len() > OUTPUT_CAP {
        s.push_str("\n[truncated]");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_plan_is_verbatim() {
        let spec = CommandSpec::new(bin::USERADD, Duration::from_secs(1))
            .arg("--uid")
            .arg("20000");
        let (p, argv) = spec.exec_plan();
        assert_eq!(p, bin::USERADD);
        assert_eq!(argv, vec![OsString::from("--uid"), OsString::from("20000")]);
    }

    #[test]
    fn as_user_plan_wraps_in_setpriv_with_full_privilege_drop() {
        let spec = CommandSpec::new(bin::MKDIR, Duration::from_secs(1))
            .args(["-p", "/home/alice/public_html"])
            .as_user(20000, 20000);
        let (p, argv) = spec.exec_plan();
        assert_eq!(p, bin::SETPRIV);
        let argv: Vec<String> = argv
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            argv,
            vec![
                "--reuid=20000",
                "--regid=20000",
                "--clear-groups",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--no-new-privs",
                "--",
                bin::MKDIR,
                "-p",
                "/home/alice/public_html",
            ]
        );
    }

    #[test]
    fn secrets_stay_out_of_argv_display_and_debug() {
        let spec = CommandSpec::new(bin::CHPASSWD, Duration::from_secs(1))
            .stdin_secret(Secret::new("alice:hunter2-hunter2"));
        assert!(spec.exec_plan().1.is_empty());
        assert!(!spec.display().contains("hunter2"));
        assert!(!format!("{spec:?}").contains("hunter2"));
        assert_eq!(spec.stdin.as_deref(), Some(&b"alice:hunter2-hunter2"[..]));
        // A secret input also keeps the child's stderr out of the journal.
        assert!(spec.secret_input);
        assert!(!format!("{:?}", Secret::new("hunter2")).contains("hunter2"));
    }

    #[test]
    fn non_zero_exit_becomes_command_failed_without_losing_stderr() {
        let out = CommandOutput {
            program: bin::NGINX,
            code: Some(1),
            stdout: vec![],
            stderr: b"bad".to_vec(),
        };
        match out.into_result() {
            Err(Error::CommandFailed {
                program,
                status,
                stderr,
            }) => {
                assert_eq!(program, bin::NGINX);
                assert_eq!(status, "status 1");
                assert_eq!(stderr, "bad");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn secret_input_is_never_printed() {
        let spec = CommandSpec::new(bin::MARIADB, Duration::from_secs(1))
            .arg("--batch")
            .secret_stdin("ALTER USER x IDENTIFIED VIA y USING '*HASH';");
        assert!(spec.secret_input);
        assert!(!format!("{spec:?}").contains("HASH"));
        assert!(format!("{spec:?}").contains("<redacted>"));
        assert_eq!(spec.display(), "/usr/bin/mariadb --batch");
        let plain = CommandSpec::new(bin::MARIADB, Duration::from_secs(1)).stdin("SELECT 1;");
        assert!(!plain.secret_input);
        assert!(format!("{plain:?}").contains("SELECT 1;"));
        assert!(!plain.display().contains("SELECT"));
    }

    #[test]
    fn output_is_capped() {
        let big = vec![b'x'; OUTPUT_CAP + 10];
        let out = CommandOutput {
            program: bin::NGINX,
            code: Some(0),
            stdout: big,
            stderr: vec![],
        };
        let s = out.stdout_lossy();
        assert!(s.ends_with("[truncated]"));
        assert!(s.len() < OUTPUT_CAP + 32);
    }
}
