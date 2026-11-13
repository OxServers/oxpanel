//! A MariaDB server small enough to live inside [`super::FakeSystem`].
//!
//! It understands exactly the statements [`crate::db::mariadb`] issues (plus a
//! few an administrator would type by hand, so tests can create drift) and
//! answers the state queries from what those statements built up. Anything
//! else is a syntax error — a statement the daemon was not meant to send
//! fails a test instead of passing silently.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::db::mariadb::{AUTH_PLUGIN, GRANT_OPTION, SIZES_SQL_PREFIX, SNAPSHOT_SQL};

const VERSION: &str = "10.5.29-MariaDB";
/// What every database "weighs" (one empty `InnoDB` table).
const SIZE: u64 = 16_384;

#[derive(Debug, Clone, Default)]
struct FakeAccount {
    locked: bool,
    max_user_connections: u32,
}

#[derive(Debug)]
pub(super) struct FakeMariaDb {
    /// A stopped server refuses connections.
    pub(super) stopped: bool,
    schemata: BTreeSet<String>,
    /// `(user, host)` → account.
    accounts: BTreeMap<(String, String), FakeAccount>,
    /// `(grantee, stored pattern)` → privileges.
    db_privs: BTreeMap<(String, String), BTreeSet<String>>,
    /// grantee → global privileges.
    global: BTreeMap<String, BTreeSet<String>>,
    /// Grantees holding a table-level grant.
    table_grants: BTreeSet<String>,
}

impl Default for FakeMariaDb {
    /// A freshly installed server: its own schemas and accounts.
    fn default() -> Self {
        let account = |user: &str, locked| {
            (
                (user.to_owned(), "localhost".to_owned()),
                FakeAccount {
                    locked,
                    max_user_connections: 0,
                },
            )
        };
        Self {
            stopped: false,
            schemata: ["information_schema", "mysql", "performance_schema"]
                .map(str::to_owned)
                .into(),
            accounts: [
                account("root", false),
                account("mysql", false),
                account("mariadb.sys", true),
            ]
            .into(),
            db_privs: BTreeMap::new(),
            global: [(
                "'root'@'localhost'".to_owned(),
                ["SUPER", GRANT_OPTION].map(str::to_owned).into(),
            )]
            .into(),
            table_grants: BTreeSet::new(),
        }
    }
}

/// `'user'@'host'` at the start of `s` → `((user, host), rest)`.
fn parse_account(s: &str) -> Option<((String, String), &str)> {
    let (user, rest) = s.strip_prefix('\'')?.split_once("'@'")?;
    let (host, rest) = rest.split_once('\'')?;
    Some(((user.to_owned(), host.to_owned()), rest))
}

fn grantee(account: &(String, String)) -> String {
    format!("'{}'@'{}'", account.0, account.1)
}

/// `` `name` `` at the start of `s` → `(name, rest)`.
fn parse_ident(s: &str) -> Option<(&str, &str)> {
    s.strip_prefix('`')?.split_once('`')
}

impl FakeMariaDb {
    /// Run a script as the `mariadb` client would: `(exit code, stdout, stderr)`.
    pub(super) fn execute(&mut self, script: &str) -> (i32, String, String) {
        if self.stopped {
            return (
                1,
                String::new(),
                "ERROR 2002 (HY000): Can't connect to local server through socket '/var/lib/mysql/mysql.sock' (2)".to_owned(),
            );
        }
        if script == SNAPSHOT_SQL {
            return (0, self.snapshot(), String::new());
        }
        if let Some(rest) = script.strip_prefix(SIZES_SQL_PREFIX) {
            return (0, self.sizes(rest), String::new());
        }
        for (n, line) in script.lines().enumerate() {
            let Some(statement) = line.strip_suffix(';') else {
                return (1, String::new(), syntax_error(n, line));
            };
            if let Err(error) = self.statement(statement) {
                // The real client echoes the failing statement.
                let (code, message) = error.split_once(": ").unwrap_or((&error, ""));
                let stderr = format!(
                    "--------------\n{statement}\n--------------\n\nERROR {code} at line {}: {message}",
                    n + 1
                );
                return (1, String::new(), stderr);
            }
        }
        (0, String::new(), String::new())
    }

    fn statement(&mut self, s: &str) -> Result<(), String> {
        let syntax = || format!("1064 (42000): You have an error in your SQL syntax near '{s}'");
        if let Some(rest) = s.strip_prefix("CREATE DATABASE ") {
            let rest = rest.strip_prefix("IF NOT EXISTS ").unwrap_or(rest);
            let (name, _) = parse_ident(rest).ok_or_else(syntax)?;
            self.schemata.insert(name.to_owned());
        } else if let Some(rest) = s.strip_prefix("DROP DATABASE ") {
            let rest = rest.strip_prefix("IF EXISTS ").unwrap_or(rest);
            let (name, _) = parse_ident(rest).ok_or_else(syntax)?;
            self.schemata.remove(name);
        } else if let Some(rest) = s
            .strip_prefix("CREATE OR REPLACE USER ")
            .or_else(|| s.strip_prefix("CREATE USER "))
        {
            let (account, rest) = parse_account(rest).ok_or_else(syntax)?;
            self.drop_account(&account);
            let max_user_connections = rest
                .split_once(" WITH MAX_USER_CONNECTIONS ")
                .and_then(|(_, r)| r.split(' ').next()?.parse().ok())
                .unwrap_or(0);
            let known_auth = rest.is_empty()
                || rest.starts_with(&format!(" IDENTIFIED VIA {AUTH_PLUGIN} USING '*"));
            if !known_auth {
                return Err(syntax());
            }
            self.accounts.insert(
                account,
                FakeAccount {
                    locked: rest.ends_with(" ACCOUNT LOCK"),
                    max_user_connections,
                },
            );
        } else if let Some(rest) = s.strip_prefix("ALTER USER ") {
            let (account, rest) = parse_account(rest).ok_or_else(syntax)?;
            let entry = self.accounts.get_mut(&account).ok_or_else(|| {
                format!(
                    "1396 (HY000): Operation ALTER USER failed for {}",
                    grantee(&account)
                )
            })?;
            if rest == " ACCOUNT LOCK" {
                entry.locked = true;
            } else if rest == " ACCOUNT UNLOCK" {
                entry.locked = false;
            } else if let Some(n) = rest.strip_prefix(" WITH MAX_USER_CONNECTIONS ") {
                entry.max_user_connections = n.parse().map_err(|_| syntax())?;
            } else if !rest.starts_with(&format!(" IDENTIFIED VIA {AUTH_PLUGIN} USING '*")) {
                return Err(syntax());
            }
        } else if let Some(rest) = s.strip_prefix("KILL USER ") {
            parse_account(rest).ok_or_else(syntax)?;
        } else if let Some(rest) = s.strip_prefix("DROP USER IF EXISTS ") {
            let (account, _) = parse_account(rest).ok_or_else(syntax)?;
            self.drop_account(&account);
        } else if let Some(rest) = s.strip_prefix("GRANT ") {
            self.grant(rest).ok_or_else(syntax)??;
        } else if let Some(rest) = s.strip_prefix("REVOKE ") {
            self.revoke(rest).ok_or_else(syntax)??;
        } else {
            return Err(syntax());
        }
        Ok(())
    }

    fn drop_account(&mut self, account: &(String, String)) {
        let who = grantee(account);
        self.accounts.remove(account);
        self.db_privs.retain(|(g, _), _| *g != who);
        self.global.remove(&who);
        self.table_grants.remove(&who);
    }

    /// `<privileges> ON <object> TO <account>[ WITH GRANT OPTION]`.
    /// `None` = not understood; `Some(Err)` = refused by the server.
    fn grant(&mut self, rest: &str) -> Option<Result<(), String>> {
        let (privileges, rest) = rest.split_once(" ON ")?;
        let (object, rest) = rest.split_once(" TO ")?;
        let (account, tail) = parse_account(rest)?;
        let mut privileges: BTreeSet<String> = privileges.split(", ").map(str::to_owned).collect();
        match tail {
            "" => {}
            " WITH GRANT OPTION" => {
                privileges.insert(GRANT_OPTION.to_owned());
            }
            _ => return None,
        }
        if !self.accounts.contains_key(&account) {
            // NO_AUTO_CREATE_USER: a grant never creates an account.
            return Some(Err(
                "1133 (28000): Can't find any matching row in the user table".to_owned(),
            ));
        }
        let who = grantee(&account);
        if object == "*.*" {
            self.global.entry(who).or_default().extend(privileges);
        } else if let Some(pattern) = object.strip_suffix(".*").and_then(parse_ident) {
            self.db_privs
                .entry((who, pattern.0.to_owned()))
                .or_default()
                .extend(privileges);
        } else {
            // `db`.`table`
            parse_ident(object)?;
            self.table_grants.insert(who);
        }
        Some(Ok(()))
    }

    /// `ALL PRIVILEGES|GRANT OPTION ON <pattern>.* FROM <account>`.
    fn revoke(&mut self, rest: &str) -> Option<Result<(), String>> {
        let (what, rest) = rest.split_once(" ON ")?;
        let (object, rest) = rest.split_once(" FROM ")?;
        let (account, tail) = parse_account(rest)?;
        let (pattern, _) = parse_ident(object.strip_suffix(".*")?)?;
        if !tail.is_empty() {
            return None;
        }
        let key = (grantee(&account), pattern.to_owned());
        let Some(held) = self.db_privs.get_mut(&key) else {
            return Some(Err(format!(
                "1141 (42000): There is no such grant defined for user '{}' on host '{}'",
                account.0, account.1
            )));
        };
        match what {
            "ALL PRIVILEGES" => held.retain(|p| p == GRANT_OPTION),
            "GRANT OPTION" => {
                held.remove(GRANT_OPTION);
            }
            _ => return None,
        }
        if held.is_empty() {
            self.db_privs.remove(&key);
        }
        Some(Ok(()))
    }

    /// The answer to [`SNAPSHOT_SQL`], escaped as `--batch` output is.
    fn snapshot(&self) -> String {
        let yes_no = |grantable: bool| if grantable { "YES" } else { "NO" };
        let mut out = format!("version\t{VERSION}\n");
        for schema in &self.schemata {
            let _ = writeln!(out, "schema\t{schema}");
        }
        for ((user, host), account) in &self.accounts {
            let _ = writeln!(
                out,
                "account\t{user}\t{host}\t{}\t{}\t{AUTH_PLUGIN}",
                u8::from(account.locked),
                account.max_user_connections
            );
            let who = grantee(&(user.clone(), host.clone()));
            let held = self.global.get(&who).cloned().unwrap_or_default();
            let grantable = held.contains(GRANT_OPTION);
            let mut named = held.iter().filter(|p| *p != GRANT_OPTION).peekable();
            if named.peek().is_none() {
                let _ = writeln!(out, "global\t{who}\tUSAGE\t{}", yes_no(grantable));
            }
            for privilege in named {
                let _ = writeln!(out, "global\t{who}\t{privilege}\t{}", yes_no(grantable));
            }
        }
        for ((who, pattern), held) in &self.db_privs {
            let grantable = held.contains(GRANT_OPTION);
            for privilege in held.iter().filter(|p| *p != GRANT_OPTION) {
                let _ = writeln!(
                    out,
                    "dbpriv\t{who}\t{}\t{privilege}\t{}",
                    pattern.replace('\\', "\\\\"),
                    yes_no(grantable)
                );
            }
        }
        for who in &self.table_grants {
            let _ = writeln!(out, "other\t{who}\ttable");
        }
        out
    }

    /// The answer to the size query for the names listed in `rest`.
    fn sizes(&self, rest: &str) -> String {
        let list = rest.split_once(')').map_or("", |(list, _)| list);
        let mut out = String::new();
        for name in list.split(", ").map(|n| n.trim_matches('\'')) {
            if self.schemata.contains(name) {
                let _ = writeln!(out, "{name}\t{SIZE}");
            }
        }
        out
    }
}

fn syntax_error(line: usize, text: &str) -> String {
    format!(
        "ERROR 1064 (42000) at line {}: You have an error in your SQL syntax near '{text}'",
        line + 1
    )
}
