//! A MariaDB server small enough to live inside [`super::FakeSystem`].
//!
//! It understands exactly the statements [`crate::db::mariadb`] issues (plus a
//! few an administrator would type by hand, so tests can create drift) and
//! answers the state queries from what those statements built up. Anything
//! else is a syntax error — a statement the daemon was not meant to send
//! fails a test instead of passing silently.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::db::mariadb::{
    AUTH_PLUGIN, GRANT_OPTION, OBJECTS_SQL_PREFIX, SIZES_SQL_PREFIX, SNAPSHOT_SQL,
};

const VERSION: &str = "10.5.29-MariaDB";
/// What every database "weighs" (one empty `InnoDB` table).
const SIZE: u64 = 16_384;

#[derive(Debug, Clone, Default)]
struct FakeAccount {
    locked: bool,
    max_user_connections: u32,
}

/// A view, trigger, routine or event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FakeObject {
    pub(super) definer: String,
    pub(super) sql_mode: String,
    pub(super) time_zone: String,
    pub(super) definition: String,
}

/// What a schema holds: tables, and objects by `(KIND, name)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct FakeSchema {
    pub(super) tables: BTreeSet<String>,
    pub(super) objects: BTreeMap<(String, String), FakeObject>,
}

/// Per client process: the database in use and the session settings.
#[derive(Debug, Default)]
struct Session {
    db: Option<String>,
    sql_mode: String,
    time_zone: String,
}

#[derive(Debug)]
pub(super) struct FakeMariaDb {
    /// A stopped server refuses connections.
    pub(super) stopped: bool,
    schemata: BTreeSet<String>,
    /// The content of every schema that has any.
    pub(super) content: BTreeMap<String, FakeSchema>,
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
            content: BTreeMap::new(),
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

/// A back-quoted name with doubled back-quotes at the start of `s`.
fn parse_quoted(s: &str) -> Option<(String, &str)> {
    let mut rest = s.strip_prefix('`')?;
    let mut name = String::new();
    loop {
        let (part, after) = rest.split_once('`')?;
        name.push_str(part);
        if let Some(more) = after.strip_prefix('`') {
            name.push('`');
            rest = more;
        } else {
            return Some((name, after));
        }
    }
}

/// `` `schema`.`name` ``
fn parse_qualified(s: &str) -> Option<(String, String, &str)> {
    let (schema, rest) = parse_quoted(s)?;
    let (name, rest) = parse_quoted(rest.strip_prefix('.')?)?;
    Some((schema, name, rest))
}

/// `CONVERT(X'<hex>' USING utf8mb4)` → the text.
fn parse_hex_text(s: &str) -> Option<String> {
    let hex = s
        .strip_prefix("CONVERT(X'")?
        .strip_suffix("' USING utf8mb4)")?;
    let bytes: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect();
    String::from_utf8(bytes?).ok()
}

fn hex(text: &str) -> String {
    text.bytes().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02X}");
        s
    })
}

/// As the client's batch output escapes a field.
fn batch_escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
}

/// The kind keyword and name a `CREATE …` statement defines, and its definer.
fn parse_definition(text: &str) -> Option<(String, String, String)> {
    let definer = text
        .split_once("DEFINER=`")
        .and_then(|(_, r)| {
            let (user, r) = r.split_once("`@`")?;
            let (host, _) = r.split_once('`')?;
            Some(format!("{user}@{host}"))
        })
        .unwrap_or_else(|| "root@localhost".to_owned());
    for kind in ["TRIGGER", "PROCEDURE", "FUNCTION", "EVENT", "VIEW"] {
        if let Some((_, rest)) = text.split_once(&format!(" {kind} ")) {
            let rest = rest.trim_start();
            let name = match parse_quoted(rest) {
                Some((name, _)) => name,
                None => rest
                    .split(|c: char| c.is_whitespace() || c == '(')
                    .next()?
                    .to_owned(),
            };
            return Some((kind.to_owned(), name, definer));
        }
    }
    None
}

impl FakeMariaDb {
    /// Run a script as the `mariadb` client would: `(exit code, stdout, stderr)`.
    /// One call is one client process (one session): `USE`, the session's
    /// `sql_mode`/`time_zone`, `DELIMITER` blocks and `EXECUTE IMMEDIATE`
    /// of a hex literal are understood besides the statements themselves.
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
        if let Some(rest) = script.strip_prefix(OBJECTS_SQL_PREFIX) {
            let schema = rest.split_once('\'').map_or("", |(s, _)| s);
            return (0, self.objects(schema), String::new());
        }
        let mut session = Session::default();
        let mut stdout = String::new();
        let lines: Vec<&str> = script.lines().collect();
        let mut n = 0;
        while let Some(line) = lines.get(n) {
            let start = n;
            n += 1;
            let result = if let Some(delimiter) = line.strip_prefix("DELIMITER ") {
                // Everything up to a line that is the delimiter is one statement.
                let mut body = Vec::new();
                while let Some(l) = lines.get(n) {
                    n += 1;
                    if *l == delimiter {
                        break;
                    }
                    body.push(*l);
                }
                self.create_object(&session, &body.join("\n"))
            } else if let Some(statement) = line.strip_suffix(';') {
                self.session_statement(&mut session, statement, &mut stdout)
            } else {
                return (1, String::new(), syntax_error(start, line));
            };
            if let Err(error) = result {
                // The real client echoes the failing statement.
                let (code, message) = error.split_once(": ").unwrap_or((&error, ""));
                let stderr = format!(
                    "--------------\n{line}\n--------------\n\nERROR {code} at line {}: {message}",
                    start + 1
                );
                return (1, stdout, stderr);
            }
        }
        (0, stdout, String::new())
    }

    /// A statement that may depend on or change the session.
    fn session_statement(
        &mut self,
        session: &mut Session,
        statement: &str,
        stdout: &mut String,
    ) -> Result<(), String> {
        let syntax =
            || format!("1064 (42000): You have an error in your SQL syntax near '{statement}'");
        if let Some(rest) = statement.strip_prefix("USE ") {
            let (db, _) = parse_quoted(rest).ok_or_else(syntax)?;
            if !self.schemata.contains(&db) {
                return Err(format!("1049 (42000): Unknown database '{db}'"));
            }
            session.db = Some(db);
        } else if let Some(rest) = statement.strip_prefix("SET SESSION sql_mode = ") {
            session.sql_mode = parse_hex_text(rest).ok_or_else(syntax)?;
        } else if let Some(rest) = statement.strip_prefix("SET SESSION time_zone = ") {
            session.time_zone = parse_hex_text(rest).ok_or_else(syntax)?;
        } else if let Some(rest) = statement.strip_prefix("EXECUTE IMMEDIATE ") {
            let text = parse_hex_text(rest).ok_or_else(syntax)?;
            // Prepared statements may create views, not the other kinds.
            if !text.contains(" VIEW ") {
                return Err("1295 (HY000): This command is not supported in the prepared statement protocol yet".to_owned());
            }
            self.create_object(session, &text)?;
        } else if let Some(rest) = statement.strip_prefix("SHOW CREATE ") {
            stdout.push_str(&self.show_create(session, rest)?);
        } else {
            self.statement(statement)?;
        }
        Ok(())
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
            self.content.remove(name);
        } else if let Some(rest) = s.strip_prefix("CREATE TABLE ") {
            // By hand only: `db`.`table` (…).
            let (schema, table, _) = parse_qualified(rest).ok_or_else(syntax)?;
            if !self.schemata.contains(&schema) {
                return Err(format!("1049 (42000): Unknown database '{schema}'"));
            }
            self.content.entry(schema).or_default().tables.insert(table);
        } else if let Some(rest) = s.strip_prefix("RENAME TABLE ") {
            self.rename(rest).ok_or_else(syntax)??;
        } else if let Some((kind, rest)) = s
            .strip_prefix("DROP ")
            .and_then(|r| r.split_once(" IF EXISTS "))
            .filter(|(kind, _)| {
                ["TRIGGER", "VIEW", "PROCEDURE", "FUNCTION", "EVENT"].contains(kind)
            })
        {
            let (schema, name, _) = parse_qualified(rest).ok_or_else(syntax)?;
            if let Some(c) = self.content.get_mut(&schema) {
                c.objects.remove(&(kind.to_owned(), name));
            }
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

    /// `` `a`.`t` TO `b`.`t`, … `` — all or nothing, like the real thing.
    fn rename(&mut self, rest: &str) -> Option<Result<(), String>> {
        let mut moves = Vec::new();
        for pair in rest.split(", ") {
            let (from, to) = pair.split_once(" TO ")?;
            let (fs, ft, _) = parse_qualified(from)?;
            let (ts, tt, _) = parse_qualified(to)?;
            moves.push((fs, ft, ts, tt));
        }
        for (fs, ft, ts, _) in &moves {
            let present = self.content.get(fs).is_some_and(|c| c.tables.contains(ft));
            if !present {
                return Some(Err(format!(
                    "1146 (42S02): Table '{fs}.{ft}' doesn't exist"
                )));
            }
            let triggered = self
                .content
                .get(fs)
                .is_some_and(|c| c.objects.keys().any(|(k, _)| k == "TRIGGER"));
            if fs != ts && triggered {
                return Some(Err("1435 (HY000): Trigger in wrong schema".to_owned()));
            }
            if !self.schemata.contains(ts) {
                return Some(Err(format!("1049 (42000): Unknown database '{ts}'")));
            }
        }
        for (fs, ft, ts, tt) in moves {
            if let Some(c) = self.content.get_mut(&fs) {
                c.tables.remove(&ft);
            }
            self.content.entry(ts).or_default().tables.insert(tt);
        }
        Some(Ok(()))
    }

    /// Create an object from its definition in the session's database.
    fn create_object(&mut self, session: &Session, text: &str) -> Result<(), String> {
        let syntax = || format!("1064 (42000): You have an error in your SQL syntax near '{text}'");
        if text.contains("FAILS") || text.contains("?oxpanel-end") {
            return Err(syntax());
        }
        let (kind, name, definer) = parse_definition(text).ok_or_else(syntax)?;
        let Some(db) = session.db.clone() else {
            return Err("1046 (3D000): No database selected".to_owned());
        };
        let schema = self.content.entry(db).or_default();
        let key = (kind, name);
        if schema.objects.contains_key(&key) {
            return Err(format!("1304 (42000): {} {} already exists", key.0, key.1));
        }
        schema.objects.insert(
            key,
            FakeObject {
                definer,
                sql_mode: session.sql_mode.clone(),
                time_zone: session.time_zone.clone(),
                definition: text.to_owned(),
            },
        );
        Ok(())
    }

    /// `SHOW CREATE <KIND> `name``: one row as the real server prints it.
    fn show_create(&self, session: &Session, rest: &str) -> Result<String, String> {
        let (kind, quoted) = rest.split_once(' ').unwrap_or((rest, ""));
        let (name, _) = parse_quoted(quoted).unwrap_or_default();
        let object = session
            .db
            .as_ref()
            .and_then(|db| self.content.get(db))
            .and_then(|c| c.objects.get(&(kind.to_owned(), name.clone())))
            .ok_or_else(|| format!("1360 (HY000): {kind} does not exist"))?;
        let (n, m, d) = (
            batch_escape(&name),
            batch_escape(&object.sql_mode),
            batch_escape(&object.definition),
        );
        Ok(match kind {
            "VIEW" => format!("{n}\t{d}\tutf8mb4\tutf8mb4_general_ci\n"),
            "TRIGGER" => format!("{n}\t{m}\t{d}\tutf8mb4\tutf8mb4_general_ci\tutf8mb4_unicode_ci\t2026-11-14 10:00:00.00\n"),
            "EVENT" => format!(
                "{n}\t{m}\t{}\t{d}\tutf8mb4\tutf8mb4_general_ci\tutf8mb4_unicode_ci\n",
                batch_escape(&object.time_zone)
            ),
            _ => format!("{n}\t{m}\t{d}\tutf8mb4\tutf8mb4_general_ci\tutf8mb4_unicode_ci\n"),
        })
    }

    /// The answer to `objects_sql` for one schema.
    fn objects(&self, schema: &str) -> String {
        let mut out = String::new();
        let Some(c) = self.content.get(schema) else {
            return out;
        };
        for t in &c.tables {
            let _ = writeln!(out, "table\t{}\t{}", hex(t), hex("BASE TABLE"));
        }
        for (tag, kinds) in [
            ("view", &["VIEW"][..]),
            ("trigger", &["TRIGGER"][..]),
            ("", &["FUNCTION", "PROCEDURE"][..]),
            ("event", &["EVENT"][..]),
        ] {
            for kind in kinds {
                for ((k, name), o) in &c.objects {
                    if k == kind {
                        let tag = if tag.is_empty() {
                            kind.to_lowercase()
                        } else {
                            tag.to_owned()
                        };
                        let _ = writeln!(out, "{tag}\t{}\t{}", hex(name), hex(&o.definer));
                    }
                }
            }
        }
        out
    }

    /// What a schema holds (for assertions).
    pub(super) fn schema(&self, name: &str) -> Option<FakeSchema> {
        self.schemata
            .contains(name)
            .then(|| self.content.get(name).cloned().unwrap_or_default())
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
