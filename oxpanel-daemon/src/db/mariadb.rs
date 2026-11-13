//! The daemon's conversation with the local MariaDB server.
//!
//! There is no SQL driver in the daemon and no network: it runs the
//! distribution's `mariadb` client as root against the server's UNIX socket
//! (`root@localhost` authenticates through `unix_socket`, i.e. by being
//! root — no administrative password exists to be stored or leaked) and
//! writes the statements to the client's **standard input**.
//!
//! SQL built from strings is the same class of risk as a shell, so the same
//! rules apply:
//!
//! - Only three kinds of value ever become part of a statement, and each is
//!   a type that can only be built by validation: [`DbName`] (database and
//!   user names: `a-z 0-9 _ -`, nothing that could end an identifier or a
//!   string), [`PasswordHash`] (`*` and 40 hex digits) and a `u32`.
//!   Everything else is a constant in this file.
//! - Identifiers are back-quoted and account names single-quoted anyway.
//! - In a `GRANT … ON db.*` the database is a *pattern*: `_` and `%` are
//!   wildcards. They are escaped, so a grant on `acme_shop` cannot also match
//!   `acmeXshop`.
//! - Nothing is ever passed with `-e`: the argument vector is constant.
//!
//! Passwords: the request's password is turned into the hash MariaDB itself
//! would store for `mysql_native_password` and only that hash is sent
//! (`IDENTIFIED VIA mysql_native_password USING '<hash>'`). The plaintext
//! therefore never reaches an argument vector, the server's process list,
//! its general or slow log, its binary log, or the journal. The client's
//! error output is withheld from the journal for such statements, because
//! the client echoes the failing statement.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use sha1::{Digest, Sha1};

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::nginx::safe_path_str;
use crate::system::{bin, CommandSpec};
use crate::validate::{DbName, DbPassword};

/// Every database user is this account and no other: it can connect through
/// the UNIX socket (or loopback) only, never from another machine.
pub const ACCOUNT_HOST: &str = "localhost";
/// The only authentication plugin OxPanel configures.
pub const AUTH_PLUGIN: &str = "mysql_native_password";
/// Oldest server the statements below work on (`ACCOUNT LOCK`, `global_priv`).
const MIN_VERSION: (u32, u32) = (10, 4);

/// What a tenant's user may do **inside a database it was granted**, and
/// nowhere else. This is what an application and its migrations need:
/// data, schema, views, routines and triggers.
///
/// Deliberately absent: `GRANT OPTION` (a tenant must not hand out access),
/// `EVENT` (scheduled work would run outside any connection limit) and
/// `DELETE HISTORY`. Global privileges (`FILE`, `PROCESS`, `SUPER`, `RELOAD`,
/// `SHUTDOWN`, `CREATE USER`, `SHOW DATABASES`, replication, …) are never
/// granted: the account is created with `USAGE` only.
pub const DB_PRIVILEGES: &[&str] = &[
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "CREATE",
    "DROP",
    "REFERENCES",
    "INDEX",
    "ALTER",
    "CREATE TEMPORARY TABLES",
    "LOCK TABLES",
    "EXECUTE",
    "CREATE VIEW",
    "SHOW VIEW",
    "CREATE ROUTINE",
    "ALTER ROUTINE",
    "TRIGGER",
];
/// How a grantable privilege set shows up in [`ServerState`].
pub const GRANT_OPTION: &str = "GRANT OPTION";

/// The server state the daemon bases every decision on, read in one go.
/// Each row carries a tag so the result sets can be told apart.
pub const SNAPSHOT_SQL: &str = "\
SELECT 'version', VERSION();
SELECT 'schema', SCHEMA_NAME FROM information_schema.SCHEMATA;
SELECT 'account', User, Host, IFNULL(JSON_VALUE(Priv, '$.account_locked'), 0), IFNULL(JSON_VALUE(Priv, '$.max_user_connections'), 0), IFNULL(JSON_VALUE(Priv, '$.plugin'), '') FROM mysql.global_priv;
SELECT 'global', GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.USER_PRIVILEGES;
SELECT 'dbpriv', GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.SCHEMA_PRIVILEGES;
SELECT DISTINCT 'other', GRANTEE, 'table' FROM information_schema.TABLE_PRIVILEGES;
SELECT DISTINCT 'other', GRANTEE, 'column' FROM information_schema.COLUMN_PRIVILEGES;
SELECT DISTINCT 'other', CONCAT('''', User, '''@''', Host, ''''), 'routine' FROM mysql.procs_priv;
SELECT DISTINCT 'other', CONCAT('''', User, '''@''', Host, ''''), 'proxy' FROM mysql.proxies_priv;
SELECT DISTINCT 'other', CONCAT('''', User, '''@''', Host, ''''), 'role' FROM mysql.roles_mapping;
";

/// Start of the statement that measures databases; the names follow.
pub const SIZES_SQL_PREFIX: &str = "SELECT TABLE_SCHEMA, IFNULL(SUM(DATA_LENGTH + INDEX_LENGTH), 0) FROM information_schema.TABLES WHERE TABLE_SCHEMA IN (";

/// What MariaDB stores for a `mysql_native_password` account:
/// `*` followed by the upper-case hex of `SHA1(SHA1(password))`.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordHash(String);

impl PasswordHash {
    pub fn of(password: &DbPassword) -> Self {
        let once = Sha1::digest(password.expose().as_bytes());
        let twice = Sha1::digest(once);
        let mut s = String::with_capacity(41);
        s.push('*');
        for byte in twice {
            let _ = write!(s, "{byte:02X}");
        }
        Self(s)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// The hash lets nobody log in by itself, but it can be attacked offline.
impl std::fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordHash(<redacted>)")
    }
}

/// `` `name` `` — a [`DbName`] cannot contain a back-quote; doubling one is
/// what the grammar asks for and costs nothing.
fn ident(name: &DbName) -> String {
    format!("`{}`", name.as_str().replace('`', "``"))
}

/// `'name'@'localhost'`
pub fn account(name: &DbName) -> String {
    format!(
        "'{}'@'{ACCOUNT_HOST}'",
        name.as_str().replace('\\', "\\\\").replace('\'', "''")
    )
}

/// The database of a `GRANT … ON <pattern>.*` as the server stores it:
/// the name with the `LIKE` wildcards `_` and `%` escaped.
pub fn grant_pattern(database: &DbName) -> String {
    let mut s = String::with_capacity(database.as_str().len() + 4);
    for c in database.as_str().chars() {
        if matches!(c, '_' | '%' | '\\') {
            s.push('\\');
        }
        s.push(c);
    }
    s
}

/// Whether a stored grant pattern covers `name` (`_` one character, `%` any
/// run of characters, `\` takes the next character literally).
pub fn pattern_matches(pattern: &str, name: &str) -> bool {
    fn go(p: &[char], n: &[char]) -> bool {
        match p.split_first() {
            None => n.is_empty(),
            Some(('%', rest)) => (0..=n.len()).any(|i| go(rest, n.get(i..).unwrap_or_default())),
            Some(('_', rest)) => n.split_first().is_some_and(|(_, n)| go(rest, n)),
            Some(('\\', rest)) => match (rest.split_first(), n.split_first()) {
                (Some((c, rest)), Some((d, n))) => c == d && go(rest, n),
                _ => false,
            },
            Some((c, rest)) => n.split_first().is_some_and(|(d, n)| c == d && go(rest, n)),
        }
    }
    let (p, n): (Vec<char>, Vec<char>) = (pattern.chars().collect(), name.chars().collect());
    go(&p, &n)
}

/// The statements the daemon can issue. One line each.
pub mod sql {
    use super::{account, grant_pattern, ident, PasswordHash, AUTH_PLUGIN, DB_PRIVILEGES};
    use crate::validate::DbName;

    pub fn create_database(name: &DbName) -> String {
        format!(
            "CREATE DATABASE IF NOT EXISTS {} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n",
            ident(name)
        )
    }

    pub fn drop_database(name: &DbName) -> String {
        format!("DROP DATABASE IF EXISTS {};\n", ident(name))
    }

    /// `OR REPLACE`: the caller has established that the name is OxPanel's.
    pub fn create_user(
        name: &DbName,
        hash: &PasswordHash,
        max_user_connections: u32,
        locked: bool,
    ) -> String {
        format!(
            "CREATE OR REPLACE USER {} IDENTIFIED VIA {AUTH_PLUGIN} USING '{}' WITH MAX_USER_CONNECTIONS {max_user_connections} ACCOUNT {};\n",
            account(name),
            hash.as_str(),
            if locked { "LOCK" } else { "UNLOCK" }
        )
    }

    pub fn set_password(name: &DbName, hash: &PasswordHash) -> String {
        format!(
            "ALTER USER {} IDENTIFIED VIA {AUTH_PLUGIN} USING '{}';\n",
            account(name),
            hash.as_str()
        )
    }

    pub fn set_locked(name: &DbName, locked: bool) -> String {
        format!(
            "ALTER USER {} ACCOUNT {};\n",
            account(name),
            if locked { "LOCK" } else { "UNLOCK" }
        )
    }

    /// End the account's open sessions; locking does not.
    pub fn kill_sessions(name: &DbName) -> String {
        format!("KILL USER {};\n", account(name))
    }

    pub fn drop_user(name: &DbName) -> String {
        format!("DROP USER IF EXISTS {};\n", account(name))
    }

    pub fn grant(user: &DbName, database: &DbName) -> String {
        format!(
            "GRANT {} ON `{}`.* TO {};\n",
            DB_PRIVILEGES.join(", "),
            grant_pattern(database),
            account(user)
        )
    }

    pub fn revoke(user: &DbName, database: &DbName) -> String {
        format!(
            "REVOKE ALL PRIVILEGES ON `{}`.* FROM {};\n",
            grant_pattern(database),
            account(user)
        )
    }

    pub fn revoke_grant_option(user: &DbName, database: &DbName) -> String {
        format!(
            "REVOKE GRANT OPTION ON `{}`.* FROM {};\n",
            grant_pattern(database),
            account(user)
        )
    }
}

/// One row of `mysql.global_priv`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub user: String,
    pub host: String,
    pub locked: bool,
    pub max_user_connections: u32,
    pub plugin: String,
}

/// Privileges by grantee (`'user'@'host'`).
pub type Privileges = BTreeMap<String, BTreeSet<String>>;

/// What the server holds, as far as OxPanel cares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerState {
    pub version: String,
    pub schemata: BTreeSet<String>,
    pub accounts: Vec<Account>,
    /// Global privileges other than `USAGE`; [`GRANT_OPTION`] if grantable.
    pub global: Privileges,
    /// Grantee → stored database pattern → privileges ([`GRANT_OPTION`] if grantable).
    pub db_privs: BTreeMap<String, Privileges>,
    /// Grantee → kinds of narrower or indirect grants it holds
    /// (`table`, `column`, `routine`, `proxy`, `role`).
    pub other: Privileges,
}

impl ServerState {
    /// The `'name'@'localhost'` account, if it exists.
    pub fn account(&self, name: &DbName) -> Option<&Account> {
        self.accounts
            .iter()
            .find(|a| a.user == name.as_str() && a.host == ACCOUNT_HOST)
    }

    /// Whether any account, on any host, has this user name.
    pub fn has_user_named(&self, name: &str) -> bool {
        self.accounts.iter().any(|a| a.user == name)
    }

    /// Privileges `user` holds on exactly the pattern of `database`.
    pub fn grant_on(&self, user: &DbName, database: &DbName) -> Option<&BTreeSet<String>> {
        self.db_privs
            .get(&account(user))?
            .get(&grant_pattern(database))
    }

    fn parse(text: &str) -> Result<Self> {
        let mut s = Self::default();
        for line in text.lines() {
            let cols: Vec<String> = line.split('\t').map(unescape).collect();
            let col = |i: usize| cols.get(i).map_or("", String::as_str);
            let grantable = |i: usize| col(i) == "YES";
            match col(0) {
                "version" => col(1).clone_into(&mut s.version),
                "schema" => {
                    s.schemata.insert(col(1).to_owned());
                }
                "account" => s.accounts.push(Account {
                    user: col(1).to_owned(),
                    host: col(2).to_owned(),
                    locked: !matches!(col(3), "0" | "" | "false"),
                    max_user_connections: col(4).parse().unwrap_or(0),
                    plugin: col(5).to_owned(),
                }),
                "global" => {
                    let set = s.global.entry(col(1).to_owned()).or_default();
                    if col(2) != "USAGE" {
                        set.insert(col(2).to_owned());
                    }
                    if grantable(3) {
                        set.insert(GRANT_OPTION.to_owned());
                    }
                }
                "dbpriv" => {
                    let set = s
                        .db_privs
                        .entry(col(1).to_owned())
                        .or_default()
                        .entry(col(2).to_owned())
                        .or_default();
                    set.insert(col(3).to_owned());
                    if grantable(4) {
                        set.insert(GRANT_OPTION.to_owned());
                    }
                }
                "other" => {
                    s.other
                        .entry(col(1).to_owned())
                        .or_default()
                        .insert(col(2).to_owned());
                }
                other => {
                    return Err(Error::Internal(format!(
                        "unexpected row '{other}' in the MariaDB state"
                    )))
                }
            }
        }
        s.global.retain(|_, privileges| !privileges.is_empty());
        Ok(s)
    }
}

/// Undo the escaping of the client's `--batch` output.
pub(crate) fn unescape(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('0') => out.push('\0'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// The client invocation. Constant apart from the configured socket path:
/// no option files (`--no-defaults` must come first), socket only, root.
fn client(ctx: &Ctx) -> Result<CommandSpec> {
    let socket = safe_path_str(&ctx.config.mariadb_socket)?;
    Ok(CommandSpec::new(bin::MARIADB, ctx.config.command_timeout)
        .args(["--no-defaults", "--protocol=socket"])
        .arg(format!("--socket={socket}"))
        .args([
            "--user=root",
            "--batch",
            "--skip-column-names",
            "--default-character-set=utf8mb4",
            "--connect-timeout=10",
        ]))
}

/// The server's own error lines (`ERROR 1396 (HY000) at line 1: …`), without
/// the statement the client echoes. For a statement that carried a password
/// hash only the error number is kept: the message may quote the statement.
fn server_errors(stderr: &str, secret: bool) -> String {
    stderr
        .lines()
        .filter(|l| l.starts_with("ERROR "))
        .map(|l| {
            if secret {
                l.split_once(':').map_or(l, |(code, _)| code)
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

async fn run(ctx: &Ctx, script: String, secret: bool) -> Result<String> {
    if !ctx.sys.is_installed(bin::MARIADB).await {
        return Err(Error::DbUnavailable(
            "MariaDB is not installed (dnf install mariadb-server)".into(),
        ));
    }
    let spec = client(ctx)?;
    let spec = if secret {
        spec.secret_stdin(script.into_bytes())
    } else {
        spec.stdin(script.into_bytes())
    };
    let out = ctx.sys.run(spec).await?;
    if out.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    let stderr = out.stderr_lossy();
    // 2002: no server behind the socket. 1045/1698: root is not let in.
    if stderr.contains("ERROR 2002") {
        return Err(Error::DbUnavailable(format!(
            "MariaDB is not running or does not listen on {} (systemctl enable --now mariadb)",
            ctx.config.mariadb_socket.display()
        )));
    }
    if stderr.contains("ERROR 1045") || stderr.contains("ERROR 1698") {
        return Err(Error::DbUnavailable(
            "root may not connect through the UNIX socket (root@localhost must authenticate with unix_socket)".into(),
        ));
    }
    Err(Error::CommandFailed {
        program: bin::MARIADB.to_owned(),
        status: out
            .code
            .map_or_else(|| "signal".to_owned(), |c| format!("status {c}")),
        stderr: server_errors(&stderr, secret),
    })
}

/// Execute statements that carry no secret.
pub async fn execute(ctx: &Ctx, script: String) -> Result<()> {
    run(ctx, script, false).await.map(|_| ())
}

/// Execute statements that carry a password hash: the client's error output
/// is kept out of the journal and reduced to error numbers.
pub async fn execute_secret(ctx: &Ctx, script: String) -> Result<()> {
    run(ctx, script, true).await.map(|_| ())
}

/// The tables and stored objects of `schema` (read-only).
pub async fn objects(ctx: &Ctx, schema: &Schema) -> Result<SchemaObjects> {
    parse_objects(&run(ctx, objects_sql(schema), false).await?)
}

/// Read the server state. Fails with [`Error::DbUnavailable`] — before the
/// caller has changed anything — when MariaDB cannot be used.
pub async fn snapshot(ctx: &Ctx) -> Result<ServerState> {
    let state = ServerState::parse(&run(ctx, SNAPSHOT_SQL.to_owned(), false).await?)?;
    let numbers: Vec<u32> = state
        .version
        .split(['.', '-'])
        .take(2)
        .filter_map(|n| n.parse().ok())
        .collect();
    let supported = state.version.contains("MariaDB")
        && matches!(numbers.as_slice(), [major, minor] if (*major, *minor) >= MIN_VERSION);
    if !supported {
        return Err(Error::DbUnavailable(format!(
            "the server reports version '{}'; MariaDB {}.{} or newer is required",
            state.version, MIN_VERSION.0, MIN_VERSION.1
        )));
    }
    Ok(state)
}

/// The hardened client for scripts that carry names or text a tenant chose
/// (table and object names, object definitions): `--binary-mode` turns off
/// the client's backslash commands (`\g`, `\!`, `\.` …) and `--sandbox`
/// every command that touches the file system. See `db::objects` for why.
fn hardened_client(ctx: &Ctx) -> Result<CommandSpec> {
    Ok(client(ctx)?.args(["--binary-mode", "--sandbox"]))
}

/// Run a script through the hardened client; returns standard output.
pub async fn run_hardened(ctx: &Ctx, script: String) -> Result<String> {
    if !ctx.sys.is_installed(bin::MARIADB).await {
        return Err(Error::DbUnavailable(
            "MariaDB is not installed (dnf install mariadb-server)".into(),
        ));
    }
    let out = ctx
        .sys
        .run(hardened_client(ctx)?.stdin(script.into_bytes()))
        .await?;
    if out.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    let stderr = out.stderr_lossy();
    if stderr.contains("ERROR 2002") {
        return Err(Error::DbUnavailable(format!(
            "MariaDB is not running or does not listen on {}",
            ctx.config.mariadb_socket.display()
        )));
    }
    Err(Error::CommandFailed {
        program: bin::MARIADB.to_owned(),
        status: out
            .code
            .map_or_else(|| "signal".to_owned(), |c| format!("status {c}")),
        stderr: server_errors(&stderr, false),
    })
}

/// A schema the daemon may name in a statement: a tenant database or a
/// trash schema. Both consist of `a-z 0-9 _ -` only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schema(String);

impl Schema {
    pub fn of_db(name: &DbName) -> Self {
        Self(name.as_str().to_owned())
    }

    pub fn of_trash(id: &crate::validate::TrashId) -> Self {
        Self(id.schema())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `` `name` `` for a name a tenant chose (a table, a trigger …): back-quoted
/// with back-quotes doubled, which is all the grammar asks inside an
/// identifier. Only ever sent through the hardened client.
pub fn quote(name: &str) -> String {
    format!("`{}`", name.replace('`', "``"))
}

/// `CONVERT(X'…' USING utf8mb4)`: text a tenant wrote, as a hex literal the
/// client never tokenises.
pub fn hex_text(text: &str) -> String {
    let mut s = String::with_capacity(text.len() * 2 + 26);
    s.push_str("CONVERT(X'");
    for b in text.bytes() {
        let _ = write!(s, "{b:02X}");
    }
    s.push_str("' USING utf8mb4)");
    s
}

/// Start of the query that lists a schema's tables and stored objects.
pub const OBJECTS_SQL_PREFIX: &str = "SELECT 'table', HEX(TABLE_NAME), HEX(TABLE_TYPE) FROM information_schema.TABLES WHERE TABLE_SCHEMA = '";

/// Tables (anything but views) and views, triggers, routines and events of
/// `schema`, with names and definers in hexadecimal so that no name can
/// disturb the output.
pub fn objects_sql(schema: &Schema) -> String {
    let s = schema.as_str();
    format!(
        "{OBJECTS_SQL_PREFIX}{s}' AND TABLE_TYPE <> 'VIEW' ORDER BY TABLE_NAME;
SELECT 'view', HEX(TABLE_NAME), HEX(DEFINER) FROM information_schema.VIEWS WHERE TABLE_SCHEMA = '{s}' ORDER BY TABLE_NAME;
SELECT 'trigger', HEX(TRIGGER_NAME), HEX(DEFINER) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = '{s}' ORDER BY TRIGGER_NAME;
SELECT LOWER(ROUTINE_TYPE), HEX(ROUTINE_NAME), HEX(DEFINER) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = '{s}' ORDER BY ROUTINE_TYPE, ROUTINE_NAME;
SELECT 'event', HEX(EVENT_NAME), HEX(DEFINER) FROM information_schema.EVENTS WHERE EVENT_SCHEMA = '{s}' ORDER BY EVENT_NAME;
"
    )
}

/// One object of a schema as listed by [`objects_sql`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub kind: crate::records::DbObjectKind,
    pub name: String,
    /// `user@host`.
    pub definer: String,
}

/// What a schema holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SchemaObjects {
    /// Base tables (and sequences, system-versioned tables …), by name.
    pub tables: Vec<String>,
    /// Views, triggers, routines and events.
    pub objects: Vec<Listed>,
}

impl SchemaObjects {
    pub fn of_kind(&self, kind: crate::records::DbObjectKind) -> impl Iterator<Item = &Listed> {
        self.objects.iter().filter(move |o| o.kind == kind)
    }
}

fn unhex(field: &str) -> Result<String> {
    let bytes = field.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::Internal(format!("not hexadecimal: '{field}'")));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let text = std::str::from_utf8(pair).unwrap_or("zz");
        out.push(
            u8::from_str_radix(text, 16)
                .map_err(|_| Error::Internal(format!("not hexadecimal: '{field}'")))?,
        );
    }
    let text = String::from_utf8(out)
        .map_err(|_| Error::Internal("a name on the server is not UTF-8".into()))?;
    if text.contains('\0') {
        return Err(Error::Internal("a name on the server contains NUL".into()));
    }
    Ok(text)
}

/// Parse the output of [`objects_sql`]. A kind of object OxPanel cannot keep
/// (Oracle-mode packages) is an error: nothing may be lost silently.
pub fn parse_objects(text: &str) -> Result<SchemaObjects> {
    use crate::records::DbObjectKind as K;
    let mut out = SchemaObjects::default();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let cols: Vec<&str> = line.split('\t').collect();
        let (Some(tag), Some(name), Some(third)) = (cols.first(), cols.get(1), cols.get(2)) else {
            return Err(Error::Internal(format!("unexpected object row '{line}'")));
        };
        let name = unhex(name)?;
        let kind = match *tag {
            "table" => {
                out.tables.push(name);
                continue;
            }
            "view" => K::View,
            "trigger" => K::Trigger,
            "procedure" => K::Procedure,
            "function" => K::Function,
            "event" => K::Event,
            other => {
                return Err(Error::Internal(format!(
                "the database holds a {other} ('{name}'), which OxPanel cannot keep; drop it first"
            )))
            }
        };
        out.objects.push(Listed {
            kind,
            name,
            definer: unhex(third)?,
        });
    }
    Ok(out)
}

/// The statements that move, restore and re-create a database's content.
/// Every one of them names tenant-chosen things and is only ever sent
/// through [`run_hardened`].
pub mod content {
    use super::{hex_text, quote, Schema};
    use crate::records::DbObjectKind;
    use std::fmt::Write as _;

    /// `SHOW CREATE …` of each object, after `USE`: views come out without
    /// the database name, so they can be re-created under another one.
    pub fn show_create(schema: &Schema, objects: &[(DbObjectKind, String)]) -> String {
        let mut s = format!("USE `{}`;\n", schema.as_str());
        for (kind, name) in objects {
            let _ = writeln!(s, "SHOW CREATE {} {};", kind.keyword(), quote(name));
        }
        s
    }

    pub fn create_schema(schema: &Schema) -> String {
        format!(
            "CREATE DATABASE IF NOT EXISTS `{}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n",
            schema.as_str()
        )
    }

    pub fn drop_schema(schema: &Schema) -> String {
        format!("DROP DATABASE IF EXISTS `{}`;\n", schema.as_str())
    }

    pub fn drop_object(schema: &Schema, kind: DbObjectKind, name: &str) -> String {
        format!(
            "DROP {} IF EXISTS `{}`.{};\n",
            kind.keyword(),
            schema.as_str(),
            quote(name)
        )
    }

    /// All tables from one schema to another in **one** statement (atomic).
    /// Empty when there are none.
    pub fn rename_tables(from: &Schema, to: &Schema, tables: &[String]) -> String {
        if tables.is_empty() {
            return String::new();
        }
        let pairs: Vec<String> = tables
            .iter()
            .map(|t| {
                format!(
                    "`{}`.{} TO `{}`.{}",
                    from.as_str(),
                    quote(t),
                    to.as_str(),
                    quote(t)
                )
            })
            .collect();
        format!("RENAME TABLE {};\n", pairs.join(", "))
    }

    /// A view is re-created from a hex literal through a prepared statement:
    /// its text never meets the client's parser.
    pub fn create_view(schema: &Schema, definition: &str) -> String {
        format!(
            "USE `{}`;\nEXECUTE IMMEDIATE {};\n",
            schema.as_str(),
            hex_text(definition)
        )
    }
}

/// Data plus index bytes of each of `names` that has tables.
pub async fn sizes(ctx: &Ctx, names: &[DbName]) -> Result<BTreeMap<String, u64>> {
    let schemas: Vec<Schema> = names.iter().map(Schema::of_db).collect();
    schema_sizes(ctx, &schemas).await
}

/// Data plus index bytes of each of `schemas` that has tables.
pub async fn schema_sizes(ctx: &Ctx, schemas: &[Schema]) -> Result<BTreeMap<String, u64>> {
    if schemas.is_empty() {
        return Ok(BTreeMap::new());
    }
    let list: Vec<String> = schemas
        .iter()
        .map(|n| format!("'{}'", n.as_str().replace('\'', "''")))
        .collect();
    let script = format!(
        "{SIZES_SQL_PREFIX}{}) GROUP BY TABLE_SCHEMA;\n",
        list.join(", ")
    );
    let out = run(ctx, script, false).await?;
    Ok(out
        .lines()
        .filter_map(|l| {
            let (name, bytes) = l.split_once('\t')?;
            // SUM() of BIGINTs is a DECIMAL: "16384" or "16384.0".
            let bytes = bytes.split('.').next()?.parse().ok()?;
            Some((unescape(name), bytes))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> DbName {
        DbName::parse(s, "name").unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn password_hash_is_what_mariadb_computes() -> Result<()> {
        // SELECT PASSWORD('Secret-pass-123') on MariaDB 10.5.
        let h = PasswordHash::of(&DbPassword::parse("Secret-pass-123")?);
        assert_eq!(h.as_str(), "*683682FA5B18D74444A8178F2DD3E999D9007573");
        assert_eq!(format!("{h:?}"), "PasswordHash(<redacted>)");
        // Whatever the password contains, the hash is `*` and 40 hex digits.
        let h = PasswordHash::of(&DbPassword::parse("x'; DROP DATABASE mysql; -- \\")?);
        assert_eq!(h.as_str().len(), 41);
        assert!(h
            .as_str()
            .bytes()
            .skip(1)
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)));
        Ok(())
    }

    #[test]
    fn statements_quote_identifiers_and_escape_grant_wildcards() -> Result<()> {
        let (db, user) = (name("acme_shop_wp"), name("acme_shop_app"));
        assert_eq!(
            sql::create_database(&db),
            "CREATE DATABASE IF NOT EXISTS `acme_shop_wp` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n"
        );
        assert_eq!(
            sql::drop_database(&db),
            "DROP DATABASE IF EXISTS `acme_shop_wp`;\n"
        );
        let hash = PasswordHash::of(&DbPassword::parse("Secret-pass-123")?);
        assert_eq!(
            sql::create_user(&user, &hash, 25, false),
            "CREATE OR REPLACE USER 'acme_shop_app'@'localhost' IDENTIFIED VIA mysql_native_password USING '*683682FA5B18D74444A8178F2DD3E999D9007573' WITH MAX_USER_CONNECTIONS 25 ACCOUNT UNLOCK;\n"
        );
        assert!(sql::create_user(&user, &hash, 5, true)
            .ends_with(" WITH MAX_USER_CONNECTIONS 5 ACCOUNT LOCK;\n"));
        assert_eq!(
            sql::set_password(&user, &hash),
            "ALTER USER 'acme_shop_app'@'localhost' IDENTIFIED VIA mysql_native_password USING '*683682FA5B18D74444A8178F2DD3E999D9007573';\n"
        );
        assert_eq!(
            sql::set_locked(&user, true),
            "ALTER USER 'acme_shop_app'@'localhost' ACCOUNT LOCK;\n"
        );
        assert_eq!(
            sql::kill_sessions(&user),
            "KILL USER 'acme_shop_app'@'localhost';\n"
        );
        assert_eq!(
            sql::drop_user(&user),
            "DROP USER IF EXISTS 'acme_shop_app'@'localhost';\n"
        );
        // `_` is a wildcard in a database-level grant: it must be escaped,
        // or the grant would also cover `acmeXshopXwp`.
        assert_eq!(
            sql::grant(&user, &db),
            "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, REFERENCES, INDEX, ALTER, CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE, TRIGGER ON `acme\\_shop\\_wp`.* TO 'acme_shop_app'@'localhost';\n"
        );
        assert_eq!(
            sql::revoke(&user, &db),
            "REVOKE ALL PRIVILEGES ON `acme\\_shop\\_wp`.* FROM 'acme_shop_app'@'localhost';\n"
        );
        assert_eq!(
            sql::revoke_grant_option(&user, &name("foo-bar_x")),
            "REVOKE GRANT OPTION ON `foo-bar\\_x`.* FROM 'acme_shop_app'@'localhost';\n"
        );
        Ok(())
    }

    #[test]
    fn no_privilege_that_reaches_beyond_the_database() {
        for forbidden in [
            "GRANT OPTION",
            "ALL",
            "ALL PRIVILEGES",
            "FILE",
            "SUPER",
            "PROCESS",
            "RELOAD",
            "SHUTDOWN",
            "CREATE USER",
            "SHOW DATABASES",
            "EVENT",
            "REPLICATION SLAVE",
            "REPLICATION CLIENT",
        ] {
            assert!(!DB_PRIVILEGES.contains(&forbidden), "{forbidden}");
        }
        assert!(!sql::grant(&name("alice_app"), &name("alice_wp")).contains("*.*"));
    }

    #[test]
    fn grant_patterns_match_only_their_own_database() {
        let p = grant_pattern(&name("acme_shop_wp"));
        assert_eq!(p, "acme\\_shop\\_wp");
        assert!(pattern_matches(&p, "acme_shop_wp"));
        assert!(!pattern_matches(&p, "acmeXshop_wp"));
        assert!(!pattern_matches(&p, "acme_shop_wp2"));
        // What an unescaped pattern, or one written by hand, would cover.
        assert!(pattern_matches("acme_shop_wp", "acmeXshop_wp"));
        assert!(pattern_matches("acme\\_%", "acme_anything"));
        assert!(pattern_matches("%", "alice_wp"));
        assert!(!pattern_matches("acme\\_%", "acmeXwp"));
        assert!(!pattern_matches("alice\\", "alice"));
    }

    #[test]
    fn state_is_parsed_from_the_clients_batch_output() -> Result<()> {
        let text = "version\t10.5.29-MariaDB\n\
schema\tmysql\n\
schema\talice_wp\n\
account\troot\tlocalhost\t0\t0\tmysql_native_password\n\
account\tmariadb.sys\tlocalhost\t1\t0\tmysql_native_password\n\
account\talice_app\tlocalhost\t0\t25\tmysql_native_password\n\
global\t'root'@'localhost'\tSUPER\tYES\n\
global\t'alice_app'@'localhost'\tUSAGE\tNO\n\
dbpriv\t'alice_app'@'localhost'\talice\\\\_wp\tSELECT\tNO\n\
dbpriv\t'alice_app'@'localhost'\talice\\\\_wp\tINSERT\tYES\n\
other\t'alice_app'@'localhost'\ttable\n";
        let s = ServerState::parse(text)?;
        assert_eq!(s.version, "10.5.29-MariaDB");
        assert!(s.schemata.contains("alice_wp"));
        let app = name("alice_app");
        assert_eq!(
            s.account(&app).map(|a| (a.locked, a.max_user_connections)),
            Some((false, 25))
        );
        assert!(s
            .accounts
            .iter()
            .any(|a| a.user == "mariadb.sys" && a.locked));
        assert!(
            !s.global.contains_key("'alice_app'@'localhost'"),
            "USAGE is no privilege"
        );
        assert!(s
            .global
            .get("'root'@'localhost'")
            .is_some_and(|p| p.contains("SUPER") && p.contains(GRANT_OPTION)));
        let grant = s.grant_on(&app, &name("alice_wp"));
        assert_eq!(
            grant.map(|g| g.iter().map(String::as_str).collect::<Vec<_>>()),
            Some(vec![GRANT_OPTION, "INSERT", "SELECT"])
        );
        assert!(s
            .other
            .get("'alice_app'@'localhost'")
            .is_some_and(|k| k.contains("table")));
        assert!(ServerState::parse("surprise\tx\n").is_err());
        Ok(())
    }

    #[test]
    fn only_server_error_lines_survive_and_secrets_lose_their_text() {
        let stderr = "--------------\nCREATE OR REPLACE USER 'a_b'@'localhost' IDENTIFIED VIA mysql_native_password USING '*ABC'\n--------------\n\nERROR 1064 (42000) at line 1: You have an error near 'USING '*ABC''";
        assert_eq!(
            server_errors(stderr, false),
            "ERROR 1064 (42000) at line 1: You have an error near 'USING '*ABC''"
        );
        assert_eq!(server_errors(stderr, true), "ERROR 1064 (42000) at line 1");
        assert!(!server_errors(stderr, true).contains("ABC"));
    }
}
