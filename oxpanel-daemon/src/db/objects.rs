//! A database's views, triggers, routines and events: captured as text, and
//! re-created by **guarded replay**.
//!
//! These objects cannot travel with `RENAME TABLE` (MariaDB refuses to move
//! a table with triggers or a view to another schema; routines and events
//! belong to the schema), so moving a database to the trash and back, or
//! restoring one from a backup under a new name, means re-creating them from
//! their definitions — SQL text written by a tenant, executed by root.
//!
//! That is dangerous in a precise way, measured on MariaDB 10.5: the server
//! and the `mariadb` client do not split text into statements the same way
//! (the server takes `--` followed by a control character as a comment, the
//! client does not; a backslash command such as `\g` in the client's view of
//! the text sends what came before it). A tenant with ordinary privileges can
//! therefore write a procedure whose stored body, replayed through the
//! client under `DELIMITER ;;` — exactly what `mariadb-dump | mariadb` does —
//! makes root run a statement of the tenant's choosing. So a definition is
//! never handed to the client's statement splitter in a way that could split
//! it:
//!
//! - views do not need the client at all: they are created from a hex
//!   literal with `EXECUTE IMMEDIATE` (prepared statements may create views,
//!   not the other kinds);
//! - every other object is replayed in a client process of its own, with
//!   `--binary-mode --sandbox` (no backslash commands except `\C`, nothing
//!   that touches files), under a delimiter that occurs nowhere in its text.
//!   The client cannot split inside the definition; if it misreads the end
//!   of the definition as an open string or comment, the server receives the
//!   definition plus `?oxpanel-end…?`, which is a syntax error outside a
//!   comment — the statement fails and nothing else is in that process;
//! - a definition containing `\C` (the one command binary mode obeys: it
//!   would change how the server decodes the rest) or a NUL is not replayed;
//! - an object whose definer is not one of the owning tenant's accounts is not
//!   created (it would run with someone else's privileges), and after a load
//!   from a dump such objects are dropped ([`drop_foreign`]).
//!
//! An object that is not re-created is returned as an [`ObjectIssue`] with
//! its definition; table data never depends on it.

use std::fmt::Write as _;

use tracing::{info, warn};

use super::mariadb::{self, content, hex_text, Schema, SchemaObjects};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::records::{DbObjectDef, DbObjectKind, ObjectIssue};
use crate::validate::{DbName, Username};

/// Whether `definer` (`user@host`) is one of the tenant's database accounts.
pub fn definer_belongs(definer: &str, tenant: &Username) -> bool {
    definer.rsplit_once('@').is_some_and(|(user, host)| {
        host == mariadb::ACCOUNT_HOST && DbName::parse_for(user, tenant, "definer").is_ok()
    })
}

/// The objects of `listed` whose definitions are captured (views only when
/// `with_views`: a dump carries views itself).
pub fn selected(listed: &SchemaObjects, with_views: bool) -> Vec<(DbObjectKind, String)> {
    listed
        .objects
        .iter()
        .filter(|o| with_views || o.kind != DbObjectKind::View)
        .map(|o| (o.kind, o.name.clone()))
        .collect()
}

/// Turn one row of `SHOW CREATE <kind>` (batch output) into a definition.
fn parse_show_create(
    kind: DbObjectKind,
    name: &str,
    definer: &str,
    line: &str,
) -> Result<DbObjectDef> {
    let cols: Vec<String> = line.split('\t').map(mariadb::unescape).collect();
    let col = |i: usize| cols.get(i).cloned().unwrap_or_default();
    // Column layouts of SHOW CREATE VIEW / TRIGGER / PROCEDURE|FUNCTION / EVENT.
    let (sql_mode, time_zone, definition) = match kind {
        DbObjectKind::View => (String::new(), String::new(), col(1)),
        DbObjectKind::Trigger | DbObjectKind::Procedure | DbObjectKind::Function => {
            (col(1), String::new(), col(2))
        }
        DbObjectKind::Event => (col(1), col(2), col(3)),
    };
    if col(0) != name || definition.is_empty() || definition == "NULL" {
        return Err(Error::Internal(format!(
            "the server did not show the definition of {} '{name}'",
            kind.as_str()
        )));
    }
    Ok(DbObjectDef {
        kind,
        name: name.to_owned(),
        definer: definer.to_owned(),
        sql_mode,
        time_zone,
        definition,
    })
}

/// The definitions of the selected objects of `schema` (read-only).
pub async fn capture(
    ctx: &Ctx,
    schema: &Schema,
    listed: &SchemaObjects,
    with_views: bool,
) -> Result<Vec<DbObjectDef>> {
    let wanted = selected(listed, with_views);
    if wanted.is_empty() {
        return Ok(Vec::new());
    }
    let out = mariadb::run_hardened(ctx, content::show_create(schema, &wanted)).await?;
    let lines: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
    if lines.len() != wanted.len() {
        return Err(Error::Internal(format!(
            "expected {} definitions from the server, got {}",
            wanted.len(),
            lines.len()
        )));
    }
    let mut defs = Vec::with_capacity(wanted.len());
    for ((kind, name), line) in wanted.iter().zip(lines) {
        let definer = listed
            .objects
            .iter()
            .find(|o| o.kind == *kind && &o.name == name)
            .map(|o| o.definer.as_str())
            .unwrap_or_default();
        defs.push(parse_show_create(*kind, name, definer, line)?);
    }
    Ok(defs)
}

/// The first delimiter of the form `?oxpanel-end-<n>?` that does not occur in
/// `text`.
pub fn delimiter_for(text: &str) -> String {
    let mut n: u64 = 0;
    loop {
        let d = format!("?oxpanel-end-{n}?");
        if !text.contains(d.as_str()) {
            return d;
        }
        n += 1;
    }
}

/// The script that re-creates one trigger, routine or event in `schema`.
/// `None` when its text cannot be replayed safely.
pub fn replay_script(schema: &Schema, def: &DbObjectDef) -> Option<String> {
    if def.definition.contains("\\C") || def.definition.contains('\0') {
        return None;
    }
    let delimiter = delimiter_for(&def.definition);
    let mut s = format!("SET SESSION sql_mode = {};\n", hex_text(&def.sql_mode));
    if def.kind == DbObjectKind::Event && !def.time_zone.is_empty() {
        let _ = writeln!(s, "SET SESSION time_zone = {};", hex_text(&def.time_zone));
    }
    let _ = write!(
        s,
        "USE `{}`;\nDELIMITER {delimiter}\n{}\n{delimiter}\n",
        schema.as_str(),
        def.definition
    );
    Some(s)
}

fn issue(def: &DbObjectDef, reason: impl Into<String>) -> ObjectIssue {
    ObjectIssue {
        kind: def.kind,
        name: def.name.clone(),
        reason: reason.into(),
        definition: def.definition.clone(),
    }
}

/// Why the server refused, for the caller; MariaDB being unreachable is not
/// an object's fault and aborts the whole operation (it is repeatable).
fn refused(e: Error) -> Result<String> {
    match e {
        Error::DbUnavailable(_) => Err(e),
        Error::CommandFailed { stderr, .. } if !stderr.is_empty() => Ok(stderr),
        other => Ok(other.to_string()),
    }
}

/// Order in which kinds are re-created: views (in rounds, they may use one
/// another), then routines, triggers (which may call them) and events.
const ORDER: [DbObjectKind; 4] = [
    DbObjectKind::Procedure,
    DbObjectKind::Function,
    DbObjectKind::Trigger,
    DbObjectKind::Event,
];

/// Re-create `defs` in `schema`, which belongs to `tenant`. Objects that
/// already exist there (an interrupted earlier attempt) are left alone.
/// Returns what could not be re-created.
pub async fn recreate(
    ctx: &Ctx,
    schema: &Schema,
    tenant: &Username,
    defs: &[DbObjectDef],
) -> Result<Vec<ObjectIssue>> {
    let present = mariadb::objects(ctx, schema).await?;
    let exists = |d: &DbObjectDef| {
        present
            .objects
            .iter()
            .any(|o| o.kind == d.kind && o.name == d.name)
    };
    let mut issues = Vec::new();
    let mut pending: Vec<&DbObjectDef> = Vec::new();
    for def in defs.iter().filter(|d| !exists(d)) {
        if definer_belongs(&def.definer, tenant) {
            pending.push(def);
        } else {
            issues.push(issue(
                def,
                format!(
                    "its definer '{}' is not one of tenant {tenant}'s database users; it was not re-created",
                    def.definer
                ),
            ));
        }
    }
    let (mut views, others): (Vec<&DbObjectDef>, Vec<&DbObjectDef>) = pending
        .into_iter()
        .partition(|d| d.kind == DbObjectKind::View);
    // Views in rounds until a round creates none.
    loop {
        let mut failed = Vec::new();
        let mut last_errors = Vec::new();
        let before = views.len();
        for def in views {
            match mariadb::run_hardened(ctx, content::create_view(schema, &def.definition)).await {
                Ok(_) => {}
                Err(e) => {
                    last_errors.push(refused(e)?);
                    failed.push(def);
                }
            }
        }
        if failed.is_empty() || failed.len() == before {
            for (def, why) in failed.iter().zip(last_errors) {
                issues.push(issue(def, why));
            }
            break;
        }
        views = failed;
    }
    for kind in ORDER {
        for def in others.iter().filter(|d| d.kind == kind) {
            let Some(script) = replay_script(schema, def) else {
                issues.push(issue(
                    def,
                    "its text contains \\C or a NUL byte and cannot be replayed safely",
                ));
                continue;
            };
            if let Err(e) = mariadb::run_hardened(ctx, script).await {
                issues.push(issue(def, refused(e)?));
            }
        }
    }
    for i in &issues {
        warn!(schema = %schema.as_str(), kind = i.kind.as_str(), name = %i.name, reason = %i.reason, "object not re-created");
    }
    info!(schema = %schema.as_str(), recreated = defs.len().saturating_sub(issues.len()), not_recreated = issues.len(), "stored objects re-created");
    Ok(issues)
}

/// Drop every view, trigger, routine and event of `schema` whose definer is
/// not one of `tenant`'s accounts (after loading a dump, before anyone is
/// granted the database). Returns them, with their definitions.
pub async fn drop_foreign(
    ctx: &Ctx,
    schema: &Schema,
    tenant: &Username,
) -> Result<Vec<ObjectIssue>> {
    let listed = mariadb::objects(ctx, schema).await?;
    let foreign = SchemaObjects {
        tables: Vec::new(),
        objects: listed
            .objects
            .into_iter()
            .filter(|o| !definer_belongs(&o.definer, tenant))
            .collect(),
    };
    if foreign.objects.is_empty() {
        return Ok(Vec::new());
    }
    let defs = capture(ctx, schema, &foreign, true).await?;
    let script: String = foreign
        .objects
        .iter()
        .map(|o| content::drop_object(schema, o.kind, &o.name))
        .collect();
    mariadb::run_hardened(ctx, script).await?;
    Ok(defs
        .iter()
        .map(|d| {
            warn!(schema = %schema.as_str(), kind = d.kind.as_str(), name = %d.name, definer = %d.definer, "object with a foreign definer dropped");
            issue(
                d,
                format!(
                    "its definer '{}' is not one of tenant {tenant}'s database users; it was dropped",
                    d.definer
                ),
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(kind: DbObjectKind, definition: &str) -> DbObjectDef {
        DbObjectDef {
            kind,
            name: "p".into(),
            definer: "alice_app@localhost".into(),
            sql_mode: "STRICT_TRANS_TABLES".into(),
            time_zone: "SYSTEM".into(),
            definition: definition.into(),
        }
    }

    #[test]
    fn definers_must_be_the_tenants_own_local_accounts() -> Result<()> {
        let alice = Username::parse("alice")?;
        assert!(definer_belongs("alice_app@localhost", &alice));
        for foreign in [
            "root@localhost",
            "alice_app@%",
            "alice_app@127.0.0.1",
            "bob_app@localhost",
            "alice@localhost",
            "alice_shop_app@localhost",
            "",
            "alice_app",
        ] {
            assert!(!definer_belongs(foreign, &alice), "{foreign}");
        }
        Ok(())
    }

    #[test]
    fn the_delimiter_never_occurs_in_the_text() {
        assert_eq!(delimiter_for("BEGIN SELECT 1; END"), "?oxpanel-end-0?");
        assert_eq!(
            delimiter_for("x ?oxpanel-end-0? ?oxpanel-end-1?"),
            "?oxpanel-end-2?"
        );
    }

    #[test]
    fn replay_scripts_are_exact_and_refuse_client_commands() {
        let schema =
            Schema::of_db(&DbName::parse("alice_wp", "n").unwrap_or_else(|e| panic!("{e}")));
        // The body that fooled `mariadb-dump | mariadb` on MariaDB 10.5.
        let evil = "CREATE DEFINER=`alice_app`@`localhost` PROCEDURE `p`()\nBEGIN SELECT 1; END --\u{1} ;; CREATE DATABASE pwned ;;";
        assert_eq!(
            replay_script(&schema, &def(DbObjectKind::Procedure, evil)),
            Some(format!(
                "SET SESSION sql_mode = CONVERT(X'5354524943545F5452414E535F5441424C4553' USING utf8mb4);\nUSE `alice_wp`;\nDELIMITER ?oxpanel-end-0?\n{evil}\n?oxpanel-end-0?\n"
            ))
        );
        let event = replay_script(
            &schema,
            &def(
                DbObjectKind::Event,
                "CREATE EVENT e ON SCHEDULE EVERY 1 DAY DO SELECT 1",
            ),
        )
        .unwrap_or_default();
        assert!(event.contains("SET SESSION time_zone = CONVERT(X'53595354454D' USING utf8mb4);\n"));
        for unsafe_text in ["BEGIN \\C gbk END", "BEGIN \0 END"] {
            assert_eq!(
                replay_script(&schema, &def(DbObjectKind::Trigger, unsafe_text)),
                None
            );
        }
    }

    #[test]
    fn show_create_rows_are_parsed_per_kind() -> Result<()> {
        let t = parse_show_create(
            DbObjectKind::Trigger,
            "trg",
            "alice_app@localhost",
            "trg\tSTRICT_TRANS_TABLES\tCREATE DEFINER=`alice_app`@`localhost` TRIGGER trg BEFORE INSERT ON t FOR EACH ROW SET @a = 1\tutf8mb4\tutf8mb4_general_ci\tlatin1_swedish_ci\t2026-11-13 16:56:10.48",
        )?;
        assert_eq!(
            (t.sql_mode.as_str(), t.definition.as_str()),
            (
                "STRICT_TRANS_TABLES",
                "CREATE DEFINER=`alice_app`@`localhost` TRIGGER trg BEFORE INSERT ON t FOR EACH ROW SET @a = 1"
            )
        );
        let p = parse_show_create(
            DbObjectKind::Procedure,
            "p",
            "alice_app@localhost",
            "p\tANSI\tCREATE PROCEDURE `p`()\\nBEGIN SELECT 'a\\tb'; END\tutf8mb4\tc\td",
        )?;
        assert_eq!(
            p.definition,
            "CREATE PROCEDURE `p`()\nBEGIN SELECT 'a\tb'; END"
        );
        let e = parse_show_create(
            DbObjectKind::Event,
            "ev",
            "alice_app@localhost",
            "ev\tANSI\t+00:00\tCREATE EVENT `ev` ON SCHEDULE EVERY 1 DAY DO SELECT 1\tutf8mb4\tc\td",
        )?;
        assert_eq!(
            (e.time_zone.as_str(), e.sql_mode.as_str()),
            ("+00:00", "ANSI")
        );
        let v = parse_show_create(
            DbObjectKind::View,
            "v",
            "alice_app@localhost",
            "v\tCREATE VIEW `v` AS select 1 AS `1`\tutf8mb4\tc",
        )?;
        assert_eq!(
            (v.sql_mode.as_str(), v.definition.as_str()),
            ("", "CREATE VIEW `v` AS select 1 AS `1`")
        );
        // Another object's row, or no definition, is refused.
        assert!(parse_show_create(DbObjectKind::View, "w", "", "v\tCREATE VIEW x").is_err());
        assert!(parse_show_create(DbObjectKind::Function, "f", "", "f\tANSI\tNULL").is_err());
        Ok(())
    }
}
