//! Property tests of every validator and renderer.
//!
//! Three families of properties:
//!
//! 1. **No input panics.** Every parser and renderer is fed arbitrary text.
//! 2. **An accepted value keeps the promise of its type.** Whatever
//!    `Username::parse`, `Domain::parse`, `RelPath::parse`, … accept
//!    round-trips unchanged and is safe in every context it is used in (file
//!    name, systemd unit name, Nginx directive, path below the tenant home).
//! 3. **Rendering commutes with substitution.** A rendered Nginx block, FPM
//!    configuration or systemd unit equals the same template rendered with
//!    placeholder values, with the placeholders replaced. So no input can add,
//!    remove or alter a line: the structure is the template's, always.
//!    Records are re-validated when rendered, so a hostile *record* either
//!    fails to render or renders the template's structure, too.
//!
//! Bounded (a few seconds in `make test`), deterministic per case count, and
//! shrinking: a failure prints the minimal offending input.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use proptest::prelude::*;

use oxpanel_daemon::auth::{PeerInfo, PeerPolicy, Scope, ScopePolicy};
use oxpanel_daemon::config::Config;
use oxpanel_daemon::records::{
    AppRecord, AppRuntime, Store, TenantRecord, TenantState, VHostRecord, RECORD_VERSION,
};
use oxpanel_daemon::system::{bin, CommandSpec};
use oxpanel_daemon::validate::{
    check_new_name, Domain, FileMode, FilePath, Limits, OwnerLabel, RelPath, Username,
    FILE_NAME_MAX, FILE_PATH_DEPTH_MAX, FILE_PATH_MAX, MAX_WEIGHT, MIN_MEMORY_MAX_BYTES,
};
use oxpanel_daemon::{app, nginx, php, systemd, Error};

// ---------------------------------------------------------------- strategies

/// Anything at all, including control characters and non-ASCII.
fn any_text() -> impl Strategy<Value = String> {
    prop_oneof![
        ".{0,64}",
        "\\PC{0,64}",
        any::<Vec<u8>>().prop_map(|b| String::from_utf8_lossy(&b).into_owned()),
    ]
}

/// Text built to look almost right, so that parsers are probed at their edges.
fn near_username() -> impl Strategy<Value = String> {
    prop_oneof!["[a-z][a-z0-9_-]{0,34}", "[a-zA-Z0-9_.-]{0,34}", any_text()]
}
fn near_domain() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z0-9-]{1,12}(\\.[a-z0-9-]{1,12}){0,5}",
        "[a-z0-9.-]{0,80}",
        "[a-zA-Z0-9.*_-]{0,40}",
        any_text()
    ]
}
fn near_relpath() -> impl Strategy<Value = String> {
    prop_oneof![
        "[A-Za-z0-9._-]{1,12}(/[A-Za-z0-9._-]{1,12}){0,5}",
        "[A-Za-z0-9._/-]{0,60}",
        "(\\.\\./|\\./|/)?[a-z.]{1,8}(/(\\.\\.|\\.|[a-z]{1,6})){0,4}/?",
        any_text()
    ]
}

/// Values the validators accept, by construction.
fn username() -> impl Strategy<Value = Username> {
    "[a-z][a-z0-9_-]{2,31}".prop_filter_map("reserved", |s| Username::parse(&s).ok())
}
fn domain() -> impl Strategy<Value = Domain> {
    "[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?){1,4}"
        .prop_filter_map("numeric tld", |s| Domain::parse(&s).ok())
}
fn relpath() -> impl Strategy<Value = RelPath> {
    "[A-Za-z0-9_-][A-Za-z0-9._-]{0,10}(/[A-Za-z0-9_-][A-Za-z0-9._-]{0,10}){0,4}"
        .prop_filter_map("dots", |s| RelPath::parse(&s).ok())
}
fn limits() -> impl Strategy<Value = Limits> {
    (
        proptest::option::of(MIN_MEMORY_MAX_BYTES..=u64::MAX),
        proptest::option::of(1..=MAX_WEIGHT),
        proptest::option::of(1..=MAX_WEIGHT),
        proptest::option::of(1..=u32::MAX),
        // Disk quotas: at least 1 MiB, whole KiB; at least 100 inodes.
        proptest::option::of((1u64 << 10..=u64::MAX >> 10).prop_map(|kib| kib << 10)),
        proptest::option::of(100..=u64::MAX),
    )
        .prop_map(
            |(memory_max_bytes, cpu_weight, io_weight, tasks_max, disk_max_bytes, inodes_max)| {
                Limits {
                    memory_max_bytes,
                    cpu_weight,
                    io_weight,
                    tasks_max,
                    disk_max_bytes,
                    inodes_max,
                    db_trash_max_bytes: None,
                }
            },
        )
}

/// Characters that end, extend or change the meaning of a line in one of the
/// places a value ends up: Nginx, a unit file, an INI file, a path, argv.
const DANGEROUS: &[char] = &[
    '\n', '\r', '\0', '\t', ' ', ';', '{', '}', '"', '\'', '$', '`', '\\', '*', '?', '#', '=', '%',
    '&', '|', '<', '>', '(', ')', '[', ']', '!', '~', ':', '@', ',', '\u{7f}', '\u{a0}',
    '\u{200b}', 'é', 'İ',
];

fn dangerous() -> impl Strategy<Value = char> {
    proptest::sample::select(DANGEROUS)
}

fn insert_at(s: &str, at: usize, c: char) -> String {
    let at = at % (s.len() + 1);
    let mut out = String::with_capacity(s.len() + 4);
    out.push_str(&s[..at]);
    out.push(c);
    out.push_str(&s[at..]);
    out
}

fn tenant_record(name: &Username, home: &Path) -> TenantRecord {
    TenantRecord {
        version: RECORD_VERSION,
        username: name.to_string(),
        uid: 20_000,
        gid: 20_000,
        home: home.to_owned(),
        limits: Limits::default(),
        slice_unit: systemd::slice_unit_name(name),
        created_at_unix: 0,
        state: TenantState::Ready,
        owner: String::new(),
        suspended: false,
        sftp_keys: Vec::new(),
        sftp_password: false,
    }
}

/// `Key` of every `Key=Value` line and every `[Section]`, in order: the
/// structure of a unit or INI file, without its values.
fn structure(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#') && !l.starts_with(';'))
        .map(|l| match l.split_once('=') {
            Some((k, _)) if !l.starts_with('[') => k.trim().to_owned(),
            _ => l.to_owned(),
        })
        .collect()
}

/// An Nginx block reduced to its directive names and braces.
fn nginx_structure(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().next().unwrap_or_default().to_owned())
        .collect()
}

// ---------------------------------------------------------------- validators

proptest! {
    #[test]
    fn no_text_makes_a_parser_panic(s in any_text()) {
        let _ = Username::parse(&s);
        let _ = Domain::parse(&s);
        let _ = RelPath::parse(&s);
        let _ = OwnerLabel::parse_optional(&s);
        let _ = Scope::parse(&s);
        let _ = app::major_of(&s);
        let _ = systemd::escape_unit_component(&s);
    }

    #[test]
    fn an_accepted_username_is_safe_everywhere_it_is_used(s in near_username()) {
        if let Ok(name) = Username::parse(&s) {
            prop_assert_eq!(name.as_str(), s.as_str());
            prop_assert_eq!(name.to_string(), s.clone());
            prop_assert!((3..=32).contains(&s.len()));
            prop_assert!(s.as_bytes()[0].is_ascii_lowercase());
            prop_assert!(s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'));
            prop_assert!(!["root", "nginx", "nobody", "wheel", "sudo"].contains(&s.as_str()));
            prop_assert!(!s.starts_with("oxpanel") && !s.starts_with("systemd-"));
            // As a systemd unit name: one slice, never nested below another
            // tenant's ('-' is the hierarchy separator), and reversible.
            let slice = systemd::slice_unit_name(&name);
            let middle = slice.strip_prefix("oxpanel-tenant-").and_then(|r| r.strip_suffix(".slice"));
            prop_assert!(middle.is_some());
            let middle = middle.unwrap_or_default();
            prop_assert!(!middle.contains('-') && !middle.contains('/') && !middle.contains(char::is_whitespace));
            prop_assert_eq!(middle.replace("\\x2d", "-"), s.clone());
            let unit = php::unit_name(&name);
            prop_assert!(unit.starts_with("oxpanel-php-") && unit.ends_with(".service"));
            // As a file name and a socket path.
            let files = php::PoolFiles::for_tenant(Path::new("/etc/oxpanel-php"), Path::new("/etc/systemd/system"), &name);
            prop_assert_eq!(files.conf.parent(), Some(Path::new("/etc/oxpanel-php")));
            prop_assert_eq!(files.unit.parent(), Some(Path::new("/etc/systemd/system")));
            prop_assert!(php::socket_path(&name).starts_with("/run/oxpanel-php"));
        }
    }

    #[test]
    fn distinct_usernames_get_distinct_units(a in username(), b in username()) {
        prop_assume!(a != b);
        prop_assert_ne!(systemd::slice_unit_name(&a), systemd::slice_unit_name(&b));
        prop_assert_ne!(php::unit_name(&a), php::unit_name(&b));
        prop_assert_ne!(php::socket_path(&a), php::socket_path(&b));
    }

    #[test]
    fn an_accepted_domain_is_safe_everywhere_it_is_used(s in near_domain()) {
        if let Ok(d) = Domain::parse(&s) {
            prop_assert_eq!(d.as_str(), s.as_str());
            prop_assert!(!s.is_empty() && s.len() <= 253);
            prop_assert!(s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'));
            let labels: Vec<&str> = s.split('.').collect();
            prop_assert!(labels.len() >= 2);
            for l in &labels {
                prop_assert!(!l.is_empty() && l.len() <= 63);
                prop_assert!(!l.starts_with('-') && !l.ends_with('-'));
            }
            prop_assert!(!labels.last().is_some_and(|t| t.bytes().all(|b| b.is_ascii_digit())), "an IP address is not a domain");
            prop_assert!(!s.contains(".."));
            // As a file name: exactly one component, in the directory given.
            let conf = nginx::conf_path(Path::new("/etc/nginx/oxpanel.d"), &d);
            prop_assert_eq!(conf.parent(), Some(Path::new("/etc/nginx/oxpanel.d")));
            let file_name = format!("{s}.conf");
            prop_assert_eq!(conf.file_name().and_then(|n| n.to_str()), Some(file_name.as_str()));
            let unit = app::unit_path(Path::new("/etc/systemd/system"), &d);
            prop_assert_eq!(unit.parent(), Some(Path::new("/etc/systemd/system")));
            let name = app::unit_name(&d);
            prop_assert!(name.starts_with("oxpanel-app-") && name.ends_with(".service"));
            let middle = &name["oxpanel-app-".len()..name.len() - ".service".len()];
            prop_assert!(!middle.contains('-') && !middle.contains('/'));
            let run_dir = app::runtime_dir(&d);
            prop_assert_eq!(run_dir.parent(), Some(Path::new("/run/oxpanel-app")));
        }
    }

    #[test]
    fn distinct_domains_get_distinct_units_and_files(a in domain(), b in domain()) {
        prop_assume!(a != b);
        prop_assert_ne!(app::unit_name(&a), app::unit_name(&b));
        prop_assert_ne!(app::socket_path(&a), app::socket_path(&b));
        let dir = Path::new("/etc/nginx/oxpanel.d");
        prop_assert_ne!(nginx::conf_path(dir, &a), nginx::conf_path(dir, &b));
    }

    #[test]
    fn an_accepted_relative_path_stays_below_the_home(s in near_relpath()) {
        if let Ok(p) = RelPath::parse(&s) {
            prop_assert_eq!(p.as_str(), s.as_str());
            prop_assert!(!s.is_empty() && s.len() <= 255);
            prop_assert!(!s.starts_with('/') && !s.ends_with('/') && !s.contains("//"));
            prop_assert!(s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/')));
            for comp in s.split('/') {
                prop_assert!(comp != "." && comp != "..");
            }
            let home = Path::new("/home/alice");
            let abs = home.join(&s);
            prop_assert!(abs.starts_with(home));
            prop_assert!(abs.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_))));
            // One component per '/'-separated part: nothing is collapsed away.
            prop_assert_eq!(abs.components().count(), 3 + s.split('/').count());
        }
    }

    #[test]
    fn an_accepted_owner_label_is_plain(s in prop_oneof!["[a-z0-9][a-z0-9_.-]{0,70}", any_text()]) {
        match OwnerLabel::parse_optional(&s) {
            Ok(None) => prop_assert!(s.is_empty()),
            Ok(Some(o)) => {
                prop_assert_eq!(o.as_str(), s.as_str());
                prop_assert!(s.len() <= 64);
                prop_assert!(s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')));
                prop_assert!(!s.starts_with(['-', '.', '_']));
            }
            Err(e) => {
                let invalid = matches!(e, Error::InvalidInput { .. });
                prop_assert!(invalid);
            }
        }
    }

    /// One dangerous character anywhere in an otherwise valid value: refused.
    #[test]
    fn one_dangerous_character_is_always_refused(
        name in username(), d in domain(), p in relpath(),
        owner in "[a-z0-9][a-z0-9_.-]{0,40}",
        at in any::<usize>(), c in dangerous(),
    ) {
        prop_assert!(Username::parse(&insert_at(name.as_str(), at, c)).is_err());
        prop_assert!(Domain::parse(&insert_at(d.as_str(), at, c)).is_err());
        prop_assert!(RelPath::parse(&insert_at(p.as_str(), at, c)).is_err());
        prop_assert!(OwnerLabel::parse_optional(&insert_at(&owner, at, c)).is_err());
    }

    #[test]
    fn traversal_is_refused_wherever_it_is_put(p in relpath(), at in any::<usize>()) {
        let parts: Vec<&str> = p.as_str().split('/').collect();
        let at = at % (parts.len() + 1);
        for evil in ["..", ".", ""] {
            let mut with: Vec<&str> = parts.clone();
            with.insert(at, evil);
            prop_assert!(RelPath::parse(&with.join("/")).is_err(), "{:?}", with);
        }
        let absolute = format!("/{}", p.as_str());
        prop_assert!(RelPath::parse(&absolute).is_err());
    }

    #[test]
    fn limits_are_accepted_exactly_within_their_bounds(m in any::<u64>(), c in any::<u32>(), i in any::<u32>(), t in any::<u32>()) {
        let valid = (m == 0 || m >= MIN_MEMORY_MAX_BYTES) && c <= MAX_WEIGHT && i <= MAX_WEIGHT;
        match Limits::parse(m, c, i, t) {
            Ok(l) => {
                prop_assert!(valid);
                prop_assert_eq!(l.memory_max_bytes.unwrap_or(0), m);
                prop_assert_eq!(l.cpu_weight.unwrap_or(0), c);
                prop_assert_eq!(l.io_weight.unwrap_or(0), i);
                prop_assert_eq!(l.tasks_max.unwrap_or(0), t);
            }
            Err(e) => {
                prop_assert!(!valid);
                let invalid = matches!(e, Error::InvalidInput { .. });
                prop_assert!(invalid);
            }
        }
    }
}

// ---------------------------------------------------------------- renderers

const P_TENANT: &str = "zqtenantqz";
const P_DOMAIN: &str = "zqdomainqz.example";
const P_HOME: &str = "/zqhomeqz";
const P_ROOT: &str = "zqrootqz";
const P_ENTRY: &str = "zqentryqz";

fn placeholder_tenant() -> (TenantRecord, Username) {
    let name = Username::parse(P_TENANT).expect("placeholder name");
    (tenant_record(&name, Path::new(P_HOME)), name)
}

/// Replace the placeholders of a reference rendering with real values.
/// Longest and most specific first; the placeholders occur nowhere else.
fn substitute(reference: &str, pairs: &[(&str, &str)]) -> String {
    pairs.iter().fold(reference.to_owned(), |acc, (from, to)| {
        acc.replace(from, to)
    })
}

proptest! {
    #[test]
    fn a_slice_unit_carries_exactly_the_requested_limits(name in username(), l in limits()) {
        for text in [systemd::render_slice_unit(&name, &l), systemd::render_user_slice_dropin(&name, &l)] {
            let mut expected: Vec<String> = Vec::new();
            if let Some(b) = l.memory_max_bytes {
                expected.push(format!("MemoryMax={b}"));
                expected.push("MemorySwapMax=0".to_owned());
            }
            if let Some(w) = l.cpu_weight { expected.push(format!("CPUWeight={w}")); }
            if let Some(w) = l.io_weight { expected.push(format!("IOWeight={w}")); }
            if let Some(t) = l.tasks_max { expected.push(format!("TasksMax={t}")); }
            let after_slice: Vec<&str> = text.split("[Slice]\n").nth(1).unwrap_or_default().lines().collect();
            prop_assert_eq!(after_slice, expected);
            prop_assert_eq!(text.matches("[Slice]").count(), 1);
            prop_assert!(!text.contains("User=") && !text.contains("Exec"));
        }
        let (_, p_name) = placeholder_tenant();
        prop_assert_eq!(
            systemd::render_slice_unit(&name, &l),
            substitute(&systemd::render_slice_unit(&p_name, &l), &[(P_TENANT, name.as_str())])
        );
    }

    #[test]
    fn an_nginx_block_is_its_template_whatever_the_inputs(
        d in domain(), aliases in proptest::collection::vec(domain(), 0..6),
        name in username(), root in relpath(),
        mode in 0..4usize,
    ) {
        let home = PathBuf::from("/home").join(name.as_str());
        let docroot = home.join(root.as_str());
        let access = PathBuf::from(format!("/var/log/nginx/oxpanel/{d}.access.log"));
        let error = PathBuf::from(format!("/var/log/nginx/oxpanel/{d}.error.log"));
        let php_sock = php::socket_path(&name);
        let app_sock = app::socket_path(&d);
        let render = |d: &Domain, aliases: &[Domain], name: &Username, docroot: &Path, access: &Path, error: &Path, php_sock: &Path, app_sock: &Path| {
            nginx::render_server_block(&nginx::ServerBlock {
                domain: d, aliases, tenant: name, document_root: docroot,
                suspended: mode == 3, access_log: access, error_log: error,
                php_socket: (mode == 1).then_some(php_sock),
                app_socket: (mode == 2).then_some(app_sock),
                acme_challenge_dir: Path::new("/var/lib/oxpanel-acme/challenges"), tls: None,
            })
        };
        let out = render(&d, &aliases, &name, &docroot, &access, &error, &php_sock, &app_sock).expect("valid inputs render");

        // Structure: one server, balanced braces, one of each directive that
        // must be unique, and every server name is one we were given.
        prop_assert_eq!(out.matches("server {").count(), 1);
        prop_assert_eq!(out.matches('{').count(), out.matches('}').count());
        prop_assert_eq!(out.lines().filter(|l| l.trim_start().starts_with("server_name ")).count(), 1);
        let names: Vec<&str> = std::iter::once(d.as_str()).chain(aliases.iter().map(Domain::as_str)).collect();
        let server_name_line = format!("    server_name {};", names.join(" "));
        prop_assert!(out.lines().any(|l| l == server_name_line));
        prop_assert_eq!(out.lines().filter(|l| l.trim_start().starts_with("root ")).count(), usize::from(mode != 3));
        prop_assert!(!out.contains("autoindex on") && !out.contains("127.0.0.1") && !out.contains("default_server"));
        if mode == 3 {
            let home_s = home.to_string_lossy();
            prop_assert!(!out.contains(home_s.as_ref()), "a suspended site names nothing of the tenant's");
        }

        // The template, rendered with placeholders, with the placeholders
        // replaced, is the same text: inputs fill slots and do nothing else.
        let (pd, pn) = (Domain::parse(P_DOMAIN).expect("placeholder"), Username::parse(P_TENANT).expect("placeholder"));
        let reference = render(
            &pd, &[], &pn, Path::new("/zqdocrootqz"), Path::new("/zqaccessqz"), Path::new("/zqerrorqz"),
            Path::new("/zqphpsockqz"), Path::new("/zqappsockqz"),
        ).expect("placeholders render");
        let expected = substitute(&reference, &[
            ("/zqdocrootqz", &docroot.to_string_lossy()),
            ("/zqaccessqz", &access.to_string_lossy()),
            ("/zqerrorqz", &error.to_string_lossy()),
            ("/zqphpsockqz", &php_sock.to_string_lossy()),
            ("/zqappsockqz", &app_sock.to_string_lossy()),
            (P_DOMAIN, &names.join(" ")),
            (P_TENANT, name.as_str()),
        ]);
        prop_assert_eq!(out, expected);
    }

    /// Paths reach the Nginx renderer from records and configuration. Any
    /// path at all either fails to render or leaves the structure alone.
    #[test]
    fn a_hostile_path_cannot_change_an_nginx_block(evil in any_text(), slot in 0..5usize, mode in 0..3usize) {
        let d = Domain::parse("example.com").expect("domain");
        let name = Username::parse("alice").expect("name");
        let good = ["/home/alice/public_html", "/var/log/a.log", "/var/log/e.log", "/run/p.sock", "/run/a.sock"];
        let mut paths: Vec<PathBuf> = good.iter().map(PathBuf::from).collect();
        paths[slot] = PathBuf::from(&evil);
        let block = |p: &[PathBuf]| nginx::render_server_block(&nginx::ServerBlock {
            domain: &d, aliases: &[], tenant: &name, document_root: &p[0], suspended: false,
            access_log: &p[1], error_log: &p[2],
            php_socket: (mode == 1).then_some(p[3].as_path()),
            app_socket: (mode == 2).then_some(p[4].as_path()),
            acme_challenge_dir: Path::new("/var/lib/oxpanel-acme/challenges"), tls: None,
        });
        let reference = block(&good.iter().map(PathBuf::from).collect::<Vec<_>>()).expect("reference");
        if let Ok(out) = block(&paths) {
            prop_assert_eq!(nginx_structure(&out), nginx_structure(&reference), "{:?}", evil);
            prop_assert_eq!(out.matches(';').count(), reference.matches(';').count());
        }
        if let Ok(include) = nginx::render_include(Path::new(&evil), true) {
            let reference = nginx::render_include(Path::new("/etc/nginx/oxpanel.d"), true).expect("reference");
            prop_assert_eq!(nginx_structure(&include), nginx_structure(&reference));
        }
    }

    #[test]
    fn a_php_pool_is_its_template_whatever_the_tenant(name in username(), home_leaf in "[a-z0-9_-]{1,16}") {
        let home = PathBuf::from("/home").join(&home_leaf);
        let t = tenant_record(&name, &home);
        let conf_path = PathBuf::from(format!("/etc/oxpanel-php/{name}.conf"));
        let conf = php::render_pool_conf(&t, &name, "nginx").expect("pool conf");
        let unit = php::render_unit(&t, &name, &conf_path).expect("unit");

        let (pt, pn) = placeholder_tenant();
        let p_conf_path = PathBuf::from(format!("/etc/oxpanel-php/{P_TENANT}.conf"));
        let home_s = home.to_string_lossy();
        let pairs = [
            (pt.slice_unit.as_str(), t.slice_unit.as_str()),
            (P_HOME, home_s.as_ref()),
            (P_TENANT, name.as_str()),
        ];
        prop_assert_eq!(&conf, &substitute(&php::render_pool_conf(&pt, &pn, "nginx").expect("reference"), &pairs));
        prop_assert_eq!(&unit, &substitute(&php::render_unit(&pt, &pn, &p_conf_path).expect("reference"), &pairs));

        // What the template promises, stated directly.
        let user_line = format!("User={name}");
        prop_assert!(unit.lines().any(|l| l == user_line));
        prop_assert_eq!(unit.lines().filter(|l| l.starts_with("User=")).count(), 1);
        prop_assert_eq!(unit.lines().filter(|l| l.starts_with("ExecStart=")).count(), 1);
        prop_assert_eq!(unit.lines().filter(|l| l.starts_with("ReadWritePaths=")).collect::<Vec<_>>(), vec![format!("ReadWritePaths={home_s}")]);
        prop_assert!(conf.lines().filter(|l| l.starts_with("listen")).all(|l| !l.contains("127.") && !l.contains(":9000")));
        let open_basedir = format!("php_admin_value[open_basedir] = {home_s}/:/tmp/:/usr/share/php/:/usr/share/pear/");
        prop_assert!(conf.lines().any(|l| l == open_basedir));
        prop_assert_eq!(conf.matches('[').count() - conf.matches("php_admin_").count(), 2, "one [global] and one pool section");
    }

    #[test]
    fn an_application_unit_is_its_template_whatever_the_inputs(
        name in username(), d in domain(), root in relpath(), entry in relpath(),
        python in any::<bool>(), selinux in any::<bool>(),
    ) {
        let home = PathBuf::from("/home").join(name.as_str());
        let t = tenant_record(&name, &home);
        let runtime = if python { AppRuntime::Python } else { AppRuntime::Node };
        let a = AppRecord { runtime, root: root.to_string(), entry: entry.to_string() };
        let unit = app::render_unit(&t, &d, &a, "nginx", selinux).expect("unit");

        let (pt, _) = placeholder_tenant();
        let pd = Domain::parse(P_DOMAIN).expect("placeholder");
        let pa = AppRecord { runtime, root: P_ROOT.into(), entry: P_ENTRY.into() };
        let reference = app::render_unit(&pt, &pd, &pa, "nginx", selinux).expect("reference");
        let home_s = home.to_string_lossy();
        let expected = substitute(&reference, &[
            (pt.slice_unit.as_str(), t.slice_unit.as_str()),
            (P_HOME, home_s.as_ref()),
            (P_ROOT, root.as_str()),
            (P_ENTRY, entry.as_str()),
            (P_DOMAIN, d.as_str()),
            (P_TENANT, name.as_str()),
        ]);
        prop_assert_eq!(&unit, &expected);

        let user_line = format!("User={name}");
        prop_assert_eq!(unit.lines().filter(|l| l.starts_with("User=")).collect::<Vec<_>>(), vec![user_line.as_str()]);
        prop_assert_eq!(unit.matches("ExecStart=").count(), 1);
        prop_assert_eq!(unit.matches("ExecStartPre=").count(), 1);
        let exec = unit.lines().find(|l| l.starts_with("ExecStart=")).unwrap_or_default();
        let program = exec.rsplit(' ').next().unwrap_or_default();
        prop_assert!(Path::new(program).starts_with(&home), "the program is below the tenant home: {}", exec);
        prop_assert_eq!(unit.contains("SELinuxContext="), selinux);
    }

    /// Records are files. Whatever a record says — edited by hand, damaged,
    /// or written by a compromised process — rendering it either fails or
    /// yields the structure of the template: never an extra directive.
    #[test]
    fn a_hostile_record_cannot_add_a_line_to_a_unit_or_pool(
        evil in prop_oneof![
            any_text(),
            "[a-z/._-]{1,20}\n[A-Z][A-Za-z]{2,12}=[a-z/+ -]{1,20}",
            "[a-z/._-]{1,12}[ ;\n][a-z/._=-]{1,12}",
            "/[a-z/._-]{1,30}",
            "[a-z-]{1,20}\\.slice",
        ],
        slot in 0..6usize, python in any::<bool>(),
    ) {
        let name = Username::parse("alice").expect("name");
        let d = Domain::parse("example.com").expect("domain");
        let good_tenant = tenant_record(&name, Path::new("/home/alice"));
        let runtime = if python { AppRuntime::Python } else { AppRuntime::Node };
        let good_app = AppRecord { runtime, root: "apps/x".into(), entry: "app.js".into() };
        let (mut t, mut a) = (good_tenant.clone(), good_app.clone());
        match slot {
            0 => t.home = PathBuf::from(&evil),
            1 => t.slice_unit.clone_from(&evil),
            2 => t.username.clone_from(&evil),
            3 => a.root.clone_from(&evil),
            4 => a.entry.clone_from(&evil),
            _ => t.owner.clone_from(&evil),
        }
        let conf_path = Path::new("/etc/oxpanel-php/alice.conf");
        if let Ok(out) = app::render_unit(&t, &d, &a, "nginx", true) {
            let reference = app::render_unit(&good_tenant, &d, &good_app, "nginx", true).expect("reference");
            prop_assert_eq!(structure(&out), structure(&reference), "application unit, slot {}, {:?}", slot, evil);
        }
        if let Ok(out) = php::render_unit(&t, &name, conf_path) {
            let reference = php::render_unit(&good_tenant, &name, conf_path).expect("reference");
            prop_assert_eq!(structure(&out), structure(&reference), "PHP unit, slot {}, {:?}", slot, evil);
        }
        if let Ok(out) = php::render_pool_conf(&t, &name, "nginx") {
            let reference = php::render_pool_conf(&good_tenant, &name, "nginx").expect("reference");
            prop_assert_eq!(structure(&out), structure(&reference), "pool configuration, slot {}, {:?}", slot, evil);
        }
        if let Ok(out) = php::render_unit(&good_tenant, &name, Path::new(&evil)) {
            let reference = php::render_unit(&good_tenant, &name, conf_path).expect("reference");
            prop_assert_eq!(structure(&out), structure(&reference), "PHP unit with configuration path {:?}", evil);
        }
    }
}

// ---------------------------------------------------------------- records

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn records_round_trip_and_damaged_ones_block_only_themselves(
        name in username(), d in domain(), root in relpath(), l in limits(),
        owner in "[a-z0-9]{0,12}", suspended in any::<bool>(), php in any::<bool>(),
        garbage in any::<Vec<u8>>(),
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = Config::default();
        cfg.state_dir = dir.path().join("state");
        let store = Store::new(&cfg);
        store.init().expect("init");
        let mut t = tenant_record(&name, &PathBuf::from("/home").join(name.as_str()));
        t.limits = l;
        t.owner = owner;
        t.suspended = suspended;
        store.save_tenant(&t).expect("save tenant");
        prop_assert_eq!(store.load_tenant(&name).expect("load"), Some(t.clone()));
        let v = VHostRecord {
            version: RECORD_VERSION,
            domain: d.to_string(),
            tenant: name.to_string(),
            document_root: root.to_string(),
            aliases: vec![],
            config_path: PathBuf::from(format!("/etc/nginx/oxpanel.d/{d}.conf")),
            created_at_unix: 1,
            php,
            app: None,
            redirect_https: false,
            hsts: false,
            tls: None,
            auto_https: oxpanel_daemon::records::AutoHttpsChoice::On,
        };
        store.save_vhost(&v).expect("save vhost");
        prop_assert_eq!(store.load_vhost(&d).expect("load"), Some(v));

        // Arbitrary bytes where a record should be: an error for that one
        // record, never a panic, and the others are still listed.
        let other = Username::parse("zzdamaged").expect("name");
        std::fs::write(cfg.tenants_dir().join("zzdamaged.json"), &garbage).expect("write");
        let loaded = store.load_tenant(&other);
        let listed = store.list_tenants().expect("listing survives a damaged record");
        prop_assert!(listed.contains(&t));
        if loaded.is_err() {
            prop_assert_eq!(listed.len(), 1);
        }
    }

    /// A record whose *content* is hostile cannot be saved under a name that
    /// leaves the state directory.
    #[test]
    fn a_record_cannot_be_saved_outside_the_state_directory(evil in any_text()) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = Config::default();
        cfg.state_dir = dir.path().join("state");
        let store = Store::new(&cfg);
        store.init().expect("init");
        let mut t = tenant_record(&Username::parse("alice").expect("name"), Path::new("/home/alice"));
        t.username.clone_from(&evil);
        let _ = store.save_tenant(&t);
        let v = VHostRecord {
            version: RECORD_VERSION, domain: evil.clone(), tenant: "alice".into(),
            document_root: "public_html".into(), aliases: vec![],
            config_path: PathBuf::from("/x"), created_at_unix: 0, php: false, app: None,
            redirect_https: false, hsts: false, tls: None,
            auto_https: oxpanel_daemon::records::AutoHttpsChoice::On,
        };
        let _ = store.save_vhost(&v);
        // Everything that exists is inside the two record directories.
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir.path()).expect("readdir").flatten() {
            found.push(entry.file_name().to_string_lossy().into_owned());
        }
        prop_assert_eq!(found, vec!["state".to_owned()]);
        for sub in [cfg.tenants_dir(), cfg.vhosts_dir()] {
            for entry in std::fs::read_dir(&sub).expect("readdir").flatten() {
                prop_assert!(entry.file_type().expect("type").is_file());
                let n = entry.file_name().to_string_lossy().into_owned();
                prop_assert!(n.ends_with(".json") && !n.contains('/'));
            }
        }
    }
}

// ---------------------------------------------------------------- the rest

const CONFIG_KEYS: &[&str] = &[
    "OXPANEL_SOCKET_PATH",
    "OXPANEL_HOME_BASE",
    "OXPANEL_STATE_DIR",
    "OXPANEL_NGINX_CONF_DIR",
    "OXPANEL_NGINX_INCLUDE_FILE",
    "OXPANEL_SYSTEMD_UNIT_DIR",
    "OXPANEL_NGINX_LOG_DIR",
    "OXPANEL_PHP_CONF_DIR",
    "OXPANEL_SOCKET_GROUP",
    "OXPANEL_ALLOWED_UIDS",
    "OXPANEL_ALLOWED_GIDS",
    "OXPANEL_ALLOW_ROOT_PEER",
    "OXPANEL_PEER_SCOPES",
    "OXPANEL_UID_MIN",
    "OXPANEL_UID_MAX",
    "OXPANEL_WEB_USER",
    "OXPANEL_NGINX_DEFAULT_SERVER",
    "OXPANEL_COMMAND_TIMEOUT_SECS",
    "OXPANEL_DRY_RUN",
    "OXPANEL_LOG",
];

fn config_value() -> impl Strategy<Value = String> {
    prop_oneof![
        any_text(),
        "/[a-zA-Z0-9._/-]{0,40}",
        "/[a-z]{1,8}(/(\\.\\.|\\.|[a-z ;$]{1,8})){0,4}",
        "[0-9]{1,12}",
        "[0-9]{1,6}(,[0-9]{1,6}){0,4}",
        "[0-9]{1,6}:(read|vhost|tenant|delete|all|x)(\\+(read|vhost|tenant|delete)){0,3}(,[0-9]{1,5}:[a-z+]{0,12}){0,2}",
        "(true|false|yes|no|1|0|on|off|TRUE|)",
        "[a-z_-]{0,12}",
    ]
}

proptest! {
    /// The environment file is operator input: any content either is refused
    /// with a message or yields a configuration that is safe to use.
    #[test]
    fn any_environment_gives_a_safe_configuration_or_an_error(
        env in proptest::collection::btree_map(proptest::sample::select(CONFIG_KEYS), config_value(), 0..8)
    ) {
        match Config::from_lookup(|k| env.get(k).cloned()) {
            Err(e) => {
                let invalid = matches!(e, Error::InvalidInput { .. });
                prop_assert!(invalid, "{}", e);
            }
            Ok(c) => {
                for p in [&c.socket_path, &c.home_base, &c.state_dir, &c.nginx_conf_dir, &c.nginx_include_file,
                          &c.systemd_unit_dir, &c.nginx_log_dir, &c.php_conf_dir] {
                    let s = p.to_str().unwrap_or("\n");
                    prop_assert!(p.is_absolute() && s != "/");
                    prop_assert!(s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-')), "{:?}", p);
                    prop_assert!(p.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_))), "{:?}", p);
                }
                prop_assert!(c.uid_min >= 1000 && c.uid_max >= c.uid_min && c.uid_max < u32::MAX);
                prop_assert!(!c.web_user.is_empty());
                prop_assert!(c.web_user.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
                prop_assert!(c.command_timeout >= Duration::from_secs(1));
                prop_assert!(c.peer_scopes.values().all(|s| !s.is_empty()), "a confined peer with no scope at all would be a silent lock-out");
                // Everything rendered from this configuration renders.
                prop_assert!(nginx::render_include(&c.nginx_conf_dir, c.nginx_default_server).is_ok());
            }
        }
    }

    /// Internal faults carry paths, command output and OS error text. None of
    /// it may reach the client.
    #[test]
    fn internal_error_detail_never_reaches_the_client(secret in "[A-Za-z0-9/_.-]{6,40}") {
        let marker = format!("SECRET-{secret}");
        let internal = [
            Error::Internal(marker.clone()),
            Error::CommandFailed { program: "/usr/sbin/useradd".into(), status: "status 1".into(), stderr: marker.clone() },
            Error::CommandTimeout { program: marker.clone(), secs: 1 },
            Error::io("open", PathBuf::from(&marker), std::io::Error::other(marker.clone())),
            Error::CorruptRecord { path: PathBuf::from(&marker), reason: marker.clone() },
        ];
        for e in internal {
            let status = tonic::Status::from(e);
            prop_assert!(!status.message().contains(&secret), "{}", status.message());
            let redacted = matches!(status.code(), tonic::Code::Internal | tonic::Code::DeadlineExceeded);
            prop_assert!(redacted);
        }
    }

    /// Tenant commands: whatever the arguments, the privilege drop comes
    /// first and the arguments cannot alter it.
    #[test]
    fn a_tenant_command_always_drops_privileges_first(
        args in proptest::collection::vec(any_text(), 0..6), uid in 1000u32.., gid in 1000u32..,
    ) {
        let spec = CommandSpec::new(bin::MKDIR, Duration::from_secs(1)).args(&args).as_user(uid, gid);
        let (program, argv) = spec.exec_plan();
        prop_assert_eq!(program, bin::SETPRIV);
        let argv: Vec<String> = argv.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        let head = [
            format!("--reuid={uid}"), format!("--regid={gid}"), "--clear-groups".to_owned(),
            "--bounding-set=-all".to_owned(), "--inh-caps=-all".to_owned(), "--no-new-privs".to_owned(),
            "--".to_owned(), bin::MKDIR.to_owned(),
        ];
        prop_assert_eq!(&argv[..head.len()], &head[..]);
        prop_assert_eq!(argv.len(), head.len() + args.len());
        let root_plan = CommandSpec::new(bin::MKDIR, Duration::from_secs(1)).args(&args).exec_plan();
        prop_assert_eq!(root_plan.0, bin::MKDIR);
        prop_assert_eq!(root_plan.1.len(), args.len());
    }

    #[test]
    fn a_peer_outside_every_list_is_never_allowed(
        uids in proptest::collection::btree_set(1u32..5000, 0..6),
        gids in proptest::collection::btree_set(1u32..5000, 0..6),
        allow_root in any::<bool>(),
        uid in 0u32..6000, gid in 0u32..6000,
        groups in proptest::collection::vec(0u32..6000, 0..6),
    ) {
        let policy = PeerPolicy::new(uids.clone(), gids.clone(), allow_root);
        let peer = PeerInfo { uid, gid, pid: None };
        let expected = (allow_root && uid == 0) || uids.contains(&uid) || gids.contains(&gid)
            || groups.iter().any(|g| gids.contains(g));
        prop_assert_eq!(policy.is_allowed(&peer, &groups), expected);
    }

    #[test]
    fn a_confined_peer_holds_exactly_its_scopes(
        confined in proptest::collection::btree_map(1u32..50, proptest::collection::btree_set(0..4usize, 0..4), 0..6),
        uid in 0u32..60,
    ) {
        let table: BTreeMap<u32, BTreeSet<Scope>> = confined
            .iter()
            .map(|(u, s)| (*u, s.iter().map(|i| Scope::ALL[*i]).collect()))
            .collect();
        let policy = ScopePolicy::new(table.clone());
        let peer = PeerInfo { uid, gid: uid, pid: None };
        for scope in Scope::ALL {
            let expected = table.get(&uid).is_none_or(|s| s.contains(&scope));
            prop_assert_eq!(policy.permits(&peer, scope), expected);
        }
    }

    /// The file manager's paths: whatever is accepted is relative, has no
    /// `.` or `..` component, is bounded, and joined to a home stays
    /// below it with one component per name (nothing collapses away).
    #[test]
    fn an_accepted_file_path_stays_below_the_home(s in near_file_path()) {
        match FilePath::parse(&s, "path") {
            Ok(p) if p.is_home() => prop_assert!(s.is_empty() || s == "."),
            Ok(p) => {
                prop_assert_eq!(p.as_str(), s.as_str());
                prop_assert!(s.len() <= FILE_PATH_MAX);
                prop_assert!(!s.starts_with('/') && !s.ends_with('/') && !s.contains("//"));
                prop_assert!(!s.contains(' '));
                let comps: Vec<&str> = s.split('/').collect();
                prop_assert!(comps.len() <= FILE_PATH_DEPTH_MAX);
                for comp in &comps {
                    prop_assert!(*comp != "." && *comp != ".." && comp.len() <= FILE_NAME_MAX);
                }
                let home = Path::new("/home/alice");
                let abs = home.join(p.as_str());
                prop_assert!(abs.starts_with(home));
                prop_assert!(abs.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_))));
                prop_assert_eq!(abs.components().count(), 3 + comps.len());
                // Its parent and name put it back together.
                match p.file_name() {
                    Some(name) => prop_assert_eq!(p.parent().join(name, "path").ok(), Some(p.clone())),
                    None => prop_assert!(false, "a non-home path has a name"),
                }
                // And it survives JSON (the worker's protocol) unchanged.
                let json = serde_json::to_string(&p).map_err(|e| TestCaseError::fail(e.to_string()))?;
                let back: FilePath = serde_json::from_str(&json).map_err(|e| TestCaseError::fail(e.to_string()))?;
                prop_assert_eq!(back, p);
            }
            Err(e) => {
                let invalid = matches!(e, Error::InvalidInput { .. });
                prop_assert!(invalid);
            }
        }
    }

    /// A name the engine creates is visible text: no control character,
    /// no separator, not `.`/`..`, no space at either end.
    #[test]
    fn an_accepted_new_name_is_visible_text(s in near_file_path()) {
        if check_new_name(&s, "name").is_ok() {
            prop_assert!(!s.is_empty() && s.len() <= FILE_NAME_MAX);
            prop_assert!(!s.contains('/') && s != "." && s != "..");
            prop_assert!(!s.chars().any(char::is_control));
            prop_assert!(!s.starts_with(' ') && !s.ends_with(' '));
            prop_assert!(s.chars().all(|c| c == ' ' || !c.is_whitespace()));
            let as_path = FilePath::parse_new(&s, "path");
            prop_assert!(as_path.is_ok());
        }
    }

    /// Modes never carry set-uid, set-gid, sticky or world-write.
    #[test]
    fn an_accepted_file_mode_is_safe(m in any::<u32>()) {
        if let Ok(mode) = FileMode::parse(m, "mode") {
            prop_assert_eq!(mode.bits(), m);
            prop_assert_eq!(m & !0o775, 0);
        }
    }
}

/// Paths a hostile panel would send to the file manager.
fn near_file_path() -> impl Strategy<Value = String> {
    prop_oneof![
        "[A-Za-z0-9 ._-]{1,12}(/[A-Za-z0-9 ._-]{1,12}){0,5}",
        r"(\.\./|\./|/)?[a-z.]{1,8}(/(\.\.|\.|[a-z]{1,6}|)){0,4}/?",
        "[a-z]{1,4}[\n\t\r\0\u{1b}\u{202e}\u{200b} /][a-z]{1,4}",
        "-[a-z-]{1,10}",
        "(a/){60,70}a",
        "[a-z]{250,260}",
        any_text(),
    ]
}
