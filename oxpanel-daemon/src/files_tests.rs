//! Tests of the file manager.
//!
//! The worker's tests run it in this process, on real directories, as the
//! test's own user (root in the build container: so they prove what
//! confined resolution and our own checks stop — the kernel's permission
//! checks against the *tenant* are proven by `make integration` and the
//! acceptance VM, where the worker really runs as a tenant). The service's
//! tests run against the fake OS and assert the exact commands.

use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::files::{self, FileService, JobRequest, JOB_RESULT};
use crate::files_tree::Notes;
use crate::files_worker::{
    self, handle, ArchiveFormat, Fault, JobSummary, Kind, Limits, LinkState, ModeChange, Op,
    Refusal, Reply, Request, Res,
};
use crate::records::{FileJobKind, JobState};
use crate::system::{bin, CommandSpec, FakeSystem};
use crate::tenant::TenantService;
use crate::validate::{FilePath, Limits as TenantLimits};
use crate::vhost::{VHostRequest, VHostService};

fn p(s: &str) -> FilePath {
    FilePath::parse(s, "path").unwrap_or_else(|e| panic!("{s:?}: {e}"))
}

/// A home in a temporary directory, with a document root (protected) and
/// a "secret" outside it.
struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    outside: PathBuf,
    limits: Limits,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let home = dir.path().join("home");
        let outside = dir.path().join("outside");
        for d in [&home, &home.join("public_html"), &outside] {
            std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("{e}"));
        }
        std::fs::write(outside.join("secret"), "other tenant's data")
            .unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(home.join("public_html/index.html"), "hello")
            .unwrap_or_else(|e| panic!("{e}"));
        Self {
            _dir: dir,
            home,
            outside,
            limits: Limits::default(),
        }
    }

    fn request(&self, op: Op) -> Request {
        Request {
            home: self.home.clone(),
            protected: vec![p("public_html")],
            limits: self.limits,
            op,
        }
    }

    fn run(&self, op: Op) -> Res<Reply> {
        handle(&self.request(op), &[]).map(|(r, _)| r)
    }

    fn run_with(&self, op: Op, data: &[u8]) -> Res<(Reply, Vec<u8>)> {
        handle(&self.request(op), data)
    }

    fn job(&self, op: Op) -> (Res<JobSummary>, Notes) {
        let mut notes = Notes::default();
        let r = files::run_job(&self.request(op), &mut notes);
        (r, notes)
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.home.join(rel)
    }

    fn write(&self, rel: &str, content: &[u8]) {
        let path = self.path(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap_or_else(|e| panic!("{e}"));
        }
        std::fs::write(path, content).unwrap_or_else(|e| panic!("{e}"));
    }

    fn symlink(&self, target: impl AsRef<Path>, rel: &str) {
        std::os::unix::fs::symlink(target, self.path(rel)).unwrap_or_else(|e| panic!("{e}"));
    }

    fn read(&self, rel: &str) -> Res<Vec<u8>> {
        self.run_with(
            Op::Read {
                path: p(rel),
                offset: 0,
                length: 1 << 20,
            },
            &[],
        )
        .map(|(_, d)| d)
    }
}

fn fault<T: std::fmt::Debug>(r: Res<T>) -> Fault {
    match r {
        Err(Refusal { fault, .. }) => fault,
        Ok(v) => panic!("expected a refusal, got {v:?}"),
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).map_or_else(
        |e| panic!("{}: {e}", path.display()),
        |m| m.permissions().mode() & 0o7777,
    )
}

// --- confinement -------------------------------------------------------------

#[test]
fn a_symlink_out_of_the_home_is_never_followed() {
    let f = Fixture::new();
    f.symlink(f.outside.join("secret"), "abs");
    f.symlink("../outside/secret", "rel");
    f.symlink("public_html/../../outside", "dir");
    f.symlink("/etc/passwd", "passwd");
    for link in ["abs", "rel", "passwd"] {
        assert_eq!(fault(f.read(link)), Fault::OutsideHome, "{link}");
    }
    // Through a directory link, too, and for every kind of operation.
    assert_eq!(fault(f.read("dir/secret")), Fault::OutsideHome);
    assert_eq!(
        fault(f.run(Op::List {
            path: p("dir"),
            offset: 0,
            limit: 10
        })),
        Fault::OutsideHome
    );
    assert_eq!(
        fault(f.run_with(
            Op::Write {
                path: p("dir/planted"),
                overwrite: true,
                mode: None
            },
            b"x"
        )),
        Fault::OutsideHome
    );
    assert!(!f.outside.join("planted").exists());
    assert_eq!(
        fault(f.run(Op::MakeDir {
            path: p("dir/new"),
            parents: true
        })),
        Fault::OutsideHome
    );
    assert!(!f.outside.join("new").exists());
    // The listing shows the links, and says where they lead without following.
    let Ok(Reply::Listing { entries, .. }) = f.run(Op::List {
        path: FilePath::home(),
        offset: 0,
        limit: 100,
    }) else {
        panic!("listing")
    };
    let state = |n: &str| {
        entries
            .iter()
            .find(|e| e.name == n)
            .and_then(|e| e.link.as_ref())
            .map(|l| l.state)
    };
    assert_eq!(state("abs"), Some(LinkState::Outside));
    assert_eq!(state("passwd"), Some(LinkState::Outside));
    assert_eq!(state("dir"), Some(LinkState::Outside));
    // Deleting a link removes the link, never its target.
    let (r, _) = f.job(Op::Delete {
        paths: vec![p("abs"), p("dir")],
    });
    assert!(r.is_ok(), "{r:?}");
    assert!(f.outside.join("secret").exists());
    // The secret was never read.
    assert_eq!(
        std::fs::read_to_string(f.outside.join("secret")).unwrap_or_default(),
        "other tenant's data"
    );
}

#[test]
fn symlinks_inside_the_home_work() {
    let f = Fixture::new();
    f.symlink("public_html/index.html", "page");
    f.symlink("../public_html", "public_html/self-parent");
    assert_eq!(f.read("page").ok(), Some(b"hello".to_vec()));
    assert_eq!(
        f.read("public_html/self-parent/index.html").ok(),
        Some(b"hello".to_vec())
    );
    let Ok(Reply::Entry { entry }) = f.run(Op::Stat { path: p("page") }) else {
        panic!("stat")
    };
    assert_eq!(entry.kind, Kind::Symlink);
    assert_eq!(
        entry.link.map(|l| (l.target, l.state)),
        Some((
            "public_html/index.html".to_owned(),
            LinkState::Inside(Kind::File)
        ))
    );
    f.symlink("nothing-there", "dangling");
    let Ok(Reply::Entry { entry }) = f.run(Op::Stat {
        path: p("dangling"),
    }) else {
        panic!("stat")
    };
    assert_eq!(entry.link.map(|l| l.state), Some(LinkState::Broken));
}

#[test]
fn traversal_never_parses_and_a_request_with_it_is_refused_whole() {
    for bad in ["../x", "/etc/passwd", "a/../../b", "a//b", "./a"] {
        let line = format!(
            "{{\"home\":\"/home/a\",\"protected\":[],\"limits\":{},\"op\":{{\"op\":\"stat\",\"path\":{}}}}}\n",
            serde_json::to_string(&Limits::default()).unwrap_or_default(),
            serde_json::to_string(bad).unwrap_or_default()
        );
        let mut out = Vec::new();
        assert_eq!(
            files_worker::serve(&mut line.as_bytes(), &mut out),
            64,
            "{bad}"
        );
        assert!(out.is_empty());
    }
    // In the protected list and every other field likewise.
    let line = "{\"home\":\"/h\",\"protected\":[\"../x\"],\"limits\":{},\"op\":{\"op\":\"stat\",\"path\":\"\"}}\n";
    assert!(files_worker::read_request(&mut line.as_bytes()).is_err());
}

#[test]
fn fifos_and_special_files_are_never_opened() {
    let f = Fixture::new();
    nix::unistd::mkfifo(
        &f.path("pipe"),
        nix::sys::stat::Mode::from_bits_truncate(0o644),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    // Would block forever if it were opened for reading without O_NONBLOCK.
    assert_eq!(fault(f.read("pipe")), Fault::NotRegular);
    assert_eq!(
        fault(f.run(Op::Chmod {
            path: p("pipe"),
            change: ModeChange::Private
        })),
        Fault::NotRegular
    );
    f.symlink("pipe", "to-pipe");
    assert_eq!(fault(f.read("to-pipe")), Fault::NotRegular);
    // Copy and compress leave it out; delete removes it.
    let (r, notes) = f.job(Op::Copy {
        sources: vec![p("pipe")],
        destination: p("public_html"),
        overwrite: false,
    });
    assert!(r.is_ok() && notes.skipped == 1, "{r:?}");
    let (r, _) = f.job(Op::Delete {
        paths: vec![p("pipe")],
    });
    assert!(r.is_ok());
    assert!(!f.path("pipe").exists());
}

#[test]
fn names_with_dashes_newlines_and_unicode_are_just_names() {
    let f = Fixture::new();
    for name in ["-rf", "--help", "日本語 file.txt"] {
        let r = f.run_with(
            Op::Write {
                path: p(name),
                overwrite: false,
                mode: None,
            },
            b"data",
        );
        assert!(r.is_ok(), "{name}: {r:?}");
        assert_eq!(f.read(name).ok(), Some(b"data".to_vec()));
    }
    // A name with a newline (made over SFTP) can be read, renamed, removed.
    f.write("bad\nname", b"x");
    assert_eq!(f.read("bad\nname").ok(), Some(b"x".to_vec()));
    let r = f.run(Op::Rename {
        from: p("bad\nname"),
        to: p("good name"),
        overwrite: false,
    });
    assert!(r.is_ok(), "{r:?}");
    assert!(f.path("good name").exists());
    // Error messages escape it: no line can be forged.
    let r = f.read("no\nsuch");
    match r {
        Err(Refusal { message, .. }) => assert!(message.contains("no\\nsuch"), "{message}"),
        Ok(_) => panic!("read a missing file"),
    }
}

// --- reading and writing ------------------------------------------------------

#[test]
fn reads_are_bounded_and_ranged() {
    let f = Fixture::new();
    f.write("big", &vec![7u8; 3000]);
    let Ok((
        Reply::Data {
            size, length: len, ..
        },
        data,
    )) = f.run_with(
        Op::Read {
            path: p("big"),
            offset: 1000,
            length: 500,
        },
        &[],
    )
    else {
        panic!("read")
    };
    assert_eq!((size, len, data.len()), (3000, 500, 500));
    let Ok((Reply::Data { length, .. }, _)) = f.run_with(
        Op::Read {
            path: p("big"),
            offset: 2900,
            length: 500,
        },
        &[],
    ) else {
        panic!("read")
    };
    assert_eq!(length, 100, "only what is there");
    assert_eq!(fault(f.read("public_html")), Fault::IsADirectory);
    assert_eq!(fault(f.read("missing")), Fault::NotFound);
}

#[test]
fn writes_are_atomic_and_never_replace_unless_asked() {
    let f = Fixture::new();
    let write = |path: &str, data: &[u8], overwrite| {
        f.run_with(
            Op::Write {
                path: p(path),
                overwrite,
                mode: None,
            },
            data,
        )
    };
    assert!(write("public_html/new.php", b"<?php // v1", false).is_ok());
    assert_eq!(mode(&f.path("public_html/new.php")), 0o644);
    assert_eq!(
        fault(write("public_html/new.php", b"v2", false)),
        Fault::Exists
    );
    std::fs::set_permissions(
        f.path("public_html/new.php"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(write("public_html/new.php", b"<?php // v2", true).is_ok());
    assert_eq!(
        f.read("public_html/new.php").ok(),
        Some(b"<?php // v2".to_vec())
    );
    assert_eq!(
        mode(&f.path("public_html/new.php")),
        0o600,
        "a replaced file keeps its mode"
    );
    assert_eq!(fault(write("public_html", b"x", true)), Fault::IsADirectory);
    assert_eq!(fault(write("missing-dir/x", b"x", false)), Fault::NotFound);
    // A symlink at the target is replaced, never written through.
    f.symlink(f.outside.join("secret"), "public_html/link");
    assert!(write("public_html/link", b"mine", true).is_ok());
    assert_eq!(
        std::fs::read_to_string(f.outside.join("secret")).unwrap_or_default(),
        "other tenant's data"
    );
    assert!(!f.path("public_html/link").is_symlink());
    // No temporary file is left behind.
    let leftovers: Vec<_> = std::fs::read_dir(f.path("public_html"))
        .map(|d| {
            d.filter_map(std::result::Result::ok)
                .filter(|e| e.file_name().to_string_lossy().starts_with(".oxpanel"))
                .collect()
        })
        .unwrap_or_default();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn uploads_grow_in_a_partial_file_and_replace_the_target_when_finished() {
    let f = Fixture::new();
    let partial = ".oxpanel-upload-u1731500000123".to_owned();
    let target = p("public_html/video.bin");
    assert!(f
        .run(Op::UploadStart {
            path: target.clone(),
            partial: partial.clone(),
            overwrite: false
        })
        .is_ok());
    let chunk = |offset, data: &[u8]| {
        f.run_with(
            Op::UploadChunk {
                path: target.clone(),
                partial: partial.clone(),
                offset,
            },
            data,
        )
        .map(|(r, _)| r)
    };
    assert_eq!(chunk(0, b"aaaa").ok(), Some(Reply::Received { bytes: 4 }));
    // The same chunk again (a retry) is fine; a gap is not.
    assert_eq!(chunk(0, b"AAAA").ok(), Some(Reply::Received { bytes: 4 }));
    assert_eq!(fault(chunk(10, b"x")), Fault::Invalid);
    assert_eq!(chunk(4, b"bb").ok(), Some(Reply::Received { bytes: 6 }));
    assert!(
        !f.path("public_html/video.bin").exists(),
        "not before it is finished"
    );
    let finish = |size, sha256: Option<&str>| {
        f.run(Op::UploadFinish {
            path: target.clone(),
            partial: partial.clone(),
            size,
            sha256: sha256.map(str::to_owned),
            overwrite: false,
        })
    };
    assert_eq!(
        fault(finish(7, None)),
        Fault::Invalid,
        "a short upload stays open"
    );
    let sha = "62a0c7e4efe3c3f1f6a8b6e9f5c44e1e74bd0e0b0f6c3e86c09c5a1b3a8ea0f8";
    assert_eq!(fault(finish(6, Some(sha))), Fault::Invalid);
    assert!(
        !f.path("public_html").join(&partial).exists(),
        "a corrupted upload is discarded"
    );

    // Again, properly, with its checksum.
    assert!(f
        .run(Op::UploadStart {
            path: target.clone(),
            partial: partial.clone(),
            overwrite: false
        })
        .is_ok());
    assert!(chunk(0, b"AAAAbb").is_ok());
    let good = "ae0d1c0a07f78aac9de7d4c6b0a1ec5b4f1f9d4a4aa3a1e75bb0d5d58c4a76c3";
    let real = {
        use sha2::Digest;
        format!("{:x}", sha2::Sha256::digest(b"AAAAbb"))
    };
    assert_ne!(good, real);
    let r = finish(6, Some(&real));
    assert!(matches!(r, Ok(Reply::Entry { .. })), "{r:?}");
    assert_eq!(
        std::fs::read(f.path("public_html/video.bin")).unwrap_or_default(),
        b"AAAAbb"
    );
    assert!(!f.path("public_html").join(&partial).exists());
    // Partial names are the daemon's only.
    assert_eq!(
        fault(f.run(Op::UploadStart {
            path: target,
            partial: "../../x".into(),
            overwrite: true
        })),
        Fault::Invalid
    );
}

#[test]
fn an_upload_beyond_its_limit_leaves_nothing_behind() {
    let mut f = Fixture::new();
    f.limits.upload_max_bytes = 8;
    let partial = ".oxpanel-upload-u1731500000999".to_owned();
    let target = p("big.bin");
    assert!(f
        .run(Op::UploadStart {
            path: target.clone(),
            partial: partial.clone(),
            overwrite: false
        })
        .is_ok());
    let r = f.run_with(
        Op::UploadChunk {
            path: target,
            partial: partial.clone(),
            offset: 0,
        },
        b"123456789",
    );
    assert_eq!(fault(r), Fault::TooLarge);
    assert!(!f.path(&partial).exists());
    assert!(!f.path("big.bin").exists());
}

// --- organising -----------------------------------------------------------------

#[test]
fn directories_renames_and_modes() {
    let f = Fixture::new();
    let mk = |path: &str, parents| {
        f.run(Op::MakeDir {
            path: p(path),
            parents,
        })
    };
    assert!(mk("a/b/c", true).is_ok());
    assert_eq!(mode(&f.path("a/b/c")), 0o755);
    assert!(mk("a/b/c", true).is_ok(), "parents: no error if it exists");
    assert_eq!(fault(mk("a/b/c", false)), Fault::Exists);
    assert_eq!(fault(mk("x/y", false)), Fault::NotFound);
    f.write("a/file", b"1");
    f.write("a/other", b"2");
    let mv = |from: &str, to: &str, overwrite| {
        f.run(Op::Rename {
            from: p(from),
            to: p(to),
            overwrite,
        })
    };
    assert_eq!(fault(mv("a/file", "a/other", false)), Fault::Exists);
    assert!(mv("a/file", "a/other", true).is_ok());
    assert_eq!(std::fs::read(f.path("a/other")).unwrap_or_default(), b"1");
    assert!(mv("a/other", "moved", false).is_ok());
    assert_eq!(fault(mv("a", "a/b/c/inside", false)), Fault::Invalid);
    // Access.
    let chmod = |path: &str, change| {
        f.run(Op::Chmod {
            path: p(path),
            change,
        })
    };
    assert!(chmod("moved", ModeChange::Private).is_ok());
    assert_eq!(mode(&f.path("moved")), 0o600);
    assert!(chmod("moved", ModeChange::WebReadable).is_ok());
    assert_eq!(mode(&f.path("moved")), 0o644);
    assert!(chmod("a", ModeChange::Private).is_ok());
    assert_eq!(mode(&f.path("a")), 0o700);
    assert!(chmod("moved", ModeChange::Bits(0o750)).is_ok());
    assert_eq!(mode(&f.path("moved")), 0o750);
    assert!(chmod("moved", ModeChange::WebReadable).is_ok());
    assert_eq!(mode(&f.path("moved")), 0o755, "executable stays executable");
    // Never more than 0775, whatever the worker is told.
    assert!(chmod("moved", ModeChange::Bits(0o6777)).is_ok());
    assert_eq!(mode(&f.path("moved")), 0o775);
    f.symlink("moved", "link");
    assert_eq!(fault(chmod("link", ModeChange::Private)), Fault::NotRegular);
}

#[test]
fn the_engines_directories_cannot_be_removed_moved_or_closed() {
    let f = Fixture::new();
    // Also through an alias: a link to the home itself.
    f.symlink(".", "alias");
    std::fs::create_dir_all(f.path("sites/shop/public")).unwrap_or_else(|e| panic!("{e}"));
    let req = |op| Request {
        protected: vec![p("public_html"), p("sites/shop/public")],
        ..f.request(op)
    };
    let refused = |op: Op| fault(handle(&req(op), &[]));
    for path in [
        "public_html",
        "alias/public_html",
        "sites",
        "sites/shop",
        "sites/shop/public",
    ] {
        assert_eq!(
            refused(Op::Rename {
                from: p(path),
                to: p("elsewhere"),
                overwrite: false
            }),
            Fault::Protected,
            "{path}"
        );
        assert_eq!(
            refused(Op::Chmod {
                path: p(path),
                change: ModeChange::Private
            }),
            Fault::Protected,
            "{path}"
        );
        let mut notes = Notes::default();
        let r = files::run_job(
            &req(Op::Delete {
                paths: vec![p(path)],
            }),
            &mut notes,
        );
        assert_eq!(fault(r), Fault::Protected, "{path}");
    }
    assert_eq!(
        refused(Op::Chmod {
            path: p("alias"),
            change: ModeChange::WebReadable
        }),
        Fault::NotRegular,
        "a link is never followed for a mode change"
    );
    // Moving something over a protected directory is refused too.
    std::fs::create_dir(f.path("empty")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        refused(Op::Rename {
            from: p("empty"),
            to: p("public_html"),
            overwrite: true
        }),
        Fault::Protected
    );
    assert!(f.path("public_html/index.html").exists());
    // What is inside is the tenant's.
    let r = handle(
        &req(Op::Rename {
            from: p("public_html/index.html"),
            to: p("public_html/home.html"),
            overwrite: false,
        }),
        &[],
    );
    assert!(r.is_ok(), "{r:?}");
}

#[test]
fn listings_page_directories_first() {
    let f = Fixture::new();
    for n in ["b", "a", "c"] {
        f.write(n, b"x");
    }
    std::fs::create_dir(f.path("zdir")).unwrap_or_else(|e| panic!("{e}"));
    let page = |offset, limit| match f.run(Op::List {
        path: FilePath::home(),
        offset,
        limit,
    }) {
        Ok(Reply::Listing {
            entries,
            total,
            truncated,
        }) => (
            entries.into_iter().map(|e| e.name).collect::<Vec<_>>(),
            total,
            truncated,
        ),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        page(0, 2),
        (vec!["public_html".into(), "zdir".into()], 5, false)
    );
    assert_eq!(page(2, 10).0, vec!["a", "b", "c"]);
    assert!(page(10, 10).0.is_empty());
    let mut f = f;
    f.limits.list_max_entries = 3;
    let r = f.run(Op::List {
        path: FilePath::home(),
        offset: 0,
        limit: 10,
    });
    assert!(
        matches!(
            r,
            Ok(Reply::Listing {
                total: 3,
                truncated: true,
                ..
            })
        ),
        "{r:?}"
    );
}

#[test]
fn search_and_size_are_bounded_and_do_not_follow_links() {
    let mut f = Fixture::new();
    f.write("public_html/wp-config.php", b"<?php");
    f.write("deep/a/b/Config.yml", b"x");
    f.symlink(&f.outside, "public_html/escape");
    std::fs::write(f.outside.join("config-secret"), "x").unwrap_or_else(|e| panic!("{e}"));
    let found = |f: &Fixture| match f.run(Op::Search {
        path: FilePath::home(),
        needle: "CONFIG".into(),
        max_results: 10,
    }) {
        Ok(Reply::Found {
            matches, truncated, ..
        }) => (
            matches
                .into_iter()
                .filter_map(|m| m.path)
                .collect::<Vec<_>>(),
            truncated,
        ),
        other => panic!("{other:?}"),
    };
    let (mut paths, truncated) = found(&f);
    paths.sort();
    assert_eq!(
        paths,
        vec!["deep/a/b/Config.yml", "public_html/wp-config.php"]
    );
    assert!(!truncated);
    f.limits.walk_max_entries = 2;
    assert!(found(&f).1, "stops at the bound and says so");
    f.limits.walk_max_entries = 1000;
    // A sparse file costs what it occupies.
    let sparse = std::fs::File::create(f.path("sparse")).unwrap_or_else(|e| panic!("{e}"));
    sparse.set_len(1 << 40).unwrap_or_else(|e| panic!("{e}"));
    match f.run(Op::Size {
        path: FilePath::home(),
    }) {
        Ok(Reply::Size {
            allocated,
            apparent,
            truncated,
            ..
        }) => {
            assert!(apparent >= 1 << 40);
            assert!(allocated < 1 << 30, "{allocated}");
            assert!(!truncated);
        }
        other => panic!("{other:?}"),
    }
}

// --- jobs: delete and copy --------------------------------------------------------

#[test]
fn trees_are_deleted_even_where_the_tenant_closed_them() {
    let f = Fixture::new();
    f.write("tree/a/b/c/file", b"1");
    f.write("tree/x", b"2");
    f.symlink(&f.outside, "tree/out");
    for d in ["tree/a/b", "tree/a"] {
        std::fs::set_permissions(f.path(d), std::fs::Permissions::from_mode(0o500))
            .unwrap_or_else(|e| panic!("{e}"));
    }
    let (r, notes) = f.job(Op::Delete {
        paths: vec![p("tree"), p("already-gone")],
    });
    assert!(r.is_ok(), "{r:?} {:?}", notes.lines);
    assert!(!f.path("tree").exists());
    assert!(f.outside.join("secret").exists());
}

#[test]
fn copies_keep_holes_links_and_modes_and_terminate_into_themselves() {
    let f = Fixture::new();
    f.write("src/a.txt", b"alpha");
    std::fs::set_permissions(f.path("src/a.txt"), std::fs::Permissions::from_mode(0o4755))
        .unwrap_or_else(|e| panic!("{e}"));
    f.symlink("a.txt", "src/link");
    let sparse = std::fs::File::create(f.path("src/sparse")).unwrap_or_else(|e| panic!("{e}"));
    sparse.set_len(1 << 32).unwrap_or_else(|e| panic!("{e}"));
    std::fs::create_dir(f.path("dest")).unwrap_or_else(|e| panic!("{e}"));
    let (r, notes) = f.job(Op::Copy {
        sources: vec![p("src")],
        destination: p("dest"),
        overwrite: false,
    });
    assert!(r.is_ok(), "{r:?} {:?}", notes.lines);
    assert_eq!(
        std::fs::read(f.path("dest/src/a.txt")).unwrap_or_default(),
        b"alpha"
    );
    assert_eq!(
        mode(&f.path("dest/src/a.txt")),
        0o755,
        "no set-uid in a copy"
    );
    assert_eq!(
        std::fs::read_link(f.path("dest/src/link")).ok(),
        Some(PathBuf::from("a.txt"))
    );
    let copied = std::fs::metadata(f.path("dest/src/sparse")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(copied.len(), 1 << 32);
    assert!(copied.blocks() < 1024, "the hole stayed a hole");
    // Again without overwrite: everything exists, nothing changes.
    f.write("dest/src/a.txt", b"changed");
    let (r, notes) = f.job(Op::Copy {
        sources: vec![p("src/a.txt")],
        destination: p("dest/src"),
        overwrite: false,
    });
    assert!(r.is_ok() && notes.skipped == 1, "{r:?}");
    assert_eq!(
        std::fs::read(f.path("dest/src/a.txt")).unwrap_or_default(),
        b"changed"
    );
    // Into itself: refused for the directory itself, copied once into a
    // subdirectory of its own without recursing forever.
    let (r, notes) = f.job(Op::Copy {
        sources: vec![p("src")],
        destination: p("src"),
        overwrite: false,
    });
    assert!(r.is_ok() && notes.skipped == 1, "{r:?} {:?}", notes.lines);
    std::fs::create_dir(f.path("src/inner")).unwrap_or_else(|e| panic!("{e}"));
    let (r, notes) = f.job(Op::Copy {
        sources: vec![p("src")],
        destination: p("src/inner"),
        overwrite: false,
    });
    assert!(r.is_ok(), "{r:?} {:?}", notes.lines);
    assert!(f.path("src/inner/src/a.txt").exists());
    assert!(!f.path("src/inner/src/inner").exists());
}

#[test]
fn a_copy_stops_at_its_byte_budget() {
    let mut f = Fixture::new();
    f.limits.job_max_bytes = 1000;
    f.write("big", &vec![1u8; 4000]);
    let (r, _) = f.job(Op::Copy {
        sources: vec![p("big")],
        destination: p("public_html"),
        overwrite: false,
    });
    assert_eq!(fault(r), Fault::TooLarge);
    assert!(!f.path("public_html/big").exists(), "no partial file");
}

// --- archives ---------------------------------------------------------------------

/// A tar with exactly these headers (names and link targets taken verbatim,
/// so `..` and absolute names can be made).
/// name, type, content, link target, mode
type RawEntry<'a> = (&'a str, tar::EntryType, &'a [u8], Option<&'a str>, u32);

fn raw_tar(entries: &[RawEntry<'_>]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, kind, data, link, mode) in entries {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(*kind);
        h.set_size(data.len() as u64);
        h.set_mode(*mode);
        h.set_mtime(1_700_000_000);
        if let Some(gnu) = h.as_gnu_mut() {
            if let Some(slot) = gnu.name.get_mut(..name.len()) {
                slot.copy_from_slice(name.as_bytes());
            }
            if let Some((l, slot)) = link.and_then(|l| Some((l, gnu.linkname.get_mut(..l.len())?)))
            {
                slot.copy_from_slice(l.as_bytes());
            }
        }
        h.set_cksum();
        b.append(&h, *data).unwrap_or_else(|e| panic!("{e}"));
    }
    b.into_inner().unwrap_or_else(|e| panic!("{e}"))
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(data).unwrap_or_else(|e| panic!("{e}"));
    gz.finish().unwrap_or_else(|e| panic!("{e}"))
}

fn extract(f: &Fixture, archive: &str, dest: &str, overwrite: bool) -> (Res<JobSummary>, Notes) {
    std::fs::create_dir_all(f.path(dest)).unwrap_or_else(|e| panic!("{e}"));
    f.job(Op::Extract {
        archive: p(archive),
        destination: p(dest),
        overwrite,
    })
}

#[test]
fn a_hostile_tar_lands_inside_its_destination_or_nowhere() {
    use tar::EntryType as T;
    let f = Fixture::new();
    // Already in the destination: a link out of the home.
    std::fs::create_dir_all(f.path("x")).unwrap_or_else(|e| panic!("{e}"));
    f.symlink(&f.outside, "x/planted");
    let tar = raw_tar(&[
        ("ok/file.txt", T::Regular, b"fine", None, 0o644),
        ("/etc/absolute", T::Regular, b"x", None, 0o644),
        ("../escape", T::Regular, b"x", None, 0o644),
        ("ok/../../escape2", T::Regular, b"x", None, 0o644),
        ("evil", T::Symlink, b"", Some("/etc"), 0o777),
        ("evil/passwd", T::Regular, b"x", None, 0o644),
        ("up", T::Symlink, b"", Some("../../outside"), 0o777),
        ("ok/sibling", T::Symlink, b"", Some("file.txt"), 0o777),
        ("planted/through", T::Regular, b"x", None, 0o644),
        ("hard-out", T::Link, b"", Some("/etc/passwd"), 0o644),
        ("hard-up", T::Link, b"", Some("../outside/secret"), 0o644),
        ("hard-in", T::Link, b"", Some("ok/file.txt"), 0o644),
        ("dev", T::Char, b"", None, 0o666),
        ("fifo", T::Fifo, b"", None, 0o666),
        ("suid", T::Regular, b"#!/bin/sh", None, 0o6777),
        ("ctl\u{1b}[31m", T::Regular, b"x", None, 0o644),
    ]);
    f.write("hostile.tar", &tar);
    let (r, notes) = extract(&f, "hostile.tar", "x", false);
    assert!(r.is_ok(), "{r:?} {:?}", notes.lines);
    let x = |rel: &str| f.path("x").join(rel);
    assert_eq!(std::fs::read(x("ok/file.txt")).unwrap_or_default(), b"fine");
    assert_eq!(std::fs::read(x("hard-in")).unwrap_or_default(), b"fine");
    assert_eq!(
        std::fs::read_link(x("ok/sibling")).ok(),
        Some(PathBuf::from("file.txt"))
    );
    assert_eq!(
        mode(&x("suid")),
        0o755,
        "no set-uid, set-gid or world write"
    );
    for absent in ["up", "hard-out", "hard-up", "dev", "fifo", "ctl\u{1b}[31m"] {
        assert!(x(absent).symlink_metadata().is_err(), "{absent}");
    }
    // "evil/passwd" became a plain directory and file inside the destination.
    assert!(x("evil").is_dir() && !x("evil").is_symlink());
    assert!(
        !f.outside.join("through").exists(),
        "never through a planted link"
    );
    assert!(
        !f.path("escape").exists() && !f.home.parent().is_none_or(|h| h.join("escape").exists())
    );
    assert_eq!(
        std::fs::read_to_string(f.outside.join("secret")).unwrap_or_default(),
        "other tenant's data"
    );
    assert!(notes.skipped >= 10, "{:?}", notes.lines);
}

#[test]
fn zip_bombs_and_huge_entry_counts_are_stopped() {
    let mut f = Fixture::new();
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("bomb", opts)
        .unwrap_or_else(|e| panic!("{e}"));
    let zeros = vec![0u8; 1 << 20];
    for _ in 0..32 {
        zip.write_all(&zeros).unwrap_or_else(|e| panic!("{e}"));
    }
    let bytes = zip.finish().unwrap_or_else(|e| panic!("{e}")).into_inner();
    assert!(bytes.len() < 100_000, "{}", bytes.len());
    f.write("bomb.zip", &bytes);
    let (r, _) = extract(&f, "bomb.zip", "out", false);
    assert_eq!(fault(r), Fault::TooLarge);
    assert!(!f.path("out/bomb").exists(), "no partial file");
    // The same as a tar.gz.
    let tgz = gzip(&raw_tar(&[(
        "bomb",
        tar::EntryType::Regular,
        &vec![0u8; 32 << 20],
        None,
        0o644,
    )]));
    f.write("bomb.tgz", &tgz);
    let (r, _) = extract(&f, "bomb.tgz", "out", false);
    assert_eq!(fault(r), Fault::TooLarge);
    // Too many entries.
    f.limits.extract_max_entries = 3;
    let many = raw_tar(&[
        ("1", tar::EntryType::Regular, b"", None, 0o644),
        ("2", tar::EntryType::Regular, b"", None, 0o644),
        ("3", tar::EntryType::Regular, b"", None, 0o644),
        ("4", tar::EntryType::Regular, b"", None, 0o644),
    ]);
    f.write("many.tar", &many);
    let (r, _) = extract(&f, "many.tar", "out", false);
    assert_eq!(fault(r), Fault::TooLarge);
}

#[test]
fn a_hostile_zip_is_held_to_the_same_rules() {
    let f = Fixture::new();
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, data) in [
        ("good/a.txt", &b"a"[..]),
        ("../zip-escape", b"x"),
        ("/zip-absolute", b"x"),
        ("good/../../zip-escape2", b"x"),
    ] {
        zip.start_file(name, opts).unwrap_or_else(|e| panic!("{e}"));
        zip.write_all(data).unwrap_or_else(|e| panic!("{e}"));
    }
    zip.add_symlink("link-out", "/etc/passwd", opts)
        .unwrap_or_else(|e| panic!("{e}"));
    zip.add_symlink("good/link-in", "a.txt", opts)
        .unwrap_or_else(|e| panic!("{e}"));
    let setuid = zip::write::SimpleFileOptions::default().unix_permissions(0o4777);
    zip.start_file("good/setuid", setuid)
        .unwrap_or_else(|e| panic!("{e}"));
    let bytes = zip.finish().unwrap_or_else(|e| panic!("{e}")).into_inner();
    f.write("hostile.zip", &bytes);
    let (r, notes) = extract(&f, "hostile.zip", "z", false);
    assert!(r.is_ok(), "{r:?} {:?}", notes.lines);
    let z = |rel: &str| f.path("z").join(rel);
    assert_eq!(std::fs::read(z("good/a.txt")).unwrap_or_default(), b"a");
    assert_eq!(
        std::fs::read_link(z("good/link-in")).ok(),
        Some(PathBuf::from("a.txt"))
    );
    assert!(z("link-out").symlink_metadata().is_err());
    assert_eq!(mode(&z("good/setuid")), 0o755);
    for escaped in ["zip-escape", "zip-absolute", "zip-escape2"] {
        assert!(!f.path(escaped).exists(), "{escaped}");
        assert!(!z(escaped).exists(), "{escaped}");
    }
    // Existing files are kept unless asked.
    std::fs::write(z("good/a.txt"), "mine").unwrap_or_else(|e| panic!("{e}"));
    let (r, notes) = extract(&f, "hostile.zip", "z", false);
    assert!(r.is_ok() && notes.skipped >= 1);
    assert_eq!(std::fs::read(z("good/a.txt")).unwrap_or_default(), b"mine");
    let (r, _) = extract(&f, "hostile.zip", "z", true);
    assert!(r.is_ok());
    assert_eq!(std::fs::read(z("good/a.txt")).unwrap_or_default(), b"a");
}

#[test]
fn archives_round_trip_and_never_contain_what_a_link_points_to() {
    for format in [ArchiveFormat::Zip, ArchiveFormat::TarGz] {
        let f = Fixture::new();
        f.write("site/index.php", b"<?php echo 1;");
        f.write("site/css/a.css", b"body{}");
        f.symlink(f.outside.join("secret"), "site/leak");
        let archive = match format {
            ArchiveFormat::Zip => "site.zip",
            ArchiveFormat::TarGz => "site.tar.gz",
        };
        let (r, notes) = f.job(Op::Compress {
            directory: FilePath::home(),
            names: vec!["site".into()],
            archive: p(archive),
            format,
            overwrite: false,
        });
        assert!(r.is_ok(), "{r:?} {:?}", notes.lines);
        assert_eq!(mode(&f.path(archive)), 0o644);
        let content = std::fs::read(f.path(archive)).unwrap_or_default();
        assert!(
            !content.windows(19).any(|w| w == b"other tenant's data"),
            "{format:?}: the target of a link is never archived"
        );
        let (r, notes) = extract(&f, archive, "restored", false);
        assert!(r.is_ok(), "{r:?} {:?}", notes.lines);
        assert_eq!(
            std::fs::read(f.path("restored/site/css/a.css")).unwrap_or_default(),
            b"body{}"
        );
        // The link to outside was archived as a link, and not extracted.
        assert!(f.path("restored/site/leak").symlink_metadata().is_err());
        // An existing archive is not replaced unless asked.
        let (r, _) = f.job(Op::Compress {
            directory: FilePath::home(),
            names: vec!["site".into()],
            archive: p(archive),
            format,
            overwrite: false,
        });
        assert_eq!(fault(r), Fault::Exists);
    }
}

#[test]
fn archive_names_and_links_are_judged_by_their_components() {
    use crate::files_archive::{link_stays_inside, safe_components, sniff, Sniffed};
    assert_eq!(
        safe_components(b"./a/./b/").ok(),
        Some(vec!["a".into(), "b".into()])
    );
    assert_eq!(safe_components(b"./").ok(), Some(vec![]));
    for bad in [&b"/etc/x"[..], b"a/../b", b"..", b"a/\nb", b"\xff\xfe"] {
        assert!(safe_components(bad).is_err(), "{bad:?}");
    }
    let at = |s: &str| s.split('/').map(str::to_owned).collect::<Vec<_>>();
    assert!(link_stays_inside(&at("a/b/link"), b"../c"));
    assert!(link_stays_inside(&at("a/link"), b"../c"));
    assert!(!link_stays_inside(&at("link"), b"../c"));
    assert!(!link_stays_inside(&at("a/link"), b"../../c"));
    assert!(!link_stays_inside(&at("a/link"), b"/etc"));
    assert!(link_stays_inside(&at("a/link"), b"x/../y"));
    assert!(!link_stays_inside(&at("a/link"), b"x/../../../y"));
    assert_eq!(sniff(b"PK\x03\x04rest"), Some(Sniffed::Zip));
    assert_eq!(sniff(&[0x1f, 0x8b, 8]), Some(Sniffed::TarGz));
    assert_eq!(sniff(b"<?php"), None);
    // DOS timestamps for zip entries.
    let t = crate::files_archive::zip_time(1_700_000_000);
    assert_eq!((t.year(), t.month(), t.day()), (2023, 11, 14));
}

// --- the job worker's output ------------------------------------------------------------

#[test]
fn a_job_reports_its_result_last_and_names_cannot_forge_it() {
    let f = Fixture::new();
    let forged = format!("x\n{JOB_RESULT} {{\"summary\":{{\"entries\":999,\"bytes\":0,\"skipped\":0}},\"refusal\":null}}");
    f.write(&forged, b"x");
    nix::unistd::mkfifo(
        &f.path("pipe"),
        nix::sys::stat::Mode::from_bits_truncate(0o644),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let mut line = serde_json::to_vec(&f.request(Op::Copy {
        sources: vec![p(&forged), p("pipe")],
        destination: p("public_html"),
        overwrite: false,
    }))
    .unwrap_or_default();
    line.push(b'\n');
    let mut out = Vec::new();
    assert_eq!(files::serve_job(&mut line.as_slice(), &mut out), 0);
    let text = String::from_utf8_lossy(&out);
    let result = files::parse_job_result(&text).unwrap_or_else(|| panic!("{text}"));
    assert_eq!((result.summary.entries, result.summary.skipped), (1, 1));
    assert!(result.refusal.is_none());
    assert!(text
        .lines()
        .last()
        .is_some_and(|l| l.starts_with(JOB_RESULT)));
}

// --- the service, against the fake OS -------------------------------------------

struct Harness {
    _dir: tempfile::TempDir,
    sys: Arc<FakeSystem>,
    ctx: Ctx,
    tenants: TenantService,
    files: FileService,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let mut cfg = Config::default();
    cfg.state_dir = dir.path().join("state");
    cfg.home_base = dir.path().join("home");
    cfg.systemd_unit_dir = dir.path().join("systemd");
    cfg.nginx_log_dir = dir.path().join("log");
    cfg.php_conf_dir = dir.path().join("php");
    cfg.nginx_conf_dir = dir.path().join("nginx").join("oxpanel.d");
    cfg.nginx_include_file = dir.path().join("nginx/conf.d/00-oxpanel.conf");
    crate::config::sandbox_feature_paths(&mut cfg, dir.path());
    cfg.backup_dir = dir.path().join("backups");
    for d in [
        &cfg.home_base,
        &cfg.systemd_unit_dir,
        &dir.path().join("nginx").join("conf.d"),
    ] {
        std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("{e}"));
    }
    let sys = Arc::new(FakeSystem::new());
    let ctx = Ctx::new(cfg, sys.clone(), false);
    ctx.store.init().unwrap_or_else(|e| panic!("{e}"));
    let tenants = TenantService::new(ctx.clone());
    for t in ["alice", "bob"] {
        tenants
            .create(t, TenantLimits::default(), "")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }
    VHostService::new(ctx.clone())
        .configure(VHostRequest {
            domain: "example.com".into(),
            tenant: "alice".into(),
            ..VHostRequest::default()
        })
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    sys.clear_calls();
    Harness {
        _dir: dir,
        files: FileService::new(ctx.clone()).with_poll_interval(Duration::from_secs(3600)),
        sys,
        ctx,
        tenants,
    }
}

fn strings(c: &CommandSpec) -> Vec<String> {
    c.args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

impl Harness {
    fn home(&self, t: &str) -> PathBuf {
        self.ctx.config.home_base.join(t)
    }
}

#[tokio::test]
async fn every_operation_runs_as_the_tenant_in_its_slice() -> Result<()> {
    let h = harness().await;
    let alice = h
        .ctx
        .store
        .load_tenant(&crate::validate::Username::parse("alice")?)?
        .unwrap_or_else(|| panic!("alice"));
    h.files
        .write(
            "alice",
            "public_html/x.php",
            b"<?php $db_password = 'hunter2';",
            false,
        )
        .await?;
    let calls = h.sys.calls_to(bin::SYSTEMD_RUN);
    let [call] = calls.as_slice() else {
        panic!("{calls:?}")
    };
    let exe = h.ctx.config.worker_exe.display().to_string();
    assert_eq!(
        strings(call),
        vec![
            "--quiet".to_owned(),
            "--scope".into(),
            "--collect".into(),
            format!("--slice={}", alice.slice_unit),
            "--property=MemoryMax=256M".into(),
            "--property=TasksMax=8".into(),
            "--".into(),
            bin::SETPRIV.into(),
            format!("--reuid={}", alice.uid),
            format!("--regid={}", alice.gid),
            "--clear-groups".into(),
            "--bounding-set=-all".into(),
            "--inh-caps=-all".into(),
            "--no-new-privs".into(),
            "--".into(),
            exe,
            "files".into(),
        ]
    );
    assert!(
        call.run_as.is_none(),
        "systemd-run itself is root; setpriv drops"
    );
    // The content is on standard input, marked secret: never printed.
    assert!(call.secret_input);
    assert!(!format!("{call:?}").contains("hunter2"));
    assert!(!call.display().contains("hunter2"));
    let input = String::from_utf8_lossy(call.stdin.as_deref().unwrap_or_default()).into_owned();
    let (req, data) =
        files_worker::read_request(&mut input.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(req.home, h.home("alice"));
    assert_eq!(req.protected, vec![p("public_html")]);
    assert_eq!(data, b"<?php $db_password = 'hunter2';");
    assert_eq!(
        std::fs::read(h.home("alice").join("public_html/x.php")).unwrap_or_default(),
        data
    );
    Ok(())
}

#[tokio::test]
async fn scopes_of_access_suspension_and_validation() -> Result<()> {
    let h = harness().await;
    // Validation before anything runs.
    for bad in ["../bob", "/etc/passwd", "public_html/../../bob"] {
        assert!(matches!(
            h.files.stat("alice", bad).await,
            Err(Error::InvalidInput { .. })
        ));
        assert!(matches!(
            h.files.read("alice", bad, 0, 0).await,
            Err(Error::InvalidInput { .. })
        ));
    }
    assert!(matches!(
        h.files
            .write("alice", "public_html/a\nb", b"x", false)
            .await,
        Err(Error::InvalidInput { .. })
    ));
    assert!(matches!(
        h.files
            .write("alice", "x", &vec![0u8; files::WRITE_MAX + 1], false)
            .await,
        Err(Error::InvalidInput { .. })
    ));
    assert!(matches!(
        h.files
            .read(
                "alice",
                "x",
                0,
                u32::try_from(files::READ_MAX + 1).unwrap_or(u32::MAX)
            )
            .await,
        Err(Error::InvalidInput { .. })
    ));
    assert!(matches!(
        h.files.chmod("alice", "x", ModeChange::Bits(0o4755)).await,
        Err(Error::InvalidInput { .. })
    ));
    assert!(h.sys.calls_to(bin::SYSTEMD_RUN).is_empty(), "nothing ran");
    // Suspended: read-only.
    h.files
        .write("alice", "public_html/keep.txt", b"k", false)
        .await?;
    h.tenants.set_suspended("alice", true).await?;
    assert!(h
        .files
        .read("alice", "public_html/keep.txt", 0, 0)
        .await
        .is_ok());
    assert!(h.files.list("alice", "", 0, 0).await.is_ok());
    for refused in [
        h.files
            .write("alice", "public_html/new.txt", b"x", false)
            .await
            .err(),
        h.files.make_dir("alice", "d", false).await.err(),
        h.files
            .rename("alice", "public_html/keep.txt", "k2", false)
            .await
            .err(),
        h.files.start_upload("alice", "u.bin", false).await.err(),
        h.files
            .start_job(
                "alice",
                JobRequest::delete(&["public_html/keep.txt".into()])?,
            )
            .await
            .err(),
    ] {
        assert!(
            matches!(refused, Some(Error::TenantSuspended(_))),
            "{refused:?}"
        );
    }
    h.tenants.set_suspended("alice", false).await?;
    assert!(h
        .files
        .write("alice", "public_html/new.txt", b"x", false)
        .await
        .is_ok());
    Ok(())
}

#[tokio::test]
async fn one_tenant_cannot_reach_anothers_upload_or_job() -> Result<()> {
    let h = harness().await;
    let up = h
        .files
        .start_upload("alice", "public_html/big.bin", false)
        .await?;
    assert!(matches!(
        h.files.upload_chunk("bob", &up.id, 0, b"x").await,
        Err(Error::UploadNotFound(_))
    ));
    assert!(!h.files.abort_upload("bob", &up.id).await?);
    assert_eq!(h.files.upload_chunk("alice", &up.id, 0, b"abc").await?, 3);
    let entry = h.files.finish_upload("alice", &up.id, 3, "").await?;
    assert_eq!(entry.size, 3);
    assert!(h.ctx.store.list_uploads()?.is_empty());
    let job = h
        .files
        .start_job(
            "alice",
            JobRequest::delete(&["public_html/big.bin".into()])?,
        )
        .await?;
    assert!(matches!(
        h.files.job("bob", &job.id).await,
        Err(Error::JobNotFound(_))
    ));
    assert!(h.files.jobs("bob").await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_job_runs_sandboxed_as_the_tenant_and_comes_back_finished() -> Result<()> {
    let h = harness().await;
    h.files
        .write("alice", "public_html/a.txt", b"a", false)
        .await?;
    h.sys.clear_calls();
    let job = h
        .files
        .start_job(
            "alice",
            JobRequest::copy(&["public_html/a.txt".into()], "", false)?,
        )
        .await?;
    assert_eq!(job.state, JobState::Succeeded, "{job:?}");
    assert_eq!((job.kind, job.entries), (FileJobKind::Copy, 1));
    assert_eq!(job.message, "1 entries copied (1 bytes)");
    assert!(h.home("alice").join("a.txt").exists());
    let alice = h
        .ctx
        .store
        .load_tenant(&crate::validate::Username::parse("alice")?)?
        .unwrap_or_else(|| panic!("alice"));
    let starts: Vec<Vec<String>> = h
        .sys
        .calls_to(bin::SYSTEMD_RUN)
        .iter()
        .map(strings)
        .filter(|a| a.iter().any(|x| x == "files-job"))
        .collect();
    let [args] = starts.as_slice() else {
        panic!("{starts:?}")
    };
    let id = crate::validate::FileJobId::parse(&job.id)?;
    let request = h.ctx.store.file_job_request_path(&id);
    let prop = |p: &str| args.iter().any(|a| a == p);
    assert!(args.starts_with(&[
        "--quiet".to_owned(),
        format!("--unit=oxpanel-files-{}", job.id),
        format!("--uid={}", alice.uid),
        format!("--gid={}", alice.gid),
    ]));
    for wanted in [
        format!("Slice={}", alice.slice_unit),
        format!("StandardInput=file:{}", request.display()),
        format!("ReadWritePaths={}", h.home("alice").display()),
        "CapabilityBoundingSet=".to_owned(),
        "NoNewPrivileges=yes".into(),
        "ProtectSystem=strict".into(),
        "PrivateNetwork=yes".into(),
        "PrivateDevices=yes".into(),
        "RestrictSUIDSGID=yes".into(),
        "RemainAfterExit=yes".into(),
        "RuntimeMaxSec=7200".into(),
    ] {
        assert!(prop(&wanted), "{wanted} missing from {args:?}");
    }
    assert!(args.ends_with(&[
        "--".to_owned(),
        h.ctx.config.worker_exe.display().to_string(),
        "files-job".into()
    ]));
    assert!(!request.exists(), "the request goes with the job");
    // One job per tenant: a second while one runs is refused.
    let running = "LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nExecMainStatus=0\n";
    for _ in 0..40 {
        h.sys.script_stdout(bin::SYSTEMCTL, running);
    }
    let first = h
        .files
        .start_job("alice", JobRequest::delete(&["a.txt".into()])?)
        .await?;
    assert_eq!(first.state, JobState::Running);
    assert!(matches!(
        h.files
            .start_job("alice", JobRequest::delete(&["a.txt".into()])?)
            .await,
        Err(Error::FileJobRunning { .. })
    ));
    // A tenant with a running job cannot be deleted; suspension stops it.
    let bobs = h
        .files
        .start_job("bob", JobRequest::delete(&["nothing".into()])?)
        .await?;
    assert_eq!(bobs.state, JobState::Running);
    assert!(matches!(
        h.tenants.delete("bob", true).await,
        Err(Error::FileJobRunning { .. })
    ));
    h.tenants.set_suspended("alice", true).await?;
    let stopped = h.files.job("alice", &first.id).await?;
    assert_eq!(stopped.state, JobState::Failed);
    assert!(stopped.message.contains("suspended"), "{}", stopped.message);
    Ok(())
}

#[tokio::test]
async fn a_job_survives_a_restart_of_the_daemon() -> Result<()> {
    let h = harness().await;
    h.files
        .write("alice", "public_html/a.txt", b"a", false)
        .await?;
    let running = "LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nExecMainStatus=0\n";
    for _ in 0..30 {
        h.sys.script_stdout(bin::SYSTEMCTL, running);
    }
    let job = h
        .files
        .start_job("alice", JobRequest::delete(&["public_html/a.txt".into()])?)
        .await?;
    assert_eq!(job.state, JobState::Running);
    // A new daemon (a new service on the same records) picks it up.
    let again = FileService::new(h.ctx.clone()).with_poll_interval(Duration::from_millis(10));
    while h.sys.calls_to(bin::SYSTEMCTL).len() < 30 {
        let _ = again
            .step(&crate::validate::FileJobId::parse(&job.id)?)
            .await?;
    }
    assert_eq!(again.resume_all().await?, 1);
    for _ in 0..200 {
        if again.job("alice", &job.id).await?.state != JobState::Running {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let done = again.job("alice", &job.id).await?;
    assert_eq!(done.state, JobState::Succeeded, "{done:?}");
    assert!(!h.home("alice").join("public_html/a.txt").exists());
    Ok(())
}

#[tokio::test]
async fn job_requests_are_validated() {
    let many: Vec<String> = (0..=files::SELECTION_MAX)
        .map(|i| format!("f{i}"))
        .collect();
    assert!(JobRequest::delete(&[]).is_err());
    assert!(JobRequest::delete(&many).is_err());
    assert!(
        JobRequest::delete(&[String::new()]).is_err(),
        "never the home"
    );
    assert!(JobRequest::copy(&["..".into()], "", false).is_err());
    assert!(JobRequest::compress("", &["a/b".into()], "x.zip", ArchiveFormat::Zip, false).is_err());
    assert!(JobRequest::compress("", &["..".into()], "x.zip", ArchiveFormat::Zip, false).is_err());
    assert!(JobRequest::compress("", &["a".into()], "x\n.zip", ArchiveFormat::Zip, false).is_err());
    assert!(JobRequest::extract("", "dest", false).is_err());
    assert!(JobRequest::extract("a.zip", "/etc", false).is_err());
    assert!(
        JobRequest::compress("", &["-rf".into()], "-x.zip", ArchiveFormat::TarGz, false).is_ok()
    );
}

#[tokio::test]
async fn deleting_a_tenant_forgets_its_uploads_and_jobs() -> Result<()> {
    let h = harness().await;
    let _ = h.files.start_upload("bob", "x.bin", false).await?;
    let _ = h.files.start_upload("bob", "y.bin", false).await?;
    h.tenants.delete("bob", true).await?;
    assert!(h.ctx.store.list_uploads()?.is_empty());
    Ok(())
}

#[test]
fn file_refusals_map_to_status_codes() {
    use tonic::Code;
    for (f, code) in [
        (Fault::NotFound, Code::NotFound),
        (Fault::Exists, Code::AlreadyExists),
        (Fault::PermissionDenied, Code::PermissionDenied),
        (Fault::QuotaExceeded, Code::ResourceExhausted),
        (Fault::TooLarge, Code::ResourceExhausted),
        (Fault::OutsideHome, Code::FailedPrecondition),
        (Fault::Protected, Code::FailedPrecondition),
        (Fault::Invalid, Code::InvalidArgument),
    ] {
        let s: tonic::Status = Error::FileRefused {
            fault: f,
            message: "'x': m".into(),
        }
        .into();
        assert_eq!(s.code(), code, "{f:?}");
        assert_eq!(s.message(), "'x': m");
    }
    let _ = OsStr::new("");
}
