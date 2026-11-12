//! Nginx virtual-host configuration: rendering and the validate-then-activate
//! lifecycle.
//!
//! The daemon owns exactly one directory (`nginx_conf_dir`, one file per
//! domain) and one include stanza in `conf.d`. It never edits anything else
//! under `/etc/nginx`. Every change is written atomically, checked with
//! `nginx -t`, and rolled back if the check fails, so a bad request can never
//! take the web server down.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tracing::{info, warn};

use crate::error::{Error, Result};
use crate::fsutil;
use crate::system::{bin, CommandSpec, System};
use crate::validate::{Domain, Username};

const HEADER: &str = "# Managed by oxpanel-daemon. Manual edits will be overwritten.\n";
pub const CONF_MODE: u32 = 0o644;
pub const DIR_MODE: u32 = 0o755;

/// `<conf_dir>/<domain>.conf`
pub fn conf_path(conf_dir: &Path, domain: &Domain) -> PathBuf {
    conf_dir.join(format!("{domain}.conf"))
}

/// The stanza dropped into `conf.d` so Nginx picks up our directory.
///
/// With `default_server` set it also installs a catch-all server for the
/// listen addresses we use. Without one, Nginx treats the *first* server block
/// it parses as the default — which, since `conf.d` is included before the
/// distribution's own server, would make the alphabetically first tenant the
/// destination for every unknown `Host` header and bare-IP request.
pub fn render_include(conf_dir: &Path, default_server: bool) -> Result<String> {
    let dir = safe_path_str(conf_dir)?;
    let mut s = format!("{HEADER}include {dir}/*.conf;\n");
    if default_server {
        s.push_str(
            "
# Catch-all for host names no tenant owns: close the connection without a response.
# (No server_name: the empty default avoids a conflict with the distribution's catch-all.)
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_tokens off;
    return 444;
}
",
        );
    }
    Ok(s)
}

/// What goes into one server block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerBlock<'a> {
    pub domain: &'a Domain,
    pub aliases: &'a [Domain],
    pub tenant: &'a Username,
    /// Absolute document root.
    pub document_root: &'a Path,
    /// The owning tenant is suspended: answer every request with 503.
    pub suspended: bool,
    /// Absolute paths of this virtual host's own logs.
    pub access_log: &'a Path,
    pub error_log: &'a Path,
    /// Socket of the tenant's PHP-FPM instance; `None` = static files only.
    pub php_socket: Option<&'a Path>,
}

/// Render a complete, self-contained server block.
pub fn render_server_block(b: &ServerBlock<'_>) -> Result<String> {
    let root = safe_path_str(b.document_root)?;
    let access_log = safe_path_str(b.access_log)?;
    let error_log = safe_path_str(b.error_log)?;
    let mut names = String::from(b.domain.as_str());
    for a in b.aliases {
        names.push(' ');
        names.push_str(a.as_str());
    }
    if b.suspended {
        // No `root`: a suspended site serves nothing from the tenant's files.
        return Ok(format!(
            "{HEADER}# tenant: {tenant} (suspended)
server {{
    listen 80;
    listen [::]:80;
    server_name {names};

    access_log {access_log};
    error_log {error_log};
    server_tokens off;

    location / {{
        add_header Retry-After 3600 always;
        return 503;
    }}
}}
",
            tenant = b.tenant,
        ));
    }
    let (index, fallback, php) = match b.php_socket {
        // Without PHP a script must never be handed out as a download:
        // its source routinely holds database passwords.
        None => (
            "index.html index.htm",
            "=404",
            "
    location ~ \\.php$ {
        return 404;
    }
"
            .to_owned(),
        ),
        Some(sock) => (
            "index.php index.html index.htm",
            "/index.php$is_args$args",
            // `try_files` first: never hand FPM a script that does not exist
            // (the classic cgi.fix_pathinfo trap). $realpath_root, so FPM and
            // open_basedir see the same resolved path Nginx checked.
            format!(
                "
    location ~ \\.php$ {{
        try_files $uri =404;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        fastcgi_param DOCUMENT_ROOT $realpath_root;
        fastcgi_hide_header X-Powered-By;
        fastcgi_pass unix:{};
    }}
",
                safe_path_str(sock)?
            ),
        ),
    };
    Ok(format!(
        "{HEADER}# tenant: {tenant}
server {{
    listen 80;
    listen [::]:80;
    server_name {names};

    root {root};
    index {index};

    access_log {access_log};
    error_log {error_log};
    server_tokens off;
    autoindex off;
    # Refuse to serve through symlinks whose target the tenant does not own.
    disable_symlinks if_not_owner;

    # Never serve dot-files (.git, .env, .htaccess, ...).
    location ~ /\\. {{
        deny all;
        return 404;
    }}

    location / {{
        try_files $uri $uri/ {fallback};
    }}
{php}}}
",
        tenant = b.tenant,
    ))
}

/// Paths are interpolated unquoted into Nginx directives, so restrict them to
/// characters that can never terminate or extend a directive.
pub(crate) fn safe_path_str(p: &Path) -> Result<&str> {
    let s = p
        .to_str()
        .ok_or_else(|| Error::Internal(format!("{} is not valid UTF-8", p.display())))?;
    if !p.is_absolute() {
        return Err(Error::Internal(format!("{s} is not absolute")));
    }
    if !s
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(Error::Internal(format!(
            "path {s} contains characters not allowed in nginx configuration"
        )));
    }
    Ok(s)
}

/// Make sure the include stanza is present and current, validating with
/// `nginx -t` and rolling back if the host's configuration rejects it (e.g. an
/// existing `default_server`). Returns whether it changed.
pub async fn ensure_include(
    sys: &dyn System,
    conf_dir: &Path,
    include_file: &Path,
    default_server: bool,
    timeout: Duration,
) -> Result<bool> {
    fsutil::ensure_dir(conf_dir, DIR_MODE)?;
    let contents = render_include(conf_dir, default_server)?;
    let previous = fsutil::read_optional(include_file)?;
    if !fsutil::write_atomic(include_file, contents.as_bytes(), CONF_MODE)? {
        return Ok(false);
    }
    match test_config(sys, timeout).await? {
        Ok(()) => {
            reload(sys, timeout).await?;
            info!(path = %include_file.display(), default_server, "nginx include installed");
            Ok(true)
        }
        Err(output) => {
            warn!(path = %include_file.display(), %output, "nginx rejected include stanza; rolling back");
            rollback(include_file, previous.as_deref())?;
            Err(Error::NginxInvalid(output))
        }
    }
}

/// `nginx -t`. `Ok(Err(output))` means the configuration is invalid.
pub async fn test_config(
    sys: &dyn System,
    timeout: Duration,
) -> Result<std::result::Result<(), String>> {
    let out = sys
        .run(CommandSpec::new(bin::NGINX, timeout).args(["-t", "-q"]))
        .await?;
    Ok(if out.success() {
        Ok(())
    } else {
        Err(out.combined_lossy())
    })
}

/// Activate the on-disk configuration.
pub async fn reload(sys: &dyn System, timeout: Duration) -> Result<()> {
    sys.run_ok(
        CommandSpec::new(bin::SYSTEMCTL, timeout).args(["reload-or-restart", "nginx.service"]),
    )
    .await?;
    Ok(())
}

/// Write `contents` to `path`, validate, activate. On validation failure the
/// previous file (or its absence) is restored and [`Error::NginxInvalid`] is
/// returned. Returns whether anything changed.
pub async fn install_config(
    sys: &dyn System,
    path: &Path,
    contents: &str,
    timeout: Duration,
) -> Result<bool> {
    let previous = fsutil::read_optional(path)?;
    if !fsutil::write_atomic(path, contents.as_bytes(), CONF_MODE)? {
        return Ok(false);
    }
    match test_config(sys, timeout).await? {
        Ok(()) => {
            reload(sys, timeout).await?;
            info!(path = %path.display(), "nginx configuration activated");
            Ok(true)
        }
        Err(output) => {
            warn!(path = %path.display(), %output, "nginx rejected configuration; rolling back");
            rollback(path, previous.as_deref())?;
            Err(Error::NginxInvalid(output))
        }
    }
}

/// Remove `path`, validate, activate. Returns whether the file existed.
pub async fn remove_config(sys: &dyn System, path: &Path, timeout: Duration) -> Result<bool> {
    let previous = fsutil::read_optional(path)?;
    if !fsutil::remove_if_exists(path)? {
        return Ok(false);
    }
    match test_config(sys, timeout).await? {
        Ok(()) => {
            reload(sys, timeout).await?;
            info!(path = %path.display(), "nginx configuration removed");
            Ok(true)
        }
        Err(output) => {
            // Removing one of our files should never break the config; if it
            // does, the rest of the tree is broken and an operator must look.
            warn!(path = %path.display(), %output, "nginx configuration invalid after removal; restoring");
            rollback(path, previous.as_deref())?;
            Err(Error::NginxInvalid(output))
        }
    }
}

pub(crate) fn rollback(path: &Path, previous: Option<&[u8]>) -> Result<()> {
    match previous {
        Some(bytes) => fsutil::write_atomic(path, bytes, CONF_MODE).map(|_| ()),
        None => fsutil::remove_if_exists(path).map(|_| ()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::FakeSystem;

    fn d(s: &str) -> Domain {
        Domain::parse(s).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn renders_server_block_with_aliases_and_hardening() -> Result<()> {
        let alice = Username::parse("alice")?;
        let aliases = [d("www.example.com"), d("example.net")];
        let s = render_server_block(&ServerBlock {
            domain: &d("example.com"),
            aliases: &aliases,
            tenant: &alice,
            document_root: Path::new("/home/alice/public_html"),
            suspended: false,
            access_log: Path::new("/var/log/nginx/oxpanel/example.com.access.log"),
            error_log: Path::new("/var/log/nginx/oxpanel/example.com.error.log"),
            php_socket: None,
        })?;
        assert!(s.starts_with(HEADER));
        assert!(s.contains("server_name example.com www.example.com example.net;\n"));
        assert!(s.contains("root /home/alice/public_html;\n"));
        assert!(s.contains("location ~ /\\. {"));
        assert!(
            s.contains("location ~ \\.php$ {\n        return 404;"),
            "PHP source is never served as a file"
        );
        assert!(!s.contains("fastcgi_pass"));
        assert!(s.contains("server_tokens off;"));
        assert!(s.contains("disable_symlinks if_not_owner;"));
        assert!(!s.contains("autoindex on"));
        Ok(())
    }

    #[test]
    fn refuses_paths_that_could_break_out_of_a_directive() -> Result<()> {
        let alice = Username::parse("alice")?;
        for bad in [
            "/home/alice/pub lic",
            "/home/alice/x;",
            "/home/alice/$x",
            "/home/alice/{",
            "/home/alice/\"",
            "relative/path",
        ] {
            let r = render_server_block(&ServerBlock {
                domain: &d("example.com"),
                aliases: &[],
                tenant: &alice,
                document_root: Path::new(bad),
                suspended: false,
                access_log: Path::new("/var/log/nginx/oxpanel/example.com.access.log"),
                error_log: Path::new("/var/log/nginx/oxpanel/example.com.error.log"),
                php_socket: None,
            });
            assert!(r.is_err(), "{bad}");
        }
        assert!(render_include(Path::new("/etc/nginx/ox panel.d"), false).is_err());
        assert_eq!(
            render_include(Path::new("/etc/nginx/oxpanel.d"), false)?,
            format!("{HEADER}include /etc/nginx/oxpanel.d/*.conf;\n")
        );
        Ok(())
    }

    #[test]
    fn include_can_carry_a_catch_all_default_server() -> Result<()> {
        let with_default = render_include(Path::new("/etc/nginx/oxpanel.d"), true)?;
        assert!(with_default.contains("include /etc/nginx/oxpanel.d/*.conf;\n"));
        assert!(with_default.contains("listen 80 default_server;"));
        assert!(with_default.contains("listen [::]:80 default_server;"));
        assert!(with_default.contains("return 444;"));
        assert!(
            !render_include(Path::new("/etc/nginx/oxpanel.d"), false)?.contains("default_server")
        );
        Ok(())
    }

    #[tokio::test]
    async fn ensure_include_validates_and_rolls_back() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|e| Error::io("tempdir", "/tmp", e))?;
        let sys = FakeSystem::new();
        let t = Duration::from_secs(5);
        let conf_dir = dir.path().join("oxpanel.d");
        let inc = dir.path().join("conf.d").join("00-oxpanel.conf");
        std::fs::create_dir_all(inc.parent().unwrap_or(dir.path()))
            .map_err(|e| Error::io("mkdir", dir.path(), e))?;
        // Host already has a default_server: nginx -t fails, the file must not remain.
        sys.script_failure(
            bin::NGINX,
            1,
            "nginx: [emerg] a duplicate default server for 0.0.0.0:80",
        );
        assert!(matches!(
            ensure_include(&sys, &conf_dir, &inc, true, t).await,
            Err(Error::NginxInvalid(_))
        ));
        assert!(!inc.exists());
        assert!(
            sys.calls_to(bin::SYSTEMCTL).is_empty(),
            "never reload an invalid config"
        );
        // Clean host: installed, tested, reloaded; a second call is a no-op.
        assert!(ensure_include(&sys, &conf_dir, &inc, true, t).await?);
        assert!(inc.is_file());
        assert_eq!(sys.calls_to(bin::SYSTEMCTL).len(), 1);
        assert!(!ensure_include(&sys, &conf_dir, &inc, true, t).await?);
        assert_eq!(sys.calls_to(bin::NGINX).len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn install_validates_then_reloads_and_is_idempotent() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|e| Error::io("tempdir", "/tmp", e))?;
        let sys = FakeSystem::new();
        let t = Duration::from_secs(5);
        let p = dir.path().join("example.com.conf");
        assert!(install_config(&sys, &p, "server {}\n", t).await?);
        let calls = sys.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls.first().map(|c| c.program), Some(bin::NGINX));
        assert_eq!(calls.get(1).map(|c| c.program), Some(bin::SYSTEMCTL));
        assert_eq!(
            calls.get(1).map(|c| c.args.clone()),
            Some(vec!["reload-or-restart".into(), "nginx.service".into()])
        );
        assert!(
            !install_config(&sys, &p, "server {}\n", t).await?,
            "identical content: no-op"
        );
        assert_eq!(sys.calls().len(), 2, "no test/reload for a no-op");
        Ok(())
    }

    #[tokio::test]
    async fn install_rolls_back_on_invalid_config() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|e| Error::io("tempdir", "/tmp", e))?;
        let sys = FakeSystem::new();
        let t = Duration::from_secs(5);
        let p = dir.path().join("example.com.conf");
        // First: a brand-new file that fails validation must disappear again.
        sys.script_failure(bin::NGINX, 1, "nginx: [emerg] unknown directive");
        let r = install_config(&sys, &p, "bogus\n", t).await;
        assert!(matches!(r, Err(Error::NginxInvalid(ref m)) if m.contains("unknown directive")));
        assert!(!p.exists());
        assert!(
            sys.calls_to(bin::SYSTEMCTL).is_empty(),
            "never reload an invalid config"
        );
        // Second: a replacement that fails must restore the previous content.
        assert!(install_config(&sys, &p, "good\n", t).await?);
        sys.script_failure(bin::NGINX, 1, "nginx: [emerg] boom");
        assert!(install_config(&sys, &p, "bad\n", t).await.is_err());
        assert_eq!(fsutil::read_optional(&p)?, Some(b"good\n".to_vec()));
        Ok(())
    }

    #[tokio::test]
    async fn remove_reloads_only_when_something_was_removed() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|e| Error::io("tempdir", "/tmp", e))?;
        let sys = FakeSystem::new();
        let t = Duration::from_secs(5);
        let p = dir.path().join("example.com.conf");
        assert!(!remove_config(&sys, &p, t).await?);
        assert!(sys.calls().is_empty());
        install_config(&sys, &p, "good\n", t).await?;
        assert!(remove_config(&sys, &p, t).await?);
        assert!(!p.exists());
        Ok(())
    }

    #[test]
    fn suspended_block_serves_nothing_from_the_tenant() -> Result<()> {
        let alice = Username::parse("alice")?;
        let aliases = [d("www.example.com")];
        let s = render_server_block(&ServerBlock {
            domain: &d("example.com"),
            aliases: &aliases,
            tenant: &alice,
            document_root: Path::new("/home/alice/public_html"),
            suspended: true,
            access_log: Path::new("/var/log/nginx/oxpanel/example.com.access.log"),
            error_log: Path::new("/var/log/nginx/oxpanel/example.com.error.log"),
            php_socket: None,
        })?;
        assert!(s.contains("server_name example.com www.example.com;"));
        assert!(s.contains("return 503;"));
        assert!(!s.contains("root "), "no document root while suspended");
        assert!(!s.contains("/home/alice"));
        assert!(s.contains("# tenant: alice (suspended)"));
        Ok(())
    }

    #[test]
    fn php_block_passes_only_existing_scripts_to_the_tenant_socket() -> Result<()> {
        let alice = Username::parse("alice")?;
        let s = render_server_block(&ServerBlock {
            domain: &d("example.com"),
            aliases: &[],
            tenant: &alice,
            document_root: Path::new("/home/alice/public_html"),
            suspended: false,
            access_log: Path::new("/var/log/nginx/oxpanel/example.com.access.log"),
            error_log: Path::new("/var/log/nginx/oxpanel/example.com.error.log"),
            php_socket: Some(Path::new("/run/oxpanel-php/alice/php.sock")),
        })?;
        assert!(s.contains("index index.php index.html index.htm;"));
        assert!(s.contains("try_files $uri $uri/ /index.php$is_args$args;"));
        assert!(s.contains("location ~ \\.php$ {\n        try_files $uri =404;"));
        assert!(s.contains("fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;"));
        assert!(s.contains("fastcgi_pass unix:/run/oxpanel-php/alice/php.sock;"));
        assert!(s.contains("access_log /var/log/nginx/oxpanel/example.com.access.log;"));
        assert!(s.contains("error_log /var/log/nginx/oxpanel/example.com.error.log;"));
        // The dot-file rule comes first, so /.user.php or /.git/x.php is never executed.
        let dot = s.find("location ~ /\\.").unwrap_or(usize::MAX);
        let php = s.find("location ~ \\.php$").unwrap_or(0);
        assert!(dot < php);
        // A hostile socket path cannot inject directives.
        let bad = render_server_block(&ServerBlock {
            domain: &d("example.com"),
            aliases: &[],
            tenant: &alice,
            document_root: Path::new("/home/alice/public_html"),
            suspended: false,
            access_log: Path::new("/var/log/nginx/oxpanel/example.com.access.log"),
            error_log: Path::new("/var/log/nginx/oxpanel/example.com.error.log"),
            php_socket: Some(Path::new("/run/x.sock; include /etc/shadow")),
        });
        assert!(bad.is_err());
        Ok(())
    }
}
