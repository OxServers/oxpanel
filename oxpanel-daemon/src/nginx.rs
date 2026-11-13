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
    let mut s = format!(
        "{HEADER}
# WebSocket upgrade for proxied applications: pass `Connection: upgrade` on
# when the client asked for one, close otherwise.
map $http_upgrade $oxpanel_connection {{
    default upgrade;
    ''      close;
}}

include {dir}/*.conf;
"
    );
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

# The same for HTTPS: refuse the TLS handshake for unknown names, so no
# tenant's certificate (or site) is ever shown for a name it does not own.
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_tokens off;
    ssl_reject_handshake on;
}
",
        );
    }
    Ok(s)
}

/// The certificate of a virtual host and how HTTPS is offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsBlock<'a> {
    /// Absolute paths of the certificate chain and its private key.
    pub certificate: &'a Path,
    pub key: &'a Path,
    /// Answer plain HTTP with a redirect to HTTPS.
    pub redirect: bool,
    /// Send `Strict-Transport-Security` over HTTPS.
    pub hsts: bool,
}

/// Protocol settings of every HTTPS server block: TLS 1.2 and 1.3 with
/// forward-secret AEAD suites only (Mozilla "intermediate" without the
/// finite-field DHE suites, so no DH parameters are needed), a shared session
/// cache and no session tickets (their keys would otherwise have to be
/// rotated). No OCSP stapling: it needs a resolver and outbound requests from
/// the web server, and Let's Encrypt no longer runs OCSP responders.
const TLS_SETTINGS: &str = "    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:oxpanel_tls:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
";

/// What browsers are told with `hsts`: HTTPS only, for one year, for this
/// name alone (no `includeSubDomains`, no `preload`).
const HSTS_HEADER: &str = "    add_header Strict-Transport-Security \"max-age=31536000\" always;\n";

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
    /// Socket of the tenant's PHP-FPM instance, if PHP is enabled.
    pub php_socket: Option<&'a Path>,
    /// Socket of the virtual host's application, if it runs one.
    pub app_socket: Option<&'a Path>,
    /// Directory ACME HTTP-01 challenge files are served from.
    pub acme_challenge_dir: &'a Path,
    /// Set when the virtual host has a certificate: it is served over HTTPS too.
    pub tls: Option<TlsBlock<'a>>,
    /// Limits that follow the site's PHP settings (`None`: Nginx's defaults,
    /// and nothing is rendered).
    pub php_tuning: Option<PhpTuning>,
}

/// Nginx limits that must follow a site's PHP settings, or the settings
/// would do nothing (see [`crate::php_settings::nginx_tuning`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PhpTuning {
    /// `client_max_body_size` in MiB (server level).
    pub client_max_body_mb: Option<u32>,
    /// `fastcgi_read_timeout` / `fastcgi_send_timeout` in seconds.
    pub read_timeout_secs: Option<u32>,
    pub send_timeout_secs: Option<u32>,
}

/// Render the complete, self-contained configuration of one virtual host: a
/// server block for port 80 and, with a certificate, one for port 443.
///
/// - Every site that is not suspended answers ACME HTTP-01 challenges on
///   port 80, also while it redirects everything else to HTTPS.
/// - A suspended site answers 503 on both ports (over HTTPS still with its
///   own certificate, so visitors see the 503 and not a certificate error),
///   never redirects and answers no challenges.
pub fn render_server_block(b: &ServerBlock<'_>) -> Result<String> {
    let access_log = safe_path_str(b.access_log)?;
    let error_log = safe_path_str(b.error_log)?;
    let mut names = String::from(b.domain.as_str());
    for a in b.aliases {
        names.push(' ');
        names.push_str(a.as_str());
    }
    let logs = format!(
        "    access_log {access_log};
    error_log {error_log};
    server_tokens off;
"
    );
    let acme = format!(
        "
    # ACME HTTP-01 challenges, answered from a directory only the ACME client
    # writes (before the dot-file rule below, which would hide them).
    location ^~ /.well-known/acme-challenge/ {{
        alias {}/;
        default_type text/plain;
        disable_symlinks on;
    }}
",
        safe_path_str(b.acme_challenge_dir)?
    );
    let tls = match &b.tls {
        None => None,
        Some(t) => Some(format!(
            "    ssl_certificate {};
    ssl_certificate_key {};
{TLS_SETTINGS}",
            safe_path_str(t.certificate)?,
            safe_path_str(t.key)?
        )),
    };
    let (label, http, https) = if b.suspended {
        // No `root`: a suspended site serves nothing from the tenant's files.
        let body = format!(
            "{logs}
    location / {{
        add_header Retry-After 3600 always;
        return 503;
    }}
"
        );
        (" (suspended)", body.clone(), body)
    } else {
        let site = render_site(b, &logs)?;
        let redirect = b.tls.as_ref().is_some_and(|t| t.redirect);
        let http = if redirect {
            format!(
                "{logs}{acme}
    location / {{
        return 301 https://$host$request_uri;
    }}
"
            )
        } else {
            format!("{site}{acme}")
        };
        let hsts = if b.tls.as_ref().is_some_and(|t| t.hsts) {
            HSTS_HEADER
        } else {
            ""
        };
        ("", http, format!("{hsts}{site}"))
    };
    let mut out = format!(
        "{HEADER}# tenant: {tenant}{label}
server {{
    listen 80;
    listen [::]:80;
    server_name {names};

{http}}}
",
        tenant = b.tenant,
    );
    if let Some(tls) = tls {
        let block = format!(
            "
server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {names};

{tls}{https}}}
"
        );
        out.push_str(&block);
    }
    Ok(out)
}

/// What an active site serves, identically over HTTP and HTTPS: everything
/// between `server_name` and the closing brace.
fn render_site(b: &ServerBlock<'_>, logs: &str) -> Result<String> {
    use std::fmt::Write as _;
    let root = safe_path_str(b.document_root)?;
    // Without PHP a script must never be handed out as a download: its
    // source routinely holds database passwords.
    let no_php = "
    location ~ \\.php$ {
        return 404;
    }
";
    // Only rendered when the site's PHP settings call for it, so a site that
    // sets nothing keeps exactly the configuration it had.
    let tuning = b.php_socket.and(b.php_tuning).unwrap_or_default();
    let body_size = tuning.client_max_body_mb.map_or_else(String::new, |mb| {
        format!("    client_max_body_size {mb}m;\n")
    });
    let mut timeouts = String::new();
    if let Some(s) = tuning.read_timeout_secs {
        let _ = writeln!(timeouts, "        fastcgi_read_timeout {s}s;");
    }
    if let Some(s) = tuning.send_timeout_secs {
        let _ = writeln!(timeouts, "        fastcgi_send_timeout {s}s;");
    }
    let (index, tries, extra) = match (b.php_socket, b.app_socket) {
        (None, None) => ("index.html index.htm", "$uri $uri/ =404", no_php.to_owned()),
        (Some(sock), _) => (
            "index.php index.html index.htm",
            "$uri $uri/ /index.php$is_args$args",
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
{timeouts}        fastcgi_pass unix:{};
    }}
",
                safe_path_str(sock)?
            ),
        ),
        // Files that exist in the document root are served directly; every
        // other request (directories included) goes to the application.
        (None, Some(sock)) => (
            "index.html index.htm",
            "$uri @app",
            format!(
                "{no_php}
    location @app {{
        proxy_pass http://unix:{}:;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $oxpanel_connection;
        proxy_hide_header X-Powered-By;
    }}
",
                safe_path_str(sock)?
            ),
        ),
    };
    Ok(format!(
        "    root {root};
    index {index};

{logs}{body_size}    autoindex off;
    # Refuse to serve through symlinks whose target the tenant does not own.
    disable_symlinks if_not_owner;

    # Never serve dot-files (.git, .env, .htaccess, ...).
    location ~ /\\. {{
        deny all;
        return 404;
    }}

    location / {{
        try_files {tries};
    }}
{extra}"
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
            app_socket: None,
            acme_challenge_dir: Path::new("/var/lib/oxpanel-acme/challenges"),
            php_tuning: None,
            tls: None,
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
                app_socket: None,
                acme_challenge_dir: Path::new("/var/lib/oxpanel-acme/challenges"),
                php_tuning: None,
                tls: None,
            });
            assert!(r.is_err(), "{bad}");
        }
        assert!(render_include(Path::new("/etc/nginx/ox panel.d"), false).is_err());
        let include = render_include(Path::new("/etc/nginx/oxpanel.d"), false)?;
        assert!(include.starts_with(HEADER));
        assert!(include.ends_with("\ninclude /etc/nginx/oxpanel.d/*.conf;\n"));
        assert!(include.contains("map $http_upgrade $oxpanel_connection {"));
        assert!(
            !include.contains("server {"),
            "no catch-all unless asked for"
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
        // Unknown names on 443 get no certificate at all, not a tenant's.
        assert!(with_default.contains(
            "listen 443 ssl default_server;\n    listen [::]:443 ssl default_server;\n    server_tokens off;\n    ssl_reject_handshake on;"
        ));
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
            app_socket: None,
            acme_challenge_dir: Path::new("/var/lib/oxpanel-acme/challenges"),
            php_tuning: None,
            tls: None,
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
            app_socket: None,
            acme_challenge_dir: Path::new("/var/lib/oxpanel-acme/challenges"),
            php_tuning: None,
            tls: None,
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
            app_socket: None,
            acme_challenge_dir: Path::new("/var/lib/oxpanel-acme/challenges"),
            php_tuning: None,
            tls: None,
        });
        assert!(bad.is_err());
        Ok(())
    }

    #[test]
    fn app_block_serves_static_files_and_proxies_the_rest() -> Result<()> {
        let alice = Username::parse("alice")?;
        let s = render_server_block(&ServerBlock {
            domain: &d("example.com"),
            aliases: &[],
            tenant: &alice,
            document_root: Path::new("/home/alice/public_html"),
            suspended: false,
            access_log: Path::new("/var/log/nginx/oxpanel/example.com.access.log"),
            error_log: Path::new("/var/log/nginx/oxpanel/example.com.error.log"),
            php_socket: None,
            app_socket: Some(Path::new("/run/oxpanel-app/example.com/app.sock")),
            acme_challenge_dir: Path::new("/var/lib/oxpanel-acme/challenges"),
            php_tuning: None,
            tls: None,
        })?;
        assert!(s.contains("location / {\n        try_files $uri @app;\n    }"));
        assert!(s.contains("proxy_pass http://unix:/run/oxpanel-app/example.com/app.sock:;"));
        assert!(s.contains("proxy_set_header Host $host;"));
        assert!(s.contains("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"));
        assert!(s.contains("proxy_set_header Connection $oxpanel_connection;"));
        assert!(s.contains("root /home/alice/public_html;"));
        assert!(s.contains("location ~ \\.php$ {\n        return 404;"));
        assert!(!s.contains("fastcgi_pass"));
        assert!(!s.contains("127.0.0.1"), "never a TCP upstream");
        let bad = render_server_block(&ServerBlock {
            domain: &d("example.com"),
            aliases: &[],
            tenant: &alice,
            document_root: Path::new("/home/alice/public_html"),
            suspended: false,
            access_log: Path::new("/var/log/nginx/oxpanel/example.com.access.log"),
            error_log: Path::new("/var/log/nginx/oxpanel/example.com.error.log"),
            php_socket: None,
            app_socket: Some(Path::new("/run/a.sock:/admin; proxy_pass http://evil")),
            acme_challenge_dir: Path::new("/var/lib/oxpanel-acme/challenges"),
            php_tuning: None,
            tls: None,
        });
        assert!(bad.is_err());
        Ok(())
    }

    #[test]
    fn https_block_mirrors_the_site_for_php_and_applications() -> Result<()> {
        let alice = Username::parse("alice")?;
        let domain = d("example.com");
        let tls = TlsBlock {
            certificate: Path::new("/etc/pki/oxpanel/example.com.crt"),
            key: Path::new("/etc/pki/oxpanel/example.com.key"),
            redirect: false,
            hsts: false,
        };
        let block = |php: Option<&'static Path>, app: Option<&'static Path>| ServerBlock {
            domain: &domain,
            aliases: &[],
            tenant: &alice,
            document_root: Path::new("/home/alice/public_html"),
            suspended: false,
            access_log: Path::new("/var/log/nginx/oxpanel/example.com.access.log"),
            error_log: Path::new("/var/log/nginx/oxpanel/example.com.error.log"),
            php_socket: php,
            app_socket: app,
            acme_challenge_dir: Path::new("/var/lib/oxpanel-acme/challenges"),
            php_tuning: None,
            tls: Some(tls),
        };
        for (php, app, marker) in [
            (
                Some(Path::new("/run/oxpanel-php/alice/php.sock")),
                None,
                "fastcgi_pass unix:/run/oxpanel-php/alice/php.sock;",
            ),
            (
                None,
                Some(Path::new("/run/oxpanel-app/example.com/app.sock")),
                "proxy_set_header X-Forwarded-Proto $scheme;",
            ),
        ] {
            let s = render_server_block(&block(php, app))?;
            let (http, https) = s
                .split_once("\nserver {\n    listen 443")
                .unwrap_or_default();
            assert!(http.contains(marker) && https.contains(marker), "{s}");
            // `include fastcgi_params` passes HTTPS=on to PHP over TLS.
            assert!(https.contains("ssl_certificate /etc/pki/oxpanel/example.com.crt;"));
            assert!(https.contains("ssl_certificate_key /etc/pki/oxpanel/example.com.key;"));
            assert!(https.contains("ssl_session_tickets off;"));
            assert!(!https.contains("ssl_stapling"));
            assert!(http.contains("location ^~ /.well-known/acme-challenge/ {\n        alias /var/lib/oxpanel-acme/challenges/;"));
        }
        // A hostile certificate path cannot inject directives either.
        let bad = TlsBlock {
            key: Path::new("/etc/pki/x.key; include /etc/shadow"),
            ..tls
        };
        assert!(render_server_block(&ServerBlock {
            tls: Some(bad),
            ..block(None, None)
        })
        .is_err());
        Ok(())
    }

    #[test]
    fn php_tuning_raises_the_body_size_and_timeouts_and_nothing_else() -> Result<()> {
        let alice = Username::parse("alice")?;
        let domain = d("example.com");
        let block = |tuning: Option<PhpTuning>, php: bool| ServerBlock {
            domain: &domain,
            aliases: &[],
            tenant: &alice,
            document_root: Path::new("/home/alice/public_html"),
            suspended: false,
            access_log: Path::new("/var/log/nginx/oxpanel/example.com.access.log"),
            error_log: Path::new("/var/log/nginx/oxpanel/example.com.error.log"),
            php_socket: php.then_some(Path::new("/run/oxpanel-php/alice/example.com.sock")),
            app_socket: None,
            acme_challenge_dir: Path::new("/var/lib/oxpanel-acme/challenges"),
            tls: None,
            php_tuning: tuning,
        };
        let tuning = PhpTuning {
            client_max_body_mb: Some(65),
            read_timeout_secs: Some(150),
            send_timeout_secs: Some(90),
        };
        let plain = render_server_block(&block(None, true))?;
        let tuned = render_server_block(&block(Some(tuning), true))?;
        // Exactly three lines more, in the right places.
        let expected = plain
            .replace(
                "    server_tokens off;\n    autoindex off;",
                "    server_tokens off;\n    client_max_body_size 65m;\n    autoindex off;",
            )
            .replace(
                "        fastcgi_hide_header X-Powered-By;\n",
                "        fastcgi_hide_header X-Powered-By;\n        fastcgi_read_timeout 150s;\n        fastcgi_send_timeout 90s;\n",
            );
        assert_ne!(plain, tuned);
        assert_eq!(tuned, expected);
        // Without PHP the tuning has nothing to apply to.
        assert_eq!(
            render_server_block(&block(Some(tuning), false))?,
            render_server_block(&block(None, false))?
        );
        Ok(())
    }
}
