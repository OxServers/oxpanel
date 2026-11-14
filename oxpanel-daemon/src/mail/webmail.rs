//! Webmail (Roundcube) and what Nginx serves for email.
//!
//! One Roundcube for the host, run by its own PHP-FPM master as its own
//! account (`oxpanel-webmail.service`), with its own configuration
//! (`RCUBE_CONFIG_PATH`) and an SQLite database under
//! `/var/lib/oxpanel-webmail`. Nginx serves it as `webmail.<domain>` for
//! every local mail domain — over HTTPS only once the name has a
//! certificate (until then the plain-HTTP name answers 503, so no password
//! ever crosses the network unencrypted). Roundcube logs in to Dovecot and
//! sends through Postfix's submission port like any mail client: the same
//! password checks, suspension and sending limits apply.
//!
//! The same Nginx file answers the mail host name's certificate challenges
//! and `autoconfig.<domain>` (the client settings Thunderbird and others
//! fetch).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use super::config::MailConfig;
use super::render::HEADER;
use crate::error::Result;
use crate::nginx::{safe_path_str, TLS_SETTINGS};
use crate::validate::Domain;

/// Roundcube's files as packaged (EPEL `roundcubemail`).
pub const ROUNDCUBE_DIR: &str = "/usr/share/roundcubemail";
pub const ROUNDCUBE_INDEX: &str = "/usr/share/roundcubemail/public_html/index.php";
/// The service that runs Roundcube's PHP.
pub const SERVICE: &str = "oxpanel-webmail.service";

/// Roundcube's PHP socket (`RuntimeDirectory=` of [`SERVICE`]).
pub fn socket(_cfg: &MailConfig) -> PathBuf {
    PathBuf::from("/run/oxpanel-webmail/php.sock")
}

pub fn fpm_conf_path(cfg: &MailConfig) -> PathBuf {
    cfg.webmail_dir.join("php-fpm.conf")
}

pub fn roundcube_conf_dir(cfg: &MailConfig) -> PathBuf {
    cfg.webmail_dir.join("roundcube")
}

pub fn roundcube_conf_path(cfg: &MailConfig) -> PathBuf {
    roundcube_conf_dir(cfg).join("config.inc.php")
}

/// The name a domain's webmail is served as.
pub fn webmail_name(domain: &str) -> String {
    format!("webmail.{domain}")
}

/// The PHP-FPM master of Roundcube.
pub fn fpm_conf(cfg: &MailConfig, web_user: &str) -> Result<String> {
    let sock_path = socket(cfg);
    let sock = safe_path_str(&sock_path)?;
    let conf_path = roundcube_conf_dir(cfg);
    let conf = safe_path_str(&conf_path)?;
    let data = safe_path_str(&cfg.webmail_data_dir)?;
    let size = cfg.message_max_bytes / (1024 * 1024);
    let post = size + 5;
    Ok(format!(
        "{}[global]
daemonize = no
error_log = syslog
syslog.ident = oxpanel-webmail
log_level = notice

[webmail]
listen = {sock}
; Only the web server may connect.
listen.acl_users = {web_user}
pm = ondemand
pm.max_children = 8
pm.process_idle_timeout = 60s
pm.max_requests = 500
clear_env = yes
env[RCUBE_CONFIG_PATH] = {conf}
security.limit_extensions = .php
php_admin_value[open_basedir] = {ROUNDCUBE_DIR}/:{conf}/:/etc/roundcubemail/:{data}/:/usr/share/php/:/usr/share/pear/:/tmp/
php_admin_value[upload_tmp_dir] = {data}/temp
php_admin_value[sys_temp_dir] = {data}/temp
php_admin_value[session.save_path] = {data}/temp
php_admin_value[upload_max_filesize] = {size}M
php_admin_value[post_max_size] = {post}M
php_admin_value[memory_limit] = 128M
php_admin_value[date.timezone] = UTC
php_admin_flag[log_errors] = on
php_admin_flag[display_errors] = off
php_admin_flag[allow_url_include] = off
php_admin_flag[allow_url_fopen] = off
php_admin_flag[expose_php] = off
php_admin_value[session.cookie_secure] = 1
php_admin_value[session.cookie_httponly] = 1
",
        HEADER.replace('#', ";")
    ))
}

/// Roundcube's configuration. `des_key` encrypts the IMAP password in the
/// session; it is generated once and kept in a root-only file.
pub fn roundcube_conf(cfg: &MailConfig, des_key: &str) -> Result<String> {
    let data = safe_path_str(&cfg.webmail_data_dir)?;
    let size = cfg.message_max_bytes;
    Ok(format!(
        "<?php
// Managed by oxpanel-daemon. Manual edits will be overwritten.
$config = [];
$config['db_dsnw'] = 'sqlite:///{data}/roundcube.db?mode=0600';
// Dovecot and Postfix on this host, over TLS on the loopback (the
// certificate names the mail host name, not 127.0.0.1).
$config['default_host'] = 'ssl://127.0.0.1';
$config['default_port'] = 993;
$config['imap_conn_options'] = ['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]];
$config['smtp_server'] = 'tls://127.0.0.1';
$config['smtp_port'] = 587;
$config['smtp_user'] = '%u';
$config['smtp_pass'] = '%p';
$config['smtp_conn_options'] = ['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]];
$config['des_key'] = '{des_key}';
$config['product_name'] = 'Webmail';
$config['support_url'] = '';
$config['skin'] = 'elastic';
$config['plugins'] = [];
// One identity, the mailbox's own address: the mail server refuses any other.
$config['identities_level'] = 3;
$config['auto_create_user'] = true;
$config['enable_installer'] = false;
$config['use_https'] = true;
$config['ip_check'] = true;
$config['session_samesite'] = 'Strict';
$config['login_autocomplete'] = 0;
$config['login_rate_limit'] = 3;
$config['x_frame_options'] = 'deny';
$config['max_message_size'] = '{size}';
$config['temp_dir'] = '{data}/temp/';
$config['log_driver'] = 'syslog';
$config['syslog_id'] = 'oxpanel-webmail';
$config['log_logins'] = true;
$config['log_session'] = false;
$config['debug_level'] = 1;
"
    ))
}

/// Whether `s` can be Roundcube's key: 24 letters and digits.
pub fn is_des_key(s: &str) -> bool {
    s.len() == 24 && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The client settings Thunderbird (and others) fetch from
/// `autoconfig.<domain>/mail/config-v1.1.xml`. The same for every domain.
pub fn autoconfig_xml(host: &Domain) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<clientConfig version=\"1.1\">
  <emailProvider id=\"{host}\">
    <domain>%EMAILDOMAIN%</domain>
    <displayName>%EMAILDOMAIN%</displayName>
    <incomingServer type=\"imap\">
      <hostname>{host}</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </incomingServer>
    <incomingServer type=\"pop3\">
      <hostname>{host}</hostname>
      <port>995</port>
      <socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </incomingServer>
    <outgoingServer type=\"smtp\">
      <hostname>{host}</hostname>
      <port>465</port>
      <socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </outgoingServer>
  </emailProvider>
</clientConfig>
"
    )
}

/// A webmail name and the certificate it is served with, if it has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebmailSite {
    pub name: String,
    pub tls: Option<(PathBuf, PathBuf)>,
}

fn acme_location(challenges: &Path) -> Result<String> {
    Ok(format!(
        "    location ^~ /.well-known/acme-challenge/ {{
        alias {}/;
        default_type text/plain;
        disable_symlinks on;
    }}
",
        safe_path_str(challenges)?
    ))
}

/// The Nginx file: the mail host name (certificate challenges only), the
/// autoconfiguration names, and each webmail name.
pub fn nginx_conf(
    cfg: &MailConfig,
    host: &Domain,
    autoconfig: &[String],
    webmail: &[WebmailSite],
    challenges: &Path,
) -> Result<String> {
    let acme = acme_location(challenges)?;
    let mut out = format!(
        "{HEADER}
# The mail host name: certificate challenges only.
server {{
    listen 80;
    listen [::]:80;
    server_name {host};
    server_tokens off;
{acme}    location / {{
        return 404;
    }}
}}
"
    );
    if !autoconfig.is_empty() {
        let xml = autoconfig_xml(host);
        let _ = write!(
            out,
            "
# Mail client settings (Thunderbird's autoconfiguration).
server {{
    listen 80;
    listen [::]:80;
    server_name {};
    server_tokens off;
    location = /mail/config-v1.1.xml {{
        default_type application/xml;
        return 200 '{xml}';
    }}
    location / {{
        return 404;
    }}
}}
",
            autoconfig.join(" ")
        );
    }

    for site in webmail {
        let name = &site.name;
        let Some((crt, key)) = &site.tls else {
            let _ = write!(
                out,
                "
# Webmail of {name}: waiting for its certificate (never over plain HTTP).
server {{
    listen 80;
    listen [::]:80;
    server_name {name};
    server_tokens off;
{acme}    location / {{
        add_header Retry-After 600 always;
        return 503;
    }}
}}
"
            );
            continue;
        };
        out.push_str(&https_server(cfg, name, crt, key, &acme)?);
    }
    Ok(out)
}

/// The HTTPS server of one webmail name, and its redirect from HTTP.
fn https_server(
    cfg: &MailConfig,
    name: &str,
    crt: &Path,
    key: &Path,
    acme: &str,
) -> Result<String> {
    let sock_path = socket(cfg);
    let sock = safe_path_str(&sock_path)?;
    let mut out = String::new();
    let (crt, key) = (safe_path_str(crt)?, safe_path_str(key)?);
    let size = cfg.message_max_bytes / (1024 * 1024) + 5;
    let _ = write!(
            out,
            "
# Webmail of {name}.
server {{
    listen 80;
    listen [::]:80;
    server_name {name};
    server_tokens off;
{acme}    location / {{
        return 301 https://$host$request_uri;
    }}
}}
server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {name};
    server_tokens off;
    ssl_certificate {crt};
    ssl_certificate_key {key};
{TLS_SETTINGS}    add_header Strict-Transport-Security \"max-age=31536000\" always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy same-origin always;
    root {ROUNDCUBE_DIR}/public_html;
    index index.php;
    client_max_body_size {size}m;
{acme}    location ~ /\\. {{
        deny all;
    }}
    location ~ ^/(bin|config|installer|logs|SQL|temp|vendor|program/(include|lib|localization|steps))/ {{
        deny all;
    }}
    location ~ \\.php$ {{
        try_files $uri =404;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        fastcgi_param DOCUMENT_ROOT $realpath_root;
        fastcgi_hide_header X-Powered-By;
        fastcgi_pass unix:{sock};
    }}
}}
"
        );
    Ok(out)
}
