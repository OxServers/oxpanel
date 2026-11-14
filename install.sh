#!/usr/bin/env bash
# OxPanel one-command installer for a fresh AlmaLinux 9 host.
#
#   sudo ./install.sh                         interactive: asks the few questions it has
#   sudo ./install.sh --yes                   unattended, with the safe defaults
#   sudo ./install.sh --yes --fail2ban --enable-epel --quota --reboot
#   sudo ./install.sh --help                  every option
#
# It installs the engine RPM and performs every host step of docs/HANDBOOK.md
# section 3 as a separate, logged stage. It is idempotent (a second run changes
# nothing and says so) and resumable (a failed stage is simply run again; every
# stage looks at the host, not at a record of what it did before).
#
# Not done without being asked: enabling EPEL, installing fail2ban, changing
# the boot configuration for disk quotas, rebooting, touching an existing
# MariaDB, masking a PHP-FPM you already use. It never disables a firewall.
#
# Log: /var/log/oxpanel-install.log. Result of the last run:
# /var/lib/oxpanel-installer/status. Licence: Apache-2.0.
set -euo pipefail

INSTALLER_VERSION="0.2.0"

# ---------------------------------------------------------------------------
# Where a real release would be fetched from. NOT SET: there is no published
# repository yet, and this script never downloads anything by itself. When one
# exists, put its base URL and the URL of the signing key here (or pass
# --repo-url); the installer then writes /etc/yum.repos.d/oxpanel.repo with
# gpgcheck=1 and installs `oxpanel-daemon` from it instead of a local file.
OXPANEL_REPO_BASEURL=""          # e.g. https://<release host>/el9/x86_64/   (to be decided)
OXPANEL_REPO_GPGKEY=""           # e.g. https://<release host>/RPM-GPG-KEY-oxpanel (to be decided)
# ---------------------------------------------------------------------------

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG=/var/log/oxpanel-install.log
STATE_DIR=/var/lib/oxpanel-installer
ENV_FILE=/etc/oxpanel/daemon.env
JAIL_FILE=/etc/fail2ban/jail.d/50-oxpanel-sshd.local
MARIADB_CNF=/etc/my.cnf.d/oxpanel-local.cnf
REPO_FILE=/etc/yum.repos.d/oxpanel.repo
ENV_BEGIN="# BEGIN oxpanel-installer (managed by install.sh; edit outside this block)"
ENV_END="# END oxpanel-installer"
MIN_FREE_MB=2048

# Options: "" = not decided yet, yes, no.
OPT_YES=0 OPT_FORCE=0 OPT_UNINSTALL=0 OPT_CHECK=0 OPT_ONLY=""
OPT_FAIL2BAN="" OPT_EPEL="" OPT_QUOTA="" OPT_REBOOT="" OPT_MARIADB=yes OPT_PHP=yes OPT_NODEJS=yes
OPT_HARDEN_EXISTING="" OPT_PANEL_ACCOUNT="" OPT_SWITCH_NODEJS="" OPT_MASK_PHPFPM=""
OPT_IGNORE_IP="" OPT_PANEL_SCOPES="" OPT_PANEL_RPM="" OPT_REPO_URL="" OPT_ANSWERS="" OPT_HOME_BASE=""
OPT_PANEL_PORT="" OPT_PANEL_HOSTNAME="" OPT_PANEL_ADMIN="" OPT_NO_PANEL="" OPT_PURGE_PANEL=""
OPT_DNS="" OPT_DNS_NAMESERVERS="" OPT_DNS_CONTACT="" OPT_DNS_IPV4="" OPT_DNS_IPV6="" OPT_DISABLE_STOCK_NAMED=""
DNS_KEYS='^OXPANEL_DNS(_NAMESERVERS|_SOA_CONTACT|_IPV4|_IPV6)?='
ENGINE_RPM=""
INTERACTIVE=0
CHANGE_FILE="" WARN_FILE="" FLAG_DIR=""

# ------------------------------------------------------------------ output
say()  { printf '%s\n' "$*"; printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >>"$LOG" 2>/dev/null || true; }
note() { say "      $*"; }
warn() { say "WARNING: $*"; if [ -n "$WARN_FILE" ]; then printf '%s\n' "$*" >>"$WARN_FILE"; fi; }
die()  { say "ERROR: $*"; exit 1; }
changed() { say "      changed: $*"; if [ -n "$CHANGE_FILE" ]; then printf '%s\n' "$*" >>"$CHANGE_FILE"; fi; }
# run <command...>: output goes to the log; on failure the tail of it is shown.
run() {
  local rc=0
  printf '+ %s\n' "$*" >>"$LOG"
  "$@" >>"$LOG" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    printf 'ERROR: command failed (exit %s): %s\n' "$rc" "$*" >&2
    tail -n 15 "$LOG" >&2 || true
    return "$rc"
  fi
}
# quiet <command...>: for questions to the host; never logs, never fails the script.
quiet() { "$@" >/dev/null 2>&1; }
# Stages run in subshells, so what one stage tells another goes through files.
flag_set() { : >"$FLAG_DIR/$1"; }
flag_is() { [ -e "$FLAG_DIR/$1" ]; }

usage() {
  cat <<'EOF'
OxPanel installer (AlmaLinux 9)

Usage: install.sh [options] [oxpanel-daemon-*.rpm]

The engine RPM is taken from the command line, else from beside this script,
else (once a repository is configured in this script or with --repo-url) from it.

General
  -y, --yes             unattended: ask nothing, use the safe defaults
                        (no EPEL, no fail2ban, no quota change, no reboot)
  --answers FILE        answers file: one key=value per line, keys are the
                        option names below without "--" (fail2ban=yes, epel=yes,
                        quota=yes, reboot=no, ignore_ip=203.0.113.5, ...)
  --check               preflight checks only; changes nothing
  --only STAGE          run only this stage (after preflight); stages:
                        nodejs engine selinux nginx mariadb php panel daemon dns
                        panelweb firewall fail2ban quota verify
  --force               continue past a conflicting web server or port 80 owner
  --uninstall           remove the engine packages and OxPanel's own
                        configuration; never customers' homes, databases or
                        backups (prints what it leaves). The panel's database
                        is kept too, unless --purge-panel
  -h, --help

Packages
  --rpm FILE            engine RPM (also given as a bare argument)
  --repo-url URL        install from this dnf repository instead of a file
  --no-nodejs           skip the Node.js 22 stream (Node.js apps then unavailable)
  --switch-nodejs       replace an older installed Node.js by stream 22
  --no-php              skip PHP-FPM and php-cli (PHP sites and PHP scheduled tasks)
  --mask-php-fpm        mask the shared php-fpm.service even if it is in use
  --no-mariadb          skip MariaDB
  --harden-existing-mariadb
                        also harden a MariaDB that was already installed
                        (removes anonymous accounts and the test database,
                        turns off its network listener)

Optional features (each asks when interactive; each is off with --yes)
  --fail2ban            ban addresses guessing SSH/SFTP passwords (needs EPEL)
  --enable-epel         allow enabling EPEL (epel-release) for fail2ban
  --ignore-ip LIST      addresses fail2ban never bans, comma separated
                        (your current session's address is added automatically)
  --quota               prepare disk quotas (boot change; needs a reboot)
  --reboot              reboot at the end if a reboot is needed
  --no-fail2ban --no-quota --no-reboot   say no explicitly
  --home-base PATH      where tenant homes live (default: OXPANEL_HOME_BASE or /home)

DNS hosting (optional; this host as the name server of its customers' domains)
  --dns                 install BIND and switch DNS hosting on (needs the four below)
  --no-dns              switch it off (zones and keys stay on disk)
  --dns-nameservers L   the name servers' host names, comma separated, first = SOA
                        primary (e.g. ns1.example.net,ns2.example.net)
  --dns-contact ADDR    the zones' SOA contact (e.g. hostmaster@example.net)
  --dns-ipv4 ADDR       this host's PUBLIC IPv4 address (never guessed: behind
  --dns-ipv6 ADDR       NAT the interface's address is private); one or both
  --disable-stock-named stop and disable the distribution's named.service if it
                        runs (it would hold port 53); otherwise the installer stops

Panel (optional; the panel is a separate product)
  --panel-rpm FILE      install (or upgrade) the panel RPM, make sure the
                        `panelapi` account exists in group `oxpanel`, put the
                        panel on HTTPS, start it and create its first
                        administrator. An oxpanel-panel-*.rpm beside this
                        script is used without this option (--no-panel: not)
  --panel-port N        serve the panel on its own HTTPS port (default 8443;
                        opened in firewalld)
  --panel-hostname NAME serve it instead under a host name of its own on 443
                        (NAME must point at this host; no extra port is opened)
  --panel-admin NAME    the first administrator's user name (default: admin);
                        its one-time password is printed at the end, never logged
  --no-panel            do not install a panel RPM found beside this script
  --purge-panel         with --uninstall: also delete the panel's database,
                        configuration and certificate
  --panel-account       only create/repair the `panelapi` account
  --panel-scopes S      confine panelapi to API scopes, e.g. read+vhost
                        (default: unconfined, which the panel needs)
EOF
}

# ------------------------------------------------------------------ arguments
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -y|--yes) OPT_YES=1;;
      -h|--help) usage; exit 0;;
      --answers) [ $# -ge 2 ] || die "--answers needs a file"; OPT_ANSWERS="$2"; shift;;
      --check) OPT_CHECK=1;;
      --only) [ $# -ge 2 ] || die "--only needs a stage name"; OPT_ONLY="$2"; shift;;
      --force) OPT_FORCE=1;;
      --uninstall) OPT_UNINSTALL=1;;
      --rpm) [ $# -ge 2 ] || die "--rpm needs a file"; ENGINE_RPM="$2"; shift;;
      --repo-url) [ $# -ge 2 ] || die "--repo-url needs a URL"; OPT_REPO_URL="$2"; shift;;
      --no-nodejs) OPT_NODEJS=no;;
      --switch-nodejs) OPT_SWITCH_NODEJS=yes;;
      --no-php) OPT_PHP=no;;
      --mask-php-fpm) OPT_MASK_PHPFPM=yes;;
      --no-mariadb) OPT_MARIADB=no;;
      --harden-existing-mariadb) OPT_HARDEN_EXISTING=yes;;
      --fail2ban) OPT_FAIL2BAN=yes;;
      --no-fail2ban) OPT_FAIL2BAN=no;;
      --enable-epel) OPT_EPEL=yes;;
      --ignore-ip) [ $# -ge 2 ] || die "--ignore-ip needs a list"; OPT_IGNORE_IP="$2"; shift;;
      --quota) OPT_QUOTA=yes;;
      --no-quota) OPT_QUOTA=no;;
      --reboot) OPT_REBOOT=yes;;
      --no-reboot) OPT_REBOOT=no;;
      --home-base) [ $# -ge 2 ] || die "--home-base needs a path"; OPT_HOME_BASE="$2"; shift;;
      --panel-rpm) [ $# -ge 2 ] || die "--panel-rpm needs a file"; OPT_PANEL_RPM="$2"; OPT_PANEL_ACCOUNT=yes; shift;;
      --panel-account) OPT_PANEL_ACCOUNT=yes;;
      --panel-port) [ $# -ge 2 ] || die "--panel-port needs a number"; OPT_PANEL_PORT="$2"; shift;;
      --panel-hostname) [ $# -ge 2 ] || die "--panel-hostname needs a name"; OPT_PANEL_HOSTNAME="$2"; shift;;
      --panel-admin) [ $# -ge 2 ] || die "--panel-admin needs a user name"; OPT_PANEL_ADMIN="$2"; shift;;
      --no-panel) OPT_NO_PANEL=yes;;
      --purge-panel) OPT_PURGE_PANEL=yes;;
      --dns) OPT_DNS=yes;;
      --no-dns) OPT_DNS=no;;
      --dns-nameservers) [ $# -ge 2 ] || die "--dns-nameservers needs a list"; OPT_DNS_NAMESERVERS="$2"; shift;;
      --dns-contact) [ $# -ge 2 ] || die "--dns-contact needs an address"; OPT_DNS_CONTACT="$2"; shift;;
      --dns-ipv4) [ $# -ge 2 ] || die "--dns-ipv4 needs an address"; OPT_DNS_IPV4="$2"; shift;;
      --dns-ipv6) [ $# -ge 2 ] || die "--dns-ipv6 needs an address"; OPT_DNS_IPV6="$2"; shift;;
      --disable-stock-named) OPT_DISABLE_STOCK_NAMED=yes;;
      --panel-scopes) [ $# -ge 2 ] || die "--panel-scopes needs a value"; OPT_PANEL_SCOPES="$2"; shift;;
      -*) die "unknown option: $1 (see --help)";;
      *) ENGINE_RPM="$1";;
    esac
    shift
  done
}

yesno_value() { # <key> <value> -> yes|no
  case "$2" in
    yes|y|true|1|on) echo yes;;
    no|n|false|0|off) echo no;;
    *) die "answers file: $1 must be yes or no, not '$2'";;
  esac
}

# Answers file: key=value, '#' comments. Parsed, never sourced. Command-line
# options win over the file, so a key is applied only where still undecided.
load_answers() {
  [ -n "$OPT_ANSWERS" ] || return 0
  [ -r "$OPT_ANSWERS" ] || die "cannot read answers file $OPT_ANSWERS"
  local line key val n=0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    line="${line%%#*}"
    line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [ -n "$line" ] || continue
    case "$line" in *=*) ;; *) die "$OPT_ANSWERS:$n: expected key=value";; esac
    key="${line%%=*}"; val="${line#*=}"
    key="$(printf '%s' "$key" | sed -e 's/[[:space:]]*$//')"
    val="$(printf '%s' "$val" | sed -e 's/^[[:space:]]*//')"
    case "$key" in
      fail2ban) [ -n "$OPT_FAIL2BAN" ] || OPT_FAIL2BAN="$(yesno_value "$key" "$val")";;
      epel) [ -n "$OPT_EPEL" ] || OPT_EPEL="$(yesno_value "$key" "$val")";;
      quota) [ -n "$OPT_QUOTA" ] || OPT_QUOTA="$(yesno_value "$key" "$val")";;
      reboot) [ -n "$OPT_REBOOT" ] || OPT_REBOOT="$(yesno_value "$key" "$val")";;
      mariadb) OPT_MARIADB="$(yesno_value "$key" "$val")";;
      php) OPT_PHP="$(yesno_value "$key" "$val")";;
      nodejs) OPT_NODEJS="$(yesno_value "$key" "$val")";;
      harden_existing_mariadb) [ -n "$OPT_HARDEN_EXISTING" ] || OPT_HARDEN_EXISTING="$(yesno_value "$key" "$val")";;
      mask_php_fpm) [ -n "$OPT_MASK_PHPFPM" ] || OPT_MASK_PHPFPM="$(yesno_value "$key" "$val")";;
      switch_nodejs) [ -n "$OPT_SWITCH_NODEJS" ] || OPT_SWITCH_NODEJS="$(yesno_value "$key" "$val")";;
      ignore_ip) [ -n "$OPT_IGNORE_IP" ] || OPT_IGNORE_IP="$val";;
      home_base) [ -n "$OPT_HOME_BASE" ] || OPT_HOME_BASE="$val";;
      panel_scopes) [ -n "$OPT_PANEL_SCOPES" ] || OPT_PANEL_SCOPES="$val";;
      panel_rpm) [ -n "$OPT_PANEL_RPM" ] || { OPT_PANEL_RPM="$val"; OPT_PANEL_ACCOUNT=yes; };;
      panel_account) [ -n "$OPT_PANEL_ACCOUNT" ] || OPT_PANEL_ACCOUNT="$(yesno_value "$key" "$val")";;
      panel_port) [ -n "$OPT_PANEL_PORT" ] || OPT_PANEL_PORT="$val";;
      panel_hostname) [ -n "$OPT_PANEL_HOSTNAME" ] || OPT_PANEL_HOSTNAME="$val";;
      panel_admin) [ -n "$OPT_PANEL_ADMIN" ] || OPT_PANEL_ADMIN="$val";;
      dns) [ -n "$OPT_DNS" ] || OPT_DNS="$(yesno_value "$key" "$val")";;
      dns_nameservers) [ -n "$OPT_DNS_NAMESERVERS" ] || OPT_DNS_NAMESERVERS="$val";;
      dns_contact) [ -n "$OPT_DNS_CONTACT" ] || OPT_DNS_CONTACT="$val";;
      dns_ipv4) [ -n "$OPT_DNS_IPV4" ] || OPT_DNS_IPV4="$val";;
      dns_ipv6) [ -n "$OPT_DNS_IPV6" ] || OPT_DNS_IPV6="$val";;
      disable_stock_named) [ -n "$OPT_DISABLE_STOCK_NAMED" ] || OPT_DISABLE_STOCK_NAMED="$(yesno_value "$key" "$val")";;
      *) die "$OPT_ANSWERS:$n: unknown key '$key'";;
    esac
  done <"$OPT_ANSWERS"
}

# ------------------------------------------------------------------ questions
# ask <question> -> 0 for yes. Interactive: asks (default no). Otherwise: no.
ask() {
  local reply
  if [ "$INTERACTIVE" -ne 1 ]; then return 1; fi
  printf '%s [y/N] ' "$1" >&2
  read -r reply || reply=""
  case "$reply" in y|Y|yes|YES|Yes) return 0;; *) return 1;; esac
}

# decide <var-name> <explanation> <question>: fill an undecided yes/no option by
# asking (interactive) or by defaulting to no (unattended). Prints the outcome.
decide() {
  local var="$1" why="$2" q="$3" cur
  cur="${!var}"
  if [ -n "$cur" ]; then return 0; fi
  if [ "$INTERACTIVE" -eq 1 ]; then
    printf '\n%s\n' "$why" >&2
    if ask "$q"; then printf -v "$var" %s yes; else printf -v "$var" %s no; fi
  else
    printf -v "$var" %s no
  fi
}

# ------------------------------------------------------------------ host facts
os_field() { sed -n "s/^$1=//p" /etc/os-release | head -1 | tr -d '"'; }
installed() { quiet rpm -q "$1"; }
unit_active() { quiet systemctl is-active "$1"; }
unit_enabled() { quiet systemctl is-enabled "$1"; }
valid_ip() { printf '%s' "$1" | grep -Eq '^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$'; }
# Version comparison: version_lt A B -> 0 when A < B.
version_lt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ]; }
cur_version() { if installed oxpanel-daemon; then rpm -q --qf '%{VERSION}-%{RELEASE}' oxpanel-daemon; fi; }

home_base() {
  local b
  if [ -n "$OPT_HOME_BASE" ]; then echo "$OPT_HOME_BASE"; return; fi
  b="$(sed -n 's/^OXPANEL_HOME_BASE=//p' "$ENV_FILE" 2>/dev/null | tail -1 | tr -d '"'"'"'')"
  echo "${b:-/home}"
}

# The address of the session this script runs in: from sshd's environment of
# this process or an ancestor (sudo drops it from ours), else `who`.
session_addr() {
  local pid=$$ conn="" addr=""
  for _ in $(seq 1 12); do
    [ "$pid" -gt 1 ] 2>/dev/null || break
    if [ -r "/proc/$pid/environ" ]; then
      conn="$(tr '\0' '\n' <"/proc/$pid/environ" 2>/dev/null | sed -n 's/^SSH_CONNECTION=//p' | head -1)" || conn=""
      if [ -n "$conn" ]; then addr="${conn%% *}"; break; fi
    fi
    pid="$(awk '{print $4}' "/proc/$pid/stat" 2>/dev/null || echo 1)"
  done
  if [ -z "$addr" ]; then
    addr="$(who -m 2>/dev/null | sed -n 's/.*(\(.*\)).*/\1/p' | head -1)" || addr=""
  fi
  if [ -n "$addr" ] && valid_ip "$addr"; then echo "$addr"; fi
}

# ------------------------------------------------------------------ stage runner
STAGES_RUN=0
stage() { # <name> <title> <function>
  local name="$1" title="$2" fn="$3" rc=0 before after
  if [ -n "$OPT_ONLY" ] && [ "$OPT_ONLY" != "$name" ]; then return 0; fi
  STAGES_RUN=$((STAGES_RUN + 1))
  say "[$name] $title"
  before="$(wc -l <"$CHANGE_FILE")"
  set +e
  ( set -e; "$fn" )
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    say "FAILED stage '$name'. Nothing is half-recorded: fix the cause (see $LOG) and run install.sh again; it resumes here."
    printf 'result=failed\nfailed_stage=%s\nfinished=%s\n' "$name" "$(date -u +%FT%TZ)" >"$STATE_DIR/status"
    exit 1
  fi
  after="$(wc -l <"$CHANGE_FILE")"
  if [ "$after" -eq "$before" ]; then say "      ok (nothing to change)"; else say "      ok ($((after - before)) change(s))"; fi
}

# ------------------------------------------------------------------ stage: preflight
preflight() {
  local id ver arch mode free_mb listener
  [ "$(id -u)" -eq 0 ] || die "run as root (sudo ./install.sh)"
  command -v dnf >/dev/null || die "dnf not found: this installer is for AlmaLinux 9"
  id="$(os_field ID)"; ver="$(os_field VERSION_ID)"
  case "$ver" in 9|9.*) ;; *) die "this is $(os_field PRETTY_NAME); OxPanel needs AlmaLinux 9";; esac
  case "$id" in
    almalinux) ;;
    rocky|rhel|centos|ol) warn "$id $ver is a RHEL 9 rebuild but untested; continuing";;
    *) die "unsupported distribution '$id'";;
  esac
  arch="$(uname -m)"
  [ "$arch" = x86_64 ] || die "architecture $arch is not supported (x86_64 only)"
  say "      OS $(os_field PRETTY_NAME), $arch"
  if command -v getenforce >/dev/null; then mode="$(getenforce)"; else mode=Disabled; fi
  case "$mode" in
    Enforcing) say "      SELinux: Enforcing";;
    Permissive) warn "SELinux is Permissive: OxPanel works, but nothing is enforced; the supported setting is Enforcing";;
    *) warn "SELinux is $mode: OxPanel works, but nothing is confined; the supported setting is Enforcing";;
  esac
  free_mb="$(df -Pm /var | awk 'NR==2{print $4}')"
  if [ "${free_mb:-0}" -lt "$MIN_FREE_MB" ]; then die "only ${free_mb} MB free on /var; at least ${MIN_FREE_MB} MB needed"; fi
  say "      free space on /var: ${free_mb} MB"
  [ -d /run/systemd/system ] || die "systemd is not running as PID 1"

  # Conflicting web servers.
  if installed httpd && { unit_active httpd || unit_enabled httpd; }; then
    if [ "$OPT_FORCE" -eq 1 ]; then warn "Apache httpd is enabled or running; --force given";
    else die "Apache httpd is installed and enabled/running. OxPanel serves sites with Nginx on ports 80 and 443; two web servers would fight over them. Stop and disable httpd (systemctl disable --now httpd) or use --force if you know what you are doing."; fi
  fi
  listener="$(ss -H -ltnp 'sport = :80' 2>/dev/null | grep -v 'users:(("nginx"' || true)"
  if [ -n "$listener" ]; then
    if [ "$OPT_FORCE" -eq 1 ]; then warn "something other than nginx listens on port 80; --force given";
    else die "port 80 is in use by something other than nginx: $(printf '%s' "$listener" | head -1 | tr -s ' ')"; fi
  fi
  if [ -d /etc/nginx ]; then
    # Only a default server on the ports the engine's catch-all uses (80, 443)
    # clashes with it; one on another port (the panel's 8443) does not.
    EXISTING_DEFAULT_SERVER="$(grep -rlE '^[^#]*listen[[:space:]]+([^;[:space:]]*:)?(80|443)([[:space:]][^;]*)?[[:space:]]default_server' /etc/nginx --include='*.conf' 2>/dev/null | grep -v '/oxpanel\.d/\|00-oxpanel\.conf' || true)"
    if [ -n "$EXISTING_DEFAULT_SERVER" ]; then
      warn "Nginx already defines a default_server ($(printf '%s' "$EXISTING_DEFAULT_SERVER" | tr '\n' ' ')); the engine's own catch-all will be turned off so the two do not clash (OXPANEL_NGINX_DEFAULT_SERVER=false in $ENV_FILE)"
    fi
  fi
}
EXISTING_DEFAULT_SERVER=""

# ------------------------------------------------------------------ locating the RPMs
find_engine_rpm() {
  local f newest=""
  if [ -n "$ENGINE_RPM" ]; then
    [ -r "$ENGINE_RPM" ] || die "cannot read $ENGINE_RPM"
    return 0
  fi
  for f in "$HERE"/oxpanel-daemon-[0-9]*.rpm; do
    [ -e "$f" ] || continue
    case "$f" in *debuginfo*|*debugsource*|*.src.rpm) continue;; esac
    if [ -z "$newest" ] || [ "$(printf '%s\n%s\n' "$newest" "$f" | sort -V | tail -1)" = "$f" ]; then newest="$f"; fi
  done
  ENGINE_RPM="$newest"
}

verify_checksum() { # <file>: against SHA256SUMS beside it, when there is one
  local f="$1" dir base
  dir="$(cd "$(dirname "$f")" && pwd)"; base="$(basename "$f")"
  [ -r "$dir/SHA256SUMS" ] || { warn "no SHA256SUMS beside $base; its integrity is not checked"; return 0; }
  if ! grep -qF -- " $base" "$dir/SHA256SUMS"; then warn "$base is not listed in $dir/SHA256SUMS"; return 0; fi
  (cd "$dir" && grep -F -- " $base" SHA256SUMS | sha256sum -c --quiet -) || die "checksum mismatch for $base: do not install it"
  note "checksum ok: $base"
}

rpm_field() { rpm -qp --qf "%{$2}" "$1" 2>/dev/null; }

# ------------------------------------------------------------------ stage: nodejs
stage_nodejs() {
  if [ "$OPT_NODEJS" != yes ]; then note "skipped (--no-nodejs): Node.js applications will be unavailable"; return 0; fi
  local enabled node_major=""
  enabled="$(dnf -q module list --enabled nodejs 2>/dev/null | awk '$1=="nodejs"{print $2}' | head -1 || true)"
  if command -v node >/dev/null; then node_major="$(node --version | sed 's/^v//; s/\..*//')"; fi
  if [ -n "$node_major" ] && [ "$node_major" -lt 22 ] && [ "$OPT_SWITCH_NODEJS" != yes ]; then
    warn "Node.js $node_major is installed and is not touched (Node.js 22 is the minimum for applications); run again with --switch-nodejs to replace it with stream 22"
    return 0
  fi
  if [ -n "$node_major" ] && [ "$node_major" -ge 22 ] && installed npm; then
    note "Node.js $(node --version) and npm are installed${enabled:+ (module stream $enabled)}"; return 0
  fi
  if [ -n "$node_major" ] && [ "$node_major" -lt 22 ]; then
    run dnf -y module switch-to nodejs:22 || return 1
  else
    run dnf -y module enable nodejs:22 || return 1
  fi
  run dnf -y install nodejs npm || return 1
  changed "Node.js 22 stream enabled; nodejs and npm installed ($(node --version))"
}

# ------------------------------------------------------------------ stage: engine
setup_repo() {
  local url="${OPT_REPO_URL:-$OXPANEL_REPO_BASEURL}" key="$OXPANEL_REPO_GPGKEY" want
  want="[oxpanel]
name=OxPanel engine
baseurl=$url
enabled=1
gpgcheck=1
gpgkey=$key
"
  [ -n "$key" ] || die "a repository needs OXPANEL_REPO_GPGKEY set in install.sh (packages are never installed from it unsigned)"
  if [ "$(cat "$REPO_FILE" 2>/dev/null || true)" != "$(printf '%s' "$want")" ]; then
    printf '%s' "$want" >"$REPO_FILE"; chmod 0644 "$REPO_FILE"
    changed "wrote $REPO_FILE"
  fi
}

stage_engine() {
  local before after target tver
  before="$(cur_version)"
  if [ -n "$ENGINE_RPM" ]; then
    verify_checksum "$ENGINE_RPM"
    [ "$(rpm_field "$ENGINE_RPM" NAME)" = oxpanel-daemon ] || die "$ENGINE_RPM is not an oxpanel-daemon package"
    tver="$(rpm_field "$ENGINE_RPM" VERSION)-$(rpm_field "$ENGINE_RPM" RELEASE)"
    if [ -n "$before" ] && version_lt "$tver" "$before"; then
      warn "installed $before is newer than $tver; not downgrading (downgrade by hand with dnf if you mean it)"
      return 0
    fi
    if [ "$before" = "$tver" ]; then note "oxpanel-daemon $before is already installed"; else
      note "installing $(basename "$ENGINE_RPM")${before:+ (upgrade from $before)}"
      run dnf -y install "$ENGINE_RPM" || return 1
    fi
  elif [ -n "${OPT_REPO_URL:-$OXPANEL_REPO_BASEURL}" ]; then
    setup_repo
    run dnf -y install oxpanel-daemon || return 1
  else
    die "no engine RPM: give one on the command line, put oxpanel-daemon-*.rpm beside install.sh, or configure a repository (OXPANEL_REPO_BASEURL in this script, or --repo-url)"
  fi
  # The weak dependencies are what the handbook calls required for SFTP and quotas.
  run dnf -y install openssh-server xfsprogs || return 1
  after="$(cur_version)"
  if [ "$before" != "$after" ]; then changed "oxpanel-daemon ${before:-(none)} -> $after"; fi
  target="$(oxpanel-daemon --version 2>/dev/null || true)"; note "engine: $target"
  engine_env_block
}

# The installer's own settings in daemon.env live in one marked block, rewritten
# from scratch each run, so a second run changes nothing and a hand edit outside
# it is never touched. The block is a function of host facts and options only;
# the panel's peer-scope line is kept from the previous run unless a new one is given.
env_block_current() { [ -r "$ENV_FILE" ] || return 0; awk -v b="$ENV_BEGIN" -v e="$ENV_END" '$0==b{f=1;next} $0==e{f=0;next} f' "$ENV_FILE"; }
env_block_content() {
  local scopes=""
  if [ -n "$EXISTING_DEFAULT_SERVER" ]; then echo "OXPANEL_NGINX_DEFAULT_SERVER=false"; fi
  if [ -n "$OPT_PANEL_SCOPES" ] && id -u panelapi >/dev/null 2>&1; then
    scopes="OXPANEL_PEER_SCOPES=$(id -u panelapi):${OPT_PANEL_SCOPES}"
  else
    scopes="$(env_block_current | grep '^OXPANEL_PEER_SCOPES=' || true)"
  fi
  if [ -n "$scopes" ]; then echo "$scopes"; fi
  dns_env_lines
}

# The DNS hosting lines of the installer's block: written once BIND is there
# (so the daemon never starts with DNS on and no server); kept as they are by
# a run that does not mention DNS; removed only by --no-dns.
dns_env_lines() {
  case "$OPT_DNS" in
    yes)
      installed bind || return 0
      echo "OXPANEL_DNS=true"
      echo "OXPANEL_DNS_NAMESERVERS=$OPT_DNS_NAMESERVERS"
      echo "OXPANEL_DNS_SOA_CONTACT=$OPT_DNS_CONTACT"
      if [ -n "$OPT_DNS_IPV4" ]; then echo "OXPANEL_DNS_IPV4=$OPT_DNS_IPV4"; fi
      if [ -n "$OPT_DNS_IPV6" ]; then echo "OXPANEL_DNS_IPV6=$OPT_DNS_IPV6"; fi
      ;;
    no) ;;
    *) env_block_current | grep -E "$DNS_KEYS" || true;;
  esac
}

# DNS hosting is configured in the installer's block (by an earlier run).
dns_in_block() { env_block_current | grep -qx 'OXPANEL_DNS=true'; }
dns_wanted() { [ "$OPT_DNS" = yes ] || { [ -z "$OPT_DNS" ] && dns_in_block; }; }
stock_named_on() { installed bind && { unit_active named || unit_enabled named; }; }

engine_env_block() {
  local want cur new
  [ -f "$ENV_FILE" ] || die "$ENV_FILE is missing (is the engine package installed?)"
  want="$(env_block_content)"
  cur="$(env_block_current)"
  if [ "$want" = "$cur" ]; then return 0; fi
  new="$(mktemp "${ENV_FILE}.XXXXXX")"
  awk -v b="$ENV_BEGIN" -v e="$ENV_END" '$0==b{f=1;next} $0==e{f=0;next} !f' "$ENV_FILE" >"$new"
  if [ -n "$want" ]; then printf '%s\n%s\n%s\n' "$ENV_BEGIN" "$want" "$ENV_END" >>"$new"; fi
  chmod --reference="$ENV_FILE" "$new"; chown --reference="$ENV_FILE" "$new"
  mv -f "$new" "$ENV_FILE"
  quiet restorecon "$ENV_FILE" || true
  flag_set env-changed
  changed "updated the installer block of $ENV_FILE"
}

# ------------------------------------------------------------------ stage: selinux
stage_selinux() {
  local b cil=/usr/share/oxpanel/selinux/oxpanel.cil any=0
  if ! quiet selinuxenabled; then note "SELinux is not enabled; nothing to do"; return 0; fi
  for b in httpd_enable_homedirs httpd_read_user_content httpd_unified; do
    if [ "$(getsebool "$b" 2>/dev/null | awk '{print $3}')" != on ]; then any=1; fi
  done
  if [ "$any" -eq 1 ]; then
    run setsebool -P httpd_enable_homedirs=on httpd_read_user_content=on httpd_unified=on || return 1
    changed "SELinux booleans httpd_enable_homedirs, httpd_read_user_content, httpd_unified set on"
  else note "SELinux booleans already on"; fi
  [ -r "$cil" ] || die "$cil is missing (engine package not installed?)"
  if semodule -l 2>/dev/null | grep -Eq '^oxpanel([[:space:]]|$)'; then
    note "policy module oxpanel is loaded"
  else
    run semodule -i "$cil" || return 1
    changed "loaded the oxpanel policy module"
  fi
  run restorecon -R /var/lib/oxpanel-acme /etc/pki/oxpanel || true
}

# ------------------------------------------------------------------ stage: nginx
stage_nginx() {
  run nginx -t || die "the existing Nginx configuration does not pass 'nginx -t'; fix it first"
  if ! unit_enabled nginx || ! unit_active nginx; then
    run systemctl enable --now nginx || return 1
    changed "nginx enabled and started"
  else note "nginx enabled and running"; fi
}

# ------------------------------------------------------------------ stage: mariadb
mariadb_sql() { mariadb --no-defaults --user=root -N -B -e "$1"; }

stage_mariadb() {
  if [ "$OPT_MARIADB" != yes ]; then note "skipped (--no-mariadb): tenant databases will be unavailable"; return 0; fi
  local ours=0 anon testdb want
  mkdir -p "$STATE_DIR"
  [ -e "$STATE_DIR/mariadb-installed-by-installer" ] && ours=1
  if installed mariadb-server; then
    if [ "$ours" -eq 0 ] && [ "$OPT_HARDEN_EXISTING" != yes ]; then
      note "MariaDB was already installed on this host: it is left exactly as it is"
      note "(to have OxPanel harden it as the handbook describes - remove anonymous accounts and the test database, no network listener - run again with --harden-existing-mariadb)"
      if ! unit_active mariadb; then warn "MariaDB is installed but not running; tenant databases are unavailable until it is started"; fi
      return 0
    fi
  else
    run dnf -y install mariadb-server || return 1
    : >"$STATE_DIR/mariadb-installed-by-installer"
    changed "mariadb-server installed"
  fi
  if ! unit_enabled mariadb || ! unit_active mariadb; then
    run systemctl enable --now mariadb || return 1
    changed "mariadb enabled and started"
  fi
  # HANDBOOK 3.5: what mysql_secure_installation does, without the prompts.
  anon="$(mariadb_sql "SELECT COUNT(*) FROM mysql.global_priv WHERE User=''")" || return 1
  testdb="$(mariadb_sql "SELECT (SELECT COUNT(*) FROM mysql.db WHERE Db='test' OR Db='test\\\\_%') + (SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='test')")" || return 1
  if [ "$anon" != 0 ] || [ "$testdb" != 0 ]; then
    run mariadb --no-defaults --user=root -e "DELETE FROM mysql.global_priv WHERE User=''; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\\\_%'; DROP DATABASE IF EXISTS test; FLUSH PRIVILEGES;" || return 1
    changed "removed $anon anonymous account(s) and the test database"
  else note "no anonymous accounts, no test database"; fi
  want="[mysqld]
skip-networking"
  if [ "$(cat "$MARIADB_CNF" 2>/dev/null || true)" != "$want" ]; then
    printf '%s\n' "$want" >"$MARIADB_CNF"; chmod 0644 "$MARIADB_CNF"; quiet restorecon "$MARIADB_CNF" || true
    run systemctl restart mariadb || return 1
    changed "MariaDB no longer listens on the network ($MARIADB_CNF); restarted"
  else note "MariaDB network listener already off"; fi
  if ss -H -ltn 2>/dev/null | grep -Eq ':3306[[:space:]]'; then die "MariaDB still listens on TCP 3306"; fi
  note "no TCP listener on 3306"
}

# ------------------------------------------------------------------ stage: php
stage_php() {
  if [ "$OPT_PHP" != yes ]; then note "skipped (--no-php): sites are static only"; return 0; fi
  local state in_use=0
  if ! installed php-fpm; then run dnf -y install php-fpm || return 1; changed "php-fpm installed"; fi
  # PHP's command-line interpreter runs the tenants' scheduled PHP tasks.
  if ! installed php-cli; then run dnf -y install php-cli || return 1; changed "php-cli installed"; fi
  if [ "$OPT_MARIADB" = yes ] && ! installed php-mysqlnd; then run dnf -y install php-mysqlnd || return 1; changed "php-mysqlnd installed"; fi
  state="$(systemctl is-enabled php-fpm.service 2>/dev/null || true)"
  if [ "$state" = masked ]; then note "the shared php-fpm.service is masked (every tenant has its own PHP-FPM)"; return 0; fi
  # A php-fpm that this installer brought in (marker, written before the first
  # package is installed) is nobody's; one that was there before is left running.
  if unit_active php-fpm.service && [ ! -e "$STATE_DIR/php-fpm-installed-by-installer" ]; then in_use=1; fi
  if [ "$in_use" -eq 1 ] && [ "$OPT_MASK_PHPFPM" != yes ]; then
    warn "the shared php-fpm.service is running, so it is NOT masked (something may use it). OxPanel never uses it; to switch it off run: systemctl mask --now php-fpm.service (or run this installer with --mask-php-fpm)"
    return 0
  fi
  run systemctl mask --now php-fpm.service || return 1
  changed "masked the shared php-fpm.service"
}

# ------------------------------------------------------------------ stage: daemon
stage_daemon() {

  if ! unit_enabled oxpanel-daemon || ! unit_active oxpanel-daemon; then
    run systemctl daemon-reload || return 1
    run systemctl enable --now oxpanel-daemon || return 1
    changed "oxpanel-daemon enabled and started"
  elif flag_is env-changed; then
    run systemctl restart oxpanel-daemon || return 1
    changed "oxpanel-daemon restarted to read its changed configuration"
  else note "oxpanel-daemon enabled and running"; fi
  for _ in $(seq 1 30); do [ -S /run/oxpanel/oxpanel.sock ] && break; sleep 1; done
  [ -S /run/oxpanel/oxpanel.sock ] || die "the engine socket did not appear; see: journalctl -u oxpanel-daemon"
}

# ------------------------------------------------------------------ stage: dns
stage_dns() {
  if ! dns_wanted; then
    if [ "$OPT_DNS" = no ] || [ -z "$(env_block_current | grep -E "$DNS_KEYS" || true)" ]; then
      rm -f "$FLAG_DIR/env-changed"
      engine_env_block
      if flag_is env-changed && unit_active oxpanel-daemon; then run systemctl restart oxpanel-daemon || return 1; fi
    fi
    note "DNS hosting not requested (--dns to switch it on)"; return 0
  fi
  local pkg ns1
  for pkg in bind bind-utils publicsuffix-list; do
    if ! installed "$pkg"; then run dnf -y install "$pkg" || return 1; changed "$pkg installed"; fi
  done
  # The distribution's named would hold port 53 and the control port. Decided
  # (and refused when not allowed) before any change; here it is carried out.
  if unit_active named || unit_enabled named; then
    run systemctl disable --now named || return 1
    changed "the distribution's named.service stopped and disabled (--disable-stock-named)"
  fi
  if [ "$OPT_DNS" = yes ]; then
    rm -f "$FLAG_DIR/env-changed"
    engine_env_block
    if flag_is env-changed && unit_active oxpanel-daemon; then run systemctl restart oxpanel-daemon || return 1; fi
  fi
  # The daemon renders the server's configuration and starts oxpanel-dns.service itself.
  for _ in $(seq 1 30); do unit_active oxpanel-dns && break; sleep 1; done
  unit_active oxpanel-dns || die "oxpanel-dns.service did not start; see: journalctl -u oxpanel-daemon -u oxpanel-dns"
  ns1="$(env_block_current | sed -n 's/^OXPANEL_DNS_NAMESERVERS=\([^,]*\).*/\1/p')"
  if dig +norec +time=2 +tries=2 @127.0.0.1 "${ns1:-example.invalid}" SOA 2>/dev/null | grep -q 'status:'; then
    note "oxpanel-dns answers on port 53 (authoritative only; no recursion)"
  else
    die "oxpanel-dns.service runs but does not answer on 127.0.0.1:53; see: journalctl -u oxpanel-dns"
  fi
}

# ------------------------------------------------------------------ stage: firewall
stage_firewall() {
  local svc zone any=0
  if ! unit_active firewalld; then
    note "firewalld is not running: no firewall was touched. If another firewall is in use, open ports 80 and 443 in it yourself."
    return 0
  fi
  zone="$(firewall-cmd --get-default-zone)"
  local svcs="http https"
  if dns_wanted; then svcs="http https dns"; fi
  for svc in $svcs; do
    if ! quiet firewall-cmd --permanent --query-service="$svc"; then run firewall-cmd --permanent --add-service="$svc" || return 1; any=1; fi
    if ! quiet firewall-cmd --query-service="$svc"; then run firewall-cmd --add-service="$svc" || return 1; any=1; fi
  done
  if [ "$any" -eq 1 ]; then changed "firewalld: ${svcs// /, } opened in zone $zone"; else note "firewalld already allows ${svcs// /, } in zone $zone"; fi
  # The panel's own HTTPS port (port mode; in host-name mode it shares 443).
  local pport; pport="$(panel_port)"
  if [ -n "$pport" ] && panel_installed; then
    any=0
    if ! quiet firewall-cmd --permanent --query-port="$pport/tcp"; then run firewall-cmd --permanent --add-port="$pport/tcp" || return 1; any=1; fi
    if ! quiet firewall-cmd --query-port="$pport/tcp"; then run firewall-cmd --add-port="$pport/tcp" || return 1; any=1; fi
    if [ "$any" -eq 1 ]; then changed "firewalld: panel port $pport/tcp opened in zone $zone"; else note "firewalld already allows the panel port $pport/tcp"; fi
  fi
  note "(only the default zone '$zone' was changed; interfaces in other zones are yours)"
}

# ------------------------------------------------------------------ stage: fail2ban
ban_action() {
  if unit_active firewalld; then echo firewallcmd-rich-rules; else echo nftables-multiport; fi
}

ssh_ports() {
  local p
  p="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -un | paste -sd, -)" || p=""
  echo "${p:-22}"
}

stage_fail2ban() {
  if [ "$OPT_FAIL2BAN" != yes ]; then note "not requested (--fail2ban): SSH/SFTP password guessing is limited only by sshd's own penalties"; return 0; fi
  local tmpl=/usr/share/oxpanel/fail2ban/oxpanel-sshd.local want action pkgs ips sess addr
  [ -r "$tmpl" ] || die "$tmpl is missing (engine package not installed?)"
  if ! installed fail2ban-server; then
    if ! installed epel-release; then
      [ "$OPT_EPEL" = yes ] || die "fail2ban is in EPEL and EPEL is not enabled; run again with --enable-epel to allow it"
      run dnf -y install epel-release || return 1
      changed "EPEL enabled (epel-release installed); it stays enabled so fail2ban gets its updates"
    fi
  fi
  action="$(ban_action)"
  pkgs="fail2ban-server"
  if [ "$action" = firewallcmd-rich-rules ]; then pkgs="$pkgs fail2ban-firewalld"; else pkgs="$pkgs nftables"; fi
  if ! installed fail2ban-selinux && quiet selinuxenabled; then pkgs="$pkgs fail2ban-selinux"; fi
  # shellcheck disable=SC2086  # $pkgs is a list of package names on purpose
  if ! quiet rpm -q $pkgs; then run dnf -y install $pkgs || return 1; changed "installed $pkgs"; fi
  # The addresses that are never banned: loopback, this session, what was asked for.
  ips="127.0.0.1/8 ::1"
  sess="$(session_addr)"
  if [ -n "$sess" ]; then ips="$ips $sess"; note "never banned: your current session address $sess"
  else warn "could not tell which address this session comes from; if you administer this host over SSH, add your address with --ignore-ip so a typo cannot ban you"; fi
  if [ -n "$OPT_IGNORE_IP" ]; then
    for addr in $(printf '%s' "$OPT_IGNORE_IP" | tr ',' ' '); do
      valid_ip "$addr" || die "--ignore-ip: '$addr' is not an address or network"
      ips="$ips $addr"
    done
  fi
  want="$(sed -e "s|@SSH_PORT@|$(ssh_ports)|" -e "s|@IGNORE_IP@|$ips|" -e "s|@BAN_ACTION@|$action|" "$tmpl")"
  mkdir -p /etc/fail2ban/jail.d
  if [ "$(cat "$JAIL_FILE" 2>/dev/null || true)" != "$want" ]; then
    printf '%s\n' "$want" >"$JAIL_FILE"; chmod 0644 "$JAIL_FILE"; quiet restorecon "$JAIL_FILE" || true
    changed "wrote $JAIL_FILE (ban action $action, ignoreip: $ips)"
    flag_set jail-changed
  else note "jail configuration already in place"; fi
  if ! unit_enabled fail2ban || ! unit_active fail2ban; then
    run systemctl enable --now fail2ban || return 1
    changed "fail2ban enabled and started"
  elif flag_is jail-changed; then
    run systemctl restart fail2ban || return 1
  fi
  for _ in $(seq 1 20); do quiet fail2ban-client status sshd && break; sleep 1; done
  quiet fail2ban-client status sshd || die "the sshd jail is not running; see: journalctl -u fail2ban"
  note "jail sshd is running ($(fail2ban-client status sshd | sed -n 's/.*Currently banned:[[:space:]]*//p') currently banned)"
}

# ------------------------------------------------------------------ stage: quota
# Prints "target fstype options" of the file system holding $1.
fs_of() {
  local p="$1"
  while [ ! -e "$p" ] && [ "$p" != / ]; do p="$(dirname "$p")"; done
  findmnt -no TARGET,FSTYPE,OPTIONS -T "$p"
}

grub_flags_of_default() { grubby --info=DEFAULT 2>/dev/null | sed -n 's/^args="\(.*\)"$/\1/p' | tr ' ' '\n' | sed -n 's/^rootflags=//p' | head -1; }

stage_quota() {
  local base target fstype opts flags newopts line tmp
  base="$(home_base)"
  read -r target fstype opts <<<"$(fs_of "$base")"
  if [ "$fstype" != xfs ]; then
    note "tenant homes ($base) are on $fstype, not XFS: disk limits cannot be offered on this host (see HANDBOOK 9.1); everything else works"
    return 0
  fi
  if printf '%s' "$opts" | tr ',' '\n' | grep -qx usrquota; then note "user quotas are active on $target"; return 0; fi
  if [ "$target" = / ] && command -v grubby >/dev/null && grub_flags_of_default | tr ',' '\n' | grep -qx uquota; then
    flag_set reboot-required
    note "user quotas are not active yet: the kernel argument rootflags=uquota is set and waits for a reboot"
    return 0
  fi
  if [ "$OPT_QUOTA" != yes ]; then
    note "user quotas are NOT active on $target, so per-customer disk limits are refused. Not changed (ask for it with --quota; HANDBOOK 9.1)."
    return 0
  fi
  quiet dnf -y install xfsprogs || true
  if [ "$target" = / ]; then
    command -v grubby >/dev/null || die "grubby is missing; cannot set the kernel argument (HANDBOOK 9.1 shows the manual steps)"
    flags="$(grub_flags_of_default)"
    if printf '%s' "$flags" | tr ',' '\n' | grep -qx uquota; then
      note "the kernel argument rootflags=uquota is already set; waiting for a reboot"
    elif [ -n "$flags" ]; then
      run grubby --update-kernel=ALL --remove-args="rootflags=$flags" --args="rootflags=$flags,uquota" || return 1
      changed "kernel argument rootflags=$flags changed to rootflags=$flags,uquota for all boot entries"
    else
      run grubby --update-kernel=ALL --args=rootflags=uquota || return 1
      changed "kernel argument rootflags=uquota added to all boot entries"
    fi
  else
    # /home (or the home base) is a file system of its own: its mount options.
    grep -qE "^[^#]*[[:space:]]${target}[[:space:]]+xfs[[:space:]]" /etc/fstab || die "$target is mounted but has no XFS line in /etc/fstab (a systemd .mount unit?): add the uquota mount option there yourself (HANDBOOK 9.1)"
    if awk -v t="$target" '$1!~/^#/ && $2==t && $3=="xfs" {print $4}' /etc/fstab | tr ',' '\n' | grep -Eqx 'uquota|usrquota|quota'; then
      note "/etc/fstab already has the quota option for $target; waiting for a remount or reboot"
    else
      [ -e /etc/fstab.oxpanel-installer.bak ] || cp -p /etc/fstab /etc/fstab.oxpanel-installer.bak
      tmp="$(mktemp /etc/fstab.XXXXXX)"
      awk -v t="$target" '$1!~/^#/ && $2==t && $3=="xfs" { $4=$4",uquota" } {print}' /etc/fstab >"$tmp"
      newopts="$(awk -v t="$target" '$1!~/^#/ && $2==t && $3=="xfs" {print $4}' "$tmp")"
      [ -n "$newopts" ] || { rm -f "$tmp"; die "could not edit /etc/fstab"; }
      chmod --reference=/etc/fstab "$tmp"; chown --reference=/etc/fstab "$tmp"
      mv -f "$tmp" /etc/fstab; quiet restorecon /etc/fstab || true
      run systemctl daemon-reload || return 1
      line="$(grep -E "[[:space:]]${target}[[:space:]]+xfs" /etc/fstab | head -1)"
      changed "/etc/fstab: uquota added for $target (original saved as /etc/fstab.oxpanel-installer.bak): $line"
    fi
  fi
  flag_set reboot-required
  note "REBOOT NEEDED: the quota option takes effect when the file system is next mounted"
  if [ "$target" != / ]; then note "(or: stop everything using $target, then umount $target && mount $target)"; fi
}

# ------------------------------------------------------------------ stage: panel
stage_panel() {
  local uid rpmfile name want_scopes="$OPT_PANEL_SCOPES" before tver
  if [ "$OPT_PANEL_ACCOUNT" != yes ]; then note "no panel requested (--panel-rpm FILE, or --panel-account)"; return 0; fi
  if [ -n "$OPT_PANEL_RPM" ]; then
    rpmfile="$OPT_PANEL_RPM"
    [ -r "$rpmfile" ] || die "cannot read $rpmfile"
    verify_checksum "$rpmfile"
    name="$(rpm_field "$rpmfile" NAME)"
    case "$name" in oxpanel-panel*) ;; *) die "$rpmfile is not an OxPanel panel package (name: $name)";; esac
    tver="$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$rpmfile" 2>/dev/null)"
    before="$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$name" 2>/dev/null || true)"
    if ! installed "$name"; then run dnf -y install "$rpmfile" || return 1; changed "installed $name $tver"
    elif [ "$before" = "$tver" ]; then note "$name $before is already installed"
    elif version_lt "$before" "$tver"; then run dnf -y install "$rpmfile" || return 1; changed "$name $before -> $tver"
    else warn "$name $before is newer than $rpmfile ($tver); not downgraded"; fi
  fi
  # The panel service account: no login, member of the engine's group, which is
  # all the engine checks (HANDBOOK 5). A panel package usually creates it with
  # sysusers; this repairs or creates it otherwise.
  getent group oxpanel >/dev/null || die "group oxpanel is missing (engine package not installed?)"
  if ! getent passwd panelapi >/dev/null; then
    run useradd -r -G oxpanel -s /sbin/nologin -c "OxPanel panel API" panelapi || return 1
    changed "created the panelapi account in group oxpanel"
  elif ! id -nG panelapi | tr ' ' '\n' | grep -qx oxpanel; then
    run usermod -aG oxpanel panelapi || return 1
    changed "added panelapi to group oxpanel"
  else note "panelapi exists and is in group oxpanel"; fi
  # Peer scopes: the panel needs every scope (it creates and deletes accounts),
  # so the default is none. Offered only for a setup that wants less.
  if [ -n "$want_scopes" ]; then
    printf '%s' "$want_scopes" | grep -Eq '^(read|vhost|tenant|delete|all)(\+(read|vhost|tenant|delete|all))*$' || die "--panel-scopes: '$want_scopes' is not a '+'-separated list of read, vhost, tenant, delete, all"
    uid="$(id -u panelapi)"
    if grep -Eq '^[[:space:]]*OXPANEL_PEER_SCOPES=' "$ENV_FILE" && ! sed -n "/^$ENV_BEGIN\$/,/^$ENV_END\$/p" "$ENV_FILE" | grep -q OXPANEL_PEER_SCOPES; then
      OPT_PANEL_SCOPES=""
      warn "$ENV_FILE already sets OXPANEL_PEER_SCOPES; it was not changed. Add ${uid}:${want_scopes} to it yourself."
      return 0
    fi
    rm -f "$FLAG_DIR/env-changed"
    engine_env_block
    if flag_is env-changed && unit_active oxpanel-daemon; then run systemctl restart oxpanel-daemon || return 1; fi
  fi
}

# ------------------------------------------------------------------ stage: panelweb
# The panel package brings `oxpanel-panel-setup` (it owns the panel's Nginx
# block, certificate and proxy secret); this stage asks it to put the panel on
# HTTPS, starts the service and creates the first administrator.
PANEL_SETUP=/usr/sbin/oxpanel-panel-setup
panel_installed() { installed oxpanel-panel && [ -x "$PANEL_SETUP" ]; }

panel_mode_args() {
  if [ -n "$OPT_PANEL_HOSTNAME" ]; then printf -- '--hostname %s' "$OPT_PANEL_HOSTNAME"
  elif [ -n "$OPT_PANEL_PORT" ]; then printf -- '--port %s' "$OPT_PANEL_PORT"; fi
}

# The panel's port in port mode (as configured), else nothing.
panel_port() {
  [ -r /etc/oxpanel-panel/setup.conf ] || return 0
  if grep -qx 'MODE=port' /etc/oxpanel-panel/setup.conf; then sed -n 's/^PORT=//p' /etc/oxpanel-panel/setup.conf | tail -1; fi
}

# What `oxpanel-panel-setup enable` writes, as one checksum (files may not exist yet).
panel_web_state() { { cat /etc/nginx/conf.d/00-oxpanel-panel.conf /etc/oxpanel-panel/setup.conf 2>/dev/null || true; } | sha256sum; }

stage_panelweb() {
  local before after out code args name="${OPT_PANEL_ADMIN:-admin}"
  if ! panel_installed; then note "no panel installed"; return 0; fi
  if [ -n "$OPT_PANEL_PORT" ] && [ -n "$OPT_PANEL_HOSTNAME" ]; then die "--panel-port and --panel-hostname exclude each other"; fi
  before="$(panel_web_state)"
  args="$(panel_mode_args)"
  # shellcheck disable=SC2086  # $args is "--port N" or "--hostname NAME", validated by the setup tool
  run "$PANEL_SETUP" enable $args || return 1
  after="$(panel_web_state)"
  if [ "$before" != "$after" ]; then changed "panel served by Nginx at $("$PANEL_SETUP" url)"; else note "panel already served at $("$PANEL_SETUP" url)"; fi
  if ! unit_enabled oxpanel-panel || ! unit_active oxpanel-panel; then
    run systemctl enable --now oxpanel-panel || return 1
    changed "oxpanel-panel enabled and started"
  elif [ "$before" != "$after" ]; then
    run systemctl restart oxpanel-panel || return 1
  else note "oxpanel-panel enabled and running"; fi
  # The first administrator: created once, with a random password that is shown
  # once (at the end of this run) and must be changed at the first sign-in. The
  # output never goes to the log.
  printf '+ %s bootstrap-admin %s (output not logged)\n' "$PANEL_SETUP" "$name" >>"$LOG"
  if out="$("$PANEL_SETUP" bootstrap-admin "$name" 2>&1)"; then
    # FLAG_DIR is this run's private temporary directory (0700, removed at exit).
    printf '%s\n' "$out" | sed -n 's/^temporary password:[[:space:]]*//p' >"$FLAG_DIR/panel-admin-password"
    printf '%s\n' "$name" >"$FLAG_DIR/panel-admin"
    changed "panel administrator '$name' created (one-time password at the end of this run)"
  elif printf '%s' "$out" | grep -q 'an administrator already exists'; then
    note "the panel already has an administrator (lost access: panel-api reset-password, see the panel's README)"
  else
    printf '%s\n' "$out" | grep -v -i 'password' >>"$LOG" || true
    die "could not create the panel's first administrator: $(printf '%s' "$out" | grep -v -i 'password' | head -3)"
  fi
  for _ in $(seq 1 20); do
    code="$("$PANEL_SETUP" status 2>/dev/null | sed -n 's/^health:[[:space:]]*HTTP //p')"
    [ "$code" = 200 ] && break; sleep 1
  done
  [ "$code" = 200 ] || die "the panel does not answer over HTTPS (HTTP ${code:-none}); see: journalctl -u oxpanel-panel -u nginx"
  note "panel answers over HTTPS: $("$PANEL_SETUP" url)"
}

# ------------------------------------------------------------------ stage: verify
stage_verify() {
  local out rc=0
  if ! oxpanel-daemon --check-config >>"$LOG" 2>&1; then die "oxpanel-daemon --check-config failed (see $LOG)"; fi
  note "oxpanel-daemon --check-config: ok"
  out="$(oxpanel-ctl host info 2>&1)" || { printf '%s\n' "$out" >>"$LOG"; die "oxpanel-ctl host info failed: $out"; }
  printf '%s\n' "$out" >>"$LOG"
  printf '%s\n' "$out" | sed -n '1p' | cut -c1-200 | sed 's/^/      host info: /'
  printf '%s\n' "$out" | grep -E '^(database_engine|disk_quota_detail)=' | cut -c1-200 | sed 's/^/      host info: /' || true
  out="$(oxpanel-ctl host reconcile 2>&1)" || rc=$?
  printf '%s\n' "$out" >>"$LOG"
  case "$rc" in
    0) note "host reconcile: clean";;
    3) warn "host reconcile reports drift (details in $LOG); most findings are healed by repeating the original request"; printf '%s\n' "$out" | head -20 | sed 's/^/      /';;
    *) die "oxpanel-ctl host reconcile failed (exit $rc): $out";;
  esac
  if [ "$OPT_FAIL2BAN" = yes ]; then quiet fail2ban-client status sshd || die "fail2ban jail sshd is not running"; note "fail2ban jail sshd: running"; fi
  if panel_installed && [ -e /etc/nginx/conf.d/00-oxpanel-panel.conf ]; then
    unit_active oxpanel-panel || die "oxpanel-panel.service is not running; see: journalctl -u oxpanel-panel"
    "$PANEL_SETUP" status >/dev/null 2>&1 || die "the panel does not answer over HTTPS; see: oxpanel-panel-setup status"
    note "panel: running, answers over HTTPS at $("$PANEL_SETUP" url)"
  fi
  if dns_wanted; then
    unit_active oxpanel-dns || die "DNS hosting is configured but oxpanel-dns.service is not running"
    oxpanel-ctl host info 2>&1 | grep -q '^dns=true .*dns_available=true' || warn "the engine does not report DNS hosting as available; see: oxpanel-ctl host info | grep ^dns"
    note "DNS hosting: oxpanel-dns running"
  fi
  if [ "$OPT_QUOTA" = yes ] && ! flag_is reboot-required; then
    if oxpanel-ctl host info 2>&1 | grep -q ' disk_quota=true '; then note "disk quotas: active"; else warn "disk quotas were requested but the engine reports them unavailable"; fi
  fi
}

# ------------------------------------------------------------------ uninstall
count_files() { find "$1" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l; }

do_uninstall() {
  local tenants vhosts
  [ "$(id -u)" -eq 0 ] || die "run as root"
  mkdir -p "$STATE_DIR"
  tenants="$(count_files /var/lib/oxpanel/tenants)"; vhosts="$(count_files /var/lib/oxpanel/vhosts)"
  say "This removes the OxPanel engine (and the panel package, if installed) and OxPanel's own"
  say "configuration. It does not touch customers: $tenants tenant account(s), $vhosts site(s), their homes, databases and backups stay."
  if [ "$OPT_YES" -ne 1 ]; then
    if [ "$INTERACTIVE" -ne 1 ] || ! ask "Remove OxPanel now?"; then say "Nothing removed."; exit 0; fi
  fi
  # dnf would also remove the packages that only the engine pulled in (Nginx, ...),
  # which would take the customers' sites down. Keep every one of them.
  for pkg in nginx php-fpm php-cli nodejs npm mariadb-server openssl acl openssh-server xfsprogs bind bind-utils publicsuffix-list; do
    if installed "$pkg"; then run dnf -y mark install "$pkg" || true; fi
  done
  local pport; pport="$(panel_port)"
  if installed oxpanel-panel; then
    # The package's own removal scriptlet takes the panel off Nginx and stops it.
    run dnf -y remove --noautoremove oxpanel-panel || die "could not remove oxpanel-panel"
    say "removed: oxpanel-panel (panel API, web interface, its Nginx server block, its SELinux module)"
  fi
  if [ -n "$pport" ] && unit_active firewalld && quiet firewall-cmd --permanent --query-port="$pport/tcp"; then
    run firewall-cmd --permanent --remove-port="$pport/tcp" || true; run firewall-cmd --remove-port="$pport/tcp" || true
    say "closed: the panel's port $pport/tcp in firewalld"
  fi
  if [ "$OPT_PURGE_PANEL" = yes ]; then
    rm -rf /var/lib/oxpanel-panel /etc/oxpanel-panel /etc/pki/oxpanel-panel /var/lib/oxpanel-panel-acme
    say "deleted (--purge-panel): the panel's database /var/lib/oxpanel-panel, /etc/oxpanel-panel, /etc/pki/oxpanel-panel"
  elif [ -d /var/lib/oxpanel-panel ]; then
    say "kept: the panel's database /var/lib/oxpanel-panel (people, plans, audit log), /etc/oxpanel-panel and its"
    say "      certificate /etc/pki/oxpanel-panel; a reinstalled panel continues with them (--purge-panel deletes them)"
  fi
  if unit_active oxpanel-daemon || unit_enabled oxpanel-daemon; then run systemctl disable --now oxpanel-daemon || true; fi
  if installed oxpanel-daemon; then run dnf -y remove --noautoremove oxpanel-daemon || die "could not remove oxpanel-daemon"; say "removed: oxpanel-daemon (engine, oxpanel-ctl, oxpanel-acme, unit, SELinux module)"; fi
  if [ -e "$JAIL_FILE" ]; then rm -f "$JAIL_FILE"; say "removed: $JAIL_FILE"; if unit_active fail2ban; then run systemctl restart fail2ban || true; fi; fi
  if [ -e "$REPO_FILE" ]; then rm -f "$REPO_FILE"; say "removed: $REPO_FILE"; fi
  if [ -f "$ENV_FILE" ]; then
    # Only reachable when the file was edited (rpm keeps those as .rpmsave).
    say "kept: $ENV_FILE"
  fi
  say ""
  say "LEFT IN PLACE on purpose (customers' data and what keeps their sites running):"
  say "  - tenant accounts and homes (${tenants} tenant(s)), /var/lib/oxpanel (the records; reinstalling resumes from them)"
  say "  - jobs in progress (backups, restores, file-manager jobs, a customer deletion): their records stay in"
  say "    /var/lib/oxpanel; a transient job unit runs to its end, and a reinstalled engine concludes or continues each one"
  say "  - databases: MariaDB and everything in it, and $MARIADB_CNF, including deleted databases in the trash"
  say "    (oxpanel_trash_* schemas: purged after their trash period only by the engine, so not while it is uninstalled)"
  say "  - backups: /var/lib/oxpanel-backups; certificates and keys: /etc/pki/oxpanel"
  say "  - /etc/nginx/oxpanel.d and /etc/nginx/conf.d/00-oxpanel.conf (the sites keep being served by Nginx)"
  say "  - /etc/ssh/sshd_config.d/60-oxpanel.conf and /etc/oxpanel-sftp (SFTP confinement and keys)"
  say "  - DNS hosting data: zones and DNSSEC signing keys in /var/lib/oxpanel-dns, the server's configuration and"
  say "    TSIG/rndc keys in /etc/named/oxpanel, zone records in /var/lib/oxpanel/dns-zones. oxpanel-dns.service went"
  say "    with the package, so THE HOSTED DOMAINS DO NOT RESOLVE until a reinstall (secondaries keep answering"
  say "    until their zones expire). Keep the signing keys: new ones would need a new DS at every registrar"
  say "  - per-tenant slices, PHP-FPM, application and scheduled-task units (they keep running and the tasks keep firing;"
  say "    the engine can no longer manage them; scheduled backups, which the engine itself starts, pause until a reinstall;"
  say "    Node.js/Python applications and scheduled tasks need the OxPanel SELinux module, which the package removal took out: reinstall to restore it)"
  say "  - nginx, MariaDB, PHP-FPM, Node.js, fail2ban, EPEL, firewall rules: installed packages and settings are yours now"
  say "  - the oxpanel groups and /var/lib/oxpanel-installer, $LOG"
  printf 'result=uninstalled\nfinished=%s\n' "$(date -u +%FT%TZ)" >"$STATE_DIR/status"
  say "RESULT: uninstalled"
}

# ------------------------------------------------------------------ main
main() {
  parse_args "$@"
  [ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root (sudo ./install.sh)" >&2; exit 1; }
  mkdir -p "$STATE_DIR"; chmod 0700 "$STATE_DIR"
  : >>"$LOG"; chmod 0600 "$LOG"
  load_answers
  # A release bundle that contains the panel installs it (--no-panel: not).
  if [ -z "$OPT_PANEL_RPM" ] && [ "$OPT_NO_PANEL" != yes ] && [ "$OPT_UNINSTALL" -ne 1 ]; then
    local f
    for f in "$HERE"/oxpanel-panel-[0-9]*.rpm; do
      if [ -e "$f" ]; then OPT_PANEL_RPM="$f"; OPT_PANEL_ACCOUNT=yes; fi
    done
  fi
  if [ "$OPT_NO_PANEL" = yes ]; then OPT_PANEL_RPM=""; fi
  if [ "$OPT_YES" -ne 1 ] && [ -t 0 ] && [ -t 1 ]; then INTERACTIVE=1; fi
  FLAG_DIR="$(mktemp -d)"; CHANGE_FILE="$FLAG_DIR/changes"; WARN_FILE="$FLAG_DIR/warnings"; : >"$CHANGE_FILE"; : >"$WARN_FILE"
  trap 'rm -rf "$FLAG_DIR"' EXIT
  say "OxPanel installer $INSTALLER_VERSION ($(date -u +%FT%TZ)); log: $LOG"

  if [ "$OPT_UNINSTALL" -eq 1 ]; then do_uninstall; exit 0; fi

  say "[preflight] checking the host"
  preflight
  find_engine_rpm
  if [ -n "$ENGINE_RPM" ]; then say "      engine package: $ENGINE_RPM"; fi
  if [ "$OPT_CHECK" -eq 1 ]; then say "RESULT: preflight ok"; exit 0; fi

  # Decisions come first so that the rest can run unattended.
  decide OPT_FAIL2BAN "Login banning: fail2ban watches sshd's log in the journal and blocks an address
for an hour (longer for repeat offenders) after 5 failed SSH/SFTP logins. It guards tenants' SFTP
passwords against guessing. fail2ban is not in AlmaLinux's own repositories but in EPEL." "Install and enable fail2ban?"
  if [ "$OPT_FAIL2BAN" = yes ] && ! installed epel-release && ! installed fail2ban-server; then
    decide OPT_EPEL "Enabling EPEL: EPEL (Extra Packages for Enterprise Linux) is a community repository run by
the Fedora project. Enabling it adds a package source that dnf will use for updates from now on, with packages
that Red Hat and AlmaLinux do not vouch for. OxPanel installs only fail2ban from it, but the repository stays
enabled afterwards (fail2ban needs its updates). Disable it later with: dnf config-manager --set-disabled epel" "Enable EPEL?"
    [ "$OPT_EPEL" = yes ] || die "fail2ban needs EPEL, and EPEL was not allowed. Run again with --enable-epel, or with --no-fail2ban."
  fi
  if [ "$OPT_FAIL2BAN" = yes ] && [ "$INTERACTIVE" -eq 1 ] && [ -z "$OPT_IGNORE_IP" ]; then
    printf '\nAddresses fail2ban must never ban (comma separated; your session address %s is added automatically): ' "$(session_addr)" >&2
    read -r OPT_IGNORE_IP || OPT_IGNORE_IP=""
  fi
  check_quota_offer
  decide_dns
  say "decisions: fail2ban=${OPT_FAIL2BAN:-no} epel=${OPT_EPEL:-no} quota=${OPT_QUOTA:-no} reboot=${OPT_REBOOT:-no} mariadb=$OPT_MARIADB php=$OPT_PHP nodejs=$OPT_NODEJS dns=$(dns_wanted && echo yes || echo no)$([ "$INTERACTIVE" -eq 1 ] && echo ' (interactive)' || echo ' (unattended)')"

  if ! installed php-fpm && [ ! -e "$STATE_DIR/php-fpm-installed-by-installer" ]; then : >"$STATE_DIR/php-fpm-installed-by-installer"; fi
  stage nodejs   "Node.js 22 module stream"                      stage_nodejs
  stage engine   "OxPanel engine package"                        stage_engine
  stage selinux  "SELinux booleans and the OxPanel policy module" stage_selinux
  stage nginx    "Nginx enabled"                                  stage_nginx
  stage mariadb  "MariaDB (tenant databases)"                     stage_mariadb
  stage php      "PHP-FPM, shared pool masked"                    stage_php
  stage panel    "panel hook (optional)"                          stage_panel
  stage daemon   "oxpanel-daemon service"                         stage_daemon
  stage dns      "DNS hosting (optional): BIND as oxpanel-dns"    stage_dns
  stage panelweb "panel: HTTPS, service, first administrator (optional)" stage_panelweb
  stage firewall "firewalld: ports 80 and 443 (53 with DNS, the panel's port)" stage_firewall
  stage fail2ban "login banning with fail2ban (optional)"         stage_fail2ban
  stage quota    "disk quotas (optional)"                         stage_quota
  stage verify   "final verification"                             stage_verify
  finish
}

# DNS hosting: asked (interactive) or taken from flags; the operator's values are
# required and never guessed; the distribution's named is never stopped unasked.
decide_dns() {
  local n
  if [ -z "$OPT_DNS" ] && dns_in_block; then return 0; fi
  decide OPT_DNS "DNS hosting: this host can be the authoritative name server of its customers' domains
(BIND, run by OxPanel as oxpanel-dns.service; zones are created for sites by themselves). You need two
name-server host names under a domain you control and this host's public address(es); port 53 (TCP and
UDP) is opened in firewalld." "Set up DNS hosting?"
  [ "$OPT_DNS" = yes ] || return 0
  if [ "$INTERACTIVE" -eq 1 ]; then
    if [ -z "$OPT_DNS_NAMESERVERS" ]; then printf 'Name servers (comma separated, e.g. ns1.example.net,ns2.example.net): ' >&2; read -r OPT_DNS_NAMESERVERS || true; fi
    if [ -z "$OPT_DNS_CONTACT" ]; then printf 'SOA contact (e.g. hostmaster@example.net): ' >&2; read -r OPT_DNS_CONTACT || true; fi
    if [ -z "$OPT_DNS_IPV4" ] && [ -z "$OPT_DNS_IPV6" ]; then
      printf "This host's PUBLIC IPv4 address (empty for none): " >&2; read -r OPT_DNS_IPV4 || true
      printf "This host's PUBLIC IPv6 address (empty for none): " >&2; read -r OPT_DNS_IPV6 || true
    fi
  fi
  printf '%s' "$OPT_DNS_NAMESERVERS" | grep -Eq '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(,[a-z0-9]([a-z0-9.-]*[a-z0-9])?)*$' \
    || die "DNS hosting needs the name servers' host names: --dns-nameservers ns1.example.net,ns2.example.net"
  printf '%s' "$OPT_DNS_CONTACT" | grep -Eq '^[a-z0-9._-]+@[a-z0-9]([a-z0-9.-]*[a-z0-9])?$' \
    || die "DNS hosting needs the SOA contact: --dns-contact hostmaster@example.net"
  [ -n "$OPT_DNS_IPV4" ] || [ -n "$OPT_DNS_IPV6" ] || die "DNS hosting needs this host's public address: --dns-ipv4 and/or --dns-ipv6 (never guessed)"
  if [ -n "$OPT_DNS_IPV4" ]; then printf '%s' "$OPT_DNS_IPV4" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || die "--dns-ipv4: '$OPT_DNS_IPV4' is not an IPv4 address"; fi
  if [ -n "$OPT_DNS_IPV6" ]; then printf '%s' "$OPT_DNS_IPV6" | grep -Eq '^[0-9a-fA-F:]+$' || die "--dns-ipv6: '$OPT_DNS_IPV6' is not an IPv6 address"; fi
  if grep -Eq "^[[:space:]]*OXPANEL_DNS=" "$ENV_FILE" 2>/dev/null && ! dns_in_block && ! env_block_current | grep -q '^OXPANEL_DNS='; then
    die "$ENV_FILE already configures DNS hosting outside the installer's block; change it there, or remove those lines and run again"
  fi
  if stock_named_on; then
    n="$(grep -cE '^[[:space:]]*zone[[:space:]]' /etc/named.conf 2>/dev/null || echo 0)"
    if [ "$OPT_DISABLE_STOCK_NAMED" != yes ]; then
      if [ "$INTERACTIVE" -eq 1 ] && ask "The distribution's named.service is running or enabled ($n zone statement(s) in /etc/named.conf); it would hold port 53. Stop and disable it?"; then
        OPT_DISABLE_STOCK_NAMED=yes
      else
        die "the distribution's named.service is running or enabled ($n zone statement(s) in /etc/named.conf, which may serve real zones). It would hold port 53. Move what it serves, then run again with --disable-stock-named (nothing was changed)."
      fi
    fi
  fi
}

# The disk-quota question, asked only where it makes sense.
check_quota_offer() {
  local base target fstype opts
  base="$(home_base)"
  read -r target fstype opts <<<"$(fs_of "$base")"
  if [ "$fstype" != xfs ] || printf '%s' "$opts" | tr ',' '\n' | grep -qx usrquota; then return 0; fi
  decide OPT_QUOTA "Disk quotas: per-customer disk limits need XFS user quotas on $target (which holds tenant homes).
XFS enables them only when the file system is mounted, so this changes the boot configuration
($([ "$target" = / ] && echo "the kernel argument rootflags=uquota, via grubby" || echo "the mount options of $target in /etc/fstab")) and takes effect after a reboot. Nothing is
lost or reformatted. Without it everything works except that a disk limit on a customer is refused." "Prepare disk quotas?"
  if [ "$OPT_QUOTA" = yes ]; then
    decide OPT_REBOOT "Reboot: the quota setting needs one. I can reboot the machine myself at the very end, after
everything else is installed and checked, or leave it to you and tell you exactly what remains." "Reboot automatically at the end if needed?"
  fi
}

finish() {
  local n w reboot=no
  n="$(wc -l <"$CHANGE_FILE")"; w="$(wc -l <"$WARN_FILE")"
  if flag_is reboot-required; then reboot=yes; fi
  say ""
  if [ "$w" -gt 0 ]; then say "Warnings ($w):"; sed 's/^/  - /' "$WARN_FILE"; fi
  if [ -s "$FLAG_DIR/panel-admin" ]; then
    # Printed to the terminal only, never to the log.
    printf '\nThe panel: %s\n' "$("$PANEL_SETUP" url)"
    printf '  administrator:      %s\n' "$(cat "$FLAG_DIR/panel-admin")"
    printf '  one-time password:  %s\n' "$(cat "$FLAG_DIR/panel-admin-password" 2>/dev/null)"
    printf '  It is shown only now. Sign in, then choose a new password and set up two-factor authentication.\n'
    printf '  The certificate is self-signed until you install your own:\n'
    printf '    oxpanel-panel-setup certificate --cert FULLCHAIN.pem --key KEY.pem\n\n'
    say "panel administrator created; its one-time password was printed on the terminal (not logged)"
  elif panel_installed && [ -e /etc/nginx/conf.d/00-oxpanel-panel.conf ]; then
    say "The panel: $("$PANEL_SETUP" url)"
  fi
  printf 'result=ok\nversion=%s\nchanges=%s\nwarnings=%s\nreboot_required=%s\nfinished=%s\n' "$(cur_version)" "$n" "$w" "$reboot" "$(date -u +%FT%TZ)" >"$STATE_DIR/status"
  if [ "$reboot" = yes ]; then
    say "RESULT: ok changes=$n warnings=$w reboot_required=yes"
    if [ "$OPT_REBOOT" = yes ]; then
      say "Rebooting now so that disk quotas take effect. After the reboot run this installer again:"
      say "    sudo $HERE/install.sh$([ "$OPT_YES" -eq 1 ] && echo ' --yes') --quota"
      say "it notices that quotas are active and finishes the verification."
      systemctl reboot
    else
      say ""
      say "What remains: a reboot, so that disk quotas take effect. Everything else is installed and running."
      say "  1. reboot when it suits you:   sudo systemctl reboot"
      say "  2. afterwards run again:       sudo $HERE/install.sh$([ "$OPT_YES" -eq 1 ] && echo ' --yes') --quota"
      say "     (it notices that quotas are active and finishes the verification; 'oxpanel-ctl host info' then shows disk_quota=true)"
    fi
  else
    say "RESULT: ok changes=$n warnings=$w reboot_required=no"
  fi
}

main "$@"
