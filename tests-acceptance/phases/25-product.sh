#!/usr/bin/env bash
# Phase 25 — the whole product (INSTALL=product): engine + panel + web interface,
# installed by install.sh from a release bundle that includes the panel RPM.
# The panel is checked as a deployed service (unit, sandbox, SELinux domain,
# socket, files, Nginx), then the product is driven through the panel's HTTPS
# API exactly as a browser does (phases/product/drive.py), and what tenant code
# on the same host can reach of the panel is attacked directly.
cd "$(dirname "$0")/.."; source phases/lib.sh
echo "== phase 25: the product through the panel's HTTPS API"
AVC0=$(avc_count)
rpm -q oxpanel-panel >/dev/null 2>&1 || { fail "oxpanel-panel is not installed (INSTALL=product installs it)"; phase_end; }
[ -s panel-admin.once ] || { fail "phase 10 did not capture the first administrator's one-time password"; phase_end; }
URL="$(oxpanel-panel-setup url)"
PORT="$(sed -n 's/^PORT=//p' /etc/oxpanel-panel/setup.conf)"
LOCAL="https://127.0.0.1:${PORT}"
info "panel: $(rpm -q oxpanel-panel) at $URL"

# ------------------------------------------------------------ the deployed service
check "rpm -V oxpanel-panel is clean" rpm -V oxpanel-panel
check "oxpanel-panel is enabled and active" bash -c 'systemctl -q is-enabled oxpanel-panel && systemctl -q is-active oxpanel-panel'
PID="$(systemctl show -p MainPID --value oxpanel-panel)"
check "it runs as panelapi" test "$(ps -o user= -p "$PID")" = panelapi
check "panelapi is in group oxpanel (the engine checks the account database)" bash -c 'id -nG panelapi | tr " " "\n" | grep -qx oxpanel'
check "panelapi has no login shell" bash -c 'getent passwd panelapi | grep -Eq ":/(usr/)?sbin/nologin$"'
check "it runs in its own SELinux domain" bash -c "ps -o label= -p $PID | grep -q ':oxpanel_panel_t:'"
info "panel process label: $(ps -o label= -p "$PID")"
check "it holds no capabilities (effective, permitted, bounding)" bash -c "test \"\$(grep -E '^Cap(Eff|Prm|Bnd):' /proc/$PID/status | awk '{print \$2}' | sort -u)\" = 0000000000000000"
check "NoNewPrivs is set" bash -c "grep -q '^NoNewPrivs:[[:space:]]*1' /proc/$PID/status"
check "the policy module oxpanel-panel is loaded" bash -c 'semodule -l | grep -qx oxpanel-panel'
check "socket directory is panelapi:nginx 2750, labelled for the web server" bash -c 'test "$(stat -c "%U:%G %a" /run/oxpanel-panel)" = "panelapi:nginx 2750" && ls -dZ /run/oxpanel-panel | grep -q ":httpd_var_run_t:"'
check "the socket is panelapi:nginx 0660" test "$(stat -c '%U:%G %a %F' /run/oxpanel-panel/panel.sock)" = "panelapi:nginx 660 socket"
check "the panel listens on no TCP port" bash -c "! ss -H -ltnp | grep -q 'pid=$PID,'"
check "database directory is panelapi 0700, the file 0600" bash -c 'test "$(stat -c "%U %a" /var/lib/oxpanel-panel)" = "panelapi 700" && test "$(stat -c "%U %a" /var/lib/oxpanel-panel/panel.db)" = "panelapi 600"'
check "the proxy secret: secret.env root:panelapi 0640, the Nginx include root 0600" bash -c 'test "$(stat -c "%U:%G %a" /etc/oxpanel-panel/secret.env)" = "root:panelapi 640" && test "$(stat -c "%U %a" /etc/nginx/oxpanel-panel-proxy.inc)" = "root 600"'
check "the TLS key is root 0600 and cert_t" bash -c 'test "$(stat -c "%U %a" /etc/pki/oxpanel-panel/panel.key)" = "root 600" && ls -Z /etc/pki/oxpanel-panel/panel.key | grep -q ":cert_t:"'
check "the panel's server block is outside the engine's directory" bash -c 'test -f /etc/nginx/conf.d/00-oxpanel-panel.conf && ! ls /etc/nginx/oxpanel.d | grep -q panel'
check "Nginx reads the panel's block before OxPanel's own" bash -c 'nginx -T 2>/dev/null | grep "^# configuration file /etc/nginx/conf.d/" | head -2 | tail -1 | grep -q 00-oxpanel.conf && nginx -T 2>/dev/null | grep "^# configuration file /etc/nginx/conf.d/" | head -1 | grep -q 00-oxpanel-panel.conf'
check "firewalld opened the panel's port" bash -c "! systemctl -q is-active firewalld || firewall-cmd --query-port=${PORT}/tcp"
check "engine reconcile is clean with the panel installed" bash -c 'oxpanel-ctl host reconcile | grep -qx "drifts=0"'
info "systemd-analyze security: $(systemd-analyze security oxpanel-panel --no-pager 2>/dev/null | tail -1)"
info "panel RSS at start: $(ps -o rss= -p "$PID") KiB"

# ------------------------------------------------------------ transport
check "HTTPS answers on the panel's port" test "$(curl -sk -o /dev/null -w '%{http_code}' "$LOCAL/api/v1/health")" = 200
check "HTTP/2 is offered" test "$(curl -sk --http2 -o /dev/null -w '%{http_version}' "$LOCAL/api/v1/health")" = 2
check "plain HTTP on the panel's port is redirected to HTTPS" bash -c "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' http://127.0.0.1:${PORT}/ | grep -q '^301 https://127.0.0.1:${PORT}/'"
check "TLS 1.1 is refused" bash -c "! echo | openssl s_client -connect 127.0.0.1:${PORT} -tls1_1 >/dev/null 2>&1"
check "the self-signed certificate names this host" bash -c "echo | openssl s_client -connect 127.0.0.1:${PORT} 2>/dev/null | openssl x509 -noout -ext subjectAltName | grep -q 'IP Address:127.0.0.1'"
check "the customers' port 443 still refuses unknown names" bash -c "! curl -sk --max-time 5 --resolve nobody.test:443:127.0.0.1 https://nobody.test/ >/dev/null 2>&1"
check "a large upload body is not cut by Nginx below the panel's own limit (panel answers 413 itself)" bash -c "head -c 300000 /dev/zero | tr '\\0' a | curl -sk -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -H 'Origin: $LOCAL' --data-binary @- '$LOCAL/api/v1/auth/login' | grep -qx 413 && ! grep -q 'client intended to send too large body' /var/log/nginx/oxpanel-panel.error.log"
check "a body above Nginx's outer wall (4 MiB) is refused by Nginx" bash -c "head -c 5000000 /dev/zero | curl -sk -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' --data-binary @- '$LOCAL/api/v1/auth/login' | grep -qx 413"

# ------------------------------------------------------------ direct access
check "a request on the socket without the proxy secret is refused (403 direct_access_refused)" bash -c "curl -s --unix-socket /run/oxpanel-panel/panel.sock http://x/api/v1/health | grep -q direct_access_refused"
SECRET="$(sed -n 's/^PANEL_PROXY_SECRET=//p' /etc/oxpanel-panel/secret.env)"
check "with the secret (Nginx's view) it answers" bash -c "curl -s -H 'X-Panel-Proxy-Secret: $SECRET' --unix-socket /run/oxpanel-panel/panel.sock http://x/api/v1/health | grep -q status"

# ------------------------------------------------------------ the product
start=$(date +%s)
python3 phases/product/drive.py "$LOCAL" "$(sed -n 1p panel-admin.once)" "$(sed -n 2p panel-admin.once)"; rc=$?
info "drive.py finished in $(( $(date +%s) - start ))s (exit $rc)"
[ "$rc" = 0 ] || fail "the product drive failed (see above)"

# ------------------------------------------------------------ a tenant against the panel (host side)
T=panelatk
check "an attacker tenant" oxpanel-ctl tenant create $T
check "a tenant cannot open the panel's socket" bash -c "! setpriv --reuid=$T --regid=$T --init-groups --no-new-privs -- curl -s --max-time 3 --unix-socket /run/oxpanel-panel/panel.sock http://x/api/v1/health"
check "a tenant cannot read the panel's database" bash -c "! setpriv --reuid=$T --regid=$T --init-groups --no-new-privs -- cat /var/lib/oxpanel-panel/panel.db >/dev/null 2>&1"
check "a tenant cannot read the proxy secret" bash -c "! setpriv --reuid=$T --regid=$T --init-groups --no-new-privs -- cat /etc/oxpanel-panel/secret.env >/dev/null 2>&1 && ! setpriv --reuid=$T --regid=$T --init-groups --no-new-privs -- cat /etc/nginx/oxpanel-panel-proxy.inc >/dev/null 2>&1"
check "a tenant cannot read the panel's TLS key" bash -c "! setpriv --reuid=$T --regid=$T --init-groups --no-new-privs -- cat /etc/pki/oxpanel-panel/panel.key >/dev/null 2>&1"
check "nothing of the panel is reachable on loopback TCP for a tenant to squat or call" bash -c "! ss -H -ltn | grep -Eq '127\\.0\\.0\\.1:8088|\\[::1\\]:8088'"
check "a tenant reaching the panel over HTTPS is an ordinary anonymous client" bash -c "test \"\$(setpriv --reuid=$T --regid=$T --init-groups --no-new-privs -- curl -sk -o /dev/null -w '%{http_code}' $LOCAL/api/v1/accounts)\" = 401"
check "remove the attacker tenant" oxpanel-ctl tenant delete $T --remove-home

PID="$(systemctl show -p MainPID --value oxpanel-panel)"
RSS="$(ps -o rss= -p "$PID" | tr -d ' ')"
info "panel RSS at the end: ${RSS} KiB; engine RSS: $(ps -o rss= -p "$(daemon_pid)") KiB"
# Each password hash takes 19 MiB; the unit makes glibc give it back (MALLOC_MMAP_THRESHOLD_).
check "the panel's memory came back after dozens of password hashes (RSS < 64 MiB)" test "$RSS" -lt 65536
check "the panel logged no errors" bash -c '! journalctl -b -u oxpanel-panel -p err --no-pager | grep -q panel-api'
check "engine reconcile is clean after the drive" bash -c 'oxpanel-ctl host reconcile | grep -qx "drifts=0"'
check "nginx -t passes" nginx -t
n=$(( $(avc_count) - AVC0 )); if [ "$n" = 0 ]; then ok "zero AVC denials during this phase"; else avc_dump; fail "$n AVC denial(s) during this phase"; fi
phase_end
