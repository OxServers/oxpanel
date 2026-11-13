#!/usr/bin/env bash
# Runs as root inside the systemd container. Every `check` is an assertion.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }
check() { local msg="$1"; shift; if "$@"; then echo "ok   - $msg"; else fail "$msg"; fi; }
check_not() { local msg="$1"; shift; if ! "$@" >/dev/null 2>&1; then echo "ok   - $msg"; else fail "$msg (unexpectedly succeeded)"; fi; }
as_user() { local u="$1"; shift; setpriv --reuid="$u" --regid="$u" --clear-groups --no-new-privs -- "$@"; }
# `systemctl reload nginx` returns when SIGHUP is sent; old workers may accept a
# connection for a few more milliseconds. Poll briefly for the expected body.
body_eventually() { local host="$1" path="$2" want="$3" i; for i in $(seq 1 50); do [ "$(curl -s -H "Host: $host" "http://127.0.0.1$path")" = "$want" ] && return 0; sleep 0.1; done; return 1; }
code_of() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $1" "http://127.0.0.1$2"; }

if [ "${SKIP_INSTALL:-0}" != 1 ]; then
  echo "== install (as the RPM would)"
  install -m0755 /work/target/release/oxpanel-daemon /usr/sbin/oxpanel-daemon
  install -m0755 /work/target/release/oxpanel-ctl /usr/bin/oxpanel-ctl
  install -Dm0644 /work/packaging/systemd/oxpanel-daemon.service /etc/systemd/system/oxpanel-daemon.service
  install -Dm0644 /work/packaging/sysusers.d/oxpanel.conf /usr/lib/sysusers.d/oxpanel.conf
  install -Dm0644 /work/packaging/tmpfiles.d/oxpanel.conf /usr/lib/tmpfiles.d/oxpanel.conf
  install -Dm0640 /work/packaging/daemon.env /etc/oxpanel/daemon.env
  install -Dm0644 /work/packaging/logrotate.d/oxpanel /etc/logrotate.d/oxpanel
  systemd-sysusers
  systemd-tmpfiles --create oxpanel.conf
  systemctl daemon-reload
  systemctl start nginx
  check "nginx is active" systemctl -q is-active nginx
else
  echo "== install skipped (SKIP_INSTALL=1): using the already installed oxpanel-daemon"
  check "nginx is active" systemctl -q is-active nginx
fi

confd_before="$(ls /etc/nginx/conf.d | grep -vc "^00-oxpanel.conf$" || true)"
echo "== start daemon through its hardened unit"
if ! systemctl start oxpanel-daemon; then
  systemctl status oxpanel-daemon --no-pager || true
  journalctl -u oxpanel-daemon --no-pager | tail -40
  fail "oxpanel-daemon failed to start"
fi
check "daemon is active (Type=notify handshake completed)" systemctl -q is-active oxpanel-daemon
check "socket exists" test -S /run/oxpanel/oxpanel.sock
check "socket is root:oxpanel 0660" test "$(stat -c '%U:%G %a' /run/oxpanel/oxpanel.sock)" = "root:oxpanel 660"
check "include stanza written" grep -q 'include /etc/nginx/oxpanel.d/\*.conf;' /etc/nginx/conf.d/00-oxpanel.conf
check "state dir is root-only" test "$(stat -c '%a' /var/lib/oxpanel/tenants)" = "700"

echo "== tenant lifecycle"
out="$(oxpanel-ctl tenant create alice --memory 256M --cpu-weight 50 --tasks-max 128)"
echo "$out"
check "created=true" grep -q '^created=true' <<<"$out"
check "account exists" id alice
check "uid in range" test "$(id -u alice)" -ge 20000
check "primary group is dedicated" test "$(id -gn alice)" = "alice"
check "login disabled" test "$(getent passwd alice | cut -d: -f7)" = "/sbin/nologin"
check "password locked" grep -qE '^alice:[!*]' /etc/shadow
check "home is 0700" test "$(stat -c '%a' /home/alice)" = "700"
check "home owned by alice:alice" test "$(stat -c '%U:%G' /home/alice)" = "alice:alice"
check "slice unit written" test -f /etc/systemd/system/oxpanel-tenant-alice.slice
check "MemoryMax rendered" grep -q '^MemoryMax=268435456$' /etc/systemd/system/oxpanel-tenant-alice.slice
check "CPUWeight rendered" grep -q '^CPUWeight=50$' /etc/systemd/system/oxpanel-tenant-alice.slice
check "TasksMax rendered" grep -q '^TasksMax=128$' /etc/systemd/system/oxpanel-tenant-alice.slice
check "user-slice drop-in written" test -f "/etc/systemd/system/user-$(id -u alice).slice.d/50-oxpanel.conf"
check "slice unit loads in systemd" systemctl cat oxpanel-tenant-alice.slice
check "slice limits visible to systemd" test "$(systemctl show -p MemoryMax --value oxpanel-tenant-alice.slice)" = "268435456"
check "record is root-only" test "$(stat -c '%a' /var/lib/oxpanel/tenants/alice.json)" = "600"

out="$(oxpanel-ctl tenant create alice --memory 256M --cpu-weight 50 --tasks-max 128)"
check "replay is idempotent (created=false)" grep -q '^created=false' <<<"$out"
check_not "spec drift is refused" oxpanel-ctl tenant create alice --memory 512M
check_not "reserved name refused" oxpanel-ctl tenant create root
check_not "foreign account is never adopted" oxpanel-ctl tenant create nginx
check "nginx account untouched" id nginx

echo "== virtual host"
out="$(oxpanel-ctl vhost set example.test --tenant alice --alias www.example.test)"
echo "$out"
check "changed=true" grep -q '^changed=true' <<<"$out"
check "docroot created" test -d /home/alice/public_html
check "docroot owned by alice" test "$(stat -c '%U' /home/alice/public_html)" = "alice"
# With an ACL present, stat shows the ACL *mask* in the group bits (0710); the
# real group and other entries must still be closed.
check "home mode is 0710 (ACL mask), not a chmod" test "$(stat -c '%a' /home/alice)" = "710"
check "home group entry closed" grep -q '^group::---' <(getfacl -p /home/alice 2>/dev/null)
check "home other entry closed" grep -q '^other::---' <(getfacl -p /home/alice 2>/dev/null)
check "nginx has traverse on home" grep -q '^user:nginx:--x' <(getfacl -p /home/alice 2>/dev/null)
check "another tenant cannot traverse alice's home" bash -c '! setpriv --reuid=nginx --regid=nginx --clear-groups -- ls /home/alice >/dev/null 2>&1'
check "docroot owned by alice" test "$(stat -c '%U' /home/alice/public_html)" = "alice"
check "nginx has read on docroot" grep -q '^user:nginx:r-x' <(getfacl -p /home/alice/public_html 2>/dev/null)
check "default ACL for new files" grep -q '^default:user:nginx:r-x' <(getfacl -p /home/alice/public_html 2>/dev/null)
check "config in managed dir" test -f /etc/nginx/oxpanel.d/example.test.conf
check "nginx -t passes" nginx -t
check "other conf.d untouched (only the include stanza was added)" test "$(ls /etc/nginx/conf.d | wc -l)" = "$((confd_before + 1))"

as_user alice sh -c 'echo hello-from-alice > /home/alice/public_html/index.html; echo SECRET=1 > /home/alice/public_html/.env; ln -s /etc/shadow /home/alice/public_html/shadow; ln -s /etc /home/alice/public_html/etc'
check "nginx serves tenant content" body_eventually example.test / hello-from-alice
check "alias served too" body_eventually www.example.test / hello-from-alice
check "dot-files are 404" test "$(code_of example.test /.env)" = "404"
code="$(code_of example.test /shadow)"
check "symlink to /etc/shadow is not served ($code)" test "$code" != "200"
code="$(code_of example.test /etc/passwd)"
check "symlink to /etc is not traversed ($code)" test "$code" != "200"
check "directory listing is off" test "$(code_of example.test /etc/)" != "200"
check "unknown host does not reach tenant (connection closed)" test "$(curl -s -H 'Host: other.test' http://127.0.0.1/ ; echo "rc=$?")" = "rc=52"
check "bare-IP request does not reach tenant" test "$(curl -s http://127.0.0.1/ ; echo "rc=$?")" = "rc=52"
check "catch-all is the default server" grep -q 'default_server' /etc/nginx/conf.d/00-oxpanel.conf

out="$(oxpanel-ctl vhost set example.test --tenant alice --alias www.example.test)"
check "vhost replay is idempotent (changed=false)" grep -q '^changed=false' <<<"$out"

echo "== second tenant, ownership, peer auth"
oxpanel-ctl tenant create bob >/dev/null
oxpanel-ctl tenant create foo-bar --owner reseller1 --memory 128M >/dev/null
check "dashed tenant slice name is escaped" test -f '/etc/systemd/system/oxpanel-tenant-foo\x2dbar.slice'
check "escaped slice loads in systemd" systemctl cat 'oxpanel-tenant-foo\x2dbar.slice'
check "escaped slice is not nested under another tenant" test "$(systemctl show -p Slice --value 'oxpanel-tenant-foo\x2dbar.slice')" = "oxpanel-tenant.slice"
check "owner label stored" grep -q 'owner=reseller1' <(oxpanel-ctl tenant get foo-bar)
check "owner filter lists only that owner's tenants" bash -c 'oxpanel-ctl tenant list --owner reseller1 | grep -q tenant=foo-bar && ! oxpanel-ctl tenant list --owner reseller1 | grep -q tenant=alice'
check_not "owner drift is refused" oxpanel-ctl tenant create foo-bar --owner reseller2 --memory 128M
check_not "bob cannot take alice's alias" oxpanel-ctl vhost set www.example.test --tenant bob
check_not "bob cannot take alice's domain" oxpanel-ctl vhost set example.test --tenant bob
check_not "unauthorised peer (bob, a tenant) is refused" as_user bob oxpanel-ctl tenant list
# The panel-api service account: a system user whose *account* is in the oxpanel group.
useradd -r -G oxpanel -s /sbin/nologin panelapi
check "authorised peer via oxpanel group membership works" bash -c 'setpriv --reuid=panelapi --regid=panelapi --init-groups --no-new-privs -- oxpanel-ctl tenant list | grep -q tenant=alice'
check "process groups alone do not grant access (account DB is authoritative)" bash -c '! setpriv --reuid=bob --regid=bob --groups="$(getent group oxpanel | cut -d: -f3)" --no-new-privs -- oxpanel-ctl tenant list >/dev/null 2>&1'
check "nginx -t output has no warnings" bash -c '! nginx -t 2>&1 | grep -q warn'
check_not "tenant with vhosts cannot be deleted" oxpanel-ctl tenant delete alice
check "daemon still healthy after refusals" systemctl -q is-active oxpanel-daemon

echo "== management: limits, owner, suspension, usage, host info, reconcile"
code_eventually() { local host="$1" path="$2" want="$3" i; for i in $(seq 1 50); do [ "$(code_of "$host" "$path")" = "$want" ] && return 0; sleep 0.1; done; return 1; }
check "a consistent host has no drift" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)
out="$(oxpanel-ctl tenant set-limits alice --memory 512M --tasks-max 64)"
check "set-limits changed=true" grep -q '^changed=true' <<<"$out"
check "new MemoryMax is live in systemd" test "$(systemctl show -p MemoryMax --value oxpanel-tenant-alice.slice)" = "536870912"
check "new TasksMax is live in systemd" test "$(systemctl show -p TasksMax --value oxpanel-tenant-alice.slice)" = "64"
check "a limit that was dropped is gone from the unit" bash -c '! grep -q CPUWeight /etc/systemd/system/oxpanel-tenant-alice.slice'
check "login-slice drop-in follows" grep -q '^TasksMax=64$' "/etc/systemd/system/user-$(id -u alice).slice.d/50-oxpanel.conf"
check "set-limits replay changed=false" grep -q '^changed=false' <(oxpanel-ctl tenant set-limits alice --memory 512M --tasks-max 64)
check_not "invalid limit is refused" oxpanel-ctl tenant set-limits alice --memory 1
check_not "limits of an unknown tenant are refused" oxpanel-ctl tenant set-limits ghost --memory 512M
check "owner label replaced" grep -q ' owner=reseller2 ' <(oxpanel-ctl tenant set-owner alice reseller2)
check "owner label cleared" grep -q ' owner=- ' <(oxpanel-ctl tenant set-owner alice '')
check_not "invalid owner label refused" oxpanel-ctl tenant set-owner alice 'Bad Owner'

out="$(oxpanel-ctl tenant suspend alice)"
check "suspend changed=true suspended=true" bash -c 'grep -q "^changed=true" <<<"$1" && grep -q " suspended=true " <<<"$1"' _ "$out"
check "suspended site answers 503" code_eventually example.test / 503
check "suspended alias answers 503" code_eventually www.example.test / 503
check "suspended site sends Retry-After" grep -qi '^retry-after: 3600' <(curl -s -D- -o /dev/null -H 'Host: example.test' http://127.0.0.1/)
check "suspended config has no document root" bash -c '! grep -q "root " /etc/nginx/oxpanel.d/example.test.conf'
check "tenant files untouched by suspension" test -f /home/alice/public_html/index.html
check "suspend replay changed=false" grep -q '^changed=false' <(oxpanel-ctl tenant suspend alice)
check "suspension is not drift" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)
check "resume changed=true" grep -q '^changed=true' <(oxpanel-ctl tenant resume alice)
check "resumed site serves content again" body_eventually example.test / hello-from-alice

out="$(oxpanel-ctl tenant usage alice)"
echo "$out"
check "usage reports the tenant" grep -q '^tenant=alice ' <<<"$out"
check "disk usage is measured (> 0 bytes)" test "$(sed -n 's/.* disk_usage=\([0-9]*\).*/\1/p' <<<"$out")" -gt 0
out="$(oxpanel-ctl host info)"
echo "$out"
check "host info reports the version" grep -qE '^version=[0-9]+\.[0-9]+\.[0-9]+ ' <<<"$out"
check "host info counts tenants and vhosts" grep -q ' tenants=3 vhosts=1 ' <<<"$out"
check "host info reports memory (> 0)" test "$(sed -n 's/.* memory_total=\([0-9]*\).*/\1/p' <<<"$out")" -gt 0
check "host info reports home disk (> 0)" test "$(sed -n 's/.* home_disk_total=\([0-9]*\).*/\1/p' <<<"$out")" -gt 0

# Drift: edit a unit by hand, remove a site's config, drop a stray file in our directory.
cp -p /etc/systemd/system/oxpanel-tenant-bob.slice /root/bob.slice.bak
echo 'CPUWeight=9999' >> /etc/systemd/system/oxpanel-tenant-bob.slice
mv /etc/nginx/oxpanel.d/example.test.conf /root/example.test.conf.bak
echo '# stray' > /etc/nginx/oxpanel.d/stray.conf
out="$(oxpanel-ctl host reconcile || true)"
echo "$out"
check "reconcile exits 3 on drift" bash -c 'oxpanel-ctl host reconcile >/dev/null; test $? -eq 3'
check "reconcile finds 3 differences" grep -q '^drifts=3$' <<<"$out"
check "reconcile reports the edited unit" grep -q '^kind=DRIFT_KIND_TENANT_UNIT_DRIFT subject=bob ' <<<"$out"
check "reconcile reports the missing config" grep -q '^kind=DRIFT_KIND_VHOST_CONFIG_DRIFT subject=example.test ' <<<"$out"
check "reconcile reports the orphan" grep -q '^kind=DRIFT_KIND_ORPHAN_NGINX_CONFIG subject=/etc/nginx/oxpanel.d/stray.conf ' <<<"$out"
check "reconcile repaired nothing (read-only)" bash -c 'test -e /etc/nginx/oxpanel.d/stray.conf && test ! -e /etc/nginx/oxpanel.d/example.test.conf && grep -q 9999 /etc/systemd/system/oxpanel-tenant-bob.slice'
rm -f /etc/nginx/oxpanel.d/stray.conf
cp -p /root/bob.slice.bak /etc/systemd/system/oxpanel-tenant-bob.slice
check "repeating the request heals the site" grep -q '^changed=true' <(oxpanel-ctl vhost set example.test --tenant alice --alias www.example.test)
check "host is consistent again" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)
check "healed site serves content" body_eventually example.test / hello-from-alice

echo "== per-peer scopes"
as_panelapi() { setpriv --reuid=panelapi --regid=panelapi --init-groups --no-new-privs -- "$@"; }
cp -p /etc/oxpanel/daemon.env /root/daemon.env.bak
echo "OXPANEL_PEER_SCOPES=$(id -u panelapi):read+vhost" >> /etc/oxpanel/daemon.env
systemctl restart oxpanel-daemon
check "daemon restarts with scopes configured" systemctl -q is-active oxpanel-daemon
check "scoped peer may read" bash -c 'setpriv --reuid=panelapi --regid=panelapi --init-groups --no-new-privs -- oxpanel-ctl tenant list | grep -q tenant=alice'
check "scoped peer may manage virtual hosts" grep -q '^changed=true' <(as_panelapi oxpanel-ctl vhost set scoped.test --tenant bob)
check "scoped peer may remove virtual hosts" grep -q '^removed=true' <(as_panelapi oxpanel-ctl vhost remove scoped.test)
check_not "scoped peer cannot create tenants" as_panelapi oxpanel-ctl tenant create mallory
check_not "scoped peer cannot change limits" as_panelapi oxpanel-ctl tenant set-limits alice --memory 1G
check_not "scoped peer cannot suspend" as_panelapi oxpanel-ctl tenant suspend alice
check_not "scoped peer cannot delete tenants" as_panelapi oxpanel-ctl tenant delete bob --remove-home
check "refusal names the missing scope" grep -q "PermissionDenied.*scope 'delete' required" <(as_panelapi oxpanel-ctl tenant delete bob 2>&1 || true)
check_not "no account was created by the refused call" id mallory
check "bob survived the refused delete" id bob
check "root stays unrestricted" grep -q '^changed=false' <(oxpanel-ctl tenant set-limits alice --memory 512M --tasks-max 64)
echo "OXPANEL_PEER_SCOPES=$(id -u panelapi):everything" >> /etc/oxpanel/daemon.env
check "an unknown scope name is rejected by --check-config" bash -c 'set -a; . /etc/oxpanel/daemon.env; /usr/sbin/oxpanel-daemon --check-config 2>&1 | grep -q "is not a scope"'
cp -p /root/daemon.env.bak /etc/oxpanel/daemon.env
systemctl restart oxpanel-daemon
check "daemon restarts without scopes" systemctl -q is-active oxpanel-daemon
check "unscoped panel peer has full access again" grep -q '^changed=false' <(as_panelapi oxpanel-ctl tenant set-limits alice --memory 512M --tasks-max 64)

echo "== per-site logs"
curl -s -o /dev/null -H 'Host: example.test' 'http://127.0.0.1/?marker=log-check-1'
check "site has its own access log" test -f /var/log/nginx/oxpanel/example.test.access.log
check "access log is readable through the API" bash -c 'for i in $(seq 1 30); do oxpanel-ctl vhost log example.test | grep -q "marker=log-check-1" && exit 0; sleep 0.1; done; exit 1'
# The refused symlink from the virtual-host section is an error-log event.
curl -s -o /dev/null -H 'Host: example.test' 'http://127.0.0.1/shadow?marker=error-check-1'
check "error log is separate and readable" bash -c 'for i in $(seq 1 30); do oxpanel-ctl vhost log example.test --error | grep -q "marker=error-check-1" && exit 0; sleep 0.1; done; exit 1'
check "log directory is closed to tenants" bash -c '! setpriv --reuid=bob --regid=bob --clear-groups -- ls /var/log/nginx/oxpanel >/dev/null 2>&1'
check_not "log of an unknown site is refused" oxpanel-ctl vhost log nosuch.test
check_not "log name cannot traverse" oxpanel-ctl vhost log ../../../etc/shadow
check "logrotate accepts our configuration" logrotate -d /etc/logrotate.d/oxpanel
as_user alice sh -c 'echo "<?php echo \"secret-source\";" > /home/alice/public_html/config.php'
check "a static site never hands out PHP source" test "$(code_of example.test /config.php)" = "404"

echo "== PHP-FPM per tenant"
check "host info reports PHP" grep -q ' php=true ' <(oxpanel-ctl host info)
out="$(oxpanel-ctl vhost set php.test --tenant bob --php)"
echo "$out"
check "php vhost changed=true php=true" bash -c 'grep -q "^changed=true" <<<"$1" && grep -q " php=true " <<<"$1"' _ "$out"
PHPU=oxpanel-php-bob.service
check "pool unit is active" systemctl -q is-active "$PHPU"
check "pool unit is enabled (survives reboot)" systemctl -q is-enabled "$PHPU"
php_pid="$(systemctl show -p MainPID --value "$PHPU")"
check "FPM master runs as the tenant, not root" test "$(ps -o user= -p "$php_pid" | tr -d ' ')" = "bob"
check "no PHP process of this pool runs as root" bash -c '! ps -o user= --ppid "$1" -p "$1" | grep -qw root' _ "$php_pid"
check "pool lives in the tenant slice" grep -q 'oxpanel-tenant-bob.slice' <(systemctl show -p ControlGroup --value "$PHPU")
check "socket exists" test -S /run/oxpanel-php/bob/php.sock
check "socket ACL names the web server" grep -q '^user:nginx:rw-' <(getfacl -p /run/oxpanel-php/bob/php.sock 2>/dev/null)
check "another tenant cannot connect to the socket" bash -c 'setpriv --reuid=alice --regid=alice --clear-groups -- curl -s -o /dev/null --unix-socket /run/oxpanel-php/bob/php.sock http://x/; test $? -eq 7'
as_user bob sh -c 'cat > /home/bob/public_html/index.php' <<'PHP'
<?php
$f = tempnam(sys_get_temp_dir(), 'ox');
echo 'euid=' . fileowner($f) . ' tmp=' . dirname($f);
unlink($f);
echo ' passwd=' . (@file_get_contents('/etc/passwd') === false ? 'blocked' : 'READABLE');
echo ' other=' . (@scandir('/home/alice') === false ? 'blocked' : 'READABLE');
echo ' write=' . (@file_put_contents(__DIR__ . '/written.txt', 'x') === 1 ? 'ok' : 'failed');
PHP
check "PHP runs as the tenant, confined by open_basedir, and can write its own site" body_eventually php.test / "euid=$(id -u bob) tmp=/tmp passwd=blocked other=blocked write=ok"
check "file written by PHP is owned by the tenant" test "$(stat -c '%U' /home/bob/public_html/written.txt)" = "bob"
check "file written by PHP is served by nginx (default ACL applies)" body_eventually php.test /written.txt x
check "PHP temp files are private to the unit (not in the host /tmp)" bash -c '! ls /tmp/ox* >/dev/null 2>&1'
check "missing script is 404, not passed to FPM" test "$(code_of php.test /nope.php)" = "404"
as_user bob sh -c 'mkdir -p /home/bob/public_html/.hidden && echo "<?php echo 1;" > /home/bob/public_html/.hidden/x.php && echo "<?php echo 1;" > /home/bob/public_html/img.php.jpg'
check "script under a dot-directory is not executed" test "$(code_of php.test /.hidden/x.php)" = "404"
check "path-info trick (file.jpg/x.php) is not executed" test "$(code_of php.test /img.php.jpg/x.php)" = "404"
check "X-Powered-By is hidden" bash -c '! curl -s -D- -o /dev/null -H "Host: php.test" http://127.0.0.1/ | grep -qi x-powered-by'
check "unknown paths fall back to the front controller" grep -q '^euid=' <(curl -s -H 'Host: php.test' http://127.0.0.1/some/pretty/url)
check "vhost replay with php is idempotent" grep -q '^changed=false' <(oxpanel-ctl vhost set php.test --tenant bob --php)
check "php pool is not drift" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)

check "suspend stops the tenant's PHP" bash -c 'oxpanel-ctl tenant suspend bob >/dev/null && ! systemctl -q is-active "$1" && ! systemctl -q is-enabled "$1" 2>/dev/null' _ "$PHPU"
check "suspended PHP site answers 503" code_eventually php.test / 503
check "resume starts PHP again" bash -c 'oxpanel-ctl tenant resume bob >/dev/null && systemctl -q is-active "$1" && systemctl -q is-enabled "$1"' _ "$PHPU"
check "resumed PHP site works" bash -c 'for i in $(seq 1 50); do curl -s -H "Host: php.test" http://127.0.0.1/ | grep -q "^euid=" && exit 0; sleep 0.1; done; exit 1'

check "memory limit applies to PHP (same slice)" bash -c 'oxpanel-ctl tenant set-limits bob --memory 128M >/dev/null && test "$(systemctl show -p MemoryMax --value oxpanel-tenant-bob.slice)" = 134217728'
check "usage now sees the PHP processes" bash -c 'test "$(oxpanel-ctl tenant usage bob | sed -n "s/.* tasks_current=\([0-9]*\).*/\1/p")" -ge 1'

check "switching PHP off removes the pool" bash -c 'oxpanel-ctl vhost set php.test --tenant bob | grep -q " php=false " && ! systemctl -q is-active "$1" && test ! -e /etc/systemd/system/"$1" && test ! -e /etc/oxpanel-php/bob.conf' _ "$PHPU"
check "with PHP off the script source is not served" bash -c 'for i in $(seq 1 50); do [ "$(curl -s -o /dev/null -w "%{http_code}" -H "Host: php.test" http://127.0.0.1/index.php)" = 404 ] && exit 0; sleep 0.1; done; exit 1'
check "PHP back on, then removing the site removes the pool" bash -c 'oxpanel-ctl vhost set php.test --tenant bob --php >/dev/null && systemctl -q is-active "$1" && oxpanel-ctl vhost remove php.test | grep -q "^removed=true" && ! systemctl -q is-active "$1" && test ! -e /etc/systemd/system/"$1"' _ "$PHPU"
check "site logs removed with the site" test ! -e /var/log/nginx/oxpanel/php.test.access.log
check "no drift after PHP teardown" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)

echo "== Node.js and Python applications"
check "host info reports Node.js and Python" grep -qE ' node=true node_version=[0-9.]+ python=true ' <(oxpanel-ctl host info)
check "Node.js is version 22 or newer" test "$(node --version | sed 's/^v//; s/\..*//')" -ge 22
out="$(oxpanel-ctl vhost set node.test --tenant bob --app node)"
echo "$out"
check "node app vhost changed=true with defaults" bash -c 'grep -q "^changed=true" <<<"$1" && grep -q " app=node:apps/node.test:app.js " <<<"$1"' _ "$out"
NODEU=oxpanel-app-node.test.service
check "application directory created for the tenant" test "$(stat -c '%U:%G' /home/bob/apps/node.test)" = "bob:bob"
check "application directory is not opened to the web server" bash -c '! getfacl -p /home/bob/apps/node.test 2>/dev/null | grep -q "^user:nginx"'
check "before any code exists the site answers 502" code_eventually node.test / 502
as_user bob sh -c 'cat > /home/bob/apps/node.test/app.js' <<'JS'
const http = require('http');
const fs = require('fs');
console.log('node-app-started-marker');
http.createServer((req, res) => {
  let other = 'blocked';
  try { fs.readdirSync('/home/alice'); other = 'READABLE'; } catch (e) {}
  let etc = 'blocked';
  try { fs.writeFileSync('/etc/oxpanel-app-probe', 'x'); etc = 'WRITABLE'; } catch (e) {}
  res.setHeader('X-Powered-By', 'leak');
  res.end(`node uid=${process.getuid()} url=${req.url} host=${req.headers.host} xff=${req.headers['x-forwarded-for'] ? 'set' : 'unset'} other=${other} etc=${etc}`);
}).listen(process.env.PORT);
JS
check "restart-app picks up the new code" grep -q '^restarted=true' <(oxpanel-ctl vhost restart-app node.test)
check "Node app answers as the tenant, behind the proxy, confined" body_eventually node.test /hello "node uid=$(id -u bob) url=/hello host=node.test xff=set other=blocked etc=blocked"
check "app unit is active and enabled" bash -c 'systemctl -q is-active "$1" && systemctl -q is-enabled "$1"' _ "$NODEU"
check "app process runs as the tenant, not root" test "$(ps -o user= -p "$(systemctl show -p MainPID --value "$NODEU")" | tr -d ' ')" = "bob"
if selinuxenabled 2>/dev/null; then
  check "SELinux: the app runs in its own domain" grep -q ':oxpanel_app_t:' <(ps -o label= -p "$(systemctl show -p MainPID --value "$NODEU")")
  check "SELinux: the app socket carries the web-server runtime type" grep -q ':httpd_var_run_t:' <(ls -Z /run/oxpanel-app/node.test/app.sock)
fi
check "app lives in the tenant slice" grep -q 'oxpanel-tenant-bob.slice' <(systemctl show -p ControlGroup --value "$NODEU")
check "app socket exists" test -S /run/oxpanel-app/node.test/app.sock
check "another tenant cannot enter the socket directory" bash -c '! setpriv --reuid=alice --regid=alice --clear-groups -- ls /run/oxpanel-app/node.test >/dev/null 2>&1'
check "another tenant cannot connect to the app socket" bash -c 'setpriv --reuid=alice --regid=alice --clear-groups -- curl -s -o /dev/null --unix-socket /run/oxpanel-app/node.test/app.sock http://x/; test $? -eq 7'
check "the app listens on no TCP port" bash -c '! ss -ltnp 2>/dev/null | grep -q "pid=$(systemctl show -p MainPID --value "$1"),"' _ "$NODEU"
as_user bob sh -c 'echo static-file > /home/bob/public_html/static.txt'
check "files in the document root are served by nginx, not the app" body_eventually node.test /static.txt static-file
check "application source is never served as a file" bash -c '! curl -s -H "Host: node.test" http://127.0.0.1/app.js | grep -q createServer'
check "the app's X-Powered-By is hidden" bash -c '! curl -s -D- -o /dev/null -H "Host: node.test" http://127.0.0.1/ | grep -qi x-powered-by'
check "application output is readable through the API" bash -c 'for i in $(seq 1 30); do oxpanel-ctl vhost log node.test --app | grep -q node-app-started-marker && exit 0; sleep 0.2; done; exit 1'
check_not "app log of a static site is refused" oxpanel-ctl vhost log example.test --app
check_not "restart-app of a static site is refused" oxpanel-ctl vhost restart-app example.test
as_user bob sh -c 'echo "{\"name\":\"probe\",\"version\":\"1.0.0\",\"private\":true}" > /home/bob/apps/node.test/package.json'
out="$(oxpanel-ctl vhost install-deps node.test || true)"
echo "$out" | tail -3
check "npm install runs as the tenant and succeeds" grep -q '^succeeded=true' <<<"$out"
check "files written by npm belong to the tenant" test "$(stat -c '%U' /home/bob/apps/node.test/package-lock.json)" = "bob"
check "the app is back after the installation" body_eventually node.test /again "node uid=$(id -u bob) url=/again host=node.test xff=set other=blocked etc=blocked"
as_user bob sh -c 'echo "{ this is not json" > /home/bob/apps/node.test/package.json'
check "a failing installation is reported with exit status 4" bash -c 'oxpanel-ctl vhost install-deps node.test > /root/deps.out 2>&1; rc=$?; grep -q "^succeeded=false" /root/deps.out && test $rc -eq 4'
# Put a valid package.json back: Node.js reads it at start-up and refuses to run with a broken one.
as_user bob sh -c 'echo "{\"name\":\"probe\",\"version\":\"1.0.0\",\"private\":true}" > /home/bob/apps/node.test/package.json'
check "vhost replay with an app is idempotent" grep -q '^changed=false' <(oxpanel-ctl vhost set node.test --tenant bob --app node)
check_not "app and php cannot be combined" oxpanel-ctl vhost set both.test --tenant bob --app node --php
check_not "app root inside the document root is refused" oxpanel-ctl vhost set bad.test --tenant bob --app node --app-root public_html/app
check_not "app entry cannot leave the app directory" oxpanel-ctl vhost set bad.test --tenant bob --app node --app-entry ../../../usr/bin/id

out="$(oxpanel-ctl vhost set py.test --tenant bob --app python --app-root apps/py --app-entry main.py)"
echo "$out"
check "python app vhost changed=true" bash -c 'grep -q "^changed=true" <<<"$1" && grep -q " app=python:apps/py:main.py " <<<"$1"' _ "$out"
PYU=oxpanel-app-py.test.service
check "virtualenv created by the tenant" bash -c 'test -x /home/bob/apps/py/.venv/bin/python && test "$(stat -c %U /home/bob/apps/py/.venv)" = bob'
as_user bob sh -c 'cat > /home/bob/apps/py/main.py' <<'PY'
import os, sys
from http.server import BaseHTTPRequestHandler
from socketserver import UnixStreamServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            os.listdir('/home/alice'); other = 'READABLE'
        except OSError:
            other = 'blocked'
        body = f"python uid={os.getuid()} venv={int(sys.prefix != sys.base_prefix)} url={self.path} other={other}".encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

print('python-app-started-marker')
UnixStreamServer(os.environ['PORT'], Handler).serve_forever()
PY
as_user bob sh -c ': > /home/bob/apps/py/requirements.txt'
out="$(oxpanel-ctl vhost install-deps py.test || true)"
check "pip install into the virtualenv succeeds (and restarts the app)" grep -q '^succeeded=true' <<<"$out"
check "Python app answers as the tenant from its own virtualenv" body_eventually py.test /x "python uid=$(id -u bob) venv=1 url=/x other=blocked"
check "python app process runs as the tenant" test "$(ps -o user= -p "$(systemctl show -p MainPID --value "$PYU")" | tr -d ' ')" = "bob"
check "python app output is readable through the API" bash -c 'for i in $(seq 1 30); do oxpanel-ctl vhost log py.test --app | grep -q python-app-started-marker && exit 0; sleep 0.2; done; exit 1'
check "applications are not drift" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)
check "usage counts the applications' processes" bash -c 'test "$(oxpanel-ctl tenant usage bob | sed -n "s/.* tasks_current=\([0-9]*\).*/\1/p")" -ge 2'

check "suspend stops every application of the tenant" bash -c 'oxpanel-ctl tenant suspend bob >/dev/null && ! systemctl -q is-active "$1" && ! systemctl -q is-active "$2" && ! systemctl -q is-enabled "$1" 2>/dev/null' _ "$NODEU" "$PYU"
check "suspended app site answers 503" code_eventually node.test / 503
check_not "restart-app is refused while suspended" oxpanel-ctl vhost restart-app node.test
check "resume starts the applications again" bash -c 'oxpanel-ctl tenant resume bob >/dev/null && systemctl -q is-active "$1" && systemctl -q is-active "$2" && systemctl -q is-enabled "$1"' _ "$NODEU" "$PYU"
check "resumed Node app works" body_eventually node.test /r "node uid=$(id -u bob) url=/r host=node.test xff=set other=blocked etc=blocked"
check "resumed Python app works" body_eventually py.test /r "python uid=$(id -u bob) venv=1 url=/r other=blocked"

check "switching the app off removes its unit and keeps the code" bash -c 'oxpanel-ctl vhost set node.test --tenant bob | grep -q " app=- " && ! systemctl -q is-active "$1" && test ! -e /etc/systemd/system/"$1" && test -f /home/bob/apps/node.test/app.js' _ "$NODEU"
check "the site is static again" body_eventually node.test /static.txt static-file
check "removing the sites removes the remaining unit" bash -c 'oxpanel-ctl vhost remove py.test | grep -q "^removed=true" && oxpanel-ctl vhost remove node.test | grep -q "^removed=true" && ! systemctl -q is-active "$1" && test ! -e /etc/systemd/system/"$1"' _ "$PYU"
check "no runtime directories left behind" bash -c '! ls /run/oxpanel-app/*/app.sock >/dev/null 2>&1'
check "no drift after application teardown" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)

echo "== sftp access"
# Needs sshd and the ssh client; the AlmaLinux images have both.
if [ -x /usr/sbin/sshd ] && command -v sftp >/dev/null; then
  systemctl -q is-active sshd || systemctl start sshd
  export SFTPDIR; SFTPDIR="$(mktemp -d /root/sftp-it.XXXXXX)"
  export SSH_O="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o ConnectTimeout=10 -o LogLevel=ERROR"
  # sftp_as <key> <user>, sftp batch commands on stdin
  # shellcheck disable=SC2086
  sftp_as() { sftp $SSH_O -i "$SFTPDIR/$1" -b - "$2@127.0.0.1"; }
  # A login expected to succeed right after one that was refused: OpenSSH 9.8+
  # penalises a source address for a few seconds after a failed authentication
  # (PerSourcePenalties) and drops its connections meanwhile, so retry.
  sftp_ok() { local i; for i in $(seq 1 40); do echo pwd | sftp_as "$1" "$2" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
  # A refused login must be refused by authentication ("Permission denied"), not
  # merely dropped by that penalty.
  sftp_denied() { local i out; for i in $(seq 1 40); do out="$(echo pwd | sftp_as "$1" "$2" 2>&1)" && return 1; grep -q "Permission denied" <<<"$out" && return 0; sleep 1; done; return 1; }
  export -f sftp_as sftp_ok sftp_denied
  # Ending sessions relies on logind (pam_systemd puts every login into the
  # tenant's user slice); the container has no logind, the real host does.
  LOGIND=0; systemctl -q is-active systemd-logind && LOGIND=1
  ssh-keygen -q -t ed25519 -N '' -C sftpa@test -f "$SFTPDIR/ka"
  ssh-keygen -q -t ed25519 -N '' -f "$SFTPDIR/kb"
  ssh-keygen -q -t rsa -b 1024 -N '' -f "$SFTPDIR/weak"

  check "the sshd drop-in is installed, root-only" test "$(stat -c '%U %a' /etc/ssh/sshd_config.d/60-oxpanel.conf)" = "root 600"
  check "sshd accepts the whole configuration" /usr/sbin/sshd -t
  check "host info reports sftp=true" grep -q ' sftp=true ' <(oxpanel-ctl host info)
  check "root's own SSH is unaffected (no forced command, no chroot)" bash -c '/usr/sbin/sshd -T -C user=root,host=localhost,addr=127.0.0.1 | grep -qx "forcecommand none" && /usr/sbin/sshd -T -C user=root,host=localhost,addr=127.0.0.1 | grep -qx "chrootdirectory none"'
  check "create tenant sftpa" grep -q '^created=true' <(oxpanel-ctl tenant create sftpa)
  check "create tenant sftpb" grep -q '^created=true' <(oxpanel-ctl tenant create sftpb)
  check "every tenant is in the tenant group" bash -c 'id -nG sftpa | grep -qw oxpanel-tenants && id -nG sftpb | grep -qw oxpanel-tenants'
  check "a tenant without keys is confined all the same" bash -c '/usr/sbin/sshd -T -C user=sftpb,host=localhost,addr=127.0.0.1 | grep -qx "forcecommand internal-sftp"'
  check "site sftpa.test with PHP" grep -q '^changed=true' <(oxpanel-ctl vhost set sftpa.test --tenant sftpa --php)
  check_not "a weak RSA key is refused" oxpanel-ctl sftp add-key sftpa --key-file "$SFTPDIR/weak.pub"
  check_not "key options are refused" oxpanel-ctl sftp add-key sftpa --key "command=\"/bin/sh\" $(cat "$SFTPDIR/ka.pub")"
  check "no key, no login" sftp_denied ka sftpa
  out="$(oxpanel-ctl sftp add-key sftpa --key-file "$SFTPDIR/ka.pub")"; echo "$out"
  check "add-key changed=true, labelled with the key's comment" bash -c 'grep -q "^changed=true" <<<"$1" && grep -q " label=sftpa@test " <<<"$1"' _ "$out"
  FPA="$(ssh-keygen -lf "$SFTPDIR/ka.pub" | awk '{print $2}')"
  check "the fingerprint is OpenSSH's" grep -q "fingerprint=$FPA " <<<"$out"
  check "add-key again is a no-op" grep -q '^changed=false' <(oxpanel-ctl sftp add-key sftpa --key-file "$SFTPDIR/ka.pub")
  check "get shows the key count" grep -q ' sftp_keys=1 ' <(oxpanel-ctl tenant get sftpa)
  check "keys file is root-owned, not writable by the tenant" test "$(stat -c '%U:%G %a' /etc/oxpanel-sftp/sftpa)" = "root:root 640"
  check "only this tenant may read its keys file" bash -c 'getfacl -p /etc/oxpanel-sftp/sftpa | grep -qx "user:sftpa:r--" && ! setpriv --reuid=sftpb --regid=sftpb --clear-groups -- cat /etc/oxpanel-sftp/sftpa >/dev/null 2>&1'
  check_not "the tenant cannot add a key itself" setpriv --reuid=sftpa --regid=sftpa --clear-groups -- sh -c 'echo x >> /etc/oxpanel-sftp/sftpa'
  check "chroot directory is root-owned 0755" test "$(stat -c '%U %a' /var/lib/oxpanel/sftp/sftpa)" = "root 755"
  check "the home is mounted into the chroot" findmnt -n /var/lib/oxpanel/sftp/sftpa/home/sftpa
  MNT="$(systemd-escape --path --suffix=mount /var/lib/oxpanel/sftp/sftpa/home/sftpa)"
  check "mount unit is active and enabled" bash -c 'systemctl -q is-active "$1" && systemctl -q is-enabled "$1"' _ "$MNT"
  check "the home itself is unchanged (tenant-owned, closed to group and others)" bash -c 'test "$(stat -c %U /home/sftpa)" = sftpa && getfacl -p /home/sftpa | grep -qx "group::---" && getfacl -p /home/sftpa | grep -qx "other::---"'

  echo "uploaded-over-sftp" > "$SFTPDIR/up.html"
  printf '<?php file_put_contents(__DIR__ . "/from-php.txt", "written-by-php"); echo "php-read:" . file_get_contents(__DIR__ . "/up.html");\n' > "$SFTPDIR/rw.php"
  check "first login with the key" sftp_ok ka sftpa
  check "sftp login, upload into the document root" bash -c 'printf "%s\n" "pwd" "put $1/up.html public_html/up.html" "put $1/rw.php public_html/rw.php" | sftp_as ka sftpa' _ "$SFTPDIR"
  check "the session starts in the home, at its real path" bash -c 'echo pwd | sftp_as ka sftpa | grep -q "/home/sftpa"'
  check "uploaded file belongs to the tenant" test "$(stat -c '%U:%G' /home/sftpa/public_html/up.html)" = "sftpa:sftpa"
  check "uploaded file inherits the web server's ACL" bash -c 'getfacl -p /home/sftpa/public_html/up.html | grep -q "^user:nginx:r"'
  if selinuxenabled 2>/dev/null; then
    check "SELinux: uploaded file is httpd_sys_content_t" grep -q ':httpd_sys_content_t:' <(ls -Z /home/sftpa/public_html/up.html)
  fi
  check "nginx serves the uploaded file" body_eventually sftpa.test /up.html uploaded-over-sftp
  check "PHP reads the uploaded file and writes its own" body_eventually sftpa.test /rw.php "php-read:uploaded-over-sftp"
  check "the file PHP wrote can be downloaded and removed over SFTP" bash -c 'printf "%s\n" "get public_html/from-php.txt $1/from-php.txt" "rm public_html/from-php.txt" | sftp_as ka sftpa && test "$(cat "$1/from-php.txt")" = written-by-php && test ! -e /home/sftpa/public_html/from-php.txt' _ "$SFTPDIR"
  check "the tenant sees only its own home" bash -c 'test "$(echo "ls -1 /" | sftp_as ka sftpa | grep -v "^sftp>")" = "/home" && test "$(echo "ls -1 /home" | sftp_as ka sftpa | grep -v "^sftp>")" = "/home/sftpa"'
  check_not "no /etc in the chroot" bash -c 'echo "ls /etc" | sftp_as ka sftpa'
  check_not "another tenant's home is not reachable" bash -c 'echo "ls /home/sftpb" | sftp_as ka sftpa'
  check_not "not even by its absolute path one level up" bash -c 'echo "get /home/../../etc/passwd /dev/null" | sftp_as ka sftpa'
  # shellcheck disable=SC2086
  out="$(ssh $SSH_O -i "$SFTPDIR/ka" sftpa@127.0.0.1 'echo shell-ran; touch /home/sftpa/shell-ran' </dev/null 2>&1 || true)"
  check "no shell: a command is never run" bash -c '! grep -q shell-ran <<<"$1" && test ! -e /home/sftpa/shell-ran' _ "$out"
  check "no terminal, no forwarding of any kind (sshd's effective settings)" bash -c 'e="$(/usr/sbin/sshd -T -C user=sftpa,host=localhost,addr=127.0.0.1)"; for kv in "permittty no" "disableforwarding yes" "allowtcpforwarding no" "allowagentforwarding no" "x11forwarding no" "permittunnel no" "allowstreamlocalforwarding no"; do grep -qx "$kv" <<<"$e" || { echo "missing: $kv"; exit 1; }; done'
  check_not "no TCP forwarding (ssh -W to the web server)" bash -c 'printf "GET / HTTP/1.0\r\n\r\n" | timeout 20 ssh $SSH_O -i "$SFTPDIR/ka" -W 127.0.0.1:80 sftpa@127.0.0.1 2>/dev/null | grep -q "^HTTP/"'
  check_not "no remote forwarding" bash -c 'timeout 20 ssh $SSH_O -i "$SFTPDIR/ka" -o ExitOnForwardFailure=yes -R 127.0.0.1:18022:127.0.0.1:22 sftpa@127.0.0.1 true </dev/null' 
  check "the key does not work for another tenant" sftp_denied ka sftpb

  # A session that stays open: where does it live, and does suspension end it?
  check "log in again (after the refusals above)" sftp_ok ka sftpa
  # shellcheck disable=SC2086
  ( sleep 60 | ssh $SSH_O -i "$SFTPDIR/ka" -s sftpa@127.0.0.1 sftp >/dev/null 2>&1 ) &
  HOLD=$!
  # The session process is sshd's (sshd-session on newer OpenSSH), running as the tenant.
  check "an open SFTP session runs as the tenant" bash -c 'for i in $(seq 1 50); do pgrep -u sftpa sshd >/dev/null && exit 0; sleep 0.2; done; exit 1'
  if [ "$LOGIND" = 1 ]; then
    check "the session lands in the tenant's user slice (its limits apply)" bash -c 'for p in $(pgrep -u sftpa sshd); do grep -q "/user.slice/user-$(id -u sftpa).slice/" /proc/$p/cgroup || exit 1; done'
  fi
  check "suspend" grep -q '^changed=true' <(oxpanel-ctl tenant suspend sftpa)
  if [ "$LOGIND" = 1 ]; then
    check "suspension ends the open session" bash -c 'for i in $(seq 1 50); do pgrep -u sftpa sshd >/dev/null || exit 0; sleep 0.2; done; exit 1'
  fi
  check "suspension withdraws the keys file" test ! -e /etc/oxpanel-sftp/sftpa
  check "no login while suspended" sftp_denied ka sftpa
  check "resume" grep -q '^changed=true' <(oxpanel-ctl tenant resume sftpa)
  check "login works again after resume" sftp_ok ka sftpa
  # Without logind (the container) suspension could not end it; end it here.
  pkill -P "$HOLD" 2>/dev/null || true; kill "$HOLD" 2>/dev/null || true; wait "$HOLD" 2>/dev/null || true
  pkill -u sftpa sshd 2>/dev/null || true

  check "a second key" grep -q '^changed=true' <(oxpanel-ctl sftp add-key sftpa --key-file "$SFTPDIR/kb.pub" --label ci)
  check "list-keys shows both" test "$(oxpanel-ctl sftp list-keys sftpa | wc -l)" = 2
  check "no drift with SFTP in use" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)
  check "removing one key" grep -q 'remaining=1' <(oxpanel-ctl sftp remove-key sftpa "$FPA")
  check "the removed key no longer logs in" sftp_denied ka sftpa
  check "the other key still does" sftp_ok kb sftpa
  check_not "removing it again is NOT_FOUND" oxpanel-ctl sftp remove-key sftpa "$FPA"
  FPB="$(ssh-keygen -lf "$SFTPDIR/kb.pub" | awk '{print $2}')"
  check "removing the last key" grep -q 'remaining=0' <(oxpanel-ctl sftp remove-key sftpa "$FPB")
  check "no keys file, mount, unit or chroot left" bash -c 'test ! -e /etc/oxpanel-sftp/sftpa && ! findmnt -n /var/lib/oxpanel/sftp/sftpa/home/sftpa && test ! -e "/etc/systemd/system/$1" && test ! -e /var/lib/oxpanel/sftp/sftpa' _ "$MNT"
  check "the tenant's files are untouched" test -f /home/sftpa/public_html/up.html
  check "access again, then delete the tenant with it" bash -c 'oxpanel-ctl sftp add-key sftpa --key-file "$1/ka.pub" >/dev/null && sftp_ok ka sftpa' _ "$SFTPDIR"
  check "remove sftpa.test" grep -q '^removed=true' <(oxpanel-ctl vhost remove sftpa.test)
  check "delete sftpa (with SFTP access)" grep -q '^deleted=true' <(oxpanel-ctl tenant delete sftpa --remove-home)
  check "deletion removed keys file, mount, unit and chroot" bash -c 'test ! -e /etc/oxpanel-sftp/sftpa && ! findmnt -n /var/lib/oxpanel/sftp/sftpa/home/sftpa && test ! -e "/etc/systemd/system/$1" && test ! -e /var/lib/oxpanel/sftp/sftpa && test ! -e /home/sftpa' _ "$MNT"
  check "delete sftpb" grep -q '^deleted=true' <(oxpanel-ctl tenant delete sftpb --remove-home)
  check "no drift after SFTP teardown" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)
  rm -rf "$SFTPDIR"
else
  echo "skip - sshd or the sftp client is not installed"
fi

echo "== disk quotas"
if grep -q ' disk_quota=true ' <(oxpanel-ctl host info); then
  info_line="$(oxpanel-ctl host info | grep '^disk_quota_detail=')"; echo "$info_line"
  check "create tenant quotaa with 5M / 200 files" grep -q '^created=true' <(oxpanel-ctl tenant create quotaa --disk 5M --inodes 200)
  QUID="$(id -u quotaa)"; QFS="$(findmnt -no TARGET -T /home)"
  check "the kernel holds the limit" bash -c 'xfs_quota -x -c "report -u -n -N -b -i -L $1 -U $1" "$2" | grep -qE "^#$1 +[0-9]+ +5120 +5120 .* 200 +200 "' _ "$QUID" "$QFS"
  check "writing beyond the limit fails with EDQUOT" bash -c 'as_out="$(setpriv --reuid=quotaa --regid=quotaa --clear-groups -- dd if=/dev/zero of=/home/quotaa/big bs=1M count=8 2>&1)"; rc=$?; echo "$as_out" | tail -1; test $rc -ne 0 && grep -q "Disk quota exceeded" <<<"$as_out"'
  check "usage comes from the quota system and is at the limit" bash -c 'u="$(oxpanel-ctl tenant usage quotaa | sed -n "s/.* disk_usage=\([0-9]*\).*/\1/p")"; test "$u" -ge $((4 << 20)) && test "$u" -le $((5 << 20))'
  check "too many files fail too" bash -c 'setpriv --reuid=quotaa --regid=quotaa --clear-groups -- sh -c "rm -f /home/quotaa/big; for i in \$(seq 1 250); do : > /home/quotaa/f\$i || exit 0; done; exit 1"'
  check "no drift with quotas set" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)
  check "raising the limit through set-limits" grep -q '^changed=true' <(oxpanel-ctl tenant set-limits quotaa --disk 64M)
  check "the write now succeeds" setpriv --reuid=quotaa --regid=quotaa --clear-groups -- dd if=/dev/zero of=/home/quotaa/big bs=1M count=8 status=none
  if [ -x /usr/sbin/sshd ] && command -v sftp >/dev/null; then
    QDIR="$(mktemp -d /root/quota-it.XXXXXX)"
    ssh-keygen -q -t ed25519 -N '' -f "$QDIR/k"
    head -c $((12 << 20)) /dev/zero > "$QDIR/blob"
    check "set-limits back to 16M" grep -q '^changed=true' <(oxpanel-ctl tenant set-limits quotaa --disk 16M)
    oxpanel-ctl sftp add-key quotaa --key-file "$QDIR/k.pub" >/dev/null
    QSFTP="sftp -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o LogLevel=ERROR -i $QDIR/k -b - quotaa@127.0.0.1"
    check "the quota tenant logs in over SFTP" bash -c 'for i in $(seq 1 40); do echo pwd | $1 >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1' _ "$QSFTP"
    check "an SFTP upload beyond the limit fails with a quota error" bash -c 'out="$(echo "put $2/blob big2" | $1 2>&1)"; rc=$?; echo "$out" | tail -2; test $rc -ne 0 && grep -qiE "quota|failure" <<<"$out"' _ "$QSFTP" "$QDIR"
    rm -rf "$QDIR"
  fi
  check "dropping the limit" grep -q '^changed=true' <(oxpanel-ctl tenant set-limits quotaa)
  check "the kernel limit is gone" bash -c '! xfs_quota -x -c "report -u -n -N -b -i -L $1 -U $1" "$2" | grep -qE "^#$1 +[0-9]+ +[1-9]"' _ "$QUID" "$QFS"
  check "delete quotaa" grep -q '^deleted=true' <(oxpanel-ctl tenant delete quotaa --remove-home)
else
  echo "info - $(oxpanel-ctl host info | grep '^disk_quota_detail=')"
  out="$(oxpanel-ctl tenant create quotab --disk 1G 2>&1 || true)"; echo "$out"
  check "a disk limit is refused, saying what to do" bash -c 'grep -q "FailedPrecondition" <<<"$1" && grep -q "uquota" <<<"$1"' _ "$out"
  check_not "and nothing was created" id quotab
fi

echo "== teardown"
check "vhost removed" grep -q '^removed=true' <(oxpanel-ctl vhost remove example.test)
check "config gone" test ! -e /etc/nginx/oxpanel.d/example.test.conf
check "nginx -t still passes" nginx -t
check "second removal is a no-op" grep -q '^removed=false' <(oxpanel-ctl vhost remove example.test)
check "tenant deleted" grep -q '^deleted=true' <(oxpanel-ctl tenant delete alice --remove-home)
check_not "account gone" id alice
check "home gone" test ! -e /home/alice
check "slice unit gone" test ! -e /etc/systemd/system/oxpanel-tenant-alice.slice
check "bob deleted" grep -q '^deleted=true' <(oxpanel-ctl tenant delete bob --remove-home)
check "foo-bar deleted" grep -q '^deleted=true' <(oxpanel-ctl tenant delete foo-bar --remove-home)
check "escaped slice removed" test ! -e '/etc/systemd/system/oxpanel-tenant-foo\x2dbar.slice'
check "no tenants left" test -z "$(oxpanel-ctl tenant list)"
check "daemon healthy at end" systemctl -q is-active oxpanel-daemon
check "no daemon errors in journal" bash -c '! journalctl -u oxpanel-daemon --no-pager -p err | grep -q oxpanel-daemon'
echo "== all checks passed"
