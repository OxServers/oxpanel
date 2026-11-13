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

echo "== backups and restores"
BK=/var/lib/oxpanel-backups
# The backup id and job id of the job a `backup create|restore|job` printed.
backup_of() { sed -n 's/^job=[^ ]* .* backup=\([^ ]*\) .*/\1/p' <<<"$1" | tail -1; }
job_of() { sed -n 's/^job=\([^ ]*\) .*/\1/p' <<<"$1" | tail -1; }
backup_ids() { oxpanel-ctl backup list "$1" | sed -n 's/^backup=\([^ ]*\) .*/\1/p'; }
# Size and SHA-256 of a member as the engine recorded them.
recorded() { python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); m=[m for m in r["members"] if m["kind"]=="home"][0]; print(m["size_bytes"], m["sha256"])' "/var/lib/oxpanel/backups/$1.json"; }
on_disk() { echo "$(stat -c %s "$1") $(sha256sum "$1" | cut -d' ' -f1)"; }
check "backup store is root-only" test "$(stat -c '%U:%G %a' "$BK")" = "root:root 700"
check "host info reports the backup store" grep -q ' backup_keep=7' <(oxpanel-ctl host info)
check_not "a backup of an unknown tenant is refused" oxpanel-ctl backup create nosuchtenant
check_not "a malformed backup id is refused" oxpanel-ctl backup restore alice '../b1731500000123'

echo "-- reading the home happens as the tenant"
as_user alice sh -c 'mkfifo /home/alice/fifo; truncate -s 10G /home/alice/sparse.img; mkdir -p /home/alice/.cache; echo cached > /home/alice/.cache/junk'
# What a tenant cannot plant itself, root plants: a file it may not read, a
# hard link to /etc/shadow, a device node.
echo root-only-secret-marker > /home/alice/root-secret; chmod 600 /home/alice/root-secret
hardlinked=0; if ln /etc/shadow /home/alice/shadow-hardlink 2>/dev/null; then hardlinked=1; fi
# (Containers without CAP_MKNOD cannot plant the node; the VM can.)
noded=0; if mknod /home/alice/null-dev c 1 3 2>/dev/null; then noded=1; fi
rc=0; out="$(timeout 300 oxpanel-ctl backup create alice --wait)" || rc=$?
echo "$out" | tail -3
check "a backup over a FIFO, a device node and unreadable files completes" test "$rc" -eq 0
HOSTILE="$(backup_of "$out")"
A="$BK/alice/$HOSTILE/home.tar.gz"
tar -tvzf "$A" > /root/listing.txt
check "a symlink to /etc/shadow is stored as a symlink" grep -q '^l.* \./public_html/shadow -> /etc/shadow$' /root/listing.txt
check "a FIFO is stored as a FIFO, never opened" grep -q '^p.* \./fifo$' /root/listing.txt
if [ "$noded" = 1 ]; then
  check "a device node is stored as a node, never read" grep -q '^c.* \./null-dev$' /root/listing.txt
fi
check "a file the tenant cannot read is not archived" bash -c '! grep -q " \./root-secret$" /root/listing.txt'
if [ "$hardlinked" = 1 ]; then
  check "a hard link to /etc/shadow is not archived" bash -c '! grep -q "shadow-hardlink" /root/listing.txt'
fi
check "no content of /etc/shadow or the root-only file in the archive" bash -c '! tar -xzOf "$1" --exclude=./sparse.img --exclude=./fifo --exclude=./null-dev 2>/dev/null | grep -aqE "^root:|root-only-secret-marker"' _ "$A"
check "a 10 GiB sparse file costs almost nothing" test "$(stat -c %s "$A")" -lt 10485760
check "download caches are left out" bash -c '! grep -q "\./\.cache" /root/listing.txt'
check "the tenant's skipped files are reported in the job output" grep -q 'root-secret' <<<"$out"
rm -f /home/alice/fifo /home/alice/sparse.img /home/alice/root-secret /home/alice/shadow-hardlink /home/alice/null-dev
rm -rf /home/alice/.cache
check "the hostile-home backup can be deleted" grep -q '^deleted=true' <(oxpanel-ctl backup delete alice "$HOSTILE")
check "and its directory is gone" test ! -e "$BK/alice/$HOSTILE"

echo "-- round trip: a static site and a PHP site"
as_user alice sh -c 'echo original-static > /home/alice/public_html/backup.html; printf nl > "/home/alice/public_html/new
line.txt"'
check "PHP site for bob" grep -q '^changed=true' <(oxpanel-ctl vhost set bkphp.test --tenant bob --php)
as_user bob sh -c 'echo "<?php echo \"php-\" . \"original\";" > /home/bob/public_html/index.php'
check "the PHP site serves" body_eventually bkphp.test / php-original
# Applications whose dependencies are not in the backup.
check "Node.js app for bob" grep -q '^changed=true' <(oxpanel-ctl vhost set bknode.test --tenant bob --app node)
check "Python app for bob" grep -q '^changed=true' <(oxpanel-ctl vhost set bkpy.test --tenant bob --app python)
as_user bob sh -c 'mkdir -p /home/bob/apps/greet && echo "{\"name\":\"greet\",\"version\":\"1.0.0\",\"main\":\"index.js\"}" > /home/bob/apps/greet/package.json && echo "module.exports = () => \"greet-from-node-modules\";" > /home/bob/apps/greet/index.js'
as_user bob sh -c 'echo "{\"name\":\"bknode\",\"version\":\"1.0.0\",\"private\":true,\"dependencies\":{\"greet\":\"file:../greet\"}}" > /home/bob/apps/bknode.test/package.json'
as_user bob sh -c 'cat > /home/bob/apps/bknode.test/app.js' <<'JS'
const greet = require('greet');
require('http').createServer((q, r) => r.end(`${greet()} url=${q.url}`)).listen(process.env.PORT);
JS
as_user bob sh -c 'cat > /home/bob/apps/bkpy.test/app.py' <<'PY'
import os, sys
from http.server import BaseHTTPRequestHandler
from socketserver import UnixStreamServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"py venv={int(sys.prefix != sys.base_prefix)} url={self.path}".encode()
        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
UnixStreamServer(os.environ['PORT'], Handler).serve_forever()
PY
as_user bob sh -c ': > /home/bob/apps/bkpy.test/requirements.txt'
check "npm installs the local dependency into node_modules" grep -q '^succeeded=true' <(oxpanel-ctl vhost install-deps bknode.test)
check "pip runs in the virtualenv" grep -q '^succeeded=true' <(oxpanel-ctl vhost install-deps bkpy.test)
check "the Node.js app answers, using node_modules" body_eventually bknode.test /a "greet-from-node-modules url=/a"
check "the Python app answers from its virtualenv" body_eventually bkpy.test /a "py venv=1 url=/a"
out="$(timeout 300 oxpanel-ctl backup create alice --wait)" || true; echo "$out" | tail -1
check "backup of alice succeeds" grep -q 'state=JOB_STATE_SUCCEEDED' <<<"$out"
A1="$(backup_of "$out")"
out="$(timeout 300 oxpanel-ctl backup create bob --wait)" || true; echo "$out" | tail -1
check "backup of bob succeeds" grep -q 'state=JOB_STATE_SUCCEEDED' <<<"$out"
B1="$(backup_of "$out")"
check "the archive contains no node_modules" bash -c '! tar -tzf "$1" | grep -q node_modules' _ "$BK/bob/$B1/home.tar.gz"
check "the archive contains no virtualenv" bash -c '! tar -tzf "$1" | grep -qE "/\.venv/|pyvenv\.cfg"' _ "$BK/bob/$B1/home.tar.gz"
check "the manifest names what was left out" bash -c 'grep -q "\"apps/bknode.test/node_modules\"" "$1" && grep -q "\"apps/bkpy.test/.venv\"" "$1" && grep -q "pyvenv.cfg" "$1"' _ "$BK/bob/$B1/manifest.json"
check "the listing counts what was left out" grep -qE "^backup=$B1 .* excluded=[2-9][0-9]*$" <(oxpanel-ctl backup list bob)
# Lose both, as a re-installed server would.
rm -rf /home/bob/apps/bknode.test/node_modules /home/bob/apps/bkpy.test/.venv
check "listed READY with its members and sites" grep -q "^backup=$A1 tenant=alice state=BACKUP_STATE_READY .* domains=[^ ]*example.test[^ ]* members=home:home.tar.gz:[0-9]*,records:records.json:[0-9]* excluded=[0-9]*$" <(oxpanel-ctl backup list alice)
check "archive, manifest and records are root-only" bash -c 'test "$(stat -c "%U %a" "$1"/home.tar.gz "$1"/manifest.json "$1"/records.json | sort -u)" = "root 600" && test "$(stat -c "%U %a" "$1")" = "root 700"' _ "$BK/alice/$A1"
check "no worker leftovers in the backup" test "$(ls "$BK/alice/$A1" | tr '\n' ' ')" = "home.tar.gz manifest.json records.json "
check "the checksum on record is the archive's" test "$(recorded "$A1")" = "$(on_disk "$BK/alice/$A1/home.tar.gz")"
check "the manifest lists the checksum" grep -q "$(recorded "$A1" | cut -d' ' -f2)" "$BK/alice/$A1/manifest.json"
check "the records member describes the tenant and its sites" bash -c 'grep -q "\"username\": \"alice\"" "$1" && grep -q example.test "$1"' _ "$BK/alice/$A1/records.json"
check_not "the tenant cannot list the backup store" as_user alice ls "$BK"
check_not "the tenant cannot read its own archive" as_user alice cat "$BK/alice/$A1/home.tar.gz"
check_not "another tenant cannot read it either" as_user bob cat "$BK/alice/$A1/home.tar.gz"
check "backups are not drift" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)

as_user alice sh -c 'echo changed > /home/alice/public_html/backup.html; rm -f "/home/alice/public_html/new
line.txt"; echo extra > /home/alice/public_html/added-later.html'
as_user bob sh -c 'echo "<?php echo \"php-modified\";" > /home/bob/public_html/index.php'
check "the static change is live" body_eventually example.test /backup.html changed
check "the PHP change is live" body_eventually bkphp.test / php-modified
check_not "a restore must say what happens to existing files" oxpanel-ctl backup restore alice "$A1"
check_not "and cannot say both" oxpanel-ctl backup restore alice "$A1" --overwrite --keep-existing
out="$(timeout 300 oxpanel-ctl backup restore alice "$A1" --keep-existing --wait)" || true; echo "$out" | tail -2
check "restore of alice keeping existing files succeeds" grep -q 'kind=JOB_KIND_RESTORE .* state=JOB_STATE_SUCCEEDED' <<<"$out"
check "it reports restored and skipped entries" grep -qE '^restored_entries=[1-9][0-9]* skipped_entries=[1-9][0-9]*$' <<<"$out"
check "a file changed since the backup is kept" body_eventually example.test /backup.html changed
check "a deleted file comes back (keep)" test -f "/home/alice/public_html/new
line.txt"
rm -f "/home/alice/public_html/new
line.txt"
out="$(timeout 300 oxpanel-ctl backup restore alice "$A1" --overwrite --wait)" || true; echo "$out" | tail -2
check "restore of alice overwriting succeeds" grep -q 'kind=JOB_KIND_RESTORE .* state=JOB_STATE_SUCCEEDED' <<<"$out"
check "nothing is reported skipped when overwriting" grep -qE '^restored_entries=[1-9][0-9]* skipped_entries=0$' <<<"$out"
check "the static site serves the original again" body_eventually example.test /backup.html original-static
check "a deleted file comes back (overwrite), even with a newline in its name" test -f "/home/alice/public_html/new
line.txt"
check "files newer than the backup stay" test -f /home/alice/public_html/added-later.html
check "restored files belong to the tenant" test "$(stat -c %U /home/alice/public_html/backup.html)" = alice
check "the home is still private" test "$(stat -c '%U:%G' /home/alice)" = "alice:alice"
check "the home still admits only the web server" grep -q '^user:nginx:--x' <(getfacl -p /home/alice 2>/dev/null)
if selinuxenabled 2>/dev/null; then
  check "SELinux: restored site files carry the web-content label" grep -q 'httpd_sys_content_t' <(ls -Z /home/alice/public_html/backup.html)
fi
out="$(timeout 300 oxpanel-ctl backup restore bob "$B1" --overwrite --wait)" || true; echo "$out" | tail -4
check "restore of bob succeeds" grep -q 'state=JOB_STATE_SUCCEEDED' <<<"$out"
check "the PHP site serves the original again" body_eventually bkphp.test / php-original
check "bob's PHP pool runs again" systemctl -q is-active oxpanel-php-bob.service
check "the restore reports both applications rebuilt" bash -c 'grep -q "^site=bknode.test dependencies_ok=true " <<<"$1" && grep -q "^site=bkpy.test dependencies_ok=true " <<<"$1"' _ "$out"
check "node_modules was reinstalled as the tenant" test "$(stat -c %U /home/bob/apps/bknode.test/node_modules)" = bob
check "the virtualenv was recreated as the tenant" test "$(stat -c %U /home/bob/apps/bkpy.test/.venv/bin/python)" = bob
check "the Node.js app answers again" body_eventually bknode.test /b "greet-from-node-modules url=/b"
check "the Python app answers again" body_eventually bkpy.test /b "py venv=1 url=/b"

echo "-- one tenant's backup is not another's"
check_not "bob cannot be restored from alice's backup" oxpanel-ctl backup restore bob "$A1" --overwrite
check "the refusal is NOT_FOUND" grep -q 'NotFound' <(oxpanel-ctl backup restore bob "$A1" --overwrite 2>&1 || true)
check "bob cannot delete alice's backup" grep -q '^deleted=false' <(oxpanel-ctl backup delete bob "$A1")
check "alice's backup is still there" test -f "$BK/alice/$A1/manifest.json"
check "bob's listing shows only bob's backup" test "$(backup_ids bob)" = "$B1"

echo "-- integrity"
cp -p "$BK/alice/$A1/home.tar.gz" /root/good.tar.gz
as_user alice sh -c 'echo after-damage > /home/alice/public_html/backup.html'
printf x >> "$BK/alice/$A1/home.tar.gz"
check "a grown archive is drift" grep -q 'BACKUP_ARCHIVE_MODIFIED' <(oxpanel-ctl host reconcile || true)
rc=0; out="$(timeout 300 oxpanel-ctl backup restore alice "$A1" --overwrite --wait)" || rc=$?
check "a corrupted archive is refused (exit 5)" test "$rc" -eq 5
check "and says so" grep -q 'archive is damaged' <<<"$out"
truncate -s 100 "$BK/alice/$A1/home.tar.gz"
rc=0; out="$(timeout 300 oxpanel-ctl backup restore alice "$A1" --overwrite --wait)" || rc=$?
check "a truncated archive is refused" bash -c 'test "$1" -eq 5 && grep -q "archive is damaged" <<<"$2"' _ "$rc" "$out"
check "nothing was restored from a damaged archive" test "$(cat /home/alice/public_html/backup.html)" = after-damage
check "the site is back in service after a refused restore" body_eventually example.test /backup.html after-damage
cp -p /root/good.tar.gz "$BK/alice/$A1/home.tar.gz"

echo "-- restoring a hostile archive (as if made from a compromised site)"
python3 - "$BK/alice/$A1/home.tar.gz" <<'PY'
import io, sys, tarfile
def add(t, name, data=b"pwned\n", **kw):
    i = tarfile.TarInfo(name); i.size = len(data)
    for k, v in kw.items(): setattr(i, k, v)
    t.addfile(i, io.BytesIO(data) if i.isreg() else None)
with tarfile.open(sys.argv[1], "w:gz", format=tarfile.GNU_FORMAT) as t:
    add(t, "./hostile-ok.txt", b"extracted\n", mode=0o644)
    add(t, "/etc/oxpanel-evil-abs", mode=0o644)
    add(t, "../../../etc/oxpanel-evil-dotdot", mode=0o644)
    add(t, "./esc", type=tarfile.SYMTYPE, linkname="/etc", size=0)
    add(t, "./esc/oxpanel-evil-link", mode=0o644)
    add(t, "./tobob", type=tarfile.SYMTYPE, linkname="/home/bob", size=0)
    add(t, "./tobob/pwned", mode=0o644)
    add(t, "./suid", b"#!/bin/sh\n", mode=0o4755)
    add(t, "./sgid", b"#!/bin/sh\n", mode=0o2755)
    add(t, "./dev-null", type=tarfile.CHRTYPE, devmajor=1, devminor=3, size=0, mode=0o666)
    add(t, "./hl", type=tarfile.LNKTYPE, linkname="/etc/shadow", size=0)
    add(t, "./rootowned", b"root\n", uid=0, gid=0, uname="root", gname="root", mode=0o644)
PY
python3 - "/var/lib/oxpanel/backups/$A1.json" "$BK/alice/$A1/home.tar.gz" <<'PY'
import hashlib, json, os, sys
rec, archive = sys.argv[1], sys.argv[2]
r = json.load(open(rec))
for m in r["members"]:
    if m["kind"] == "home":
        m["size_bytes"] = os.path.getsize(archive)
        m["sha256"] = hashlib.sha256(open(archive, "rb").read()).hexdigest()
json.dump(r, open(rec, "w"), indent=2)
PY
for mode in --keep-existing --overwrite; do
  rc=0; out="$(timeout 300 oxpanel-ctl backup restore alice "$A1" "$mode" --wait)" || rc=$?
  echo "$out" | tail -4
  check "the restore reports the refused members (exit 5) ($mode)" test "$rc" -eq 5
  check "the harmless member was restored, as the tenant ($mode)" test "$(stat -c '%U' /home/alice/hostile-ok.txt)" = alice
  check "an absolute path stays inside the home ($mode)" bash -c 'test ! -e /etc/oxpanel-evil-abs && test -f /home/alice/etc/oxpanel-evil-abs'
  check "a '..' path is not extracted ($mode)" test ! -e /etc/oxpanel-evil-dotdot
  check "nothing is written through a symlink to /etc ($mode)" test ! -e /etc/oxpanel-evil-link
  check "nothing is written through a symlink into another home ($mode)" test ! -e /home/bob/pwned
  check "no set-uid file ($mode)" bash -c 'test ! -u /home/alice/suid'
  check "no set-gid file ($mode)" bash -c 'test ! -g /home/alice/sgid'
  check "no device node ($mode)" bash -c 'test ! -c /home/alice/dev-null'
  check "no hard link to /etc/shadow ($mode)" bash -c '! test /home/alice/hl -ef /etc/shadow'
  check "/etc/shadow is untouched ($mode)" test "$(stat -c '%U:%G %a' /etc/shadow)" = "root:root 0"
  check "a member owned by root is owned by the tenant ($mode)" test "$(stat -c '%U' /home/alice/rootowned)" = alice
  check "the site is back in service after a hostile restore ($mode)" body_eventually example.test /backup.html after-damage
  rm -rf /home/alice/hostile-ok.txt /home/alice/etc /home/alice/esc /home/alice/tobob /home/alice/suid /home/alice/sgid /home/alice/dev-null /home/alice/hl /home/alice/rootowned
done
check "the tampered backup is drift" grep -q "BACKUP_ARCHIVE_MODIFIED.*$A1\|subject=$A1" <(oxpanel-ctl host reconcile || true)
check "and can be deleted" grep -q '^deleted=true' <(oxpanel-ctl backup delete alice "$A1")

echo "-- the daemon killed during a backup; the worker killed during a backup"
as_user alice sh -c 'head -c 400M /dev/urandom > /home/alice/big.bin'
out="$(oxpanel-ctl backup create alice)" || true; J="$(job_of "$out")"; K="$(backup_of "$out")"
check "the job runs in its own unit" systemctl -q is-active "oxpanel-job-$J.service"
check "the job is charged to the tenant's slice" test "$(systemctl show -p Slice --value "oxpanel-job-$J.service")" = oxpanel-tenant-alice.slice
check "the archiver runs as the tenant, not root" bash -c 'for i in $(seq 1 50); do u="$(ps -o user= -C tar | sort -u | tr -d " ")"; [ -n "$u" ] && { [ "$u" = alice ]; exit; }; sleep 0.1; done; exit 1'
check "a repeated request returns the running job" grep -q "^started=false" <(oxpanel-ctl backup create alice)
check_not "a backup in flight cannot be restored yet" oxpanel-ctl backup restore alice "$K" --overwrite
check "listed as CREATING while it runs" grep -q "^backup=$K .*state=BACKUP_STATE_CREATING" <(oxpanel-ctl backup list alice)
systemctl kill -s SIGKILL oxpanel-daemon
check "the worker outlives the daemon" systemctl -q is-active "oxpanel-job-$J.service"
for i in $(seq 1 60); do systemctl -q is-active oxpanel-daemon && break; sleep 0.5; done
out="$(timeout 600 oxpanel-ctl backup job "$J" --wait)" || true; echo "$out" | tail -1
check "the restarted daemon finishes the backup" grep -q 'state=JOB_STATE_SUCCEEDED' <<<"$out"
check "it is complete and listed" grep -q "^backup=$K .*state=BACKUP_STATE_READY" <(oxpanel-ctl backup list alice)
check "and its checksum is right" test "$(recorded "$K")" = "$(on_disk "$BK/alice/$K/home.tar.gz")"
out="$(oxpanel-ctl backup create alice)" || true; J="$(job_of "$out")"; K2="$(backup_of "$out")"
sleep 1
systemctl kill -s SIGKILL "oxpanel-job-$J.service"
rc=0; out="$(timeout 300 oxpanel-ctl backup job "$J" --wait)" || rc=$?
echo "$out" | tail -1
check "a killed worker fails the job (exit 5)" test "$rc" -eq 5
check "and leaves no backup behind" bash -c '! oxpanel-ctl backup list alice | grep -q "^backup=$1 " && test ! -e "$2"' _ "$K2" "$BK/alice/$K2"
rm -f /home/alice/big.bin
check "delete the big backup" grep -q '^deleted=true' <(oxpanel-ctl backup delete alice "$K")

echo "-- retention, suspended tenants, deletion"
oxpanel-ctl tenant suspend foo-bar >/dev/null
out="$(timeout 300 oxpanel-ctl backup create foo-bar --wait)" || true
check "a suspended tenant can be backed up" grep -q 'state=JOB_STATE_SUCCEEDED' <<<"$out"
first="$(backup_of "$out")"
oxpanel-ctl tenant resume foo-bar >/dev/null
for i in $(seq 1 7); do timeout 300 oxpanel-ctl backup create foo-bar --wait >/dev/null; done
check "retention keeps the newest 7" test "$(backup_ids foo-bar | wc -l)" -eq 7
check "the oldest is gone, with its files" bash -c '! oxpanel-ctl backup list foo-bar | grep -q "^backup=$1 " && test ! -e "$2"' _ "$first" "$BK/foo-bar/$first"
check_not "a tenant with backups cannot be deleted" oxpanel-ctl tenant delete foo-bar --remove-home
check "the refusal says why" grep -q 'still has backups' <(oxpanel-ctl tenant delete foo-bar --remove-home 2>&1 || true)
mkdir -p "$BK/ghost/b0000000000001"
check "a directory without a record is drift" grep -q "ORPHAN_BACKUP_ARCHIVE subject=$BK/ghost/b0000000000001" <(oxpanel-ctl host reconcile || true)
rm -r "$BK/ghost"
echo "-- a final backup retained after the tenant is deleted"
as_user foo-bar sh -c 'echo final-marker > /home/foo-bar/final.txt'
check_not "a retention period over 12 months is refused" oxpanel-ctl backup create foo-bar --retain-months 13
out="$(timeout 300 oxpanel-ctl backup create foo-bar --retain-months 12 --wait)" || true
check "a final backup retained for 12 months" grep -q 'state=JOB_STATE_SUCCEEDED' <<<"$out"
FINAL="$(backup_of "$out")"
EARLY="$(backup_ids foo-bar | head -1)"
check "an existing backup can be retained too" grep -q "^backup=$EARLY .* retain_until=[1-9]" <(oxpanel-ctl backup retain foo-bar "$EARLY" --months 1)
check "the final backup is dated about a year ahead" bash -c 'u="$(oxpanel-ctl backup list foo-bar | sed -n "s/^backup=$1 .* retain_until=\([0-9]*\) .*/\1/p")"; n="$(date +%s)"; test "$u" -ge $((n + 31556952 - 120)) && test "$u" -le $((n + 31556952))' _ "$FINAL"
for id in $(backup_ids foo-bar); do [ "$id" = "$FINAL" ] || [ "$id" = "$EARLY" ] || oxpanel-ctl backup delete foo-bar "$id" >/dev/null; done
check "a tenant with only retained backups can be deleted" grep -q '^deleted=true' <(oxpanel-ctl tenant delete foo-bar --remove-home)
check "its retained backups are kept, marked as of a deleted tenant" test "$(oxpanel-ctl backup list-retained | grep -c '^backup=.* tenant=foo-bar tenant_deleted=true ')" -eq 2
check "their files are kept" test -f "$BK/foo-bar/$FINAL/home.tar.gz"
check "retained backups are not drift" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)
check "a new tenant of the same name" grep -q '^created=true' <(oxpanel-ctl tenant create foo-bar --owner reseller1 --memory 128M)
check "does not see them" test -z "$(oxpanel-ctl backup list foo-bar)"
check "cannot restore them" grep -q 'NotFound' <(oxpanel-ctl backup restore foo-bar "$FINAL" --overwrite 2>&1 || true)
check "cannot delete them" grep -q '^deleted=false' <(oxpanel-ctl backup delete foo-bar "$FINAL")
check_not "cannot read them" as_user foo-bar cat "$BK/foo-bar/$FINAL/home.tar.gz"
check_not "the operator's restore needs the right source tenant" oxpanel-ctl backup restore-retained "$FINAL" --from bob --to foo-bar --overwrite
out="$(timeout 300 oxpanel-ctl backup restore-retained "$FINAL" --from foo-bar --to foo-bar --keep-existing --wait)" || true
check "the operator restores the final backup into the re-created account" grep -q 'kind=JOB_KIND_RESTORE tenant=foo-bar .* state=JOB_STATE_SUCCEEDED' <<<"$out"
check "the files are back, owned by the new account" test "$(stat -c '%U' /home/foo-bar/final.txt)/$(cat /home/foo-bar/final.txt)" = "foo-bar/final-marker"
check "an early deletion needs the deleted-tenant flag" grep -q '^deleted=true' <(oxpanel-ctl backup delete foo-bar "$EARLY" --tenant-deleted)
python3 - "/var/lib/oxpanel/backups/$FINAL.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1])); r["retain_until_unix"] = 1
json.dump(r, open(sys.argv[1], "w"), indent=2)
PY
systemctl restart oxpanel-daemon
check "a backup past its date is removed when the daemon starts" bash -c 'for i in $(seq 1 50); do [ ! -e "$1" ] && [ ! -e "$2" ] && exit 0; sleep 0.2; done; exit 1' _ "/var/lib/oxpanel/backups/$FINAL.json" "$BK/foo-bar/$FINAL"
check "no retained backups left" test -z "$(oxpanel-ctl backup list-retained)"
for t in alice bob foo-bar; do for id in $(backup_ids "$t"); do oxpanel-ctl backup delete "$t" "$id" >/dev/null; done; done
check "every backup deleted" test -z "$(ls "$BK")"
check "remove the PHP backup site" grep -q '^removed=true' <(oxpanel-ctl vhost remove bkphp.test)
check "remove the backup application sites" bash -c 'oxpanel-ctl vhost remove bknode.test | grep -q "^removed=true" && oxpanel-ctl vhost remove bkpy.test | grep -q "^removed=true"'
check "no drift after backups" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)
check "no job unit left behind" bash -c '! systemctl list-units --all --no-legend "oxpanel-job-*" | grep -q .'

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
