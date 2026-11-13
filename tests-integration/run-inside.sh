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
  install -Dm0755 /work/target/release/oxpanel-acme /usr/libexec/oxpanel/oxpanel-acme
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

echo "== HTTPS: bring your own certificate"
T=/root/tls-it; rm -rf "$T"; mkdir -p "$T"
https_of() { curl -s --resolve "$1:443:127.0.0.1" --cacert "$3" "https://$1$2"; }
https_code() { curl -s -o /dev/null -w '%{http_code}' --resolve "$1:443:127.0.0.1" --cacert "$3" "https://$1$2"; }
https_eventually() { local i; for i in $(seq 1 50); do [ "$(https_of "$1" "$2" "$3")" = "$4" ] && return 0; sleep 0.1; done; return 1; }
https_code_eventually() { local i; for i in $(seq 1 50); do [ "$(https_code "$1" "$2" "$3")" = "$4" ] && return 0; sleep 0.1; done; return 1; }
served_fingerprint() { openssl s_client -connect 127.0.0.1:443 -servername "$1" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null; }
# A private CA and leaf certificates: leaf <name> <key> <SANs> [openssl x509 date options...]
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$T/ca.key" -out "$T/ca.crt" -subj "/CN=OxPanel IT CA" -days 3 2>/dev/null
leaf() {
  local name="$1" key="$2" sans="$3"; shift 3
  openssl req -new -key "$T/$key" -subj "/CN=$name" -out "$T/$name.csr" 2>/dev/null
  openssl x509 -req -in "$T/$name.csr" -CA "$T/ca.crt" -CAkey "$T/ca.key" -set_serial "0x$(openssl rand -hex 8)" \
    -extfile <(printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\n' "$sans") -out "$T/$name.crt" "$@" 2>/dev/null
}
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/site.key" 2>/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$T/other.key" 2>/dev/null
leaf example.test site.key "DNS:example.test,DNS:www.example.test" -days 2
cat "$T/example.test.crt" "$T/ca.crt" > "$T/example.test.chain"
leaf expired.example.test site.key "DNS:example.test" -not_before 20200101000000Z -not_after 20200201000000Z
leaf wrongname.test site.key "DNS:wrongname.test"
check "host info reports TLS support" grep -q ' tls=true ' <(oxpanel-ctl host info)
check "a key that does not match is refused" grep -q 'InvalidArgument.*does not belong' <(oxpanel-ctl cert install example.test --chain "$T/example.test.chain" --key "$T/other.key" 2>&1 || true)
check "an expired certificate is refused" grep -q 'InvalidArgument.*expired' <(oxpanel-ctl cert install example.test --chain "$T/expired.example.test.crt" --key "$T/site.key" 2>&1 || true)
check "a certificate for another name is refused" grep -q 'InvalidArgument.*not valid for example.test' <(oxpanel-ctl cert install example.test --chain "$T/wrongname.test.crt" --key "$T/site.key" 2>&1 || true)
check "a refused certificate leaves nothing behind" bash -c 'test ! -e /etc/pki/oxpanel/example.test.crt && test ! -e /etc/pki/oxpanel/example.test.key && ! ls /etc/pki/oxpanel/*.new >/dev/null 2>&1 && ! grep -q 443 /etc/nginx/oxpanel.d/example.test.conf'
check "the refused key never reached the journal" bash -c '! journalctl -u oxpanel-daemon --no-pager | grep -q "PRIVATE KEY"'
out="$(oxpanel-ctl cert install example.test --chain "$T/example.test.chain" --key "$T/site.key")"
echo "$out"
check "certificate installed" bash -c 'grep -q "^changed=true" <<<"$1" && grep -q " source=uploaded " <<<"$1" && grep -q " names=example.test,www.example.test uncovered=- " <<<"$1"' _ "$out"
check "certificate directory is root-only" test "$(stat -c '%U %a' /etc/pki/oxpanel)" = "root 700"
check "private key is root 0600" test "$(stat -c '%U %a' /etc/pki/oxpanel/example.test.key)" = "root 600"
check "the key is not in the record" bash -c '! grep -q "PRIVATE" /var/lib/oxpanel/vhosts/example.test.json && ! grep -qF "$(sed -n 2p "$1")" /var/lib/oxpanel/vhosts/example.test.json' _ "$T/site.key"
check "the key never appeared on a command line or in the journal" bash -c '! journalctl --no-pager -b | grep -qF "$(sed -n 2p "$1")"' _ "$T/site.key"
check "a tenant cannot read the key" bash -c '! setpriv --reuid=bob --regid=bob --clear-groups -- cat /etc/pki/oxpanel/example.test.key >/dev/null 2>&1'
check "nginx -t passes with HTTPS" nginx -t
check "HTTPS serves the site with the uploaded certificate" https_eventually example.test / "$T/ca.crt" hello-from-alice
check "HTTPS serves the alias too" https_eventually www.example.test / "$T/ca.crt" hello-from-alice
check "the certificate served is exactly the uploaded one" test "$(served_fingerprint example.test)" = "$(openssl x509 -in "$T/example.test.crt" -noout -fingerprint -sha256)"
check "HTTP/2 is offered" test "$(curl -s -o /dev/null -w '%{http_version}' --http2 --resolve example.test:443:127.0.0.1 --cacert "$T/ca.crt" https://example.test/)" = 2
check "TLS 1.2 is accepted" test "$(curl -s -o /dev/null -w '%{http_code}' --tlsv1.2 --tls-max 1.2 --resolve example.test:443:127.0.0.1 --cacert "$T/ca.crt" https://example.test/)" = 200
check "TLS 1.1 is refused" bash -c '! openssl s_client -connect 127.0.0.1:443 -servername example.test -tls1_1 </dev/null >/dev/null 2>&1'
check "plain HTTP still serves the site (no redirect unless asked)" body_eventually example.test / hello-from-alice
check "dot-files are 404 over HTTPS too" test "$(https_code example.test /.env "$T/ca.crt")" = 404
check "an unknown name on 443 gets no certificate" bash -c '! openssl s_client -connect 127.0.0.1:443 -servername other.test </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"'
check "a request without SNI gets no certificate" bash -c '! openssl s_client -connect 127.0.0.1:443 -noservername </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"'
check "an unknown name on 443 never reaches a tenant" bash -c '! curl -sk --resolve other.test:443:127.0.0.1 https://other.test/ >/dev/null 2>&1'
check "installing the same certificate again changes nothing" grep -q '^changed=false' <(oxpanel-ctl cert install example.test --chain "$T/example.test.chain" --key "$T/site.key")
check "cert show reports it" grep -q '^domain=example.test certificate=present source=uploaded ' <(oxpanel-ctl cert show example.test)
check "HTTPS is not drift" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)

out="$(oxpanel-ctl vhost set example.test --tenant alice --alias www.example.test --redirect-https)"
check "redirect switched on (certificate kept)" bash -c 'grep -q "^changed=true" <<<"$1" && test -e /etc/pki/oxpanel/example.test.crt' _ "$out"
check "HTTP redirects to HTTPS" code_eventually example.test /x 301
check "the redirect keeps host and path" grep -qi '^location: https://example.test/x?y=1' <(curl -s -D- -o /dev/null -H 'Host: example.test' 'http://127.0.0.1/x?y=1')
setpriv --reuid=oxpanel-acme --regid=oxpanel-acme --clear-groups -- sh -c 'echo challenge-ok > /var/lib/oxpanel-acme/challenges/it-probe-token'
check "ACME challenges are still answered over HTTP while redirecting" body_eventually example.test /.well-known/acme-challenge/it-probe-token challenge-ok
check "the challenge directory is not reachable over HTTPS" test "$(https_code example.test /.well-known/acme-challenge/it-probe-token "$T/ca.crt")" = 404
check "HSTS is off by default" bash -c '! curl -s -D- -o /dev/null --resolve example.test:443:127.0.0.1 --cacert "$1" https://example.test/ | grep -qi strict-transport' _ "$T/ca.crt"
oxpanel-ctl vhost set example.test --tenant alice --alias www.example.test --redirect-https --hsts >/dev/null
check "HSTS is sent over HTTPS when enabled" bash -c 'for i in $(seq 1 50); do curl -s -D- -o /dev/null --resolve example.test:443:127.0.0.1 --cacert "$1" https://example.test/ | grep -qi "^strict-transport-security: max-age=31536000" && exit 0; sleep 0.1; done; exit 1' _ "$T/ca.crt"
check "HSTS is not sent over plain HTTP" bash -c '! curl -s -D- -o /dev/null -H "Host: example.test" http://127.0.0.1/ | grep -qi strict-transport'

check "suspend: HTTPS answers 503 with the site's own certificate" bash -c 'oxpanel-ctl tenant suspend alice >/dev/null' && check "suspended HTTPS site is 503" https_code_eventually example.test / "$T/ca.crt" 503
check "suspended site does not redirect" code_eventually example.test / 503
check "suspended site answers no ACME challenges" test "$(code_of example.test /.well-known/acme-challenge/it-probe-token)" = 503
check_not "no certificate can be requested for a suspended tenant" oxpanel-ctl cert request example.test
oxpanel-ctl tenant resume alice >/dev/null
check "resumed HTTPS site serves content" https_eventually example.test / "$T/ca.crt" hello-from-alice
rm -f /var/lib/oxpanel-acme/challenges/it-probe-token

cp -p /etc/pki/oxpanel/example.test.crt "$T/crt.bak"
echo edited >> /etc/pki/oxpanel/example.test.crt
chmod 0644 /etc/pki/oxpanel/example.test.key
echo stray > /etc/pki/oxpanel/stray.pem
out="$(oxpanel-ctl host reconcile || true)"
echo "$out"
check "reconcile reports the edited certificate and the opened key" test "$(grep -c '^kind=DRIFT_KIND_TLS_CERTIFICATE_DRIFT subject=example.test ' <<<"$out")" = 2
check "reconcile reports the stray file" grep -q '^kind=DRIFT_KIND_ORPHAN_TLS_FILE subject=/etc/pki/oxpanel/stray.pem ' <<<"$out"
rm -f /etc/pki/oxpanel/stray.pem
check "installing again heals the certificate files" grep -q '^changed=true' <(oxpanel-ctl cert install example.test --chain "$T/example.test.chain" --key "$T/site.key")
check "key is root-only again" test "$(stat -c '%a' /etc/pki/oxpanel/example.test.key)" = 600
check "no drift after healing" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)

echo "== HTTPS: PHP and Node.js applications"
oxpanel-ctl vhost set tlsphp.test --tenant bob --php >/dev/null
as_user bob sh -c 'echo "<?php echo \"https=\" . (\$_SERVER[\"HTTPS\"] ?? \"unset\") . \" port=\" . \$_SERVER[\"SERVER_PORT\"];" > /home/bob/public_html/index.php'
leaf tlsphp.test other.key "DNS:tlsphp.test"
check "certificate for the PHP site (EC key) installed" grep -q '^changed=true' <(oxpanel-ctl cert install tlsphp.test --chain "$T/tlsphp.test.crt" --key "$T/other.key")
check "PHP sees HTTPS=on over HTTPS" https_eventually tlsphp.test / "$T/ca.crt" "https=on port=443"
check "PHP sees no HTTPS over HTTP" body_eventually tlsphp.test / "https=unset port=80"
oxpanel-ctl vhost set tlsnode.test --tenant bob --app node >/dev/null
as_user bob sh -c 'cat > /home/bob/apps/tlsnode.test/app.js' <<'JS'
require('http').createServer((req, res) => {
  res.end(`node proto=${req.headers['x-forwarded-proto']} host=${req.headers.host}`);
}).listen(process.env.PORT);
JS
oxpanel-ctl vhost restart-app tlsnode.test >/dev/null
leaf tlsnode.test other.key "DNS:tlsnode.test"
check "certificate for the Node.js site installed" grep -q '^changed=true' <(oxpanel-ctl cert install tlsnode.test --chain "$T/tlsnode.test.crt" --key "$T/other.key")
check "the Node.js app sees X-Forwarded-Proto https over HTTPS" https_eventually tlsnode.test /p "$T/ca.crt" "node proto=https host=tlsnode.test"
check "the Node.js app sees X-Forwarded-Proto http over HTTP" body_eventually tlsnode.test /p "node proto=http host=tlsnode.test"
check "removing a certificate makes the site HTTP-only again" bash -c 'oxpanel-ctl cert remove tlsnode.test | grep -q "^removed=true" && test ! -e /etc/pki/oxpanel/tlsnode.test.key && test ! -e /etc/pki/oxpanel/tlsnode.test.crt && ! grep -q 443 /etc/nginx/oxpanel.d/tlsnode.test.conf'
check "after removal the name gets no certificate on 443" bash -c 'for i in $(seq 1 50); do openssl s_client -connect 127.0.0.1:443 -servername tlsnode.test </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE" || exit 0; sleep 0.1; done; exit 1'
check "second removal is a no-op" grep -q '^removed=false' <(oxpanel-ctl cert remove tlsnode.test)
check "removing a site removes its certificate" bash -c 'oxpanel-ctl vhost remove tlsphp.test | grep -q "^removed=true" && test ! -e /etc/pki/oxpanel/tlsphp.test.key && test ! -e /etc/pki/oxpanel/tlsphp.test.crt'
oxpanel-ctl vhost remove tlsnode.test >/dev/null
check "no drift after the HTTPS sites" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)

echo "== HTTPS: ACME end to end against a local test CA (Pebble)"
if [ "${OXPANEL_IT_SKIP_ACME:-0}" = 1 ]; then
  echo "SKIPPED: ACME end to end (OXPANEL_IT_SKIP_ACME=1)"
else
  # Pebble, Let's Encrypt's ACME test server, from its pinned release.
  PEBBLE=/usr/local/bin/oxpanel-it-pebble
  PEBBLE_URL=https://github.com/letsencrypt/pebble/releases/download/v2.10.1/pebble-linux-amd64.tar.gz
  PEBBLE_SHA256=4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed
  if [ ! -x "$PEBBLE" ]; then
    curl -sSfL -o "$T/pebble.tar.gz" "$PEBBLE_URL" || fail "cannot download Pebble (set OXPANEL_IT_SKIP_ACME=1 to skip the ACME checks)"
    check "Pebble download matches the pinned checksum" bash -c 'echo "$1  $2" | sha256sum -c --quiet' _ "$PEBBLE_SHA256" "$T/pebble.tar.gz"
    tar -xzf "$T/pebble.tar.gz" -C "$T"
    install -m0755 "$T/pebble-linux-amd64/linux/amd64/pebble" "$PEBBLE"
  fi
  # Outside /root and /home: the ACME client's unit (ProtectHome=yes) must read the CA.
  P=/usr/local/share/oxpanel-it; mkdir -p "$P"
  cp "$T/ca.crt" "$P/ca.crt"
  leaf localhost other.key "DNS:localhost,IP:127.0.0.1"
  cp "$T/localhost.crt" "$P/pebble.crt"; install -m0600 "$T/other.key" "$P/pebble.key"
  # Certificates valid for 10 days, so a renewal (due 30 days ahead) can be tested at once.
  cat > "$P/pebble.json" <<JSON
{"pebble": {"listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000",
  "certificate": "$P/pebble.crt", "privateKey": "$P/pebble.key", "httpPort": 80, "tlsPort": 5001,
  "ocspResponderURL": "", "externalAccountBindingRequired": false,
  "profiles": {"default": {"description": "OxPanel IT", "validityPeriod": 864000}}}}
JSON
  systemd-run --unit=oxpanel-it-pebble --collect --setenv=PEBBLE_VA_NOSLEEP=1 "$PEBBLE" -config "$P/pebble.json" >/dev/null
  check "Pebble is up" bash -c 'for i in $(seq 1 100); do curl -sf --cacert "$1" https://localhost:14000/dir >/dev/null && exit 0; sleep 0.1; done; exit 1' _ "$P/ca.crt"
  cp -p /etc/hosts "$T/hosts.bak"
  echo "127.0.0.1 acme.test www.acme.test" >> /etc/hosts
  cp -p /etc/oxpanel/daemon.env "$T/daemon.env.bak"
  printf 'OXPANEL_ACME_DIRECTORY_URL=https://localhost:14000/dir\nOXPANEL_ACME_CA_FILE=%s/ca.crt\nOXPANEL_ACME_EMAIL=hostmaster@example.org\n' "$P" >> /etc/oxpanel/daemon.env
  systemctl restart oxpanel-daemon
  check "host info reports ACME against the test CA" grep -q ' acme=true acme_directory=https://localhost:14000/dir' <(oxpanel-ctl host info)
  oxpanel-ctl vhost set acme.test --tenant alice --alias www.acme.test --redirect-https >/dev/null
  as_user alice sh -c 'mkdir -p /home/alice/public_html && echo hello-from-alice > /home/alice/public_html/index.html'
  # `systemctl reload nginx` returns before the new workers serve the new site;
  # until then the catch-all closes the connection on the CA's validation request.
  check "acme.test is live over HTTP before the request" code_eventually acme.test / 200
  check "www.acme.test too" code_eventually www.acme.test / 200
  out="$(oxpanel-ctl cert request acme.test || true)"
  echo "$out" | tail -8
  check "ACME: certificate issued and installed" bash -c 'grep -q "^succeeded=true" <<<"$1" && grep -q " source=acme " <<<"$1" && grep -q " names=acme.test,www.acme.test uncovered=- " <<<"$1"' _ "$out"
  curl -sf --cacert "$P/ca.crt" https://localhost:15000/roots/0 > "$T/pebble-root.pem"
  check "ACME: the site is served over HTTPS with the issued certificate" https_eventually acme.test / "$T/pebble-root.pem" hello-from-alice
  check "ACME: the alias too" https_eventually www.acme.test / "$T/pebble-root.pem" hello-from-alice
  check "ACME: HTTP redirects" code_eventually acme.test / 301
  check "ACME: private key is root 0600" test "$(stat -c '%U %a' /etc/pki/oxpanel/acme.test.key)" = "root 600"
  check "ACME: no challenge, request, reply or pending key is left behind" bash -c 'test -z "$(find /var/lib/oxpanel-acme/challenges /var/lib/oxpanel-acme/csr /var/lib/oxpanel-acme/issued -mindepth 1)" && ! ls /etc/pki/oxpanel/*.pending >/dev/null 2>&1'
  check "ACME: the client ran as oxpanel-acme (it owns its account key, 0600)" bash -c 'test "$(stat -c "%U %a" /var/lib/oxpanel-acme/account/*.pk8)" = "oxpanel-acme 600"'
  check "ACME: the client's account cannot read any site key" bash -c '! setpriv --reuid=oxpanel-acme --regid=oxpanel-acme --clear-groups -- cat /etc/pki/oxpanel/acme.test.key >/dev/null 2>&1'
  check "ACME: the client's output reached the journal" bash -c 'journalctl --no-pager -u oxpanel-acme-acme.test.service | grep -q "certificate issued"'
  check "ACME: not drift" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)
  before="$(sha256sum /etc/pki/oxpanel/acme.test.crt)"
  out="$(oxpanel-ctl cert renew || true)"
  echo "$out"
  check "ACME: a certificate expiring within 30 days is renewed" bash -c 'grep -q "^renewals=1$" <<<"$1" && grep -q "^domain=acme.test succeeded=true$" <<<"$1"' _ "$out"
  check "ACME: the renewed certificate is a new one" test "$(sha256sum /etc/pki/oxpanel/acme.test.crt)" != "$before"
  check "ACME: the renewed certificate is served" bash -c 'for i in $(seq 1 50); do test "$(openssl s_client -connect 127.0.0.1:443 -servername acme.test </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256)" = "$(openssl x509 -in /etc/pki/oxpanel/acme.test.crt -noout -fingerprint -sha256)" && exit 0; sleep 0.1; done; exit 1'
  oxpanel-ctl vhost set unreachable.test --tenant alice >/dev/null
  check "unreachable.test is live over HTTP" code_eventually unreachable.test / 200
  check "ACME: a name the CA cannot validate fails with the reason (exit 4)" bash -c 'oxpanel-ctl cert request unreachable.test > /root/acme-fail.out 2>&1; rc=$?; grep -q "^succeeded=false" /root/acme-fail.out && grep -q "unreachable.test" /root/acme-fail.out && test $rc -eq 4'
  check "ACME: a failed request installs nothing" bash -c 'test ! -e /etc/pki/oxpanel/unreachable.test.crt && ! ls /etc/pki/oxpanel/*.pending >/dev/null 2>&1 && grep -q "certificate=-" <(oxpanel-ctl cert show unreachable.test)'
  oxpanel-ctl vhost remove unreachable.test >/dev/null
  check "ACME: removing the site removes the certificate" bash -c 'oxpanel-ctl vhost remove acme.test | grep -q "^removed=true" && test ! -e /etc/pki/oxpanel/acme.test.key'

  echo "-- Automatic HTTPS (no request at all)"
  # cert_names_eventually <domain> <names> [seconds]: an ACME certificate for exactly these names appears.
  cert_names_eventually() { local i; for i in $(seq 1 $(( ${3:-60} * 2 ))); do oxpanel-ctl cert show "$1" 2>/dev/null | grep -q " source=acme .* names=$2 " && return 0; sleep 0.5; done; oxpanel-ctl cert show "$1"; oxpanel-ctl cert auto status "$1"; return 1; }
  auto_status_eventually() { local i; for i in $(seq 1 120); do oxpanel-ctl cert auto status "$1" | grep -q "$2" && return 0; sleep 0.5; done; oxpanel-ctl cert auto status "$1"; return 1; }
  check "Automatic HTTPS is on by default" grep -q ' auto_https=true$' <(oxpanel-ctl host info)
  echo "127.0.0.1 auto.test www.auto.test new.auto.test optout.test susp.test off.test" >> /etc/hosts
  oxpanel-ctl vhost set auto.test --tenant alice --alias www.auto.test >/dev/null
  check "a new site gets a certificate with no request at all" cert_names_eventually auto.test "auto.test,www.auto.test"
  check "... and is served over HTTPS with it" https_eventually auto.test / "$T/pebble-root.pem" hello-from-alice
  check "status: covered" auto_status_eventually auto.test '^domain=auto.test auto_https=covered covered=auto.test,www.auto.test pending=- skipped=- '
  check "no probe file is left in the challenge directory" test -z "$(find /var/lib/oxpanel-acme/challenges -mindepth 1)"
  oxpanel-ctl vhost set auto.test --tenant alice --alias www.auto.test --alias new.auto.test >/dev/null
  check "an alias added later gets covered" cert_names_eventually auto.test "auto.test,new.auto.test,www.auto.test"
  oxpanel-ctl vhost set auto.test --tenant alice --alias www.auto.test --alias new.auto.test --alias nx.auto.test >/dev/null
  check "a name that does not resolve is skipped, the rest stays covered" auto_status_eventually auto.test '^domain=auto.test auto_https=partial covered=auto.test,new.auto.test,www.auto.test pending=- skipped=nx.auto.test '
  st="$(oxpanel-ctl cert auto status auto.test)"; echo "$st"
  check "the reason is given in plain words" grep -q '^  skipped name=nx.auto.test failures=1 next_attempt=[0-9]* reason=the name does not resolve$' <<<"$st"
  next="$(sed -n 's/^  skipped name=nx.auto.test failures=1 next_attempt=\([0-9]*\) .*/\1/p' <<<"$st")"
  check "the name backs off for about an hour" test "$(( next - $(date +%s) ))" -gt 3300
  check "the certificate does not name the unresolvable alias (it is listed as uncovered)" bash -c 'oxpanel-ctl cert show auto.test | grep -q " names=auto.test,new.auto.test,www.auto.test uncovered=nx.auto.test "'
  systemctl restart oxpanel-daemon
  check "back-off survives a daemon restart" grep -q "^  skipped name=nx.auto.test failures=1 next_attempt=$next " <(oxpanel-ctl cert auto status auto.test)
  oxpanel-ctl cert auto run >/dev/null || true
  check "a run over every site respects the back-off" grep -q "^  skipped name=nx.auto.test failures=1 next_attempt=$next " <(oxpanel-ctl cert auto status auto.test)
  oxpanel-ctl cert auto run auto.test >/dev/null || true
  check "a run for the one site retries now, and backs off longer" grep -q '^  skipped name=nx.auto.test failures=2 ' <(oxpanel-ctl cert auto status auto.test)

  oxpanel-ctl vhost set optout.test --tenant alice --no-auto-https >/dev/null
  sleep 6
  oxpanel-ctl cert auto run optout.test >/dev/null || true
  check "a site that opted out gets nothing" bash -c 'grep -q "certificate=- auto_https=off" <(oxpanel-ctl cert show optout.test) && grep -q "^domain=optout.test auto_https=disabled " <(oxpanel-ctl cert auto status optout.test)'

  oxpanel-ctl tenant create carol >/dev/null
  oxpanel-ctl tenant suspend carol >/dev/null
  oxpanel-ctl vhost set susp.test --tenant carol >/dev/null
  sleep 6
  oxpanel-ctl cert auto run susp.test >/dev/null || true
  check "nothing is requested for a suspended tenant" bash -c 'grep -q "certificate=-" <(oxpanel-ctl cert show susp.test) && grep -q "^domain=susp.test auto_https=suspended " <(oxpanel-ctl cert auto status susp.test) && ! journalctl --no-pager -q -u oxpanel-acme-susp.test.service | grep -q .'
  oxpanel-ctl tenant resume carol >/dev/null
  check "after resume the site catches up by itself" cert_names_eventually susp.test "susp.test"

  check "a valid uploaded certificate is left alone" bash -c 'oxpanel-ctl cert auto run example.test >/dev/null; grep -q " source=uploaded " <(oxpanel-ctl cert show example.test) && grep -q "^domain=example.test auto_https=uploaded " <(oxpanel-ctl cert auto status example.test)'

  echo "OXPANEL_AUTO_HTTPS=false" >> /etc/oxpanel/daemon.env
  systemctl restart oxpanel-daemon
  check "the host-wide switch is reported" grep -q ' auto_https=false$' <(oxpanel-ctl host info)
  oxpanel-ctl vhost set off.test --tenant alice >/dev/null
  sleep 6
  oxpanel-ctl cert auto run off.test >/dev/null || true
  check "with the host-wide switch off nothing is requested" bash -c 'grep -q "certificate=-" <(oxpanel-ctl cert show off.test) && grep -q "^domain=off.test auto_https=disabled " <(oxpanel-ctl cert auto status off.test)'
  sed -i '/^OXPANEL_AUTO_HTTPS=false$/d' /etc/oxpanel/daemon.env
  systemctl restart oxpanel-daemon
  check "switched back on, the waiting site is served" bash -c 'oxpanel-ctl cert auto run off.test >/dev/null; grep -q " source=acme " <(oxpanel-ctl cert show off.test)'
  check "Automatic HTTPS state is not drift" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)
  for d in auto.test optout.test susp.test off.test; do oxpanel-ctl vhost remove "$d" >/dev/null; done
  check "its state goes with the sites" bash -c 'test -z "$(find /var/lib/oxpanel/auto-https -name "auto.test.json" -o -name "susp.test.json" -o -name "off.test.json")"'
  oxpanel-ctl tenant delete carol --remove-home >/dev/null

  echo "-- External Account Binding (Pebble requiring it)"
  systemctl stop oxpanel-it-pebble
  EAB_KEY="$(openssl rand 32 | base64 -w0 | tr '+/' '-_' | tr -d '=')"
  cat > "$P/pebble-eab.json" <<JSON
{"pebble": {"listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000",
  "certificate": "$P/pebble.crt", "privateKey": "$P/pebble.key", "httpPort": 80, "tlsPort": 5001,
  "ocspResponderURL": "", "externalAccountBindingRequired": true,
  "externalAccountMACKeys": {"oxpanel-it-kid": "$EAB_KEY"}}}
JSON
  systemd-run --unit=oxpanel-it-pebble-eab --collect --setenv=PEBBLE_VA_NOSLEEP=1 "$PEBBLE" -config "$P/pebble-eab.json" >/dev/null
  check "Pebble (EAB required) is up" bash -c 'for i in $(seq 1 100); do curl -sf --cacert "$1" https://localhost:14000/dir >/dev/null && exit 0; sleep 0.1; done; exit 1' _ "$P/ca.crt"
  echo "127.0.0.1 eab.test" >> /etc/hosts
  oxpanel-ctl vhost set eab.test --tenant alice --no-auto-https >/dev/null
  code_eventually eab.test / 200 || true
  check "EAB: without a binding the CA refuses" bash -c 'oxpanel-ctl cert request eab.test > /root/eab.out 2>&1; grep -q "^succeeded=false" /root/eab.out && grep -qi "externalAccountBinding" /root/eab.out'
  printf 'kid=oxpanel-it-kid\nhmac_key=%s\n' "$EAB_KEY" > /etc/oxpanel/acme-eab
  chmod 0644 /etc/oxpanel/acme-eab
  echo "OXPANEL_ACME_EAB_FILE=/etc/oxpanel/acme-eab" >> /etc/oxpanel/daemon.env
  systemctl restart oxpanel-daemon
  check "EAB: a binding file others can read is refused" grep -q 'FailedPrecondition.*readable by root only' <(oxpanel-ctl cert request eab.test 2>&1 || true)
  chmod 0600 /etc/oxpanel/acme-eab
  out="$(oxpanel-ctl cert request eab.test || true)"; echo "$out" | tail -4
  check "EAB: with the binding the certificate is issued" bash -c 'grep -q "^succeeded=true" <<<"$1" && grep -q " source=acme " <<<"$1" && grep -q "binding the account to an external account" <<<"$1"' _ "$out"
  check "EAB: the HMAC key never reached the journal or a command line" bash -c '! journalctl --no-pager -b | grep -qF "$1"' _ "$EAB_KEY"
  oxpanel-ctl vhost remove eab.test >/dev/null
  systemctl stop oxpanel-it-pebble-eab
  rm -f /etc/oxpanel/acme-eab
  cp -p "$T/hosts.bak" /etc/hosts
  cp -p "$T/daemon.env.bak" /etc/oxpanel/daemon.env
  systemctl restart oxpanel-daemon
  check "daemon restarts with the default ACME settings" systemctl -q is-active oxpanel-daemon
  rm -rf "$P" "$PEBBLE"
fi
check "certificate removed with the last HTTPS check" grep -q '^removed=true' <(oxpanel-ctl cert remove example.test)

echo "== dry-run mode: the whole daemon against a fake OS, as an unprivileged user"
DRY=/tmp/oxpanel-dry; rm -rf "$DRY"; install -d -o panelapi -g panelapi -m 0700 "$DRY"
dry() { setpriv --reuid=panelapi --regid=panelapi --clear-groups --no-new-privs -- env \
  OXPANEL_STATE_DIR="$DRY/state" OXPANEL_HOME_BASE="$DRY/home" OXPANEL_SYSTEMD_UNIT_DIR="$DRY/systemd" \
  OXPANEL_NGINX_CONF_DIR="$DRY/nginx/oxpanel.d" OXPANEL_NGINX_INCLUDE_FILE="$DRY/nginx/00-oxpanel.conf" \
  OXPANEL_NGINX_LOG_DIR="$DRY/log" OXPANEL_PHP_CONF_DIR="$DRY/php" OXPANEL_SOCKET_PATH="$DRY/sock" \
  OXPANEL_SOCKET_GROUP= OXPANEL_ALLOWED_UIDS="$(id -u panelapi)" "$@"; }
dry /usr/sbin/oxpanel-daemon --dry-run > /root/dry-run.log 2>&1 &
DRYPID=$!
for _ in $(seq 1 50); do [ -S "$DRY/sock" ] && break; sleep 0.1; done
check "the dry-run daemon runs without root and opens its socket" test -S "$DRY/sock"
check "an unprivileged client creates a tenant in it" grep -q '^created=true' <(dry oxpanel-ctl tenant create dryt --memory 64M)
check "and a virtual host" grep -q '^changed=true' <(dry oxpanel-ctl vhost set dry.test --tenant dryt)
check "the fake host reports the dry-run flag" grep -q ' dry_run=true' <(dry oxpanel-ctl host info)
check "the records are written under the dry-run state directory" test -f "$DRY/state/tenants/dryt.json"
check_not "no real account was created" id dryt
check "no real unit or Nginx file was written" bash -c '! ls /etc/systemd/system/oxpanel-tenant-dryt.slice /etc/nginx/oxpanel.d/dry.test.conf 2>/dev/null | grep -q .'
kill "$DRYPID"; wait "$DRYPID" 2>/dev/null || true
check "the real daemon was not disturbed" systemctl -q is-active oxpanel-daemon
rm -rf "$DRY"

echo "== preflight refusals"
check "--check-config passes on this host" /usr/sbin/oxpanel-daemon --check-config
check "a non-root user cannot start the daemon" bash -c '! setpriv --reuid=panelapi --regid=panelapi --clear-groups -- /usr/sbin/oxpanel-daemon --check-config >/dev/null 2>&1'
check "a missing web-server account is refused" bash -c '! OXPANEL_WEB_USER=nosuchweb1 /usr/sbin/oxpanel-daemon --check-config >/dev/null 2>&1'
check "root as the web-server account is refused" bash -c '! OXPANEL_WEB_USER=root /usr/sbin/oxpanel-daemon --check-config >/dev/null 2>&1'
check "a tenant as the web-server account is refused" bash -c '! OXPANEL_WEB_USER=bob /usr/sbin/oxpanel-daemon --check-config >/dev/null 2>&1'
check "a missing socket group is refused" bash -c '! OXPANEL_SOCKET_GROUP=nosuchgrp1 /usr/sbin/oxpanel-daemon --check-config >/dev/null 2>&1'

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
