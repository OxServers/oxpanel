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
  install -Dm0644 /work/packaging/systemd/oxpanel-dns.service /etc/systemd/system/oxpanel-dns.service
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
  out="$(oxpanel-ctl cert request eab.test || true)"; echo "$out" | tail -40
  # The binding reaches the client as a systemd credential. systemd hands
  # credentials to an unprivileged unit on every real host; in a rootless
  # container started with CAP_SYS_ADMIN (which the SFTP bind mounts need)
  # it mounts them on ramfs inside the user namespace, where the unit's user
  # cannot read them. Probe that exact situation; the acceptance VM (phase
  # 20) always runs the check.
  # (The probe loads the very file the daemon hands over, so that systemd
  # and SELinux treat it as they treat the real request. An issued
  # certificate needs no probe: the full check below then applies.)
  if grep -q "^succeeded=true" <<<"$out" || systemd-run --wait --collect --quiet --unit=oxpanel-it-credprobe -p User=oxpanel-acme \
       -p LoadCredential=p:/etc/oxpanel/acme-eab /usr/bin/test -r /run/credentials/oxpanel-it-credprobe.service/p 2>/dev/null; then
    check "EAB: with the binding the certificate is issued" bash -c 'grep -q "^succeeded=true" <<<"$1" && grep -q " source=acme " <<<"$1" && grep -q "binding the account to an external account" <<<"$1"' _ "$out"
  else
    echo "info - SKIPPED here (runs on the acceptance VM): this container's systemd cannot pass a credential to an unprivileged unit"
    check "EAB: the client was given the binding and could not read it in this container" bash -c 'journalctl --no-pager -b -u oxpanel-acme-eab.test | grep -q "cannot read the EAB credential"'
  fi
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
  check "removing the last key" grep -q 'remaining=0' <(oxpanel-ctl sftp remove-key sftpa "$FPB" --end-sessions)
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

echo "== sftp passwords, end_sessions"
if [ -x /usr/sbin/sshd ] && command -v sftp >/dev/null; then
  export PWDIR; PWDIR="$(mktemp -d /root/sftp-pw.XXXXXX)"; chmod 700 "$PWDIR"
  export PW='correct horse battery staple'
  printf '%s\n' "$PW" > "$PWDIR/pw"; printf 'wrong horse battery staple\n' > "$PWDIR/bad"
  # The client reads the password from a file through SSH_ASKPASS: never in an argv.
  printf '#!/bin/sh\ncat "$PWFILE"\n' > "$PWDIR/askpass"; chmod 700 "$PWDIR/askpass"
  export PW_O="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1"
  # pw_sftp <user> <password file>, sftp batch commands on stdin
  # shellcheck disable=SC2086
  pw_sftp() { PWFILE="$2" SSH_ASKPASS="$PWDIR/askpass" SSH_ASKPASS_REQUIRE=force setsid -w sftp $PW_O -o BatchMode=no -b - "$1@127.0.0.1"; }
  pw_ok() { local i; for i in $(seq 1 40); do echo pwd | pw_sftp "$1" "$2" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
  pw_denied() { local i out; for i in $(seq 1 40); do out="$(echo pwd | pw_sftp "$1" "$2" 2>&1)" && return 1; grep -q "Permission denied" <<<"$out" && return 0; sleep 1; done; return 1; }
  export -f pw_sftp pw_ok pw_denied
  key_session_count() { pgrep -u "$1" sshd 2>/dev/null | wc -l; }

  check "host info reports sftp_passwords=true (the default)" grep -q ' sftp_passwords=true ' <(oxpanel-ctl host info)
  check "create tenant pwa" grep -q '^created=true' <(oxpanel-ctl tenant create pwa)
  check "create tenant pwb" grep -q '^created=true' <(oxpanel-ctl tenant create pwb)
  check_not "a password shorter than 12 characters is refused" bash -c 'echo short-pw | oxpanel-ctl sftp set-password pwa'
  check "a tenant without a password is not offered password login" bash -c '/usr/sbin/sshd -T -C user=pwa,host=x,addr=127.0.0.1 | grep -qx "passwordauthentication no"'
  check "set-password (read from stdin)" bash -c 'oxpanel-ctl sftp set-password pwa < "$PWDIR/pw" | grep -q "^password=set" && oxpanel-ctl tenant get pwa | grep -q " sftp_password=true "'
  check "the shadow file holds a hash, not the password" bash -c 'f="$(getent shadow pwa | cut -d: -f2)"; [ "${f#\$}" != "$f" ] && ! grep -qF "$PW" /etc/shadow'
  check "the password is in no record and not in the journal" bash -c '! grep -rqF "$PW" /var/lib/oxpanel && ! journalctl -u oxpanel-daemon --no-pager | grep -qF "$PW"'
  check "the account is in the password group" bash -c 'id -nG pwa | grep -qw oxpanel-sftp-password'
  check "password tenants are confined exactly like key tenants" bash -c 'e="$(/usr/sbin/sshd -T -C user=pwa,host=x,addr=127.0.0.1)"; for kv in "passwordauthentication yes" "authenticationmethods publickey password" "maxauthtries 3" "forcecommand internal-sftp" "chrootdirectory /var/lib/oxpanel/sftp/%u" "permittty no" "disableforwarding yes" "allowtcpforwarding no" "x11forwarding no" "permittunnel no" "kbdinteractiveauthentication no"; do grep -qx "$kv" <<<"$e" || { echo "missing: $kv"; exit 1; }; done'
  check "password login works and lands in the home" bash -c 'pw_ok pwa "$PWDIR/pw" && echo pwd | pw_sftp pwa "$PWDIR/pw" | grep -q "/home/pwa"'
  echo "uploaded-with-a-password" > "$PWDIR/up.txt"
  check "upload with a password; the file belongs to the tenant" bash -c 'echo "put $PWDIR/up.txt up.txt" | pw_sftp pwa "$PWDIR/pw" && test "$(stat -c %U /home/pwa/up.txt)" = pwa'
  check "the tenant sees only its own home (password login)" bash -c 'test "$(echo "ls -1 /" | pw_sftp pwa "$PWDIR/pw" | grep -v "^sftp>")" = "/home" && ! echo "ls /etc" | pw_sftp pwa "$PWDIR/pw" >/dev/null 2>&1'
  check "a wrong password is refused" pw_denied pwa "$PWDIR/bad"
  check "the password does not work for another tenant" pw_denied pwb "$PWDIR/pw"
  # shellcheck disable=SC2086
  out="$(PWFILE="$PWDIR/pw" SSH_ASKPASS="$PWDIR/askpass" SSH_ASKPASS_REQUIRE=force setsid -w ssh $PW_O pwa@127.0.0.1 'echo shell-ran; touch /home/pwa/shell-ran' </dev/null 2>&1 || true)"
  check "no shell with a password either" bash -c '! grep -q shell-ran <<<"$1" && test ! -e /home/pwa/shell-ran' _ "$out"
  check_not "no TCP forwarding with a password (ssh -W)" bash -c 'printf "GET / HTTP/1.0\r\n\r\n" | PWFILE="$PWDIR/pw" SSH_ASKPASS="$PWDIR/askpass" SSH_ASKPASS_REQUIRE=force timeout 20 setsid -w ssh $PW_O -W 127.0.0.1:80 pwa@127.0.0.1 2>/dev/null | grep -q "^HTTP/"'
  check "no drift with a password" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)

  # Suspension locks the hash (no plaintext kept) and ends sessions; resume unlocks it.
  check "log in again before the session test" pw_ok pwa "$PWDIR/pw"
  ( sleep 60 | PWFILE="$PWDIR/pw" SSH_ASKPASS="$PWDIR/askpass" SSH_ASKPASS_REQUIRE=force setsid -w ssh $PW_O -s pwa@127.0.0.1 sftp >/dev/null 2>&1 ) &
  HOLD=$!
  check "an open password session" bash -c 'for i in $(seq 1 50); do pgrep -u pwa sshd >/dev/null && exit 0; sleep 0.2; done; exit 1'
  check "suspend pwa" grep -q '^changed=true' <(oxpanel-ctl tenant suspend pwa)
  check "the hash is locked while suspended (kept, prefixed with !)" bash -c 'getent shadow pwa | cut -d: -f2 | grep -qE "^![^!*]"'
  if [ "$LOGIND" = 1 ]; then
    check "suspension ends the password session" bash -c 'for i in $(seq 1 50); do pgrep -u pwa sshd >/dev/null || exit 0; sleep 0.2; done; exit 1'
  fi
  check "no password login while suspended" pw_denied pwa "$PWDIR/pw"
  check "resume pwa" grep -q '^changed=true' <(oxpanel-ctl tenant resume pwa)
  check "the same password works again after resume" pw_ok pwa "$PWDIR/pw"
  pkill -P "$HOLD" 2>/dev/null || true; kill "$HOLD" 2>/dev/null || true; wait "$HOLD" 2>/dev/null || true
  pkill -u pwa sshd 2>/dev/null || true

  # end_sessions: without it a live session continues; with it, it ends.
  ssh-keygen -q -t ed25519 -N '' -f "$PWDIR/k"
  check "pwa also gets a key" grep -q '^changed=true' <(oxpanel-ctl sftp add-key pwa --key-file "$PWDIR/k.pub")
  FPK="$(ssh-keygen -lf "$PWDIR/k.pub" | awk '{print $2}')"
  # shellcheck disable=SC2086
  hold_key_session() { ( sleep 60 | ssh $SSH_O -i "$PWDIR/k" -s pwa@127.0.0.1 sftp >/dev/null 2>&1 ) & HOLD=$!; for i in $(seq 1 50); do pgrep -u pwa sshd >/dev/null && return 0; sleep 0.2; done; return 1; }
  check "key login (after the refusals above)" bash -c 'for i in $(seq 1 40); do echo pwd | sftp $SSH_O -i "$PWDIR/k" -b - pwa@127.0.0.1 >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1'
  check "an open key session" hold_key_session
  check "clear-password without --end-sessions" grep -q '^cleared=true' <(oxpanel-ctl sftp clear-password pwa)
  check "the open session continues" bash -c 'sleep 1; pgrep -u pwa sshd >/dev/null'
  check "but the password no longer logs in" pw_denied pwa "$PWDIR/pw"
  check "the hash is gone and so is the group membership" bash -c 'test "$(getent shadow pwa | cut -d: -f2)" = "!!" && ! id -nG pwa | grep -qw oxpanel-sftp-password'
  check "remove-key without --end-sessions: the session still continues" bash -c 'oxpanel-ctl sftp remove-key pwa "$1" | grep -q remaining=0 && sleep 1 && pgrep -u pwa sshd >/dev/null' _ "$FPK"
  if [ "$LOGIND" = 1 ]; then
    check "its mount is kept while it is open (reported until the daemon tidies it up)" bash -c 'findmnt -n /var/lib/oxpanel/sftp/pwa/home/pwa >/dev/null && oxpanel-ctl host reconcile | grep -q "kind=DRIFT_KIND_ORPHAN_SFTP_ACCESS"'
  fi
  pkill -P "$HOLD" 2>/dev/null || true; kill "$HOLD" 2>/dev/null || true; wait "$HOLD" 2>/dev/null || true
  pkill -u pwa sshd 2>/dev/null || true
  check "after the session ended, a daemon restart removes the kept mount" bash -c 'for i in $(seq 1 40); do systemctl -q is-active "user-$(id -u pwa).slice" || break; sleep 0.5; done; systemctl restart oxpanel-daemon && test ! -e /var/lib/oxpanel/sftp/pwa && oxpanel-ctl host reconcile | grep -qx "drifts=0"'
  check "key again" grep -q '^changed=true' <(oxpanel-ctl sftp add-key pwa --key-file "$PWDIR/k.pub")
  check "key login works" bash -c 'for i in $(seq 1 40); do echo pwd | sftp $SSH_O -i "$PWDIR/k" -b - pwa@127.0.0.1 >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1'
  check "an open key session (2)" hold_key_session
  if [ "$LOGIND" = 1 ]; then
    check "remove-key --end-sessions ends it" bash -c 'oxpanel-ctl sftp remove-key pwa "$1" --end-sessions | grep -q remaining=0 && for i in $(seq 1 50); do pgrep -u pwa sshd >/dev/null || exit 0; sleep 0.2; done; exit 1' _ "$FPK"
  else
    check "remove-key --end-sessions" bash -c 'oxpanel-ctl sftp remove-key pwa "$1" --end-sessions | grep -q remaining=0' _ "$FPK"
  fi
  pkill -P "$HOLD" 2>/dev/null || true; kill "$HOLD" 2>/dev/null || true; wait "$HOLD" 2>/dev/null || true

  # Reconcile notices password state that differs from the record, both ways.
  check "a password set behind OxPanel's back is drift" bash -c 'printf "pwb:%s\n" "$PW" | chpasswd && oxpanel-ctl host reconcile | grep -q "kind=DRIFT_KIND_SFTP_ACCESS_DRIFT subject=pwb"'
  check "set-password pwa again" bash -c 'oxpanel-ctl sftp set-password pwa < "$PWDIR/pw" | grep -q "^password=set"'
  check "a recorded password that vanished is drift" bash -c 'printf "pwa:!!\n" | chpasswd -e && oxpanel-ctl host reconcile | grep -q "subject=pwa detail=.*set the password again"'
  check "a daemon restart removes the stray password; the lost one must be set again" bash -c 'systemctl restart oxpanel-daemon && test "$(getent shadow pwb | cut -d: -f2)" = "!!" && oxpanel-ctl host reconcile | grep -q "subject=pwa" && ! oxpanel-ctl host reconcile | grep -q "subject=pwb"'
  check "set it again: no drift" bash -c 'oxpanel-ctl sftp set-password pwa < "$PWDIR/pw" >/dev/null && oxpanel-ctl host reconcile | grep -qx "drifts=0"'

  # The host-wide switch.
  systemctl set-environment OXPANEL_SFTP_PASSWORDS=false; systemctl restart oxpanel-daemon
  check "with OXPANEL_SFTP_PASSWORDS=false host info says so" grep -q ' sftp_passwords=false ' <(oxpanel-ctl host info)
  check_not "and set-password is refused" bash -c 'oxpanel-ctl sftp set-password pwb < "$PWDIR/pw"'
  check "sshd offers no tenant password login" bash -c '/usr/sbin/sshd -T -C user=pwa,host=x,addr=127.0.0.1 | grep -qx "passwordauthentication no"'
  check "a recorded password is refused by sshd" pw_denied pwa "$PWDIR/pw"
  check "and reported" bash -c 'oxpanel-ctl host reconcile | grep -q "subject=pwa detail=.*forbids"'
  systemctl unset-environment OXPANEL_SFTP_PASSWORDS; systemctl restart oxpanel-daemon
  check "allowed again: the password works" pw_ok pwa "$PWDIR/pw"
  check "delete pwa (with a password)" grep -q '^deleted=true' <(oxpanel-ctl tenant delete pwa --remove-home)
  check "no shadow entry, chroot or mount left" bash -c '! getent shadow pwa && test ! -e /var/lib/oxpanel/sftp/pwa && ! findmnt -n /var/lib/oxpanel/sftp/pwa/home/pwa'
  check "delete pwb" grep -q '^deleted=true' <(oxpanel-ctl tenant delete pwb --remove-home)
  check "no drift after the password tests" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)
  rm -rf "$PWDIR"
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
  # Only the inode limit now (a shell redirection error would end `sh` itself, hence touch).
  check "too many files fail too" bash -c 'oxpanel-ctl tenant set-limits quotaa --inodes 200 >/dev/null && setpriv --reuid=quotaa --regid=quotaa --clear-groups -- sh -c "rm -f /home/quotaa/big; i=0; while [ \$i -lt 400 ]; do i=\$((i+1)); touch /home/quotaa/f\$i 2>/dev/null || { echo refused at file \$i; exit 0; }; done; exit 1"'
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

echo "== databases (MariaDB)"
if [ -x /usr/bin/mariadb ] && systemctl cat mariadb.service >/dev/null 2>&1 && rpm -q php-mysqlnd >/dev/null 2>&1; then
  if ! systemctl -q is-active mariadb; then
    # What docs/HANDBOOK.md §3.5 tells the operator to do (the acceptance VM ran it in phase 10).
    systemctl enable --now mariadb
    mariadb --no-defaults --user=root <<'SQL'
DELETE FROM mysql.global_priv WHERE User='';
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;
SQL
    printf '[mysqld]\nskip-networking\n' > /etc/my.cnf.d/oxpanel-local.cnf
    systemctl restart mariadb
  fi
  rootsql() { mariadb --no-defaults --user=root --batch --raw --skip-column-names -e "$1"; }
  # $1 user, $2 password, $3 SQL: as the tenant's database user, over the socket.
  usersql() { MYSQL_PWD="$2" mariadb --no-defaults --protocol=socket --user="$1" --batch --skip-column-names -e "$3"; }
  export -f rootsql usersql
  check "host info reports MariaDB" grep -qE '^database_engine=mariadb available=true version=10\.' <(oxpanel-ctl host info)
  check "MariaDB does not listen on the network" bash -c '! ss -ltnp 2>/dev/null | grep -q mariadbd'
  oxpanel-ctl tenant create carol >/dev/null
  oxpanel-ctl tenant create dave >/dev/null
  DBPW='Carol-DB-pass-4711'
  DAVEPW="it's \"quoted\" \\ ; -- DROP"

  # Watch argv of every process and MariaDB's process list while passwords travel.
  : > /root/db-ps.log
  ( while :; do ps -eo args >> /root/db-ps.log; rootsql 'SELECT IFNULL(INFO, "") FROM information_schema.PROCESSLIST' >> /root/db-ps.log 2>/dev/null; sleep 0.05; done ) &
  watcher=$!
  out="$(oxpanel-ctl db create carol_wp --tenant carol)"
  check "database created" bash -c 'grep -q "^created=true" <<<"$1" && grep -q "database=carol_wp tenant=carol engine=mariadb" <<<"$1"' _ "$out"
  check "replay is idempotent" grep -q '^created=false' <(oxpanel-ctl db create carol_wp --tenant carol)
  check "the database exists on the server" grep -qx carol_wp <(rootsql 'SHOW DATABASES')
  out="$(printf '%s\n' "$DBPW" | oxpanel-ctl db user-create carol_app --tenant carol)"
  check "database user created (password on stdin)" grep -q '^created=true' <<<"$out"
  check "the account is local only, with a connection limit" test "$(rootsql "SELECT Host, max_user_connections FROM mysql.user WHERE User='carol_app'")" = "localhost	25"
  check "the account holds no global privilege" test "$(rootsql "SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE = \"'carol_app'@'localhost'\" AND PRIVILEGE_TYPE <> 'USAGE'")" = 0
  check "grant on the tenant's own database" grep -q '^changed=true' <(oxpanel-ctl db grant carol_app carol_wp)
  check "the grant pattern escapes _ (no wildcard)" grep -qF 'ON `carol\_wp`.*' <(rootsql "SHOW GRANTS FOR 'carol_app'@'localhost'")
  check "no GRANT OPTION, FILE, SUPER or PROCESS" bash -c '! rootsql "SHOW GRANTS FOR '"'"'carol_app'"'"'@'"'"'localhost'"'"'" | grep -qE "GRANT OPTION|FILE|SUPER|PROCESS|ALL PRIVILEGES"'
  oxpanel-ctl db create dave_wp --tenant dave >/dev/null
  printf '%s\n' "$DAVEPW" | oxpanel-ctl db user-create dave_app --tenant dave >/dev/null
  oxpanel-ctl db grant dave_app dave_wp >/dev/null
  check "a password full of SQL metacharacters works" test "$(usersql dave_app "$DAVEPW" 'SELECT CURRENT_USER()')" = "dave_app@localhost"
  printf '%s\n' "$DBPW-changed" | oxpanel-ctl db user-passwd carol_app >/dev/null
  check "password change takes effect" test "$(usersql carol_app "$DBPW-changed" 'SELECT 1')" = 1
  check_not "the old password no longer works" usersql carol_app "$DBPW" 'SELECT 1'
  printf '%s\n' "$DBPW" | oxpanel-ctl db user-passwd carol_app >/dev/null
  # The requests above can finish within a few watcher rounds; let it complete
  # some more (at most 10 s) so the sanity check below measures the watcher,
  # not how fast the daemon was.
  for _ in $(seq 1 100); do [ "$(grep -c '^COMMAND$' /root/db-ps.log)" -ge 6 ] && break; sleep 0.1; done
  kill "$watcher"; wait "$watcher" 2>/dev/null || true
  echo "info - the watcher captured $(wc -l < /root/db-ps.log) lines, $(grep -c '^COMMAND$' /root/db-ps.log) process listings"
  check "watcher saw processes and MariaDB statements" test "$(wc -l < /root/db-ps.log)" -gt 100
  check "no password in any process argv or the MariaDB process list" bash -c '! grep -qF -e "$1" -e "Carol-DB-pass" -e "quoted" /root/db-ps.log' _ "$DAVEPW"
  check "no password and no password hash in the daemon journal" bash -c '! journalctl -u oxpanel-daemon --no-pager | grep -qE "Carol-DB-pass|quoted|\*[0-9A-F]{40}"'

  check "user sees only its own database" test "$(usersql carol_app "$DBPW" 'SHOW DATABASES' | grep -v information_schema)" = carol_wp
  check_not "user cannot read mysql.*" usersql carol_app "$DBPW" 'SELECT User FROM mysql.user'
  check_not "user cannot reach another tenant's database" usersql carol_app "$DBPW" 'CREATE TABLE dave_wp.x (i INT)'
  check_not "user cannot create a database next to its own" usersql carol_app "$DBPW" 'CREATE DATABASE carolXwp'
  check "user cannot read files" test "$(usersql carol_app "$DBPW" "SELECT LOAD_FILE('/etc/passwd') IS NULL")" = 1
  check_not "user cannot hand out access" usersql carol_app "$DBPW" "GRANT SELECT ON carol_wp.* TO 'dave_app'@'localhost'"
  check_not "grant across tenants is refused" oxpanel-ctl db grant carol_app dave_wp
  for bad in 'carol_wp`; DROP DATABASE mysql; --' "carol_wp'; DROP USER 'root'@'localhost'; --" 'carol_w%' 'carol\_wp' 'mysql' 'dave_x' 'carol_' 'carol_WP'; do
    check_not "hostile name refused: $bad" oxpanel-ctl db create "$bad" --tenant carol
    check_not "hostile user name refused: $bad" bash -c 'printf "%s\n" "$2" | oxpanel-ctl db user-create "$1" --tenant carol' _ "$bad" "$DBPW"
    check_not "hostile grant refused: $bad" oxpanel-ctl db grant carol_app "$bad"
  done
  check "the server's own schemas are intact" test "$(rootsql "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME IN ('mysql','information_schema','performance_schema')")" = 3
  check "no unrecorded object was created" test "$(rootsql "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE 'carol%'")" = 1
  check_not "short passwords are refused by the engine" bash -c 'printf "short\n" | oxpanel-ctl db user-create carol_two --tenant carol'
  rootsql "CREATE DATABASE carol_legacy"
  check_not "a database OxPanel did not create is never adopted" oxpanel-ctl db create carol_legacy --tenant carol
  check "nor dropped" bash -c 'oxpanel-ctl db delete carol_legacy | grep -q "^deleted=false" && rootsql "SHOW DATABASES" | grep -qx carol_legacy'
  check "an unrecorded object with a tenant prefix is drift" bash -c 'oxpanel-ctl host reconcile | grep -q "kind=DRIFT_KIND_ORPHAN_DATABASE_OBJECT subject=carol_legacy"'
  rootsql "DROP DATABASE carol_legacy"
  check "databases are not drift" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)

  echo "-- a PHP site using its database"
  oxpanel-ctl vhost set db.test --tenant carol --php >/dev/null
  as_user carol sh -c 'cat > /home/carol/public_html/index.php' <<PHP
<?php
mysqli_report(MYSQLI_REPORT_OFF);
\$db = @new mysqli('localhost', 'carol_app', '$DBPW', 'carol_wp', 0, '/var/lib/mysql/mysql.sock');
if (\$db->connect_errno) { echo 'connect-failed ', \$db->connect_errno, ' ', \$db->connect_error; exit; }
\$db->query('CREATE TABLE IF NOT EXISTS notes (id INT AUTO_INCREMENT PRIMARY KEY, body VARCHAR(64))');
\$db->query("INSERT INTO notes (body) VALUES ('hello')");
\$r = \$db->query("SELECT body FROM notes WHERE body = 'hello' LIMIT 1");
\$read = (\$r && \$r->fetch_row()[0] === 'hello') ? 'ok' : 'failed';
\$other = @\$db->select_db('dave_wp') ? 'OPEN' : 'denied';
\$sys = @\$db->query('SELECT User FROM mysql.user') ? 'OPEN' : 'denied';
echo "write+read=\$read other=\$other mysql=\$sys";
PHP
  check "PHP writes and reads its own database, and nothing else" body_eventually db.test / "write+read=ok other=denied mysql=denied"
  check "rows written by PHP are in the tenant's database" test "$(rootsql 'SELECT COUNT(*) > 0 FROM carol_wp.notes')" = 1
  check "database size is reported" bash -c 'oxpanel-ctl db list --tenant carol | grep -qE "^database=carol_wp tenant=carol engine=mariadb size=[1-9][0-9]* "'

  echo "-- an application connecting to the database socket"
  oxpanel-ctl vhost set dbapp.test --tenant carol --app python --app-root apps/dbapp --app-entry main.py >/dev/null
  as_user carol sh -c 'cat > /home/carol/apps/dbapp/main.py' <<'PY'
import os, socket
from http.server import BaseHTTPRequestHandler
from socketserver import UnixStreamServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect('/var/lib/mysql/mysql.sock')
            greeting = 'ok' if b'MariaDB' in s.recv(256) else 'unexpected'
            s.close()
        except OSError as e:
            greeting = 'failed:' + type(e).__name__
        body = f"db-greeting={greeting}".encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

UnixStreamServer(os.environ['PORT'], Handler).serve_forever()
PY
  oxpanel-ctl vhost restart-app dbapp.test >/dev/null
  check "an application (its own SELinux domain) reaches the MariaDB socket" body_eventually dbapp.test / "db-greeting=ok"
  oxpanel-ctl vhost remove dbapp.test >/dev/null

  echo "-- suspension, reconcile, lifecycle"
  usersql carol_app "$DBPW" 'SELECT SLEEP(30)' >/dev/null 2>&1 &
  sleeper=$!
  sleep 0.5
  oxpanel-ctl tenant suspend carol >/dev/null
  check_not "suspension locks the tenant's database accounts" usersql carol_app "$DBPW" 'SELECT 1'
  check "the server says why" grep -q 'locked' <(usersql carol_app "$DBPW" 'SELECT 1' 2>&1 || true)
  check "suspension ends open sessions" bash -c 'for i in $(seq 1 50); do kill -0 "$1" 2>/dev/null || exit 0; sleep 0.1; done; exit 1' _ "$sleeper"
  check "other tenants' accounts stay unlocked" test "$(usersql dave_app "$DAVEPW" 'SELECT 1')" = 1
  check "a suspended tenant is not drift" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)
  oxpanel-ctl tenant resume carol >/dev/null
  check "resume unlocks them" test "$(usersql carol_app "$DBPW" 'SELECT 1')" = 1
  rootsql "GRANT FILE ON *.* TO 'carol_app'@'localhost'; GRANT SELECT ON \`dave\\_wp\`.* TO 'carol_app'@'localhost'"
  out="$(oxpanel-ctl host reconcile || true)"
  check "reconcile reports privileges added by hand" bash -c 'grep -q "kind=DRIFT_KIND_DATABASE_PRIVILEGE_DRIFT subject=carol_app .*global privileges: FILE" <<<"$1" && grep -q "SELECT on .dave" <<<"$1"' _ "$out"
  check "reconcile exits 3 on drift" bash -c 'oxpanel-ctl host reconcile >/dev/null; test $? -eq 3'
  rootsql "REVOKE FILE ON *.* FROM 'carol_app'@'localhost'; REVOKE SELECT ON \`dave\\_wp\`.* FROM 'carol_app'@'localhost'"
  rootsql "DROP USER 'dave_app'@'localhost'"
  check "a missing account is drift" grep -q 'kind=DRIFT_KIND_DATABASE_USER_MISSING subject=dave_app' <(oxpanel-ctl host reconcile || true)
  printf '%s\n' "$DAVEPW" | oxpanel-ctl db user-passwd dave_app >/dev/null
  check "setting the password re-creates it with its grants" test "$(usersql dave_app "$DAVEPW" 'SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = "dave_wp"')" = 1
  check "no drift after healing" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)
  check_not "a tenant with databases cannot be deleted" oxpanel-ctl tenant delete dave
  check "deleting a database revokes it and drops it" bash -c 'oxpanel-ctl db delete dave_wp | grep -q "^deleted=true" && ! rootsql "SHOW DATABASES" | grep -qx dave_wp && oxpanel-ctl db user-list --tenant dave | grep -q "databases=- "'
  check "deleting a user drops the account" bash -c 'oxpanel-ctl db user-delete dave_app | grep -q "^deleted=true" && test "$(rootsql "SELECT COUNT(*) FROM mysql.user WHERE User=\"dave_app\"")" = 0'
  oxpanel-ctl vhost remove db.test >/dev/null
  oxpanel-ctl db user-delete carol_app >/dev/null
  oxpanel-ctl db delete carol_wp >/dev/null
  check "tenants without databases can be deleted" bash -c 'oxpanel-ctl tenant delete carol --remove-home | grep -q "^deleted=true" && oxpanel-ctl tenant delete dave --remove-home | grep -q "^deleted=true"'
  check "nothing of the tenants is left on the server" test "$(rootsql "SELECT (SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE 'carol%' OR SCHEMA_NAME LIKE 'dave%') + (SELECT COUNT(*) FROM mysql.user WHERE User LIKE 'carol%' OR User LIKE 'dave%')")" = 0
  check "no drift after database teardown" grep -q '^drifts=0$' <(oxpanel-ctl host reconcile)
else
  echo "skip - MariaDB or php-mysqlnd not installed"
fi

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

echo "== dry-run mode: the whole daemon against a fake OS, as an unprivileged user"
DRY=/tmp/oxpanel-dry; rm -rf "$DRY"; install -d -o panelapi -g panelapi -m 0700 "$DRY"
dry() { setpriv --reuid=panelapi --regid=panelapi --clear-groups --no-new-privs -- env \
  OXPANEL_STATE_DIR="$DRY/state" OXPANEL_HOME_BASE="$DRY/home" OXPANEL_SYSTEMD_UNIT_DIR="$DRY/systemd" \
  OXPANEL_NGINX_CONF_DIR="$DRY/nginx/oxpanel.d" OXPANEL_NGINX_INCLUDE_FILE="$DRY/nginx/00-oxpanel.conf" \
  OXPANEL_NGINX_LOG_DIR="$DRY/log" OXPANEL_PHP_CONF_DIR="$DRY/php" OXPANEL_SOCKET_PATH="$DRY/sock" \
  OXPANEL_TLS_DIR="$DRY/pki" OXPANEL_ACME_DIR="$DRY/acme" \
  OXPANEL_SSHD_DROPIN_FILE="$DRY/sshd_config.d/60-oxpanel.conf" OXPANEL_SFTP_KEYS_DIR="$DRY/sftp-keys" \
  OXPANEL_BACKUP_DIR="$DRY/backups" \
  OXPANEL_SOCKET_GROUP= OXPANEL_ALLOWED_UIDS="$(id -u panelapi)" "$@"; }
real_dropin="$(sha256sum /etc/ssh/sshd_config.d/60-oxpanel.conf 2>/dev/null || true)"
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
check "the real sshd drop-in was not touched" test "$(sha256sum /etc/ssh/sshd_config.d/60-oxpanel.conf 2>/dev/null || true)" = "$real_dropin"
rm -rf "$DRY"

echo "== preflight refusals"
check "--check-config passes on this host" /usr/sbin/oxpanel-daemon --check-config
check "a non-root user cannot start the daemon" bash -c '! setpriv --reuid=panelapi --regid=panelapi --clear-groups -- /usr/sbin/oxpanel-daemon --check-config >/dev/null 2>&1'
check "a missing web-server account is refused" bash -c '! OXPANEL_WEB_USER=nosuchweb1 /usr/sbin/oxpanel-daemon --check-config >/dev/null 2>&1'
check "root as the web-server account is refused" bash -c '! OXPANEL_WEB_USER=root /usr/sbin/oxpanel-daemon --check-config >/dev/null 2>&1'
check "a tenant as the web-server account is refused" bash -c '! OXPANEL_WEB_USER=bob /usr/sbin/oxpanel-daemon --check-config >/dev/null 2>&1'
check "a missing socket group is refused" bash -c '! OXPANEL_SOCKET_GROUP=nosuchgrp1 /usr/sbin/oxpanel-daemon --check-config >/dev/null 2>&1'

echo "== DNS hosting"
if [ -x /usr/sbin/named ] && [ -x /usr/bin/dig ] && [ -f /usr/share/publicsuffix/public_suffix_list.dat ]; then
  DT=/root/dns-test; rm -rf "$DT"; mkdir -p "$DT"
  P=127.0.0.1
  dq() { dig +norec +time=2 +tries=2 @"$P" "$@"; }
  ds() { dig +short +norec +time=2 +tries=2 @"$P" "$@"; }
  sec() { dig +short +norec +time=2 +tries=2 @"$P" -p 853 "$@"; }
  soa_serial() { dig +short +norec +time=2 +tries=1 @"$P" ${2:+-p "$2"} "$1" SOA | awk '{print $3}'; }
  zone_file() { cat "/var/lib/oxpanel-dns/zones/$1.zone"; }
  eventually() { local n="$1"; shift; for _ in $(seq 1 "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done; "$@"; }
  check "DNS hosting is off by default" grep -q '^dns=false ' <(oxpanel-ctl host info)
  check_not "a zone is refused while DNS hosting is off" oxpanel-ctl dns zone-create dnsa.oxtest --tenant alice
  check "--check-config refuses DNS hosting without its settings" bash -c 'OXPANEL_DNS=true /usr/sbin/oxpanel-daemon --check-config 2>&1 | grep -q OXPANEL_DNS_NAMESERVERS'
  cp -p /etc/oxpanel/daemon.env "$DT/daemon.env.bak"
  printf '%s\n' OXPANEL_DNS=true OXPANEL_DNS_NAMESERVERS=ns1.oxtest.example,ns2.oxtest.example \
    OXPANEL_DNS_SOA_CONTACT=hostmaster@oxtest.example OXPANEL_DNS_IPV4=192.0.2.80 OXPANEL_DNS_IPV6=2001:db8::80 \
    OXPANEL_DNS_SECONDARIES=127.0.0.1:853 OXPANEL_DNS_CHECK_RESOLVER=127.0.0.1:853 >> /etc/oxpanel/daemon.env
  systemctl restart oxpanel-daemon
  check "the DNS server was set up and started by the daemon" eventually 40 systemctl -q is-active oxpanel-dns
  check "host info: DNS hosting available, server running" grep -q '^dns=true dns_available=true dns_server_running=true ' <(oxpanel-ctl host info)
  check "host info: the name servers and addresses" grep -q 'nameservers=ns1.oxtest.example,ns2.oxtest.example secondaries=127.0.0.1:853 ipv4=192.0.2.80 ipv6=2001:db8::80' <(oxpanel-ctl host info)
  check "host info: no warnings (a secondary is configured)" bash -c '! oxpanel-ctl host info | grep -q ^dns_warning='
  check "configuration owned root:named 0640" test "$(stat -c '%U:%G %a' /etc/named/oxpanel/named.conf /etc/named/oxpanel/transfer.key /etc/named/oxpanel/rndc.key | sort -u)" = "root:named 640"
  check "the distribution's named.conf is untouched" bash -c '! rpm -V bind | grep -q " /etc/named.conf$"'
  check "the stock named.service is not running" bash -c '! systemctl -q is-active named'
  check "named runs as named" test "$(ps -o user= -C named | sort -u)" = "named"
  check "version is hidden" bash -c '! dig +short @127.0.0.1 version.bind CH TXT | grep -qi bind'
  check "recursion is refused (not an open resolver)" grep -q 'status: REFUSED' <(dq +rec example.org A)
  check "no recursion offered" bash -c '! dig +rec @127.0.0.1 example.org A | grep -q "flags:.* ra"'

  # A plain secondary (a second BIND instance, as an operator would set one
  # up elsewhere): the transfer key, the primary, and the catalog. Port 853
  # is labelled dns_port_t by the stock policy.
  install -d -o named -g named -m 0770 /var/named/slaves/oxtest
  cat > /etc/named/oxtest-secondary.conf <<'CONF'
include "/etc/named/oxpanel/transfer.key";
options {
    directory "/var/named/slaves/oxtest";
    pid-file none;
    session-keyfile none;
    listen-on port 853 { 127.0.0.1; };
    listen-on-v6 { none; };
    recursion no;
    dnssec-validation no;
    catalog-zones {
        zone "catalog.oxpanel.invalid" default-masters { 127.0.0.1 key "oxpanel-transfer"; } zone-directory "/var/named/slaves/oxtest";
    };
};
controls { };
server 127.0.0.1 { keys { "oxpanel-transfer"; }; };
zone "catalog.oxpanel.invalid" { type slave; file "/var/named/slaves/oxtest/catalog.db"; masters { 127.0.0.1 key "oxpanel-transfer"; }; };
// Not served by OxPanel: a parent for the DNSSEC test, and a domain delegated elsewhere.
zone "parent.oxtest" { type master; file "/var/named/slaves/oxtest/parent.oxtest.db"; };
zone "elsewhere.oxtest" { type master; file "/var/named/slaves/oxtest/elsewhere.oxtest.db"; };
CONF
  printf 'parent.oxtest. 60 IN SOA ns.parent.oxtest. h.parent.oxtest. 1 60 60 600 60\nparent.oxtest. 60 IN NS ns.parent.oxtest.\nns.parent.oxtest. 60 IN A 192.0.2.53\n' > /var/named/slaves/oxtest/parent.oxtest.db
  printf 'elsewhere.oxtest. 60 IN SOA ns1.other.example. h.other.example. 1 60 60 600 60\nelsewhere.oxtest. 60 IN NS ns1.other.example.\nelsewhere.oxtest. 60 IN NS ns2.other.example.\n' > /var/named/slaves/oxtest/elsewhere.oxtest.db
  chown named:named /var/named/slaves/oxtest/*.db
  [ "$(getenforce 2>/dev/null)" = Enforcing ] && restorecon -R /etc/named/oxtest-secondary.conf /var/named/slaves/oxtest
  check "the test secondary's configuration is valid" named-checkconf /etc/named/oxtest-secondary.conf
  check "start the test secondary" systemd-run --unit=oxtest-dns-secondary --quiet /usr/sbin/named -f -u named -c /etc/named/oxtest-secondary.conf
  check "the test secondary answers" eventually 20 bash -c "dig +short @127.0.0.1 -p 853 parent.oxtest SOA | grep -q ns.parent.oxtest"

  echo "-- zones follow sites"
  for t in dnsa dnsb; do oxpanel-ctl tenant create "$t" --memory 128M >/dev/null; done
  check "site dnsa.oxtest with aliases" grep -q '^changed=true' <(oxpanel-ctl vhost set dnsa.oxtest --tenant dnsa --alias www.dnsa.oxtest --no-auto-https)
  check "the site reports its zone" grep -q ' dns_zone=dnsa.oxtest$' <(oxpanel-ctl vhost list --tenant dnsa)
  check "a zone was created for the site" grep -q '^zone=dnsa.oxtest tenant=dnsa automatic=true ' <(oxpanel-ctl dns zone-list)
  check "SOA from the configured name server and contact" grep -q '^ns1.oxtest.example. hostmaster.oxtest.example. [0-9]* 7200 3600 1209600 3600$' <(ds dnsa.oxtest SOA)
  check "NS records of the configured name servers" test "$(ds dnsa.oxtest NS | sort | tr '\n' ' ')" = "ns1.oxtest.example. ns2.oxtest.example. "
  check "A of the apex" test "$(ds dnsa.oxtest A)" = 192.0.2.80
  check "AAAA of the apex" test "$(ds dnsa.oxtest AAAA)" = 2001:db8::80
  check "A of the www alias" test "$(ds www.dnsa.oxtest A)" = 192.0.2.80
  check "answers are authoritative" grep -q 'flags: qr aa' <(dq dnsa.oxtest A)
  check "a name nobody created is NXDOMAIN" grep -q 'status: NXDOMAIN' <(dq nope.dnsa.oxtest A)
  check "the zone file is root's, 0644" test "$(stat -c '%U %a' /var/lib/oxpanel-dns/zones/dnsa.oxtest.zone)" = "root 644"
  check "the secondary got the zone through the catalog" eventually 40 bash -c "test \"\$(dig +short @127.0.0.1 -p 853 dnsa.oxtest A)\" = 192.0.2.80"
  check "and serves the primary's serial" eventually 40 bash -c "test \"\$(dig +short @127.0.0.1 -p 853 dnsa.oxtest SOA | awk '{print \$3}')\" = \"\$(dig +short @127.0.0.1 dnsa.oxtest SOA | awk '{print \$3}')\""
  s1="$(soa_serial dnsa.oxtest)"
  check "an alias added later gets its records" grep -q '^changed=true' <(oxpanel-ctl vhost set dnsa.oxtest --tenant dnsa --alias www.dnsa.oxtest --alias shop.dnsa.oxtest --no-auto-https)
  check "shop.dnsa.oxtest resolves" eventually 10 bash -c "test \"\$(dig +short @127.0.0.1 shop.dnsa.oxtest A)\" = 192.0.2.80"
  check "the serial increased" test "$(soa_serial dnsa.oxtest)" -gt "$s1"
  check "the secondary follows the change (NOTIFY + transfer)" eventually 40 bash -c "test \"\$(dig +short @127.0.0.1 -p 853 shop.dnsa.oxtest A)\" = 192.0.2.80"
  check "an alias removed loses its records" grep -q '^changed=true' <(oxpanel-ctl vhost set dnsa.oxtest --tenant dnsa --alias www.dnsa.oxtest --no-auto-https)
  check "shop.dnsa.oxtest is gone" eventually 10 bash -c "dig +norec @127.0.0.1 shop.dnsa.oxtest A | grep -q 'status: NXDOMAIN'"
  check "an opted-out site gets no zone" bash -c "oxpanel-ctl vhost set optout.oxtest --tenant dnsb --no-dns --no-auto-https | grep -q ' dns_zone=opted-out$' && ! oxpanel-ctl dns zone-list | grep -q '^zone=optout.oxtest '"
  check "the zone apex comes from the public suffix list" bash -c "oxpanel-ctl vhost set shop.dnsb.co.uk --tenant dnsb --no-auto-https | grep -q ' dns_zone=dnsb.co.uk$'"
  check "a site of tenant B inside tenant A's zone gets no records" bash -c "oxpanel-ctl vhost set blog.dnsa.oxtest --tenant dnsb --no-auto-https | grep -q ' dns_zone=-$' && dig +norec @127.0.0.1 blog.dnsa.oxtest A | grep -q 'status: NXDOMAIN'"

  echo "-- records"
  add() { oxpanel-ctl dns record-add dnsa.oxtest --tenant dnsa "$@"; }
  check "MX at the apex (external mail provider)" grep -q '^changed=true' <(add --name @ --type mx --priority 10 --value mx1.mail.example.net)
  check "second MX" grep -q '^changed=true' <(add --name @ --type mx --priority 20 --value mx2.mail.example.net.)
  check "MX on a subdomain" grep -q '^changed=true' <(add --name lists --type mx --priority 5 --value mx.lists.example.net)
  check "dig: MX with priorities" test "$(ds dnsa.oxtest MX | sort | tr '\n' ' ')" = "10 mx1.mail.example.net. 20 mx2.mail.example.net. "
  check "dig: subdomain MX" test "$(ds lists.dnsa.oxtest MX)" = "5 mx.lists.example.net."
  SPF="v=spf1 include:_spf.mail.example.net include:spf.protection.example.org$(for i in $(seq 1 16); do printf ' ip4:198.51.100.%s' "$i"; done) ip6:2001:db8::/32 -all"
  check "SPF longer than 255 characters" test "${#SPF}" -gt 255
  check "SPF as TXT" grep -q '^changed=true' <(add --name @ --type txt --value "$SPF")
  check "dig: SPF arrives whole (split into 255-byte strings)" test "$(dig +short @127.0.0.1 dnsa.oxtest TXT | grep spf1 | sed 's/" "//g; s/^"//; s/"$//')" = "$SPF"
  check "dig: SPF is two character-strings" test "$(dig +short @127.0.0.1 dnsa.oxtest TXT | grep spf1 | grep -o '" "' | wc -l)" = 1
  openssl genrsa 2048 2>/dev/null | openssl rsa -pubout 2>/dev/null | grep -v '^-----' | tr -d '\n' > "$DT/dkim.b64"
  printf 'v=DKIM1; k=rsa; p=%s' "$(cat "$DT/dkim.b64")" > "$DT/dkim.txt"
  check "DKIM (2048-bit key) as TXT on selector._domainkey" grep -q '^changed=true' <(add --name s1._domainkey --type txt --value-file "$DT/dkim.txt")
  check "dig: the DKIM key arrives whole" test "$(dig +short @127.0.0.1 s1._domainkey.dnsa.oxtest TXT | sed 's/" "//g; s/^"//; s/"$//')" = "$(cat "$DT/dkim.txt")"
  check "DKIM as CNAME (provider-hosted key)" grep -q '^changed=true' <(add --name s2._domainkey --type cname --value s2.domainkey.u123.mail.example.net)
  check "dig: DKIM CNAME" test "$(ds s2._domainkey.dnsa.oxtest CNAME)" = "s2.domainkey.u123.mail.example.net."
  check "DMARC on _dmarc" grep -q '^changed=true' <(add --name _dmarc --type txt --value "v=DMARC1; p=quarantine; rua=mailto:dmarc@dnsa.oxtest")
  check "dig: DMARC" test "$(ds _dmarc.dnsa.oxtest TXT)" = '"v=DMARC1; p=quarantine; rua=mailto:dmarc@dnsa.oxtest"'
  check "verification TXT" grep -q '^changed=true' <(add --name @ --type txt --value "provider-verification=4f1c2a")
  check "verification CNAME" grep -q '^changed=true' <(add --name a1b2c3 --type cname --value verify.mail.example.net)
  check "SRV for autodiscover" grep -q '^changed=true' <(add --name _autodiscover._tcp --type srv --priority 0 --weight 1 --port 443 --value autodiscover.mail.example.net)
  check "dig: SRV" test "$(ds _autodiscover._tcp.dnsa.oxtest SRV)" = "0 1 443 autodiscover.mail.example.net."
  check "CNAME" grep -q '^changed=true' <(add --name docs --type cname --value docs.example.net)
  check "dig: CNAME" test "$(ds docs.dnsa.oxtest CNAME)" = "docs.example.net."
  check "CAA" grep -q '^changed=true' <(add --name @ --type caa --caa-tag issue --value letsencrypt.org)
  check "dig: CAA" test "$(ds dnsa.oxtest CAA)" = '0 issue "letsencrypt.org"'
  check "A and AAAA records of the tenant's own" bash -c "oxpanel-ctl dns record-add dnsa.oxtest --tenant dnsa --name api --type a --value 198.51.100.7 | grep -q ^changed=true && oxpanel-ctl dns record-add dnsa.oxtest --tenant dnsa --name api --type aaaa --value 2001:db8::7 | grep -q ^changed=true"
  check "dig: A and AAAA" test "$(ds api.dnsa.oxtest A) $(ds api.dnsa.oxtest AAAA)" = "198.51.100.7 2001:db8::7"
  check "wildcard" grep -q '^changed=true' <(add --name '*.dev' --type a --value 198.51.100.8)
  check "dig: wildcard" test "$(ds anything.dev.dnsa.oxtest A)" = 198.51.100.8
  check "NS delegation of a subdomain, with glue" bash -c "oxpanel-ctl dns record-add dnsa.oxtest --tenant dnsa --name sub --type ns --value ns1.sub.dnsa.oxtest | grep -q ^changed=true && oxpanel-ctl dns record-add dnsa.oxtest --tenant dnsa --name ns1.sub --type a --value 198.51.100.53 | grep -q ^changed=true"
  check "dig: a referral for the delegated name" bash -c "dig +norec @127.0.0.1 x.sub.dnsa.oxtest A | grep -q 'AUTHORITY: 1' && dig +norec @127.0.0.1 x.sub.dnsa.oxtest A | grep -q 'sub.dnsa.oxtest.*NS.*ns1.sub.dnsa.oxtest'"
  check "a repeated record changes nothing" grep -q '^changed=false' <(add --name docs --type cname --value docs.example.net)
  id="$(add --name tmp --type txt --value one | awk -F'[= ]' '/^id=/{print $2}')"
  check "change a record" grep -q '^changed=true' <(oxpanel-ctl dns record-update dnsa.oxtest "$id" --tenant dnsa --name tmp --type txt --value two)
  check "dig: changed" test "$(ds tmp.dnsa.oxtest TXT)" = '"two"'
  check "remove a record" grep -q '^removed=true' <(oxpanel-ctl dns record-remove dnsa.oxtest "$id" --tenant dnsa)
  check "dig: removed" bash -c "dig +norec @127.0.0.1 tmp.dnsa.oxtest TXT | grep -q 'status: NXDOMAIN'"
  check "the engine's records are listed as protected" bash -c "oxpanel-ctl dns zone-show dnsa.oxtest --tenant dnsa | grep -q '^id=0 name=www type=A .* protected=true origin=site:dnsa.oxtest '"
  check "TXT text with zone-file syntax stays literal text" grep -q '^changed=true' <(add --name lit --type txt --value '$INCLUDE /etc/shadow ; ( ) "q" \e')
  check "dig: literal" test "$(ds lit.dnsa.oxtest TXT)" = '"$INCLUDE /etc/shadow ; ( ) \"q\" \\e"'

  echo "-- refusals: protection, rules, injection"
  before="$(sha256sum /var/lib/oxpanel-dns/zones/dnsa.oxtest.zone)"
  check_not "A at a site's name (protected)" add --name www --type a --value 198.51.100.9
  check_not "CNAME at a site's name (protected)" add --name www --type cname --value x.example.net
  check_not "CNAME at the apex" add --name @ --type cname --value x.example.net
  check_not "NS at the apex (protected)" add --name @ --type ns --value ns.evil.example
  check_not "a second record beside a CNAME" add --name docs --type txt --value x
  check_not "MX pointing at a CNAME" add --name @ --type mx --priority 30 --value docs.dnsa.oxtest
  check_not "a record under a delegation" add --name x.sub --type txt --value x
  check_not "a fully-qualified name where a relative one is meant" add --name www.dnsa.oxtest --type txt --value x
  for bad in $'a\nb' 'a;b' '$INCLUDE' '$GENERATE' '(' ')' 'a"b' 'a\b' 'a b' "$(printf 'a%.0s' $(seq 1 64))" '..' '-x' 'x.*' '@.x'; do
    check_not "record name '$(printf %q "$bad")' is refused" add --name "$bad" --type txt --value x
  done
  for bad in $'1.2.3.4\nevil. 1 IN A 6.6.6.6' '1.2.3.4 ; x' '1.2.3' '0.0.0.0' '01.2.3.4'; do
    check_not "A value '$(printf %q "$bad")' is refused" add --name inj --type a --value "$bad"
  done
  for bad in $'x.example.net\nevil' 'x.example.net;' 'x example.net' '(x.example.net)' '"x.example.net"' '$INCLUDE' 'localhost' '192.0.2.1'; do
    check_not "CNAME target '$(printf %q "$bad")' is refused" add --name inj --type cname --value "$bad"
  done
  check_not "TXT with a line break is refused" add --name inj --type txt --value $'a\nevil. 1 IN A 6.6.6.6'
  check_not "TXT with a tab is refused" add --name inj --type txt --value $'a\tb'
  check_not "TXT over 4000 characters is refused" add --name inj --type txt --value "$(head -c 4001 /dev/zero | tr '\0' a)"
  check_not "CAA value with a quote is refused" add --name @ --type caa --caa-tag issue --value 'le"; x'
  check_not "a TTL below 60 is refused" add --name inj --type a --value 198.51.100.1 --ttl 59
  check_not "an MX priority beyond 65535 is refused" add --name @ --type mx --priority 70000 --value mx.example.net
  check "nothing reached the zone file" test "$(sha256sum /var/lib/oxpanel-dns/zones/dnsa.oxtest.zone)" = "$before"

  echo "-- tenants"
  check_not "tenant B cannot read tenant A's zone" oxpanel-ctl dns zone-show dnsa.oxtest --tenant dnsb
  check_not "tenant B cannot add a record to it" oxpanel-ctl dns record-add dnsa.oxtest --tenant dnsb --name evil --type a --value 6.6.6.6
  check_not "tenant B cannot reset it" oxpanel-ctl dns zone-reset dnsa.oxtest --tenant dnsb
  check "tenant B's delete of it is a no-op" grep -q '^deleted=false' <(oxpanel-ctl dns zone-delete dnsa.oxtest --tenant dnsb)
  check_not "tenant B cannot create the zone" oxpanel-ctl dns zone-create dnsa.oxtest --tenant dnsb
  check_not "tenant B cannot create a zone inside it" oxpanel-ctl dns zone-create evil.dnsa.oxtest --tenant dnsb
  check_not "nobody can create a zone for a public suffix" oxpanel-ctl dns zone-create co.uk --tenant dnsb
  check "tenant A's zone is intact" test "$(sha256sum /var/lib/oxpanel-dns/zones/dnsa.oxtest.zone)" = "$before"

  echo "-- validation, reloads, serials"
  check "the zone transfer is refused to strangers" bash -c "dig @127.0.0.1 dnsa.oxtest AXFR | grep -qi 'transfer failed'"
  check "the zone transfer works with the TSIG key" bash -c "dig -k /etc/named/oxpanel/transfer.key @127.0.0.1 dnsa.oxtest AXFR | grep -q 'mx1.mail.example.net'"
  check "the catalog is not readable by strangers" bash -c "! dig +short @127.0.0.1 catalog.oxpanel.invalid AXFR | grep -q PTR && dig @127.0.0.1 catalog.oxpanel.invalid SOA | grep -q 'status: REFUSED'"
  # An MX pointing at a host of the zone that has no address: it passes the
  # engine's own rules, the server's checker refuses the zone, nothing is
  # activated.
  served="$(soa_serial dnsa.oxtest)"
  out="$(oxpanel-ctl dns record-add dnsa.oxtest --tenant dnsa --name @ --type mx --priority 40 --value nohost.dnsa.oxtest 2>&1 || true)"
  echo "$out" | head -3
  check "a zone the server's checker rejects is refused with its reason" grep -qi "rejected the zone.*nohost.dnsa.oxtest.*has no address records" <<<"$out"
  check "and never activated (file and served serial unchanged)" bash -c "test \"\$(sha256sum /var/lib/oxpanel-dns/zones/dnsa.oxtest.zone)\" = \"$before\" && test \"\$(dig +short @127.0.0.1 dnsa.oxtest SOA | awk '{print \$3}')\" = $served"
  check "the zone is unchanged in the record too" bash -c "! oxpanel-ctl dns zone-show dnsa.oxtest --tenant dnsa | grep -q 'nohost'"
  check "site dnsb2.oxtest with a zone of its own" grep -q '^changed=true' <(oxpanel-ctl vhost set dnsb2.oxtest --tenant dnsb --no-auto-https)
  sleep 1.2; since="$(date '+%Y-%m-%d %H:%M:%S')"; sleep 1.2
  check "a change" grep -q '^changed=true' <(add --name reloaded --type txt --value yes)
  check "reloads exactly the changed zone" eventually 10 bash -c "journalctl -u oxpanel-dns --since '$since' --no-pager | grep -q \"received control channel command 'reload dnsa.oxtest'\""
  check "and no other" bash -c "! journalctl -u oxpanel-dns --since '$since' --no-pager | grep -q 'dnsb2.oxtest/IN: loaded serial'"
  s2="$(soa_serial dnsa.oxtest)"
  systemctl restart oxpanel-daemon
  check "after a daemon restart the zone keeps its serial" test "$(soa_serial dnsa.oxtest)" = "$s2"
  check "and the next change increases it" bash -c "oxpanel-ctl dns record-add dnsa.oxtest --tenant dnsa --name after-restart --type txt --value x | grep -q ^changed=true && test \"\$(dig +short @127.0.0.1 dnsa.oxtest SOA | awk '{print \$3}')\" -gt $s2"
  systemctl restart oxpanel-dns
  check "after a DNS server restart the zone is served again" eventually 20 bash -c "test \"\$(dig +short @127.0.0.1 dnsa.oxtest A)\" = 192.0.2.80"
  check "the delegation check (resolver: the secondary) says delegated" grep -q '^zone=dnsa.oxtest delegation=DELEGATED ' <(oxpanel-ctl dns zone-check dnsa.oxtest --tenant dnsa)
  check "primary and secondary serials are reported" eventually 20 bash -c "oxpanel-ctl dns zone-check dnsa.oxtest --tenant dnsa | grep -q '^server=127.0.0.1:853 serial=[1-9][0-9]* status=ok$'"
  oxpanel-ctl vhost set elsewhere.oxtest --tenant dnsb --no-auto-https >/dev/null
  check "a domain delegated elsewhere is reported with guidance" bash -c "oxpanel-ctl dns zone-check elsewhere.oxtest --tenant dnsb | tee /dev/stderr | grep -q '^zone=elsewhere.oxtest delegation=ELSEWHERE nameservers_seen=ns1.other.example,ns2.other.example' && oxpanel-ctl dns zone-check elsewhere.oxtest --tenant dnsb | grep -q '^guidance=.*set the domain.s name servers to ns1.oxtest.example, ns2.oxtest.example'"
  oxpanel-ctl vhost remove elsewhere.oxtest >/dev/null
  check "no drift" eventually 20 bash -c "oxpanel-ctl host reconcile | grep -q '^drifts=0$'"
  echo '; hand edit' >> /var/lib/oxpanel-dns/zones/dnsa.oxtest.zone
  check "a hand-edited zone file is drift" grep -q '^kind=DRIFT_KIND_DNS_ZONE_DRIFT subject=dnsa.oxtest ' <(oxpanel-ctl host reconcile)
  touch /var/lib/oxpanel-dns/zones/stray.zone
  check "a stray file is an orphan" grep -q '^kind=DRIFT_KIND_ORPHAN_DNS_FILE ' <(oxpanel-ctl host reconcile)
  rm -f /var/lib/oxpanel-dns/zones/stray.zone
  systemctl restart oxpanel-daemon
  check "a restart re-renders the zone file" eventually 20 bash -c "oxpanel-ctl host reconcile | grep -q '^drifts=0$'"

  echo "-- DNSSEC"
  check "an explicit zone below another domain" grep -q '^created=true' <(oxpanel-ctl dns zone-create sig.parent.oxtest --tenant dnsa)
  oxpanel-ctl dns record-add sig.parent.oxtest --tenant dnsa --name www --type a --value 198.51.100.20 >/dev/null
  check "switch DNSSEC on" grep -q '^zone=sig.parent.oxtest .* dnssec=' <(oxpanel-ctl dns dnssec sig.parent.oxtest on --tenant dnsa)
  check "the server generates the key and signs" eventually 40 bash -c "oxpanel-ctl dns zone-show sig.parent.oxtest --tenant dnsa | grep -q ' dnssec=signed '"
  check "dig +dnssec returns RRSIGs" eventually 20 bash -c "dig +dnssec +norec @127.0.0.1 www.sig.parent.oxtest A | grep -q 'RRSIG.*A 13 '"
  check "NSEC3 proves non-existence" eventually 20 bash -c "dig +dnssec +norec @127.0.0.1 nope.sig.parent.oxtest A | grep -q NSEC3"
  ds_engine="$(oxpanel-ctl dns zone-show sig.parent.oxtest --tenant dnsa | sed -n 's/^ds=//p')"
  dig +norec @127.0.0.1 sig.parent.oxtest DNSKEY > "$DT/dnskey.txt"
  check "the DS the engine reports is what the server's tools compute" test "$(dnssec-dsfromkey -2 -f "$DT/dnskey.txt" sig.parent.oxtest | head -1)" = "$ds_engine"
  awk '$4=="DNSKEY" && $5==257 {k=""; for(i=8;i<=NF;i++) k=k $i; printf "trust-anchors { sig.parent.oxtest. static-key 257 3 13 \"%s\"; };\n", k}' "$DT/dnskey.txt" > "$DT/anchor.conf"
  check "a validating resolver check (delv, the zone's own trust anchor) succeeds" bash -c "delv @127.0.0.1 -a $DT/anchor.conf +root=sig.parent.oxtest www.sig.parent.oxtest A | grep -q 'fully validated'"
  check "a record added after signing is signed too" bash -c "oxpanel-ctl dns record-add sig.parent.oxtest --tenant dnsa --name late --type txt --value signed-later | grep -q ^changed=true"
  check "dig: its RRSIG" eventually 20 bash -c "dig +dnssec +norec @127.0.0.1 late.sig.parent.oxtest TXT | grep -q 'RRSIG.*TXT 13 '"
  check "delv validates it" eventually 20 bash -c "delv @127.0.0.1 -a $DT/anchor.conf +root=sig.parent.oxtest late.sig.parent.oxtest TXT | grep -q 'fully validated'"
  check "the secondary serves the signed zone" eventually 40 bash -c "dig +dnssec +norec @127.0.0.1 -p 853 late.sig.parent.oxtest TXT | grep -q 'RRSIG.*TXT 13 '"
  check "the private key belongs to the server's account, mode 0600" test "$(stat -c '%U %a' /var/lib/oxpanel-dns/keys/sig.parent.oxtest/*.private)" = "named 600"
  check_not "a tenant cannot read the signing keys" as_user dnsa cat /var/lib/oxpanel-dns/keys/sig.parent.oxtest/*.private
  check_not "a tenant cannot even list them" as_user dnsa ls /var/lib/oxpanel-dns/keys
  check "no private key in a response" bash -c "! oxpanel-ctl dns zone-show sig.parent.oxtest --tenant dnsa | grep -qi private"
  systemctl restart oxpanel-daemon oxpanel-dns
  check "signing survives daemon and server restarts" eventually 40 bash -c "dig +dnssec +norec @127.0.0.1 www.sig.parent.oxtest A | grep -q 'RRSIG.*A 13 '"
  check "with the same key (same DS)" test "$(oxpanel-ctl dns zone-show sig.parent.oxtest --tenant dnsa | sed -n 's/^ds=//p')" = "$ds_engine"
  # The parent publishes the DS: switching DNSSEC off must be refused.
  dsrr="$(echo "$ds_engine" | sed 's/^sig.parent.oxtest. IN DS /sig.parent.oxtest. 60 IN DS /')"
  printf 'parent.oxtest. 60 IN SOA ns.parent.oxtest. h.parent.oxtest. 2 60 60 600 60\nparent.oxtest. 60 IN NS ns.parent.oxtest.\nns.parent.oxtest. 60 IN A 192.0.2.53\nsig.parent.oxtest. 60 IN NS ns1.oxtest.example.\n%s\n' "$dsrr" > /var/named/slaves/oxtest/parent.oxtest.db
  systemctl kill -s HUP oxtest-dns-secondary
  check "the parent now publishes the DS" eventually 20 bash -c "dig +short @127.0.0.1 -p 853 sig.parent.oxtest DS | grep -q ' 13 2 '"
  check "the check sees the DS at the parent and that it matches" eventually 20 bash -c "oxpanel-ctl dns zone-check sig.parent.oxtest --tenant dnsa | grep -q 'ds_checked=true ds_at_parent=1 ds_matches=true'"
  out="$(oxpanel-ctl dns dnssec sig.parent.oxtest off --tenant dnsa 2>&1 || true)"
  check "switching DNSSEC off is refused while the parent publishes the DS" grep -q 'still publishes a DS record' <<<"$out"
  check_not "even with --force" oxpanel-ctl dns dnssec sig.parent.oxtest off --tenant dnsa --force
  check "the zone is still signed" grep -q ' dnssec=signed ' <(oxpanel-ctl dns zone-show sig.parent.oxtest --tenant dnsa)
  printf 'parent.oxtest. 60 IN SOA ns.parent.oxtest. h.parent.oxtest. 3 60 60 600 60\nparent.oxtest. 60 IN NS ns.parent.oxtest.\nns.parent.oxtest. 60 IN A 192.0.2.53\n' > /var/named/slaves/oxtest/parent.oxtest.db
  systemctl kill -s HUP oxtest-dns-secondary
  check "the DS is withdrawn at the parent" eventually 20 bash -c "dig @127.0.0.1 -p 853 sig.parent.oxtest DS | grep -q 'ANSWER: 0'"
  signed_serial="$(soa_serial sig.parent.oxtest)"
  check "now DNSSEC can be switched off" grep -q ' dnssec=off ' <(oxpanel-ctl dns dnssec sig.parent.oxtest off --tenant dnsa)
  check "no more signatures" eventually 20 bash -c "! dig +dnssec +norec @127.0.0.1 www.sig.parent.oxtest A | grep -q RRSIG"
  check "the unsigned zone has a higher serial than the signed one had" test "$(soa_serial sig.parent.oxtest)" -gt "$signed_serial"
  check "the secondary takes the unsigned zone" eventually 40 bash -c "! dig +dnssec +norec @127.0.0.1 -p 853 www.sig.parent.oxtest A | grep -q RRSIG && test \"\$(dig +short @127.0.0.1 -p 853 www.sig.parent.oxtest A)\" = 198.51.100.20"
  check "the keys are gone" test ! -e /var/lib/oxpanel-dns/keys/sig.parent.oxtest

  echo "-- suspension and deletion"
  check "suspend dnsa" grep -q '^changed=true' <(oxpanel-ctl tenant suspend dnsa)
  check "a suspended tenant's zone keeps answering" test "$(ds dnsa.oxtest A)" = 192.0.2.80
  check "its mail records too" test "$(ds dnsa.oxtest MX | wc -l)" = 2
  site_answers() { [ "$(code_of "$1" /)" = "$2" ]; }
  check "its site answers 503" eventually 20 site_answers dnsa.oxtest 503
  check_not "its zone cannot be changed" add --name frozen --type txt --value x
  check "resume dnsa" grep -q '^changed=true' <(oxpanel-ctl tenant resume dnsa)
  check "changes are possible again" grep -q '^changed=true' <(add --name thawed --type txt --value x)
  check_not "a tenant with zones cannot be deleted" oxpanel-ctl tenant delete dnsb --remove-home
  for d in dnsb2.oxtest shop.dnsb.co.uk optout.oxtest blog.dnsa.oxtest; do oxpanel-ctl vhost remove "$d" >/dev/null; done
  check "the automatic zones of removed sites are gone" bash -c "! oxpanel-ctl dns zone-list --tenant dnsb | grep -q ."
  check "and no longer answered" grep -q 'status: REFUSED' <(dq dnsb2.oxtest SOA)
  check "the secondary drops them too (catalog)" eventually 40 bash -c "dig +norec @127.0.0.1 -p 853 dnsb2.oxtest SOA | grep -q 'status: REFUSED'"
  check "now dnsb can be deleted" grep -q '^deleted=true' <(oxpanel-ctl tenant delete dnsb --remove-home)
  check "removing the last site keeps a zone with the tenant's records" bash -c "oxpanel-ctl vhost remove dnsa.oxtest | grep -q ^removed=true && oxpanel-ctl dns zone-show dnsa.oxtest --tenant dnsa | grep -q '^zone=dnsa.oxtest .* sites=-'"
  check "its MX still answers, its site's A does not" bash -c "test \"\$(dig +short @127.0.0.1 dnsa.oxtest MX | wc -l)\" = 2 && test -z \"\$(dig +short @127.0.0.1 dnsa.oxtest A)\""
  check "reset to defaults removes the tenant's records" bash -c "oxpanel-ctl dns zone-reset dnsa.oxtest --tenant dnsa | grep -q '^zone=dnsa.oxtest .* records=0 '"
  for z in dnsa.oxtest sig.parent.oxtest; do check "delete zone $z" grep -q '^deleted=true' <(oxpanel-ctl dns zone-delete "$z" --tenant dnsa); done
  left="$(ls -A /var/lib/oxpanel-dns/zones /var/lib/oxpanel-dns/keys | grep -v -e '^catalog.oxpanel.invalid.zone' -e '^/' -e '^$' || true)"
  [ -z "$left" ] || echo "left behind: $left"
  check "no zone file or key left" test -z "$left"
  check "dnsa deleted" grep -q '^deleted=true' <(oxpanel-ctl tenant delete dnsa --remove-home)
  check "no drift after DNS hosting" eventually 40 bash -c "oxpanel-ctl host reconcile | grep -q '^drifts=0$'"
  systemctl stop oxtest-dns-secondary 2>/dev/null || true
  rm -rf /var/named/slaves/oxtest /etc/named/oxtest-secondary.conf
  cp -p "$DT/daemon.env.bak" /etc/oxpanel/daemon.env
  systemctl disable --now oxpanel-dns >/dev/null 2>&1
  systemctl restart oxpanel-daemon
  check "DNS hosting off again" grep -q '^dns=false ' <(oxpanel-ctl host info)
else
  echo "skip - BIND, dig or the public suffix list not installed"
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
