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
  systemd-sysusers
  systemd-tmpfiles --create oxpanel.conf
  systemctl daemon-reload
  systemctl start nginx
  check "nginx is active" systemctl -q is-active nginx
else
  echo "== install skipped (SKIP_INSTALL=1): using the already installed oxpanel-daemon"
  check "nginx is active" systemctl -q is-active nginx
fi

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
check "other conf.d untouched" test "$(ls /etc/nginx/conf.d | wc -l)" = "1"

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
