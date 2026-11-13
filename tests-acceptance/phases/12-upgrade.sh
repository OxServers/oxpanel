#!/usr/bin/env bash
# Phase 12 — upgrade (INSTALL=upgrade). Phase 10 installed the 0.1.0 engine by hand.
# Here: tenants and sites are created with it (static, PHP, Node.js), then the
# release's install.sh upgrades the host. The tenants must survive with the same
# uid and home, the sites must keep answering, and the new features must work on the
# pre-existing tenant.
cd "$(dirname "$0")/.."; source phases/lib.sh
echo "== phase 12: upgrade from the old engine with install.sh"
T=upg1

OLDV=$(rpm -q --qf '%{VERSION}-%{RELEASE}' oxpanel-daemon)
info "installed before the upgrade: $OLDV ($(oxpanel-daemon --version))"
check "the old engine is running" daemon_active

check "create a tenant with the old engine" oxpanel-ctl tenant create $T --memory 512M --tasks-max 200
check "a static site" oxpanel-ctl vhost set static.upg.test --tenant $T
check "its page" as_user $T sh -c 'echo static-old > /home/upg1/public_html/index.html'
check "a PHP site" oxpanel-ctl vhost set php.upg.test --tenant $T --root phpsite --php
check "its page (PHP)" as_user $T sh -c 'mkdir -p /home/upg1/phpsite && echo "<?php echo \"php-old\";" > /home/upg1/phpsite/index.php'
check "a Node.js site" oxpanel-ctl vhost set app.upg.test --tenant $T --app node
check "its application" as_user $T sh -c 'mkdir -p /home/upg1/apps/app.upg.test && echo "require(\"http\").createServer((q,r)=>r.end(\"node-old\")).listen(process.env.PORT)" > /home/upg1/apps/app.upg.test/app.js'
check "restart the application" oxpanel-ctl vhost restart-app app.upg.test
eventually "static site answers" 20 1 http_body_is static.upg.test / static-old
eventually "PHP site answers" 20 1 http_body_is php.upg.test / php-old
eventually "Node.js site answers" 20 1 http_body_is app.upg.test / node-old

UID_BEFORE=$(oxpanel-ctl tenant get $T | sed -n 's/.* uid=\([0-9]*\).*/\1/p' | head -1)
info "tenant $T uid=$UID_BEFORE"
oxpanel-ctl vhost list --tenant $T > vhosts.before
oxpanel-ctl host reconcile > reconcile.before 2>&1; info "reconcile before: $(head -1 reconcile.before)"
cp -a /var/lib/oxpanel /root/acc/state.before
ls /etc/nginx/oxpanel.d > nginx-files.before

# ---- the upgrade, as the operator would do it
start=$(date +%s)
bash release/install.sh --yes > upgrade.log 2>&1; rc=$?
echo "--- upgrade.log ---"; cat upgrade.log; echo "-------------------"
[ "$rc" = 0 ] || fail "install.sh exited $rc"
ok "install.sh upgraded the host ($(( $(date +%s) - start ))s)"
NEWV=$(rpm -q --qf '%{VERSION}-%{RELEASE}' oxpanel-daemon)
check "the engine package changed ($OLDV -> $NEWV)" test "$OLDV" != "$NEWV"
check "the installer says what it upgraded" bash -c "grep -q 'oxpanel-daemon $OLDV -> $NEWV' upgrade.log"
check "the new engine runs" bash -c 'oxpanel-daemon --version | grep -q "0\.2\."'
eventually "the daemon is active after the upgrade" 30 1 daemon_active
check "the daemon's journal has no errors since the upgrade" bash -c '! journalctl -u oxpanel-daemon --since "-5min" -p err --no-pager | grep -q oxpanel-daemon'

# ---- nothing was lost
check "the tenant is still there with the same uid" bash -c "oxpanel-ctl tenant get $T | grep -q ' uid=$UID_BEFORE '"
check "its home is intact" test -f /home/$T/public_html/index.html
check "its sites are all still configured" bash -c "diff <(oxpanel-ctl vhost list --tenant $T) vhosts.before"
check "the Nginx files are the same set" bash -c 'diff <(ls /etc/nginx/oxpanel.d) nginx-files.before'
eventually "static site still answers" 20 1 http_body_is static.upg.test / static-old
eventually "PHP site still answers" 20 1 http_body_is php.upg.test / php-old
eventually "Node.js site still answers" 20 1 http_body_is app.upg.test / node-old
check "the tenant's limits survived" bash -c "oxpanel-ctl tenant get $T | grep -q 'memory_max=536870912'"
oxpanel-ctl host reconcile > reconcile.after 2>&1; rc=$?
info "reconcile after: exit $rc"; cat reconcile.after | head -20
check "host reconcile is clean after the upgrade (the daemon re-rendered what changed)" test "$rc" = 0

# ---- the new engine's features work on the old tenant
check "the new host info shows the databases" bash -c 'oxpanel-ctl host info | grep -q "^database_engine=mariadb available=true"'
check "an SFTP key can be added to the pre-existing tenant" bash -c "ssh-keygen -q -t ed25519 -N '' -f /root/acc/upg.key && oxpanel-ctl sftp add-key $T --key-file /root/acc/upg.key.pub --label upg | grep -q '^changed=true'"
check "a database for it" oxpanel-ctl db create ${T}_shop --tenant $T
check "a backup of it, waited for" bash -c "oxpanel-ctl backup create $T --wait | grep -q 'state=JOB_STATE_SUCCEEDED'"
check "the old sites are still fine after those" bash -c 'curl -s -H "Host: static.upg.test" http://127.0.0.1/ | grep -qx static-old'
check "a second run of the installer changes nothing" bash -c 'bash release/install.sh --yes 2>&1 | grep -q "^RESULT: ok changes=0 "'

# ---- clean up what this phase made
oxpanel-ctl db delete ${T}_shop >/dev/null 2>&1
for id in $(oxpanel-ctl backup list $T | sed -n 's/^backup=\([^ ]*\).*/\1/p'); do oxpanel-ctl backup delete $T "$id" >/dev/null 2>&1; done
for d in static.upg.test php.upg.test app.upg.test; do oxpanel-ctl vhost remove $d >/dev/null 2>&1; done
check "the tenant is deleted again" oxpanel-ctl tenant delete $T --remove-home
n=$(avc_count); if [ "$n" = 0 ]; then ok "zero AVC denials"; else avc_dump; fail "$n AVC denial(s)"; fi
phase_end
