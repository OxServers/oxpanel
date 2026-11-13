#!/usr/bin/env bash
# Phase 95 — uninstall (installer mode). A tenant with a site, a database and a
# backup exists; `install.sh --uninstall` must remove the engine and OxPanel's own
# configuration and nothing of the customer's: account, home, database, backup,
# the site that keeps being served. Installing again must find the tenant.
cd "$(dirname "$0")/.."; source phases/lib.sh
echo "== phase 95: uninstall keeps the customers' data"
T=unin1
AVC0=$(avc_count)

check "create a tenant" oxpanel-ctl tenant create $T
check "a site" oxpanel-ctl vhost set keep.unin.test --tenant $T
check "its page" as_user $T sh -c 'echo kept-page > /home/unin1/public_html/index.html'
check "a database" oxpanel-ctl db create ${T}_data --tenant $T
check "a table with a row in it" mariadb --no-defaults -u root -e "CREATE TABLE ${T}_data.t (v INT); INSERT INTO ${T}_data.t VALUES (42)"
check "a backup" bash -c "oxpanel-ctl backup create $T --wait | grep -q 'state=JOB_STATE_SUCCEEDED'"
check "a database in the trash" bash -c "oxpanel-ctl db create ${T}_old --tenant $T >/dev/null && oxpanel-ctl db delete ${T}_old | grep -q ' trash_id='"
check "a file-manager job in the history" bash -c "oxpanel-ctl files compress $T '' page.tar.gz public_html --format tar-gz --wait | grep -q 'state=JOB_STATE_SUCCEEDED'"
eventually "the site answers" 20 1 http_body_is keep.unin.test / kept-page

# Asked non-interactively without --yes: it must do nothing.
bash release/install.sh --uninstall </dev/null > uninstall-declined.log 2>&1; rc=$?
check "uninstall without --yes and without a terminal does nothing" bash -c "[ $rc = 0 ] && grep -q 'Nothing removed' uninstall-declined.log && rpm -q oxpanel-daemon"

bash release/install.sh --uninstall --yes > uninstall.log 2>&1; rc=$?
echo "--- uninstall.log ---"; cat uninstall.log; echo "---------------------"
[ "$rc" = 0 ] || fail "uninstall exited $rc"
ok "install.sh --uninstall ran"
check "the engine package is gone" bash -c '! rpm -q oxpanel-daemon'
check "the daemon binary is gone" bash -c '! test -e /usr/sbin/oxpanel-daemon'
check "the daemon is not running" bash -c '! systemctl -q is-active oxpanel-daemon'
check "the SELinux module is gone with the package" bash -c '! semodule -l | grep -q "^oxpanel"'
check "the fail2ban jail OxPanel added is gone" bash -c '! test -e /etc/fail2ban/jail.d/50-oxpanel-sshd.local'
check "the uninstaller said what it left" bash -c 'grep -q "LEFT IN PLACE" uninstall.log && grep -q "homes" uninstall.log && grep -q "databases" uninstall.log && grep -q "backups" uninstall.log'
check "RESULT line" grep -q '^RESULT: uninstalled' uninstall.log

check "the tenant account is still there" getent passwd $T
check "its home and page are still there" test "$(cat /home/$T/public_html/index.html)" = kept-page
check "its database and data are still there" bash -c "[ \"\$(mariadb --no-defaults -u root -N -B -e 'SELECT v FROM ${T}_data.t')\" = 42 ]"
check "its backup is still there" bash -c "ls /var/lib/oxpanel-backups/$T/*/ | grep -q ."
check "its deleted database is still in the trash" bash -c "[ \"\$(mariadb --no-defaults -u root -N -B -e \"SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE 'oxpanel\\_trash\\_%'\")\" -ge 1 ]"
check "the uninstaller named the trash and the jobs among what it left" bash -c 'grep -q "trash" uninstall.log && grep -q "jobs" uninstall.log'
check "the records are still there" test -f /var/lib/oxpanel/tenants/$T.json
check "Nginx is still installed and running" bash -c 'rpm -q nginx && systemctl -q is-active nginx'
check "Nginx still serves the site" http_body_is keep.unin.test / kept-page
check "MariaDB is still hardened (no network listener)" bash -c '! ss -H -ltn | grep -Eq ":3306[[:space:]]"'

# Installing again picks everything up.
bash release/install.sh --yes --fail2ban > reinstall.log 2>&1; rc=$?
tail -20 reinstall.log
[ "$rc" = 0 ] || fail "reinstall exited $rc"
ok "install.sh ran again on the host that was uninstalled"
eventually "the daemon is active" 30 1 daemon_active
check "the engine knows the tenant again (its records were kept)" bash -c "oxpanel-ctl tenant get $T | grep -q 'state=TENANT_STATE_READY'"
check "its site is still served" http_body_is keep.unin.test / kept-page
check "its database is still listed" bash -c "oxpanel-ctl db list --tenant $T | grep -q 'database=${T}_data'"
check "its backup is still listed" bash -c "oxpanel-ctl backup list $T | grep -q '^backup='"
check "its trash is still listed" bash -c "oxpanel-ctl db trash-list $T | grep -q ' ${T}_old '"
check "its file-manager job history is still listed" bash -c "oxpanel-ctl files jobs $T | grep -q 'kind=FILE_JOB_KIND_COMPRESS tenant=$T state=JOB_STATE_SUCCEEDED'"
check "the fail2ban jail is back" bash -c 'fail2ban-client status sshd >/dev/null'
check "reconcile is clean" bash -c 'oxpanel-ctl host reconcile | grep -qx "drifts=0"'

oxpanel-ctl db delete ${T}_data >/dev/null 2>&1
oxpanel-ctl db trash-purge $T >/dev/null 2>&1
for id in $(oxpanel-ctl backup list $T | sed -n 's/^backup=\([^ ]*\).*/\1/p'); do oxpanel-ctl backup delete $T "$id" >/dev/null 2>&1; done
oxpanel-ctl vhost remove keep.unin.test >/dev/null 2>&1
check "clean up: the tenant is deleted" oxpanel-ctl tenant delete $T --remove-home
n=$(( $(avc_count) - AVC0 )); if [ "$n" = 0 ]; then ok "zero AVC denials during this phase"; else avc_dump; fail "$n AVC denial(s) during this phase"; fi
phase_end
