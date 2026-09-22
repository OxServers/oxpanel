#!/usr/bin/env bash
# Phase 50 — restart, crash and resume behaviour with real state on disk.
cd "$(dirname "$0")/.."; source phases/lib.sh
echo "== phase 50: restart / kill / resume"
check "create res1" bash -c "oxpanel-ctl tenant create res1 --memory 128M --cpu-weight 20 | grep -q '^created=true'"
check "configure res1.test" bash -c "oxpanel-ctl vhost set res1.test --tenant res1 | grep -q '^changed=true'"
as_user res1 sh -c 'echo res1 > /home/res1/public_html/index.html'
eventually "res1.test serves" 30 0.2 http_body_is res1.test / res1

check "systemctl restart succeeds" systemctl restart oxpanel-daemon
check "daemon active after restart" daemon_active
check "socket recreated with correct perms" test "$(stat -c '%U:%G %a' /run/oxpanel/oxpanel.sock)" = "root:oxpanel 660"
check "tenant still listed after restart" bash -c "oxpanel-ctl tenant list | grep -q tenant=res1"
check "site still serves after restart" http_body_is res1.test / res1

restarts_before=$(systemctl show -p NRestarts --value oxpanel-daemon)
systemctl kill -s SIGKILL oxpanel-daemon
eventually "Restart=on-failure brought the daemon back after SIGKILL" 30 0.5 daemon_active
eventually "API answers after crash restart" 20 0.5 bash -c "oxpanel-ctl tenant list | grep -q tenant=res1"
check "NRestarts incremented" test "$(systemctl show -p NRestarts --value oxpanel-daemon)" -gt "$restarts_before"
check "socket perms intact after crash restart" test "$(stat -c '%U:%G %a' /run/oxpanel/oxpanel.sock)" = "root:oxpanel 660"

echo "-- simulate a crash between useradd and finalisation"
systemctl stop oxpanel-daemon
check "record can be forced back to provisioning" sed -i 's/"state": "ready"/"state": "provisioning"/' /var/lib/oxpanel/tenants/res1.json
check "record now says provisioning" grep -q '"state": "provisioning"' /var/lib/oxpanel/tenants/res1.json
rm -f /etc/systemd/system/oxpanel-tenant-res1.slice; systemctl daemon-reload
systemctl start oxpanel-daemon
check "daemon active" daemon_active
check "identical CreateTenant resumes (created=true)" bash -c "oxpanel-ctl tenant create res1 --memory 128M --cpu-weight 20 | grep -q '^created=true'"
check "tenant is ready again" bash -c "oxpanel-ctl tenant get res1 | grep -q state=TENANT_STATE_READY"
check "slice unit regenerated" test -f /etc/systemd/system/oxpanel-tenant-res1.slice
check "exactly one useradd for res1 in this boot" test "$(journalctl -b _COMM=useradd --no-pager | grep -c 'new user: name=res1,')" = 1
check "account intact" id res1
check "site still serves" http_body_is res1.test / res1
check "provisioning record not applicable to a different spec" bash -c "! oxpanel-ctl tenant create res1 --memory 256M >/dev/null 2>&1"

check "remove res1.test" bash -c "oxpanel-ctl vhost remove res1.test | grep -q '^removed=true'"
check "delete res1" bash -c "oxpanel-ctl tenant delete res1 --remove-home | grep -q '^deleted=true'"
check "daemon journal has no errors" bash -c '! journalctl -b -u oxpanel-daemon -p err --no-pager | grep -q oxpanel-daemon'
phase_end
