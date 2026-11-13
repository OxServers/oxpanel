#!/usr/bin/env bash
# Phase 60 (after reboot) — everything came back.
cd "$(dirname "$0")/.."; source phases/lib.sh
echo "== phase 60: reboot — verifying"
check "boot id changed (a real reboot happened)" test "$(cat /proc/sys/kernel/random/boot_id)" != "$(cat boot_id.pre)"
eventually "oxpanel-daemon active after boot" 60 1 daemon_active
eventually "nginx active after boot" 60 1 systemctl -q is-active nginx
check "socket back with correct perms" test "$(stat -c '%U:%G %a' /run/oxpanel/oxpanel.sock)" = "root:oxpanel 660"
check "tenant list identical" bash -c "diff <(oxpanel-ctl tenant list) tenants.pre"
check "vhost list identical" bash -c "diff <(oxpanel-ctl vhost list) vhosts.pre"
eventually "boota.test serves after reboot" 60 0.5 http_body_is boota.test / boota
eventually "www.boota.test alias serves" 20 0.5 http_body_is www.boota.test / boota
eventually "bootb.test serves after reboot" 20 0.5 http_body_is bootb.test / bootb
eventually "PHP pool came back by itself after reboot" 60 0.5 systemctl -q is-active oxpanel-php-bootb.service
eventually "bootphp.test serves PHP after reboot" 60 0.5 http_body_is bootphp.test / php-42
eventually "Node app came back by itself after reboot" 60 0.5 systemctl -q is-active oxpanel-app-bootnode.test.service
eventually "bootnode.test serves after reboot" 60 0.5 http_body_is bootnode.test / node-42
check "PHP pool is in the tenant slice after reboot" bash -c "systemctl show -p ControlGroup --value oxpanel-php-bootb.service | grep -q oxpanel-tenant-bootb.slice"
eventually "SFTP chroot mount came back by itself" 60 0.5 findmnt -n /var/lib/oxpanel/sftp/boota/home/boota
check "SFTP login works after reboot" bash -c 'echo "get public_html/index.html boota.sftp" | sftp -q -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o LogLevel=ERROR -i boot_sftp_key -b - boota@127.0.0.1 && test "$(cat boota.sftp)" = boota'
if grep -q ' disk_max=67108864 ' tenants.pre; then
  check "bootb's disk limit is enforced after reboot" bash -c 'u=$(id -u bootb); xfs_quota -x -c "report -u -n -N -b -L $u -U $u" "$(findmnt -no TARGET -T /home)" | grep -qE "^#$u +[0-9]+ +65536 +65536 "'
fi
check "no drift after reboot" bash -c "oxpanel-ctl host reconcile | grep -q '^drifts=0$'"
check "boota slice loaded with its MemoryMax" test "$(systemctl show -p MemoryMax --value oxpanel-tenant-boota.slice)" = 268435456
check "boota slice CPUWeight" test "$(systemctl show -p CPUWeight --value oxpanel-tenant-boota.slice)" = 40
check "bootb slice loaded" test "$(systemctl show -p MemoryMax --value oxpanel-tenant-bootb.slice)" = 134217728
check "ACLs intact" bash -c "diff <(getfacl -p /home/boota /home/boota/public_html 2>/dev/null) acl.pre"
check "records intact" test -f /var/lib/oxpanel/tenants/boota.json -a -f /var/lib/oxpanel/vhosts/bootb.test.json
check "no sandbox directive ignored on this boot" bash -c "! journalctl -b -u oxpanel-daemon --no-pager | grep -qi ignoring"
check "no daemon errors on this boot" bash -c '! journalctl -b -u oxpanel-daemon -p err --no-pager | grep -q oxpanel-daemon'
n=$(avc_count); if [ "$n" = 0 ]; then ok "zero AVC denials on this boot"; else avc_dump; fail "$n AVC denial(s) on this boot"; fi
check "unknown host still closed" test "$(curl -s -H 'Host: nobody.test' http://127.0.0.1/; echo "rc=$?")" = "rc=52"
for d in boota.test bootb.test bootphp.test bootnode.test; do check "remove $d" bash -c "oxpanel-ctl vhost remove $d | grep -q '^removed=true'"; done
for t in boota bootb; do check "delete $t" bash -c "oxpanel-ctl tenant delete $t --remove-home | grep -q '^deleted=true'"; done
phase_end
