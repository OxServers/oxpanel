#!/usr/bin/env bash
# Phase 70 — create/destroy soak; nothing may be left behind.
cd "$(dirname "$0")/.."; source phases/lib.sh
N="${SOAK_N:-20}"
echo "== phase 70: soak ($N cycles)"
uid_min=20000; uid_max=29999
rss_before=$(ps -o rss= -p "$(daemon_pid)" | tr -d ' ')
start=$(date +%s); fails=0
for ((i=1;i<=N;i++)); do
  t="soak$i"; d="soak$i.test"
  ctl_ok '^created=true' oxpanel-ctl tenant create "$t" --memory 64M --cpu-weight $((i % 100 + 1)) --owner soak || { echo "cycle $i: create failed"; fails=$((fails+1)); continue; }
  ctl_ok '^changed=true' oxpanel-ctl vhost set "$d" --tenant "$t" || { echo "cycle $i: vhost failed"; fails=$((fails+1)); }
  as_user "$t" sh -c "echo $t > /home/$t/public_html/index.html"
  served=0; for ((j=1;j<=30;j++)); do http_body_is "$d" / "$t" && { served=1; break; }; sleep 0.1; done
  [ "$served" = 1 ] || { echo "cycle $i: $d not served"; fails=$((fails+1)); }
  ctl_ok '^removed=true' oxpanel-ctl vhost remove "$d" || { echo "cycle $i: remove failed"; fails=$((fails+1)); }
  ctl_ok '^deleted=true' oxpanel-ctl tenant delete "$t" --remove-home || { echo "cycle $i: delete failed"; fails=$((fails+1)); }
done
dur=$(( $(date +%s) - start ))
rss_after=$(ps -o rss= -p "$(daemon_pid)" | tr -d ' ')
info "soak: $N cycles in ${dur}s ($(( dur * 1000 / N )) ms/cycle); daemon RSS ${rss_before} kB → ${rss_after} kB"
check "every cycle succeeded ($fails failures)" test "$fails" = 0
check "no tenants remain" test -z "$(oxpanel-ctl tenant list)"
check "no vhosts remain" test -z "$(oxpanel-ctl vhost list)"
check "no tenant slices remain" bash -c "! ls /etc/systemd/system/oxpanel-tenant-*.slice >/dev/null 2>&1"
check "no user-slice drop-ins remain" bash -c "! ls -d /etc/systemd/system/user-2*.slice.d >/dev/null 2>&1"
check "no vhost configs remain" test -z "$(ls -A /etc/nginx/oxpanel.d/)"
check "no soak homes remain" bash -c "! ls -d /home/soak* >/dev/null 2>&1"
check "no accounts left in the tenant uid range" bash -c "! awk -F: -v a=$uid_min -v b=$uid_max '\$3>=a && \$3<=b' /etc/passwd | grep -q ."
check "no records remain" test -z "$(ls -A /var/lib/oxpanel/tenants)$(ls -A /var/lib/oxpanel/vhosts)"
check "nginx -t still clean" nginx -t
check "uid allocation restarted from the bottom" bash -c "oxpanel-ctl tenant create soakfinal | grep -q 'uid=$uid_min' && oxpanel-ctl tenant delete soakfinal --remove-home | grep -q deleted=true"
check "daemon still active" daemon_active
check "no daemon errors in journal" bash -c '! journalctl -b -u oxpanel-daemon -p err --no-pager | grep -q oxpanel-daemon'
n=$(avc_count); if [ "$n" = 0 ]; then ok "zero AVC denials"; else avc_dump; fail "$n AVC denial(s)"; fi
phase_end
