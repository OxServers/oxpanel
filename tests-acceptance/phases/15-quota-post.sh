#!/usr/bin/env bash
# Phase 15 (after reboot) — user quotas are enforced and the daemon sees it.
cd "$(dirname "$0")/.."; source phases/lib.sh
echo "== phase 15: disk-quota host preparation — verifying"
check "a real reboot happened" test "$(cat /proc/sys/kernel/random/boot_id)" != "$(cat quota-boot_id.pre)"
info "after: $(findmnt -no SOURCE,FSTYPE,OPTIONS -T /home)"
check "the file system holding /home enforces user quotas" bash -c 'findmnt -no OPTIONS -T /home | tr , "\n" | grep -qx usrquota'
eventually "oxpanel-daemon active after boot" 60 1 daemon_active
check "host info reports disk_quota=true" bash -c 'oxpanel-ctl host info | grep -q " disk_quota=true "'
info "$(oxpanel-ctl host info | grep '^disk_quota_detail=')"
if [ "${INSTALL:-}" = installer ]; then
  # The installer, run again after the reboot, must notice that quotas are active and finish.
  bash release/install.sh --yes --quota --no-reboot --fail2ban --enable-epel > install-3.log 2>&1; rc=$?
  tail -30 install-3.log
  [ "$rc" = 0 ] || fail "install.sh after the reboot exited $rc"
  check "install.sh notices that quotas are active" bash -c 'grep -q "user quotas are active on" install-3.log'
  check "install.sh no longer asks for a reboot" bash -c 'grep -q "^RESULT: ok changes=0 .*reboot_required=no" install-3.log'
  check "install.sh verified quotas through the engine" bash -c 'grep -q "disk quotas: active" install-3.log'
  check "the status file says no reboot is needed" grep -qx "reboot_required=no" /var/lib/oxpanel-installer/status
  check "fail2ban came back after the reboot" systemctl -q is-active fail2ban
fi
n=$(avc_count); if [ "$n" = 0 ]; then ok "zero AVC denials on this boot"; else avc_dump; fail "$n AVC denial(s) on this boot"; fi
phase_end
