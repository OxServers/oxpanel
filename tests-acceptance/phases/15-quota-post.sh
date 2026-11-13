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
n=$(avc_count); if [ "$n" = 0 ]; then ok "zero AVC denials on this boot"; else avc_dump; fail "$n AVC denial(s) on this boot"; fi
phase_end
