#!/usr/bin/env bash
# Phase 40 — the unit's sandbox directives actually applied (needs a real machine).
cd "$(dirname "$0")/.."; source phases/lib.sh
echo "== phase 40: sandbox"
PID=$(daemon_pid); [ -n "$PID" ] && [ "$PID" != 0 ] || fail "daemon has no MainPID"
info "MainPID=$PID"
check "no sandbox directive was ignored" bash -c "! journalctl -b -u oxpanel-daemon --no-pager | grep -qi 'ignoring'"
check "PrivateNetwork configured" test "$(systemctl show -p PrivateNetwork --value oxpanel-daemon)" = yes
check "daemon has its own network namespace" test "$(readlink /proc/$PID/ns/net)" != "$(readlink /proc/1/ns/net)"
check "that namespace contains only lo" test "$(nsenter -t "$PID" -n -- ip -o link show | wc -l)" = 1
check "daemon has its own UTS namespace (ProtectHostname)" test "$(readlink /proc/$PID/ns/uts)" != "$(readlink /proc/1/ns/uts)"
check "daemon has its own mount namespace" test "$(readlink /proc/$PID/ns/mnt)" != "$(readlink /proc/1/ns/mnt)"
check "NoNewPrivs=1" grep -qE '^NoNewPrivs:\s+1' /proc/$PID/status
check "seccomp filter active (Seccomp=2)" grep -qE '^Seccomp:\s+2' /proc/$PID/status
check "runs as uid 0 (by design, sandboxed)" test "$(awk '/^Uid:/{print $2}' /proc/$PID/status)" = 0
command -v capsh >/dev/null || dnf -y -q install libcap >/dev/null 2>&1 || true
caps=$(capsh --decode="$(awk '/^CapBnd:/{print $2}' /proc/$PID/status)")
info "CapBnd: $caps"
for c in cap_sys_module cap_net_admin cap_net_raw cap_sys_ptrace cap_sys_boot cap_sys_time cap_mknod cap_sys_rawio cap_audit_control cap_bpf; do
  check "bounding set excludes $c" bash -c "! echo '$caps' | grep -q '\b$c\b'"
done
for c in cap_chown cap_dac_override cap_fowner cap_setuid cap_setgid cap_net_bind_service cap_sys_admin; do
  check "bounding set keeps $c (needed by useradd/setfacl/nginx -t/namespaces)" bash -c "echo '$caps' | grep -q '\b$c\b'"
done
check_not "/usr is read-only inside the service (ProtectSystem=strict)" nsenter -t "$PID" -m -- sh -c 'echo x > /usr/.oxpanel-rw-test'
check "/etc/nginx/oxpanel.d is writable inside the service" nsenter -t "$PID" -m -- sh -c 'echo x > /etc/nginx/oxpanel.d/.rwtest && rm -f /etc/nginx/oxpanel.d/.rwtest'
check "/home is writable inside the service" nsenter -t "$PID" -m -- sh -c 'mkdir /home/.oxpanel-rw-test && rmdir /home/.oxpanel-rw-test'
check_not "/boot is invisible or read-only inside the service" nsenter -t "$PID" -m -- sh -c 'ls /boot/* >/dev/null 2>&1 && echo x > /boot/.oxpanel-rw-test'
check "/proc/kcore not visible (ProtectKernelLogs/ProcSubset)" nsenter -t "$PID" -m -- sh -c '! test -r /proc/kcore'
info "unit hardening score: $(systemd-analyze security oxpanel-daemon --no-pager 2>/dev/null | tail -1)"
phase_end
