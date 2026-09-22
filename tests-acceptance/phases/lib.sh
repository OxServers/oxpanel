# Shared helpers for acceptance phases. Sourced on the VM; runs as root.
set -uo pipefail
PHASE_FAILED=0
ok()   { echo "ok   - $*"; }
info() { echo "info - $*"; }
fail() { echo "FAIL: $*" >&2; PHASE_FAILED=1; if [ "${CONTINUE:-0}" != 1 ]; then exit 1; fi; }
# check "message" cmd args...   → ok/FAIL by exit status (output suppressed unless it fails)
check() { local msg="$1"; shift; local out; if out="$("$@" 2>&1)"; then ok "$msg"; else fail "$msg"$'\n'"$out"; fi; }
# check_not "message" cmd...    → ok when the command fails
check_not() { local msg="$1"; shift; if "$@" >/dev/null 2>&1; then fail "$msg (unexpectedly succeeded)"; else ok "$msg"; fi; }
# eventually "message" tries delay cmd...  → retry until success
eventually() { local msg="$1" tries="$2" delay="$3"; shift 3; local i; for ((i=1;i<=tries;i++)); do if "$@" >/dev/null 2>&1; then ok "$msg"; return 0; fi; sleep "$delay"; done; fail "$msg (after $tries tries)"; }
as_user() { local u="$1"; shift; setpriv --reuid="$u" --regid="$u" --clear-groups --no-new-privs -- "$@"; }
# ctl_ok "<regex>" cmd args...  → run the command, succeed if its output matches.
# (Capture first: piping into `grep -q` closes the pipe early and turns a clean
# multi-line reply into a spurious failure under pipefail.)
ctl_ok() { local pat="$1"; shift; local out; out="$("$@" 2>&1)" && grep -qE "$pat" <<<"$out"; }
http_code() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $1" "http://127.0.0.1${2:-/}"; }
http_body_is() { [ "$(curl -s -H "Host: $1" "http://127.0.0.1${2:-/}")" = "$3" ]; }
daemon_pid() { systemctl show -p MainPID --value oxpanel-daemon; }
daemon_active() { systemctl -q is-active oxpanel-daemon; }
avc_count() {
  local n=0
  if command -v ausearch >/dev/null 2>&1 && systemctl -q is-active auditd; then
    n=$(ausearch -m avc -ts boot -i 2>/dev/null | grep -c '^type=AVC' || true)
  else
    n=$(journalctl -b -k --no-pager 2>/dev/null | grep -c 'avc:  denied' || true)
  fi
  echo "$n"
}
avc_dump() {
  if command -v ausearch >/dev/null 2>&1 && systemctl -q is-active auditd; then ausearch -m avc -ts boot -i 2>/dev/null | tail -60; fi
  journalctl -b -k --no-pager 2>/dev/null | grep 'avc:  denied' | tail -30 || true
}
phase_end() { if [ "$PHASE_FAILED" = 1 ]; then echo "PHASE_RESULT: FAIL"; exit 1; else echo "PHASE_RESULT: OK"; exit 0; fi; }
