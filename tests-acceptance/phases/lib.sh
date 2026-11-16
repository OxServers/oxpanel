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
    n=$(ausearch --input-logs -m avc -ts boot -i 2>/dev/null | grep -c '^type=AVC' || true)
  else
    n=$(journalctl -b -k --no-pager 2>/dev/null | grep -c 'avc:  denied' || true)
  fi
  echo "$n"
}
avc_dump() {
  if command -v ausearch >/dev/null 2>&1 && systemctl -q is-active auditd; then ausearch --input-logs -m avc -ts boot -i 2>/dev/null | tail -60; fi
  journalctl -b -k --no-pager 2>/dev/null | grep 'avc:  denied' | tail -30 || true
}
phase_end() { if [ "$PHASE_FAILED" = 1 ]; then echo "PHASE_RESULT: FAIL"; exit 1; else echo "PHASE_RESULT: OK"; exit 0; fi; }
# A local ACME authority (Pebble, Let's Encrypt's test server, pinned as in
# tests-integration/run-inside.sh) for the engine on this VM, never a real one.
# pebble_up DAYS: certificates valid DAYS days (10: always due for renewal).
# Lines appended to daemon.env (outside the installer's block); pebble_down
# takes them out again and stops the server.
PEBBLE_BIN=/usr/local/bin/oxpanel-it-pebble
PEBBLE_DIR=/usr/local/share/oxpanel-acc-pebble
pebble_up() {
  local days="${1:-10}" url=https://github.com/letsencrypt/pebble/releases/download/v2.10.1/pebble-linux-amd64.tar.gz
  local sum=4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed
  mkdir -p "$PEBBLE_DIR"
  if [ ! -x "$PEBBLE_BIN" ]; then
    curl -sSfL -o "$PEBBLE_DIR/pebble.tar.gz" "$url" || return 1
    echo "$sum  $PEBBLE_DIR/pebble.tar.gz" | sha256sum -c --quiet || return 1
    tar -xzf "$PEBBLE_DIR/pebble.tar.gz" -C "$PEBBLE_DIR" && install -m0755 "$PEBBLE_DIR/pebble-linux-amd64/linux/amd64/pebble" "$PEBBLE_BIN" || return 1
  fi
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj "/CN=OxPanel acceptance CA" \
    -keyout "$PEBBLE_DIR/ca.key" -out "$PEBBLE_DIR/ca.crt" 2>/dev/null || return 1
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=localhost \
    -keyout "$PEBBLE_DIR/pebble.key" -out "$PEBBLE_DIR/pebble.csr" 2>/dev/null || return 1
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > "$PEBBLE_DIR/san.ext"
  openssl x509 -req -in "$PEBBLE_DIR/pebble.csr" -CA "$PEBBLE_DIR/ca.crt" -CAkey "$PEBBLE_DIR/ca.key" -CAcreateserial -days 30 \
    -extfile "$PEBBLE_DIR/san.ext" -out "$PEBBLE_DIR/pebble.crt" 2>/dev/null || return 1
  cat > "$PEBBLE_DIR/pebble.json" <<JSON
{"pebble": {"listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000",
  "certificate": "$PEBBLE_DIR/pebble.crt", "privateKey": "$PEBBLE_DIR/pebble.key", "httpPort": 80, "tlsPort": 5001,
  "ocspResponderURL": "", "externalAccountBindingRequired": false,
  "profiles": {"default": {"description": "OxPanel acceptance", "validityPeriod": $((days * 86400))}}}}
JSON
  systemctl stop oxpanel-acc-pebble >/dev/null 2>&1 || true
  systemd-run --unit=oxpanel-acc-pebble --collect --setenv=PEBBLE_VA_NOSLEEP=1 "$PEBBLE_BIN" -config "$PEBBLE_DIR/pebble.json" >/dev/null || return 1
  local i; for i in $(seq 1 100); do curl -sf --cacert "$PEBBLE_DIR/ca.crt" https://localhost:14000/dir >/dev/null && break; sleep 0.1; done
  sed -i '/^OXPANEL_ACME_\(DIRECTORY_URL\|CA_FILE\|EMAIL\)=/d' /etc/oxpanel/daemon.env
  printf 'OXPANEL_ACME_DIRECTORY_URL=https://localhost:14000/dir\nOXPANEL_ACME_CA_FILE=%s/ca.crt\nOXPANEL_ACME_EMAIL=hostmaster@example.org\n' \
    "$PEBBLE_DIR" >> /etc/oxpanel/daemon.env
  systemctl restart oxpanel-daemon
}
pebble_down() {
  sed -i '/^OXPANEL_ACME_\(DIRECTORY_URL\|CA_FILE\|EMAIL\)=/d' /etc/oxpanel/daemon.env
  systemctl stop oxpanel-acc-pebble >/dev/null 2>&1 || true
  systemctl restart oxpanel-daemon
}
