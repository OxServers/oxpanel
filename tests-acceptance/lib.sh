# Driver-side helpers (inside the rig container).
log() { printf '[acc %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
warn() { log "WARNING: $*"; }
die() { log "ERROR: $*"; exit 1; }
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR -o ServerAliveInterval=15 -o ServerAliveCountMax=4)
key_opt() { if [ -n "${KEY:-}" ]; then printf '%s' "-i"; fi; }
vm_ssh() {
  if [ -n "${KEY:-}" ]; then ssh "${SSH_OPTS[@]}" -i "$KEY" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" "$@";
  else ssh "${SSH_OPTS[@]}" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" "$@"; fi
}
# vm_scp <local...> <remote path>
vm_scp() {
  local args=("$@"); local dest="${args[-1]}"; unset 'args[-1]'
  if [ -n "${KEY:-}" ]; then scp -q "${SSH_OPTS[@]}" -i "$KEY" -P "$SSH_PORT" -r "${args[@]}" "$SSH_USER@$SSH_HOST:$dest";
  else scp -q "${SSH_OPTS[@]}" -P "$SSH_PORT" -r "${args[@]}" "$SSH_USER@$SSH_HOST:$dest"; fi
}
vm_wait_ssh() {
  local deadline=$(( $(date +%s) + ${1:-180} ))
  while ! vm_ssh true 2>/dev/null; do
    [ "$(date +%s)" -lt "$deadline" ] || return 1
    if [ -n "${QEMU_PID:-}" ] && ! kill -0 "$QEMU_PID" 2>/dev/null; then return 2; fi
    sleep 2
  done
}
# shell-quote an env assignment list for the remote side
remote_env() { local out=""; local v; for v in "$@"; do out+="$(printf '%s=%q ' "$v" "${!v:-}")"; done; printf '%s' "$out"; }
