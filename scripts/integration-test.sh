#!/usr/bin/env bash
# Root integration test on the real target OS.
#
# Builds release binaries in the dev container, then boots an AlmaLinux 9
# container *with systemd as PID 1*, installs the daemon from the packaging
# files exactly as the RPM would, starts it through its hardened unit, and
# drives it with oxpanel-ctl while asserting on the real effects: accounts,
# home modes, ACLs, systemd units, nginx serving the tenant's files, and the
# symlink / dot-file / unauthorised-peer defences.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${OXPANEL_DEV_IMAGE:-localhost/oxpanel-dev:alma9}"
NAME="oxpanel-it-$$"

if ! podman image exists "$IMAGE"; then
  podman build -t "$IMAGE" -f "$ROOT/tests-integration/Containerfile" "$ROOT/tests-integration"
fi

echo "[it] building release binaries"
"$ROOT/scripts/dev.sh" cargo build --release --locked -p oxpanel-daemon -p oxpanel-ctl

echo "[it] booting systemd container $NAME"
podman run -d --name "$NAME" --systemd=always --security-opt label=disable \
  -v "$ROOT:/work:ro" -v "${OXPANEL_TARGET_VOLUME:-oxpanel-target}":/work/target:ro "$IMAGE" >/dev/null
trap 'echo "[it] logs:"; podman exec "$NAME" journalctl -u oxpanel-daemon --no-pager -o short-monotonic 2>/dev/null | tail -60 || true; podman rm -f "$NAME" >/dev/null' EXIT

for _ in $(seq 1 60); do
  state="$(podman exec "$NAME" systemctl is-system-running 2>/dev/null || true)"
  case "$state" in running|degraded) break ;; esac
  sleep 1
done
echo "[it] systemd state: ${state:-unknown}"

podman exec "$NAME" bash /work/tests-integration/run-inside.sh
echo "[it] PASS"
