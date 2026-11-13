#!/usr/bin/env bash
# Build the engine RPM of an OLDER commit, for the upgrade test of the installer
# (INSTALL=upgrade make acceptance). Runs on the host (needs git and podman):
# exports the commit into a temporary directory and builds it in the dev
# container with a build volume of its own, so the working tree and its build
# volume are untouched.
#
#   scripts/build-old-rpm.sh [<git ref>]      default: d38bae2 (the 0.1.0 line, tag-less)
#
# Output: dist/old-rpms/oxpanel-daemon-<version>-<release>.<dist>.x86_64.rpm
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REF="${1:-${OLD_REF:-d38bae2}}"
IMAGE="${OXPANEL_DEV_IMAGE:-localhost/oxpanel-dev:alma9}"
VOLUME="${OXPANEL_OLD_TARGET_VOLUME:-oxpanel-target-old-rpm}"
SHA="$(git -C "$ROOT" rev-parse --verify "$REF^{commit}")"
OUT="$ROOT/dist/old-rpms"
if ls "$OUT"/oxpanel-daemon-[0-9]*.rpm >/dev/null 2>&1 && [ -e "$OUT/.built-from" ] && [ "$(cat "$OUT/.built-from")" = "$SHA" ]; then
  echo "[old-rpm] already built from $SHA"; ls -1 "$OUT"/oxpanel-daemon-[0-9]*.rpm; exit 0
fi
TMP="$(mktemp -d)"
trap 'podman unshare rm -rf "$TMP" 2>/dev/null || rm -rf "$TMP"' EXIT
git -C "$ROOT" archive "$SHA" | tar -x -C "$TMP"
echo "[old-rpm] building $SHA ($(git -C "$ROOT" log -1 --format=%s "$SHA"))"
podman run --rm --security-opt label=disable \
  -v "$TMP:/work" \
  -v oxpanel-cargo-registry:/usr/local/cargo/registry \
  -v "$VOLUME":/work/target \
  -w /work "$IMAGE" ./scripts/build-rpm.sh >/dev/null
mkdir -p "$OUT"; rm -f "$OUT"/oxpanel-daemon-*.rpm
cp "$TMP"/dist/rpms/oxpanel-daemon-[0-9]*.rpm "$OUT/"
rm -f "$OUT"/oxpanel-daemon-*debug*.rpm
printf '%s\n' "$SHA" >"$OUT/.built-from"
ls -1 "$OUT"/oxpanel-daemon-[0-9]*.rpm
