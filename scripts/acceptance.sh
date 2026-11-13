#!/usr/bin/env bash
# Host side of `make acceptance`: checks KVM, builds images, builds the RPM when
# needed, and runs the acceptance driver inside the rig container.
#
#   make acceptance                      install from git (handbook §3.2) at the current branch
#   INSTALL=rpm make acceptance          build + install the RPM from the working tree
#   KEEP=1 make acceptance               leave the VM running afterwards
#   PHASES="30 60" SOAK_N=50 GIT_REF=<branch|sha> TARGET=user@host I_UNDERSTAND=1 …
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RIG="${OXPANEL_RIG_IMAGE:-localhost/oxpanel-rig:alma9}"
DEV="${OXPANEL_DEV_IMAGE:-localhost/oxpanel-dev:alma9}"
export INSTALL="${INSTALL:-git}" KEEP="${KEEP:-0}" ACCEL="${ACCEL:-kvm}" TARGET="${TARGET:-}" CONTINUE="${CONTINUE:-0}"
export PHASES="${PHASES:-10 15 20 30 40 50 60 70}" SOAK_N="${SOAK_N:-20}" I_UNDERSTAND="${I_UNDERSTAND:-0}" REFRESH_IMAGE="${REFRESH_IMAGE:-0}"
export GIT_URL="${GIT_URL:-}" GIT_REF="${GIT_REF:-}" VM_CPUS="${VM_CPUS:-}" VM_MEM="${VM_MEM:-}"
export PHASE_TIMEOUT="${PHASE_TIMEOUT:-900}" INSTALL_TIMEOUT="${INSTALL_TIMEOUT:-2400}" TARGET_PORT="${TARGET_PORT:-22}"
say() { echo "[acceptance] $*" >&2; }
die() { say "ERROR: $*"; exit 2; }

if [ -z "$TARGET" ] && [ "$ACCEL" = kvm ]; then
  [ -e /dev/kvm ] || die "/dev/kvm not found: enable virtualisation in the BIOS/hypervisor, or run with ACCEL=tcg (slow) or TARGET=user@host"
  { [ -r /dev/kvm ] && [ -w /dev/kvm ]; } || die "/dev/kvm is not readable/writable by $(id -un): add yourself to the kvm group or chmod 666 /dev/kvm"
fi
command -v podman >/dev/null || die "podman is required"
podman image exists "$RIG" || { say "building rig image $RIG"; podman build -t "$RIG" -f "$ROOT/tests-acceptance/Containerfile" "$ROOT/tests-acceptance" >/dev/null; }

case "$INSTALL" in
  rpm)
    if [ -n "${RPM:-}" ]; then mkdir -p "$ROOT/dist/rpms"; cp -f "$RPM" "$ROOT/dist/rpms/"; else
      podman image exists "$DEV" || { say "building dev image $DEV"; podman build -t "$DEV" -f "$ROOT/tests-integration/Containerfile" "$ROOT/tests-integration" >/dev/null; }
      say "building RPM from the working tree"; (cd "$ROOT" && ./scripts/dev.sh ./scripts/build-rpm.sh >/dev/null)
    fi
    say "RPM: $(ls "$ROOT"/dist/rpms/oxpanel-daemon-[0-9]*.rpm | grep -vE 'debuginfo|debugsource' | xargs -n1 basename)";;
  git)
    if [ -z "$GIT_REF" ]; then
      branch="$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)"
      [ "$branch" = HEAD ] && branch="$(git -C "$ROOT" rev-parse HEAD)"
      [ "$branch" = main ] || GIT_REF="$branch"   # main = the handbook's own clone line, unmodified
      export GIT_REF
    fi
    if [ -n "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ]; then say "WARNING: the working tree has uncommitted changes; a git install tests what is on the remote, not this tree (use INSTALL=rpm for local changes)"; fi
    ref="${GIT_REF:-main}"; git -C "$ROOT" fetch -q origin 2>/dev/null || true
    if git -C "$ROOT" rev-parse -q --verify "origin/$ref" >/dev/null 2>&1 && ! git -C "$ROOT" merge-base --is-ancestor HEAD "origin/$ref" 2>/dev/null; then
      say "WARNING: local HEAD is not pushed to origin/$ref; the VM will test $(git -C "$ROOT" rev-parse --short "origin/$ref")"
    fi
    say "git install: ${GIT_URL:-https://github.com/OxServers/oxpanel.git} @ ${GIT_REF:-main}";;
  *) die "INSTALL must be git or rpm";;
esac

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"; OUT="$ROOT/dist/acceptance/$STAMP"; mkdir -p "$OUT"; ln -sfn "$STAMP" "$ROOT/dist/acceptance/latest"
ARGS=(--security-opt label=disable -v "$ROOT:/work:ro" -v oxpanel-images:/cache -v "$OUT:/out"
      -e INSTALL -e KEEP -e ACCEL -e TARGET -e CONTINUE -e PHASES -e SOAK_N -e I_UNDERSTAND -e REFRESH_IMAGE
      -e GIT_URL -e GIT_REF -e VM_CPUS -e VM_MEM -e PHASE_TIMEOUT -e INSTALL_TIMEOUT -e TARGET_PORT)
[ -z "$TARGET" ] && [ "$ACCEL" = kvm ] && ARGS+=(--device /dev/kvm)
if [ -n "${TARGET_KEY:-}" ]; then ARGS+=(-v "$TARGET_KEY:/target-key:ro" -e TARGET_KEY=/target-key); fi
say "run directory: dist/acceptance/$STAMP"
if [ "$KEEP" = 1 ] && [ -z "$TARGET" ]; then
  podman rm -f oxpanel-acceptance-vm >/dev/null 2>&1 || true
  cid="$(podman run -d --name oxpanel-acceptance-vm -p 127.0.0.1:2222:2222 -p 127.0.0.1:8080:8080 "${ARGS[@]}" "$RIG" /work/tests-acceptance/acceptance.sh)"
  podman logs -f "$cid" 2>&1 | sed '/^ACCEPTANCE_DONE/q'
  rc="$(cat "$OUT/exit-code" 2>/dev/null || echo 2)"
else
  set +e; podman run --rm --name "oxpanel-acceptance-$STAMP" "${ARGS[@]}" "$RIG" /work/tests-acceptance/acceptance.sh; rc=$?; set -e
fi
say "report: dist/acceptance/$STAMP/report.md (exit $rc)"
exit "$rc"
