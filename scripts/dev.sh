#!/usr/bin/env bash
# Run a command (default: cargo) inside the AlmaLinux 9 build container.
#   scripts/dev.sh cargo test
#   scripts/dev.sh cargo clippy --all-targets
#   scripts/dev.sh bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${OXPANEL_DEV_IMAGE:-localhost/oxpanel-dev:alma9}"

if ! podman image exists "$IMAGE"; then
  echo "[dev] building $IMAGE" >&2
  podman build -t "$IMAGE" -f "$ROOT/tests-integration/Containerfile" "$ROOT/tests-integration"
fi

# The registry cache and target dir live in named volumes so incremental builds
# stay fast and the host tree is never littered with root-owned files.
# label=disable: don't relabel the developer's source tree on SELinux hosts.
# OXPANEL_TARGET_VOLUME: a separate build volume, for working in several
# checkouts (git worktrees) at once without them overwriting each other's binaries.
TTY=(); COLOR=never
if [ -t 0 ] && [ -t 1 ]; then TTY=(-t); COLOR=always; fi
exec podman run --rm -i "${TTY[@]}" \
  --security-opt label=disable \
  -v "$ROOT:/work" \
  -v oxpanel-cargo-registry:/usr/local/cargo/registry \
  -v "${OXPANEL_TARGET_VOLUME:-oxpanel-target}":/work/target \
  -w /work \
  -e CARGO_TERM_COLOR="$COLOR" \
  -e RUST_BACKTRACE="${RUST_BACKTRACE:-0}" \
  "$IMAGE" "${@:-cargo build}"
