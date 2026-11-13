#!/usr/bin/env bash
# Line coverage of oxpanel-daemon from `cargo test`, inside the dev container
# (cargo-llvm-cov + llvm-tools-preview are in tests-integration/Containerfile).
#   make coverage                 summary + gate
#   COVERAGE_HTML=1 make coverage HTML report in target/llvm-cov/html
# The floor is deliberately a little below the measured value (see
# docs/COVERAGE.md): it catches a test suite that stops running, not a point lost.
set -euo pipefail
FLOOR="${COVERAGE_FLOOR:-90}"
cargo llvm-cov --version >/dev/null 2>&1 || { echo "cargo-llvm-cov is missing: run 'make image' (or use OXPANEL_DEV_IMAGE=localhost/oxpanel-dev:<tag> built from tests-integration/Containerfile)" >&2; exit 2; }
# Not instrumented: generated code, the real-OS process runner (it needs root and a real
# host; acceptance and integration cover it), and the entry point.
IGNORE='(oxpanel-proto/|system/real\.rs|oxpanel-bench/|oxpanel-ctl/|/tests/|src/main\.rs)'
cargo llvm-cov -p oxpanel-daemon --ignore-filename-regex "$IGNORE" --summary-only --fail-under-lines "$FLOOR"
if [ "${COVERAGE_HTML:-0}" = 1 ]; then cargo llvm-cov report -p oxpanel-daemon --ignore-filename-regex "$IGNORE" --html; fi
