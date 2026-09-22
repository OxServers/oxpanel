#!/usr/bin/env bash
# Phase 20 — the container integration suite, unchanged, on the real host.
cd "$(dirname "$0")/.."; source phases/lib.sh
echo "== phase 20: integration suite (tests-integration/run-inside.sh)"
if SKIP_INSTALL=1 bash run-inside.sh; then ok "run-inside.sh: all checks passed"; else fail "run-inside.sh reported a failure"; fi
phase_end
