#!/usr/bin/env bash
# Feature traceability gate: every row of docs/FEATURES.md must map to at least
# one automated test in docs/traceability.map, and every reference in the map
# must still exist. Pure bash + awk + grep: runs anywhere, in about a second.
#   scripts/traceability.sh            check; exit 1 on any problem
#   scripts/traceability.sh --report   also print the matrix (row -> number of tests)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
FEATURES=docs/FEATURES.md
MAP=docs/traceability.map
REPORT=0; [ "${1:-}" = "--report" ] && REPORT=1
errors=0
err() { echo "traceability: $*" >&2; errors=$((errors + 1)); }

# "[Section] Feature" for every table row of FEATURES.md (the header row of each
# table, "| Feature | Detail |", is skipped).
rows="$(awk -F'|' '
  /^## / { s = $0; sub(/^## /, "", s); next }
  /^\| / && !/^\| Feature \|/ && !/^\|---/ { f = $2; gsub(/^ +| +$/, "", f); print "[" s "] " f }
' "$FEATURES")"

# The map, as "header<TAB>kind<TAB>args" lines.
parsed="$(awk '
  /^#/ || /^[[:space:]]*$/ { next }
  /^\[/ { h = $0; next }
  /^  / { sub(/^  +/, ""); print h "\t" $0; next }
  { print "BADLINE\t" $0 }
' "$MAP")"

# 1. Every feature row has an entry with at least one reference.
total=0; covered=0
while IFS= read -r row; do
  [ -n "$row" ] || continue
  total=$((total + 1))
  n="$(awk -F'\t' -v h="$row" '$1 == h' <<<"$parsed" | wc -l)"
  if [ "$n" -eq 0 ]; then err "no test mapped for feature row: $row"; else covered=$((covered + 1)); fi
  [ "$REPORT" = 1 ] && printf '%3d  %s\n' "$n" "$row"
done <<<"$rows"

# 2. Every entry names an existing row (so a renamed or removed row cannot leave a stale mapping).
while IFS= read -r h; do
  [ -n "$h" ] || continue
  grep -qxF -- "$h" <<<"$rows" || err "map entry for a row that does not exist in $FEATURES: $h"
done < <(grep '^\[' "$MAP")

# 3. Every reference exists.
while IFS=$'\t' read -r h ref; do
  [ -n "${ref:-}" ] || continue
  if [ "$h" = BADLINE ]; then err "unparsable line in $MAP: $ref"; continue; fi
  kind="${ref%% *}"; rest="${ref#* }"
  case "$kind" in
    unit)
      mod="${rest%% *}"; test="${rest#* }"
      f="oxpanel-daemon/src/$mod.rs"
      [ -f "$f" ] || f="oxpanel-daemon/src/$mod/mod.rs"
      [ -f "$f" ] || { err "[$h] unit $mod: no such module"; continue; }
      grep -qE "^\s*(pub )?(async )?fn $test\(" "$f" || err "[$h] unit test $mod::$test does not exist"
      ;;
    it)
      file="${rest%% *}"; test="${rest#* }"
      f="oxpanel-daemon/tests/$file.rs"
      [ -f "$f" ] || { err "[$h] it $file: no such test file"; continue; }
      grep -qE "^\s*(pub )?(async )?fn $test\(" "$f" || err "[$h] test $file::$test does not exist"
      ;;
    sh)
      f="${rest%% *}"; text="${rest#* }"
      [ -f "$f" ] || { err "[$h] sh $f: no such file"; continue; }
      grep -qF -- "$text" "$f" || err "[$h] check \"$text\" not found in $f"
      ;;
    *) err "[$h] unknown reference kind: $ref";;
  esac
done <<<"$parsed"

echo "traceability: $covered of $total feature rows mapped to tests; $(grep -c . <<<"$parsed") references checked"
if [ "$errors" -ne 0 ]; then echo "traceability: FAILED with $errors problem(s)" >&2; exit 1; fi
echo "traceability: OK"
