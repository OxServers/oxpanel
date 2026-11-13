#!/usr/bin/env bash
# Phase 90 — what provisioning costs on a real host (real useradd, nginx -t,
# systemctl), and how it grows with the number of sites. Numbers go to the log
# ("info - perf:" lines, copied into docs/PERFORMANCE.md); the budgets are wide
# (about 3x the measured values) so only a real regression fails the phase.
cd "$(dirname "$0")/.."; source phases/lib.sh
N="${PERF_N:-100}"
echo "== phase 90: performance on the real host ($N tenants with a site each)"
now_ms() { echo $(( $(date +%s%N) / 1000000 )); }
rss() { ps -o rss= -p "$(daemon_pid)" | tr -d ' '; }
median() { sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }
AVC0=$(avc_count)
rss0=$(rss); info "perf: daemon RSS at start: ${rss0} kB"
declare -a TC SC; t_start=$(now_ms)
for ((i=1;i<=N;i++)); do
  t="perf$i"; d="perf$i.test"
  a=$(now_ms); oxpanel-ctl tenant create "$t" --memory 64M --owner perf >/dev/null || fail "create $t"
  b=$(now_ms); oxpanel-ctl vhost set "$d" --tenant "$t" >/dev/null || fail "site $d"
  c=$(now_ms); TC+=($((b-a))); SC+=($((c-b)))
  if [ $((i % 25)) = 0 ] || [ "$i" = 1 ]; then
    r0=$(now_ms); systemctl reload nginx; r1=$(now_ms)
    t0=$(now_ms); nginx -t >/dev/null 2>&1; t1=$(now_ms)
    info "perf: at $i sites: reload nginx $((r1-r0)) ms, nginx -t $((t1-t0)) ms, create tenant (last) $((b-a)) ms, configure site (last) $((c-b)) ms, daemon RSS $(rss) kB"
  fi
done
total=$(( $(now_ms) - t_start ))
first10=$(printf '%s\n' "${TC[@]:0:10}" | median); last10=$(printf '%s\n' "${TC[@]: -10}" | median)
sfirst10=$(printf '%s\n' "${SC[@]:0:10}" | median); slast10=$(printf '%s\n' "${SC[@]: -10}" | median)
info "perf: $N tenants + sites in $((total/1000)) s ($((total/N)) ms per tenant+site)"
info "perf: CreateTenant median first 10: ${first10} ms, last 10: ${last10} ms"
info "perf: ConfigureVirtualHost median first 10: ${sfirst10} ms, last 10: ${slast10} ms"
t0=$(now_ms); oxpanel-ctl tenant list >/dev/null; t1=$(now_ms); info "perf: ListTenants ($N): $((t1-t0)) ms (includes oxpanel-ctl start-up)"
t0=$(now_ms); oxpanel-ctl vhost list >/dev/null; t1=$(now_ms); info "perf: ListVirtualHosts ($N): $((t1-t0)) ms"
t0=$(now_ms); oxpanel-ctl host reconcile >/dev/null; t1=$(now_ms); info "perf: Reconcile ($N tenants, $N sites): $((t1-t0)) ms"
t0=$(now_ms); oxpanel-ctl host info >/dev/null; t1=$(now_ms); info "perf: GetHostInfo: $((t1-t0)) ms"
t0=$(now_ms); oxpanel-ctl tenant suspend perf50 >/dev/null; t1=$(now_ms); oxpanel-ctl tenant resume perf50 >/dev/null; t2=$(now_ms); info "perf: suspend $((t1-t0)) ms, resume $((t2-t1)) ms (one site)"
systemctl restart oxpanel-daemon; t0=$(now_ms)
until oxpanel-ctl tenant list >/dev/null 2>&1; do sleep 0.1; [ $(( $(now_ms) - t0 )) -lt 60000 ] || break; done
info "perf: daemon restart until it answers ($N tenants, $N sites; includes start-up convergence of every site): $(( $(now_ms) - t0 )) ms"
rss1=$(rss); info "perf: daemon RSS after: ${rss1} kB"
ok_http=0; for d in perf1.test "perf${N}.test"; do [ "$(http_code "$d" /)" != 000 ] && ok_http=$((ok_http+1)); done

# Budgets: about 3x what this was measured at.
check "$N tenants with a site each in under $((N * 1500)) ms per pair (took $((total/N)) ms)" test $((total / N)) -lt 1500
check "creating the last tenant is not more than 5x slower than the first (${first10} -> ${last10} ms)" test "$last10" -lt $(( first10 * 5 + 200 ))
check "configuring the last site is not more than 5x slower than the first (${sfirst10} -> ${slast10} ms)" test "$slast10" -lt $(( sfirst10 * 5 + 200 ))
check "daemon RSS stays under 100 MB (${rss1} kB)" test "$rss1" -lt 100000
check "all sites still serve" test "$ok_http" = 2
check "no drift at $N tenants" bash -c "oxpanel-ctl host reconcile | grep -q '^drifts=0$'"
for ((i=1;i<=N;i++)); do oxpanel-ctl vhost remove "perf$i.test" >/dev/null 2>&1 || true; oxpanel-ctl tenant delete "perf$i" --remove-home >/dev/null 2>&1 || true; done
check "everything removed again" test -z "$(oxpanel-ctl tenant list)$(oxpanel-ctl vhost list)"
check "daemon still active, no errors" bash -c "systemctl -q is-active oxpanel-daemon && ! journalctl -b -u oxpanel-daemon -p err --no-pager | grep -q oxpanel-daemon"
n=$(( $(avc_count) - AVC0 )); if [ "$n" = 0 ]; then ok "zero AVC denials during this phase"; else avc_dump; fail "$n AVC denial(s) during this phase"; fi
phase_end
