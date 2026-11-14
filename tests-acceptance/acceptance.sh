#!/usr/bin/env bash
# Acceptance driver. Runs inside the rig container (see scripts/acceptance.sh for
# the host side). Boots a fresh AlmaLinux 9 VM (or uses TARGET=user@host), installs
# OxPanel the way a user would, runs the phases, collects artifacts, writes report.md.
set -euo pipefail
HERE=/work/tests-acceptance; WORK=/work
source "$HERE/lib.sh"

OUT="${OUT:-/out}"; CACHE="${CACHE:-/cache}"
INSTALL="${INSTALL:-git}"; PHASES="${PHASES:-10 15 20 30 40 50 60 70 80 90}"; SOAK_N="${SOAK_N:-20}"
ACCEL="${ACCEL:-kvm}"; CONTINUE="${CONTINUE:-0}"; KEEP="${KEEP:-0}"; REFRESH_IMAGE="${REFRESH_IMAGE:-0}"
GIT_URL="${GIT_URL:-}"; GIT_REF="${GIT_REF:-}"; RPM_DIR="${RPM_DIR:-/work/dist/rpms}"
TARGET="${TARGET:-}"; TARGET_PORT="${TARGET_PORT:-22}"; TARGET_KEY="${TARGET_KEY:-}"; I_UNDERSTAND="${I_UNDERSTAND:-0}"
SSH_PORT="${SSH_PORT:-2222}"; HTTP_PORT="${HTTP_PORT:-8080}"
PHASE_TIMEOUT="${PHASE_TIMEOUT:-900}"; INSTALL_TIMEOUT="${INSTALL_TIMEOUT:-2400}"
IMAGE_BASE=https://repo.almalinux.org/almalinux/9/cloud/x86_64/images
IMAGE_NAME=AlmaLinux-9-GenericCloud-latest.x86_64.qcow2
QEMU=/usr/libexec/qemu-kvm

mkdir -p "$OUT/phases" "$OUT/host"
RUN="$(mktemp -d /tmp/acc.XXXXXX)"
T0=$(date +%s); STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
EXIT=0; QEMU_PID=""; PASST_PID=""; IMAGE_DESC="-"; VM_DESC="-"; TESTED_COMMIT="-"
declare -a P_NUM P_NAME P_STATUS P_SECS P_OK P_FAIL

cleanup_vm() {
  if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
    vm_ssh 'systemctl poweroff' >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do kill -0 "$QEMU_PID" 2>/dev/null || break; sleep 1; done
    kill -0 "$QEMU_PID" 2>/dev/null && { warn "qemu did not stop; killing"; kill -9 "$QEMU_PID" 2>/dev/null || true; }
  fi
  [ -n "$PASST_PID" ] && kill "$PASST_PID" 2>/dev/null || true
  rm -rf "$RUN"
}
DONE=0
on_exit() {
  local rc=$?
  [ "$DONE" = 1 ] && return 0
  log "driver aborted unexpectedly (exit $rc)"; EXIT=2
  collect || true; report || true
  [ "$KEEP" = 1 ] || cleanup_vm
  echo "$EXIT" > "$OUT/exit-code"; echo "ACCEPTANCE_DONE exit=$EXIT"
}
trap on_exit EXIT

# ---------------------------------------------------------------- image
ensure_image() {
  mkdir -p "$CACHE"
  local base="$CACHE/base.qcow2"
  if [ "$REFRESH_IMAGE" = 1 ] || [ ! -f "$base" ]; then
    log "downloading $IMAGE_NAME"
    curl -sSfL -o "$base.part" "$IMAGE_BASE/$IMAGE_NAME"; mv "$base.part" "$base"; rm -f "$base.verified"
  fi
  if [ ! -f "$base.verified" ] || [ "$REFRESH_IMAGE" = 1 ]; then
    curl -sSfL -o "$CACHE/CHECKSUM" "$IMAGE_BASE/CHECKSUM" || die "cannot fetch CHECKSUM"
    local sha; sha="$(sha256sum "$base" | cut -d' ' -f1)"
    local name; name="$(awk -v s="$sha" '$1==s{print $2}' "$CACHE/CHECKSUM" | head -1)"
    [ -n "$name" ] || die "image sha256 $sha not present in the published CHECKSUM file"
    echo "$name $sha" > "$base.verified"
  fi
  IMAGE_DESC="$(cat "$base.verified")"
  log "image verified: $IMAGE_DESC"
}

# ---------------------------------------------------------------- vm
provision() {
  ensure_image
  local cpus mem
  if [ "$INSTALL" = git ]; then cpus="${VM_CPUS:-4}"; mem="${VM_MEM:-4096}"; else cpus="${VM_CPUS:-2}"; mem="${VM_MEM:-2048}"; fi
  qemu-img create -q -f qcow2 -b "$CACHE/base.qcow2" -F qcow2 "$RUN/disk.qcow2" 20G
  ssh-keygen -q -t ed25519 -N '' -C oxpanel-acceptance -f "$KEY"
  local pub; pub="$(cat "$KEY.pub")"
  mkdir -p "$RUN/seed"
  sed "s|__PUBKEY__|$pub|g" "$HERE/cloud-init/user-data" > "$RUN/seed/user-data"
  sed "s|__INSTANCE__|oxpanel-acc-$(date +%s)|" "$HERE/cloud-init/meta-data" > "$RUN/seed/meta-data"
  if command -v xorriso >/dev/null; then
    xorriso -as mkisofs -quiet -o "$RUN/seed.iso" -V cidata -J -r -input-charset utf-8 "$RUN/seed/user-data" "$RUN/seed/meta-data" 2>/dev/null
  else
    genisoimage -quiet -o "$RUN/seed.iso" -V cidata -J -r -input-charset utf-8 "$RUN/seed/user-data" "$RUN/seed/meta-data"
  fi
  local accel_args net_args
  if [ "$ACCEL" = kvm ]; then accel_args="-accel kvm -cpu host"; else accel_args="-accel tcg -cpu max"; fi
  if "$QEMU" -netdev help 2>/dev/null | grep -qx user; then
    net_args="-netdev user,id=n0,hostfwd=tcp:0.0.0.0:$SSH_PORT-:22,hostfwd=tcp:0.0.0.0:$HTTP_PORT-:80"
    VM_DESC="qemu $("$QEMU" --version | head -1 | awk '{print $4}') · $ACCEL · ${cpus} vCPU · ${mem} MB · slirp"
  else
    passt -f -s "$RUN/passt.sock" -t "$SSH_PORT:22" -t "$HTTP_PORT:80" > "$OUT/passt.log" 2>&1 &
    PASST_PID=$!
    for _ in $(seq 1 50); do [ -S "$RUN/passt.sock" ] && break; sleep 0.1; done
    net_args="-netdev stream,id=n0,server=off,addr.type=unix,addr.path=$RUN/passt.sock"
    VM_DESC="qemu $("$QEMU" --version | head -1 | awk '{print $4}') · $ACCEL · ${cpus} vCPU · ${mem} MB · passt"
  fi
  log "booting VM ($VM_DESC)"
  # shellcheck disable=SC2086
  "$QEMU" -name oxpanel-acc $accel_args -machine q35 -smp "$cpus" -m "$mem" \
    -display none -monitor none -serial "file:$OUT/console.log" \
    -device virtio-rng-pci \
    -drive "file=$RUN/disk.qcow2,if=virtio,format=qcow2,cache=unsafe" \
    -drive "file=$RUN/seed.iso,if=virtio,format=raw,readonly=on" \
    $net_args -device virtio-net-pci,netdev=n0 \
    > "$OUT/qemu.log" 2>&1 &
  QEMU_PID=$!
  sleep 1; kill -0 "$QEMU_PID" 2>/dev/null || { cat "$OUT/qemu.log"; die "qemu exited immediately"; }
  log "waiting for SSH"
  local rc=0; vm_wait_ssh 240 || rc=$?
  if [ "$rc" = 1 ]; then
    # Root key login refused? Come in as the image's default user and enable it.
    warn "root login not available yet; trying the default user"
    SSH_USER=almalinux
    if vm_wait_ssh 60; then
      vm_ssh "sudo -n sh -c 'mkdir -p /root/.ssh && cat ~almalinux/.ssh/authorized_keys >> /root/.ssh/authorized_keys && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys && restorecon -R /root/.ssh; printf \"PermitRootLogin prohibit-password\\n\" > /etc/ssh/sshd_config.d/10-oxpanel-acceptance.conf && systemctl reload sshd'"
      SSH_USER=root; rc=0; vm_wait_ssh 60 || rc=$?
    fi
  fi
  if [ "$rc" != 0 ]; then tail -40 "$OUT/console.log" || true; cat "$OUT/qemu.log" || true; die "VM did not become reachable over SSH (rc=$rc)"; fi
  vm_ssh 'timeout 240 cloud-init status --wait >/dev/null 2>&1; cloud-init status' | tail -1 | sed 's/^/[acc] cloud-init: /'
  log "VM up: $(vm_ssh 'echo "$(cat /etc/almalinux-release) · $(uname -r) · SELinux $(getenforce)"')"
}

# ---------------------------------------------------------------- phases
run_remote() { # <label> <timeout> <remote command>
  local label="$1" to="$2" cmd="$3" t0 rc=0 secs okc failc first
  t0=$(date +%s); log "phase $label: start"
  set +e; timeout "$to" bash -c "$(declare -f vm_ssh); $(declare -p SSH_OPTS KEY SSH_PORT SSH_USER SSH_HOST); vm_ssh $(printf '%q' "$cmd")" > "$OUT/phases/$label.log" 2>&1; rc=$?; set -e
  secs=$(( $(date +%s) - t0 ))
  okc=$(grep -c '^ok   -' "$OUT/phases/$label.log" || true); failc=$(grep -c '^FAIL:' "$OUT/phases/$label.log" || true)
  first=$(grep -m1 '^FAIL:' "$OUT/phases/$label.log" | cut -c1-160 || true)
  local status; case "$rc" in 0) status=OK;; 124) status=TIMEOUT;; 255) status=SSH-LOST;; *) status=FAIL;; esac
  [ "$status" = OK ] && [ "$failc" != 0 ] && status=FAIL
  P_NUM+=("${label%%-*}"); P_NAME+=("${label#*-}"); P_STATUS+=("$status"); P_SECS+=("$secs"); P_OK+=("$okc"); P_FAIL+=("${first:-}")
  log "phase $label: $status ($okc ok, ${failc} fail, ${secs}s)"
  if [ "$status" != OK ]; then echo "----- $label (last 25 lines) -----"; tail -25 "$OUT/phases/$label.log"; echo "-----"; fi
  [ "$status" = OK ]
}
phase_env() { remote_env INSTALL GIT_URL GIT_REF SOAK_N CONTINUE; }
run_phase() { # <NN> → script name
  local n="$1" script rc=0
  case "$n" in
    10) run_remote 10-install "$INSTALL_TIMEOUT" "cd /root/acc && $(phase_env) bash phases/10-install.sh" || rc=$?;;
    12) run_remote 12-upgrade "$PHASE_TIMEOUT" "cd /root/acc && $(phase_env) bash phases/12-upgrade.sh" || rc=$?;;
    17) run_remote 17-installer-options "$PHASE_TIMEOUT" "cd /root/acc && $(phase_env) bash phases/17-installer-options.sh" || rc=$?;;
    16) run_remote 16-fail2ban "$PHASE_TIMEOUT" "cd /root/acc && $(phase_env) bash phases/16-fail2ban.sh" || rc=$?;;
    95) run_remote 95-uninstall "$PHASE_TIMEOUT" "cd /root/acc && $(phase_env) bash phases/95-uninstall.sh" || rc=$?;;
    15) run_remote 15-quota-pre "$PHASE_TIMEOUT" "cd /root/acc && $(phase_env) bash phases/15-quota-pre.sh" || rc=$?
        if [ "$rc" = 0 ]; then
          log "rebooting VM (disk quotas)"; vm_ssh 'systemctl reboot' >/dev/null 2>&1 || true; sleep 8
          if vm_wait_ssh 300; then run_remote 15-quota-post "$PHASE_TIMEOUT" "cd /root/acc && $(phase_env) bash phases/15-quota-post.sh" || rc=$?
          else P_NUM+=(15); P_NAME+=(quota-post); P_STATUS+=(NO-SSH); P_SECS+=(300); P_OK+=(0); P_FAIL+=("VM did not come back after reboot"); rc=1; fi
        fi;;
    20) run_remote 20-integration "$PHASE_TIMEOUT" "cd /root/acc && $(phase_env) bash phases/20-integration.sh" || rc=$?;;
    30) run_remote 30-selinux "$PHASE_TIMEOUT" "cd /root/acc && $(phase_env) bash phases/30-selinux.sh" || rc=$?;;
    40) run_remote 40-sandbox "$PHASE_TIMEOUT" "cd /root/acc && $(phase_env) bash phases/40-sandbox.sh" || rc=$?;;
    50) run_remote 50-resume "$PHASE_TIMEOUT" "cd /root/acc && $(phase_env) bash phases/50-resume.sh" || rc=$?;;
    60) run_remote 60-reboot-pre "$PHASE_TIMEOUT" "cd /root/acc && $(phase_env) bash phases/60-reboot-pre.sh" || rc=$?
        if [ "$rc" = 0 ]; then
          log "rebooting VM"; vm_ssh 'systemctl reboot' >/dev/null 2>&1 || true; sleep 8
          if vm_wait_ssh 300; then run_remote 60-reboot-post "$PHASE_TIMEOUT" "cd /root/acc && $(phase_env) bash phases/60-reboot-post.sh" || rc=$?
          else P_NUM+=(60); P_NAME+=(reboot-post); P_STATUS+=(NO-SSH); P_SECS+=(300); P_OK+=(0); P_FAIL+=("VM did not come back after reboot"); rc=1; fi
        fi;;
    70) run_remote 70-soak "$PHASE_TIMEOUT" "cd /root/acc && $(phase_env) bash phases/70-soak.sh" || rc=$?;;
    # Phase 80 attacks every feature from tenant code (sections 1-15): longer than the others.
    80) run_remote 80-attacks "$(( PHASE_TIMEOUT * 3 ))" "cd /root/acc && $(phase_env) bash phases/80-attacks.sh" || rc=$?;;
    90) run_remote 90-performance "$PHASE_TIMEOUT" "cd /root/acc && $(phase_env) bash phases/90-performance.sh" || rc=$?;;
    *) die "unknown phase $n";;
  esac
  return $rc
}

# ---------------------------------------------------------------- artifacts + report
collect() {
  vm_ssh true 2>/dev/null || { warn "VM unreachable; skipping artifact collection"; return 0; }
  log "collecting artifacts"
  vm_ssh 'journalctl -u oxpanel-daemon --no-pager -o short-precise' > "$OUT/host/journal-oxpanel-daemon.txt" 2>/dev/null || true
  vm_ssh 'journalctl -u nginx --no-pager -o short-precise' > "$OUT/host/journal-nginx.txt" 2>/dev/null || true
  vm_ssh 'journalctl --list-boots --no-pager; echo; journalctl -p warning --no-pager -o short-precise | tail -300' > "$OUT/host/journal-warnings.txt" 2>/dev/null || true
  vm_ssh 'tar czf - --ignore-failed-read /var/log/audit /var/log/nginx /etc/nginx/oxpanel.d /etc/nginx/conf.d/00-oxpanel.conf /var/lib/oxpanel /etc/oxpanel /usr/lib/systemd/system/oxpanel-daemon.service /etc/systemd/system/oxpanel-daemon.service /root/acc/*.log /root/acc/*.sh /root/acc/*.pre 2>/dev/null' 2>/dev/null | tar xzf - -C "$OUT/host" 2>/dev/null || true
  vm_ssh 'echo "release: $(cat /etc/almalinux-release)"; echo "kernel: $(uname -r)"; echo "selinux: $(getenforce)"; echo "package: $(rpm -q oxpanel-daemon 2>/dev/null || echo "(source install)")"; echo "binary: $(oxpanel-daemon --version 2>/dev/null)"; echo "nginx: $(nginx -v 2>&1)"; echo; systemd-analyze security oxpanel-daemon --no-pager 2>/dev/null | tail -2' > "$OUT/host/system.txt" 2>/dev/null || true
  TESTED_COMMIT="$(vm_ssh 'git -C /root/acc/oxpanel rev-parse HEAD 2>/dev/null || rpm -q --qf "%{VERSION}-%{RELEASE} (rpm)" oxpanel-daemon 2>/dev/null || echo -' 2>/dev/null || echo '-')"
}
report() {
  local total=$(( $(date +%s) - T0 )) i overall="PASS"
  for i in "${!P_STATUS[@]}"; do [ "${P_STATUS[$i]}" = OK ] || overall="FAIL"; done
  [ "$EXIT" = 0 ] || overall="FAIL"
  {
    echo "# OxPanel acceptance — $overall"
    echo
    echo "| | |"; echo "|---|---|"
    echo "| Started | $STARTED |"; echo "| Duration | ${total}s |"
    echo "| Install mode | \`$INSTALL\`$([ "$INSTALL" = git ] && echo " (${GIT_URL:-https://github.com/OxServers/oxpanel.git} @ ${GIT_REF:-main, handbook verbatim})") |"
    echo "| Tested | $TESTED_COMMIT |"
    echo "| Host | $([ -n "$TARGET" ] && echo "TARGET $TARGET" || echo "$VM_DESC") |"
    echo "| Image | $IMAGE_DESC |"
    echo "| Phases requested | $PHASES |"
    echo
    echo "## Phases"; echo
    echo "| # | Phase | Result | Checks passed | Time |"; echo "|---|---|---|---|---|"
    for i in "${!P_STATUS[@]}"; do echo "| ${P_NUM[$i]} | ${P_NAME[$i]} | **${P_STATUS[$i]}** | ${P_OK[$i]} | ${P_SECS[$i]}s |"; done
    echo
    for i in "${!P_STATUS[@]}"; do
      if [ "${P_STATUS[$i]}" != OK ]; then
        echo "## ${P_NUM[$i]} ${P_NAME[$i]}: ${P_STATUS[$i]}"; echo
        [ -n "${P_FAIL[$i]}" ] && { echo "First failure: \`${P_FAIL[$i]}\`"; echo; }
        echo '```'; tail -40 "$OUT/phases/${P_NUM[$i]}-${P_NAME[$i]}.log" 2>/dev/null || true; echo '```'; echo
      fi
    done
    if [ -s "$OUT/host/system.txt" ]; then echo "## System"; echo; echo '```'; cat "$OUT/host/system.txt"; echo '```'; echo; fi
    echo "## Artifacts"; echo
    echo '- `phases/*.log` — full output of every phase'
    echo '- `host/journal-*.txt`, `host/var/log/audit/`, `host/var/log/nginx/` — logs from the VM'
    echo '- `host/etc/nginx/oxpanel.d/`, `host/var/lib/oxpanel/` — generated configuration and records at the end of the run'
    echo '- `console.log` — serial console of the VM; `qemu.log` — hypervisor messages'
    if [ "$KEEP" = 1 ] && [ -z "$TARGET" ]; then
      echo; echo "## VM kept running"; echo
      echo "\`\`\`"; echo "ssh -i dist/acceptance/latest/id_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@127.0.0.1"; echo "curl -H 'Host: <domain>' http://127.0.0.1:8080/"; echo "make acceptance-destroy   # when done"; echo "\`\`\`"
    fi
  } > "$OUT/report.md"
  log "report: $OUT/report.md ($overall)"
}

# ---------------------------------------------------------------- main
log "oxpanel acceptance · install=$INSTALL · phases=[$PHASES] · keep=$KEEP"
if [ -n "$TARGET" ]; then
  SSH_USER="${TARGET%@*}"; SSH_HOST="${TARGET#*@}"; SSH_PORT="$TARGET_PORT"; KEY="$TARGET_KEY"
  for p in $PHASES; do case "$p" in 15|60|70|80|90) [ "$I_UNDERSTAND" = 1 ] || die "phases 15/60/70/80/90 reboot or load $TARGET and create accounts on it; set I_UNDERSTAND=1 to allow";; esac; done
  vm_wait_ssh 30 || die "cannot reach $TARGET"
  log "using $TARGET: $(vm_ssh 'echo "$(cat /etc/almalinux-release 2>/dev/null || uname -o) · $(uname -r) · SELinux $(getenforce 2>/dev/null || echo n/a)"')"
else
  SSH_USER=root; SSH_HOST=127.0.0.1; KEY="$OUT/id_ed25519"
  provision
fi

log "copying test payload"
vm_ssh 'mkdir -p /root/acc/phases /root/acc/rpms'
vm_scp "$HERE"/phases/*.sh /root/acc/phases/
vm_scp "$HERE"/phases/attack /root/acc/phases/
vm_scp "$WORK/tests-integration/run-inside.sh" "$WORK/docs/HANDBOOK.md" /root/acc/
if [ "$INSTALL" = rpm ]; then
  ls "$RPM_DIR"/oxpanel-daemon-*.rpm >/dev/null 2>&1 || die "no RPMs in $RPM_DIR (run make rpm)"
  vm_scp "$RPM_DIR"/oxpanel-daemon-*.rpm /root/acc/rpms/
fi
if [ "$INSTALL" = installer ] || [ "$INSTALL" = upgrade ]; then
  [ -f "$WORK/dist/release/install.sh" ] || die "no dist/release (run make dist)"
  vm_ssh 'mkdir -p /root/acc/release'
  vm_scp "$WORK"/dist/release/. /root/acc/release/
fi
if [ "$INSTALL" = upgrade ]; then
  ls "$WORK"/dist/old-rpms/oxpanel-daemon-[0-9]*.rpm >/dev/null 2>&1 || die "no old RPM in dist/old-rpms (make rpm-old)"
  vm_ssh 'mkdir -p /root/acc/old-rpms'
  vm_scp "$WORK"/dist/old-rpms/oxpanel-daemon-[0-9]*.rpm /root/acc/old-rpms/
fi

for p in $PHASES; do
  if ! run_phase "$p"; then
    EXIT=1
    if [ "$CONTINUE" != 1 ]; then log "stopping after failed phase $p (CONTINUE=1 to run the rest)"; break; fi
  fi
done

collect || true
report
[ "$KEEP" = 1 ] || cleanup_vm
echo "$EXIT" > "$OUT/exit-code"
DONE=1
echo "ACCEPTANCE_DONE exit=$EXIT"
if [ "$KEEP" = 1 ] && [ -n "$QEMU_PID" ]; then
  log "KEEP=1: VM stays up (ssh -p $SSH_PORT root@127.0.0.1 with id_ed25519 from the run directory)"
  wait "$QEMU_PID" || true
fi
exit "$EXIT"
