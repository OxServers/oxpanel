#!/usr/bin/env bash
# Phase 15 (before reboot) — prepare the host for disk quotas exactly as the
# handbook says (§9.1), so the integration suite (phase 20) exercises them.
cd "$(dirname "$0")/.."; source phases/lib.sh
echo "== phase 15: disk-quota host preparation (handbook §9.1)"
handbook_block() { awk -v h="$1" 'index($0,h)==1{f=1;next} f&&/^```sh/{c=1;next} f&&c&&/^```/{exit} f&&c{print}' HANDBOOK.md; }
info "before: $(findmnt -no SOURCE,FSTYPE,OPTIONS -T /home)"
check "the daemon reports quotas unavailable before the preparation" bash -c 'oxpanel-ctl host info | grep -q " disk_quota=false "'
if [ "${INSTALL:-}" = installer ]; then
  # The installer (phase 10, --quota) has already made the change; it must not need this phase's help.
  info "installer mode: the boot change was made by install.sh in phase 10"
  check "install.sh printed exactly what remains" bash -c 'grep -q "What remains: a reboot" install-1.log && grep -q "install.sh --yes --quota" install-1.log'
else
  handbook_block "### 9.1 " > quota-prep.sh
  [ -s quota-prep.sh ] || fail "could not extract the §9.1 block from HANDBOOK.md"
  echo "--- quota-prep.sh ---"; cat quota-prep.sh; echo "---------------------"
  if bash -e quota-prep.sh > quota-prep.log 2>&1; then ok "handbook §9.1 block ran clean"; else cat quota-prep.log; fail "handbook §9.1 block failed"; fi
fi
check "the kernel argument is in the boot entries" bash -c 'grubby --info=DEFAULT | grep -q "rootflags=uquota"'
cat /proc/sys/kernel/random/boot_id > quota-boot_id.pre
info "rebooting to mount / with user quotas"
phase_end
