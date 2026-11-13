#!/usr/bin/env bash
# Phase 17 — installer options that the main run does not use (installer mode):
# the answers file, the panel account hook, and the /etc/fstab variant of the disk
# quota change (on a loopback XFS image that stands in for a separate /home).
cd "$(dirname "$0")/.."; source phases/lib.sh
echo "== phase 17: installer options"
INST="bash release/install.sh --yes"
ENVF=/etc/oxpanel/daemon.env

cleanup() {
  userdel panelapi >/dev/null 2>&1 || true
  sed -i '/^# BEGIN oxpanel-installer/,/^# END oxpanel-installer/d' $ENVF
  umount /mnt/xt >/dev/null 2>&1 || true
  [ -f /root/acc/fstab.keep ] && cp -p /root/acc/fstab.keep /etc/fstab
  systemctl daemon-reload; systemctl restart oxpanel-daemon; rm -f /var/xt.img /etc/fstab.oxpanel-installer.bak
}
trap cleanup EXIT

# --- answers file
printf '# answers\nfail2ban = yes\nepel=yes\nquota=no\nreboot=no\n' > answers.txt
$INST --answers answers.txt --only verify > opt-answers.log 2>&1; rc=$?
check "an answers file is accepted" test "$rc" = 0
check "its answers are the decisions taken" bash -c 'grep -q "^decisions: fail2ban=yes epel=yes quota=no reboot=no" opt-answers.log'
printf 'bogus=1\n' > bad.txt
check_not "an unknown key in the answers file is refused" bash -c "$INST --answers bad.txt --only verify"
check_not "an unknown option is refused" bash -c "$INST --no-such-option"
check "a flag wins over the answers file" bash -c "$INST --answers answers.txt --no-fail2ban --only verify 2>&1 | grep -q '^decisions: fail2ban=no'"

# --- the panel hook (without a panel package)
check_not "a package that is not a panel is refused as --panel-rpm" bash -c "$INST --panel-rpm release/oxpanel-daemon-*.rpm --only panel"
check "--panel-account creates panelapi in group oxpanel" bash -c "$INST --panel-account --only panel > opt-panel.log 2>&1 && id -nG panelapi | tr ' ' '\n' | grep -qx oxpanel"
check "a second run changes nothing" bash -c "$INST --panel-account --only panel 2>&1 | grep -q '^RESULT: ok changes=0 '"
check "panelapi can use the engine socket (membership decides)" runuser -u panelapi -- oxpanel-ctl tenant list
check "panelapi may create a tenant by default (all scopes)" bash -c 'runuser -u panelapi -- oxpanel-ctl tenant create scopechk >/dev/null && oxpanel-ctl tenant delete scopechk --remove-home >/dev/null'
check "--panel-scopes writes the peer scope for panelapi" bash -c "$INST --panel-account --panel-scopes read+vhost --only panel > opt-scopes.log 2>&1 && grep -qx \"OXPANEL_PEER_SCOPES=\$(id -u panelapi):read+vhost\" $ENVF"
eventually "the daemon restarted with it" 30 1 daemon_active
check_not "panelapi is now refused creating a tenant (scope read+vhost)" runuser -u panelapi -- oxpanel-ctl tenant create scopechk2
check "but can still read" runuser -u panelapi -- oxpanel-ctl tenant list
check "the scope line is kept by a run that does not mention it" bash -c "$INST --only engine >/dev/null 2>&1; grep -qx \"OXPANEL_PEER_SCOPES=\$(id -u panelapi):read+vhost\" $ENVF"
check_not "a bad scope is refused" bash -c "$INST --panel-account --panel-scopes everything --only panel"

# --- fstab variant: a separate XFS file system holding the homes
cp -p /etc/fstab /root/acc/fstab.keep
truncate -s 300M /var/xt.img && mkfs.xfs -q /var/xt.img && mkdir -p /mnt/xt
echo '/var/xt.img /mnt/xt xfs loop 0 0' >> /etc/fstab
systemctl daemon-reload
check "mount the stand-in /home file system" mount /mnt/xt
check "it is XFS without quotas" bash -c 'findmnt -no FSTYPE,OPTIONS /mnt/xt | grep -q "^xfs" && ! findmnt -no OPTIONS /mnt/xt | grep -q usrquota'
$INST --quota --no-reboot --home-base /mnt/xt --only quota > opt-fstab.log 2>&1; rc=$?
cat opt-fstab.log | tail -12
check "install.sh --home-base finished" test "$rc" = 0
check "the fstab line gained uquota" bash -c 'grep -E "^/var/xt.img /mnt/xt xfs loop,uquota " /etc/fstab'
check "the other fstab lines are unchanged" bash -c 'diff <(grep -v xt.img /etc/fstab) <(grep -v xt.img /root/acc/fstab.keep)'
check "a copy of the original was kept" test -f /etc/fstab.oxpanel-installer.bak
check "it says a reboot (or remount) is needed" bash -c 'grep -q "reboot_required=yes" opt-fstab.log && grep -q "umount /mnt/xt" opt-fstab.log'
check "the grub arguments were NOT touched for this" bash -c '! grep -q "rootflags=uquota.*xt" opt-fstab.log'
$INST --quota --no-reboot --home-base /mnt/xt --only quota 2>&1 | tail -3
check "a second run does not edit fstab again" bash -c "$INST --quota --no-reboot --home-base /mnt/xt --only quota 2>&1 | grep -q 'already has the quota option'"
check "the fstab line has uquota exactly once" bash -c '[ "$(grep -o uquota /etc/fstab | wc -l)" = 1 ]'
check "remounting picks the quota up (what the installer told the operator)" bash -c 'umount /mnt/xt && mount /mnt/xt && findmnt -no OPTIONS /mnt/xt | tr , "\n" | grep -qx usrquota'
check "then the installer reports quotas active on it" bash -c "$INST --quota --home-base /mnt/xt --only quota 2>&1 | grep -q 'user quotas are active on /mnt/xt'"
n=$(avc_count); if [ "$n" = 0 ]; then ok "zero AVC denials"; else avc_dump; fail "$n AVC denial(s)"; fi
phase_end
