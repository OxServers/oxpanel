#!/usr/bin/env bash
# Phase 16 — login banning (installer mode). The installer set fail2ban up in
# phase 10; here a tenant's SFTP password is guessed from one address of a network
# namespace and that address must get banned, a correct login from another address
# must keep working, an address on the ignore list must never be banned, and none of
# it may cost an AVC denial. The namespace is connected by a veth pair, so the
# traffic is not loopback traffic and the firewall's ban rule really applies.
cd "$(dirname "$0")/.."; source phases/lib.sh
echo "== phase 16: fail2ban (SSH/SFTP password guessing)"
BAD=10.99.0.2; GOOD=10.99.0.3; HOST=10.99.0.1
PW="correct-horse-battery-1"

cleanup() {
  ip netns del atk >/dev/null 2>&1 || true
  ip link del vatk0 >/dev/null 2>&1 || true
  oxpanel-ctl tenant delete f2btenant --remove-home >/dev/null 2>&1 || true
  rm -f /root/acc/askpass-good.sh /root/acc/askpass-bad.sh
}
trap cleanup EXIT

check "fail2ban is active" systemctl -q is-active fail2ban
check "the jail file is the one the installer wrote" test -f /etc/fail2ban/jail.d/50-oxpanel-sshd.local
check "the jail reads the journal, not a log file" bash -c 'fail2ban-client get sshd journalmatch | grep -q sshd.service'
check "the jail watches the SSH port" bash -c 'grep -Eq "^port += +22\$" /etc/fail2ban/jail.d/50-oxpanel-sshd.local'
SESSION_IP=""
for pid in $$ $PPID; do
  v=$(tr '\0' '\n' </proc/$pid/environ 2>/dev/null | sed -n 's/^SSH_CONNECTION=//p' | head -1 | cut -d' ' -f1); [ -n "$v" ] && SESSION_IP=$v
done
info "this session comes from: ${SESSION_IP:-unknown}"
[ -n "$SESSION_IP" ] && check "the operator's session address is on the ignore list" bash -c "fail2ban-client get sshd ignoreip | grep -q '$SESSION_IP'"
check "loopback is on the ignore list" bash -c 'fail2ban-client get sshd ignoreip | grep -q "127.0.0.0/8"'
check "fail2ban runs in its own SELinux domain" bash -c 'ps -eZ | grep -q "fail2ban_t.*fail2ban-server"'
check "the ban action is firewalld's (firewalld is running)" bash -c 'fail2ban-client get sshd actions | grep -q firewallcmd'

# A tenant with an SFTP password.
check "create a tenant for the test" oxpanel-ctl tenant create f2btenant
printf '%s\n' "$PW" > /root/acc/f2b.pw; chmod 600 /root/acc/f2b.pw
check "give it an SFTP password" bash -c 'oxpanel-ctl sftp set-password f2btenant < /root/acc/f2b.pw | grep -q "^password=set"'
rm -f /root/acc/f2b.pw

# Two addresses on the far side of a veth pair.
check "create the attacker namespace" bash -c '
  ip netns add atk && ip link add vatk0 type veth peer name vatk1 && ip link set vatk1 netns atk &&
  ip addr add '$HOST'/24 dev vatk0 && ip link set vatk0 up &&
  ip netns exec atk ip link set lo up && ip netns exec atk ip addr add '$BAD'/24 dev vatk1 &&
  ip netns exec atk ip addr add '$GOOD'/24 dev vatk1 && ip netns exec atk ip link set vatk1 up'
printf '#!/bin/sh\necho "%s"\n' "$PW" > /root/acc/askpass-good.sh
printf '#!/bin/sh\necho "wrong-password-guess"\n' > /root/acc/askpass-bad.sh
chmod 700 /root/acc/askpass-good.sh /root/acc/askpass-bad.sh

# sftp_from <source address> <good|bad> [timeout]  → exit status of an sftp "ls" as the tenant
sftp_from() {
  SSH_ASKPASS="/root/acc/askpass-$2.sh" SSH_ASKPASS_REQUIRE=force DISPLAY=none \
    ip netns exec atk timeout 25 sftp -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout="${3:-6}" \
      -o BindAddress="$1" f2btenant@"$HOST" <<<"ls"
}
banned() { fail2ban-client get sshd banip 2>/dev/null | tr ', ' '\n\n' | grep -qx "$1"; }

eventually "the tenant can log in with the right password from $GOOD" 5 2 sftp_from "$GOOD" good
check_not "a wrong password is refused" sftp_from "$BAD" bad
n0=$(journalctl -u sshd --since '-2min' --no-pager | grep -c "Failed password for f2btenant from $BAD" || true)
check "sshd logged the failure to the journal (the jail's source)" test "$n0" -ge 1

# Guess until the jail acts.
for i in $(seq 1 12); do
  banned "$BAD" && break
  sftp_from "$BAD" bad 4 >/dev/null 2>&1 || true; sleep 2
done
check "the guessing address $BAD got banned" banned "$BAD"
info "$(fail2ban-client status sshd | tr '\n' ' ')"
check "the ban is a real firewall rule" bash -c "firewall-cmd --list-rich-rules | grep -q '$BAD'"
check_not "the banned address cannot connect even with the right password" sftp_from "$BAD" good 4
check "another address ($GOOD) is not banned" bash -c "! fail2ban-client get sshd banip | tr ', ' '\n\n' | grep -qx $GOOD"
eventually "the correct login from $GOOD still works" 10 6 sftp_from "$GOOD" good

# The operator's own address can be protected: the installer takes --ignore-ip.
n=$(bash release/install.sh --yes --quota --no-reboot --fail2ban --enable-epel --ignore-ip "$GOOD" > install-ignore.log 2>&1; echo $?)
tail -12 install-ignore.log
check "install.sh --ignore-ip succeeded" test "$n" = 0
check "it changed exactly the jail configuration" bash -c 'grep -q "wrote /etc/fail2ban/jail.d/50-oxpanel-sshd.local" install-ignore.log'
check "the address is on the ignore list now" bash -c "fail2ban-client get sshd ignoreip | grep -q '$GOOD'"
check "and the same options again change nothing" bash -c 'bash release/install.sh --yes --quota --no-reboot --fail2ban --enable-epel --ignore-ip '$GOOD' 2>&1 | grep -q "^RESULT: ok changes=0 "'
for i in $(seq 1 6); do sftp_from "$GOOD" bad 4 >/dev/null 2>&1 || true; sleep 1; done
sleep 3
check "$GOOD failed six times and is NOT banned (ignore list)" bash -c "! fail2ban-client get sshd banip | tr ', ' '\n\n' | grep -qx $GOOD"
eventually "its correct login still works (sshd's own short penalty for the failures may delay it)" 12 6 sftp_from "$GOOD" good

# Lifting a ban, as documented.
check "unban $BAD by hand" fail2ban-client set sshd unbanip "$BAD"
eventually "the correct login from $BAD works again" 5 3 sftp_from "$BAD" good

n=$(avc_count); if [ "$n" = 0 ]; then ok "zero AVC denials (fail2ban, firewalld, sshd)"; else avc_dump; fail "$n AVC denial(s)"; fi
phase_end
