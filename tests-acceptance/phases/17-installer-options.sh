#!/usr/bin/env bash
# Phase 17 — installer options that the main run does not use (installer mode):
# the answers file, the panel account hook, DNS hosting, email, and the /etc/fstab variant of the disk
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
  systemctl stop oxpanel-dns >/dev/null 2>&1 || true
  systemctl disable --now exim.service >/dev/null 2>&1; rm -f /etc/systemd/system/exim.service
  rm -f /etc/fail2ban/jail.d/50-oxpanel-mail.local; systemctl -q is-active fail2ban && systemctl reload fail2ban >/dev/null 2>&1
  for s in smtp smtps smtp-submission imaps pop3s; do firewall-cmd -q --remove-service=$s 2>/dev/null; firewall-cmd -q --permanent --remove-service=$s 2>/dev/null; done
  systemctl daemon-reload
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
check_not "an unknown stage in --only is refused (a typo never runs nothing quietly)" bash -c "$INST --only dns,firewal"
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

# --- DNS hosting
DNSF="--dns-nameservers ns1.inst.example,ns2.inst.example --dns-contact hostmaster@inst.example --dns-ipv4 192.0.2.53"
check_not "--dns without its settings is refused" bash -c "$INST --dns --only dns"
check "and nothing was written" bash -c "! grep -q '^OXPANEL_DNS' $ENVF"
systemctl enable named >/dev/null 2>&1
check_not "an enabled stock named.service stops the run (it may serve real zones)" bash -c "$INST --dns $DNSF --only dns"
check "it was left alone, and nothing was written" bash -c "systemctl -q is-enabled named && ! grep -q '^OXPANEL_DNS' $ENVF"
$INST --dns $DNSF --disable-stock-named --only dns > opt-dns.log 2>&1; rc=$?
tail -8 opt-dns.log
check "--dns with its settings and --disable-stock-named" test "$rc" = 0
check "the stock named is stopped and disabled" bash -c '! systemctl -q is-enabled named && ! systemctl -q is-active named'
check "the DNS lines are in the installer's block" bash -c "grep -qx OXPANEL_DNS=true $ENVF && grep -qx OXPANEL_DNS_NAMESERVERS=ns1.inst.example,ns2.inst.example $ENVF"
check "oxpanel-dns runs" systemctl -q is-active oxpanel-dns
check "it answers, authoritatively only (a name it does not host is refused, not resolved)" bash -c 'dig +norec +time=2 @127.0.0.1 example.org A | grep -q "status: REFUSED"'
check "the engine reports DNS hosting available" bash -c 'oxpanel-ctl host info | grep -q "^dns=true .*dns_available=true"'
check "a second run changes nothing" bash -c "$INST --dns $DNSF --only dns 2>&1 | grep -q '^RESULT: ok changes=0 '"
check "the DNS address is also the public address (0.3.2)" bash -c "grep -qx OXPANEL_PUBLIC_IPV4=192.0.2.53 $ENVF && oxpanel-ctl host info | grep -qx 'public_ipv4=192.0.2.53 public_ipv6=-'"
check_not "a loopback public address is refused" bash -c "$INST --public-ipv4 127.0.0.1 --only daemon"
check "--public-ipv4 with --only daemon sets it and restarts the engine" bash -c "$INST --public-ipv4 198.51.100.7 --only daemon >/dev/null 2>&1 && grep -qx OXPANEL_PUBLIC_IPV4=198.51.100.7 $ENVF && oxpanel-ctl host info | grep -q '^public_ipv4=198.51.100.7 '"
check "a run that does not mention it keeps it" bash -c "$INST --only daemon 2>&1 | grep -q '^RESULT: ok changes=0 ' && grep -qx OXPANEL_PUBLIC_IPV4=198.51.100.7 $ENVF"
check "--only dns,firewall (the handbook's command) opens 53 for it" bash -c "$INST --dns $DNSF --only dns,firewall 2>&1 | grep -q '^\[firewall\]' && firewall-cmd -q --query-service=dns"
check "a run that does not mention DNS keeps it" bash -c "$INST --only engine >/dev/null 2>&1; grep -qx OXPANEL_DNS=true $ENVF"
check "--no-dns takes the lines out" bash -c "$INST --no-dns --only dns >/dev/null 2>&1; ! grep -q '^OXPANEL_DNS' $ENVF"
firewall-cmd -q --remove-service=dns; firewall-cmd -q --permanent --remove-service=dns

# --- email
MAILF="--mail --mail-hostname mail.inst.example --enable-epel"
check_not "--mail with a bad host name is refused" bash -c "$INST --mail --mail-hostname 'Not A Name' --enable-epel --only mail"
check "and nothing was written" bash -c "! grep -q '^OXPANEL_MAIL' $ENVF"
printf '[Unit]\nDescription=stand-in for another MTA\n[Service]\nExecStart=/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/exim.service
systemctl daemon-reload; systemctl enable exim.service >/dev/null 2>&1
check_not "an enabled other mail server (exim) stops the run" bash -c "$INST $MAILF --only mail"
check "it was left alone, and nothing was written" bash -c "systemctl -q is-enabled exim && ! grep -q '^OXPANEL_MAIL' $ENVF"
systemctl disable exim.service >/dev/null 2>&1; rm -f /etc/systemd/system/exim.service; systemctl daemon-reload
$INST $MAILF --only mail > opt-mail.log 2>&1; rc=$?
tail -12 opt-mail.log
check "--mail with a host name" test "$rc" = 0
check "the email lines are in the installer's block" bash -c "grep -qx OXPANEL_MAIL=true $ENVF && grep -qx OXPANEL_MAIL_HOSTNAME=mail.inst.example $ENVF && grep -qx OXPANEL_MAIL_WEBMAIL=true $ENVF && grep -qx OXPANEL_MAIL_ANTIVIRUS=false $ENVF"
check "rspamd's repository is used over HTTPS with signed packages and metadata" bash -c 'grep -qx "baseurl=https://rspamd.com/rpm-stable/centos-9/\$basearch" /etc/yum.repos.d/rspamd.repo && grep -qx gpgcheck=1 /etc/yum.repos.d/rspamd.repo && grep -qx repo_gpgcheck=1 /etc/yum.repos.d/rspamd.repo && grep -qx "gpgkey=https://rspamd.com/rpm/rspamd.asc" /etc/yum.repos.d/rspamd.repo'
check "the mail packages are installed" rpm -q postfix dovecot dovecot-pigeonhole rspamd roundcubemail php-pdo
check "ClamAV is not (off by default)" bash -c '! rpm -q clamd'
check "the _rspamd account exists" getent passwd _rspamd
check "Roundcube is not served from Nginx's default server" bash -c '! grep -q location /etc/nginx/default.d/roundcubemail.conf'
for u in postfix dovecot rspamd oxpanel-mail-policy oxpanel-webmail; do check "$u runs" systemctl -q is-active $u; done
check "the engine reports email on with that host name" bash -c 'oxpanel-ctl mail host | grep -q "^enabled=true host_name=mail.inst.example "'
check "OxPanel took over Postfix and kept the original" bash -c 'head -1 /etc/postfix/main.cf | grep -q "Managed by oxpanel-daemon" && test -s /etc/postfix/main.cf.oxpanel-orig'
check "a second run changes nothing" bash -c "$INST $MAILF --only mail 2>&1 | grep -q '^RESULT: ok changes=0 '"
check "--only mail,firewall (the handbook's command) opens the mail ports" bash -c "$INST $MAILF --only mail,firewall >/dev/null 2>&1 && for s in smtp smtps smtp-submission imaps pop3s; do firewall-cmd -q --query-service=\$s && firewall-cmd -q --permanent --query-service=\$s || exit 1; done"
check "with login banning, the mail jails run" bash -c "$INST $MAILF --fail2ban --only fail2ban >/dev/null 2>&1 && fail2ban-client status dovecot >/dev/null && fail2ban-client status postfix-sasl >/dev/null && fail2ban-client status oxpanel-webmail >/dev/null"
check "the mail jails never ban the loopback (webmail logs in from there)" bash -c 'grep -q "^ignoreip  = 127.0.0.1/8 ::1" /etc/fail2ban/jail.d/50-oxpanel-mail.local'
check "a run that does not mention email keeps it" bash -c "$INST --only engine >/dev/null 2>&1; grep -qx OXPANEL_MAIL=true $ENVF"
check "verification checks email too" bash -c "out=\$($INST --only verify 2>&1); grep -q 'mail host: enabled=true' <<<\"\$out\" || { tail -8 <<<\"\$out\"; systemctl --no-pager status oxpanel-mail-resolver | head -5; exit 1; }"
check "--no-mail takes the lines out and stops OxPanel's mail services" bash -c "$INST --no-mail --only mail >/dev/null 2>&1; ! grep -q '^OXPANEL_MAIL' $ENVF && ! systemctl -q is-active oxpanel-mail-policy && ! systemctl -q is-active oxpanel-webmail"
check "the engine reports email off again" bash -c 'oxpanel-ctl mail host | grep -q "^enabled=false "'

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
