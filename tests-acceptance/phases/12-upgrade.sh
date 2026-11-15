#!/usr/bin/env bash
# Phase 12 — upgrade (INSTALL=upgrade). Phase 10 installed the old engine by hand:
# 0.2.0 (without email; OLD_REF=v0.2.0, the default) or 0.3.0 (OLD_REF=v0.3.0:
# email is then set up here with 0.3.0's own installer, and the email limits it
# held must come through the upgrade as the 0.3.1 migration says).
# Here: tenants and sites are created with it (static, PHP, Node.js), then the
# release's install.sh upgrades the host. The tenants must survive with the same
# uid and home, the sites must keep answering, and the new features must work on the
# pre-existing tenant.
cd "$(dirname "$0")/.."; source phases/lib.sh
echo "== phase 12: upgrade from the old engine with install.sh"
T=upg1

OLDV=$(rpm -q --qf '%{VERSION}-%{RELEASE}' oxpanel-daemon)
info "installed before the upgrade: $OLDV ($(oxpanel-daemon --version))"
check "the old engine is running" daemon_active

OLD_MAIL=0
case "$OLDV" in 0.3.*) OLD_MAIL=1;; esac
if [ "$OLD_MAIL" = 1 ]; then
  echo "-- the old engine with email (its own installer), and email limits it holds"
  [ -f old-rpms/install.sh ] || fail "no old installer in old-rpms/ (scripts/build-old-rpm.sh copies it)"
  if bash old-rpms/install.sh --only mail --mail --mail-hostname mail.upg.test --enable-epel --yes > old-mail.log 2>&1; then ok "the old installer set email up"; else tail -30 old-mail.log; fail "old install.sh --mail failed"; fi
  eventually "the old engine reports email on" 60 1 bash -c 'oxpanel-ctl mail host | grep -q "^enabled=true "'
  for t in upgd upgv upgu; do check "account $t (old engine)" oxpanel-ctl tenant create $t; done
  # 0.3.0 records: upgd exactly the old defaults, upgv staff's values, upgu
  # unlimited (0 then); upg1 (created below) has none.
  check "upgd: exactly the old defaults (0 0 500 200)" oxpanel-ctl mail limits-set upgd --max-mailboxes 0 --max-mailbox-bytes 0 --per-hour-account 500 --per-hour-mailbox 200
  check "upgv: staff's own values (3 mailboxes, 1000 and 50 an hour)" oxpanel-ctl mail limits-set upgv --max-mailboxes 3 --max-mailbox-bytes 0 --per-hour-account 1000 --per-hour-mailbox 50
  check "upgu: unlimited (0 in 0.3.0)" oxpanel-ctl mail limits-set upgu --max-mailboxes 0 --max-mailbox-bytes 0 --per-hour-account 0 --per-hour-mailbox 0
  check "the old engine has no resolver for the filter (and Unbound is not installed)" bash -c '! rpm -q unbound >/dev/null && ! grep -q "^OXPANEL_MAIL_RESOLVER" /etc/oxpanel/daemon.env'
fi

check "create a tenant with the old engine" oxpanel-ctl tenant create $T --memory 512M --tasks-max 200
check "a static site" oxpanel-ctl vhost set static.upg.test --tenant $T
check "its page" as_user $T sh -c 'echo static-old > /home/upg1/public_html/index.html'
check "a PHP site" oxpanel-ctl vhost set php.upg.test --tenant $T --root phpsite --php
check "its page (PHP)" as_user $T sh -c 'mkdir -p /home/upg1/phpsite && echo "<?php echo \"php-old\";" > /home/upg1/phpsite/index.php'
check "a Node.js site" oxpanel-ctl vhost set app.upg.test --tenant $T --app node
check "its application" as_user $T sh -c 'mkdir -p /home/upg1/apps/app.upg.test && echo "require(\"http\").createServer((q,r)=>r.end(\"node-old\")).listen(process.env.PORT)" > /home/upg1/apps/app.upg.test/app.js'
check "restart the application" oxpanel-ctl vhost restart-app app.upg.test
eventually "static site answers" 20 1 http_body_is static.upg.test / static-old
eventually "PHP site answers" 20 1 http_body_is php.upg.test / php-old
eventually "Node.js site answers" 20 1 http_body_is app.upg.test / node-old

UID_BEFORE=$(oxpanel-ctl tenant get $T | sed -n 's/.* uid=\([0-9]*\).*/\1/p' | head -1)
info "tenant $T uid=$UID_BEFORE"
oxpanel-ctl vhost list --tenant $T > vhosts.before
oxpanel-ctl host reconcile > reconcile.before 2>&1; info "reconcile before: $(head -1 reconcile.before)"
cp -a /var/lib/oxpanel /root/acc/state.before
ls /etc/nginx/oxpanel.d > nginx-files.before
MAILPKGS="postfix dovecot dovecot-pigeonhole rspamd roundcubemail clamav clamd"
mail_pkgs() { rpm -q $MAILPKGS 2>/dev/null | grep -v 'is not installed' | sort; }
mail_pkgs > mail-pkgs.before; info "mail packages before the upgrade: $(tr '\n' ' ' < mail-pkgs.before)"
fw_mail() { command -v firewall-cmd >/dev/null && systemctl -q is-active firewalld || return 0; firewall-cmd --list-services; firewall-cmd --permanent --list-services; firewall-cmd --list-ports; firewall-cmd --permanent --list-ports; }
fw_mail > fw.before

# ---- the upgrade, as the operator would do it
start=$(date +%s)
bash release/install.sh --yes > upgrade.log 2>&1; rc=$?
echo "--- upgrade.log ---"; cat upgrade.log; echo "-------------------"
[ "$rc" = 0 ] || fail "install.sh exited $rc"
ok "install.sh upgraded the host ($(( $(date +%s) - start ))s)"
NEWV=$(rpm -q --qf '%{VERSION}-%{RELEASE}' oxpanel-daemon)
check "the engine package changed ($OLDV -> $NEWV)" test "$OLDV" != "$NEWV"
check "the installer says what it upgraded" bash -c "grep -q 'oxpanel-daemon $OLDV -> $NEWV' upgrade.log"
check "the new engine runs" bash -c 'oxpanel-daemon --version | grep -q "0\.3\."'
eventually "the daemon is active after the upgrade" 30 1 daemon_active
check "the daemon's journal has no errors since the upgrade" bash -c '! journalctl -u oxpanel-daemon --since "-5min" -p err --no-pager | grep -q oxpanel-daemon'

# ---- nothing was lost
check "the tenant is still there with the same uid" bash -c "oxpanel-ctl tenant get $T | grep -q ' uid=$UID_BEFORE '"
check "its home is intact" test -f /home/$T/public_html/index.html
# The new oxpanel-ctl appends fields the old one did not print (dns_zone=);
# every field the old engine reported must be unchanged, line for line.
same_or_extended() { # <before> <after>: each line of after is the line of before, or it followed by more fields
  [ "$(wc -l < "$1")" = "$(wc -l < "$2")" ] || return 1
  paste -d '\n' "$1" "$2" | awk 'NR % 2 == 1 { old = $0; next } $0 != old && index($0, old " ") != 1 { print "changed: " old " -> " $0; bad = 1 } END { exit bad }'
}
oxpanel-ctl vhost list --tenant $T > vhosts.after
check "its sites are all still configured" same_or_extended vhosts.before vhosts.after
check "the Nginx files are the same set" bash -c 'diff <(ls /etc/nginx/oxpanel.d) nginx-files.before'
eventually "static site still answers" 20 1 http_body_is static.upg.test / static-old
eventually "PHP site still answers" 20 1 http_body_is php.upg.test / php-old
eventually "Node.js site still answers" 20 1 http_body_is app.upg.test / node-old
check "the tenant's limits survived" bash -c "oxpanel-ctl tenant get $T | grep -q 'memory_max=536870912'"
oxpanel-ctl host reconcile > reconcile.after 2>&1; rc=$?
info "reconcile after: exit $rc"; cat reconcile.after | head -20
check "host reconcile is clean after the upgrade (the daemon re-rendered what changed)" test "$rc" = 0

# ---- the new engine's features work on the old tenant
check "the DNS server's unit came with the upgrade, not started (DNS hosting is off until configured)" bash -c 'systemctl cat oxpanel-dns.service >/dev/null && ! systemctl -q is-active oxpanel-dns && oxpanel-ctl host info | grep -q "^dns=false"'
[ "$OLD_MAIL" = 1 ] || check "the email units came with the upgrade, not started (email is off until install.sh --mail)" bash -c 'systemctl cat oxpanel-mail-policy.service oxpanel-webmail.service >/dev/null && ! systemctl -q is-active oxpanel-mail-policy && ! systemctl -q is-active oxpanel-webmail'
[ "$OLD_MAIL" = 1 ] || check "the engine answers about email: off" bash -c 'oxpanel-ctl mail host | grep -q "^enabled=false "'
[ "$OLD_MAIL" = 1 ] || check "an email request is refused with mail_unavailable, nothing else" bash -c 'out=$(oxpanel-ctl mail domain-list --tenant '"$T"' 2>&1); echo "$out" | grep -q "mail_unavailable"'
check "the upgrade created the email accounts" bash -c 'getent passwd oxpanel-mail >/dev/null && getent passwd oxpanel-webmail >/dev/null'
[ "$OLD_MAIL" = 1 ] || check "the upgrade did not touch Postfix or Dovecot (no OxPanel configuration while email is off)" bash -c '! grep -qs "Managed by oxpanel-daemon" /etc/postfix/main.cf /etc/dovecot/dovecot.conf && test ! -e /var/lib/oxpanel-mail'
[ "$OLD_MAIL" = 1 ] || check "the upgrade installed no mail package (email stays off until install.sh --mail)" diff <(mail_pkgs) mail-pkgs.before
check "the upgrade opened nothing in the firewall" diff <(fw_mail) fw.before
[ "$OLD_MAIL" = 1 ] || check "no mail port listens (25, 465, 587, 993, 995)" bash -c '! ss -Hltn | grep -E ":(25|465|587|993|995) "'
[ "$OLD_MAIL" = 1 ] || check "no mail jail for login banning" test ! -e /etc/fail2ban/jail.d/50-oxpanel-mail.local
check "PHP sends through OxPanel's sendmail, which hands non-account mail to Postfix unchanged" bash -c 'php -i 2>/dev/null | grep -q "^sendmail_path => /usr/sbin/oxpanel-daemon sendmail -t -i"'
if [ "$OLD_MAIL" = 1 ]; then
  echo "-- email after the upgrade: the limits as the migration says, no resolver until install.sh --mail"
  lim() { oxpanel-ctl mail limits "$1" | head -1; }
  check "the upgrade installed no new mail package (no Unbound)" bash -c '! rpm -q unbound >/dev/null'
  check "the filter's resolver is not set up by the package upgrade" bash -c '! systemctl -q is-active oxpanel-mail-resolver && ! grep -q "^OXPANEL_MAIL_RESOLVER" /etc/oxpanel/daemon.env && oxpanel-ctl mail host | head -1 | grep -q filter_resolver=false'
  check "email is still on" bash -c 'oxpanel-ctl mail host | grep -q "^enabled=true "'
  check "the host default is the new built-in one (30 and 20 an hour)" grep -qx 'defaults: max_mailboxes=unlimited max_mailbox_bytes=unlimited per_hour_account=30 per_hour_mailbox=20' <(oxpanel-ctl mail defaults)
  check "upgd held exactly the old defaults: it follows the host default now" grep -q 'max_mailboxes=unlimited(default) max_mailbox_bytes=unlimited(default) per_hour_account=30(default) per_hour_mailbox=20(default)' <(lim upgd)
  check "upgv keeps staff's values, as an account override" grep -q 'max_mailboxes=3(account) max_mailbox_bytes=unlimited(account) per_hour_account=1000(account) per_hour_mailbox=50(account)' <(lim upgv)
  check "upgu keeps unlimited, now an explicit override" grep -q 'per_hour_account=unlimited(account) per_hour_mailbox=unlimited(account)' <(lim upgu)
  check "$T, without limits of its own, follows the host default" grep -q 'per_hour_account=30(default) per_hour_mailbox=20(default)' <(lim $T)
  check "the policy service has the migrated limits" python3 -c 'import json; a=json.load(open("/var/lib/oxpanel-mail/policy.json"))["accounts"]; assert (a["upgd"]["rate_account"],a["upgd"]["rate_mailbox"],a["upgv"]["rate_account"],a["upgu"]["rate_account"])==(30,20,1000,0), a'
  out="$(bash release/install.sh --yes --mail --mail-hostname mail.upg.test --enable-epel 2>&1)"; rc=$?
  printf '%s\n' "$out" | tail -15
  check "install.sh --mail on the upgraded host succeeds" test "$rc" = 0
  check "it says it installed Unbound for the filter" grep -q 'installed.* unbound' <<<"$out"
  eventually "the filter's resolver runs" 60 1 systemctl -q is-active oxpanel-mail-resolver
  check "the engine reports it" bash -c 'oxpanel-ctl mail host | head -1 | grep -q filter_resolver=true'
  check "the filter asks it" grep -q '127.0.0.1:5335' /etc/rspamd/local.d/options.inc
  check "the limits are unchanged by it" grep -q 'per_hour_account=1000(account)' <(lim upgv)
  for t in upgd upgv upgu; do oxpanel-ctl tenant delete $t --cascade --confirm $t --wait >/dev/null 2>&1 || true; done
fi
check "the new host info shows the databases" bash -c 'oxpanel-ctl host info | grep -q "^database_engine=mariadb available=true"'
check "an SFTP key can be added to the pre-existing tenant" bash -c "ssh-keygen -q -t ed25519 -N '' -f /root/acc/upg.key && oxpanel-ctl sftp add-key $T --key-file /root/acc/upg.key.pub --label upg | grep -q '^changed=true'"
check "a database for it" oxpanel-ctl db create ${T}_shop --tenant $T
check "a backup of it, waited for" bash -c "oxpanel-ctl backup create $T --wait | grep -q 'state=JOB_STATE_SUCCEEDED'"
check "the file manager works on the pre-existing tenant's home" bash -c "printf upgraded-by-file-manager | oxpanel-ctl files write $T public_html/fm.html >/dev/null && curl -s -H 'Host: static.upg.test' http://127.0.0.1/fm.html | grep -qx upgraded-by-file-manager"
check "a file-manager job on it, waited for" bash -c "oxpanel-ctl files compress $T '' site.tar.gz public_html --format tar-gz --wait | grep -q 'state=JOB_STATE_SUCCEEDED'"
check "a database of it goes to the trash and comes back under a new name" bash -c "id=\$(oxpanel-ctl db delete ${T}_shop | sed -n 's/.* trash_id=\([^ ]*\) .*/\1/p') && oxpanel-ctl db trash-list $T | grep -q \"^\$id ${T}_shop \" && oxpanel-ctl db trash-restore $T \"\$id\" ${T}_shop2 >/dev/null && oxpanel-ctl db list --tenant $T | grep -q 'database=${T}_shop2'"
check "a scheduled task for the pre-existing tenant" bash -c "oxpanel-ctl task set $T nightly --node apps/app.upg.test/app.js --schedule 'daily 04:00' | grep -q '^changed=true' && systemctl -q is-enabled oxpanel-task-$T-nightly.timer"
check "the old sites are still fine after those" bash -c 'curl -s -H "Host: static.upg.test" http://127.0.0.1/ | grep -qx static-old'
check "a second run of the installer changes nothing" bash -c 'bash release/install.sh --yes 2>&1 | grep -q "^RESULT: ok changes=0 "'

# ---- clean up what this phase made: the pre-existing tenant goes in one step
check "the upgraded tenant is deleted with everything it has (cascade)" bash -c "oxpanel-ctl tenant delete $T --cascade --confirm $T --wait | grep -q 'kind=JOB_KIND_DELETE_TENANT .* state=JOB_STATE_SUCCEEDED'"
check "nothing of it is left" bash -c "! id $T 2>/dev/null && test ! -e /etc/systemd/system/oxpanel-task-$T-nightly.timer && test ! -e /home/$T && test -z \"\$(ls /etc/nginx/oxpanel.d | grep upg.test)\" && test -z \"\$(oxpanel-ctl backup list $T 2>/dev/null)\""
n=$(avc_count); if [ "$n" = 0 ]; then ok "zero AVC denials"; else avc_dump; fail "$n AVC denial(s)"; fi
phase_end
