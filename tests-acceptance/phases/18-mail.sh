#!/usr/bin/env bash
# Phase 18 — email on the real host: the mail component is installed with
# install.sh --mail (from the release bundle, or the repository's install.sh
# for INSTALL=rpm), then what only an enforcing host can show is checked:
# the SELinux domains and labels of the mail services and the mail in tenant
# homes, a site's PHP-FPM (httpd_t) sending through OxPanel's sendmail, an
# autoresponder (Dovecot → OxPanel's sendmail), webmail behind Nginx — with
# zero AVC denials. Email stays on for the later phases (reboot, attacks,
# performance); phase 20's suite covers the rest of the feature.
cd "$(dirname "$0")/.."; source phases/lib.sh
echo "== phase 18: email"
MC=/root/acc/mail-client.py
HOSTNAME_MAIL=mail.oxacc.test
AVC0=$(avc_count); START_TIME=$(date +%T)

if ! grep -q '^OXPANEL_MAIL=true' /etc/oxpanel/daemon.env 2>/dev/null || ! systemctl -q is-active postfix; then
  INST=/root/acc/release/install.sh; [ -f "$INST" ] || INST=/root/acc/install.sh
  info "installing the mail component with $INST"
  if bash "$INST" --only mail --mail --mail-hostname "$HOSTNAME_MAIL" --enable-epel --yes > /root/acc/install-mail.log 2>&1; then
    ok "install.sh --mail succeeded"
  else
    tail -40 /root/acc/install-mail.log; fail "install.sh --mail failed"
  fi
  bash "$INST" --only firewall --mail --mail-hostname "$HOSTNAME_MAIL" --enable-epel --yes >> /root/acc/install-mail.log 2>&1 || info "firewall stage did not run (no firewalld?)"
fi
HOSTNAME_MAIL="$(sed -n 's/^enabled=true host_name=\([^ ]*\) .*/\1/p' <(oxpanel-ctl mail host))"
check "email is on" test -n "$HOSTNAME_MAIL"
for u in postfix dovecot rspamd oxpanel-mail-policy oxpanel-webmail; do
  eventually "$u is active" 60 0.5 systemctl -q is-active "$u"
done

echo "-- SELinux domains and labels"
ctx_of() { ps -eo label,comm | awk -v c="$1" '$2==c {print $1; exit}'; }
check "Postfix's master runs confined (postfix_master_t)" bash -c "ps -eZ | grep -q 'postfix_master_t.*master'"
check "Dovecot runs confined (dovecot_t)" bash -c "ps -eZ | grep -q 'dovecot_t.*dovecot'"
check "the mail policy service runs in oxpanel_app_t" bash -c "ps -eZ | grep oxpanel_app_t | grep -q oxpanel-daemon"
check "Roundcube's PHP runs in oxpanel_app_t" bash -c "ps -eZ | grep oxpanel_app_t | grep -q php-fpm"
check "the policy service's sockets are labelled for the web server" bash -c "ls -dZ /run/oxpanel-mail /run/oxpanel-mail/sendmail.sock | grep -c httpd_var_run_t | grep -qx 2"
check "autoresponder scripts are Dovecot's state" bash -c "matchpathcon /var/lib/oxpanel-mail/sieve/x.test/a.sieve | grep -q dovecot_var_lib_t"
info "contexts: rspamd=$(ctx_of rspamd) policy=$(ps -eo label,args | grep 'mail-policy' | grep -v grep | awk '{print $1}' | head -1)"

echo "-- a customer with a PHP site, a mailbox and an autoresponder"
for t in acmail1 acmail2; do oxpanel-ctl tenant delete "$t" --cascade --confirm "$t" --wait >/dev/null 2>&1 || true; done
check "create acmail1" oxpanel-ctl tenant create acmail1
check "create acmail2" oxpanel-ctl tenant create acmail2
check "a PHP site for acmail1" oxpanel-ctl vhost set m1.oxacc.test --tenant acmail1 --php
check "a site for acmail2" oxpanel-ctl vhost set m2.oxacc.test --tenant acmail2
check "mail domain m1.oxacc.test" oxpanel-ctl mail domain-set m1.oxacc.test --tenant acmail1
check "mail domain m2.oxacc.test" oxpanel-ctl mail domain-set m2.oxacc.test --tenant acmail2
P1='Amber-Field-2207'; P2='Silver-Coast-6164'
check "mailbox info@m1" bash -c "echo '$P1' | oxpanel-ctl mail mailbox-set info@m1.oxacc.test --tenant acmail1 --password"
check "mailbox info@m2" bash -c "echo '$P2' | oxpanel-ctl mail mailbox-set info@m2.oxacc.test --tenant acmail2 --password"
check "the mailbox directory belongs to the account, private" test "$(stat -c '%U %a' /home/acmail1/mail/m1.oxacc.test/info)" = "acmail1 700"
check "delivery on port 25" python3 "$MC" deliver 25 a@remote.example info@m1.oxacc.test --subject acc-in
eventually "IMAPS reads it" 40 0.5 python3 "$MC" imap-find info@m1.oxacc.test "$P1" acc-in
check "delivered files belong to the account" bash -c "test -z \"\$(find /home/acmail1/mail -type f ! -user acmail1)\""
check "submission sends to the other customer" python3 "$MC" submit 587 info@m1.oxacc.test "$P1" info@m1.oxacc.test info@m2.oxacc.test --subject acc-sub
eventually "it arrives, DKIM-signed" 40 0.5 python3 "$MC" imap-find info@m2.oxacc.test "$P2" acc-sub --out /root/acc/acc-sub.eml
PUB="$(oxpanel-ctl mail domain-show m1.oxacc.test --tenant acmail1 | sed -n 's/.*record=v=DKIM1; k=rsa; p=//p')"
check "the DKIM signature verifies" python3 "$MC" dkim-verify /root/acc/acc-sub.eml "$PUB"

# A PHP page of the site calls mail(): PHP-FPM runs in httpd_t; OxPanel's
# sendmail talks to the policy service (oxpanel_app_t) over its socket.
as_user acmail1 sh -c "cat > /home/acmail1/public_html/mail.php" <<'PHP'
<?php
$ok = mail('info@m2.oxacc.test', 'acc-site-'.($_GET['n'] ?? '0'), 'from a PHP site', 'From: wordpress@m1.oxacc.test');
echo $ok ? 'sent' : 'refused';
PHP
eventually "the PHP site answers" 50 0.2 bash -c "curl -s -H 'Host: m1.oxacc.test' 'http://127.0.0.1/mail.php?n=1' | grep -q sent"
eventually "the site's message arrives" 40 0.5 python3 "$MC" imap-find info@m2.oxacc.test "$P2" acc-site-1 --out /root/acc/acc-site.eml
check "it is DKIM-signed by the site's domain" python3 "$MC" dkim-verify /root/acc/acc-site.eml "$PUB"
as_user acmail1 sh -c "cat > /home/acmail1/public_html/spoof.php" <<'PHP'
<?php echo mail('info@m2.oxacc.test', 'acc-spoof', 'x', 'From: ceo@m2.oxacc.test') ? 'sent' : 'refused';
PHP
check "the site cannot send as the other customer" bash -c "curl -s -H 'Host: m1.oxacc.test' http://127.0.0.1/spoof.php | grep -q refused"

check "an autoresponder for info@m1" oxpanel-ctl mail autoreply info@m1.oxacc.test --tenant acmail1 --subject acc-away --body 'Away until Monday.'
check "a message to it" python3 "$MC" submit 587 info@m2.oxacc.test "$P2" info@m2.oxacc.test info@m1.oxacc.test --subject acc-needs-reply
eventually "the reply arrives (Dovecot → OxPanel's sendmail → Postfix)" 60 0.5 python3 "$MC" imap-find info@m2.oxacc.test "$P2" acc-away

echo "-- webmail behind Nginx"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=webmail.m1.oxacc.test -addext subjectAltName=DNS:webmail.m1.oxacc.test \
  -keyout /etc/pki/oxpanel-mail/webmail.m1.oxacc.test.key -out /etc/pki/oxpanel-mail/webmail.m1.oxacc.test.crt >/dev/null 2>&1
chmod 600 /etc/pki/oxpanel-mail/webmail.m1.oxacc.test.key
restorecon -R /etc/pki/oxpanel-mail
oxpanel-ctl mail domain-set m1.oxacc.test --tenant acmail1 >/dev/null
W=(curl -sk --resolve webmail.m1.oxacc.test:443:127.0.0.1 -b /root/acc/wm.cj -c /root/acc/wm.cj); rm -f /root/acc/wm.cj
eventually "the login page is served over HTTPS" 40 0.5 bash -c "curl -sk --resolve webmail.m1.oxacc.test:443:127.0.0.1 https://webmail.m1.oxacc.test/ | grep -q rcmloginuser"
page="$("${W[@]}" https://webmail.m1.oxacc.test/)"
tok="$(grep -o 'name="_token" value="[^"]*"' <<<"$page" | head -1 | sed 's/.*value="//; s/"$//')"
"${W[@]}" -o /dev/null -d "_token=$tok&_task=login&_action=login&_timezone=UTC&_url=&_user=info@m1.oxacc.test&_pass=$P1" 'https://webmail.m1.oxacc.test/?_task=login'
check "a webmail login succeeds under enforcing" bash -c "curl -sk --resolve webmail.m1.oxacc.test:443:127.0.0.1 -b /root/acc/wm.cj 'https://webmail.m1.oxacc.test/?_task=mail&_mbox=INBOX' | grep -q Inbox"

echo "-- clean up (email stays on)"
check "delete acmail1 with everything" bash -c "oxpanel-ctl tenant delete acmail1 --cascade --confirm acmail1 --wait >/dev/null"
check "delete acmail2 with everything" bash -c "oxpanel-ctl tenant delete acmail2 --cascade --confirm acmail2 --wait >/dev/null"
check "no mail drift" bash -c '! oxpanel-ctl host reconcile | grep -q MAIL'

AVC1=$(avc_count)
if [ "$AVC1" = "$AVC0" ]; then ok "zero AVC denials during the email phase"; else
  ausearch --input-logs -m avc -ts "$START_TIME" -i 2>/dev/null | grep '^type=AVC' | tail -40
  fail "$((AVC1 - AVC0)) AVC denial(s) during the email phase (listed above)"
fi
check "daemon journal has no errors" bash -c '! journalctl -b -u oxpanel-daemon -p err --no-pager | grep -q oxpanel-daemon'
phase_end
