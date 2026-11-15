# Phase 80, section 16: email, attacked by a hostile customer (attack3) and
# from the network. Sourced by 80-attacks.sh after the feature sections
# (helpers: ctl, check, check_not, eventually, as_user, run_ok, eval_lines,
# feat_everywhere, FT, AT3; DNS hosting is on for the phase).
#
# The victim (victim1) gets a mail domain with a mailbox holding a secret
# message, a forwarder and an autoresponder. The attacker gets its own mail
# domain and mailbox. Then: open relay, sender spoofing (across customers
# and across mailboxes), reading the victim's mail (IMAP, LMTP, the file
# system, the file manager, webmail, doveadm), injection in every field,
# symlinks in ~/mail (delivery, backup, deletion), forwarder loops and
# amplification, rate-limit bypass, password guessing, claiming the victim's
# domain, autoresponder abuse (backscatter, loops), webmail as a pivot.
# shellcheck shell=bash

MCL=/root/acc/mail-client.py
VPW='Victim-Mail-Pass-4471'; APW='Attack-Mail-Pass-8813'

features_mail() {
  echo "-- 16. email"
  if ! oxpanel-ctl mail host 2>/dev/null | grep -q '^enabled=true'; then info "email is not on: section 16 skipped"; return; fi
  local VD=vphp.test AD=fphp.test out n before
  # Setup.
  check "victim: mail domain $VD" run_ok ctl mail domain-set "$VD" --tenant victim1
  check "victim: mailbox info@$VD" bash -c "echo '$VPW' | oxpanel-ctl mail mailbox-set info@$VD --tenant victim1 --password >/dev/null"
  check "victim: mailbox sales@$VD" bash -c "echo '$VPW' | oxpanel-ctl mail mailbox-set sales@$VD --tenant victim1 --password >/dev/null"
  check "victim: a secret message" python3 "$MCL" deliver 25 bank@remote.example "info@$VD" --subject VICTIM-SECRET-MAIL
  eventually "victim: the secret message is in the mailbox" 40 0.5 python3 "$MCL" imap-find "info@$VD" "$VPW" VICTIM-SECRET-MAIL
  check "attacker: mail domain $AD" run_ok ctl mail domain-set "$AD" --tenant attack3
  check "attacker: mailbox shop@$AD" bash -c "echo '$APW' | oxpanel-ctl mail mailbox-set shop@$AD --tenant attack3 --password >/dev/null"
  check "attacker: generous limits for the controls" run_ok ctl mail limits-set attack3 --max-mailboxes unlimited --max-mailbox-bytes unlimited --per-hour-account 1000 --per-hour-mailbox 1000

  echo "-- 16a. from the attacker's code (PHP, Python, scheduled task)"
  feat_everywhere mail 30 mail /home/victim1 "$VD" "$AD" /usr/libexec/oxpanel/sendmail

  echo "-- 16b. claiming the victim's names"
  check "the victim's domain cannot become the attacker's mail domain" bash -c "oxpanel-ctl mail domain-set $VD --tenant attack3 2>&1 | grep -q mail_domain_not_owned"
  check "nor a name below it" bash -c "oxpanel-ctl mail domain-set sub.$VD --tenant attack3 2>&1 | grep -q mail_domain_not_owned"
  check "the victim's webmail name cannot be the attacker's site" bash -c "oxpanel-ctl vhost set webmail.$VD --tenant attack3 2>&1 | grep -qi 'owned by'"
  check "nor its autoconfiguration name" bash -c "oxpanel-ctl vhost set autoconfig.$VD --tenant attack3 2>&1 | grep -qi 'owned by'"
  check "the attacker cannot add mailboxes to the victim's domain" bash -c "echo '$APW' | oxpanel-ctl mail mailbox-set evil@$VD --tenant attack3 --password 2>&1 | grep -q mail_domain_not_found"
  check "nor forwarders" bash -c "oxpanel-ctl mail forwarder-set evil@$VD --tenant attack3 --to x@relay.example 2>&1 | grep -q mail_domain_not_found"
  check "nor read the victim's mailboxes through the API" bash -c "oxpanel-ctl mail mailbox-list $VD --tenant attack3 2>&1 | grep -q mail_domain_not_found"
  check "nor the victim's autoresponder" bash -c "oxpanel-ctl mail autoreply-show info@$VD --tenant attack3 2>&1 | grep -q mail_domain_not_found"

  echo "-- 16c. relaying and spoofing from the network"
  check "port 25 relays nothing" bash -c "python3 $MCL deliver 25 x@relay.example victim@relay2.example | grep -q 'Relay access denied'"
  check "port 25 relays nothing on the host's own address either" bash -c "python3 $MCL deliver 25 x@relay.example victim@relay2.example --host \$(hostname -I | awk '{print \$1}') | grep -q 'Relay access denied'"
  check "a mailbox cannot send as the victim (envelope)" bash -c "python3 $MCL submit 587 shop@$AD '$APW' info@$VD info@$VD | grep -q 'not owned by user'"
  check "a mailbox cannot send as the victim (From:)" bash -c "python3 $MCL submit 587 shop@$AD '$APW' shop@$AD info@$VD --from-header info@$VD | grep -q 'own address'"
  check "a mailbox cannot send as another mailbox of the same customer" bash -c "python3 $MCL submit 587 sales@$VD '$VPW' info@$VD bank@relay.example | grep -q 'not owned by user'"
  check "mail from the internet claiming the victim's domain is not signed with its key" bash -c "python3 $MCL deliver 25 info@$VD sales@$VD --subject spoof-in && sleep 2 && python3 $MCL imap-find sales@$VD '$VPW' spoof-in --out $FT/spoof.eml && ! grep -qi '^DKIM-Signature' $FT/spoof.eml"

  echo "-- 16d. reading the victim's mail"
  check_not "IMAP login as the victim with the attacker's password" python3 "$MCL" imap-count "info@$VD" "$APW"
  check_not "IMAP login as the victim with the address as password" python3 "$MCL" imap-count "info@$VD" "info@$VD"
  check "the file manager refuses paths outside the attacker's home" bash -c "! oxpanel-ctl files ls attack3 ../victim1/mail >/dev/null 2>&1 && ! oxpanel-ctl files cat attack3 ../victim1/mail/vphp.test/info/cur >/dev/null 2>&1"
  check "webmail's account cannot read the victim's mail" bash -c "! setpriv --reuid=oxpanel-webmail --regid=oxpanel-webmail --clear-groups -- ls /home/victim1/mail >/dev/null 2>&1"
  check "the mail policy service's account cannot either" bash -c "! setpriv --reuid=oxpanel-mail --regid=oxpanel-mail --clear-groups -- ls /home/victim1/mail >/dev/null 2>&1"
  check "webmail may reach only the loopback" bash -c "systemctl show oxpanel-webmail -p IPAddressDeny | grep -q 0.0.0.0/0"

  echo "-- 16e. injection in every field"
  for bad in $'info\nroot' 'info@x' 'in fo' '../info' 'info;' '.info' 'INFO' 'info+tag'; do
    check "mailbox local part refused: $(printf %q "$bad")" bash -c "! echo '$APW' | oxpanel-ctl mail mailbox-set '$bad@$AD' --tenant attack3 --password >/dev/null 2>&1"
  done
  for bad in $'a@b.example\nroot@localhost' 'a@b.example,c@d.example' '<a@b.example>' 'a b@c.example' '|/bin/sh' '/etc/passwd' ':include:/etc/passwd' 'a@b.example\\'; do
    check "forwarder destination refused: $(printf %q "$bad")" bash -c "! oxpanel-ctl mail forwarder-set inj@$AD --tenant attack3 --to $(printf %q "$bad") >/dev/null 2>&1"
  done
  check "an autoresponder subject with a line break is refused" bash -c "! oxpanel-ctl mail autoreply shop@$AD --tenant attack3 --subject \$'x\nBcc: a@b.example' --body x >/dev/null 2>&1"
  check "an external MX with a line break is refused" bash -c "! oxpanel-ctl mail domain-set $AD --tenant attack3 --mode external --mx \$'mx.example.org\nrelay' >/dev/null 2>&1"
  check "an autoresponder body that tries to end the Sieve string stays text" run_ok ctl mail autoreply "shop@$AD" --tenant attack3 --subject 'away "x"; redirect "a@b.example";' --body $'line\n.\n"; redirect "evil@relay.example"; keep;'
  # sievec writes its output by renaming a new file over it: never give it a
  # path that is not a scratch file of the test (with /dev/null it replaced
  # the device and broke the host).
  check "the script compiles and holds no redirect (the text stayed text)" bash -c "rm -f $FT/shop.svbin $FT/shop.dump && sievec /var/lib/oxpanel-mail/sieve/$AD/shop.sieve $FT/shop.svbin && sieve-dump $FT/shop.svbin > $FT/shop.dump && grep -qiE '^ *[0-9a-f]+: *vacation' $FT/shop.dump && ! grep -qiE '^ *[0-9a-f]+: *redirect' $FT/shop.dump"
  check "/dev/null is still the null device" test -c /dev/null
  check "Postfix still accepts its maps" bash -c "postfix check >/dev/null 2>&1"
  check "Dovecot still accepts its configuration" bash -c "doveconf -n >/dev/null 2>&1"
  ctl mail autoreply "shop@$AD" --tenant attack3 --off >/dev/null

  echo "-- 16f. symlinks in the attacker's ~/mail"
  check "a second attacker mailbox (to be replaced by links)" bash -c "echo '$APW' | oxpanel-ctl mail mailbox-set link@$AD --tenant attack3 --password >/dev/null"
  before="$(find /home/victim1/mail -type f | sort | sha256sum)"
  as_user attack3 bash -c "rm -rf $AT3/mail/$AD/link && ln -s /home/victim1/mail/$VD/info $AT3/mail/$AD/link"
  python3 "$MCL" deliver 25 a@remote.example "link@$AD" --subject via-link >/dev/null 2>&1 || true
  sleep 3
  check "delivery through a link into the victim's mailbox writes nothing there" test "$(find /home/victim1/mail -type f | sort | sha256sum)" = "$before"
  as_user attack3 bash -c "rm -f $AT3/mail/$AD/link && ln -s /etc $AT3/mail/$AD/link"
  python3 "$MCL" deliver 25 a@remote.example "link@$AD" --subject via-etc >/dev/null 2>&1 || true
  sleep 3
  check "delivery through a link to /etc writes nothing there" bash -c "test ! -e /etc/new && test ! -e /etc/cur && test ! -e /etc/tmp"
  rc=0; out="$(timeout 300 oxpanel-ctl backup create attack3 --wait 2>&1)" || rc=$?
  B="$(sed -n 's/^job=[^ ]* .* backup=\([^ ]*\) .*/\1/p' <<<"$out" | tail -1)"
  check "a backup of the attacker stores the link, not the victim's mail" bash -c "! tar -xzOf /var/lib/oxpanel-backups/attack3/$B/home.tar.gz 2>/dev/null | grep -q VICTIM-SECRET-MAIL"
  ctl backup delete attack3 "$B" >/dev/null 2>&1 || true
  as_user attack3 bash -c "rm -f $AT3/mail/$AD/link && ln -s /home/victim1/mail/$VD $AT3/mail/$AD/link"
  check "deleting the mailbox behind a link" run_ok ctl mail mailbox-delete "link@$AD" --tenant attack3
  sleep 3
  check "removes the link only, never the victim's mail" python3 "$MCL" imap-find "info@$VD" "$VPW" VICTIM-SECRET-MAIL
  as_user attack3 rm -f "$AT3/mail/$AD/link"

  echo "-- 16g. forwarders: loops and amplification"
  check "a forwarder to the victim (allowed: any address)" run_ok ctl mail forwarder-set "fw@$AD" --tenant attack3 --to "info@$VD"
  check "the victim cannot be made part of a loop" bash -c "oxpanel-ctl mail forwarder-set back@$VD --tenant victim1 --to fw@$AD >/dev/null && ! oxpanel-ctl mail forwarder-set fw@$AD --tenant attack3 --to back@$VD 2>&1 | grep -qv forward_loop"
  check "a loop through two customers is refused (forward_loop)" bash -c "oxpanel-ctl mail forwarder-set fw@$AD --tenant attack3 --to back@$VD 2>&1 | grep -q forward_loop"
  args=(); for i in $(seq 1 11); do args+=(--to "d$i@relay.example"); done
  check "more than ten destinations are refused" bash -c "oxpanel-ctl mail forwarder-set amp@$AD --tenant attack3 $(printf '%q ' "${args[@]}") 2>&1 | grep -q too_many_destinations"
  check "Postfix bounds alias expansion" test "$(postconf -h virtual_alias_expansion_limit)" -le 1000
  ctl mail forwarder-delete "back@$VD" --tenant victim1 >/dev/null; ctl mail forwarder-delete "fw@$AD" --tenant attack3 >/dev/null

  echo "-- 16h. sending limits cannot be bypassed"
  check "a tight limit for the attacker" run_ok ctl mail limits-set attack3 --max-mailboxes unlimited --max-mailbox-bytes unlimited --per-hour-account 2 --per-hour-mailbox unlimited
  for i in 1 2 3; do python3 "$MCL" submit 587 "shop@$AD" "$APW" "shop@$AD" bank@relay.example --subject "rate-$i" >/dev/null 2>&1 || true; done
  check "over the limit, submission is deferred" bash -c "python3 $MCL submit 587 shop@$AD '$APW' shop@$AD bank@relay.example | grep -q 45"
  check "over the limit, the site's sendmail is held too" bash -c "printf 'From: shop@$AD\nTo: bank@relay.example\nSubject: x\n\nx\n' | setpriv --reuid=attack3 --regid=attack3 --clear-groups --no-new-privs -- /usr/sbin/oxpanel-daemon sendmail -t; test \$? -eq 75"
  check "the loopback's port 25 does not send out instead" bash -c "python3 $MCL deliver 25 shop@$AD bank@relay.example | grep -q 'Relay access denied'"
  check "Postfix's sendmail is not available to the attacker" bash -c "! printf 'Subject: x\n\nx\n' | setpriv --reuid=attack3 --regid=attack3 --clear-groups --no-new-privs -- /usr/sbin/sendmail.postfix -f shop@$AD bank@relay.example 2>/dev/null"
  ctl mail limits-set attack3 --max-mailboxes unlimited --max-mailbox-bytes unlimited --per-hour-account 1000 --per-hour-mailbox 1000 >/dev/null

  echo "-- 16i. autoresponders: backscatter and loops"
  check "victim: an autoresponder" run_ok ctl mail autoreply "info@$VD" --tenant victim1 --subject victim-away --body 'Away.'
  check "attacker: an autoresponder too (to try a loop)" run_ok ctl mail autoreply "shop@$AD" --tenant attack3 --subject attacker-away --body 'Away too.'
  python3 "$MCL" submit 587 "shop@$AD" "$APW" "shop@$AD" "info@$VD" --subject loop-start >/dev/null
  sleep 8
  n="$(python3 "$MCL" imap-count "shop@$AD" "$APW")"
  check "two autoresponders do not answer each other in circles (at most one reply)" test "$(grep -c . <<<"$(python3 - "$APW" "$AD" <<'PY'
import imaplib,ssl,sys
c=ssl.create_default_context(); c.check_hostname=False; c.verify_mode=ssl.CERT_NONE
m=imaplib.IMAP4_SSL('127.0.0.1',993,ssl_context=c); m.login('shop@'+sys.argv[2],sys.argv[1]); m.select('INBOX')
print('\n'.join(x.decode() for x in m.search(None,'SUBJECT','victim-away')[1][0].split()))
PY
)")" -le 1
  python3 "$MCL" submit 587 "shop@$AD" "$APW" "shop@$AD" "info@$VD" --subject loop-again >/dev/null
  sleep 5
  check "a second message the same day gets no second reply" test "$(python3 "$MCL" imap-count "shop@$AD" "$APW")" -le "$((n + 1))"
  check "a message marked as bulk gets no reply (no backscatter)" bash -c "grep -q precedence /var/lib/oxpanel-mail/sieve/$VD/info.sieve"
  ctl mail autoreply "info@$VD" --tenant victim1 --off >/dev/null; ctl mail autoreply "shop@$AD" --tenant attack3 --off >/dev/null

  echo "-- 16j. password guessing"
  for i in $(seq 1 6); do python3 "$MCL" imap-count "info@$VD" "guess-$i-password" >/dev/null 2>&1 || true; done
  check "after guessing, the right password still works from elsewhere (no account lockout)" python3 "$MCL" imap-count "info@$VD" "$VPW"
  if systemctl -q is-active fail2ban; then
    check "fail2ban watches Dovecot" bash -c "fail2ban-client status dovecot >/dev/null"
    check "fail2ban watches Postfix's logins" bash -c "fail2ban-client status postfix-sasl >/dev/null"
    check "fail2ban watches webmail" bash -c "fail2ban-client status oxpanel-webmail >/dev/null"
    check "the loopback is never banned (webmail logs in from it)" bash -c "fail2ban-client get dovecot ignoreip | grep -qE \"127\\.0\\.0\\.(1|0/8)\""
  else
    info "fail2ban is not active here: the ban itself is covered in installer mode"
  fi

  echo "-- 16k. a suspended customer's email"
  check "suspend the victim" run_ok ctl tenant suspend victim1
  check_not "a suspended customer's mailbox cannot log in" python3 "$MCL" imap-count "info@$VD" "$VPW"
  check "mail for it is deferred, not bounced" bash -c "python3 $MCL deliver 25 a@remote.example info@$VD | grep -q 450"
  check "resume the victim" run_ok ctl tenant resume victim1

  echo "-- 16l. the mail filter's resolver (127.0.0.1:5335), from the attacker's code"
  if systemctl -q is-active oxpanel-mail-resolver; then
    local RLOG=/root/acc/attack-authority.log RCONF=/etc/oxpanel-mail-resolver/local.d/oxacc-attack.conf
    : > "$RLOG"; pkill -f 'mail-client.py authority' 2>/dev/null || true
    nohup python3 "$MCL" authority 5399 oxresolve.test "$RLOG" >/dev/null 2>&1 &
    printf 'server:\n  do-not-query-localhost: no\n  domain-insecure: "oxresolve.test"\n  local-zone: "test." nodefault\nstub-zone:\n  name: "oxresolve.test"\n  stub-addr: 127.0.0.1@5399\n' > "$RCONF"
    chgrp unbound "$RCONF"; chmod 0640 "$RCONF"; systemctl reload oxpanel-mail-resolver
    eventually "the test authority answers through the resolver" 20 0.5 bash -c "dig +short +tries=1 +time=2 @127.0.0.1 -p 5335 ready.oxresolve.test A | grep -qx 192.0.2.53"
    asa3() { setpriv --reuid=attack3 --regid=attack3 --clear-groups --no-new-privs -- "$@"; }
    check "the attacker cannot read the resolver's configuration" bash -c "! setpriv --reuid=attack3 --regid=attack3 --clear-groups --no-new-privs -- cat /etc/oxpanel-mail-resolver/unbound.conf 2>/dev/null"
    check "ANY questions are refused (no amplification)" bash -c "setpriv --reuid=attack3 --regid=attack3 --clear-groups --no-new-privs -- dig +tries=1 +time=3 @127.0.0.1 -p 5335 ready.oxresolve.test ANY | grep -q 'status: NOTIMP'"
    check "no remote control to flush or change it (nothing on 8953)" bash -c '! ss -Hltn "sport = :8953" | grep -q LISTEN'
    check "unbound-control cannot reach it" bash -c "! timeout 10 unbound-control -s 127.0.0.1@5335 status >/dev/null 2>&1"
    # Forged answers: the attacker races the resolver for a name it is about
    # to look up, sending answers with every ID to the loopback's ports.
    asa3 python3 - <<'PY' &
import socket, struct, time, random
def ans(qid, name, ip):
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
    return struct.pack(">HHHHHH", qid, 0x8400, 1, 1, 0, 0) + q + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 86400, 4) + bytes(ip)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
end = time.time() + 8
while time.time() < end:
    pkt = ans(random.randrange(65536), "poison.oxresolve.test", [6, 6, 6, 6])
    for port in (5335, random.randrange(32768, 61000)):
        try: s.sendto(pkt, ("127.0.0.1", port))
        except OSError: pass
PY
    sleep 1
    check "forged answers do not get into the cache" bash -c "test \"\$(dig +short +tries=1 +time=5 @127.0.0.1 -p 5335 poison.oxresolve.test A)\" = 192.0.2.53"
    wait
    # Exhaustion: a flood of random names for ten seconds.
    asa3 python3 - <<'PY'
import socket, struct, time, random, string
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setblocking(False)
end, n = time.time() + 10, 0
while time.time() < end:
    name = "".join(random.choice(string.ascii_lowercase) for _ in range(20)) + ".flood.oxresolve.test"
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
    try: s.sendto(struct.pack(">HHHHHH", random.randrange(65536), 0x0100, 1, 0, 0, 0) + q, ("127.0.0.1", 5335)); n += 1
    except OSError: time.sleep(0.001)
print(f"flood: {n} questions sent")
PY
    check "after the flood the resolver still runs" systemctl -q is-active oxpanel-mail-resolver
    info "resolver memory after the flood: $(( $(systemctl show -P MemoryCurrent oxpanel-mail-resolver) / 1048576 )) MiB (cap 256 MiB); questions the test authority saw: $(grep -c flood "$RLOG")"
    check "its memory stays under the unit's cap" test "$(systemctl show -P MemoryCurrent oxpanel-mail-resolver)" -lt 268435456
    eventually "and it answers the filter's questions again within seconds" 30 1 bash -c "dig +short +tries=1 +time=2 @127.0.0.1 -p 5335 after-flood.oxresolve.test A | grep -qx 192.0.2.53"
    local PROBE="atk$RANDOM.oxresolve.test"
    check "the filter's lookups go through after the flood" python3 "$MCL" deliver 25 "a@$PROBE" "info@$VD" --subject after-flood
    eventually "(the test authority saw the filter's question)" 60 0.5 grep -q "$PROBE" "$RLOG"
    pkill -f 'mail-client.py authority' 2>/dev/null || true
    rm -f "$RCONF"; systemctl reload oxpanel-mail-resolver
  else
    info "the mail filter's resolver is not running here: 16l skipped"
  fi

  echo "-- 16 teardown"
  ctl mail mailbox-delete "info@$VD" --tenant victim1 >/dev/null 2>&1; ctl mail mailbox-delete "sales@$VD" --tenant victim1 >/dev/null 2>&1
  ctl mail domain-set "$VD" --tenant victim1 --mode off >/dev/null 2>&1
  check "no mail drift after the email attacks" bash -c "sleep 3; ! oxpanel-ctl host reconcile | grep -q MAIL"
}
