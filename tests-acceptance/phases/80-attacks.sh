#!/usr/bin/env bash
# Phase 80 — tenant-isolation attacks, from inside the tenant's own PHP, Node.js and
# Python code, and from the network. Every attempt must fail.
#
# How the phase tells "denied" from "a hole":
#   * Every probe has an expected result. A probe that is OPEN where BLOCKED is
#     expected is an attack that worked: the phase fails.
#   * Kernel permission checks (DAC) run before SELinux. So an AVC denial for a
#     tenant's code means plain Unix permissions would have allowed the access and
#     SELinux stopped it. Those are listed and counted as "denied attacks" (the
#     attack failed; but each one is also a finding about the DAC layer).
#   * An AVC whose source domain is anything else (the daemon, nginx itself, init)
#     means a legitimate operation was refused: a hole in our policy or a feature
#     that broke under enforcement. The phase fails.
cd "$(dirname "$0")/.."; source phases/lib.sh
echo "== phase 80: tenant isolation attacks"
A=phases/attack; LOG=/root/acc/attacks; mkdir -p "${LOG:?}"; rm -f "${LOG:?}"/*
AVC0=$(avc_count); START_TIME=$(date +%T)
get() { curl -s -m 60 -H "Host: $1" "http://127.0.0.1$2"; }
getc() { curl -s -m 60 -o /dev/null -w '%{http_code}' -H "Host: $1" "http://127.0.0.1$2"; }
ctl() { oxpanel-ctl "$@"; }
snap() { { stat -c '%n %a %U:%G %C' /etc /usr /home /tmp /var/lib/oxpanel /etc/nginx/oxpanel.d; getfacl -p /etc /home /tmp /var/lib/oxpanel /etc/nginx 2>/dev/null; } | sha256sum | cut -d' ' -f1; }
unit_pid() { systemctl show -p MainPID --value "$1"; }
victim_ok() { [ "$(curl -s -m 10 -H 'Host: vnode.test' http://127.0.0.1/)" = victim-node-ok ] && [ "$(curl -s -m 10 -H 'Host: vphp.test' http://127.0.0.1/)" = victim-php-ok ] && [ "$(curl -s -m 10 -H 'Host: vpy.test' http://127.0.0.1/)" = victim-py-ok ]; }
raw() { printf "$1" > /root/acc/raw.req; python3 -I /root/acc/rawhttp.py /root/acc/raw.req; }
status_of() { head -1 | awk '{print $2}'; }
export -f get getc raw status_of victim_ok

# ------------------------------------------------------------------ setup
echo "-- setup: a victim, an attacker, and a suspended tenant"
for t in victim1 attack1 susp1 attack2; do ctl tenant delete "$t" --remove-home >/dev/null 2>&1 || true; done
check "create victim1" bash -c "oxpanel-ctl tenant create victim1 --memory 256M | grep -q '^created=true'"
check "create attack1 (192M memory, 200 tasks)" bash -c "oxpanel-ctl tenant create attack1 --memory 192M --cpu-weight 50 --tasks-max 200 | grep -q '^created=true'"
check "create susp1" bash -c "oxpanel-ctl tenant create susp1 --memory 128M | grep -q '^created=true'"
V=/home/victim1; AT=/home/attack1; AUID=$(id -u attack1)
check "victim PHP site" bash -c "oxpanel-ctl vhost set vphp.test --tenant victim1 --php | grep -q '^changed=true'"
check "victim Node.js site" bash -c "oxpanel-ctl vhost set vnode.test --tenant victim1 --app node | grep -q '^changed=true'"
check "victim Python site" bash -c "oxpanel-ctl vhost set vpy.test --tenant victim1 --app python | grep -q '^changed=true'"
as_user victim1 sh -c "echo VICTIM-SECRET-HOME > $V/secret.txt; echo VICTIM-SECRET-DOC > $V/public_html/doc-secret.txt; echo '<?php echo \"victim-php-ok\";' > $V/public_html/index.php; echo VICTIM-SECRET-APP > $V/apps/vnode.test/secret-app.txt; echo VICTIM-SECRET-APP > $V/apps/vpy.test/secret-app.txt"
as_user victim1 sh -c "cat > $V/apps/vnode.test/app.js" <<'JS'
let n = 0;
require('http').createServer((req, res) => { n++; res.end(req.url === '/count' ? String(n) : 'victim-node-ok'); }).listen(process.env.PORT);
JS
as_user victim1 sh -c "cat > $V/apps/vpy.test/app.py" <<'PY'
import os
from http.server import BaseHTTPRequestHandler
from socketserver import UnixStreamServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        b = b'victim-py-ok'; self.send_response(200); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
UnixStreamServer(os.environ['PORT'], H).serve_forever()
PY
ctl vhost restart-app vnode.test >/dev/null; ctl vhost restart-app vpy.test >/dev/null
eventually "victim PHP site serves" 50 0.2 http_body_is vphp.test / victim-php-ok
eventually "victim Node.js site serves" 50 0.2 http_body_is vnode.test / victim-node-ok
eventually "victim Python site serves" 50 0.2 http_body_is vpy.test / victim-py-ok
VPHP=$(unit_pid oxpanel-php-victim1.service); VNODE=$(unit_pid oxpanel-app-vnode.test.service)
info "victim pids: php=$VPHP node=$VNODE"
check "victim processes exist" test "$VPHP" -gt 1 -a "$VNODE" -gt 1

check "susp1 site" bash -c "oxpanel-ctl vhost set susp.test --tenant susp1 --alias www.susp.test | grep -q '^changed=true'"
as_user susp1 sh -c "echo SUSPENDED-SECRET > /home/susp1/public_html/index.html"
eventually "susp.test serves before suspension" 30 0.2 http_body_is susp.test / SUSPENDED-SECRET
check "suspend susp1" bash -c "oxpanel-ctl tenant suspend susp1 | grep -q 'suspended=true'"

# probes.tsv: op<TAB>name<TAB>argument<TAB>expectation (blocked | open | info)
P=/root/acc/probes.tsv
{
  p() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4:-blocked}"; }
  p read victim-home-file $V/secret.txt;                      p list victim-home $V
  p list victim-docroot $V/public_html;                       p read victim-docroot-file $V/public_html/doc-secret.txt
  p list victim-apps $V/apps;                                 p read victim-app-secret $V/apps/vnode.test/secret-app.txt
  p read victim-app-source $V/apps/vnode.test/app.js;        p list victim-venv $V/apps/vpy.test/.venv
  p read victim-access-log /var/log/nginx/oxpanel/vphp.test.access.log
  p list nginx-log-dir /var/log/nginx/oxpanel;                p read nginx-error-log /var/log/nginx/error.log info
  p read shadow /etc/shadow;  p read gshadow /etc/gshadow;    p read sudoers /etc/sudoers
  p list root-home /root;     p read root-authorized-keys /root/.ssh/authorized_keys
  p list engine-state /var/lib/oxpanel;                       p list engine-tenants /var/lib/oxpanel/tenants
  p read engine-tenant-record /var/lib/oxpanel/tenants/victim1.json
  p read engine-vhost-record /var/lib/oxpanel/vhosts/vphp.test.json
  p read engine-env /etc/oxpanel/daemon.env;                  p list engine-config-dir /etc/oxpanel
  p unix engine-socket /run/oxpanel/oxpanel.sock
  p unix victim-php-socket /run/oxpanel-php/victim1/php.sock
  p unix victim-node-socket /run/oxpanel-app/vnode.test/app.sock
  p unix victim-py-socket /run/oxpanel-app/vpy.test/app.sock
  p list victim-app-run-dir /run/oxpanel-app/vnode.test
  p write etc /etc/oxprobe;   p write usr /usr/oxprobe;       p write home-base /home/oxprobe
  p write victim-home $V/oxprobe;  p write victim-docroot $V/public_html/oxprobe;  p write victim-apps $V/apps/oxprobe
  p write engine-state /var/lib/oxpanel/oxprobe;              p write engine-tenants /var/lib/oxpanel/tenants/oxprobe.json
  p write nginx-conf-dir /etc/nginx/oxpanel.d/oxprobe.conf;   p write nginx-conf-d /etc/nginx/conf.d/oxprobe.conf
  p write unit-dir /etc/systemd/system/oxprobe.service;       p write php-conf-dir /etc/oxpanel-php/oxprobe.conf
  p write engine-run /run/oxpanel/oxprobe;                    p write boot /boot/oxprobe
  p read proc1-environ /proc/1/environ
  p read victim-php-environ /proc/$VPHP/environ;              p read victim-node-mem /proc/$VNODE/mem
  p read victim-node-cwd-listing /proc/$VNODE/cwd/secret-app.txt
  p kill victim-php-master "$VPHP";                           p kill victim-node-process "$VNODE";  p kill init 1
  p run sudo "/usr/bin/sudo -n true";                         p run su "/usr/bin/su -c true root"
  p run systemd-run "/usr/bin/systemd-run --quiet --pipe /usr/bin/true"
  p run setfacl-etc "/usr/bin/setfacl -m u:attack1:rwx /etc"; p run chmod-passwd "/usr/bin/chmod 666 /etc/passwd"
  p run chown-self "/usr/bin/chown attack1 /etc/passwd";      p run useradd "/usr/sbin/useradd oxprobe1"
  p run mount "/usr/bin/mount -t tmpfs none /mnt";            p run nsenter "/usr/bin/nsenter -t 1 -m /usr/bin/true"
  p run engine-ctl-list "/usr/bin/oxpanel-ctl tenant list"
  p run engine-ctl-delete "/usr/bin/oxpanel-ctl tenant delete victim1 --remove-home"
  p run engine-ctl-vhost-remove "/usr/bin/oxpanel-ctl vhost remove vphp.test"
  p run crontab-root "/usr/bin/crontab -u root -l"
  p read own-file $AT/own.txt open;                            p write own-docroot $AT/public_html/own-probe open
  p read php-conf-of-victim /etc/oxpanel-php/victim1.conf info
  p read victim-unit-file /etc/systemd/system/oxpanel-app-vnode.test.service info
  p read passwd /etc/passwd info
  p read victim-node-cmdline /proc/$VNODE/cmdline info
  p list run-oxpanel-app /run/oxpanel-app info
  p list run-oxpanel-php /run/oxpanel-php info
} > "$P"
NPROBES=$(grep -c . "$P"); NEXPECT=$(awk -F'\t' '{n+=1+($1=="read")+($1=="write")} END{print n+1}' "$P")
check "probe list written ($NPROBES probes, $NEXPECT result lines per runtime)" test "$NPROBES" -gt 60

# the attacker's applications, and the code that attacks from inside them
check "attack1 PHP site" bash -c "oxpanel-ctl vhost set aphp.test --tenant attack1 --php | grep -q '^changed=true'"
check "attack1 Node.js site" bash -c "oxpanel-ctl vhost set anode.test --tenant attack1 --app node | grep -q '^changed=true'"
check "attack1 Python site" bash -c "oxpanel-ctl vhost set apy.test --tenant attack1 --app python | grep -q '^changed=true'"
install -o attack1 -g attack1 -m 0600 "$P" $AT/probes.tsv
as_user attack1 sh -c "echo OWN-SECRET > $AT/own.txt"
inst() { sed "s|/home/ATTACKER/|$AT/|" "$A/$1" | as_user attack1 sh -c "cat > $2"; }
inst probe.php $AT/public_html/probe.php
inst probe.js $AT/apps/anode.test/app.js
inst probe.py $AT/apps/apy.test/app.py
ctl vhost restart-app anode.test >/dev/null; ctl vhost restart-app apy.test >/dev/null
eventually "attacker PHP code is served" 50 0.2 bash -c "curl -s -H 'Host: aphp.test' 'http://127.0.0.1/probe.php?do=echo' | grep -q url"
eventually "attacker Node.js code is served" 50 0.2 bash -c "curl -s -H 'Host: anode.test' http://127.0.0.1/count | grep -qE '^[0-9]+$'"
eventually "attacker Python code is served" 50 0.2 bash -c "curl -s -H 'Host: apy.test' http://127.0.0.1/count | grep -qE '^[0-9]+$'"
SNAP0=$(snap)

# ------------------------------------------------------------------ 1. the battery, from inside each runtime
battery() { # <label> <host> <path>
  local label="$1" out n bad=0 name res want detail
  out="$(curl -s -m 180 -H "Host: $2" "http://127.0.0.1$3")"; echo "$out" > "$LOG/battery-$label.tsv"
  n=$(grep -c . <<<"$out")
  [ "$n" = "$NEXPECT" ] || { fail "$label: expected $NEXPECT result lines, got $n (see $LOG/battery-$label.tsv)"; return; }
  while IFS=$'\t' read -r name res want detail; do
    [ "$name" = STATUS ] && continue
    case "$want:$res" in
      blocked:BLOCKED|open:OPEN) ;;
      blocked:OPEN) echo "ATTACK SUCCEEDED ($label): $name — $detail"; bad=$((bad+1));;
      open:BLOCKED) echo "CONTROL FAILED ($label): $name — the harness cannot do what the tenant may do: $detail"; bad=$((bad+1));;
      info:*) info "$label: $name is $res ($detail) [not asserted]";;
    esac
  done <<<"$out"
  if [ "$bad" = 0 ]; then ok "$label: all $((n-1)) probes behave (everything outside the tenant refused, the tenant's own files allowed)"; else fail "$label: $bad probe(s) wrong"; fi
  local st; st="$(grep '^STATUS' <<<"$out")"
  if [ "$label" = php ]; then   # open_basedir hides /proc from the script: read the instance's own status as root
    local pid; pid=$(unit_pid oxpanel-php-attack1.service)
    st="nonewprivs=$(awk '/^NoNewPrivs:/{print $2}' /proc/$pid/status) capeff=$(awk '/^CapEff:/{print $2}' /proc/$pid/status)"
  fi
  check "$label: NoNewPrivs is set ($st)" grep -q 'nonewprivs=1' <<<"$st"
  check "$label: effective capability set is empty" grep -qE 'capeff=0+([[:space:]]|$)' <<<"$st"
}
echo "-- 1. from inside the tenant's code"
battery php aphp.test /probe.php
battery node anode.test /probe
battery python apy.test /probe
check "the attacks changed nothing outside the tenant (permissions, ACLs, labels)" test "$(snap)" = "$SNAP0"
check "no probe file was created outside the tenant" bash -c '! ls /etc/oxprobe /usr/oxprobe /home/oxprobe /boot/oxprobe /var/lib/oxpanel/oxprobe /home/victim1/oxprobe /home/victim1/public_html/oxprobe >/dev/null 2>&1'
check "no account was created by the attacker's useradd" bash -c '! id oxprobe1 >/dev/null 2>&1'
check "victim's secret untouched" test "$(cat $V/secret.txt)" = VICTIM-SECRET-HOME
check "the engine still lists victim1 (the attacker's oxpanel-ctl delete did nothing)" bash -c "oxpanel-ctl tenant get victim1 | grep -q state=TENANT_STATE_READY"
check "the victim's sites still serve" victim_ok

# ------------------------------------------------------------------ 2. links planted by the tenant, served by nginx
echo "-- 2. planted links, read through the web server"
as_user attack1 sh -c "cd $AT/public_html && echo '<?php echo \"index\";' > index.php && ln -sf /etc/shadow l-shadow && ln -sf /etc/passwd l-passwd && ln -sf $V/public_html/doc-secret.txt l-vdoc && ln -sf $V/secret.txt l-vsecret && ln -sf /var/lib/oxpanel/tenants/victim1.json l-record && ln -sfn $V/public_html l-vdir && ln -sfn /etc l-etc && ln -sf $V/public_html/index.php l-vphp.php"
for l in l-shadow l-passwd l-vdoc l-vsecret l-record l-vdir/doc-secret.txt l-etc/passwd l-vphp.php; do
  body="$(get aphp.test "/$l")"; code="$(getc aphp.test "/$l")"
  check "symlink /$l does not leak the target (HTTP $code: the PHP front controller answers refused paths)" bash -c '! grep -qE "root:|VICTIM-SECRET|victim-php-ok|\"username\"" <<<"$1"' _ "$body"
done
check_not "a hard link to /etc/passwd is refused by the kernel (protected_hardlinks)" as_user attack1 ln /etc/passwd $AT/hl-passwd
check_not "a hard link to another tenant's file is impossible" as_user attack1 ln $V/secret.txt $AT/hl-secret
check_not "a hard link to an engine record is refused" as_user attack1 ln /var/lib/oxpanel/tenants/victim1.json $AT/hl-record
check "the Node.js site's static files are protected the same way" bash -c "! curl -s -H 'Host: anode.test' http://127.0.0.1/l-shadow | grep -q root: && ! curl -s -H 'Host: anode.test' http://127.0.0.1/l-vdoc | grep -q VICTIM"

# ------------------------------------------------------------------ 3. crafted requests
echo "-- 3. crafted requests"
cat > /root/acc/rawhttp.py <<'PY'
import socket, sys
data = open(sys.argv[1], 'rb').read()
s = socket.create_connection(('127.0.0.1', 80), timeout=4)
s.sendall(data)
buf = b''
try:
    while len(buf) < 20000:
        c = s.recv(4096)
        if not c: break
        buf += c
except socket.timeout:
    pass
sys.stdout.buffer.write(buf)
PY
for h in nobody.test vphp.test.evil.test localhost 127.0.0.1 ''; do
  rc=0; code="$(curl -s -m 5 -o /dev/null -w '%{http_code}' -H "Host: $h" http://127.0.0.1/)" || rc=$?
  check "unknown Host '${h:-<empty>}' reaches no tenant (curl exit $rc, HTTP $code)" bash -c '[ "$1" = 52 ] || [ "$2" = 444 ] || [ "$2" = 000 ] || [ "$2" = 400 ]' _ "$rc" "$code"
done
for h in susp.test SUSP.TEST susp.test. susp.test:80 susp.test:8080 www.susp.test; do
  body="$(get "$h" /)"; code="$(getc "$h" /)"
  check "suspended site via Host '$h' answers 503, never its content" bash -c '[ "$1" = 503 ] && ! grep -q SUSPENDED-SECRET <<<"$2"' _ "$code" "$body"
done
resp="$(raw 'GET http://susp.test/ HTTP/1.1\r\nHost: vphp.test\r\n\r\n')"
check "absolute-URI request for the suspended site never yields its content" bash -c '! grep -q SUSPENDED-SECRET <<<"$1"' _ "$resp"
resp="$(raw 'GET / HTTP/1.1\r\nHost: susp.test\r\nX-Forwarded-Host: vphp.test\r\nX-Original-URL: /secret\r\nX-Rewrite-URL: /secret\r\nForwarded: host=aphp.test\r\n\r\n')"
check "forwarding headers do not change which site answers" bash -c 'head -1 <<<"$1" | grep -q 503 && ! grep -q SUSPENDED-SECRET <<<"$1"' _ "$resp"
for p in /static/../../etc/passwd /%2e%2e/%2e%2e/etc/passwd /..%2f..%2fetc/passwd //etc/passwd /.%2e/.%2e/etc/passwd /%252e%252e/etc/passwd '/..;/etc/passwd' '/..%5c..%5cetc/passwd' /../../victim1/public_html/doc-secret.txt /../victim1/secret.txt /%00 /.git/config /.env; do
  for h in aphp.test anode.test; do
    body="$(curl -s --path-as-is -m 10 -H "Host: $h" "http://127.0.0.1$p")"; code="$(curl -s --path-as-is -m 10 -o /dev/null -w '%{http_code}' -H "Host: $h" "http://127.0.0.1$p")"
    check "path $p against $h yields nothing from outside the document root ($code)" bash -c '! grep -qE "root:x|VICTIM-SECRET" <<<"$1"' _ "$body"
  done
done
check "duplicate Host headers are refused (400)" bash -c '[ "$(raw "GET / HTTP/1.1\r\nHost: anode.test\r\nHost: vnode.test\r\n\r\n" | status_of)" = 400 ]'
check "a space before the colon in a header name is refused (400)" bash -c '[ "$(raw "GET / HTTP/1.1\r\nHost : anode.test\r\n\r\n" | status_of)" = 400 ]'
check "control characters in Host are not served (no 200)" bash -c '[ "$(raw "GET / HTTP/1.1\r\nHost: anode.test\001\r\n\r\n" | status_of)" != 200 ]'
resp="$(raw 'POST /echo HTTP/1.1\r\nHost: anode.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: vnode.test\r\n\r\n')"
check "Content-Length together with Transfer-Encoding is refused or forwarded unambiguously" bash -c 'head -1 <<<"$1" | grep -q " 400 " || ! grep -qi "\"content-length\".*\"transfer-encoding\"\|\"transfer-encoding\".*\"content-length\"" <<<"$1"' _ "$resp"
resp="$(raw 'POST /echo HTTP/1.1\r\nHost: anode.test\r\nContent-Length: 4\r\nContent-Length: 40\r\n\r\nAAAA')"
check "two Content-Length headers are refused (400)" bash -c 'head -1 <<<"$1" | grep -q " 400 "' _ "$resp"
resp="$(raw 'POST /echo HTTP/1.1\r\nHost: anode.test\r\nTransfer-Encoding: xchunked\r\nContent-Length: 4\r\n\r\nAAAA')"
check "an obfuscated Transfer-Encoding is refused or forwarded unambiguously" bash -c 'head -1 <<<"$1" | grep -qE " (400|501) " || ! grep -qi "transfer-encoding" <<<"$1"' _ "$resp"
resp="$(raw 'GET /x%%0d%%0aX-Evil:%%201 HTTP/1.1\r\nHost: anode.test\r\nConnection: close\r\n\r\n')"
check "CRLF smuggled in the URL path does not become a header (it was served: $(head -1 <<<"$resp" | tr -d '\r'))" bash -c '! grep -qi "\"x-evil\"" <<<"$1"' _ "$resp"
resp="$(raw 'GET /echo HTTP/1.1\r\nHost: anode.test\r\nX-Forwarded-For: 6.6.6.6\r\nConnection: close\r\n\r\n')"
check "a client-supplied X-Forwarded-For is appended to, the real peer is last" bash -c 'grep -q "6.6.6.6, 127.0.0.1" <<<"$1"' _ "$resp"
check "the attacker's responses never carry the victim's content after all of the above" bash -c "[ \"\$(curl -s -H 'Host: anode.test' http://127.0.0.1/x)\" = 'node-attacker /x' ]"

# ------------------------------------------------------------------ 4. the daemon acts on a tree the attacker controls
echo "-- 4. making the root daemon (or the operator's oxpanel-ctl) act outside the tenant"
as_user attack1 sh -c "ln -sfn /etc $AT/evil; ln -sfn /var/lib/oxpanel $AT/evil2; mkdir -p /tmp/att-outside; ln -sfn /tmp/att-outside $AT/evil3; ln -sfn $V/public_html $AT/evil4; ln -sfn / $AT/rootlink; ln -sfn . $AT/loop; ln -sfn /usr $AT/big"
S1=$(snap)
for r in evil evil/inner evil2 evil2/tenants evil3 evil3/sub evil4 evil4/sub; do
  check_not "document root '$r' through a planted symlink is refused" ctl vhost set d1.test --tenant attack1 --root "$r"
done
check "nothing was created, labelled or ACL'd outside the home" test "$(snap)" = "$S1"
check "no record or config was left by the refused requests" bash -c '! oxpanel-ctl vhost list | grep -q d1.test && test ! -e /etc/nginx/oxpanel.d/d1.test.conf && test ! -e /etc/inner'
check "the attacker's outside directory got no web-server ACL" bash -c '! getfacl -p /tmp/att-outside /tmp 2>/dev/null | grep -q nginx'
t0=$(date +%s)
out="$(ctl tenant usage attack1)"; dt=$(( $(date +%s) - t0 ))
check "usage of a home with links to / and /usr is measured quickly (${dt}s) and does not count the targets" bash -c '[ "$1" -lt 15 ] && [ "$(sed -n "s/.* disk_usage=\([0-9]*\).*/\1/p" <<<"$2")" -lt 300000000 ]' _ "$dt" "$out"

echo "-- 4b. replace the document root by a link after the site exists, then let the operator act"
as_user attack1 sh -c "mv $AT/public_html $AT/public_html.real && ln -s /var/lib/oxpanel $AT/public_html"
for cmd in "vhost set aphp.test --tenant attack1 --php" "tenant suspend attack1" "tenant resume attack1" "host reconcile" "tenant set-limits attack1 --memory 192M --cpu-weight 50 --tasks-max 200" "tenant usage attack1"; do
  # shellcheck disable=SC2086
  ctl $cmd >/dev/null 2>&1 || true
done
check "the engine's records were not ACL'd, relabelled or chmod'ed through the link" test "$(snap)" = "$S1"
check "records are still root-only 0700" test "$(stat -c '%a %U' /var/lib/oxpanel/tenants)" = "700 root"
check "the site does not expose the engine's records" bash -c '! curl -s -H "Host: aphp.test" http://127.0.0.1/tenants/victim1.json | grep -q username'
check "daemon still active" daemon_active
as_user attack1 sh -c "rm $AT/public_html && mv $AT/public_html.real $AT/public_html"
check "the operator's next request converges (the tenant restored its directory)" bash -c "oxpanel-ctl tenant resume attack1 >/dev/null; oxpanel-ctl vhost set aphp.test --tenant attack1 --php >/dev/null"
check "no drift after the attack and the repair" bash -c "oxpanel-ctl host reconcile | grep -q '^drifts=0$'"

echo "-- 4c. race: the tenant flips a path between directory and link while the operator configures and removes"
# What the engine guarantees here (and what this section asserts): a
# configuration raced by the tenant either completes or is refused whole —
# it never acts outside the home and never leaves a record without its
# configuration or the reverse; a configuration that loses the race is
# simply refused (it is NOT guaranteed that any of the 40 wins: on the VM
# 0 to 6 of 40 do, and a run where none did failed this section when it
# expected the site to exist); and an existing site can always be removed,
# whatever the tenant does to its document root meanwhile.
check "a site whose document root the tenant will race (created first)" bash -c "oxpanel-ctl vhost set race.test --tenant attack1 --root race | grep -q '^changed=true'"
check "a second site that does not exist yet" bash -c "! test -e /var/lib/oxpanel/vhosts/race2.test.json"
( timeout 120 setpriv --reuid=attack1 --regid=attack1 --clear-groups --no-new-privs -- sh -c "while :; do rm -rf $AT/race; ln -s /var/lib/oxpanel $AT/race; rm -f $AT/race; mkdir $AT/race; done" >/dev/null 2>&1 & )
won=0; for _ in $(seq 1 40); do ctl vhost set race.test --tenant attack1 --root race >/dev/null 2>&1 && won=$((won+1)); done
won2=0; for _ in $(seq 1 20); do ctl vhost set race2.test --tenant attack1 --root race >/dev/null 2>&1 && won2=$((won2+1)); done
info "raced configurations that completed: $won of 40 (existing site), $won2 of 20 (new site)"
check "the raced site still has both its record and its configuration, and Nginx accepts it" bash -c "test -f /var/lib/oxpanel/vhosts/race.test.json && test -f /etc/nginx/oxpanel.d/race.test.conf && nginx -t >/dev/null 2>&1"
check "the new site has either both its record and its configuration or neither ($won2 of 20 completed)" bash -c "{ test -f /var/lib/oxpanel/vhosts/race2.test.json && test -f /etc/nginx/oxpanel.d/race2.test.conf; } || { test ! -e /var/lib/oxpanel/vhosts/race2.test.json && test ! -e /etc/nginx/oxpanel.d/race2.test.conf; }"
check "the operator removes the raced site while its document root keeps changing (found by this section: restorecon losing the race used to fail the removal)" bash -c "oxpanel-ctl vhost remove race.test | grep -q '^removed=true' && test ! -e /var/lib/oxpanel/vhosts/race.test.json && test ! -e /etc/nginx/oxpanel.d/race.test.conf"
check "removing the second site answers by its record, and leaves nothing ($won2 of 20 completed)" bash -c "out=\$(oxpanel-ctl vhost remove race2.test) && { [ \"\$out\" = removed=true ] || [ \"\$out\" = removed=false ]; } && test ! -e /var/lib/oxpanel/vhosts/race2.test.json && test ! -e /etc/nginx/oxpanel.d/race2.test.conf"
pkill -u attack1 -f 'while :' 2>/dev/null || true; sleep 1
check "after 60 configurations and two removals raced against the flipping path, nothing outside the home changed" test "$(snap)" = "$S1"
check "the engine's records are intact" bash -c "oxpanel-ctl tenant get victim1 | grep -q READY && test -f /var/lib/oxpanel/tenants/attack1.json"
check "no SELinux labelling rule is left for the raced path" bash -c "! semanage fcontext -l -C 2>/dev/null | grep -q '$AT/race'"
check "Nginx still accepts the whole configuration" nginx -t
as_user attack1 sh -c "rm -rf $AT/race $AT/evil $AT/evil2 $AT/evil3 $AT/evil4 $AT/rootlink $AT/loop $AT/big; rmdir /tmp/att-outside" 2>/dev/null || true

echo "-- 4e. the tenant deletes, or replaces by a link, the document root of a site; the operator removes the site"
check "site with its own root (delroot)" bash -c "oxpanel-ctl vhost set del.test --tenant attack1 --root delroot | grep -q '^changed=true'"
as_user attack1 rm -rf $AT/delroot
check "removing a site whose document root the tenant deleted works (found by this phase: restorecon on the missing path used to fail it)" bash -c "oxpanel-ctl vhost remove del.test | grep -q '^removed=true'"
check "site with its own root (symroot)" bash -c "oxpanel-ctl vhost set sym.test --tenant attack1 --root symroot | grep -q '^changed=true'"
as_user attack1 sh -c "rm -rf $AT/symroot; ln -s /var/lib/oxpanel $AT/symroot"
S2=$(snap)
check "removing a site whose document root became a link to the engine's records works" bash -c "oxpanel-ctl vhost remove sym.test | grep -q '^removed=true'"
check "and relabelled nothing through the link" test "$(snap)" = "$S2"
as_user attack1 rm -f $AT/symroot

echo "-- 4d. deleting a tenant whose home is full of links"
check "create attack2" bash -c "oxpanel-ctl tenant create attack2 | grep -q '^created=true'"
as_user attack2 sh -c "ln -s /etc/ssh /home/attack2/l-ssh; ln -s /etc/passwd /home/attack2/l-passwd; ln -s /var/lib/oxpanel /home/attack2/l-state; mkdir -p /home/attack2/d; ln -s /usr/share /home/attack2/d/l-share; ln -s $V /home/attack2/l-victim"
before="$(ls /etc/ssh | wc -l) $(wc -c < /etc/passwd) $(ls /var/lib/oxpanel/tenants | wc -l) $(ls /usr/share | wc -l)"
check "tenant delete --remove-home succeeds" bash -c "oxpanel-ctl tenant delete attack2 --remove-home | grep -q '^deleted=true'"
after="$(ls /etc/ssh | wc -l) $(wc -c < /etc/passwd) $(ls /var/lib/oxpanel/tenants | wc -l) $(ls /usr/share | wc -l)"
# the tenants directory lost attack2's record on purpose
before_adj="${before% *} $(( $(ls /var/lib/oxpanel/tenants | wc -l) ))"; : "$before_adj"
check "nothing the links pointed at was removed (/etc/ssh, /usr/share, /etc/passwd)" bash -c '[ "$(cut -d" " -f1,4 <<<"$1")" = "$(cut -d" " -f1,4 <<<"$2")" ] && grep -q "^root:" /etc/passwd && ! grep -q "^attack2:" /etc/passwd' _ "$before" "$after"
check "the victim's files survived" test "$(cat $V/secret.txt)" = VICTIM-SECRET-HOME

# ------------------------------------------------------------------ 5. resources
echo "-- 5. resource attacks, from inside each runtime"
SLICE=oxpanel-tenant-attack1.slice
cg() { echo "/sys/fs/cgroup$(systemctl show -p ControlGroup --value $SLICE)"; }
oom_kills() { awk '/^oom_kill /{print $2}' "$(cg)/memory.events"; }
VNODE0=$(unit_pid oxpanel-app-vnode.test.service); VPHP0=$(unit_pid oxpanel-php-victim1.service)
global_oom0=$(journalctl -k -b --no-pager | grep -c 'kernel: Out of memory' || true)
for rt in node py php; do
  case $rt in node) h=anode.test; path=/memhog;; py) h=apy.test; path=/memhog;; php) h=aphp.test; path='/probe.php?do=memhog';; esac
  oom0=$(oom_kills)
  curl -s -m 60 -o /dev/null -H "Host: $h" "http://127.0.0.1$path" || true
  check "$rt memory bomb was killed by the tenant's cgroup (oom_kill $oom0 -> $(oom_kills))" test "$(oom_kills)" -gt "$oom0"
done
check "the victim's sites kept answering and their processes are the same ones" bash -c "victim_ok && [ $(unit_pid oxpanel-app-vnode.test.service) = $VNODE0 ] && [ $(unit_pid oxpanel-php-victim1.service) = $VPHP0 ]"
check "no host-wide out-of-memory kill happened" test "$(journalctl -k -b --no-pager | grep -c 'kernel: Out of memory' || true)" = "$global_oom0"
eventually "the attacker's Node.js site came back by itself (Restart=on-failure)" 40 0.5 bash -c "curl -s -H 'Host: anode.test' http://127.0.0.1/x | grep -q node-attacker"
eventually "the attacker's Python site came back by itself" 40 0.5 bash -c "curl -s -H 'Host: apy.test' http://127.0.0.1/x | grep -q python-attacker"

echo "-- 5b. fork bombs"
wait_no_sleepers() { for _ in $(seq 1 60); do pgrep -u attack1 -x sleep >/dev/null || return 0; sleep 1; done; return 1; }
pids_max_events() { awk '/^max /{print $2}' "$(cg)/pids.events"; }
for rt in node py php; do
  case $rt in node) h=anode.test; path=/fork;; py) h=apy.test; path=/fork;; php) h=aphp.test; path='/probe.php?do=fork';; esac
  m0=$(pids_max_events); peak=0
  ( curl -s -m 90 -o /dev/null -H "Host: $h" "http://127.0.0.1$path" ) &
  worst=0
  for _ in $(seq 1 20); do
    n=$(systemctl show -p TasksCurrent --value $SLICE); [ "$n" -gt "$peak" ] 2>/dev/null && peak=$n
    t0=$(date +%s%N); victim_ok; vok=$?; ms=$(( ($(date +%s%N) - t0) / 1000000 )); [ "$ms" -gt "$worst" ] && worst=$ms
    [ "$vok" = 0 ] || break
    sleep 0.3
  done
  check "$rt fork bomb: the victim's three sites answered throughout (slowest round ${worst} ms)" test "$vok" = 0 -a "$worst" -lt 8000
  check "$rt fork bomb: the engine API answers during it" timeout 10 oxpanel-ctl host info
  wait
  # pids.current is charged before the limit is checked and uncharged on failure: one or two over is the accounting, not an escape.
  check "$rt fork bomb: the tenant never exceeded TasksMax (peak $peak of 200, tolerance 8)" test "$peak" -le 208
  check "$rt fork bomb: the kernel refused forks (pids.events max $m0 -> $(pids_max_events))" test "$(pids_max_events)" -gt "$m0"
  # The bomb's children are the tenant's own tasks until reaped (a parent that never waits leaves zombies): restart the unit that ran it.
  case $rt in node) ctl vhost restart-app anode.test >/dev/null;; py) ctl vhost restart-app apy.test >/dev/null;; php) systemctl restart oxpanel-php-attack1.service;; esac
  wait_no_sleepers || info "sleepers of the $rt bomb still alive after restarting its unit"
done

echo "-- 5c. filling /tmp"
eventually "the attacker's Node.js site is up again after the bombs" 60 1 bash -c "curl -s -H 'Host: anode.test' http://127.0.0.1/x | grep -q node-attacker"
eventually "the attacker's Python site is up again after the bombs" 60 1 bash -c "curl -s -H 'Host: apy.test' http://127.0.0.1/x | grep -q python-attacker"
free0=$(df --output=avail -B1M / | tail -1)
out="$(get anode.test /tmpfill)"
check "the tenant could write 200 MiB into its private /tmp ($out)" grep -q 'filled 209715200' <<<"$out"
free1=$(df --output=avail -B1M / | tail -1)
info "GAP (docs/SECURITY.md): the private /tmp is on the root file system and has no quota; free space fell by $((free0 - free1)) MiB"
check "the file is not in the host's /tmp" test ! -e /tmp/fill
check "the other applications' /tmp are separate (the Python site cannot see it)" bash -c "! curl -s -H 'Host: apy.test' http://127.0.0.1/tmplist | grep -q fill"
ctl vhost restart-app anode.test >/dev/null
check "restarting the application discards its private /tmp" bash -c '! find /var/tmp -name fill 2>/dev/null | grep -q .'
get aphp.test '/probe.php?do=tmpfill' >/dev/null
check "PHP's private /tmp is per tenant unit, not the host's" test ! -e /tmp/fill
systemctl restart oxpanel-php-attack1.service; sleep 1
check "restarting the PHP instance discards its /tmp too" bash -c '! find /var/tmp -name fill 2>/dev/null | grep -q .'
eventually "the attacker's sites answer after the resource attacks" 40 0.5 bash -c "curl -s -H 'Host: anode.test' http://127.0.0.1/x | grep -q node-attacker"

# ------------------------------------------------------------------ 6. suspension and deletion must end everything
echo "-- 6. processes must not outlive suspension, removal of the site, or deletion"
n0=0
for h in anode.test apy.test; do
  get "$h" /spawn >/dev/null; sleep 1; n1=$(pgrep -u attack1 -x sleep | wc -l)
  check "$h started a detached background process ($n0 -> $n1 sleepers)" test "$n1" -gt "$n0"; n0=$n1
done
get aphp.test '/probe.php?do=spawn' >/dev/null; sleep 1; n1=$(pgrep -u attack1 -x sleep | wc -l)
check "PHP started a detached background process ($n0 -> $n1 sleepers)" test "$n1" -gt "$n0"
check "suspend attack1" bash -c "oxpanel-ctl tenant suspend attack1 | grep -q 'suspended=true'"
sleep 2
check "after suspension no process of the tenant remains (detached children included)" bash -c "! pgrep -u attack1 >/dev/null"
check "suspended: every attacker site answers 503" bash -c "for h in aphp.test anode.test apy.test; do [ \"\$(curl -s -o /dev/null -w '%{http_code}' -H \"Host: \$h\" http://127.0.0.1/)\" = 503 ] || exit 1; done"
check "suspended: the PHP instance is stopped" bash -c "! systemctl -q is-active oxpanel-php-attack1.service"
check "suspended: the victim is unaffected" victim_ok
check "resume attack1" bash -c "oxpanel-ctl tenant resume attack1 | grep -q 'suspended=false'"
eventually "after resume the attacker's Node.js site works again" 40 0.5 bash -c "curl -s -H 'Host: anode.test' http://127.0.0.1/x | grep -q node-attacker"
for h in anode.test apy.test; do get "$h" /spawn >/dev/null; done
get aphp.test '/probe.php?do=spawn' >/dev/null; sleep 1
check "remove the attacker's three sites" bash -c "for d in aphp.test anode.test apy.test; do oxpanel-ctl vhost remove \$d | grep -q '^removed=true' || exit 1; done"
sleep 2
check "after the sites are removed no process of the tenant remains" bash -c "! pgrep -u attack1 >/dev/null"
check "no unit, socket or runtime directory of the removed sites remains" bash -c "! ls /etc/systemd/system/oxpanel-app-a-*.service /etc/systemd/system/oxpanel-php-attack1.service /run/oxpanel-app/a-* /run/oxpanel-php/attack1 >/dev/null 2>&1"
check "the removed sites answer nothing (connection closed)" bash -c "[ \"\$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: anode.test' http://127.0.0.1/)\" = 000 ]"
check "delete attack1" bash -c "oxpanel-ctl tenant delete attack1 --remove-home | grep -q '^deleted=true'"
check "no file owned by the deleted tenant's uid is left on the root file system" bash -c "! find / -xdev -uid $AUID 2>/dev/null | grep -q ."
check "no process of the deleted uid remains" bash -c "! pgrep -u $AUID >/dev/null"

# ------------------------------------------------------------------ wrap up
echo "-- wrap up"
check "the victim's sites are still fine" victim_ok
check "no drift after the whole phase" bash -c "oxpanel-ctl host reconcile | grep -q '^drifts=0$'"
check "daemon still active" daemon_active
check "no daemon errors in the journal" bash -c '! journalctl -b -u oxpanel-daemon -p err --no-pager | grep -q oxpanel-daemon'
check "nginx -t still clean" nginx -t
check "remove the victim's and the suspended tenant's sites" bash -c "for d in vphp.test vnode.test vpy.test susp.test; do oxpanel-ctl vhost remove \$d | grep -q '^removed=true' || exit 1; done"
check "delete victim1 and susp1" bash -c "oxpanel-ctl tenant delete victim1 --remove-home | grep -q deleted=true && oxpanel-ctl tenant delete susp1 --remove-home | grep -q deleted=true"
rm -f "$P" /root/acc/raw.req

# AVC accounting: see the header of this file.
AVC1=$(avc_count)
if [ "$AVC1" -gt "$AVC0" ]; then
  info "$((AVC1 - AVC0)) AVC denial(s) during this phase:"
  ausearch --input-logs -m avc -ts "$START_TIME" -i 2>/dev/null | grep '^type=AVC' | tee "$LOG/avc.txt" | sed 's/^/    /' | cut -c1-260
  # source is tenant code, or the target is an object of tenant code (a system daemon refusing to write to a tenant's pipe)
  other=$(grep -v -E 'scontext=[a-z_]+:[a-z_]+:(httpd_t|oxpanel_app_t)|tcontext=[a-z_]+:[a-z_]+:(httpd_t|oxpanel_app_t)' "$LOG/avc.txt" | grep -c . || true)
  nginx_self=$(grep -E 'scontext=[a-z_]+:[a-z_]+:httpd_t' "$LOG/avc.txt" | grep -c 'comm=nginx' || true)
  check "every denial is of tenant code (httpd_t PHP / oxpanel_app_t), none of the daemon, init or nginx itself ($other other, $nginx_self nginx)" test "$other" = 0 -a "$nginx_self" = 0
  info "each denial above is an attack that plain Unix permissions would have allowed and SELinux stopped: see docs/SECURITY.md"
else
  ok "zero AVC denials: every attack was already refused by Unix permissions, cgroups or the service sandbox"
fi
phase_end
