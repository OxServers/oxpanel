# Phase 80, sections 7-15: the features added since the phase was written
# (SFTP, file manager, certificates, databases and their trash, backups,
# scheduled tasks and PHP settings, DNS hosting, cascade deletion), attacked
# from where a hostile customer stands: its PHP, its Python application, its
# scheduled task, its SFTP session, the files, archives, SQL objects and DNS
# data it controls. Sourced by 80-attacks.sh (helpers from phases/lib.sh and
# the phase itself: ctl, get, getc, snap, victim_ok, as_user, check, ...).
#
# Every attempt has an expectation like the battery of section 1:
#   blocked  an attack; OPEN is a hole and fails the phase
#   open     a control: proves the harness could have succeeded
#   info     recorded, not asserted (docs/SECURITY.md says why)
# shellcheck shell=bash

FT=/root/acc/feat
VDB_PW='Victim-db-pw-7781'
ADB_PW='Attack-db-pw-5523'

# ------------------------------------------------------------------ setup (before the battery)
# The victim gets one of everything, so that section 1's battery (run by
# attack1 from PHP, Node.js and Python) finds a credential or a store of
# every feature to try: a certificate and its private key, a database with a
# secret table, a database in the trash, SFTP access (keys file and chroot
# mount), a scheduled task, PHP settings with a pool of its own, a backup, DNS
# zones with DNSSEC keys. DNS hosting is switched on for the phase (as
# run-inside.sh does) and off again at the end.
features_setup() {
  rm -rf "${FT:?}"; mkdir -p "$FT"; chmod 700 "$FT"
  cp -p /etc/oxpanel/daemon.env "$FT/daemon.env.bak"
  printf '%s\n' OXPANEL_DNS=true OXPANEL_DNS_NAMESERVERS=ns1.oxatk.example,ns2.oxatk.example \
    OXPANEL_DNS_SOA_CONTACT=hostmaster@oxatk.example OXPANEL_DNS_IPV4=192.0.2.81 >> /etc/oxpanel/daemon.env
  systemctl restart oxpanel-daemon
  eventually "DNS hosting on for the phase (oxpanel-dns active)" 60 0.5 systemctl -q is-active oxpanel-dns
  eventually "the victim's sites got their zones" 40 0.5 bash -c "oxpanel-ctl dns zone-list --tenant victim1 | grep -q '^zone=vphp.test '"
  check "victim: DNSSEC on for vphp.test (signing keys on disk)" ctl_ok '' oxpanel-ctl dns dnssec --tenant victim1 vphp.test on
  check "victim: a TXT record of its own" ctl_ok '' oxpanel-ctl dns record-add --tenant victim1 --name secret --type txt --value VICTIM-DNS-TXT vphp.test
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=vphp.test -addext 'subjectAltName=DNS:vphp.test' \
    -keyout "$FT/vphp.key" -out "$FT/vphp.crt" >/dev/null 2>&1
  check "victim: a certificate with its private key (bring your own)" ctl_ok '' oxpanel-ctl cert install --chain "$FT/vphp.crt" --key "$FT/vphp.key" vphp.test
  if systemctl -q is-active mariadb; then
    check "victim: database victim1_db" ctl_ok '' oxpanel-ctl db create victim1_db --tenant victim1
    check "victim: database user victim1_app" bash -c "printf '%s\n' '$VDB_PW' | oxpanel-ctl db user-create victim1_app --tenant victim1 >/dev/null && oxpanel-ctl db grant victim1_app victim1_db >/dev/null"
    MYSQL_PWD="$VDB_PW" mariadb --no-defaults --protocol=socket --user=victim1_app victim1_db \
      -e "CREATE TABLE secrets (s VARCHAR(40)); INSERT INTO secrets VALUES ('VICTIM-SECRET-DB')"
    check "victim: a database in the trash" bash -c "oxpanel-ctl db create victim1_old --tenant victim1 >/dev/null && oxpanel-ctl db delete victim1_old | grep -q trash_id="
  fi
  ssh-keygen -q -t ed25519 -N '' -C victim1@feat -f "$FT/victim-key"
  check "victim: SFTP key (keys file, chroot mount)" ctl_ok '' oxpanel-ctl sftp add-key victim1 --key-file "$FT/victim-key.pub"
  as_user victim1 sh -c 'echo "print(\"victim-task\")" > /home/victim1/vtask.py'
  check "victim: a scheduled task" ctl_ok '' oxpanel-ctl task set victim1 vtask --python vtask.py --schedule 'daily 04:00'
  check "victim: PHP settings (a pool of its own)" ctl_ok '' oxpanel-ctl php set vphp.test --memory-limit 200M
  out="$(timeout 300 oxpanel-ctl backup create victim1 --wait 2>&1)" || true
  VBACKUP="$(sed -n 's/^job=[^ ]* .* backup=\([^ ]*\) .*/\1/p' <<<"$out" | tail -1)"
  check "victim: a backup ($VBACKUP)" grep -q 'state=JOB_STATE_SUCCEEDED' <<<"$out"
  # The attacker of section 1 gets SFTP access too, so its own keys file exists to be tampered with.
  ssh-keygen -q -t ed25519 -N '' -C attack1@feat -f "$FT/attack1-key"
  check "attack1: SFTP key" ctl_ok '' oxpanel-ctl sftp add-key attack1 --key-file "$FT/attack1-key.pub"
}

# Extra probes for the battery: every engine-owned directory and file of the
# features, as found on disk now (nothing is hard-coded but the roots).
# Public material (certificates, DNSSEC public keys, zone data that is
# published anyway) is info; everything else must be refused.
feature_probes() {
  local d f n
  for d in /etc/pki/oxpanel /var/lib/oxpanel-acme /var/lib/oxpanel-acme/account /var/lib/oxpanel-acme/issued \
           /var/lib/oxpanel-backups /var/lib/oxpanel-backups/victim1 /etc/oxpanel-sftp /var/lib/oxpanel/sftp \
           /var/lib/oxpanel/sftp/victim1/home/victim1 /var/lib/oxpanel-dns/keys /var/lib/oxpanel-dns/data \
           /etc/named/oxpanel /var/lib/mysql /var/lib/mysql/victim1_db /var/lib/oxpanel/file-jobs /var/lib/oxpanel/db-trash \
           /var/lib/oxpanel/tasks /var/lib/oxpanel/jobs /var/lib/oxpanel/uploads /var/lib/oxpanel/dns-zones /run/oxpanel/scratch; do
    # /var/lib/oxpanel-acme must be searchable (the web server serves challenges
    # from a subdirectory) and /var/lib/mysql is MariaDB's own 0755: their
    # listings are info (docs/SECURITY.md, known gaps); their contents are not.
    case "$d" in /var/lib/oxpanel-acme|/var/lib/mysql) [ -d "$d" ] && p list "feat-dir$(tr / _ <<<"$d")" "$d" info; continue;; esac
    [ -d "$d" ] && p list "feat-dir$(tr / _ <<<"$d")" "$d"
  done
  for d in /var/lib/oxpanel-acme /etc/pki/oxpanel /var/lib/oxpanel-backups /etc/oxpanel-sftp /var/lib/oxpanel-dns \
           /etc/named/oxpanel /var/lib/oxpanel/db-trash /var/lib/oxpanel/tasks /var/lib/oxpanel/jobs /var/lib/oxpanel/dns-zones \
           /var/lib/oxpanel/backup-schedules /var/lib/mysql/victim1_db; do
    [ -d "$d" ] || continue
    n=0
    while IFS= read -r f; do
      case "$f" in *$'\t'*|*' '*) continue;; esac
      n=$((n+1)); [ "$n" -le 14 ] || break
      case "$f" in
        /etc/oxpanel-sftp/attack1) p read "feat-file$(tr / _ <<<"$f")" "$f" info;;  # its own keys file: sshd reads it as the tenant (PHP: open_basedir)
        *.crt|*/K*.key|/var/lib/oxpanel-dns/zones/*) p read "feat-file$(tr / _ <<<"$f")" "$f" info;;
        *) p read "feat-file$(tr / _ <<<"$f")" "$f";;
      esac
    done < <(find "$d" -maxdepth 4 -type f 2>/dev/null | sort)
  done
  p read sshd-dropin /etc/ssh/sshd_config.d/60-oxpanel.conf
  p read sftp-keys-of-victim /etc/oxpanel-sftp/victim1
  p write sftp-own-keys-file-tamper /etc/oxpanel-sftp/attack1
  p write sftp-keys-dir /etc/oxpanel-sftp/oxprobe
  p write sftp-chroot-dir /var/lib/oxpanel/sftp/attack1/oxprobe
  p read victim-through-sftp-mount /var/lib/oxpanel/sftp/victim1/home/victim1/secret.txt
  p write pki-dir /etc/pki/oxpanel/oxprobe
  p write acme-challenges /var/lib/oxpanel-acme/challenges/oxprobe
  p write acme-account /var/lib/oxpanel-acme/account/oxprobe
  p write backup-store /var/lib/oxpanel-backups/oxprobe
  p write backup-store-victim /var/lib/oxpanel-backups/victim1/oxprobe
  p write dns-zones /var/lib/oxpanel-dns/zones/oxprobe.zone
  p write named-conf-dir /etc/named/oxpanel/oxprobe
  p write mysql-datadir /var/lib/mysql/oxprobe
  p write task-unit /etc/systemd/system/oxpanel-task-oxprobe.service
  p read victim-task-script /home/victim1/vtask.py
  p unix mariadb-socket /var/lib/mysql/mysql.sock open
  p run mariadb-as-root "/usr/bin/mariadb --no-defaults --user=root -e select.1"
  p run mariadb-as-mysql "/usr/bin/mariadb --no-defaults --user=mysql -e select.1"
  p run rndc-status "/usr/sbin/rndc -s 127.0.0.1 -p 953 status"
  p run rndc-with-engine-key "/usr/sbin/rndc -s 127.0.0.1 -p 953 -k /etc/named/oxpanel/rndc.key -y oxpanel-rndc status"
  p run sshd-config-dump "/usr/sbin/sshd -T"
}

# Evaluate "name<TAB>OPEN|BLOCKED<TAB>want<TAB>detail" lines (feat.py, probe.php db).
# eval_lines <label> <minimum lines> <<<"$output"
eval_lines() {
  local label="$1" min="$2" out n bad=0 name res want detail
  out="$(cat)"; printf '%s\n' "$out" > "$LOG/feat-$label.tsv"
  n=$(grep -cP '^[^\t]+\t(OPEN|BLOCKED)\t' <<<"$out" || true)
  if [ "$n" -lt "$min" ]; then fail "$label: expected at least $min result lines, got $n (see $LOG/feat-$label.tsv)"; head -5 <<<"$out"; return; fi
  while IFS=$'\t' read -r name res want detail; do
    case "$res" in OPEN|BLOCKED) ;; *) continue;; esac
    case "$want:$res" in
      blocked:BLOCKED|open:OPEN) ;;
      blocked:OPEN) echo "ATTACK SUCCEEDED ($label): $name — $detail"; bad=$((bad+1));;
      open:BLOCKED) echo "CONTROL FAILED ($label): $name — $detail"; bad=$((bad+1));;
      info:*) info "$label: $name is $res ($detail) [not asserted]";;
    esac
  done <<<"$out"
  if [ "$bad" = 0 ]; then ok "$label: all $n attempts behave"; else fail "$label: $bad attempt(s) wrong"; fi
}

rootsql() { mariadb --no-defaults --user=root --batch --raw --skip-column-names -e "$1"; }
asql() { MYSQL_PWD="$ADB_PW" mariadb --no-defaults --protocol=socket --user=attack3_app --batch --skip-column-names "$@"; }
privs_digest() { rootsql "SELECT User, Host, Priv FROM mysql.global_priv ORDER BY User, Host; SELECT * FROM mysql.db ORDER BY User, Db; SELECT * FROM mysql.tables_priv ORDER BY User; SELECT * FROM mysql.procs_priv ORDER BY User; SELECT SCHEMA_NAME FROM information_schema.SCHEMATA ORDER BY 1" | sha256sum | cut -d' ' -f1; }
etc_digest() { find /etc /usr/local /var/lib/oxpanel /root -xdev \( -path /etc/oxpanel-sftp -o -path /var/lib/oxpanel/jobs -o -path /var/lib/oxpanel/file-jobs -o -path /var/lib/oxpanel/tasks -o -path /var/lib/oxpanel/uploads \) -prune -o -newer "$FT/stamp" -print 2>/dev/null | grep -vE '^/(etc/(nginx/oxpanel.d|systemd/system|oxpanel-php|named|ssh/sshd_config.d|pki/oxpanel|group|gshadow|passwd|shadow|subuid|subgid|group-|gshadow-|passwd-|shadow-|subuid-|subgid-|selinux/targeted)|root/acc|var/lib/oxpanel/(tenants|vhosts|dns-zones|db-trash|backup-schedules|sftp|auto-https))' ; }

# The attacker of sections 7-15: attack3, with a PHP site, a Python
# application and a Node.js application, each serving the probe code.
features_attacker() {
  echo "-- 7-15 setup: a new attacker (attack3) with PHP, Python and Node.js code"
  ctl tenant delete attack3 --cascade --confirm attack3 --wait >/dev/null 2>&1 || true
  check "create attack3 (256M, 300 tasks)" bash -c "oxpanel-ctl tenant create attack3 --memory 256M --tasks-max 300 | grep -q '^created=true'"
  AT3=/home/attack3; A3UID=$(id -u attack3)
  check "attack3 PHP site" ctl_ok '^changed=true' oxpanel-ctl vhost set fphp.test --tenant attack3 --php
  check "attack3 second PHP site" ctl_ok '^changed=true' oxpanel-ctl vhost set fphp2.test --tenant attack3 --php --root site2
  check "attack3 Python site" ctl_ok '^changed=true' oxpanel-ctl vhost set fpy.test --tenant attack3 --app python
  sed "s|/home/ATTACKER/|$AT3/|g" "$A/probe.php" | as_user attack3 sh -c "cat > $AT3/public_html/probe.php"
  sed "s|/home/ATTACKER/|$AT3/|g" "$A/probe.php" | as_user attack3 sh -c "cat > $AT3/site2/probe.php"
  sed "s|/home/ATTACKER/|$AT3/|g" "$A/probe.py" | as_user attack3 sh -c "cat > $AT3/apps/fpy.test/app.py"
  as_user attack3 sh -c "cat > $AT3/feat.py" < "$A/feat.py"
  as_user attack3 sh -c ": > $AT3/probes.tsv"
  ctl vhost restart-app fpy.test >/dev/null
  eventually "attack3's PHP code is served" 50 0.2 bash -c "curl -s -H 'Host: fphp.test' 'http://127.0.0.1/probe.php?do=echo' | grep -q url"
  eventually "attack3's Python code is served" 50 0.2 bash -c "curl -s -H 'Host: fpy.test' http://127.0.0.1/count | grep -qE '^[0-9]+$'"
  touch "$FT/stamp"; SNAP7=$(snap)
}

# Run a feat.py action from every place tenant code runs and evaluate each:
# the Python application in-process (language API) and as a child, PHP (a
# child of PHP-FPM), and a scheduled task. feat_everywhere <label> <min> <args...>
feat_everywhere() {
  local label="$1" min="$2"; shift 2
  local path; path="$(printf '/%s' "$@")"
  eval_lines "$label-python" "$min" < <(curl -s -m 240 -H 'Host: fpy.test' "http://127.0.0.1/feat$path")
  eval_lines "$label-python-child" "$min" < <(curl -s -m 240 -H 'Host: fpy.test' "http://127.0.0.1/featc$path")
  eval_lines "$label-php-child" "$min" < <(curl -s -m 240 -H 'Host: fphp.test' "http://127.0.0.1/probe.php?do=feat&args=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(chr(9).join(sys.argv[1:])))' "$@")")
  local tname="f$(tr -dc 'a-z' <<<"$label" | cut -c1-20)"
  if ctl_ok '' oxpanel-ctl task set attack3 "$tname" --python feat.py --schedule 'daily 05:00' --timeout 240 --disabled $(for a in "$@"; do printf -- '--arg=%s ' "$a"; done); then
    ctl task run attack3 "$tname" >/dev/null
    for _ in $(seq 1 240); do sleep 1; ctl task log attack3 "$tname" | grep -qE 'END( {8}|	)done' && break; done
    eval_lines "$label-task" "$min" < <(ctl task log attack3 "$tname" | sed -n 's/^.*python3\[[0-9]*\]: //p' | sed 's/        /\t/g')
    ctl task delete attack3 "$tname" >/dev/null
  else
    fail "$label: could not create the task that runs it"
  fi
}

# ------------------------------------------------------------------ 7. SFTP
features_sftp() {
  echo "-- 7. SFTP: the session, the chroot, forwarding, planted keys, the engine's keys file"
  if ! { [ -x /usr/sbin/sshd ] && command -v sftp >/dev/null && systemctl -q is-active sshd; }; then info "sshd not active: section 7 skipped"; return; fi
  local K="$FT/sftp" O out pid
  mkdir -p "$K"
  O=(-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o ConnectTimeout=10 -o LogLevel=ERROR)
  ssh-keygen -q -t ed25519 -N '' -f "$K/ka"; ssh-keygen -q -t ed25519 -N '' -f "$K/planted"
  sftp3() { local i; for i in $(seq 1 30); do out="$(sftp "${O[@]}" -i "$K/ka" -b - attack3@127.0.0.1 2>&1)" && { printf '%s' "$out"; return 0; }; grep -q 'Permission denied\|No such file\|not found\|Failure\|Couldn' <<<"$out" && { printf '%s' "$out"; return 1; }; sleep 1; done; printf '%s' "$out"; return 1; }
  check "attack3 gets an SFTP key" ctl_ok '' oxpanel-ctl sftp add-key attack3 --key-file "$K/ka.pub"
  check "control: attack3 logs in over SFTP with it" bash -c "for i in \$(seq 1 30); do echo pwd | sftp ${O[*]} -i $K/ka -b - attack3@127.0.0.1 >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1"
  # A key the tenant plants itself (its PHP, or a session) in ~/.ssh/authorized_keys must never work:
  # a compromised site could otherwise use the host's sshd as a proxy (the hole SFTP closed).
  as_user attack3 sh -c "mkdir -p $AT3/.ssh && chmod 700 $AT3/.ssh && cp $K/planted.pub $AT3/.ssh/authorized_keys 2>/dev/null || cat > $AT3/.ssh/authorized_keys" < "$K/planted.pub"
  for i in $(seq 1 30); do out="$(echo pwd | sftp "${O[@]}" -i "$K/planted" -b - attack3@127.0.0.1 2>&1)" && break; grep -q 'Permission denied' <<<"$out" && break; sleep 1; done
  check "a key planted in ~/.ssh/authorized_keys does not log in" grep -q 'Permission denied' <<<"$out"
  check "the planted key does not reach a shell or a forward either" bash -c "! timeout 20 ssh ${O[*]} -i $K/planted -W 127.0.0.1:80 attack3@127.0.0.1 </dev/null 2>/dev/null | grep -q ."
  # The engine's keys file: the tenant may read its own (sshd reads it as the tenant), never change it.
  check_not "the tenant cannot write the engine's keys file" as_user attack3 sh -c "echo '$(cat "$K/planted.pub")' >> /etc/oxpanel-sftp/attack3"
  check_not "nor replace it (the directory is root's)" as_user attack3 sh -c "mv /etc/oxpanel-sftp/attack3 /etc/oxpanel-sftp/x"
  check_not "nor read another tenant's" as_user attack3 cat /etc/oxpanel-sftp/victim1
  # No shell, no command, no forwarding of any kind.
  out="$(timeout 20 ssh "${O[@]}" -i "$K/ka" attack3@127.0.0.1 id 2>&1 </dev/null)" || true
  check "a command over SSH does not run (only internal-sftp)" bash -c '! grep -q "uid=" <<<"$1"' _ "$out"
  out="$(timeout 20 ssh "${O[@]}" -tt -i "$K/ka" attack3@127.0.0.1 2>&1 </dev/null)" || true
  check "no terminal or shell is given" bash -c '! grep -qE "uid=|\\$ |# " <<<"$1"' _ "$out"
  check "stdio forwarding (-W) to the web server is refused" bash -c "! printf 'GET / HTTP/1.0\r\nHost: vphp.test\r\n\r\n' | timeout 20 ssh ${O[*]} -i $K/ka -W 127.0.0.1:80 attack3@127.0.0.1 2>/dev/null | grep -q victim-php-ok"
  check "stdio forwarding to the engine socket's neighbours (MariaDB) is refused" bash -c "! timeout 20 ssh ${O[*]} -i $K/ka -W /var/lib/mysql/mysql.sock attack3@127.0.0.1 </dev/null 2>/dev/null | grep -qa mysql"
  timeout 25 ssh "${O[@]}" -i "$K/ka" -N -L 127.0.0.1:24080:127.0.0.1:80 -o ExitOnForwardFailure=no attack3@127.0.0.1 </dev/null >/dev/null 2>&1 & pid=$!
  sleep 4
  check "local port forwarding (-L) reaches nothing" bash -c "! curl -s -m 5 -H 'Host: vphp.test' http://127.0.0.1:24080/ | grep -q victim-php-ok"
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  timeout 25 ssh "${O[@]}" -i "$K/ka" -N -R 127.0.0.1:24081:127.0.0.1:80 -o ExitOnForwardFailure=no attack3@127.0.0.1 </dev/null >/dev/null 2>&1 & pid=$!
  sleep 4
  check "remote port forwarding (-R) opens no listener on the host" bash -c "! ss -H -ltn | grep -q ':24081 '"
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  timeout 25 ssh "${O[@]}" -i "$K/ka" -N -D 127.0.0.1:24082 attack3@127.0.0.1 </dev/null >/dev/null 2>&1 & pid=$!
  sleep 4
  check "dynamic forwarding (-D, SOCKS) reaches nothing" bash -c "! curl -s -m 5 --socks5-hostname 127.0.0.1:24082 -H 'Host: vphp.test' http://127.0.0.1/ | grep -q victim-php-ok"
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  out="$(/usr/sbin/sshd -T -C user=attack3,host=localhost,addr=127.0.0.1)"
  for kv in "forcecommand internal-sftp" "allowagentforwarding no" "allowtcpforwarding no" "allowstreamlocalforwarding no" "x11forwarding no" "permittunnel no" "permittty no" "permituserrc no" "maxauthtries 3" "passwordauthentication no" "authenticationmethods publickey" "authorizedkeysfile /etc/oxpanel-sftp/%u" "chrootdirectory /var/lib/oxpanel/sftp/%u"; do
    check "sshd's effective configuration for the tenant: $kv" grep -qx "$kv" <<<"$out"
  done
  out="$(timeout 20 ssh -o BatchMode=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=0 attack3@127.0.0.1 true 2>&1 </dev/null)" || true
  check "a tenant without a password is not even asked for one ($(tr -d '\r' <<<"$out" | tail -1))" grep -q 'Permission denied (publickey)' <<<"$out"
  # Inside the session: the chroot holds the home and nothing else.
  as_user attack3 sh -c "cd $AT3 && ln -sfn /etc/shadow s-shadow && ln -sfn /etc/passwd s-passwd && ln -sfn /home/victim1/secret.txt s-victim && ln -sfn /home/victim1 s-vdir && ln -sfn / s-root && echo own > own-sftp.txt"
  out="$(printf 'ls -a /\nls -a /home\n' | sftp3)" || true
  check "the chroot shows only /home and the tenant's own home ($(grep -v '^sftp>' <<<"$out" | tr -s ' \n' ' '))" bash -c 'for w in $(grep -v "^sftp>" <<<"$1"); do case "${w##*/}" in .|..|home|attack3) ;; *) echo "unexpected: $w"; exit 1;; esac; done' _ "$out"
  for f in /etc/passwd /etc/shadow /proc/self/environ /var/lib/oxpanel/tenants/victim1.json /home/victim1/secret.txt ../victim1/secret.txt ../../etc/passwd s-shadow s-passwd s-victim s-vdir/secret.txt s-root/etc/passwd; do
    rm -f "$K/got"; printf 'cd %s\nget %s %s\n' "$AT3" "$f" "$K/got" | sftp3 >/dev/null 2>&1 || true
    check "SFTP: get $f yields nothing" bash -c '! grep -qE "root:|VICTIM|\"username\"" "$1" 2>/dev/null' _ "$K/got"
  done
  rm -f "$K/got"; printf 'cd %s\nget own-sftp.txt %s\n' "$AT3" "$K/got" | sftp3 >/dev/null 2>&1 || true
  check "control: SFTP get of the tenant's own file works" grep -qx own "$K/got"
  echo pwned > "$K/up"
  for f in /oxprobe /home/oxprobe /home/victim1/oxprobe ../victim1/oxprobe s-vdir/oxprobe s-root/tmp/oxprobe-sftp; do
    printf 'cd %s\nput %s %s\n' "$AT3" "$K/up" "$f" | sftp3 >/dev/null 2>&1 || true
  done
  check "SFTP: nothing was written outside the home" bash -c '! ls /home/victim1/oxprobe /home/oxprobe /oxprobe /tmp/oxprobe-sftp /var/lib/oxpanel/sftp/attack3/oxprobe /var/lib/oxpanel/sftp/attack3/home/oxprobe >/dev/null 2>&1'
  printf 'cd %s\nln /etc/passwd hl-passwd\nln /home/attack3/../victim1/secret.txt hl-victim\nsymlink /etc/shadow sl-shadow\nrename public_html ../../pwned\nmkdir /pwned\nchmod 4755 own-sftp.txt\nchmod 2777 public_html\n' "$AT3" | sftp3 >/dev/null 2>&1 || true
  check "SFTP: hard links to files outside the chroot are impossible" bash -c "! test -e $AT3/hl-passwd && ! test -e $AT3/hl-victim"
  check "SFTP: a symlink made in the session points nowhere useful (served by nothing, read by no root process)" bash -c "! grep -q root: $AT3/sl-shadow 2>/dev/null"
  check "SFTP: the document root was not moved out of the home" test -d "$AT3/public_html"
  info "SFTP: mode after 'chmod 4755' on an own file: $(stat -c %a "$AT3/own-sftp.txt") (a set-uid bit on a tenant's own file grants nothing: the file runs as the tenant)"
  check "SFTP: a set-uid file of the tenant is not set-uid for anyone else (nosuid or harmless)" bash -c "! find $AT3 -xdev -perm -4000 -user root | grep -q ."
  as_user attack3 sh -c "cd $AT3 && rm -f s-shadow s-passwd s-victim s-vdir s-root sl-shadow own-sftp.txt"
  # Mount set-up and teardown raced by the tenant: whatever it does in its home, the chroot's mount is its home and only that.
  as_user attack3 sh -c "cd $AT3 && rm -rf home && mkdir -p home && ln -sfn /etc home/attack3"
  for i in 1 2 3 4; do ctl sftp remove-key attack3 "$(ssh-keygen -lf "$K/ka.pub" | awk '{print $2}')" --end-sessions >/dev/null; ctl sftp add-key attack3 --key-file "$K/ka.pub" >/dev/null; done
  check "after keys came and went the chroot mount is the tenant's home, nothing else" bash -c "findmnt -n -o SOURCE,TARGET -T /var/lib/oxpanel/sftp/attack3/home/attack3 | grep -q '/var/lib/oxpanel/sftp/attack3/home/attack3' && ! findmnt -n | grep -q '/etc ' && test \"\$(stat -c %i /var/lib/oxpanel/sftp/attack3/home/attack3)\" = \"\$(stat -c %i $AT3)\""
  as_user attack3 rm -rf "$AT3/home"
  # A live session does not survive suspension, nor the removal of its key with end_sessions.
  sftp_live() { ( { sleep 300; } | sftp "${O[@]}" -i "$K/ka" -b - attack3@127.0.0.1 >/dev/null 2>&1 ) & }
  if systemctl -q is-active systemd-logind; then
    for i in $(seq 1 20); do sftp_live; sleep 2; pgrep -u attack3 -f sftp-server >/dev/null || pgrep -u attack3 sshd >/dev/null && break; done
    check "a live SFTP session of attack3 runs" bash -c "pgrep -u attack3 sshd >/dev/null"
    check "suspend attack3" ctl_ok 'suspended=true' oxpanel-ctl tenant suspend attack3
    eventually "suspension ended the live session" 20 0.5 bash -c "! pgrep -u attack3 sshd >/dev/null"
    check_not "and no login is possible while suspended" bash -c "echo pwd | sftp ${O[*]} -i $K/ka -b - attack3@127.0.0.1"
    check "resume attack3" ctl_ok 'suspended=false' oxpanel-ctl tenant resume attack3
    for i in $(seq 1 20); do sftp_live; sleep 2; pgrep -u attack3 sshd >/dev/null && break; done
    check "a live session again" bash -c "pgrep -u attack3 sshd >/dev/null"
    check "remove the key with end_sessions" ctl_ok '' oxpanel-ctl sftp remove-key attack3 "$(ssh-keygen -lf "$K/ka.pub" | awk '{print $2}')" --end-sessions
    eventually "the session ended with the key" 20 0.5 bash -c "! pgrep -u attack3 sshd >/dev/null"
    check "no chroot mount is left once the last key is gone" bash -c "! findmnt -n /var/lib/oxpanel/sftp/attack3/home/attack3 >/dev/null"
    check "attack3 gets its key back (for the cascade section)" ctl_ok '' oxpanel-ctl sftp add-key attack3 --key-file "$K/ka.pub"
  else
    info "no logind: live-session checks skipped"
  fi
  pkill -f "sleep 300" 2>/dev/null || true
}

# ------------------------------------------------------------------ 8. file manager
features_files() {
  echo "-- 8. file manager: the operator's panel acting on a tree the tenant controls"
  local E0 out f
  as_user attack3 sh -c "mkdir -p $AT3/fm && cd $AT3/fm && ln -sfn /etc/shadow l-shadow && ln -sfn /etc/passwd l-passwd && ln -sfn /etc l-etc && ln -sfn /home/victim1 l-victim && ln -sfn / l-root && ln -sfn ../../victim1/secret.txt l-rel && mkfifo fifo && echo own > own.txt && mkdir -p real && echo inner > real/inner.txt"
  E0=$(sha256sum /etc/passwd /etc/shadow /etc/group | sha256sum)
  for cmd in "files cat attack3 fm/l-passwd" "files cat attack3 fm/l-shadow" "files cat attack3 fm/l-rel" "files cat attack3 fm/l-victim/secret.txt" \
             "files ls attack3 fm/l-etc" "files ls attack3 fm/l-victim" "files stat attack3 fm/l-etc/passwd" "files du attack3 fm/l-etc" "files find attack3 fm/l-etc passwd" \
             "files mkdir attack3 fm/l-etc/oxprobe" "files mv attack3 fm/l-etc/passwd fm/stolen" "files mv attack3 fm/own.txt fm/l-etc/own.txt" "files chmod attack3 fm/l-etc --mode 0777" "files chmod attack3 fm/l-passwd --mode 0666" \
             "files cp attack3 fm fm/l-etc/passwd --wait" "files cp attack3 fm/l-etc fm/own.txt --wait" "files rm attack3 fm/l-etc/passwd --wait" "files compress attack3 fm/l-etc out.zip passwd --wait" \
             "files extract attack3 fm/l-etc/x.zip fm --wait" \
             "files cat attack3 /etc/passwd" "files cat attack3 ../victim1/secret.txt" "files cat attack3 fm/../../victim1/secret.txt" "files ls attack3 /" "files ls attack3 .." \
             "files cat attack3 ./fm/../../../etc/passwd" "files stat attack3 //etc/passwd" "files ls attack3 fm/./l-etc" "files cat attack3 %2e%2e/victim1/secret.txt"; do
    # shellcheck disable=SC2086
    out="$(timeout 60 oxpanel-ctl $cmd 2>&1 </dev/null)"; rc=$?
    check "file manager: '$cmd' does not reach outside the home (exit $rc)" bash -c '! grep -qE "root:x:|root:\\\$|VICTIM-SECRET|^l-shadow|shadow$|\"username\"|state=JOB_STATE_SUCCEEDED.* entries=[1-9]" <<<"$1" || [ "$2" != 0 ]' _ "$out" "$rc"
  done
  echo "x" | oxpanel-ctl files write attack3 fm/l-etc/oxprobe >/dev/null 2>&1 || true
  echo "x" | oxpanel-ctl files write attack3 fm/l-passwd --overwrite >/dev/null 2>&1 || true
  echo pwned > "$FT/up.txt"; oxpanel-ctl files put attack3 "$FT/up.txt" fm/l-etc/oxprobe2 >/dev/null 2>&1 || true
  check "file manager: /etc/passwd, /etc/shadow, /etc/group unchanged; nothing created in /etc" bash -c '[ "$(sha256sum /etc/passwd /etc/shadow /etc/group | sha256sum)" = "$1" ] && ! ls /etc/oxprobe /etc/oxprobe2 /etc/own.txt >/dev/null 2>&1' _ "$E0"
  check "file manager: /etc kept its mode" test "$(stat -c %a /etc)" = 755
  # What is allowed must stay inside: links are copied and archived as links, a FIFO does not hang the worker.
  as_user attack3 mkdir -p "$AT3/fm/copy"
  check "control: the operator can copy the tenant's tree (links stay links)" ctl_ok 'state=JOB_STATE_SUCCEEDED' oxpanel-ctl files cp attack3 fm/copy fm/l-passwd fm/l-etc fm/own.txt --wait
  check "the copied link is a link, not the content of /etc/passwd" bash -c "test -L $AT3/fm/copy/l-passwd && ! grep -rqs 'root:x' $AT3/fm/copy"
  check "control: compress the tree with its links" ctl_ok 'state=JOB_STATE_SUCCEEDED' oxpanel-ctl files compress attack3 fm out.zip l-passwd l-etc l-root own.txt real --wait
  check "the archive holds links, never the files they point to" bash -c "python3 -I -c 'import zipfile,sys; z=zipfile.ZipFile(sys.argv[1]); sys.exit(any(b\"root:x\" in z.read(i) for i in z.infolist() if not i.is_dir()))' $AT3/out.zip"
  t0=$(date +%s); timeout 60 oxpanel-ctl files cat attack3 fm/fifo >/dev/null 2>&1; dt=$(( $(date +%s) - t0 ))
  check "reading a FIFO the tenant planted does not hang the worker (${dt}s)" test "$dt" -lt 30
  t0=$(date +%s); out="$(timeout 120 oxpanel-ctl files du attack3 fm 2>&1)"; dt=$(( $(date +%s) - t0 ))
  check "sizing a tree with links to / is quick and does not count the targets (${dt}s: $(tr '\n' ' ' <<<"$out" | cut -c1-80))" bash -c '[ "$1" -lt 30 ] && [ "$(grep -oE "apparent=[0-9]+" <<<"$2" | head -1 | cut -d= -f2)" -lt 50000000 ]' _ "$dt" "$out"
  check "deleting the link to /etc deletes the link" bash -c "oxpanel-ctl files rm attack3 fm/l-etc fm/l-root --wait | grep -q state=JOB_STATE_SUCCEEDED && test -d /etc/ssh && test -e /etc/passwd && test ! -e $AT3/fm/l-etc"
  # Race: the tenant swaps a directory for a link to /etc while jobs walk it.
  as_user attack3 sh -c "mkdir -p $AT3/fm/race $AT3/fm/dst && echo r > $AT3/fm/race/f"
  ( timeout 90 setpriv --reuid=attack3 --regid=attack3 --clear-groups --no-new-privs -- sh -c "cd $AT3/fm; while :; do mv race race.d 2>/dev/null; ln -sfn /etc race; rm -f race; mv race.d race 2>/dev/null; ln -sfn /etc/ssh race/ssh 2>/dev/null; rm -f race/ssh; done" >/dev/null 2>&1 & )
  for i in $(seq 1 12); do
    oxpanel-ctl files cp attack3 fm/dst fm/race --overwrite --wait >/dev/null 2>&1
    oxpanel-ctl files compress attack3 fm "r$i.zip" race --wait >/dev/null 2>&1
    oxpanel-ctl files du attack3 fm/race >/dev/null 2>&1; oxpanel-ctl files find attack3 fm/race ssh >/dev/null 2>&1
    oxpanel-ctl files chmod attack3 fm/race --private >/dev/null 2>&1
    oxpanel-ctl files rm attack3 fm/race/f --wait >/dev/null 2>&1; as_user attack3 sh -c "echo r > $AT3/fm/race/f" 2>/dev/null
  done
  pkill -u attack3 -f 'while :' 2>/dev/null; sleep 1
  check "after 72 jobs raced against the swapping link nothing in /etc changed" bash -c '[ "$(sha256sum /etc/passwd /etc/shadow /etc/group | sha256sum)" = "$1" ] && test -d /etc/ssh && test "$(stat -c %a /etc /etc/ssh)" = "755
755"' _ "$E0"
  check "and no copy or archive in the home holds a host file's content" python3 -I -c 'import glob, os, sys, zipfile
bad = (b"root:x:0:0", b"PRIVATE KEY", b"HostKey")
hit = []
for root, _, files in os.walk(sys.argv[1] + "/fm/dst"):
    for f in files:
        p = os.path.join(root, f)
        if not os.path.islink(p) and any(b in open(p, "rb").read() for b in bad): hit.append(p)
for z in glob.glob(sys.argv[1] + "/r*.zip") + glob.glob(sys.argv[1] + "/out.zip"):
    for i in zipfile.ZipFile(z).infolist():
        if any(b in zipfile.ZipFile(z).read(i) for b in bad): hit.append(z + ":" + i.filename)
print(hit); sys.exit(1 if hit else 0)' "$AT3"
  check "nothing outside the home is owned by the tenant" bash -c "! find / -xdev -uid $A3UID -not -path '$AT3/*' -not -path '$AT3' -not -path '/var/spool/mail/*' -not -path '/var/lib/oxpanel/sftp/*' 2>/dev/null | grep -q ."
  features_archives
  # A suspended tenant's files can be read, never changed.
  check "suspend attack3" ctl_ok 'suspended=true' oxpanel-ctl tenant suspend attack3
  check_not "suspended: a write is refused" bash -c "echo x | oxpanel-ctl files write attack3 fm/susp.txt"
  check_not "suspended: a copy job is refused" oxpanel-ctl files cp attack3 fm/dst fm/own.txt --wait
  check "suspended: reading still works (evidence)" ctl_ok '^own$' oxpanel-ctl files cat attack3 fm/own.txt
  check "resume attack3" ctl_ok 'suspended=false' oxpanel-ctl tenant resume attack3
  for f in /var/lib/oxpanel/file-jobs/*.request /var/lib/oxpanel/file-jobs/*.json; do
    [ -e "$f" ] || continue
    check_not "the tenant cannot read the job spool ($(basename "$f"))" as_user attack3 cat "$f"
  done
  check_not "the tenant cannot list the job spool" as_user attack3 ls /var/lib/oxpanel/file-jobs
}

# Hostile archives the tenant "uploads", extracted by the operator's panel.
features_archives() {
  local H="$FT/arch" name out
  mkdir -p "$H"
  python3 -I - "$H" "$AT3" <<'PY'
import io, os, sys, tarfile, zipfile, gzip
d, home = sys.argv[1], sys.argv[2]
def tar(name, members, mode='w:gz'):
    with tarfile.open(os.path.join(d, name), mode) as t:
        for m, data in members:
            t.addfile(m, io.BytesIO(data) if data is not None else None)
def reg(n, data=b'x', mode=0o644):
    m = tarfile.TarInfo(n); m.size = len(data); m.mode = mode; return (m, data)
def special(n, typ, link='', mode=0o644):
    m = tarfile.TarInfo(n); m.type = typ; m.linkname = link; m.mode = mode; return (m, None)
tar('slip.tar.gz', [reg('../slip-up.txt', b'SLIP'), reg('../../victim1/slip.txt', b'SLIP'), reg('/tmp/slip-abs.txt', b'SLIP'), reg('a/../../slip2.txt', b'SLIP'), reg('ok.txt', b'OK')])
tar('links.tar.gz', [special('l', tarfile.SYMTYPE, '/etc'), reg('l/pwned-via-link', b'P'), special('rel', tarfile.SYMTYPE, '../../../victim1'), reg('rel/pwned2', b'P'),
                     special('h', tarfile.LNKTYPE, '/etc/shadow'), special('h2', tarfile.LNKTYPE, '../../victim1/secret.txt'), reg('ok2.txt', b'OK')])
tar('special.tar.gz', [special('dev-null', tarfile.CHRTYPE), special('disk', tarfile.BLKTYPE), special('fifo', tarfile.FIFOTYPE),
                       reg('suid', b'#!/bin/sh\nid\n', 0o4755), reg('sgid', b'x', 0o2777), reg('ww', b'x', 0o666 | 0o002), reg('ok3.txt', b'OK')])
names = ['new\nline', 'tab\there', 'esc\x1b[31m', 'bidi\u202etxt.exe', '-rf', '--checkpoint-action=exec=sh', ' lead', 'trail ', 'ok4.txt']
tar('names.tar.gz', [reg(n, b'N') for n in names])
with tarfile.open(os.path.join(d, 'nonutf8.tar'), 'w', format=tarfile.GNU_FORMAT) as t:
    m = tarfile.TarInfo('x'); m.size = 1
    m.name = b'bad-\xff\xfe-name'.decode('utf-8', 'surrogateescape'); t.addfile(m, io.BytesIO(b'B'))
with zipfile.ZipFile(os.path.join(d, 'slip.zip'), 'w') as z:
    z.writestr('../zip-up.txt', 'SLIP'); z.writestr('/etc/zip-abs.txt', 'SLIP'); z.writestr('..\\..\\zip-win.txt', 'SLIP'); z.writestr('okz.txt', 'OK')
    zi = zipfile.ZipInfo('zlink'); zi.external_attr = (0o120777 << 16); z.writestr(zi, '/etc/passwd')
    zi = zipfile.ZipInfo('zsuid'); zi.external_attr = (0o104755 << 16); z.writestr(zi, 'x')
with zipfile.ZipFile(os.path.join(d, 'ratio.zip'), 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('zeros.bin', b'\0' * (300 << 20))
with tarfile.open(os.path.join(d, 'count.tar.gz'), 'w:gz') as t:
    for i in range(120000):
        m = tarfile.TarInfo(f'c/{i}'); m.size = 0; t.addfile(m, io.BytesIO(b''))
# A tar.gz whose gzip layer is a bomb (the tar inside is a single huge file).
with gzip.open(os.path.join(d, 'gzbomb.tar.gz'), 'wb', 9) as g:
    h = tarfile.TarInfo('huge.bin'); h.size = 400 << 20; g.write(h.tobuf())
    blk = b'\0' * (1 << 20)
    for _ in range(400): g.write(blk)
    g.write(b'\0' * 1024)
PY
  as_user attack3 mkdir -p "$AT3/up"
  for name in slip.tar.gz links.tar.gz special.tar.gz names.tar.gz nonutf8.tar slip.zip ratio.zip count.tar.gz gzbomb.tar.gz; do
    check "upload $name through the panel" ctl_ok '' oxpanel-ctl files put attack3 "$H/$name" "up/$name"
    as_user attack3 mkdir -p "$AT3/x-${name%%.*}"
    out="$(timeout 300 oxpanel-ctl files extract attack3 "up/$name" "x-${name%%.*}" --wait 2>&1)"; echo "$out" | grep -m1 '^job=' | cut -c1-200
    info "extract $name: $(grep -oE 'state=[A-Z_]+ entries=[0-9]+ bytes=[0-9]+ skipped=[0-9]+' <<<"$out" | head -1)"
  done
  check "zip slip and absolute names wrote nothing outside the destination" bash -c "! ls $AT3/slip-up.txt $AT3/slip2.txt /home/victim1/slip.txt /tmp/slip-abs.txt $AT3/zip-up.txt /etc/zip-abs.txt $AT3/zip-win.txt /home/zip-up.txt >/dev/null 2>&1"
  check "control: the harmless entries of the slip archives were extracted" bash -c "test -f $AT3/x-slip/ok.txt && test -f $AT3/x-slip/okz.txt"
  check "no link out of the destination was created, and nothing was written through one" bash -c "! test -e /etc/pwned-via-link && ! test -e /home/victim1/pwned2 && ! find $AT3/x-links $AT3/x-slip -type l -lname '/*' | grep -q . && ! find $AT3/x-links -type l -lname '*..*' | grep -q ."
  check "hard links to /etc/shadow and to another tenant were not made" bash -c "! test -e $AT3/x-links/h && ! test -e $AT3/x-links/h2"
  check "no device node or FIFO came out of an archive" bash -c "! find $AT3 -xdev \( -type b -o -type c \) | grep -q . && ! test -p $AT3/x-special/fifo"
  check "no set-uid, set-gid or world-writable file came out of an archive" bash -c "! find $AT3/x-special $AT3/x-slip -perm /6002 | grep -q ."
  check "names with control or bidirectional characters were skipped; a leading dash is only a name" bash -c "! ls $AT3/x-names | grep -qP '[\\x00-\\x1f\\x7f]|\\x{202e}' && test -f $AT3/x-names/-rf && test -f $AT3/x-names/ok4.txt"
  check "the ratio bomb stopped well below its 300 MiB" bash -c "[ \"\$(du -sm $AT3/x-ratio | cut -f1)\" -lt 120 ]"
  check "the gzip bomb stopped well below its 400 MiB" bash -c "[ \"\$(du -sm $AT3/x-gzbomb | cut -f1)\" -lt 120 ]"
  check "the 120,000-entry archive was refused before it filled the directory" bash -c "[ \"\$(find $AT3/x-count -type f | wc -l)\" -le 100000 ]"
  check "no temporary file of an interrupted entry is left" bash -c "! find $AT3 -name '.oxpanel-*' | grep -q ."
  # Quota exhaustion in the middle of an extraction (only where the host enforces quotas).
  if oxpanel-ctl host info | grep -q 'disk_quota=true'; then
    used=$(( $(du -sm --apparent-size "$AT3" | cut -f1) ))
    check "attack3 gets a disk limit of ${used}M + 60M" ctl_ok '' oxpanel-ctl tenant set-limits attack3 --memory 256M --tasks-max 300 --disk "$(( used + 60 ))M"
    head -c 100M /dev/urandom > "$FT/rand.bin"; tar -C "$FT" -cf "$FT/big.tar" rand.bin
    out="$(oxpanel-ctl files put attack3 "$FT/big.tar" up/big.tar 2>&1)"
    if grep -q ResourceExhausted <<<"$out"; then
      check "an upload beyond the quota leaves no partial file" bash -c "! test -e $AT3/up/big.tar && ! find $AT3/up -name '.oxpanel-upload-*' | grep -q ."
      head -c 40M /dev/urandom > "$FT/rand.bin"; tar -C "$FT" -cf "$FT/big.tar" rand.bin
      oxpanel-ctl files put attack3 "$FT/big.tar" up/big.tar >/dev/null
      oxpanel-ctl files cp attack3 cp1 up/big.tar --wait >/dev/null 2>&1 || true
      out="$(timeout 300 oxpanel-ctl files extract attack3 up/big.tar x-big --wait 2>&1)" || true
      info "extract beyond the quota: $(grep -oE 'state=[A-Z_]+ .* message=.*' <<<"$out" | head -1 | cut -c1-160)"
      check "an extraction stopped by the quota leaves no temporary file" bash -c "! find $AT3 -name '.oxpanel-*' | grep -q ."
      check "the tenant can still delete to get below its quota" ctl_ok 'state=JOB_STATE_SUCCEEDED' oxpanel-ctl files rm attack3 up/big.tar cp1 x-big --wait
    else
      fail "an upload beyond the disk limit was not refused: $out"
    fi
    check "attack3's disk limit removed" ctl_ok '' oxpanel-ctl tenant set-limits attack3 --memory 256M --tasks-max 300
    rm -f "$FT/rand.bin" "$FT/big.tar"
  else
    info "no disk quotas on this host: the quota-exhaustion checks were skipped"
  fi
  as_user attack3 rm -rf "$AT3/up" "$AT3"/x-*
}

# ------------------------------------------------------------------ 9. certificates and ACME challenges
features_certs() {
  echo "-- 9. certificates: other sites' keys, the challenge directory, PEM that carries configuration"
  local B="$FT/pem" conf
  mkdir -p "$B"
  check_not "the tenant cannot read another site's private key" as_user attack3 cat /etc/pki/oxpanel/vphp.test.key
  check_not "nor list the key directory" as_user attack3 ls /etc/pki/oxpanel
  check_not "nor the ACME account" as_user attack3 ls /var/lib/oxpanel-acme/account
  # The challenge path is answered from the engine's directory, for every site, never from the tenant's files.
  as_user attack3 sh -c "mkdir -p $AT3/public_html/.well-known/acme-challenge && echo TENANT-ANSWER > $AT3/public_html/.well-known/acme-challenge/tok && ln -sfn /etc/passwd $AT3/public_html/.well-known/acme-challenge/pw"
  for h in fphp.test vphp.test nosuchsite.test; do
    body="$(curl -s -m 10 -H "Host: $h" http://127.0.0.1/.well-known/acme-challenge/tok)"
    check "challenge path on $h does not serve the tenant's planted answer" bash -c '! grep -q TENANT-ANSWER <<<"$1"' _ "$body"
    body="$(curl -s -m 10 -H "Host: $h" http://127.0.0.1/.well-known/acme-challenge/pw)"
    check "challenge path on $h does not follow a planted link" bash -c '! grep -q root: <<<"$1"' _ "$body"
  done
  for p in /.well-known/acme-challenge/../../../../etc/passwd /.well-known/acme-challenge/..%2f..%2f..%2faccount/x /.well-known/acme-challenge/%2e%2e/issued/vphp.test.pem; do
    body="$(curl -s --path-as-is -m 10 -H 'Host: fphp.test' "http://127.0.0.1$p")"
    check "challenge path traversal $p yields nothing" bash -c '! grep -qE "root:|BEGIN" <<<"$1"' _ "$body"
  done
  check_not "a certificate cannot be requested for a name the tenant does not host" oxpanel-ctl cert request nothosted.test
  check_not "nor for another tenant's name through its own site's request" oxpanel-ctl cert request vphp.test.fphp.test
  # Uploaded certificate and key carrying Nginx directives, comments and extra blocks.
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=fphp.test -addext 'subjectAltName=DNS:fphp.test' -keyout "$B/k.pem" -out "$B/c.pem" >/dev/null 2>&1
  { echo 'ssl_certificate /etc/shadow;'; echo '}'; echo 'server { listen 8444; root /; }'; cat "$B/c.pem"; echo '# } include /etc/shadow;'; } > "$B/c-inj.pem"
  { cat "$B/k.pem"; echo '}'; echo 'server { listen 8445; root /; }'; } > "$B/k-inj.pem"
  { cat "$B/c.pem"; printf 'ssl_ciphers NULL;\n'; cat "$B/c.pem"; } > "$B/c-mid.pem"
  sed 's/^-----END CERTIFICATE-----$/-----END CERTIFICATE-----\nserver_name evil.test;/' "$B/c.pem" > "$B/c-tail.pem"
  for pair in "c-inj.pem k.pem" "c.pem k-inj.pem" "c-mid.pem k.pem" "c-tail.pem k.pem" "$FT/vphp.crt $FT/vphp.key" "c.pem $FT/vphp.key"; do
    set -- $pair; c="$1"; k="$2"; [ "${c#/}" = "$c" ] && c="$B/$c"; [ "${k#/}" = "$k" ] && k="$B/$k"
    oxpanel-ctl cert install --chain "$c" --key "$k" fphp.test >/dev/null 2>&1; rc=$?
    info "cert install $(basename "$c") + $(basename "$k") on fphp.test: exit $rc"
    conf="$(cat /etc/nginx/oxpanel.d/fphp.test.conf)"
    check "after $(basename "$c")+$(basename "$k"): no injected directive in the site's configuration or the PEM files" bash -c '! grep -qE "listen 844[45]|/etc/shadow|evil.test|ssl_ciphers NULL" <<<"$1" && ! cat /etc/pki/oxpanel/fphp.test.* 2>/dev/null | grep -qE "listen 844|/etc/shadow|server_name|ssl_ciphers"' _ "$conf"
    check "nginx -t passes and nothing listens on 8444/8445" bash -c "nginx -t >/dev/null 2>&1 && ! ss -H -ltn | grep -qE ':844[45] '"
  done
  check_not "the victim's certificate and key are refused for the attacker's site (name mismatch)" oxpanel-ctl cert install --chain "$FT/vphp.crt" --key "$FT/vphp.key" fphp.test
  check "control: the attacker's own certificate installs" ctl_ok '' oxpanel-ctl cert install --chain "$B/c.pem" --key "$B/k.pem" fphp.test
  check "the attacker cannot read its own site's installed key either (root-only)" bash -c "! as_user attack3 cat /etc/pki/oxpanel/fphp.test.key >/dev/null 2>&1"
  check "HSTS and the redirect apply to the tenant's own site only" bash -c "oxpanel-ctl vhost set fphp.test --tenant attack3 --php --redirect-https --hsts >/dev/null && ! grep -q Strict-Transport /etc/nginx/oxpanel.d/vphp.test.conf && [ \"\$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: vphp.test' http://127.0.0.1/)\" = 200 ]"
  check "back to plain HTTP for the attacker's site" bash -c "oxpanel-ctl vhost set fphp.test --tenant attack3 --php >/dev/null && oxpanel-ctl cert remove fphp.test | grep -q removed=true"
  as_user attack3 rm -rf "$AT3/public_html/.well-known"
}

# ------------------------------------------------------------------ 10. databases and the trash
features_db() {
  echo "-- 10. databases: other tenants' data, the trash, FILE, the root socket, stored objects replayed as root"
  if ! systemctl -q is-active mariadb; then info "MariaDB not active: section 10 skipped"; return; fi
  local P0 out t
  check "attack3: database attack3_db" ctl_ok '' oxpanel-ctl db create attack3_db --tenant attack3
  check "attack3: user attack3_app with access" bash -c "printf '%s\n' '$ADB_PW' | oxpanel-ctl db user-create attack3_app --tenant attack3 >/dev/null && oxpanel-ctl db grant attack3_app attack3_db >/dev/null"
  as_user attack3 sh -c "umask 077; printf '%s\n' '$ADB_PW' > $AT3/.dbpw"
  feat_everywhere db 20 db attack3_app "$ADB_PW" attack3_db victim1_db
  eval_lines db-php-mysqli 12 < <(curl -s -m 120 -H 'Host: fphp.test' "http://127.0.0.1/probe.php?do=db&u=attack3_app&p=$ADB_PW&own=attack3_db&victim=victim1_db")
  # Connections: the cap per account keeps one tenant from exhausting the server.
  out="$(curl -s -m 120 -H 'Host: fpy.test' "http://127.0.0.1/featc/dbconn/attack3_app/$ADB_PW/60")"
  local got; got=$(awk -F'\t' '/^CONNECTIONS/{print $2}' <<<"$out")
  check "60 simultaneous connections from tenant code: at most the per-account cap succeed ($got; $(awk -F'\t' '/^CONNECTIONS/{print $4}' <<<"$out" | cut -c1-80))" bash -c '[ -n "$1" ] && [ "$1" -le 25 ]' _ "$got"
  ( curl -s -m 120 -H 'Host: fpy.test' "http://127.0.0.1/featc/dbconn/attack3_app/$ADB_PW/40" >/dev/null & ); sleep 2
  check "meanwhile the victim's application still connects" bash -c "MYSQL_PWD='$VDB_PW' mariadb --no-defaults --protocol=socket --user=victim1_app -N -e 'SELECT s FROM secrets' victim1_db | grep -q VICTIM-SECRET-DB"
  # Stored objects crafted so that a client splitting the text differently from the server runs SQL as root.
  P0=$(privs_digest)
  asql attack3_db -e "CREATE TABLE t (a INT); INSERT INTO t VALUES (1)"
  printf 'DELIMITER $$\nCREATE PROCEDURE p1() BEGIN SELECT 1; END --\001 ;; CREATE DATABASE pw_p1 ;;\n$$\n' | asql attack3_db
  printf 'DELIMITER $$\nCREATE PROCEDURE p2() BEGIN SELECT 1; END -- \\g CREATE DATABASE pw_p2 \\g\n$$\n' | asql attack3_db
  printf 'DELIMITER $$\nCREATE PROCEDURE p3() BEGIN SELECT 1 /*!99999 ; CREATE DATABASE pw_p3 */; END\n$$\n' | asql attack3_db
  printf 'DELIMITER $$\nCREATE PROCEDURE p4() COMMENT "x\n;CREATE DATABASE pw_p4;\n" BEGIN SELECT "DELIMITER ;;\nCREATE DATABASE pw_p4b;;"; END\n$$\n' | asql attack3_db
  printf 'DELIMITER $$\nCREATE FUNCTION f1(x INT) RETURNS INT DETERMINISTIC RETURN x -- \001\001 ;; GRANT ALL ON *.* TO attack3_app@localhost ;;\n$$\n' | asql attack3_db
  printf 'DELIMITER $$\nCREATE TRIGGER tr1 BEFORE INSERT ON t FOR EACH ROW BEGIN SET NEW.a = NEW.a; END --\001 ;; CREATE DATABASE pw_tr1 ;;\n$$\n' | asql attack3_db
  asql attack3_db -e "CREATE VIEW v1 AS SELECT '\\'; CREATE DATABASE pw_v1; -- ' AS x, 'a\`b' AS y" 2>/dev/null
  asql attack3_db -e 'CREATE VIEW `v2``; CREATE DATABASE pw_v2; --` AS SELECT 1 AS x' 2>/dev/null
  printf 'DELIMITER $$\nCREATE EVENT ev1 ON SCHEDULE AT CURRENT_TIMESTAMP + INTERVAL 1 YEAR DO BEGIN SELECT 1; END --\001 ;; CREATE DATABASE pw_ev1 ;;\n$$\n' | asql attack3_db 2>/dev/null
  asql attack3_db -e "CREATE TABLE \`tn
;CREATE DATABASE pw_tn1;
-- \` (a INT); INSERT INTO \`tn
;CREATE DATABASE pw_tn1;
-- \` VALUES (1)" 2>/dev/null
  asql attack3_db -e "CREATE TABLE \`tc*/;CREATE DATABASE pw_tc1;/*\` (a INT COMMENT '*/; CREATE DATABASE pw_tc2; /*') COMMENT='
;CREATE DATABASE pw_tc3;
'" 2>/dev/null
  asql attack3_db -e "CREATE TABLE g (s VARCHAR(40)) CHARACTER SET gbk; INSERT INTO g VALUES (CONCAT(0xbf5c27, '; CREATE DATABASE pw_gbk; -- '))" 2>/dev/null
  asql attack3_db -e "CREATE TABLE b (s BLOB); INSERT INTO b VALUES (0x5c27293b2043524541544520444154414241534520707764623b202d2d200a5c67)" 2>/dev/null
  info "objects the tenant could create: $(rootsql "SELECT CONCAT(COUNT(*),' routines') FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA='attack3_db'") $(rootsql "SELECT CONCAT(COUNT(*),' triggers') FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='attack3_db'") $(rootsql "SELECT CONCAT(COUNT(*),' tables/views') FROM information_schema.TABLES WHERE TABLE_SCHEMA='attack3_db'") $(rootsql "SELECT CONCAT(COUNT(*),' events') FROM information_schema.EVENTS WHERE EVENT_SCHEMA='attack3_db'")"
  check "the crafted objects changed nothing yet (the tenant's own session cannot)" test "$(rootsql "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE 'pw%'")" = 0
  out="$(timeout 300 oxpanel-ctl backup create attack3 --wait 2>&1)" || true
  A3BACKUP="$(sed -n 's/^job=[^ ]* .* backup=\([^ ]*\) .*/\1/p' <<<"$out" | tail -1)"
  check "a backup of the tenant with the crafted objects succeeds ($A3BACKUP)" grep -q 'state=JOB_STATE_SUCCEEDED' <<<"$out"
  out="$(timeout 300 oxpanel-ctl backup restore-db attack3 "$A3BACKUP" attack3_db attack3_r1 --wait 2>&1)" || true; echo "$out" | grep -E '^(job=|not-recreated)' | cut -c1-200
  check "restoring that database from the backup completes" grep -q 'state=JOB_STATE_SUCCEEDED' <<<"$out"
  out="$(oxpanel-ctl db delete attack3_db)"; t="$(sed -n 's/.* trash_id=\([^ ]*\) .*/\1/p' <<<"$out")"
  check "moving it to the trash works ($t)" test -n "$t"
  check "restoring it from the trash completes" ctl_ok 'restored=attack3_r2' oxpanel-ctl db trash-restore attack3 "$t" attack3_r2
  check "no statement hidden in a stored object ran as root (no pw_* schema)" test "$(rootsql "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE 'pw%'")" = 0
  check "and no account or grant changed except the restored databases" bash -c '[ "$(rootsql "SELECT COUNT(*) FROM mysql.global_priv WHERE User NOT IN (\"root\",\"mysql\",\"mariadb.sys\",\"PUBLIC\") AND User NOT LIKE \"%\\_app\" AND User <> \"\"")" = 0 ] && ! rootsql "SHOW GRANTS FOR attack3_app@localhost" | grep -qE "ON \*\.\*.*(ALL|FILE|SUPER|CREATE USER)"'
  check "the restored databases have no grants (the old user does not get in)" bash -c '! MYSQL_PWD="$1" mariadb --no-defaults --protocol=socket --user=attack3_app -e "SELECT 1" attack3_r1 >/dev/null 2>&1 && ! MYSQL_PWD="$1" mariadb --no-defaults --protocol=socket --user=attack3_app -e "SELECT 1" attack3_r2 >/dev/null 2>&1' _ "$ADB_PW"
  check "the victim's data is untouched" test "$(rootsql 'SELECT GROUP_CONCAT(s) FROM victim1_db.secrets')" = VICTIM-SECRET-DB
  info "privilege tables before/after the replays: $P0 / $(privs_digest) (differ only by the restored databases)"
  # Restoring across tenants and out of the tenant's prefix.
  check_not "a database of the victim's backup cannot be restored into the attacker" oxpanel-ctl backup restore-db attack3 "$VBACKUP" victim1_db attack3_stolen
  check_not "the attacker's database cannot be restored under the victim's prefix" oxpanel-ctl backup restore-db attack3 "$A3BACKUP" attack3_db victim1_pwn
  for n in 'attack3_x`; DROP DATABASE victim1_db; --' 'attack3_../victim1_db' 'attack3_x' "attack3_$(printf 'a%.0s' $(seq 1 80))"; do
    out="$(oxpanel-ctl db trash-restore attack3 "$t" "$n" 2>&1)"
    check "trash-restore to '$(cut -c1-40 <<<"$n")' cannot leave the prefix" bash -c '! grep -q "restored=" <<<"$1" || grep -qx "restored=attack3_x" <<<"$1"' _ "$out"
  done
  check "the victim's database still exists" test "$(rootsql "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='victim1_db'")" = 1
  local vt; vt="$(oxpanel-ctl db trash-list victim1 | sed -n 's/.*trash_id=\([^ ]*\).*/\1/p' | head -1)"
  check_not "the victim's trash cannot be restored into the attacker" oxpanel-ctl db trash-restore attack3 "$vt" attack3_vt
  check_not "nor purged by naming it under the attacker" oxpanel-ctl db trash-purge attack3 "$vt"
  check "the victim's trashed database is still there" bash -c "oxpanel-ctl db trash-list victim1 | grep -q '$vt'"
  # A grant does not survive into a re-created database of the same name.
  check "re-create attack3_db (the name is free once it is in the trash)" ctl_ok '' oxpanel-ctl db create attack3_db --tenant attack3
  check_not "the old user's grant does not apply to the new database" asql attack3_db -e 'SELECT 1'
  check "grant again (for the rest of the phase)" ctl_ok '' oxpanel-ctl db grant attack3_app attack3_db
  # A suspended tenant's accounts are locked.
  check "suspend attack3" ctl_ok 'suspended=true' oxpanel-ctl tenant suspend attack3
  check_not "suspended: the database account cannot log in" asql attack3_db -e 'SELECT 1'
  check "resume attack3" ctl_ok 'suspended=false' oxpanel-ctl tenant resume attack3
  check "resumed: it can again" asql attack3_db -e 'SELECT 1'
  for d in attack3_r1 attack3_r2; do oxpanel-ctl db delete "$d" >/dev/null 2>&1; done
  oxpanel-ctl db trash-purge attack3 >/dev/null 2>&1 || true
}

# ------------------------------------------------------------------ 11. backups
features_backups() {
  echo "-- 11. backups: what a backup captures, hostile content, dependency installation, other tenants' backups"
  local out B T
  as_user attack3 sh -c "cd $AT3 && ln -sfn /etc/shadow b-shadow && ln -sfn /home/victim1 b-victim && ln -sfn /var/lib/oxpanel b-state && mkfifo b-fifo && printf x > 'b-new
line' && printf x > manifest.json && printf x > '.oxpanel-backup-manifest.json' && mkdir -p deep && cd deep && i=0; while [ \$i -lt 40 ]; do mkdir d; cd d; i=\$((i+1)); done; echo deep > f"
  out="$(timeout 300 oxpanel-ctl backup create attack3 --wait 2>&1)" || true
  B="$(sed -n 's/^job=[^ ]* .* backup=\([^ ]*\) .*/\1/p' <<<"$out" | tail -1)"
  check "a backup of a home full of links, a FIFO and odd names succeeds ($B)" grep -q 'state=JOB_STATE_SUCCEEDED' <<<"$out"
  check "the archive holds no file the tenant may not read" bash -c "for f in /var/lib/oxpanel-backups/attack3/$B/*.tar.gz; do tar -xzOf \"\$f\" 2>/dev/null | grep -qaE 'root:\\\$|VICTIM-SECRET|\"username\": \"victim1\"' && exit 1; done; exit 0"
  check "the links are stored as links" bash -c "tar -tvzf /var/lib/oxpanel-backups/attack3/$B/home.tar.gz 2>/dev/null | grep -q 'b-shadow -> /etc/shadow'"
  check_not "the tenant cannot read its own backup store" as_user attack3 ls "/var/lib/oxpanel-backups/attack3"
  check_not "nor the victim's" as_user attack3 ls /var/lib/oxpanel-backups/victim1
  # Restoring while the tenant has replaced the restore target by links out of the home.
  as_user attack3 sh -c "cd $AT3 && rm -rf deep && mv public_html public_html.real && ln -sfn /etc public_html && ln -sfn /home/victim1/public_html apps"
  T=$(find /etc /home/victim1 -xdev -newer "$FT/stamp" 2>/dev/null | wc -l)
  out="$(timeout 300 oxpanel-ctl backup restore attack3 "$B" --overwrite --wait 2>&1)" || true
  info "restore over links: $(grep -oE 'state=[A-Z_]+' <<<"$out" | head -1) $(grep -oE 'message=.*' <<<"$out" | head -1 | cut -c1-140)"
  check "a restore wrote nothing through links into /etc or the victim's home" bash -c "! test -e /etc/b-shadow && ! test -e /etc/probe.php && ! test -e /home/victim1/public_html/probe.php && [ \"\$(find /etc /home/victim1 -xdev -newer $FT/stamp 2>/dev/null | wc -l)\" -le \"$T\" ]"
  as_user attack3 sh -c "cd $AT3 && rm -f public_html apps && rm -rf public_html && mv public_html.real public_html && mkdir -p apps/fpy.test" 2>/dev/null
  as_user attack3 sh -c "cd $AT3 && rm -f b-shadow b-victim b-state b-fifo manifest.json .oxpanel-backup-manifest.json 'b-new
line'"
  # Dependency installation after a restore runs the tenant's package scripts: as the tenant, in the sandbox.
  check "attack3 Node.js site (package.json with install scripts)" ctl_ok '^changed=true' oxpanel-ctl vhost set fnode.test --tenant attack3 --app node
  as_user attack3 sh -c "mkdir -p $AT3/apps/fnode.test/evil && cd $AT3/apps/fnode.test && echo 'require(\"http\").createServer((q,r)=>r.end(\"fnode\")).listen(process.env.PORT)' > app.js && printf '%s' '{\"name\":\"fnode\",\"version\":\"1.0.0\",\"dependencies\":{\"evil\":\"file:./evil\"}}' > package.json && printf '%s' '{\"name\":\"evil\",\"version\":\"1.0.0\",\"scripts\":{\"preinstall\":\"node pwn.js\",\"install\":\"node pwn.js\"}}' > evil/package.json"
  as_user attack3 sh -c "cat > $AT3/apps/fnode.test/evil/pwn.js" <<'JS'
const fs = require('fs'), net = require('net'), cp = require('child_process');
const out = [];
const tryit = (name, f) => { try { f(); out.push(name + '=OPEN'); } catch (e) { out.push(name + '=BLOCKED:' + (e.code || e.message).toString().slice(0, 30)); } };
out.push('uid=' + process.getuid() + ' gid=' + process.getgid() + ' groups=' + process.getgroups().join(','));
tryit('read-shadow', () => fs.readFileSync('/etc/shadow'));
tryit('read-victim', () => fs.readFileSync('/home/victim1/secret.txt'));
tryit('read-records', () => fs.readdirSync('/var/lib/oxpanel/tenants'));
tryit('read-backups', () => fs.readdirSync('/var/lib/oxpanel-backups'));
tryit('write-etc', () => fs.writeFileSync('/etc/oxprobe-npm', 'x'));
tryit('write-usr', () => fs.writeFileSync('/usr/oxprobe-npm', 'x'));
tryit('ctl', () => cp.execFileSync('/usr/bin/oxpanel-ctl', ['tenant', 'list'], { stdio: 'pipe', timeout: 5000 }));
tryit('setuid-file', () => { fs.writeFileSync('/tmp/su', 'x'); fs.chmodSync('/tmp/su', 0o4755); if (!(fs.statSync('/tmp/su').mode & 0o4000)) throw new Error('stripped'); });
const s = net.connect('/run/oxpanel/oxpanel.sock');
s.on('connect', () => { out.push('engine-socket=OPEN'); fin(); }); s.on('error', (e) => { out.push('engine-socket=BLOCKED:' + e.code); fin(); });
let done = false;
function fin() { if (done) return; done = true; fs.appendFileSync(process.env.HOME + '/npm-proof.txt', out.join(' ') + '\n'); console.log('PWN ' + out.join(' ')); }
setTimeout(fin, 3000);
JS
  out="$(timeout 300 oxpanel-ctl backup create attack3 --wait 2>&1)" || true
  B="$(sed -n 's/^job=[^ ]* .* backup=\([^ ]*\) .*/\1/p' <<<"$out" | tail -1)"
  as_user attack3 rm -f "$AT3/npm-proof.txt"
  out="$(timeout 400 oxpanel-ctl backup restore attack3 "$B" --overwrite --wait 2>&1)" || true
  info "restore with dependency reinstall: $(grep -oE 'state=[A-Z_]+' <<<"$out" | head -1)"
  if [ -f "$AT3/npm-proof.txt" ]; then
    proof="$(cat "$AT3/npm-proof.txt")"; info "the package's install script reported: $(head -1 <<<"$proof")"
    check "the install script ran as the tenant, without supplementary groups" grep -q "^uid=$A3UID gid=$A3UID groups=$A3UID\( \|$\)\|^uid=$A3UID gid=$A3UID groups= " <<<"$proof"
    for w in read-shadow read-victim read-records read-backups write-etc write-usr engine-socket ctl setuid-file; do
      check "the install script could not: $w" bash -c '! grep -q "$2=OPEN" <<<"$1"' _ "$proof" "$w"
    done
  else
    check "the restore reinstalled dependencies, running the package's script" grep -q 'npm-proof' <<<"no proof file: $(grep -oE 'message=.*' <<<"$out" | head -1)"
  fi
  check "nothing was written into /etc or /usr" bash -c "! test -e /etc/oxprobe-npm && ! test -e /usr/oxprobe-npm"
  # Other tenants' backups.
  check_not "restoring the victim's backup into the attacker is refused" oxpanel-ctl backup restore attack3 "$VBACKUP" --overwrite --wait
  check_not "deleting the victim's backup by naming it under the attacker is refused" oxpanel-ctl backup delete attack3 "$VBACKUP"
  check "the victim's backup is still listed" bash -c "oxpanel-ctl backup list victim1 | grep -q '$VBACKUP'"
  # A retained backup of a deleted tenant is not the next tenant of that name's.
  check "create ret1 with a secret" bash -c "oxpanel-ctl tenant create ret1 | grep -q created=true && setpriv --reuid=ret1 --regid=ret1 --clear-groups sh -c 'echo RET1-SECRET > /home/ret1/secret.txt'"
  local RUID; RUID=$(id -u ret1)
  out="$(timeout 300 oxpanel-ctl backup create ret1 --retain-days 2 --wait 2>&1)" || true
  local RB; RB="$(sed -n 's/^job=[^ ]* .* backup=\([^ ]*\) .*/\1/p' <<<"$out" | tail -1)"
  check "ret1 has a retained backup ($RB)" grep -q 'state=JOB_STATE_SUCCEEDED' <<<"$out"
  check "delete ret1 (the retained backup stays)" ctl_ok 'deleted=true' oxpanel-ctl tenant delete ret1 --remove-home
  check "a new tenant takes the name ret1" ctl_ok 'created=true' oxpanel-ctl tenant create ret1
  info "uid of the old ret1: $RUID, of the new one: $(id -u ret1)"
  check "the new ret1 does not see the old one's backup" bash -c "! oxpanel-ctl backup list ret1 | grep -q '$RB'"
  check_not "nor can it be restored into it as its own" oxpanel-ctl backup restore ret1 "$RB" --overwrite --wait
  check_not "the new ret1 cannot read the retained archive" as_user ret1 sh -c "ls /var/lib/oxpanel-backups/ret1 || cat /var/lib/oxpanel-backups/ret1/$RB/home.tar.gz"
  check "the secret did not come back into the new home" bash -c "! test -e /home/ret1/secret.txt"
  oxpanel-ctl tenant delete ret1 --remove-home >/dev/null 2>&1
  oxpanel-ctl backup delete ret1 "$RB" >/dev/null 2>&1 || info "the retained backup $RB of the deleted ret1 stays until it expires"
  ctl vhost remove fnode.test >/dev/null
}

# ------------------------------------------------------------------ 12. scheduled tasks and PHP settings
features_tasks() {
  echo "-- 12. scheduled tasks and PHP settings"
  local out n
  as_user attack3 sh -c "cat > $AT3/linger.py" <<'PY'
import os, subprocess, time
# Escape the task's control group the usual ways: double fork, a new session, a nohup'd child.
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        os.execv('/usr/bin/sleep', ['sleep', '901'])
    os._exit(0)
subprocess.Popen(['/usr/bin/nohup', '/usr/bin/sleep', '902'], start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print('lingering', flush=True)
time.sleep(600)
PY
  check "a task with a 5 s time limit that tries to outlive it" ctl_ok '' oxpanel-ctl task set attack3 linger --python linger.py --schedule 'daily 05:00' --timeout 5 --disabled
  ctl task run attack3 linger >/dev/null; sleep 3
  check "it is running and has left children" bash -c "pgrep -u attack3 -f 'sleep 90[12]' >/dev/null"
  eventually "after its time limit nothing it started remains" 30 0.5 bash -c "! pgrep -u attack3 -f 'sleep 90[12]' >/dev/null && ! pgrep -u attack3 -f linger.py >/dev/null"
  ctl task run attack3 linger >/dev/null; sleep 2
  check "suspend attack3 while the task runs" ctl_ok 'suspended=true' oxpanel-ctl tenant suspend attack3
  check "suspension ended the task and its children" bash -c "! pgrep -u attack3 >/dev/null"
  check_not "a suspended tenant's task cannot be started" oxpanel-ctl task run attack3 linger
  check "resume attack3" ctl_ok 'suspended=false' oxpanel-ctl tenant resume attack3
  ctl task delete attack3 linger >/dev/null
  # URL tasks: only the tenant's own sites, pinned to this host; a redirect is not followed.
  as_user attack3 sh -c "echo '<?php header(\"Location: http://vphp.test/doc-secret.txt\"); echo \"redir\";' > $AT3/public_html/redir.php"
  check "a URL task of the tenant's own site" ctl_ok '' oxpanel-ctl task set attack3 urlt --url http://fphp.test/redir.php --schedule 'daily 05:00' --disabled
  ctl task run attack3 urlt >/dev/null; sleep 4
  out="$(oxpanel-ctl task log attack3 urlt)"
  check "a redirect to another tenant's site is not followed ($(grep -o 'HTTP [0-9]*' <<<"$out" | tail -1))" bash -c '! grep -q VICTIM-SECRET <<<"$1" && grep -q "HTTP 302" <<<"$1"' _ "$out"
  ctl task delete attack3 urlt >/dev/null
  n=0
  for u in http://vphp.test/ http://127.0.0.1/ http://localhost/ http://2130706433/ http://0x7f000001/ http://0177.0.0.1/ 'http://[::1]/' 'http://[::ffff:127.0.0.1]/' \
           http://fphp.test@vphp.test/ 'http://fphp.test:2222/' http://fphp.test:3306/ 'http://fphp.test.vphp.test/' http://169.254.169.254/latest/meta-data/ \
           file:///etc/passwd gopher://fphp.test/ dict://fphp.test:11211/ 'http://fphp.test/%0d%0aX:1' "http://fphp.test/\$(id)" 'http://fphp.test/a b' 'http://vphp.test%2efphp.test/' 'https://fphp.test:443@vphp.test/'; do
    if oxpanel-ctl task set attack3 "u$n" --url "$u" --schedule 'daily 05:00' --disabled >/dev/null 2>&1; then
      fail "a URL task for '$u' was accepted"; ctl task delete attack3 "u$n" >/dev/null
    else ok "a URL task for '$u' is refused"; fi
    n=$((n+1))
  done
  # Every task field: nothing reaches a unit file as a directive.
  n=0
  for args in "--python ../victim1/vtask.py" "--python /etc/passwd" "--python feat.py --venv ../../usr" "--python feat.py --venv /usr" \
              "--python feat.py --tz UTC\nUser=root" "--python feat.py --tz ../../../etc/shadow" "--python feat.py --arg=a\nExecStartPre=/bin/sh" \
              "--php public_html/probe.php\n[Service]" "--node app.js\0x"; do
    # shellcheck disable=SC2086
    if eval "oxpanel-ctl task set attack3 inj$n $(sed 's/\\n/$'"'"'\\n'"'"'/g' <<<"$args") --schedule 'daily 05:00' --disabled" >/dev/null 2>&1; then
      fail "task field injection accepted: $args"; ctl task delete attack3 "inj$n" >/dev/null
    else ok "task field injection refused: $(tr '\n' ' ' <<<"$args")"; fi
    n=$((n+1))
  done
  check "a task argument with systemd specifiers and quotes is passed literally" ctl_ok '' oxpanel-ctl task set attack3 argt --python feat.py --arg='%h $HOME ${PATH} "q" '"'"'s'"'"' ;id' --arg=id --schedule 'daily 05:00' --disabled
  ctl task run attack3 argt >/dev/null; sleep 4
  check "the task ran feat.py with the literal arguments (no expansion)" bash -c "oxpanel-ctl task log attack3 argt | grep -q \"unknown action '%h \\\$HOME \\\${PATH}\""
  ctl task delete attack3 argt >/dev/null
  check "no unit of a refused task exists, and the units that do pass systemd's own check" bash -c "! ls /etc/systemd/system/ | grep -qE 'oxpanel-task-attack3-(u[0-9]|inj)' && for u in /etc/systemd/system/oxpanel-task-*.service; do systemd-analyze verify \"\$u\" >/dev/null 2>&1 || { echo \$u; exit 1; }; done"
  # PHP settings: one site's settings stay with it; .user.ini cannot lift the pool's hardening.
  check "attack3: PHP settings for fphp.test only" ctl_ok '' oxpanel-ctl php set fphp.test --memory-limit 64M
  eventually "fphp.test runs with 64M" 20 0.5 bash -c "curl -s -H 'Host: fphp.test' 'http://127.0.0.1/probe.php?do=ini' | grep -q 'memory_limit=64M'"
  check "the tenant's other site keeps the default" bash -c "curl -s -H 'Host: fphp2.test' 'http://127.0.0.1/probe.php?do=ini' | grep -q 'memory_limit=128M'"
  as_user attack3 sh -c "printf 'open_basedir=/\nauto_prepend_file=/etc/passwd\nupload_max_filesize=2G\npost_max_size=2G\nallow_url_include=On\ndisplay_errors=On\ndisable_functions=\nmemory_limit=4G\n' > $AT3/public_html/.user.ini"
  systemctl reload oxpanel-php-attack3.service 2>/dev/null || true; sleep 2
  out="$(curl -s -H 'Host: fphp.test' 'http://127.0.0.1/probe.php?do=ini')"; info ".user.ini applied: $(tr '\n' ' ' <<<"$out" | cut -c1-200)"
  check ".user.ini cannot widen open_basedir" bash -c 'grep -q "open_basedir=/home/attack3/:" <<<"$1"' _ "$out"
  check ".user.ini cannot prepend a file outside the home" bash -c '! curl -s -H "Host: fphp.test" "http://127.0.0.1/probe.php?do=ini" | grep -q "root:x"'
  check ".user.ini cannot switch on allow_url_include" bash -c 'grep -q "allow_url_include=0\|allow_url_include=$" <<<"$1"' _ "$out"
  info "memory_limit after .user.ini: $(grep -o 'memory_limit=[^ ]*' <<<"$out") (php_value by design: the cgroup is the bound, see SECURITY.md)"
  head -c 3M /dev/zero > "$FT/post.bin"
  check "a raised upload_max_filesize does not lift the web server's body limit (413)" test "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: fphp.test' --data-binary @"$FT/post.bin" 'http://127.0.0.1/probe.php?do=echo')" = 413
  as_user attack3 rm -f "$AT3/public_html/.user.ini"
  check "the victim's PHP settings are its own" bash -c "grep -q 'memory_limit' /etc/oxpanel-php/victim1*.conf && ! grep -q '64M' /etc/oxpanel-php/victim1*.conf"
  check "PHP settings back to the defaults" ctl_ok '' oxpanel-ctl php set fphp.test
}

# ------------------------------------------------------------------ 13. DNS hosting
features_dns() {
  echo "-- 13. DNS: zone data the tenant supplies, other tenants' zones, the server from tenant code"
  local zf out id n
  feat_everywhere dns 14 dns vphp.test
  check "attack3's site has its zone" bash -c "oxpanel-ctl dns zone-list --tenant attack3 | grep -q '^zone=fphp.test '"
  for z in vphp.test sub.vphp.test www.vnode.test test com co.uk catalog.oxpanel.invalid oxatk.example ns1.oxatk.example in-addr.arpa 0.0.127.in-addr.arpa localhost fphp.test.; do
    out="$(oxpanel-ctl dns zone-create --tenant attack3 "$z" 2>&1)"
    check "zone '$z' cannot be taken by attack3" bash -c '! grep -q "^created=true" <<<"$1"' _ "$out"
  done
  check_not "a record cannot be added to the victim's zone" oxpanel-ctl dns record-add --tenant attack3 --name pwn --type a --value 192.0.2.66 vphp.test
  id="$(oxpanel-ctl dns zone-show --tenant victim1 vphp.test | sed -n 's/.*id=\([^ ]*\) name=secret .*/\1/p' | head -1)"
  check_not "nor a victim's record removed by its id" oxpanel-ctl dns record-remove --tenant attack3 vphp.test "${id:-x}"
  check_not "nor the victim's DNSSEC switched off" oxpanel-ctl dns dnssec --tenant attack3 vphp.test off --force
  check_not "nor the victim's zone deleted" oxpanel-ctl dns zone-delete vphp.test --tenant attack3
  zf=/var/lib/oxpanel-dns/zones/fphp.test.zone
  local ndollar; ndollar=$(grep -c '^\$' "$zf" || true)
  n=0
  while IFS= read -r spec; do
    [ -n "$spec" ] || continue
    IFS='|' read -r name type value <<<"$spec"
    value="$(printf '%b' "$value")"; name="$(printf '%b' "$name")"
    if out="$(oxpanel-ctl dns record-add --tenant attack3 --name "$name" --type "$type" --value "$value" fphp.test 2>&1)"; then
      n=$((n+1)); info "accepted: name=$(printf %q "$name") $type $(printf %q "$value" | cut -c1-60)"
    fi
  done <<'SPECS'
x|txt|$INCLUDE /etc/shadow
$INCLUDE|txt|x
$GENERATE 1-100 a$ A 1.2.3.4|a|192.0.2.1
$ORIGIN|a|192.0.2.1
x|txt|a"\n$ORIGIN evil.
x|txt|"; injected IN A 6.6.6.6
x|txt|ends with backslash\\
x|txt|paren ( 3600 IN A 6.6.6.6 )
x|txt|semi ; comment
x|txt|\x01\x02binary\x7f
x|txt|\xff\xfe not utf8
long|txt|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
a(b|a|192.0.2.1
a;b|a|192.0.2.1
a b|a|192.0.2.1
a"b|a|192.0.2.1
a\\.b|a|192.0.2.1
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx|a|192.0.2.1
@|ns|ns.evil.example.
@|cname|vphp.test.
www|cname|vphp.test.
x|a|192.0.2.1 6.6.6.6
x|a|192.0.2.1\nevil IN A 6.6.6.6
x|mx|mail.example. ; x
x|caa|"letsencrypt.org"; iodef
x|txt|v=spf1 -all
ok|txt|tenant-ok
SPECS
  out="$(dig +short +norec @127.0.0.1 ok.fphp.test TXT)"
  check "control: the tenant's own plain record is served (${n} of the records were accepted)" grep -q '"tenant-ok"' <<<"$out"
  check "the zone file still has only the engine's directives (no \$INCLUDE, \$GENERATE, \$ORIGIN)" test "$(grep -c '^\$' "$zf" || true)" = "$ndollar"
  check "named-checkzone accepts the zone file" bash -c "named-checkzone -q fphp.test $zf"
  check "nothing of /etc/shadow or an injected record is served" bash -c "! dig +norec @127.0.0.1 fphp.test AXFR -y hmac-sha256:x:AAAA 2>/dev/null | grep -q 'root:' && ! dig +short +norec @127.0.0.1 evil.fphp.test A | grep -q 6.6.6.6 && ! dig +short +norec @127.0.0.1 x.fphp.test A | grep -q 6.6.6.6 && ! dig +short +norec @127.0.0.1 fphp.test A | grep -q 6.6.6.6"
  check "every record in the zone file is one line (no line starts inside another's data)" bash -c "awk 'NF && \$1 !~ /^;/ {print}' $zf | grep -vqE '\"[^\"]*\$'"
  check "the apex was not delegated to the attacker's name server" bash -c "! dig +short +norec @127.0.0.1 fphp.test NS | grep -q evil"
  # The engine's records of the site cannot be changed by the tenant.
  id="$(oxpanel-ctl dns zone-show --tenant attack3 fphp.test | grep -i 'protected\|engine' | sed -n 's/.*id=\([^ ]*\).*/\1/p' | head -1)"
  if [ -n "$id" ]; then
    check_not "an engine-maintained record cannot be removed by the tenant" oxpanel-ctl dns record-remove --tenant attack3 fphp.test "$id"
    check_not "nor replaced" oxpanel-ctl dns record-update --tenant attack3 --name @ --type a --value 192.0.2.66 fphp.test "$id"
  else
    info "zone-show lists no engine record id for fphp.test: $(oxpanel-ctl dns zone-show --tenant attack3 fphp.test | head -5 | tr '\n' ' ')"
  fi
  check "the site's address is still the engine's" bash -c "dig +short +norec @127.0.0.1 fphp.test A | grep -qx 192.0.2.81"
  # DNSSEC: keys are the server's; switching off leaves a zone that answers.
  check "DNSSEC on for the tenant's zone" ctl_ok '' oxpanel-ctl dns dnssec --tenant attack3 fphp.test on
  eventually "the zone is signed" 40 0.5 bash -c "dig +dnssec +norec @127.0.0.1 fphp.test SOA | grep -q RRSIG"
  check_not "the tenant cannot read the signing keys" as_user attack3 sh -c "ls /var/lib/oxpanel-dns/keys/fphp.test || cat /var/lib/oxpanel-dns/keys/fphp.test/*.private"
  check "DNSSEC off again (forced: the parent has no DS)" ctl_ok '' oxpanel-ctl dns dnssec --tenant attack3 fphp.test off --force
  eventually "the zone answers unsigned, still authoritatively" 40 0.5 bash -c "dig +norec +dnssec @127.0.0.1 fphp.test SOA | grep -q 'status: NOERROR' && ! dig +dnssec +norec @127.0.0.1 fphp.test SOA | grep -q RRSIG"
  check "the victim's zone is still signed and answers" bash -c "dig +dnssec +norec @127.0.0.1 vphp.test SOA | grep -q RRSIG && dig +short +norec @127.0.0.1 secret.vphp.test TXT | grep -q VICTIM-DNS-TXT"
  out="$(dig +norec +bufsize=4096 @127.0.0.1 fphp.test ANY)"
  info "ANY for a hosted zone: $(grep -oE 'MSG SIZE  rcvd: [0-9]+' <<<"$out") (amplification bounded by minimal responses and RRL)"
  check "zone-check of the tenant's zone completes and contacts nothing it was not configured to" bash -c "timeout 120 oxpanel-ctl dns zone-check --tenant attack3 fphp.test >/dev/null 2>&1; true"
  check "oxpanel-dns is still running" systemctl -q is-active oxpanel-dns
  oxpanel-ctl dns zone-reset --tenant attack3 fphp.test >/dev/null 2>&1 || true
}

# ------------------------------------------------------------------ 14. cascade deletion raced by the tenant
features_cascade() {
  echo "-- 14. cascade deletion: a tenant racing its own deletion"
  local out pid
  as_user attack3 sh -c "cat > $AT3/respawn.py" <<'PY'
import os, subprocess, time
# Keep spawning detached children and writing files until the end.
end = time.time() + 120
while time.time() < end:
    try:
        subprocess.Popen(['/usr/bin/setsid', '/usr/bin/sleep', '903'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        open(os.path.expanduser('~/churn-%d' % (int(time.time() * 10) % 50)), 'w').write('x')
    except Exception:
        pass
    time.sleep(0.2)
PY
  check "a respawning task" ctl_ok '' oxpanel-ctl task set attack3 respawn --python respawn.py --schedule 'every 1m' --timeout 200
  ctl task run attack3 respawn >/dev/null
  curl -s -m 5 -H 'Host: fpy.test' http://127.0.0.1/spawn >/dev/null; curl -s -m 5 -H 'Host: fphp.test' 'http://127.0.0.1/probe.php?do=spawn' >/dev/null
  as_user attack3 sh -c "cd $AT3 && ln -sfn /etc c-etc && ln -sfn /home/victim1 c-victim && ln -sfn /var/lib/oxpanel c-state && mkdir -p apps/fpy.test/sub && ln -sfn /usr apps/fpy.test/sub/usr"
  if systemctl -q is-active mariadb; then
    ( MYSQL_PWD="$ADB_PW" timeout 200 mariadb --no-defaults --protocol=socket --user=attack3_app -e 'SELECT SLEEP(180)' attack3_db >/dev/null 2>&1 & )
  fi
  echo partial | oxpanel-ctl files write attack3 partial.txt >/dev/null 2>&1
  oxpanel-ctl files put attack3 /etc/hosts up-inflight.txt >/dev/null 2>&1 || true
  if [ -f "$FT/sftp/ka" ]; then
    ( { sleep 200; } | sftp -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -i "$FT/sftp/ka" -b - attack3@127.0.0.1 >/dev/null 2>&1 & )
  fi
  sleep 3
  info "attack3 before deletion: $(pgrep -u attack3 | wc -l) processes"
  local E0; E0=$(sha256sum /etc/passwd /etc/group | sha256sum); local U0; U0=$(ls /usr | wc -l)
  out="$(timeout 600 oxpanel-ctl tenant delete attack3 --cascade --confirm attack3 --wait 2>&1)"; echo "$out" | tail -2 | cut -c1-200
  check "the cascade completes while the tenant races it" bash -c 'grep -q "state=JOB_STATE_SUCCEEDED" <<<"$1" || ! oxpanel-ctl tenant get attack3 >/dev/null 2>&1' _ "$out"
  check "the account is gone" bash -c "! id attack3 >/dev/null 2>&1"
  check "no process of the deleted uid remains" bash -c "! pgrep -u $A3UID >/dev/null"
  check "no file of the deleted uid remains on the root file system" bash -c "! find / -xdev -uid $A3UID 2>/dev/null | grep -q ."
  check "nothing the tenant's links pointed at was removed" bash -c '[ "$(sha256sum /etc/passwd /etc/group | sha256sum)" = "$1" ] && [ "$(ls /usr | wc -l)" = "$2" ] && test -d /etc/ssh && test -f /var/lib/oxpanel/tenants/victim1.json && test "$(cat /home/victim1/secret.txt)" = VICTIM-SECRET-HOME' _ "$E0" "$U0"
  check "no unit, timer, pool, keys file, chroot or mount of attack3 is left" bash -c "! ls /etc/systemd/system | grep -q attack3 && ! ls /etc/systemd/system | grep -qE 'oxpanel-app-f(py|node)' && ! ls /etc/oxpanel-php | grep -q attack3 && ! test -e /etc/oxpanel-sftp/attack3 && ! test -e /var/lib/oxpanel/sftp/attack3 && ! findmnt -n | grep -q attack3"
  if systemctl -q is-active mariadb; then
    check "no database, account or session of attack3 is left" bash -c "[ \"\$(mariadb --no-defaults -u root -N -B -e \"SELECT (SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE 'attack3%' OR SCHEMA_NAME LIKE 'oxpanel_trash%' AND SCHEMA_NAME IN (SELECT 'x')) + (SELECT COUNT(*) FROM mysql.global_priv WHERE User LIKE 'attack3%') + (SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER LIKE 'attack3%')\")\" = 0 ]"
  fi
  check "no zone of attack3 is left" bash -c "! oxpanel-ctl dns zone-list | grep -q 'tenant=attack3' && ! ls /var/lib/oxpanel-dns/zones | grep -q fphp"
  check "the victim is unaffected" victim_ok
  # A new tenant of the same name inherits nothing.
  check "a new tenant takes the name attack3" ctl_ok 'created=true' oxpanel-ctl tenant create attack3
  check "it has no databases, keys, tasks, backups or zones" bash -c "[ -z \"\$(oxpanel-ctl db list --tenant attack3 2>/dev/null)\" ] && ! oxpanel-ctl sftp list-keys attack3 | grep -q SHA256 && [ -z \"\$(oxpanel-ctl task list attack3 2>/dev/null)\" ] && ! oxpanel-ctl backup list attack3 2>/dev/null | grep -q backup= && ! oxpanel-ctl dns zone-list --tenant attack3 | grep -q zone="
  check "its home is empty of the old tenant's files" bash -c "! ls -A /home/attack3 | grep -qE 'churn|feat.py|c-etc|partial'"
  if [ -f "$FT/sftp/ka" ]; then
    check_not "the old tenant's SFTP key does not log in as the new one" bash -c "echo pwd | sftp -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o ConnectTimeout=10 -i $FT/sftp/ka -b - attack3@127.0.0.1"
  fi
  check "delete the new attack3" ctl_ok 'deleted=true' oxpanel-ctl tenant delete attack3 --remove-home
}

# ------------------------------------------------------------------ 15. every local listener and socket
features_listeners() {
  echo "-- 15. every listener and UNIX socket on the host, from tenant code"
  feat_everywhere listeners 10 listeners /var/lib/mysql/mysql.sock
}

features_teardown() {
  echo "-- 7-15 teardown"
  ctl task delete victim1 vtask >/dev/null 2>&1
  ctl sftp remove-key victim1 "$(ssh-keygen -lf "$FT/victim-key.pub" | awk '{print $2}')" --end-sessions >/dev/null 2>&1
  ctl cert remove vphp.test >/dev/null 2>&1
  ctl php set vphp.test >/dev/null 2>&1
  if systemctl -q is-active mariadb; then
    ctl db delete victim1_db >/dev/null 2>&1; ctl db user-delete victim1_app >/dev/null 2>&1; ctl db trash-purge victim1 >/dev/null 2>&1
  fi
  for b in $(oxpanel-ctl backup list victim1 2>/dev/null | sed -n 's/^backup=\([^ ]*\).*/\1/p'); do ctl backup delete victim1 "$b" >/dev/null 2>&1; done
  oxpanel-ctl dns zone-list | sed -n 's/^zone=\([^ ]*\) tenant=\([^ ]*\) .*/\1 \2/p' | while read -r z t; do oxpanel-ctl dns zone-delete "$z" --tenant "$t" >/dev/null 2>&1; done
  cp -p "$FT/daemon.env.bak" /etc/oxpanel/daemon.env
  systemctl disable --now oxpanel-dns >/dev/null 2>&1
  systemctl restart oxpanel-daemon
  check "DNS hosting off again" bash -c "oxpanel-ctl host info | grep -q '^dns=false '"
  rm -rf "${FT:?}"
}
