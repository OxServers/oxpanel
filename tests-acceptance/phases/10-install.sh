#!/usr/bin/env bash
# Phase 10 — install like a user. INSTALL=git follows docs/HANDBOOK.md §3.2 verbatim;
# INSTALL=rpm installs the package built from the working tree;
# INSTALL=installer runs release/install.sh unattended on a host that has a firewall;
# INSTALL=upgrade installs the OLD (0.1.0) RPM by hand, as its handbook said (phase 12 then upgrades).
cd "$(dirname "$0")/.."; source phases/lib.sh
INSTALL="${INSTALL:-git}"
echo "== phase 10: install ($INSTALL)"
info "host: $(cat /etc/almalinux-release) · kernel $(uname -r) · selinux $(getenforce)"

# Extract the first ```sh block that follows a given markdown heading.
handbook_block() { awk -v h="$1" 'index($0,h)==1{f=1;next} f&&/^```sh/{c=1;next} f&&c&&/^```/{exit} f&&c{print}' HANDBOOK.md; }

case "$INSTALL" in
  rpm)
    RPM=$(ls rpms/oxpanel-daemon-[0-9]*.el9.x86_64.rpm 2>/dev/null | grep -vE 'debuginfo|debugsource' | head -1)
    [ -n "$RPM" ] || fail "no RPM found in $(pwd)/rpms"
    info "installing $RPM"
    check "enable the Node.js 22 module stream" dnf -y -q module enable nodejs:22
    check "dnf install resolves every dependency" dnf -y -q install "./$RPM"
    check "the recommended Node.js is 22 or newer" bash -c 'test "$(node --version | sed "s/^v//; s/\..*//")" -ge 22'
    check "rpm -V is clean" rpm -V oxpanel-daemon
    check "unit shipped by the package" test -f /usr/lib/systemd/system/oxpanel-daemon.service
    check "enable and start services" systemctl enable --now nginx oxpanel-daemon
    ;;
  installer)
    check "the release directory is intact (SHA256SUMS)" bash -c 'cd release && sha256sum -c --quiet SHA256SUMS'
    # A host with a firewall: the installer must open 80/443 and must not disable it.
    check "install firewalld and start it (a host that has a firewall)" bash -c 'dnf -y -q install firewalld && systemctl enable --now firewalld'
    check "firewalld does not allow http before the installer runs" bash -c '! firewall-cmd --query-service=http'
    out="$(bash release/install.sh --check 2>&1)"; echo "$out" | tail -5
    check "--check runs the preflight only" bash -c 'echo "$1" | grep -q "RESULT: preflight ok"' _ "$out"
    check "nothing was installed by --check" bash -c '! rpm -q oxpanel-daemon'
    start=$(date +%s)
    # Unattended, everything optional switched on: that is the widest run the rig can make.
    bash release/install.sh --yes --quota --no-reboot --fail2ban --enable-epel > install-1.log 2>&1; rc=$?
    echo "--- install-1.log ---"; cat install-1.log; echo "---------------------"
    [ "$rc" = 0 ] || fail "install.sh exited $rc (see above)"
    ok "install.sh --yes ran clean ($(( $(date +%s) - start ))s)"
    check "the run reports success and that a reboot is needed for quotas" bash -c 'grep -q "^RESULT: ok changes=[1-9][0-9]* .*reboot_required=yes" install-1.log'
    check "every stage ran" bash -c 'for s in preflight nodejs engine selinux nginx mariadb php panel daemon dns panelweb firewall fail2ban quota verify; do grep -q "^\[$s\]" install-1.log || { echo "stage $s missing"; exit 1; }; done'
    check "the status file records the result" bash -c 'grep -qx "reboot_required=yes" /var/lib/oxpanel-installer/status && grep -qx "result=ok" /var/lib/oxpanel-installer/status'
    check "the log file exists, root-only" test "$(stat -c %a /var/log/oxpanel-install.log)" = 600
    # Idempotence: the second run changes nothing.
    bash release/install.sh --yes --quota --no-reboot --fail2ban --enable-epel > install-2.log 2>&1; rc=$?
    tail -25 install-2.log
    [ "$rc" = 0 ] || fail "second install.sh run exited $rc"
    check "the second run changes nothing" bash -c 'grep -q "^RESULT: ok changes=0 " install-2.log'
    check "the second run says so in every stage" bash -c '! grep -q "changed:" install-2.log'
    ;;
  product)
    # The release bundle includes the panel RPM (make dist PANEL_RPM=...): install.sh
    # installs both, puts the panel on HTTPS and prints the first administrator's
    # one-time password, which phase 25 uses to sign in like the operator would.
    check "the release directory is intact (SHA256SUMS)" bash -c 'cd release && sha256sum -c --quiet SHA256SUMS'
    check "the bundle includes the panel RPM" bash -c 'ls release/oxpanel-panel-[0-9]*.rpm'
    check "install firewalld and start it (a host that has a firewall)" bash -c 'dnf -y -q install firewalld && systemctl enable --now firewalld'
    start=$(date +%s)
    bash release/install.sh --yes --fail2ban --enable-epel > install-1.log 2>&1; rc=$?
    # The log printed here must not show the password: keep it out of the phase log too.
    echo "--- install-1.log (password line masked) ---"; sed 's/\(one-time password: *\).*/\1<masked>/' install-1.log; echo "---------------------"
    [ "$rc" = 0 ] || fail "install.sh exited $rc (see above)"
    ok "install.sh --yes with the bundled panel ran clean ($(( $(date +%s) - start ))s)"
    check "every stage ran, the panel's included" bash -c 'for s in preflight nodejs engine selinux nginx mariadb php panel daemon dns panelweb firewall fail2ban quota verify; do grep -q "^\[$s\]" install-1.log || { echo "stage $s missing"; exit 1; }; done'
    check "the run reports success" grep -q '^RESULT: ok changes=[1-9]' install-1.log
    sed -n 's/^  administrator: *//p' install-1.log > panel-admin.once
    sed -n 's/^  one-time password: *//p' install-1.log >> panel-admin.once
    chmod 600 panel-admin.once
    check "the installer printed the first administrator and a one-time password" bash -c 'test "$(wc -l < panel-admin.once)" = 2 && test "$(sed -n 2p panel-admin.once | wc -c)" -gt 12'
    check "the one-time password is not in the installer's log file" bash -c '! grep -qF -- "$(sed -n 2p panel-admin.once)" /var/log/oxpanel-install.log'
    check "the installer checked the panel over HTTPS" grep -q 'panel answers over HTTPS' install-1.log
    bash release/install.sh --yes --fail2ban --enable-epel > install-2.log 2>&1; rc=$?
    tail -25 install-2.log
    [ "$rc" = 0 ] || fail "second install.sh run exited $rc"
    check "the second run changes nothing" bash -c 'grep -q "^RESULT: ok changes=0 " install-2.log'
    check "the second run creates no second administrator and prints no password" bash -c '! grep -q "one-time password" install-2.log && grep -q "already has an administrator" install-2.log'
    ;;
  upgrade)
    OLD=$(ls old-rpms/oxpanel-daemon-[0-9]*.el9.x86_64.rpm 2>/dev/null | grep -vE 'debuginfo|debugsource' | head -1)
    [ -n "$OLD" ] || fail "no old RPM found in $(pwd)/old-rpms"
    info "installing the OLD package $OLD the way its handbook said"
    check "enable the Node.js 22 module stream" dnf -y -q module enable nodejs:22
    check "dnf install of the old RPM" dnf -y -q install "./$OLD"
    check "enable and start services" systemctl enable --now nginx oxpanel-daemon
    check "the old engine is what is installed" bash -c "rpm -q --qf '%{VERSION}' oxpanel-daemon | grep -q '^0\.1\.'"
    info "old version: $(oxpanel-daemon --version)"
    ;;
  git)
    handbook_block "### 3.2 " > install-from-git.sh
    [ -s install-from-git.sh ] || fail "could not extract the §3.2 install block from HANDBOOK.md"
    if [ -n "${GIT_URL:-}" ] || [ -n "${GIT_REF:-}" ]; then
      url="${GIT_URL:-https://github.com/OxServers/oxpanel.git}"; ref="${GIT_REF:-main}"
      sed -i "s|^git clone .* && cd oxpanel$|git clone \"$url\" oxpanel \&\& git -C oxpanel checkout -q \"$ref\" \&\& cd oxpanel|" install-from-git.sh
      info "clone: $url @ $ref"
    else
      info "running the handbook block unmodified"
    fi
    grep -q "git clone" install-from-git.sh || fail "install block lost its clone line"
    echo "--- install-from-git.sh ---"; cat install-from-git.sh; echo "---------------------------"
    start=$(date +%s)
    if ! HOME=/root bash -e install-from-git.sh > install-from-git.log 2>&1; then
      tail -60 install-from-git.log; fail "handbook §3.2 install block failed (see above)"
    fi
    ok "handbook §3.2 install block ran clean ($(( $(date +%s) - start ))s)"
    info "tested commit: $(git -C /root/oxpanel rev-parse HEAD 2>/dev/null || git -C ./oxpanel rev-parse HEAD 2>/dev/null || echo unknown)"
    handbook_block "### 3.4 " > verify.sh
    [ -s verify.sh ] || fail "could not extract the §3.4 verification block"
    if ! bash -e verify.sh > verify.log 2>&1; then tail -40 verify.log; fail "handbook §3.4 verification block failed"; fi
    ok "handbook §3.4 verification block ran clean"
    ;;
  *) fail "unknown INSTALL=$INSTALL";;
esac

# DNS hosting is optional: the RPM recommends BIND and the public suffix list
# (installed with it by default); the checks query the server with the BIND
# tools, which an operator installs the same way.
if [ "$INSTALL" = rpm ]; then check "BIND and the public suffix list came with the package (Recommends)" rpm -q bind publicsuffix-list; fi
check "DNS tools for the checks (dig, delv, dnssec-dsfromkey)" dnf -y -q install bind bind-utils bind-dnssec-utils publicsuffix-list

# Tenant databases are optional; set MariaDB up exactly as HANDBOOK §3.5 says
# (the installer did it itself, and phase 10 then checks the result is the same).
if [ "$INSTALL" = upgrade ]; then
  info "MariaDB comes with the upgrade (phase 12)"
else
  if [ "$INSTALL" != installer ] && [ "$INSTALL" != product ]; then
    handbook_block "### 3.5 " > install-mariadb.sh
    [ -s install-mariadb.sh ] || fail "could not extract the §3.5 MariaDB block from HANDBOOK.md"
    if ! bash -e install-mariadb.sh > install-mariadb.log 2>&1; then tail -30 install-mariadb.log; fail "handbook §3.5 MariaDB block failed"; fi
    ok "handbook §3.5 MariaDB block ran clean"
  fi
  check "MariaDB is active" systemctl -q is-active mariadb
  check "MariaDB has no anonymous accounts" bash -c '[ "$(mariadb --no-defaults -u root -N -B -e "SELECT COUNT(*) FROM mysql.global_priv WHERE User=\"\"")" = 0 ]'
  check "MariaDB has no test database" bash -c '[ "$(mariadb --no-defaults -u root -N -B -e "SHOW DATABASES LIKE \"test\"")" = "" ]'
  check "MariaDB has no network listener" bash -c '! ss -H -ltn | grep -Eq ":3306[[:space:]]"'
fi

check "oxpanel group exists" getent group oxpanel
check "daemon.env is root-owned 0640" test "$(stat -c '%U %a' /etc/oxpanel/daemon.env)" = "root 640"
check "config dir is root:oxpanel 0750" test "$(stat -c '%U:%G %a' /etc/oxpanel)" = "root:oxpanel 750"
check "--check-config passes" /usr/sbin/oxpanel-daemon --check-config
check "oxpanel-ctl on PATH" command -v oxpanel-ctl
info "version: $(oxpanel-daemon --version)"
check "nginx active" systemctl -q is-active nginx
check "oxpanel-daemon active" daemon_active
check "socket exists" test -S /run/oxpanel/oxpanel.sock
check "socket is root:oxpanel 0660" test "$(stat -c '%U:%G %a' /run/oxpanel/oxpanel.sock)" = "root:oxpanel 660"
check "daemon saw selinux=$([ "$(getenforce)" = Disabled ] && echo false || echo true)" bash -c "journalctl -b -u oxpanel-daemon --no-pager | grep -q 'selinux=$([ "$(getenforce)" = Disabled ] && echo false || echo true)'"
check "no errors in daemon journal" bash -c '! journalctl -b -u oxpanel-daemon -p err --no-pager | grep -q oxpanel-daemon'
phase_end
