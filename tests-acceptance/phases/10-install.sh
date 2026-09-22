#!/usr/bin/env bash
# Phase 10 — install like a user. INSTALL=git follows docs/HANDBOOK.md §3.2 verbatim;
# INSTALL=rpm installs the package built from the working tree.
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
    check "dnf install resolves every dependency" dnf -y -q install "./$RPM"
    check "rpm -V is clean" rpm -V oxpanel-daemon
    check "unit shipped by the package" test -f /usr/lib/systemd/system/oxpanel-daemon.service
    check "enable and start services" systemctl enable --now nginx oxpanel-daemon
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
