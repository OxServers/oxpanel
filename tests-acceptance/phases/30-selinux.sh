#!/usr/bin/env bash
# Phase 30 — SELinux enforcing, end to end.
cd "$(dirname "$0")/.."; source phases/lib.sh
echo "== phase 30: selinux"
check "SELinux is enforcing" test "$(getenforce)" = "Enforcing"
check "policy is targeted" grep -q '^SELINUXTYPE=targeted' /etc/selinux/config
check "daemon detected SELinux at start" bash -c "journalctl -b -u oxpanel-daemon --no-pager | grep -q 'selinux=true'"
info "daemon context: $(ps -o label= -p "$(daemon_pid)")"
info "AVC denials before this phase: $(avc_count)"
info "customizable types: $(tr '\n' ' ' < /etc/selinux/targeted/contexts/customizable_types 2>/dev/null)"

check "create tenant selx" bash -c "oxpanel-ctl tenant create selx --memory 128M | grep -q '^created=true'"
check "home has the standard home label" bash -c "ls -dZ /home/selx | grep -q ':user_home_dir_t:'"
check "configure selx.test" bash -c "oxpanel-ctl vhost set selx.test --tenant selx | grep -q '^changed=true'"
check "fcontext equivalence recorded" bash -c "semanage fcontext -l -C | grep -qE '^/home/selx/public_html = /usr/share/nginx/html'"
for b in httpd_enable_homedirs httpd_read_user_content httpd_unified; do
  check "boolean $b is on" bash -c "getsebool $b | tee /dev/stderr | grep -q -- '--> on'"
done
check "matchpathcon agrees" bash -c "matchpathcon /home/selx/public_html | grep -q httpd_sys_content_t"
info "labels: $(ls -dZ /home/selx /home/selx/public_html | awk '{print $1}' | tr '\n' ' ')"
check "docroot labelled httpd_sys_content_t" bash -c "ls -dZ /home/selx/public_html | grep -q ':httpd_sys_content_t:'"
as_user selx sh -c 'echo selinux-ok > /home/selx/public_html/index.html'
check "tenant-created file inherits the httpd type" bash -c "ls -Z /home/selx/public_html/index.html | grep -q ':httpd_sys_content_t:'"
eventually "nginx serves the site under enforcing" 30 0.2 http_body_is selx.test / selinux-ok
check "dot-file still 404 under enforcing" test "$(as_user selx sh -c 'echo x > /home/selx/public_html/.env'; http_code selx.test /.env)" = 404
check "remove selx.test" bash -c "oxpanel-ctl vhost remove selx.test | grep -q '^removed=true'"
check_not "fcontext equivalence removed with the site" bash -c "semanage fcontext -l -C | grep -qE '^/home/selx/public_html = '"
check "delete tenant selx" bash -c "oxpanel-ctl tenant delete selx --remove-home | grep -q '^deleted=true'"

n=$(avc_count)
if [ "$n" = 0 ]; then ok "zero AVC denials since boot"; else avc_dump; fail "$n AVC denial(s) since boot (dumped above)"; fi
check "daemon journal has no errors" bash -c '! journalctl -b -u oxpanel-daemon -p err --no-pager | grep -q oxpanel-daemon'
phase_end
