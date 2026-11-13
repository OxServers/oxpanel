# OxPanel engine — manual QA plan

A script for a person, on a fresh AlmaLinux 9 host, who has never seen the
project. It starts the way a user starts (the handbook's §3.2 "From source"
block, copied, not paraphrased), walks through every feature in
[FEATURES.md](FEATURES.md), upgrades from the previous commit, injects the
failures an operator can inject by hand, and uninstalls.

Every step is `command`, then **Expect:** the observable result. A step that
does not give the expected result is a defect: write down the step number, the
command, what you saw, and `journalctl -u oxpanel-daemon -n 50`.

The automated suites cover most of this (see `docs/traceability.map`); the point
of this plan is a human looking at it: error messages that read badly, pages
that look wrong in a browser, a reload that takes too long to feel right, and
anything the scripts did not think of. Allow about three hours.

## 0. What you need

* A **fresh** AlmaLinux 9 machine (virtual is fine): 2 vCPU, 2 GiB RAM, 20 GiB disk,
  root or sudo, outbound Internet (packages, GitHub, crates.io), SELinux
  **enforcing** (`getenforce` prints `Enforcing`). A second, throw-away copy of
  the VM for section 9 (the upgrade) is convenient.
* A browser or `curl` that can reach the machine's port 80. The steps use
  `curl --resolve` so no DNS is needed.
* Two terminals on the host: **T1** for commands, **T2** for
  `journalctl -fu oxpanel-daemon`.

Conventions: `$` is a root shell (`sudo -i`). `ctl` means `oxpanel-ctl`.

```sh
$ getenforce; cat /etc/almalinux-release; uname -r
```
**Expect:** `Enforcing`; `AlmaLinux release 9.x`. Note the numbers in your report.

```sh
$ cat > /root/qa.sh <<'EOF'
# helper used below: web <host> [path]  -> prints the HTTP status and body
web() { curl -s -m 10 -w '\n[HTTP %{http_code}]\n' --resolve "$1:80:127.0.0.1" "http://$1${2:-/}"; }
EOF
$ . /root/qa.sh
```

## 1. Install like a user (from git)

Open `docs/HANDBOOK.md` §3.2 on GitHub, copy the shell block **as it is**, paste
it in T1 as root without the leading `sudo` words if you are already root.

```sh
$ time ( <the §3.2 block> )
```
**Expect:** it ends without an error; it takes 5 to 15 minutes (it compiles the
daemon). `systemctl is-active nginx oxpanel-daemon` prints `active` twice.

Run the handbook's §3.4 block:

```sh
$ oxpanel-daemon --check-config; echo "exit=$?"
```
**Expect:** `exit=0`, no output about missing programs.
```sh
$ systemctl status oxpanel-daemon --no-pager | head -5
$ ls -l /run/oxpanel/oxpanel.sock
$ oxpanel-ctl tenant list; echo "exit=$?"
$ journalctl -u oxpanel-daemon -n 20 --no-pager
```
**Expect:** `active (running)`; `srw-rw---- 1 root oxpanel`; the list is empty and
`exit=0`; the journal says `preflight selinux=true` and a line with
`listening`, and no line at `ERROR` or `WARN`.
```sh
$ semodule --list-modules | grep -x oxpanel
$ getsebool httpd_enable_homedirs httpd_read_user_content httpd_unified
$ ausearch -m avc -ts boot 2>/dev/null | head
```
**Expect:** `oxpanel`; all three booleans `--> on`; no AVC records (an `ausearch`
that prints `<no matches>` is right).

### 1.1 Install from the RPM instead (second machine, optional)

```sh
$ dnf module enable -y nodejs:22 && dnf install -y ./oxpanel-daemon-*.rpm
$ rpm -V oxpanel-daemon; systemctl enable --now nginx oxpanel-daemon
```
**Expect:** every dependency resolves; `rpm -V` prints nothing; both services active.

## 2. Tenants

T2 shows the journal throughout. Watch it for `ERROR` lines in every section.

```sh
$ ctl tenant create acme --memory 512M --cpu-weight 25 --tasks-max 200 --owner reseller-north
```
**Expect:** `created=true` and a line `tenant=acme owner=reseller-north uid=20000 gid=20000 home=/home/acme state=TENANT_STATE_READY slice=oxpanel-tenant-acme.slice memory_max=536870912 cpu_weight=25 … tasks_max=200`.
```sh
$ id acme; getent passwd acme; stat -c '%a %U:%G' /home/acme; grep '^acme:' /etc/shadow
$ cat /etc/systemd/system/oxpanel-tenant-acme.slice; systemctl show -p MemoryMax,TasksMax,CPUWeight oxpanel-tenant-acme.slice
```
**Expect:** uid and gid 20000, shell `/sbin/nologin`, home `700 acme:acme`, the
password field `!` or `*`; the slice file lists `MemoryMax=536870912`,
`MemorySwapMax=0`, `CPUWeight=25`, `TasksMax=200`; systemd shows the same values.

Idempotence and refusals:
```sh
$ ctl tenant create acme --memory 512M --cpu-weight 25 --tasks-max 200 --owner reseller-north | head -1
$ ctl tenant create acme --memory 1G; echo "exit=$?"
$ ctl tenant create root; ctl tenant create nginx; ctl tenant create Bad_Name; ctl tenant create 'a b'; ctl tenant create oxpanelx
```
**Expect:** `created=false`; an `AlreadyExists … different specification` error and a
non-zero exit; the next five each fail with an `InvalidArgument` or
`FailedPrecondition` message that names the problem in words a customer-support
person could read (judge the wording and record any that is unclear). `id nginx`
is unchanged.
```sh
$ ctl tenant create foo-bar --owner reseller-south --memory 128M
$ ls /etc/systemd/system/ | grep 'foo'
$ ctl tenant list; ctl tenant list --owner reseller-north; ctl tenant get acme
```
**Expect:** the slice file name contains `foo\x2dbar`; the filtered list shows only `acme`.

Limits, owner, usage:
```sh
$ ctl tenant set-limits acme --memory 256M --tasks-max 100
$ systemctl show -p MemoryMax,TasksMax,CPUWeight oxpanel-tenant-acme.slice
$ ctl tenant set-limits acme --memory 1; echo "exit=$?"
$ ctl tenant set-owner acme reseller-east; ctl tenant set-owner acme ''
$ ctl tenant usage acme
```
**Expect:** `changed=true`; `MemoryMax=268435456`, `TasksMax=100`, and `CPUWeight` back
to its default (set-limits replaces *all* limits); the invalid limit is refused;
`owner=reseller-east` and then `owner=-`; `usage` prints
`memory_current=… tasks_current=… disk_usage=<more than 0>`.

## 3. Virtual hosts

```sh
$ ctl vhost set acme.test --tenant acme --alias www.acme.test
$ ls -ld /home/acme /home/acme/public_html; getfacl -p /home/acme /home/acme/public_html
$ cat /etc/nginx/oxpanel.d/acme.test.conf; nginx -t
$ ls -dZ /home/acme/public_html; semanage fcontext -l -C | grep acme
```
**Expect:** `changed=true`; the document root is owned by `acme`; the home shows
`user:nginx:--x`, `group::---`, `other::---` (and `stat` says `710`: that is the
ACL mask, not a `chmod`); the document root has `user:nginx:r-x` and a default
ACL; the Nginx file contains `server_name acme.test www.acme.test`, `root
/home/acme/public_html`, `disable_symlinks if_not_owner`; `nginx -t` is clean;
the label is `httpd_sys_content_t`, with an equivalence rule in `semanage`.
```sh
$ sudo -u acme sh -c 'echo hello-acme > /home/acme/public_html/index.html; echo SECRET=1 > /home/acme/public_html/.env; ln -s /etc/shadow /home/acme/public_html/shadow'
$ web acme.test; web www.acme.test; web acme.test /.env; web acme.test /shadow; web other.test; web acme.test /nothing
$ curl -s -m 5 http://127.0.0.1/; echo "curl exit=$?"
```
**Expect:** `hello-acme [HTTP 200]` twice; `/.env` and `/shadow` are 404 or 403, never
200 and never the contents; the unknown host and the bare IP are closed with
no response (`curl exit=52`; `web` prints nothing and `[HTTP 000]`); a missing page is a
plain 404.
```sh
$ ctl vhost set acme.test --tenant acme --alias www.acme.test | head -1
$ ctl vhost set acme.test --tenant foo-bar; echo "exit=$?"
$ ctl vhost set www.acme.test --tenant foo-bar; echo "exit=$?"
$ ctl vhost set evil.test --tenant acme --root ../etc; ctl vhost set evil.test --tenant acme --root 'a;b'; ctl vhost set 'Bad Domain' --tenant acme
$ ctl vhost list; ctl vhost list --tenant acme
```
**Expect:** `changed=false`; both attempts to take acme's names are refused and the
message names the owner; the three malformed requests are refused and create no
file (`ls /etc/nginx/oxpanel.d`, `ls /home/acme`).
```sh
$ ctl vhost set sub.acme.test --tenant acme --root www/shop
$ ls -ld /home/acme/www /home/acme/www/shop; getfacl -p /home/acme/www | head
```
**Expect:** both directories exist and belong to `acme`; `www` has traverse for nginx.

Logs:
```sh
$ web acme.test '/?marker=qa-1' >/dev/null; sleep 1
$ ctl vhost log acme.test | tail -3; ctl vhost log acme.test --error | tail -3
$ ls -l /var/log/nginx/oxpanel/; sudo -u acme ls /var/log/nginx/oxpanel; echo "exit=$?"
```
**Expect:** the access log shows the `marker=qa-1` request; the error log shows the
refused `/shadow` symlink; the directory is closed to tenants (non-zero exit).

PHP source is never handed out on a static site:
```sh
$ sudo -u acme sh -c 'echo "<?php echo \"SOURCE\";" > /home/acme/public_html/config.php'; web acme.test /config.php
```
**Expect:** 404 (never the source, never a download).

## 4. PHP

```sh
$ ctl host info | tr ' ' '\n' | grep php
$ ctl vhost set php.test --tenant acme --php
$ systemctl status oxpanel-php-acme --no-pager | head -8; ls -l /run/oxpanel-php/acme/; ps -o user,pid,cmd -C php-fpm
$ cat /etc/oxpanel-php/acme.conf
```
**Expect:** `php=true`; the unit `active (running)` and `enabled`; every `php-fpm`
process (master and workers) belongs to `acme`, none to root; the socket has an
ACL for `nginx`; the pool file contains `open_basedir`, `pm = ondemand`.
```sh
$ sudo -u acme tee /home/acme/public_html/index.php >/dev/null <<'EOF'
<?php
echo 'euid=' . fileowner(tempnam(sys_get_temp_dir(), 'x')) . ' tmp=' . sys_get_temp_dir();
echo ' passwd=' . (@file_get_contents('/etc/passwd') === false ? 'blocked' : 'READABLE');
echo ' write=' . (@file_put_contents(__DIR__ . '/w.txt', 'x') === 1 ? 'ok' : 'failed');
EOF
$ web php.test; ls -l /home/acme/public_html/w.txt; web php.test /w.txt; ls /tmp | grep -c '^x'
```
**Expect:** `euid=20000 tmp=/tmp passwd=blocked write=ok`; `w.txt` owned by `acme`
and served by Nginx; the host's `/tmp` has no file starting with `x` (the
pool's `/tmp` is private).
```sh
$ sudo -u acme sh -c 'mkdir -p /home/acme/public_html/.hidden; echo "<?php echo 1;" > /home/acme/public_html/.hidden/x.php; echo "<?php echo 1;" > /home/acme/public_html/img.php.jpg'
$ web php.test /nope.php; web php.test /.hidden/x.php; web php.test /img.php.jpg/x.php; web php.test /some/pretty/url
$ curl -sI --resolve php.test:80:127.0.0.1 http://php.test/ | grep -i x-powered-by
```
**Expect:** the first three are 404; the pretty URL runs `index.php` (front controller);
no `X-Powered-By` header.
```sh
$ systemctl kill -s SIGKILL oxpanel-php-acme; sleep 5; systemctl is-active oxpanel-php-acme
$ ctl vhost set php.test --tenant acme | head -1; ctl vhost set php.test --tenant acme --php | head -1
$ systemctl is-active oxpanel-php-acme; ls /etc/oxpanel-php /etc/systemd/system | grep -c oxpanel-php
```
**Expect:** the pool comes back by itself (`active` after SIGKILL; the unit restarts
on failure); the first replay (PHP off) removes the pool (`php=false`, unit gone);
the second creates it again.

## 5. Node.js and Python applications

```sh
$ node --version; python3 --version; ctl host info | tr ' ' '\n' | grep -E 'node|python'
$ ctl vhost set node.test --tenant acme --app node
$ sudo -u acme tee /home/acme/apps/node.test/app.js >/dev/null <<'EOF'
require('http').createServer((req, res) => {
  let other = 'blocked'; try { require('fs').readdirSync('/home/foo-bar'); other = 'READABLE'; } catch (e) {}
  res.end(`node uid=${process.getuid()} url=${req.url} other=${other}`);
}).listen(process.env.PORT);
EOF
$ web node.test /; ctl vhost restart-app node.test; sleep 2; web node.test /hello
```
**Expect:** before the code exists the site answers 502; after `restart-app`:
`node uid=20000 url=/hello other=blocked [HTTP 200]`.
```sh
$ systemctl status oxpanel-app-node.test --no-pager | head -5; ls -l /run/oxpanel-app/node.test/; ss -ltnp | grep -c node
$ sudo -u acme sh -c 'echo static > /home/acme/public_html/s.txt'; web node.test /s.txt
$ web node.test /app.js
$ ctl vhost log node.test --app | tail -3
```
**Expect:** the unit runs as `acme`; the socket directory is `0750` with an ACL for
nginx; no TCP listener for node; `s.txt` is served by Nginx; `/app.js` is the
application's answer (not the source file); the application's output appears in the log.
```sh
$ sudo -u acme sh -c 'echo "{\"name\":\"qa\",\"version\":\"1.0.0\",\"private\":true}" > /home/acme/apps/node.test/package.json'
$ ctl vhost install-deps node.test; echo "exit=$?"
$ sudo -u acme sh -c 'echo "{ not json" > /home/acme/apps/node.test/package.json'; ctl vhost install-deps node.test; echo "exit=$?"
$ sudo -u acme sh -c 'echo "{\"name\":\"qa\",\"version\":\"1.0.0\",\"private\":true}" > /home/acme/apps/node.test/package.json'
```
**Expect:** `succeeded=true`, exit 0, then `succeeded=false` with npm's error text and exit
**4**; the site works after the first.
```sh
$ ctl vhost set py.test --tenant acme --app python --app-root apps/py --app-entry main.py
$ sudo -u acme tee /home/acme/apps/py/main.py >/dev/null <<'EOF'
import os, sys
from http.server import BaseHTTPRequestHandler
from socketserver import UnixStreamServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        b = f"python uid={os.getuid()} venv={int(sys.prefix != sys.base_prefix)}".encode()
        self.send_response(200); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
UnixStreamServer(os.environ['PORT'], H).serve_forever()
EOF
$ sudo -u acme sh -c ': > /home/acme/apps/py/requirements.txt'; ctl vhost install-deps py.test; sleep 2; web py.test
```
**Expect:** `python uid=20000 venv=1 [HTTP 200]`; `/home/acme/apps/py/.venv` exists and belongs to `acme`.

Refusals (each must fail without side effects):
```sh
$ ctl vhost set both.test --tenant acme --app node --php
$ ctl vhost set bad.test --tenant acme --app node --app-root public_html/app
$ ctl vhost set bad.test --tenant acme --app node --app-entry ../../../usr/bin/id
$ ctl vhost log acme.test --app; ctl vhost restart-app acme.test
```
**Expect:** four or five refusals with clear messages; `ls /etc/nginx/oxpanel.d` unchanged.
If Node.js older than 22 is installed (`dnf module switch-to nodejs:20`): the
Node site request is refused with "version 22 or newer is required" before
anything is created; switch back afterwards.

## 6. Suspension

```sh
$ ctl tenant suspend acme
$ web acme.test; web php.test; web node.test; curl -sI --resolve acme.test:80:127.0.0.1 http://acme.test/ | grep -i retry-after
$ systemctl is-active oxpanel-php-acme oxpanel-app-node.test oxpanel-app-py.test; pgrep -u acme | wc -l
$ ctl vhost restart-app node.test; echo "exit=$?"; ctl tenant suspend acme | head -1
$ ctl vhost set late.test --tenant acme; web late.test
```
**Expect:** every site answers `503` with `Retry-After: 3600` and no tenant content;
PHP and both applications are `inactive` and the tenant has no process left;
`restart-app` is refused while suspended; the second `suspend` says `changed=false`;
a site added while suspended is born suspended (503).
```sh
$ ctl host reconcile; echo "exit=$?"
$ ctl tenant resume acme; web acme.test; web php.test; web node.test; web py.test; web late.test
$ ctl vhost remove late.test
```
**Expect:** `drifts=0` and `exit=0` (suspension is not drift); after resume every site
serves again (give Nginx a second); `files untouched`: `cat /home/acme/public_html/index.html`.

## 7. Drift, reconcile, repair

```sh
$ cp -p /etc/systemd/system/oxpanel-tenant-foo\\x2dbar.slice /root/slice.bak
$ echo CPUWeight=9999 >> '/etc/systemd/system/oxpanel-tenant-foo\x2dbar.slice'
$ mv /etc/nginx/oxpanel.d/acme.test.conf /root/
$ echo '# stray' > /etc/nginx/oxpanel.d/stray.conf
$ ctl host reconcile; echo "exit=$?"
```
**Expect:** `drifts=3`, one line each of `kind=DRIFT_KIND_TENANT_UNIT_DRIFT subject=foo-bar`,
`kind=DRIFT_KIND_VHOST_CONFIG_DRIFT subject=acme.test`,
`kind=DRIFT_KIND_ORPHAN_NGINX_CONFIG subject=/etc/nginx/oxpanel.d/stray.conf`; exit **3**;
nothing was repaired (the three files are as you left them).
```sh
$ rm /etc/nginx/oxpanel.d/stray.conf; cp -p /root/slice.bak '/etc/systemd/system/oxpanel-tenant-foo\x2dbar.slice'
$ ctl vhost set acme.test --tenant acme --alias www.acme.test | head -1; ctl host reconcile
```
**Expect:** `changed=true` (the request heals the site); `drifts=0`.

## 8. Operator failure injection

Run each, then `ctl host reconcile` and the checks given. After each: `systemctl
is-active oxpanel-daemon`, `journalctl -u oxpanel-daemon -p err --since '5 min ago'`.

1. **Kill the daemon during provisioning.** In T1 run
   `while :; do ctl tenant create loop$RANDOM >/dev/null 2>&1; done` and in a second
   shell `for i in 1 2 3 4 5; do sleep 1; systemctl kill -s SIGKILL oxpanel-daemon; done`.
   Stop the loop. **Expect:** systemd restarts the daemon each time;
   `ctl host reconcile` lists any half-made tenant as `DRIFT_KIND_TENANT_INCOMPLETE`; repeating
   the identical `ctl tenant create <name>` for each completes it
   (`created=true`, state `READY`) with exactly one account per name
   (`grep -c '^loop' /etc/passwd` equals the number of records). Delete the loop tenants.
2. **Disk full.** `fallocate -l $(( $(df --output=avail -B1 / | tail -1) - 1048576 )) /fill`,
   then `ctl tenant create fulltest` and `ctl vhost set full.test --tenant acme`.
   **Expect:** clear errors (not a crash, not a hang), no half-written
   record or config (`ls /var/lib/oxpanel/*`, `nginx -t`). `rm /fill`; repeat both
   requests: they succeed.
3. **Nginx broken by someone else.** Add `bogus directive;` to `/etc/nginx/nginx.conf`,
   then `ctl vhost set broken.test --tenant acme`. **Expect:** refused with nginx's
   own message, no `broken.test.conf` and no record. Fix the file; repeat: success.
   Remove the site.
4. **Stale socket / wrong permissions.** `chmod 666 /run/oxpanel/oxpanel.sock`
   then `systemctl restart oxpanel-daemon`. **Expect:** the socket is `0660 root:oxpanel` again.
5. **Unauthorised peer.** `sudo -u acme ctl tenant list`. **Expect:** a permission or
   transport error; the journal says `rejected connection`. Then
   `useradd -r -G oxpanel -s /sbin/nologin panelapi` and
   `setpriv --reuid=panelapi --regid=panelapi --init-groups -- ctl tenant list`: works.
6. **Scopes.** Append `OXPANEL_PEER_SCOPES=$(id -u panelapi):read+vhost` to
   `/etc/oxpanel/daemon.env`, restart. As `panelapi`: `tenant list` and
   `vhost set` work; `tenant create`, `tenant suspend`, `tenant delete` fail with
   `scope '…' required`. Add `…:everything`: `oxpanel-daemon --check-config` names the
   unknown scope. Restore the file.
7. **Reboot.** `reboot`; after it returns: `systemctl is-active oxpanel-daemon nginx
   oxpanel-php-acme oxpanel-app-node.test`, every site answers as before (section 6's
   `web` lines), `ctl host reconcile` says `drifts=0`, the socket is back.
8. **Hand-edited record.** `sed -i 's/"state": "ready"/"state": "provisioning"/' /var/lib/oxpanel/tenants/foo-bar.json`;
   `systemctl restart oxpanel-daemon`; `ctl host reconcile` reports the tenant as
   incomplete; the identical `ctl tenant create foo-bar --owner reseller-south --memory 128M`
   completes it. **Expect:** exactly one `useradd` for it in `journalctl _COMM=useradd`.
9. **Corrupt record.** `echo '{' > /var/lib/oxpanel/tenants/foo-bar.json`.
   **Expect:** `ctl tenant list` skips it and logs `corrupt record skipped`; every other tenant
   is unaffected; `ctl tenant get foo-bar` fails closed. Restore with the
   `cp` of a saved copy (take one first) or delete the tenant's account by
   hand and the record.
10. **A tenant tries things** (this is what `make acceptance` phase 80 automates;
    do a few by hand): as `acme`, `ls /home/foo-bar`, `cat /etc/shadow`,
    `ls /var/lib/oxpanel`, `ln -s /etc /home/acme/evil; ctl vhost set evil.test --tenant acme --root evil`
    (the last as root: refused). **Expect:** every attempt refused.
11. **Memory and fork limits.** `ctl tenant set-limits acme --memory 64M --tasks-max 20`, then
    as the tenant (through the Node app, add `/hog` that allocates) or
    `systemd-run --slice=oxpanel-tenant-acme.slice --uid=acme -p MemoryMax=… tail /dev/zero`:
    the process is killed (`journalctl -k | grep -i 'out of memory'` names the
    slice), other tenants' sites keep answering. Restore the limits.

## 9. Upgrade from the previous commit

On a second fresh machine, install the **previous** commit with the §3.2 block
(`git clone … && cd oxpanel && git checkout 96c06df` before the `cargo build`),
then create state:

```sh
$ ctl tenant create up1 --memory 256M; ctl vhost set up1.test --tenant up1; ctl vhost set up1php.test --tenant up1 --php
$ sudo -u up1 sh -c 'echo before-upgrade > /home/up1/public_html/index.html'; web up1.test
$ ctl host reconcile; cp -a /var/lib/oxpanel /root/state.before; sha256sum /etc/nginx/oxpanel.d/*.conf > /root/conf.before
```
Now upgrade to the commit under test: `git fetch && git checkout <commit>`, rebuild,
and run only the `install -m0755 …` lines of §3.2 plus
`systemctl daemon-reload && systemctl restart oxpanel-daemon`
(for the RPM route: `dnf upgrade ./oxpanel-daemon-NEW.rpm`).

**Expect:**
* the daemon starts (`systemctl is-active`), the journal has no `ERROR`, the
  start-up convergence line appears and nothing is reported as failed;
* `ctl tenant list` and `ctl vhost list` show the same tenants and sites; old
  records load (`diff -r /root/state.before /var/lib/oxpanel` shows differences
  only in fields added since: the daemon may rewrite records);
* `web up1.test` still says `before-upgrade`; `ctl host reconcile` says `drifts=0`
  (if it does not, repeating `ctl vhost set …` heals it, but note it as a defect);
* the Nginx files may differ from `/root/conf.before` (new template) but
  `nginx -t` is clean and sites serve; the PHP pool is still active;
* new features work on old data: `ctl vhost set up1app.test --tenant up1 --app node`.

Then the other direction is **not supported**: do not downgrade.

## 10. Uninstall

```sh
$ ctl vhost list; ctl tenant list
$ for d in $(ctl vhost list | sed -n 's/^domain=\([^ ]*\).*/\1/p'); do ctl vhost remove $d; done
$ for t in $(ctl tenant list | sed -n 's/^tenant=\([^ ]*\).*/\1/p'); do ctl tenant delete $t --remove-home; done
```
**Expect:** each `removed=true` / `deleted=true`; `ctl tenant delete` refuses
while a tenant still has sites (try it once before removing sites); then:
```sh
$ ctl tenant list; ctl vhost list; ls /home /etc/nginx/oxpanel.d /var/lib/oxpanel/* /etc/oxpanel-php /run/oxpanel-app /run/oxpanel-php
$ ls /etc/systemd/system | grep oxpanel; getent passwd | awk -F: '$3>=20000 && $3<30000'
$ semanage fcontext -l -C | grep -c /home; ctl host reconcile; nginx -t
```
**Expect:** all empty (only `oxpanel-daemon.service` remains under systemd), no
account in the tenant range, no leftover `semanage` rules, `drifts=0`.
```sh
$ systemctl disable --now oxpanel-daemon
$ dnf remove -y oxpanel-daemon            # RPM install; for a source install remove the files installed in §3.2
$ semodule -l | grep oxpanel; ls /run/oxpanel /usr/sbin/oxpanel-daemon /usr/bin/oxpanel-ctl
```
**Expect:** the package is gone; the `oxpanel` SELinux module is removed (if it is still
listed, record that: it is a packaging defect); the binaries and the socket are gone;
Nginx still starts (`nginx -t && systemctl restart nginx`); the include stanza in
`/etc/nginx/conf.d/00-oxpanel.conf` remains by design (handbook §12) and, with
the directory empty, is harmless.

## 11. What to report

For each defect: the step number, the exact command, expected and actual
output, the journal excerpt, the machine (release and kernel from section 0),
and whether it reproduces after `systemctl restart oxpanel-daemon`. Severity
guide: **critical**: a tenant reads or changes another tenant's data, or the
daemon acts outside a tenant's home; **high**: data loss, a daemon crash, a
workflow that cannot be repeated to completion; **medium**: a wrong result that
a repeat or `reconcile` fixes; **low**: wording, cosmetics, documentation.
