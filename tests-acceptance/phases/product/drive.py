#!/usr/bin/env python3
"""Drive the whole OxPanel product through the panel's HTTPS API, as a browser does.

Runs on the acceptance VM as root, after install.sh installed engine + panel.
Everything goes through Nginx on the panel's HTTPS port: the session cookie,
the CSRF token, Origin and Sec-Fetch-Site on every state-changing request, the
forced password change and (for the administrator) two-factor enrolment.
Content is put in place the way a customer does it (SFTP) and fetched the way a
visitor does (Nginx on port 80/443).

Output: `ok   - …`, `FAIL: …`, `info - …` lines (the rig counts them).
Usage: drive.py PANEL_URL ADMIN_USER ADMIN_TEMP_PASSWORD
"""
import base64
import hashlib
import hmac
import http.client
import json
import os
import shutil
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse

FAILED = 0
CONTINUE = os.environ.get("CONTINUE", "0") == "1"
WORK = tempfile.mkdtemp(prefix="oxp-drive-")
SSH_O = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "IdentitiesOnly=yes", "-o", "LogLevel=ERROR"]


class Abort(Exception):
    pass


def ok(msg):
    print(f"ok   - {msg}", flush=True)


def info(msg):
    print(f"info - {msg}", flush=True)


def fail(msg, fatal=False):
    global FAILED
    FAILED = 1
    print(f"FAIL: {msg}", flush=True)
    if fatal or not CONTINUE:
        raise Abort(msg)


def check(cond, msg, detail="", fatal=False):
    if cond:
        ok(msg)
    else:
        fail(f"{msg}" + (f"\n{detail}" if detail else ""), fatal)
    return cond


def totp(secret_b32, at=None):
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    step = int((at or time.time()) // 30)
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


class Resp:
    def __init__(self, status, headers, raw):
        self.status = status
        self.headers = headers
        self.raw = raw
        try:
            self.body = json.loads(raw) if raw else None
        except ValueError:
            self.body = None

    @property
    def code(self):
        if isinstance(self.body, dict) and isinstance(self.body.get("error"), dict):
            return self.body["error"].get("code")
        return None

    def __repr__(self):
        return f"HTTP {self.status} {self.raw[:400]!r}"


class Browser:
    """One browser profile: its own cookie, CSRF token and same-origin headers."""

    def __init__(self, url, name):
        u = urllib.parse.urlsplit(url)
        self.host, self.port = u.hostname, u.port or 443
        self.origin = f"https://{u.netloc}"
        self.netloc = u.netloc
        self.name = name
        self.cookie = None
        self.csrf = None
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE  # the panel's certificate is self-signed at install
        self.set_cookie_headers = []

    def request(self, method, path, body=None, headers=None, csrf=True, origin=True):
        h = {"Host": self.netloc, "Accept": "application/json", "User-Agent": f"oxpanel-acceptance/{self.name}"}
        if self.cookie:
            h["Cookie"] = self.cookie
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        if method not in ("GET", "HEAD"):
            if origin:
                h["Origin"] = self.origin
                h["Sec-Fetch-Site"] = "same-origin"
            if csrf and self.csrf:
                h["X-CSRF-Token"] = self.csrf
        h.update(headers or {})
        c = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=400)
        try:
            c.request(method, path, body=data, headers=h)
            r = c.getresponse()
            raw = r.read().decode("utf-8", "replace")
            hdrs = r.getheaders()
        finally:
            c.close()
        for k, v in hdrs:
            if k.lower() == "set-cookie":
                self.set_cookie_headers.append(v)
                name, _, rest = v.partition("=")
                val = rest.split(";", 1)[0]
                if name == "__Host-oxpanel_session":
                    self.cookie = None if val == "" or "Max-Age=0" in v else f"{name}={val}"
        resp = Resp(r.status, dict((k.lower(), v) for k, v in hdrs), raw)
        if isinstance(resp.body, dict) and resp.body.get("csrf_token"):
            self.csrf = resp.body["csrf_token"]
        return resp

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body, **kw)

    def put(self, path, body=None, **kw):
        return self.request("PUT", path, body, **kw)

    def patch(self, path, body=None, **kw):
        return self.request("PATCH", path, body, **kw)

    def delete(self, path, body=None, **kw):
        return self.request("DELETE", path, body, **kw)

    def refresh(self):
        r = self.get("/api/v1/auth/session")
        if r.status == 200:
            self.csrf = r.body["csrf_token"]
        return r

    def first_login(self, user, temp, new_password):
        """Sign in with a temporary password and change it, as the UI forces."""
        r = self.post("/api/v1/auth/login", {"username": user, "password": temp}, csrf=False)
        check(r.status == 200 and r.body.get("restriction") == "password_change_required",
              f"{user}: first sign-in is restricted to a password change", repr(r), fatal=True)
        r = self.get("/api/v1/accounts")
        check(r.status == 403 and r.code == "password_change_required",
              f"{user}: nothing else is allowed before the password is changed", repr(r))
        old_cookie = self.cookie
        r = self.post("/api/v1/auth/password", {"current_password": temp, "new_password": new_password})
        check(r.status == 200, f"{user}: password changed", repr(r), fatal=True)
        check(self.cookie and self.cookie != old_cookie, f"{user}: the session id rotated at the password change")
        return self.refresh()


def sh(*cmd, inp=None, timeout=120, check_rc=False):
    p = subprocess.run(list(cmd), input=inp, capture_output=True, text=True, timeout=timeout)
    if check_rc and p.returncode != 0:
        raise RuntimeError(f"{cmd}: exit {p.returncode}: {p.stderr[-500:]}")
    return p


def curl_site(host, path="/", https=False):
    if https:
        p = sh("curl", "-sk", "--max-time", "20", "--resolve", f"{host}:443:127.0.0.1", "-w", "\n%{http_code}",
               f"https://{host}{path}")
    else:
        p = sh("curl", "-s", "--max-time", "20", "-H", f"Host: {host}", "-w", "\n%{http_code}",
               f"http://127.0.0.1{path}")
    body, _, code = p.stdout.rpartition("\n")
    return code, body


def wait_site(host, want_code, want_body=None, path="/", https=False, tries=20):
    """Nginx applies a new configuration a moment AFTER the engine's reload
    returns (the reload signal is asynchronous), so a visitor's view is polled."""
    code = body = ""
    for _ in range(tries):
        code, body = curl_site(host, path, https)
        if code == want_code and (want_body is None or body.strip().startswith(want_body)):
            return True, code, body
        time.sleep(0.5)
    return False, code, body


def eventually(fn, tries=60, delay=1.0):
    last = None
    for _ in range(tries):
        last = fn()
        if last is True or (isinstance(last, tuple) and last[0] is True):
            return last
        time.sleep(delay)
    return last


def poll_job(b, account, job_id, timeout=600):
    t0 = time.time()
    while time.time() - t0 < timeout:
        r = b.get(f"/api/v1/accounts/{account}/jobs/{job_id}")
        if r.status != 200:
            return r, time.time() - t0
        if r.body.get("state") != "running":
            return r, time.time() - t0
        time.sleep(2)
    return None, time.time() - t0


def sftp(key, user, batch, tries=40):
    for _ in range(tries):
        p = sh("sftp", *SSH_O, "-i", key, "-b", "-", f"{user}@127.0.0.1", inp=batch, timeout=60)
        if p.returncode == 0:
            return p
        time.sleep(1)
    return p


def main():
    url, admin_user, admin_temp = sys.argv[1:4]
    pw = {"admin": "Admin-acceptance-passphrase-1", "reseller": "Reseller-acceptance-pass-1",
          "customer": "Customer-acceptance-pass-1"}
    rss0 = None

    # ------------------------------------------------------------ administrator
    admin = Browser(url, "admin")
    r = admin.get("/api/v1/health")
    check(r.status == 200 and r.body.get("status"), "health over HTTPS through Nginx", repr(r), fatal=True)
    for hname, want in [("content-security-policy", "default-src 'self'"), ("x-content-type-options", "nosniff"),
                        ("strict-transport-security", "max-age=")]:
        check(want in r.headers.get(hname, ""), f"answer carries {hname}", repr(r.headers))
    r = admin.get("/")
    check(r.status == 200 and "<html" in r.raw.lower(),
          "the web interface (index.html) is served at /", repr(r)[:300])
    check("script-src 'self'" in r.headers.get("content-security-policy", ""), "index.html is served with the CSP")
    r = admin.post("/api/v1/auth/login", {"username": admin_user, "password": "wrong-password-123456"}, csrf=False)
    check(r.status == 401 and r.code == "invalid_credentials", "a wrong password is refused", repr(r))
    r = admin.first_login(admin_user, admin_temp, pw["admin"])
    cookie_hdr = next((c for c in admin.set_cookie_headers if c.startswith("__Host-oxpanel_session=")), "")
    for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
        check(flag.lower() in cookie_hdr.lower(), f"session cookie has {flag}", cookie_hdr)
    check("domain=" not in cookie_hdr.lower(), "session cookie has no Domain (the __Host- prefix)", cookie_hdr)
    check(r.body.get("restriction") == "two_factor_enrolment_required",
          "an administrator must enrol a second factor next", repr(r), fatal=True)
    r = admin.post("/api/v1/auth/2fa/setup", {"password": pw["admin"]})
    check(r.status == 200 and r.body.get("secret"), "two-factor setup returns a secret", repr(r), fatal=True)
    secret = r.body["secret"]
    r = admin.post("/api/v1/auth/2fa/enable", {"code": totp(secret)})
    check(r.status == 200 and len(r.body.get("recovery_codes", [])) == 10,
          "two-factor enabled with a TOTP code; ten recovery codes shown once", repr(r), fatal=True)
    r = admin.refresh()
    check(r.status == 200 and not r.body.get("restriction"), "the administrator's session is unrestricted", repr(r), fatal=True)

    # CSRF and cross-site defences, through Nginx.
    r = admin.post("/api/v1/plans", {"name": "csrf-probe"}, csrf=False)
    check(r.status == 403 and r.code == "csrf_token_invalid", "a state change without the CSRF token is refused", repr(r))
    r = admin.post("/api/v1/plans", {"name": "csrf-probe"}, headers={"Origin": "https://evil.example"})
    check(r.status == 403 and r.code == "cross_site_request", "a state change from another Origin is refused", repr(r))
    r = admin.post("/api/v1/plans", {"name": "csrf-probe"}, headers={"Sec-Fetch-Site": "cross-site"})
    check(r.status == 403 and r.code == "cross_site_request", "Sec-Fetch-Site: cross-site is refused", repr(r))

    # ------------------------------------------------------------ host
    r = admin.get("/api/v1/host")
    check(r.status == 200, "host information from the real engine", repr(r), fatal=True)
    host = r.body
    check(host.get("dry_run") is False and host.get("selinux_enabled") is True,
          "the panel talks to the real engine (not a dry run) on an SELinux host", json.dumps(host)[:300])
    info("host: " + json.dumps({k: host.get(k) for k in ("engine_version", "https", "sftp", "disk_quota",
                                                          "database_engines", "backups")}, sort_keys=True)[:900])
    r = admin.get("/api/v1/host/capabilities")
    check(r.status == 200, "host capabilities", repr(r))
    caps = r.body or {}
    info("capabilities: " + json.dumps(caps, sort_keys=True))
    r = admin.post("/api/v1/host/reconcile")
    check(r.status == 200, "reconcile through the panel (administrator)", repr(r))
    info(f"reconcile before any customer: {r.raw[:300]}")

    # ------------------------------------------------------------ plan, reseller, customer
    plan = {"name": "Standard", "memory_max_bytes": 512 * 1024 * 1024, "cpu_weight": 100, "io_weight": 0,
            "tasks_max": 256, "disk_max_bytes": 0, "inodes_max": 0, "max_sites": 10, "allow_php": True,
            "allow_apps": True, "max_hosting_accounts": 1}
    r = admin.post("/api/v1/plans", plan)
    check(r.status == 201, "administrator creates a plan", repr(r), fatal=True)
    plan_id = r.body["id"]
    if not (caps.get("storage") or {}).get("disk_limits"):
        r = admin.post("/api/v1/plans", dict(plan, name="With disk", disk_max_bytes=1 << 30))
        dplan = r.body.get("id") if r.status == 201 else None
        info(f"plan with a disk limit on a host without quotas: {r!r}"[:300])
        if dplan:
            r2 = admin.post("/api/v1/accounts", {"name": "quotaprobe", "plan_id": dplan})
            check(r2.status == 409 and r2.code == "disk_quota_unavailable",
                  "an account with a disk limit is refused where quotas are off (409 disk_quota_unavailable)", repr(r2))
            admin.delete(f"/api/v1/plans/{dplan}")

    r = admin.post("/api/v1/users", {"username": "north", "role": "reseller", "display_name": "North Hosting"})
    check(r.status == 201 and r.body.get("temporary_password"), "administrator creates a reseller", repr(r), fatal=True)
    reseller_id, reseller_temp = r.body["user"]["id"], r.body["temporary_password"]
    r = admin.put(f"/api/v1/users/{reseller_id}/quota",
                  {"max_customers": 5, "max_accounts": 5, "max_total_memory_bytes": 4 * 1024 ** 3})
    check(r.status == 200, "administrator sets the reseller's quota", repr(r))

    reseller = Browser(url, "reseller")
    r = reseller.first_login("north", reseller_temp, pw["reseller"])
    check(r.status == 200 and not r.body.get("restriction"), "reseller signs in (no second factor required)", repr(r), fatal=True)
    r = reseller.post("/api/v1/users", {"username": "alice", "role": "customer", "display_name": "Alice",
                                        "plan_id": plan_id, "hosting_account": {"name": "alice", "plan_id": plan_id}})
    check(r.status == 201 and r.body.get("temporary_password"),
          "reseller creates a customer with a hosting account in one call", repr(r), fatal=True)
    cust_id, cust_temp = r.body["user"]["id"], r.body["temporary_password"]
    p = sh("oxpanel-ctl", "tenant", "get", "alice")
    check(p.returncode == 0 and f"owner=u{reseller_id}" in p.stdout,
          "the engine has the account, owned by the reseller's label", p.stdout + p.stderr)
    check(os.path.isdir("/home/alice"), "the account's home exists on the host")

    cust = Browser(url, "customer")
    r = cust.first_login("alice", cust_temp, pw["customer"])
    check(r.status == 200 and not r.body.get("restriction"), "customer signs in", repr(r), fatal=True)
    r = cust.get("/api/v1/hosting")
    check(r.status == 200 and r.body.get("show_account_switcher") is False,
          "a customer with one account sees no account switcher", repr(r))
    r = cust.get("/api/v1/accounts/alice")
    check(r.status == 200, "customer reads its account", repr(r))
    r = cust.post("/api/v1/plans", plan)
    check(r.status == 403 and r.code == "forbidden", "customer may not create plans", repr(r))

    # ------------------------------------------------------------ SFTP
    key = os.path.join(WORK, "id_ed25519")
    sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "alice-laptop", "-f", key, check_rc=True)
    pub = open(key + ".pub").read().strip()
    r = cust.post("/api/v1/accounts/alice/sftp/keys", {"public_key": pub, "label": "laptop"})
    check(r.status == 201 and r.body.get("fingerprint", "").startswith("SHA256:"),
          "customer adds an SFTP key", repr(r), fatal=True)
    key_id = r.body["id"]
    p = sftp(key, "alice", "pwd\n")
    check(p.returncode == 0, "SFTP login with the key", p.stdout + p.stderr, fatal=True)
    info(f"SFTP start directory: {p.stdout.strip().splitlines()[-1] if p.stdout.strip() else '?'}")
    p = sh("ssh", *SSH_O, "-i", key, "alice@127.0.0.1", "id")
    check(p.returncode != 0 and "uid=" not in p.stdout, "the key gives SFTP only, no shell", p.stdout + p.stderr)

    # ------------------------------------------------------------ sites
    sites = {"static": "www.alice.test", "php": "php.alice.test", "node": "app.alice.test"}
    r = cust.put(f"/api/v1/sites/{sites['static']}", {"document_root": "public_html"})
    check(r.status == 201, "customer creates a static site", repr(r), fatal=True)
    r = cust.put(f"/api/v1/sites/{sites['php']}", {"document_root": "php_html", "php": True})
    check(r.status == 201, "customer creates a PHP site", repr(r), fatal=True)
    r = cust.put(f"/api/v1/sites/{sites['node']}", {"app": {"runtime": "node"}})
    check(r.status == 201, "customer creates a Node.js application", repr(r), fatal=True)
    node_site = r.body
    info(f"node site as created: {json.dumps(node_site)[:400]}")
    r = cust.get("/api/v1/sites")
    check(r.status == 200 and r.body.get("total") == 3, "the customer lists its three sites", repr(r))
    p = sh("nginx", "-t")
    check(p.returncode == 0, "nginx -t passes with customer sites and the panel's server block", p.stderr)

    # Content, uploaded the way a customer does it.
    files = os.path.join(WORK, "files")
    os.makedirs(files)
    open(os.path.join(files, "index.html"), "w").write("static-ok\n")
    db_pw = "Db-acceptance-pass-1"
    php = """<?php
header('Content-Type: text/plain');
if (isset($_GET['db'])) {
  mysqli_report(MYSQLI_REPORT_OFF);
  $db = @new mysqli('localhost', 'alice_app', '%s', 'alice_shop', 0, '/var/lib/mysql/mysql.sock');
  if ($db->connect_errno) { echo "DB-ERR ", $db->connect_error; exit; }
  $db->query('CREATE TABLE IF NOT EXISTS t (v INT)');
  $db->query('DELETE FROM t');
  $db->query('INSERT INTO t VALUES (42)');
  $row = $db->query('SELECT v FROM t')->fetch_row();
  echo "DB-OK ", $row[0];
  exit;
}
if (isset($_GET['probe'])) {
  // What tenant code on this host can reach of the panel.
  $s = @stream_socket_client('unix:///run/oxpanel-panel/panel.sock', $en, $es, 2);
  echo 'socket=', $s ? 'CONNECTED' : 'refused', "\\n";
  foreach (['/var/lib/oxpanel-panel/panel.db', '/etc/oxpanel-panel/secret.env', '/etc/nginx/oxpanel-panel-proxy.inc',
            '/etc/pki/oxpanel-panel/panel.key'] as $f) {
    echo basename($f), '=', (@file_get_contents($f, false, null, 0, 16) === false ? 'unreadable' : 'READABLE'), "\\n";
  }
  // (The engine's own socket is attacked in phase 80; SELinux refuses that
  // probe with an audited denial, which this phase would count.)
  exit;
}
echo "php-ok ", PHP_VERSION, " uid=", getmyuid(), " euid=", function_exists('posix_geteuid') ? posix_geteuid() : '-';
""" % db_pw
    open(os.path.join(files, "index.php"), "w").write(php)
    open(os.path.join(files, "app.js"), "w").write(
        "require('http').createServer((q, s) => { s.end('node-ok ' + process.version); }).listen(process.env.PORT);\n")
    batch = (f"put {files}/index.html public_html/index.html\n"
             f"put {files}/index.php php_html/index.php\n"
             f"-mkdir apps\n-mkdir apps/{sites['node']}\n"
             f"put {files}/app.js apps/{sites['node']}/app.js\n")
    p = sftp(key, "alice", batch)
    check(p.returncode == 0, "content uploaded over SFTP (static page, PHP page, Node.js app)", p.stdout + p.stderr, fatal=True)
    st = os.stat("/home/alice/public_html/index.html")
    check(st.st_uid == int(sh("id", "-u", "alice").stdout), "uploaded files belong to the account")

    good, code, body = wait_site(sites["static"], "200", "static-ok")
    check(good, "the static site is served by Nginx", f"{code} {body[:200]}")
    alice_uid = sh("id", "-u", "alice").stdout.strip()
    good, code, body = wait_site(sites["php"], "200", "php-ok")
    check(good and f"uid={alice_uid}" in body, "the PHP site runs, as the account", f"{code} {body[:200]}")
    # In PHP the script owner and the process are both the account (its own FPM pool).
    info(f"PHP: {body.strip()[:120]}")
    t0 = time.time()
    r = cust.post(f"/api/v1/sites/{sites['node']}/restart")
    check(r.status == 204, "customer restarts its application after uploading code", repr(r))
    res = eventually(lambda: (lambda c_b: (c_b[0] == "200" and c_b[1].startswith("node-ok"), c_b))(curl_site(sites["node"])), 60, 1)
    check(res[0] is True, "the Node.js application answers through Nginx", repr(res[1])[:200])
    info(f"node app answered {time.time() - t0:.1f}s after the restart call")
    r = cust.get(f"/api/v1/sites/{sites['static']}/logs?kind=access&max_bytes=4096")
    check(r.status == 200 and "GET / " in json.dumps(r.body), "the site's access log is readable by its owner", repr(r)[:300])

    # ------------------------------------------------------------ HTTPS
    cert = os.path.join(WORK, "c.pem")
    ckey = os.path.join(WORK, "k.pem")
    sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "30",
       "-subj", f"/CN={sites['static']}", "-addext", f"subjectAltName=DNS:{sites['static']}",
       "-keyout", ckey, "-out", cert, check_rc=True)
    r = cust.put(f"/api/v1/sites/{sites['static']}/certificate",
                 {"certificate_chain_pem": open(cert).read(), "private_key_pem": open(ckey).read()})
    check(r.status == 200 and (r.body.get("https") or {}).get("certificate", {}).get("source") == "uploaded",
          "customer uploads a certificate", repr(r)[:400])
    t0 = time.time()
    good, code, body = wait_site(sites["static"], "200", "static-ok", https=True)
    check(good, "the site answers over HTTPS with it", f"{code} {body[:200]}")
    info(f"HTTPS with the uploaded certificate answered {time.time() - t0:.1f}s after the upload returned")
    served = sh("bash", "-c", f"echo | openssl s_client -connect 127.0.0.1:443 -servername {sites['static']} 2>/dev/null"
                              f" | openssl x509 -noout -fingerprint -sha256").stdout.strip()
    mine = sh("openssl", "x509", "-in", cert, "-noout", "-fingerprint", "-sha256").stdout.strip()
    check(served and served == mine, "Nginx serves exactly the uploaded certificate", f"{served} vs {mine}")
    r = cust.put(f"/api/v1/sites/{sites['php']}/certificate",
                 {"certificate_chain_pem": open(cert).read(), "private_key_pem": open(ckey).read()})
    check(r.status == 422 and r.code == "certificate_rejected",
          "a certificate that does not cover the site is refused (422 certificate_rejected)", repr(r)[:300])
    leaked = "PRIVATE KEY" in r.raw
    check(not leaked, "the refusal does not echo the key")
    r = cust.get(f"/api/v1/sites/{sites['php']}/auto-https")
    check(r.status == 200, "Automatic HTTPS status of a site", repr(r))
    info(f"auto-https on the VM (names do not resolve publicly): {r.raw[:400]}")
    # No explicit certificate request: the engine's default authority is Let's
    # Encrypt's production service, which a test must not call (and .test names
    # cannot be validated). Automatic HTTPS skips names that do not resolve here.

    # ------------------------------------------------------------ databases
    r = cust.post("/api/v1/accounts/alice/databases", {"suffix": "shop"})
    check(r.status == 201 and r.body.get("name") == "alice_shop", "customer creates a database", repr(r))
    r = cust.post("/api/v1/accounts/alice/database-users", {"suffix": "app", "password": db_pw})
    check(r.status == 201, "customer creates a database user", repr(r))
    r = cust.put("/api/v1/accounts/alice/database-users/alice_app/databases/alice_shop")
    check(r.status == 200, "customer grants the user the database", repr(r))
    good, code, body = wait_site(sites["php"], "200", "DB-OK 42", "/?db=1", tries=6)
    check(good, "the PHP site uses the database", f"{code} {body[:300]}")
    r = cust.get("/api/v1/accounts/alice/databases")
    info(f"databases: {r.raw[:300]}")

    # ------------------------------------------------------------ what tenant code can reach
    code, body = curl_site(sites["php"], "/?probe=1")
    info("tenant PHP probe: " + body.replace("\n", " "))
    check("socket=refused" in body, "tenant PHP cannot connect to the panel's socket", body)
    check("READABLE" not in body, "tenant PHP can read none of: panel database, proxy secret, Nginx include, TLS key", body)
    spoof = Browser(url, "spoofer")
    r = spoof.post("/api/v1/auth/login", {"username": "spoof-probe-user", "password": "x" * 14}, csrf=False,
                   headers={"X-Real-IP": "203.0.113.77", "X-Forwarded-For": "203.0.113.77"})
    check(r.status == 401, "a sign-in through Nginx with forged forwarding headers is an ordinary failure", repr(r))
    r = admin.get("/api/v1/audit?action=auth.login&limit=200")
    entries = [e for e in (r.body or {}).get("items", []) if e.get("object_id") == "spoof-probe-user"
               or e.get("actor_name") == "spoof-probe-user"]
    check(entries and all(e.get("ip") != "203.0.113.77" for e in entries),
          "the audit log records the real client address, not the forged one", json.dumps(entries)[:400])

    # ------------------------------------------------------------ usage
    r = cust.get("/api/v1/accounts/alice/usage")
    check(r.status == 200, "usage measured by the engine", repr(r))
    info(f"usage: {r.raw[:300]}")

    # ------------------------------------------------------------ backups
    r = cust.post("/api/v1/accounts/alice/backups")
    check(r.status == 202 and r.body.get("job", {}).get("id"), "customer starts a backup (202 + job)", repr(r), fatal=True)
    job = r.body["job"]["id"]
    j, secs = poll_job(cust, "alice", job)
    check(j is not None and j.status == 200 and j.body.get("state") == "succeeded",
          f"the backup job succeeds ({secs:.0f}s)", repr(j))
    r = cust.get("/api/v1/accounts/alice/backups")
    check(r.status == 200 and r.body.get("total", 0) >= 1 and r.body["items"][0].get("state") == "ready",
          "the backup is listed as ready", repr(r)[:300])
    backup = r.body["items"][0]
    info(f"backup: size={backup.get('size_bytes')} members={backup.get('members')} excluded={backup.get('excluded')}")
    open(os.path.join(files, "index.html"), "w").write("changed-after-backup\n")
    sftp(key, "alice", f"put {files}/index.html public_html/index.html\n")
    good, code, body = wait_site(sites["static"], "200", "changed-after-backup")
    check(good, "the page was changed after the backup", body[:100])
    r = cust.post(f"/api/v1/accounts/alice/backups/{backup['id']}/restore", {})
    check(r.status == 422, "a restore without on_existing is refused", repr(r))
    r = cust.post(f"/api/v1/accounts/alice/backups/{backup['id']}/restore", {"on_existing": "overwrite"})
    check(r.status == 202, "customer restores the backup (overwrite)", repr(r), fatal=True)
    j, secs = poll_job(cust, "alice", r.body["job"]["id"])
    check(j is not None and j.body.get("state") == "succeeded", f"the restore job succeeds ({secs:.0f}s)", repr(j))
    if j is not None:
        info(f"restore job: restored={j.body.get('restored_entries')} skipped={j.body.get('skipped_entries')} sites={json.dumps(j.body.get('sites'))[:300]}")
    good, code, body = wait_site(sites["static"], "200", "static-ok")
    check(good, "the restored page is served", f"{code} {body[:100]}")
    good, code, body = wait_site(sites["php"], "200", "DB-OK 42", "/?db=1")
    check(good, "PHP and its database work after the restore", f"{code} {body[:200]}")
    res = eventually(lambda: (lambda c_b: (c_b[0] == "200" and c_b[1].startswith("node-ok"), c_b))(curl_site(sites["node"])), 90, 1)
    check(res[0] is True, "the Node.js application answers after the restore", repr(res[1])[:200])

    # ------------------------------------------------------------ suspend / resume
    r = reseller.post("/api/v1/accounts/alice/suspend")
    check(r.status == 200, "reseller suspends the account", repr(r))
    t0 = time.time()
    good, code, _ = wait_site(sites["static"], "503")
    check(good, "a suspended account's site answers 503", code)
    info(f"503 visible {time.time() - t0:.1f}s after the suspend call returned")
    p = sftp(key, "alice", "pwd\n", tries=3)
    check(p.returncode != 0, "SFTP is cut while suspended", p.stdout + p.stderr)
    r = cust.put(f"/api/v1/sites/{sites['static']}", {"document_root": "public_html", "aliases": ["alice.test"]})
    info(f"customer changes a site of its suspended account: {r!r}"[:300])
    good, code, _ = wait_site(sites["static"], "503", tries=6)
    check(good, "the changed site of a suspended account still answers 503", code)
    r = reseller.post("/api/v1/accounts/alice/resume")
    check(r.status == 200, "reseller resumes the account", repr(r))
    good, code, body = wait_site(sites["static"], "200", "static-ok")
    check(good, "the site is back after resuming", f"{code} {body[:100]}")
    res = eventually(lambda: (lambda c_b: (c_b[0] == "200" and c_b[1].startswith("node-ok"), c_b))(curl_site(sites["node"])), 60, 1)
    check(res[0] is True, "the Node.js application is back after resuming", repr(res[1])[:200])
    p = sftp(key, "alice", "pwd\n")
    check(p.returncode == 0, "SFTP works again after resuming", p.stdout + p.stderr)

    p = sh("oxpanel-ctl", "host", "reconcile")
    check(p.returncode == 0, "engine reconcile is clean with the panel and a customer's sites present", p.stdout + p.stderr)
    p = sh("bash", "-c", "ps -o rss= -p $(systemctl show -p MainPID --value oxpanel-panel)")
    info(f"panel RSS after the drive: {p.stdout.strip()} KiB")

    # ------------------------------------------------------------ delete
    for d in sites.values():
        r = cust.delete(f"/api/v1/sites/{d}")
        check(r.status in (200, 204), f"customer deletes the site {d}", repr(r))
    r = cust.delete("/api/v1/accounts/alice/database-users/alice_app")
    check(r.status in (200, 204), "customer deletes the database user", repr(r))
    r = cust.delete("/api/v1/accounts/alice/databases/alice_shop")
    check(r.status in (200, 204), "customer deletes the database", repr(r))
    r = cust.get("/api/v1/accounts/alice/backups")
    for b in (r.body or {}).get("items", []):
        r2 = cust.delete(f"/api/v1/accounts/alice/backups/{b['id']}")
        check(r2.status == 204, f"customer deletes backup {b['id']}", repr(r2))
    r = cust.delete(f"/api/v1/accounts/alice/sftp/keys/{key_id}", {"end_sessions": True})
    check(r.status == 200, "customer removes its SFTP key", repr(r))
    r = cust.delete("/api/v1/accounts/alice")
    check(r.status == 409 and r.code == "last_hosting_account", "a customer cannot delete its last account", repr(r))
    r = reseller.delete("/api/v1/accounts/alice?remove_files=true")
    if r.status == 409 and r.code == "account_has_databases":
        # The real engine keeps a deleted database in the account's trash for
        # 30 days, and an account with a trash cannot be deleted. The panel API on
        # this branch has no trash routes yet (and its own database list is empty):
        # the operator has to purge it on the host.
        info("DIFFERENCE: deleting the account is refused (409 account_has_databases) although the panel lists no"
             " database: the engine holds the deleted database in its trash; purged with oxpanel-ctl")
        p = sh("oxpanel-ctl", "db", "trash-purge", "alice")
        check(p.returncode == 0, "operator purges the account's database trash on the host", p.stdout + p.stderr)
        r = reseller.delete("/api/v1/accounts/alice?remove_files=true")
    check(r.status in (200, 204), "reseller deletes the account (and its files)", repr(r))
    p = sh("oxpanel-ctl", "tenant", "get", "alice")
    check(p.returncode != 0, "the engine no longer has the account", p.stdout)
    check(not os.path.exists("/home/alice"), "its home is gone")
    r = reseller.delete(f"/api/v1/users/{cust_id}")
    check(r.status in (200, 204), "reseller deletes the customer", repr(r))
    r = admin.delete(f"/api/v1/users/{reseller_id}")
    check(r.status in (200, 204), "administrator deletes the reseller", repr(r))
    r = admin.delete(f"/api/v1/plans/{plan_id}")
    check(r.status in (200, 204), "administrator deletes the plan", repr(r))
    r = admin.get("/api/v1/audit?limit=200")
    check(r.status == 200 and r.body.get("total", 0) > 20, "the audit log recorded the session", repr(r)[:200])
    for secret_value in (pw["customer"], db_pw, open(ckey).read().splitlines()[1]):
        check(secret_value not in r.raw, "no password or key in the audit log")
    r = admin.post("/api/v1/auth/logout")
    check(r.status in (200, 204), "administrator signs out", repr(r))
    r = admin.get("/api/v1/accounts")
    check(r.status == 401, "the old session is dead", repr(r))
    # Credentials for later phases (the reboot check signs in again).
    with open("/root/acc/panel-admin.json", "w") as f:
        json.dump({"user": admin_user, "password": pw["admin"], "totp_secret": secret}, f)
    os.chmod("/root/acc/panel-admin.json", 0o600)
    return 0


if __name__ == "__main__":
    rc = 0
    try:
        rc = main()
    except Abort:
        rc = 1
    except Exception as e:  # noqa: BLE001 - report, never hide
        import traceback
        traceback.print_exc()
        print(f"FAIL: driver crashed: {e!r}", flush=True)
        rc = 1
    finally:
        shutil.rmtree(WORK, ignore_errors=True)
    sys.exit(1 if (rc or FAILED) else 0)
