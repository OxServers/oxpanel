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
import glob
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
    def __init__(self, status, headers, data):
        self.status = status
        self.headers = headers
        self.data = data  # the bytes as received (file-manager downloads)
        raw = data.decode("utf-8", "replace")
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

    def request(self, method, path, body=None, headers=None, csrf=True, origin=True, raw=None):
        h = {"Host": self.netloc, "Accept": "application/json", "User-Agent": f"oxpanel-acceptance/{self.name}"}
        if self.cookie:
            h["Cookie"] = self.cookie
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        elif raw is not None:
            data = raw  # a file-manager upload chunk: raw bytes
            h["Content-Type"] = "application/octet-stream"
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
            got = r.read()
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
        resp = Resp(r.status, dict((k.lower(), v) for k, v in hdrs), got)
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


def poll_deletion(b, deletion_id, timeout=600):
    t0 = time.time()
    while time.time() - t0 < timeout:
        r = b.get(f"/api/v1/deletions/{deletion_id}")
        if r.status != 200 or r.body.get("state") != "running":
            return r, time.time() - t0
        time.sleep(2)
    return None, time.time() - t0


def drive_files(cust, sites, alice_uid):
    """The file manager through Nginx: a chunked upload, a listing, the editor, downloads."""
    base = "/api/v1/accounts/alice/files"
    blob = os.urandom(450_000) + b"<html><script>alert(1)</script></html>"
    r = cust.post(f"{base}/uploads", {"path": "public_html/fm-blob.bin", "overwrite": False})
    check(r.status == 201 and r.body.get("upload_id") and r.body.get("max_chunk_bytes"),
          "file manager: an upload is started", repr(r), fatal=True)
    up, chunk = r.body["upload_id"], int(r.body["max_chunk_bytes"])
    off, n, last = 0, 0, None
    while off < len(blob):
        piece = blob[off:off + chunk]
        last = cust.put(f"{base}/uploads/{up}?offset={off}", raw=piece)
        if last.status != 200:
            break
        off += len(piece)
        n += 1
    check(off == len(blob) and (last.body or {}).get("received_bytes") == len(blob) and n >= 3,
          f"file manager: {len(blob)} bytes sent in {n} raw chunks of at most {chunk} bytes", repr(last))
    r = cust.post(f"{base}/uploads/{up}/finish", {"size_bytes": len(blob), "sha256": hashlib.sha256(blob).hexdigest()})
    check(r.status in (200, 201), "file manager: the upload is finished with its size and SHA-256", repr(r))
    target = "/home/alice/public_html/fm-blob.bin"
    st = os.stat(target) if os.path.exists(target) else None
    check(st is not None and st.st_size == len(blob) and str(st.st_uid) == alice_uid,
          "the uploaded file is on disk, owned by the account", repr(st))
    # A checksum that does not match discards the upload.
    r = cust.post(f"{base}/uploads", {"path": "public_html/fm-bad.bin", "overwrite": False})
    if check(r.status == 201, "file manager: a second upload is started", repr(r)):
        bad = r.body["upload_id"]
        cust.put(f"{base}/uploads/{bad}?offset=0", raw=b"twelve bytes")
        r = cust.post(f"{base}/uploads/{bad}/finish", {"size_bytes": 12, "sha256": "0" * 64})
        check(r.status == 422 and r.code == "upload_checksum_mismatch",
              "a wrong checksum is refused (422 upload_checksum_mismatch)", repr(r))
        check(not os.path.exists("/home/alice/public_html/fm-bad.bin"), "and nothing of it is left in place")
    r = cust.get(f"{base}?path=public_html")
    names = {e.get("name"): e for e in (r.body or {}).get("entries", [])}
    check(r.status == 200 and names.get("fm-blob.bin", {}).get("size_bytes") == len(blob)
          and names.get("fm-blob.bin", {}).get("type") == "file",
          "file manager: the folder lists the file with its size", repr(r)[:400])
    r = cust.get(f"{base}/download?path=public_html/fm-blob.bin")
    check(r.status == 200 and r.data == blob, "file manager: the download is byte for byte what was uploaded",
          f"HTTP {r.status}, {len(r.data)} bytes")
    ctype, disp = r.headers.get("content-type", ""), r.headers.get("content-disposition", "")
    check(ctype.startswith("application/octet-stream") and disp.startswith("attachment")
          and "fm-blob.bin" in disp and r.headers.get("x-content-type-options") == "nosniff"
          and "sandbox" in r.headers.get("content-security-policy", ""),
          "the download is an attachment, application/octet-stream, nosniff, sandboxed", repr(r.headers))
    r = cust.get(f"{base}/download?path=public_html")
    check(r.status == 409 and r.code == "is_a_directory", "a folder cannot be downloaded (409 is_a_directory)", repr(r))
    # The editor.
    page = "public_html/fm-note.html"
    r = cust.put(f"{base}/content", {"path": page, "content": "<h1>fm-note-1</h1>\n", "overwrite": False})
    check(r.status in (200, 201), "file manager: the editor creates a file", repr(r))
    r = cust.get(f"{base}/content?path={page}")
    check(r.status == 200 and r.body.get("content") == "<h1>fm-note-1</h1>\n" and r.body.get("editable") is True
          and r.body.get("binary") is False, "file manager: the editor reads it back", repr(r))
    opened = r.body or {}
    # The change differs in size too: the panel's stale-save check compares the
    # size and the modification time, which is in whole seconds, and the stale
    # save below comes within the same second.
    r = cust.put(f"{base}/content", {"path": page, "content": "<h1>fm-note-2, longer</h1>\n", "overwrite": True,
                                    "expected_modified": opened.get("modified"), "expected_size": opened.get("size_bytes")})
    check(r.status in (200, 201), "file manager: the editor saves a change over the version it opened", repr(r))
    r = cust.put(f"{base}/content", {"path": page, "content": "<h1>stale</h1>\n", "overwrite": True,
                                    "expected_modified": opened.get("modified"), "expected_size": opened.get("size_bytes")})
    check(r.status == 409 and r.code == "file_changed", "a save over a file that changed since it was opened is refused"
          " (409 file_changed)", repr(r))
    r = cust.put(f"{base}/access", {"path": page, "access": "web_readable"})
    check(r.status == 200, "file manager: the page is made readable by the web server", repr(r))
    good, code, body = wait_site(sites["static"], "200", "<h1>fm-note-2, longer</h1>", "/fm-note.html")
    check(good, "the edited page is served by Nginx", f"{code} {body[:200]}")
    r = cust.get(f"{base}/download?path={page}")
    check(r.status == 200 and r.headers.get("content-type", "").startswith("application/octet-stream")
          and r.headers.get("content-disposition", "").startswith("attachment"),
          "an HTML file is downloaded as an attachment, never rendered in the panel's origin", repr(r.headers))
    r = cust.post(f"{base}/delete", {"paths": ["public_html/fm-blob.bin"]})
    check(r.status == 202, "file manager: a delete job is started", repr(r))
    check(eventually(lambda: not os.path.exists("/home/alice/public_html/fm-blob.bin"), 30, 1) is True,
          "and the file is gone")


def drive_php_settings(cust, sites):
    d = sites["php"]
    r = cust.put(f"/api/v1/sites/{d}/php-settings", {"memory_limit_mb": 200, "max_input_vars": 2000})
    check(r.status == 200 and (r.body.get("settings") or {}).get("memory_limit_mb") == 200,
          "customer changes the PHP site's settings (memory_limit 200 MiB, max_input_vars 2000)", repr(r)[:400])
    good, code, body = wait_site(d, "200", "memory_limit=200M max_input_vars=2000", "/?ini=1", tries=60)
    check(good, "the PHP page sees the new settings", f"{code} {body[:200]}")
    r = cust.put(f"/api/v1/sites/{d}/php-settings", {"memory_limit_mb": 1_000_000})
    check(r.status == 422 and r.code == "validation_failed", "a setting above the account's cap is refused (422)",
          repr(r)[:300])
    info(f"refusal of memory_limit_mb=1000000: {r.raw[:300]}")
    good, code, body = wait_site(d, "200", "memory_limit=200M", "/?ini=1", tries=4)
    check(good, "and the settings in force are unchanged", f"{code} {body[:200]}")


def drive_task(cust, alice_uid):
    script = ("const fs = require('fs'), path = require('path');\n"
              "fs.writeFileSync(path.join(__dirname, 'task-ran.txt'), 'task-ok ' + process.getuid() + ' ' + process.argv[2]);\n"
              "console.log('task-output-ok');\n")
    r = cust.put("/api/v1/accounts/alice/files/content", {"path": "task.js", "content": script, "overwrite": False})
    check(r.status in (200, 201), "the task's script is written with the editor", repr(r))
    r = cust.put("/api/v1/accounts/alice/tasks/drive-task",
                 {"kind": "node", "script": "task.js", "args": ["hello"],
                  "schedule": {"form": "daily", "hour": 4, "minute": 0}, "timeout_seconds": 60})
    check(r.status == 201, "customer creates a scheduled task (Node.js, daily)", repr(r)[:400])
    units = glob.glob("/etc/systemd/system/oxpanel-task-alice-*.timer")
    check(len(units) == 1, "the engine wrote its timer", repr(units))
    r = cust.get("/api/v1/accounts/alice/tasks")
    items = (r.body or {}).get("items", r.body if isinstance(r.body, list) else [])
    task = next((t for t in items if t.get("name") == "drive-task"), {})
    check(r.status == 200 and task.get("enabled") is True and task.get("next_run"),
          "the task is listed, enabled, with its next run", repr(r)[:400])
    r = cust.post("/api/v1/accounts/alice/tasks/drive-task/run")
    check(r.status == 200 and r.body.get("started") is True, "customer runs it now", repr(r))

    def done():
        r2 = cust.get("/api/v1/accounts/alice/tasks")
        its = (r2.body or {}).get("items", r2.body if isinstance(r2.body, list) else [])
        t = next((x for x in its if x.get("name") == "drive-task"), {})
        return (t.get("running") is False and t.get("last_result") is not None, t)
    res = eventually(done, 60, 1)
    check(res[0] is True and res[1].get("last_result") == "success", "the run finishes with success", repr(res[1])[:400])
    try:
        ran = open("/home/alice/task-ran.txt").read()
    except OSError as e:
        ran = repr(e)
    check(ran == f"task-ok {alice_uid} hello", "it ran as the account, with its argument", ran)
    r = cust.get("/api/v1/accounts/alice/tasks/drive-task/output")
    check(r.status == 200 and "task-output-ok" in (r.body or {}).get("text", ""), "its output is readable", repr(r)[:300])


DNS_FLAGS = ["--dns-nameservers", "ns1.product.example,ns2.product.example", "--dns-contact",
             "hostmaster@product.example", "--dns-ipv4", "192.0.2.25", "--disable-stock-named"]


def dig(name, rtype="A"):
    return sh("dig", "+short", "+norec", "+time=2", "+tries=1", "@127.0.0.1", name, rtype).stdout.strip()


def drive_dns(admin, cust):
    """DNS hosting through the panel. The product is installed without it; the
    operator switches it on with the installer (as the handbook says), and it is
    switched off again at the end of the drive. Returns whether it switched it on."""
    switched = False
    caps = admin.get("/api/v1/host/capabilities").body or {}
    if not (caps.get("dns") or {}).get("available"):
        p = sh("bash", "/root/acc/release/install.sh", "--yes", "--dns", *DNS_FLAGS, "--only", "dns", timeout=900)
        check(p.returncode == 0, "the operator switches DNS hosting on with the installer", p.stdout[-1500:] + p.stderr[-500:],
              fatal=True)
        switched = True
    res = eventually(lambda: (lambda c: ((c.get("dns") or {}).get("available") is True, c))(
        admin.get("/api/v1/host/capabilities").body or {}), 60, 1)
    check(res[0] is True, "the panel reports DNS hosting available", repr(res[1])[:300], fatal=True)

    def zone_there():
        r2 = cust.get("/api/v1/accounts/alice/dns/zones")
        return (r2.status == 200 and "alice.test" in r2.raw, r2)
    res = eventually(zone_there, 30, 1)
    check(res[0] is True, "the account's sites got their zone (alice.test) by themselves", repr(res[1])[:300])
    if res[0] is not True:
        r = cust.post("/api/v1/accounts/alice/dns/zones", {"zone": "alice.test"})
        info(f"zone created explicitly: {r!r}"[:300])
    r = cust.get("/api/v1/accounts/alice/dns/zones/alice.test")
    check(r.status == 200 and any(x.get("protected") for x in r.body.get("records", [])),
          "the zone lists the engine's own (protected) records", repr(r)[:400])
    r = cust.post("/api/v1/accounts/alice/dns/zones/alice.test/records",
                  {"name": "bad", "type": "A", "value": "not-an-address"})
    check(r.status == 422 and "ipv4_required" in r.raw, "a malformed record is refused (422, reason ipv4_required)",
          repr(r)[:300])
    r = cust.post("/api/v1/accounts/alice/dns/zones/alice.test/records",
                  {"name": "drive", "type": "A", "ttl": 300, "value": "192.0.2.77"})
    check(r.status == 201 and r.body.get("id"), "customer adds an A record through the panel", repr(r)[:300])
    rec_id = (r.body or {}).get("id")
    res = eventually(lambda: (lambda a: (a == "192.0.2.77", a))(dig("drive.alice.test")), 30, 1)
    check(res[0] is True, "the host's name server answers it (dig @127.0.0.1 drive.alice.test)", repr(res[1]))
    res = eventually(lambda: (lambda a: ("ns1.product.example" in a, a))(dig("alice.test", "SOA")), 10, 1)
    check(res[0] is True, "and the zone's SOA names the configured primary", repr(res[1]))
    if rec_id:
        r = cust.delete(f"/api/v1/accounts/alice/dns/zones/alice.test/records/{rec_id}")
        check(r.status in (200, 204), "customer deletes the record", repr(r))
        res = eventually(lambda: (lambda a: (a == "", a))(dig("drive.alice.test")), 30, 1)
        check(res[0] is True, "the name server no longer answers it", repr(res[1]))
    return switched


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
    # An API answer is never a document: its CSP forbids everything and sandboxes it.
    api_csp = r.headers.get("content-security-policy", "")
    check("default-src 'none'" in api_csp and "sandbox" in api_csp and "frame-ancestors 'none'" in api_csp,
          "an API answer carries the sandboxing CSP (default-src 'none'; frame-ancestors 'none'; sandbox)", api_csp)
    for hname, want in [("x-content-type-options", "nosniff"), ("strict-transport-security", "max-age=")]:
        check(want in r.headers.get(hname, ""), f"answer carries {hname}", repr(r.headers))
    r = admin.get("/")
    check(r.status == 200 and "<html" in r.raw.lower(),
          "the web interface (index.html) is served at /", repr(r)[:300])
    ui_csp = r.headers.get("content-security-policy", "")
    check("default-src 'self'" in ui_csp and "script-src 'self'" in ui_csp and "sandbox" not in ui_csp,
          "index.html is served with the application's CSP (default-src 'self')", ui_csp)
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
    r = cust.put(f"/api/v1/sites/{sites['static']}", {"document_root": "public_html"})
    check(r.status == 200, "PUT on an existing site updates it (200, not 201)", repr(r))
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
if (isset($_GET['ini'])) {
  echo 'memory_limit=', ini_get('memory_limit'), ' max_input_vars=', ini_get('max_input_vars');
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

    # ------------------------------------------------------------ file manager, PHP settings, a task, DNS
    drive_files(cust, sites, alice_uid)
    drive_php_settings(cust, sites)
    drive_task(cust, alice_uid)
    dns_switched = drive_dns(admin, cust)

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
    check(r.status == 200 and r.body.get("trash_id") and r.body.get("purge_at"),
          "customer deletes the database: it goes to the trash (trash_id, purge date)", repr(r))
    r = cust.get("/api/v1/accounts/alice/database-trash")
    check(r.status == 200 and any(t.get("name") == "alice_shop" for t in r.body.get("items", [])),
          "the deleted database is listed in the account's trash", repr(r)[:300])
    r = cust.get("/api/v1/accounts/alice/backups")
    for b in (r.body or {}).get("items", []):
        r2 = cust.delete(f"/api/v1/accounts/alice/backups/{b['id']}")
        check(r2.status == 204, f"customer deletes backup {b['id']}", repr(r2))
    r = cust.delete(f"/api/v1/accounts/alice/sftp/keys/{key_id}", {"end_sessions": True})
    check(r.status == 200, "customer removes its SFTP key", repr(r))
    r = cust.delete("/api/v1/accounts/alice")
    check(r.status == 409 and r.code == "last_hosting_account", "a customer cannot delete its last account", repr(r))
    r = reseller.delete("/api/v1/accounts/alice?remove_files=true")
    check(r.status == 409 and r.code == "account_has_databases",
          "deleting the account is refused while its database trash is not empty (409 account_has_databases)", repr(r))
    r = cust.delete("/api/v1/accounts/alice/database-trash", {"confirm_account": "someone-else"})
    check(r.status == 422 and "confirmation_mismatch" in r.raw, "emptying the trash needs the account's name typed again",
          repr(r))
    r = cust.delete("/api/v1/accounts/alice/database-trash", {"confirm_account": "alice"})
    check(r.status == 200, "customer empties the database trash through the panel", repr(r))
    r = cust.get("/api/v1/accounts/alice/database-trash")
    check(r.status == 200 and not r.body.get("items"), "the trash is empty", repr(r)[:300])
    # Something in the trash again, for the one-step deletion to take with it.
    r = cust.post("/api/v1/accounts/alice/databases", {"suffix": "scratch"})
    check(r.status == 201, "customer creates another database", repr(r))
    r = cust.delete("/api/v1/accounts/alice/databases/alice_scratch")
    check(r.status == 200 and r.body.get("trash_id"), "and deletes it (to the trash)", repr(r))
    r = cust.post("/api/v1/accounts/alice/deletion", {"confirm_account": "alice", "final_backup_retain_days": 0})
    check(r.status == 409 and r.code == "last_hosting_account",
          "the one-step deletion of a customer's own last account is refused too", repr(r))
    r = reseller.post("/api/v1/accounts/alice/deletion", {"confirm_account": "alice", "final_backup_retain_days": 0})
    check(r.status == 202 and (r.body.get("deletion") or {}).get("id"),
          "reseller deletes the account in one step, trash, task, zones and files included (202)", repr(r), fatal=True)
    d, secs = poll_deletion(reseller, r.body["deletion"]["id"])
    check(d is not None and d.status == 200 and d.body.get("state") == "succeeded",
          f"the deletion succeeds ({secs:.0f}s)", repr(d)[:600])
    p = sh("mariadb", "--no-defaults", "-u", "root", "-N", "-B", "-e",
           "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE 'alice\\_%'"
           " OR SCHEMA_NAME LIKE 'oxpanel\\_trash\\_%'")
    check(p.returncode == 0 and p.stdout.strip() == "0", "no database of the account is left, not even in the trash",
          p.stdout + p.stderr)
    left = glob.glob("/etc/systemd/system/oxpanel-task-alice-*")
    check(not left, "no scheduled task of the account is left (its timer and service are gone)", repr(left))
    p = sh("oxpanel-ctl", "tenant", "get", "alice")
    check(p.returncode != 0, "the engine no longer has the account", p.stdout)
    check(not os.path.exists("/home/alice"), "its home is gone")
    if dns_switched:
        res = eventually(lambda: (lambda a: (a == "", a))(dig("alice.test", "SOA")), 30, 1)
        check(res[0] is True, "the account's zone went with it", repr(res[1]))
        p = sh("bash", "/root/acc/release/install.sh", "--yes", "--no-dns", "--only", "dns", timeout=600)
        check(p.returncode == 0, "the operator switches DNS hosting off again (for the later phases)",
              p.stdout[-1500:] + p.stderr[-500:])
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
