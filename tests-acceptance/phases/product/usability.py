"""The usability release (engine 0.3.2, panel 0.2.2) through the panel's HTTPS API (phase 25).

Imported by drive.py, which hands over its helpers with `bind()`. Each step is
driven as a browser does (session cookie, CSRF token, Origin) and what the
answer claims is then looked at on the host:

- the optional features an installation left off, as the panel reports them to
  an administrator, and the installer commands its "how to switch it on" cards
  show (the options are run, the DNS one for real by drive.py);
- the panel's own certificate: self-signed at first, then the engine's
  automatic one for the panel's name (from a local Pebble, never a real
  authority), switched in by the panel's path unit, renewed, the administrator's
  own certificate winning and `--automatic` handing back, a certificate Nginx
  refuses rolled back, and the same in host-name mode;
- subdomains by label, `www` on a new and on an existing site, with their DNS
  records when the zone is hosted here and the public address when it is not;
- "check again now" for Automatic HTTPS: a customer waits for the back-off,
  staff do not;
- a backup downloaded as one tar file, checked against its manifest, refused to
  another customer, and a large one streamed without Nginx or the panel holding it;
- a deleted customer's retained backup restored into a new account;
- `oxpanel-panel-setup reset-password` on the host.
"""
import hashlib
import http.client
import json
import os
import re
import shutil
import ssl
import subprocess
import tarfile
import threading
import time
import urllib.parse

D = None  # drive.py's module (check, info, sh, eventually, dig, Browser, ...)

SETUP = "/usr/sbin/oxpanel-panel-setup"
SETUP_CONF = "/etc/oxpanel-panel/setup.conf"
NGINX_CONF = "/etc/nginx/conf.d/00-oxpanel-panel.conf"
REGISTRATION = "/etc/oxpanel/host-certificates.d/panel.conf"
AUTO_CRT = "/etc/pki/oxpanel-host/panel.crt"
AUTO_KEY = "/etc/pki/oxpanel-host/panel.key"
OWN_CRT = "/etc/pki/oxpanel-panel/panel.crt"
PANEL_NAME = "mail.oxacc.test"      # the mail host name of the product install: the installer gives it to the panel
HOSTNAME_MODE_NAME = "panel.oxacc.test"
PUBLIC_IPV4 = "192.0.2.25"          # the same address drive.py gives DNS hosting
HOSTS_MARK = "# oxacc-usability-drive"

# Pebble, Let's Encrypt's ACME test server, from the release run-inside.sh pins.
PEBBLE_URL = "https://github.com/letsencrypt/pebble/releases/download/v2.10.1/pebble-linux-amd64.tar.gz"
PEBBLE_SHA256 = "4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed"
PEBBLE_BIN = "/usr/local/bin/oxpanel-acc-pebble"
PEBBLE_DIR = "/usr/local/share/oxpanel-acc-pebble"   # outside /root: the ACME client's unit has ProtectHome=yes
DAEMON_ENV = "/etc/oxpanel/daemon.env"


def bind(module):
    global D
    D = module


# ------------------------------------------------------------------ helpers
def items(r):
    b = r.body or {}
    return b.get("items", []) if isinstance(b, dict) else []


def field_reason(r, field, reason):
    if r.status != 422 or r.code != "validation_failed":
        return False
    return any(f.get("field") == field and f.get("reason") == reason for f in (r.body or {}).get("error", {}).get("fields", []))


def avc_count():
    p = D.sh("bash", "-c", "ausearch --input-logs -m avc -ts boot -i </dev/null 2>/dev/null | grep -c '^type=AVC' || true")
    try:
        return int(p.stdout.strip() or 0)
    except ValueError:
        return -1


def setup(*args, timeout=600):
    p = D.sh(SETUP, *args, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).strip()


def conf_value(key, path=SETUP_CONF):
    try:
        lines = open(path).read().splitlines()
    except OSError:
        return None
    vals = [ln.split("=", 1)[1] for ln in lines if ln.startswith(key + "=")]
    return vals[-1] if vals else None


def served_lines():
    try:
        return re.findall(r"^\s*ssl_certificate\s+([^;]+);", open(NGINX_CONF).read(), re.M)
    except OSError:
        return []


def fp_file(path):
    return D.sh("openssl", "x509", "-in", path, "-noout", "-fingerprint", "-sha256").stdout.strip()


def fp_served(port, sni):
    return D.sh("bash", "-c", f"openssl s_client -connect 127.0.0.1:{port} -servername {sni} </dev/null 2>/dev/null"
                              " | openssl x509 -noout -fingerprint -sha256 2>/dev/null").stdout.strip()


def issuer_served(port, sni):
    return D.sh("bash", "-c", f"openssl s_client -connect 127.0.0.1:{port} -servername {sni} </dev/null 2>/dev/null"
                              " | openssl x509 -noout -issuer 2>/dev/null").stdout.strip()


def served_becomes(port, sni, want_fp, tries=60):
    """Nginx applies a reload a moment after it returns: poll the handshake."""
    got = ""
    for _ in range(tries):
        got = fp_served(port, sni)
        if got and got == want_fp:
            return True, got
        time.sleep(0.5)
    return False, got


def cert_host(consumer="panel"):
    p = D.sh("oxpanel-ctl", "cert", "host", consumer)
    return dict(ln.split("=", 1) for ln in p.stdout.splitlines() if "=" in ln)


def auto_run():
    p = D.sh("timeout", "300", "oxpanel-ctl", "cert", "auto", "run", timeout=330)
    return p.returncode, (p.stdout + p.stderr).strip()


def cert_service_runs():
    """How often the panel's certificate oneshot has run this boot, and its last result."""
    p = D.sh("journalctl", "-b", "-u", "oxpanel-panel-certificate.service", "--no-pager", "-o", "cat")
    starts = p.stdout.count("Starting OxPanel panel: serve the certificate")
    res = D.sh("systemctl", "show", "-p", "Result", "--value", "oxpanel-panel-certificate.service").stdout.strip()
    return starts, res, p.stdout


def wait_service_run(before, tries=60):
    """Wait until the path unit started the oneshot again and it finished."""
    starts, res, log = before, "", ""
    for _ in range(tries):
        starts, res, log = cert_service_runs()
        active = D.sh("systemctl", "is-active", "oxpanel-panel-certificate.service").stdout.strip()
        if starts > before and active in ("inactive", "failed"):
            return True, res, log
        time.sleep(0.5)
    return False, res, log


def health(url_port=8443, host=None, sni=None):
    h = host or f"127.0.0.1:{url_port}"
    args = ["curl", "-sk", "--max-time", "10", "-o", "/dev/null", "-w", "%{http_code}", "-H", f"Host: {h}"]
    if sni:
        args += ["--resolve", f"{sni}:{url_port}:127.0.0.1", f"https://{sni}:{url_port}/api/v1/health"]
    else:
        args += [f"https://127.0.0.1:{url_port}/api/v1/health"]
    return D.sh(*args).stdout.strip()


def make_cert(stem, cn, sans, key_args=("-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"), org="Acceptance"):
    crt, key = os.path.join(D.WORK, stem + ".crt"), os.path.join(D.WORK, stem + ".key")
    D.sh("openssl", "req", "-x509", *key_args, "-nodes", "-days", "30", "-subj", f"/O={org}/CN={cn}",
         "-addext", "subjectAltName=" + ",".join(f"DNS:{s}" for s in sans), "-keyout", key, "-out", crt, check_rc=True)
    return crt, key


# ------------------------------------------------------------------ 1. features left off, and how to switch them on
def off_states(admin):
    """The product is installed with email and login banning but without DNS
    hosting and without public addresses: GET /host must say so, with what the
    UI needs to show "off — how to switch it on"."""
    r = admin.get("/api/v1/host")
    h = r.body or {}
    dns = h.get("dns") or {}
    D.check(r.status == 200 and dns.get("enabled") is False and dns.get("available") is False,
            "GET /host: DNS hosting is reported off (enabled=false, available=false)", json.dumps(dns)[:300])
    D.check(h.get("public_ipv4") == "" and h.get("public_ipv6") == "",
            "GET /host: no public address is claimed when none was configured (empty, never guessed)",
            json.dumps({k: h.get(k) for k in ("public_ipv4", "public_ipv6")}))
    lb = h.get("login_banning") or {}
    D.check(lb.get("active") is True and lb.get("jails"),
            "GET /host: login banning is on (fail2ban with OxPanel's jails) and its jails are listed", json.dumps(lb)[:300])
    D.info(f"login banning as reported: {json.dumps(lb)[:300]}")
    hc = [c for c in h.get("host_certificates") or [] if c.get("consumer") == "panel"]
    D.check(len(hc) == 1 and hc[0].get("name") == PANEL_NAME and hc[0].get("state") == "pending" and hc[0].get("reason"),
            f"GET /host: the panel's certificate for {PANEL_NAME} is pending, with the reason (no authority reachable)",
            json.dumps(h.get("host_certificates"))[:500])
    D.info(f"the panel's certificate before any authority: {json.dumps(hc)[:400]}")
    r = admin.get("/api/v1/host/capabilities")
    D.check(r.status == 200 and ((r.body or {}).get("dns") or {}).get("available") is False,
            "GET /host/capabilities: DNS off for everyone else's pages", repr(r)[:200])
    r = admin.get("/api/v1/auth/session")
    D.check(r.status == 200 and (r.body or {}).get("panel_address") == f"https://{PANEL_NAME}:8443/",
            "the session carries the panel's proper address (https://<name>:8443/, from oxpanel-panel-setup)",
            repr(r)[:300])

    # The commands the "how to switch it on" cards show (the panel's
    # feature-off/logic.ts), with this host's values. Each must be a command the
    # installer accepts: run with --check (preflight only, nothing changes).
    # The DNS card's command is run for real in drive.py's DNS step.
    cards = {
        "email (with login banning on)": ["--only", "mail,firewall,fail2ban", "--mail", "--mail-hostname", "mail.oxacc.test",
                                          "--enable-epel", "--fail2ban"],
        "disk quotas": ["--only", "quota", "--quota", "--reboot"],
        "login banning": ["--only", "fail2ban", "--fail2ban", "--enable-epel", "--ignore-ip", "203.0.113.5"],
        "DNS hosting": ["--only", "dns,firewall", "--dns", "--dns-nameservers", "ns1.oxacc.test,ns2.oxacc.test",
                        "--dns-contact", "hostmaster@oxacc.test", "--dns-ipv4", "203.0.113.10"],
    }
    for what, args in cards.items():
        p = D.sh("bash", "/root/acc/release/install.sh", "--yes", "--check", *args, timeout=300)
        D.check(p.returncode == 0, f"the {what} card's command is accepted by the installer (install.sh --check {' '.join(args)})",
                (p.stdout + p.stderr)[-1200:])
    p = D.sh("bash", "/root/acc/release/install.sh", "--yes", "--check", "--only", "dns,nosuchstage", timeout=120)
    D.check(p.returncode != 0 and "nosuchstage" in (p.stdout + p.stderr),
            "an unknown stage in --only is refused, not silently skipped", (p.stdout + p.stderr)[-400:])

    # The public addresses alone ("the public addresses only" in the handbook).
    p = D.sh("bash", "/root/acc/release/install.sh", "--yes", "--only", "daemon", "--public-ipv4", PUBLIC_IPV4, timeout=600)
    D.check(p.returncode == 0, f"the operator gives the public address with install.sh --only daemon --public-ipv4 {PUBLIC_IPV4}",
            (p.stdout + p.stderr)[-1500:])
    res = D.eventually(lambda: (lambda b: (b.get("public_ipv4") == PUBLIC_IPV4, b.get("public_ipv4")))(
        admin.get("/api/v1/host").body or {}), 30, 1)
    D.check(res[0] is True, "GET /host shows it at once (the engine was restarted to read it)", repr(res))
    p = D.sh("bash", "/root/acc/release/install.sh", "--yes", "--only", "daemon", "--public-ipv4", "127.0.0.1", timeout=300)
    D.check(p.returncode != 0, "a loopback address is refused as the public address", (p.stdout + p.stderr)[-400:])


# ------------------------------------------------------------------ 2. the panel's own certificate
class Pebble:
    """A local ACME server for the panel's name; the engine is pointed at it
    for the duration and back at nothing afterwards."""

    def __init__(self):
        self.env_backup = None
        self.hosts_added = False

    def start(self):
        work = D.WORK
        if not os.path.exists(PEBBLE_BIN):
            tgz = os.path.join(work, "pebble.tar.gz")
            p = D.sh("curl", "-sSfL", "-o", tgz, PEBBLE_URL, timeout=300)
            D.check(p.returncode == 0, "Pebble (the ACME test server) is downloaded", p.stderr, fatal=True)
            got = hashlib.sha256(open(tgz, "rb").read()).hexdigest()
            D.check(got == PEBBLE_SHA256, "Pebble matches the pinned checksum", got, fatal=True)
            D.sh("tar", "-xzf", tgz, "-C", work, check_rc=True)
            D.sh("install", "-m0755", os.path.join(work, "pebble-linux-amd64/linux/amd64/pebble"), PEBBLE_BIN, check_rc=True)
        os.makedirs(PEBBLE_DIR, exist_ok=True)
        ca_key, ca = f"{PEBBLE_DIR}/ca.key", f"{PEBBLE_DIR}/ca.crt"
        D.sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "3",
             "-subj", "/CN=oxpanel acceptance Pebble listener CA", "-keyout", ca_key, "-out", ca, check_rc=True)
        D.sh("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-subj", "/CN=localhost",
             "-keyout", f"{PEBBLE_DIR}/pebble.key", "-out", f"{PEBBLE_DIR}/pebble.csr", check_rc=True)
        with open(f"{PEBBLE_DIR}/san.ext", "w") as f:
            f.write("subjectAltName=DNS:localhost,IP:127.0.0.1\n")
        D.sh("openssl", "x509", "-req", "-in", f"{PEBBLE_DIR}/pebble.csr", "-CA", ca, "-CAkey", ca_key, "-CAcreateserial",
             "-days", "3", "-extfile", f"{PEBBLE_DIR}/san.ext", "-out", f"{PEBBLE_DIR}/pebble.crt", check_rc=True)
        os.chmod(f"{PEBBLE_DIR}/pebble.key", 0o600)
        # Certificates valid for 10 days: inside the 30-day renewal window, so
        # every certificate run renews (a renewal can be watched at once).
        cfg = {"pebble": {"listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000",
                          "certificate": f"{PEBBLE_DIR}/pebble.crt", "privateKey": f"{PEBBLE_DIR}/pebble.key",
                          "httpPort": 80, "tlsPort": 5001, "ocspResponderURL": "", "externalAccountBindingRequired": False,
                          "profiles": {"default": {"description": "oxpanel acceptance", "validityPeriod": 864000}}}}
        with open(f"{PEBBLE_DIR}/pebble.json", "w") as f:
            json.dump(cfg, f)
        D.sh("systemctl", "stop", "oxpanel-acc-pebble.service")
        p = D.sh("systemd-run", "--unit=oxpanel-acc-pebble", "--collect", "--setenv=PEBBLE_VA_NOSLEEP=1",
                 PEBBLE_BIN, "-config", f"{PEBBLE_DIR}/pebble.json")
        D.check(p.returncode == 0, "Pebble starts", p.stderr, fatal=True)
        up = D.eventually(lambda: D.sh("curl", "-sf", "--cacert", ca, "https://localhost:14000/dir").returncode == 0, 50, 0.2)
        D.check(up is True, "Pebble answers on its directory", "", fatal=True)
        # The panel's names resolve to this host (in real life: the operator's DNS).
        if D.sh("getent", "hosts", PANEL_NAME).returncode != 0 or D.sh("getent", "hosts", HOSTNAME_MODE_NAME).returncode != 0:
            with open("/etc/hosts", "a") as f:
                f.write(f"127.0.0.1 {PANEL_NAME} {HOSTNAME_MODE_NAME} {HOSTS_MARK}\n")
            self.hosts_added = True
        self.env_backup = open(DAEMON_ENV).read()
        with open(DAEMON_ENV, "a") as f:
            f.write(f"OXPANEL_ACME_DIRECTORY_URL=https://localhost:14000/dir\nOXPANEL_ACME_CA_FILE={ca}\n"
                    "OXPANEL_ACME_EMAIL=hostmaster@oxacc.test\n")
        D.sh("systemctl", "restart", "oxpanel-daemon", check_rc=True)
        p = D.sh("oxpanel-ctl", "host", "info")
        D.check("acme_directory=https://localhost:14000/dir" in p.stdout,
                "the engine now asks the local Pebble (never a real authority)", p.stdout[:400], fatal=True)

    def stop(self):
        if self.env_backup is not None:
            with open(DAEMON_ENV, "w") as f:
                f.write(self.env_backup)
            D.sh("systemctl", "restart", "oxpanel-daemon")
            self.env_backup = None
        D.sh("systemctl", "stop", "oxpanel-acc-pebble.service")
        if self.hosts_added:
            lines = [ln for ln in open("/etc/hosts").read().splitlines(True) if HOSTS_MARK not in ln]
            with open("/etc/hosts", "w") as f:
                f.writelines(lines)
            self.hosts_added = False
        shutil.rmtree(PEBBLE_DIR, ignore_errors=True)
        try:
            os.unlink(PEBBLE_BIN)
        except OSError:
            pass
        p = D.sh("oxpanel-ctl", "host", "info")
        D.check("acme_directory=https://127.0.0.1:9/directory" in p.stdout,
                "the engine points at nothing again (the test host's setting)", p.stdout[:400])


def panel_certificate(admin):
    avc0 = avc_count()
    D.check(conf_value("NAME") == PANEL_NAME,
            f"the installer gave the panel the mail host name {PANEL_NAME} as its name", open(SETUP_CONF).read())
    reg = open(REGISTRATION).read() if os.path.exists(REGISTRATION) else ""
    D.check(f"name={PANEL_NAME}\n" in reg and "challenges=engine\n" in reg and "redirect_port=8443" in reg,
            "oxpanel-panel-setup registered the name with the engine (port mode: the engine answers the challenges)", reg)
    st = os.stat(REGISTRATION)
    D.check(st.st_uid == 0 and (st.st_mode & 0o022) == 0, "the registration is root's and writable by root only",
            oct(st.st_mode))
    D.check(served_lines() == [OWN_CRT], "before any certificate the panel serves its own (self-signed) one",
            repr(served_lines()))
    iss = issuer_served(8443, PANEL_NAME)
    D.check("OxPanel" in iss, "... which is what the panel's port presents", iss)
    rc, out = setup("status")
    D.check("certificate: self-signed" in out, "oxpanel-panel-setup status says so", out[-600:])
    D.check(D.sh("systemctl", "is-active", "oxpanel-panel-certificate.path").stdout.strip() == "active",
            "the panel's path unit watches for the engine's certificate", "")

    peb = Pebble()
    try:
        peb.start()
        runs0, _, _ = cert_service_runs()
        rc, out = auto_run()
        D.info(f"cert auto run: {out[-300:]}")
        ch = cert_host()
        D.check(ch.get("state") in ("issued", "renewing") and "pebble" in ch.get("issuer", "").lower(),
                f"the engine obtained the panel's certificate for {PANEL_NAME} (Pebble's 10 days: issued or renewing)",
                repr(ch))
        st_c, st_k = os.stat(AUTO_CRT), os.stat(AUTO_KEY)
        D.check((st_c.st_uid, st_c.st_mode & 0o777, st_k.st_uid, st_k.st_mode & 0o777) == (0, 0o644, 0, 0o600),
                "the pair is root's: certificate 0644, key 0600", f"{oct(st_c.st_mode)} {oct(st_k.st_mode)}")
        good, res, log = wait_service_run(runs0)
        D.check(good and res == "success", "the path unit ran oxpanel-panel-certificate.service, which succeeded",
                f"result={res}\n{log[-800:]}")
        D.check(served_lines() == [AUTO_CRT], "the panel's server block now names the automatic certificate",
                repr(served_lines()))
        good, got = served_becomes(8443, PANEL_NAME, fp_file(AUTO_CRT))
        D.check(good, "the panel answers with exactly that certificate", f"{got} vs {fp_file(AUTO_CRT)}")
        D.check(health() == "200", "the panel answers on it", "")
        rc, out = setup("status")
        D.check("certificate: automatic" in out, "status: automatic", out[-600:])
        r = admin.get("/api/v1/host")
        hc = [c for c in (r.body or {}).get("host_certificates") or [] if c.get("consumer") == "panel"]
        D.check(len(hc) == 1 and hc[0].get("state") in ("issued", "renewing") and "pebble" in (hc[0].get("issuer") or "").lower()
                and hc[0].get("not_after"), "GET /host reports it to the administrator (state, issuer, expiry)", json.dumps(hc)[:400])

        # Renewal: the engine replaces the pair and reloads Nginx itself.
        before = fp_file(AUTO_CRT)
        runs1, _, _ = cert_service_runs()
        auto_run()
        after = fp_file(AUTO_CRT)
        D.check(after and after != before, "renewal: the engine wrote a new certificate", f"{before} -> {after}")
        good, got = served_becomes(8443, PANEL_NAME, after)
        D.check(good, "renewal: the panel answers with the new one", f"{got} vs {after}")
        good, res, _ = wait_service_run(runs1, tries=20)
        D.check(served_lines() == [AUTO_CRT] and (not good or res == "success"),
                "renewal: the server block is unchanged (same paths), the path unit's run was a no-op", repr(served_lines()))

        # Precedence: the administrator's own certificate wins, --automatic hands back.
        own_crt, own_key = make_cert("own", PANEL_NAME, [PANEL_NAME])
        rc, out = setup("certificate", "--cert", own_crt, "--key", own_key)
        D.check(rc == 0 and conf_value("CERT") == "manual", "the administrator installs a certificate of its own (CERT=manual)",
                out[-600:])
        good, got = served_becomes(8443, PANEL_NAME, fp_file(own_crt))
        D.check(good and served_lines() == [OWN_CRT], "it is served from then on", f"{got} {served_lines()}")
        runs2, _, _ = cert_service_runs()
        auto_run()
        wait_service_run(runs2, tries=30)
        time.sleep(1)
        D.check(fp_served(8443, PANEL_NAME) == fp_file(own_crt) and served_lines() == [OWN_CRT],
                "a renewal of the automatic certificate does not take over from the administrator's", "")
        rc, out = setup("status")
        D.check("installed by the administrator" in out, "status: installed by the administrator", out[-600:])
        # A key that does not belong to the certificate is refused; nothing changes.
        _, other_key = make_cert("other", PANEL_NAME, [PANEL_NAME])
        rc, out = setup("certificate", "--cert", own_crt, "--key", other_key)
        D.check(rc != 0 and "does not belong" in out and served_lines() == [OWN_CRT]
                and fp_served(8443, PANEL_NAME) == fp_file(own_crt),
                "a certificate with someone else's key is refused; the served one stays", out[-400:])
        rc, out = setup("certificate", "--automatic")
        D.check(rc == 0 and conf_value("CERT") == "auto" and served_lines() == [AUTO_CRT],
                "certificate --automatic hands back to the engine's certificate", out[-600:])
        good, got = served_becomes(8443, PANEL_NAME, fp_file(AUTO_CRT))
        D.check(good, "... and it is served again", got)

        # A certificate Nginx refuses (an RSA key of 1024 bits: below the host's
        # crypto policy, though openssl reads it) is rolled back.
        setup("certificate", "--cert", own_crt, "--key", own_key)
        saved = {p: open(p, "rb").read() for p in (AUTO_KEY, AUTO_CRT)}
        weak_crt, weak_key = make_cert("weak", PANEL_NAME, [PANEL_NAME], key_args=("-newkey", "rsa:1024"))
        try:
            runs3, _, _ = cert_service_runs()
            shutil.copyfile(weak_key, AUTO_KEY)
            shutil.copyfile(weak_crt, AUTO_CRT)
            wait_service_run(runs3, tries=20)
            rc, out = setup("certificate", "--automatic")
            D.check(rc != 0 and "refused" in out and served_lines() == [OWN_CRT],
                    "a certificate Nginx refuses is not switched to: the previous configuration is kept", out[-600:])
            D.check(D.sh("nginx", "-t").returncode == 0 and fp_served(8443, PANEL_NAME) == fp_file(own_crt)
                    and health() == "200", "Nginx is unharmed and the panel still answers with the previous certificate", "")
            rc2, st = setup("status")
            D.check(conf_value("CERT") == "manual" and "installed by the administrator" in st,
                    "the refused --automatic leaves the state as served: CERT=manual, status says the administrator's",
                    f"CERT={conf_value('CERT')}\n{st[-400:]}")
        finally:
            runs4, _, _ = cert_service_runs()
            for p, data in saved.items():  # key first, as the engine writes them
                with open(p + ".acc", "wb") as f:
                    f.write(data)
                os.chmod(p + ".acc", 0o600 if p == AUTO_KEY else 0o644)
                os.replace(p + ".acc", p)
            D.sh("restorecon", AUTO_KEY, AUTO_CRT)
        good, res, _ = wait_service_run(runs4, tries=30)
        rc, out = setup("certificate", "--automatic")
        D.check(rc == 0 and served_lines() == [AUTO_CRT], "with the engine's own pair back, --automatic succeeds", out[-400:])
        good, got = served_becomes(8443, PANEL_NAME, fp_file(AUTO_CRT))
        D.check(good, "... and it is served", got)
        D.check(D.sh("systemctl", "show", "-p", "Result", "--value", "oxpanel-panel-certificate.service").stdout.strip() == "success",
                "the certificate oneshot is not left failed", "")

        hostname_mode(admin)

        p = D.sh("oxpanel-ctl", "host", "reconcile")
        D.check(p.returncode == 0 and "drifts=0" in p.stdout.splitlines(), "reconcile is clean after the panel's certificates",
                p.stdout + p.stderr)
    finally:
        peb.stop()
    D.check(health() == "200", "the panel answers on its port after the engine points at nothing again", "")
    n = avc_count() - avc0
    D.check(n == 0, "zero SELinux denials for the certificate oneshot, its path unit and the engine's certificate runs",
            D.sh("bash", "-c", "ausearch --input-logs -m avc -ts boot -i </dev/null 2>/dev/null | tail -30").stdout)


def hostname_mode(admin):
    """The same path with the panel on its own host name (port 443, its own
    port-80 server answering the engine's challenges), then back to port mode."""
    rc, out = setup("enable", "--hostname", HOSTNAME_MODE_NAME)
    D.check(rc == 0, f"the panel is moved to host-name mode ({HOSTNAME_MODE_NAME})", out[-800:])
    reg = open(REGISTRATION).read() if os.path.exists(REGISTRATION) else ""
    D.check(f"name={HOSTNAME_MODE_NAME}\n" in reg and "challenges=consumer" in reg,
            "the registration follows: the panel's own port-80 server answers the challenges", reg)
    tok = "/var/lib/oxpanel-acme/challenges/acc-hostname-mode-token"
    D.sh("setpriv", "--reuid=oxpanel-acme", "--regid=oxpanel-acme", "--clear-groups", "--", "sh", "-c",
         f"echo hostname-mode-challenge > {tok}")
    got = D.sh("curl", "-s", "-H", f"Host: {HOSTNAME_MODE_NAME}",
               "http://127.0.0.1/.well-known/acme-challenge/acc-hostname-mode-token").stdout.strip()
    D.sh("rm", "-f", tok)
    D.check(got == "hostname-mode-challenge", "the panel's port-80 server serves the engine's challenge directory", got)
    runs0, _, _ = cert_service_runs()
    auto_run()
    ch = cert_host()
    D.check(ch.get("name") == HOSTNAME_MODE_NAME and ch.get("state") in ("issued", "renewing"),
            "the engine obtained the certificate for the new name (consumer challenges)", repr(ch))
    san = D.sh("openssl", "x509", "-in", AUTO_CRT, "-noout", "-ext", "subjectAltName").stdout
    D.check(f"DNS:{HOSTNAME_MODE_NAME}" in san, "the pair names the panel's host name", san)
    wait_service_run(runs0)
    good, got = served_becomes(443, HOSTNAME_MODE_NAME, fp_file(AUTO_CRT))
    D.check(good and served_lines() == [AUTO_CRT], "the panel answers on 443 for its name with the automatic certificate",
            f"{got} {served_lines()}")
    D.check(health(443, sni=HOSTNAME_MODE_NAME, host=HOSTNAME_MODE_NAME) == "200", "the panel answers there", "")
    D.check(D.sh("nginx", "-t").returncode == 0, "nginx -t passes in host-name mode", "")
    # Back to port mode, under the mail host name.
    rc, out = setup("enable", "--port", "8443", "--name", PANEL_NAME)
    D.check(rc == 0 and conf_value("NAME") == PANEL_NAME and conf_value("MODE") == "port",
            "back to port mode under the mail host name", out[-800:])
    D.check(served_lines() == [OWN_CRT], "until the engine has a certificate for that name again, the panel's own is served",
            repr(served_lines()))
    runs1, _, _ = cert_service_runs()
    auto_run()
    wait_service_run(runs1)
    good, got = served_becomes(8443, PANEL_NAME, fp_file(AUTO_CRT))
    D.check(good and served_lines() == [AUTO_CRT], "and then the automatic one for the mail host name", f"{got} {served_lines()}")
    r = admin.get("/api/v1/host")
    D.check(r.status == 200, "the administrator's session still works after the moves (sessions survive the panel's restart)",
            repr(r)[:200])


# ------------------------------------------------------------------ 3. subdomains and www
def overview(cust):
    return cust.get("/api/v1/accounts/alice/subdomains")


def put_page(cust, path, content):
    r = cust.put("/api/v1/accounts/alice/files/content", {"path": path, "content": content, "overwrite": True})
    r2 = cust.put("/api/v1/accounts/alice/files/access", {"path": path, "access": "web_readable"})
    return r.status in (200, 201) and r2.status == 200, f"{r!r} {r2!r}"


def subdomains_before_dns(cust):
    r = overview(cust)
    b = r.body or {}
    parents = {p.get("domain"): p for p in b.get("parents", [])}
    D.check(r.status == 200 and b.get("dns_available") is False and "alice.test" in parents
            and parents["alice.test"].get("dns_hosted") is False,
            "subdomains: the account's domain is offered as a parent, not hosted here (DNS hosting is off)",
            f"dns_available={b.get('dns_available')!r} parents={json.dumps(b.get('parents'))}")
    D.check(b.get("public_ipv4") == PUBLIC_IPV4,
            "... with the server's public address for the record the customer adds elsewhere", repr(b.get("public_ipv4")))
    sites = b.get("sites") or {}
    D.check(sites.get("used") == 3 and sites.get("max") == 10 and sites.get("remaining") == 7,
            "the overview counts the plan's sites (3 of 10)", repr(sites))
    r = cust.post("/api/v1/accounts/alice/subdomains", {"parent": "alice.test", "label": "blog"})
    site = r.body or {}
    D.check(r.status == 201 and site.get("domain") == "blog.alice.test" and site.get("document_root") == "blog.alice.test"
            and not site.get("aliases"), "a subdomain by its label only: blog.alice.test, in a folder of its own, no www",
            repr(r)[:500])
    good, detail = put_page(cust, "blog.alice.test/index.html", "blog-ok\n")
    D.check(good, "a page is put in its folder with the file manager", detail)
    good, code, body = D.wait_site("blog.alice.test", "200", "blog-ok")
    D.check(good, "Nginx serves the subdomain from its folder", f"{code} {body[:200]}")
    r = overview(cust)
    subs = [(s.get("parent"), (s.get("site") or {}).get("domain")) for s in (r.body or {}).get("subdomains", [])]
    D.check(("alice.test", "blog.alice.test") in subs and ((r.body or {}).get("sites") or {}).get("used") == 4,
            "it is listed under its parent and counted", repr(r)[:600])
    for label, reason, what in [("Bad_Label", "label_syntax", "a label with characters a name cannot have"),
                                ("a" * 64, "label_syntax", "a label of 64 characters"),
                                ("x.y", "label_syntax", "two labels"),
                                ("blog", "already_exists", "a subdomain that exists"),
                                ("www", "www_is_alias", "www (an alias of the site, not a subdomain)"),
                                ("webmail", "reserved_name", "webmail (the server's)")]:
        r = cust.post("/api/v1/accounts/alice/subdomains", {"parent": "alice.test", "label": label})
        D.check(field_reason(r, "label", reason), f"refused: {what} (422, label {reason})", repr(r)[:300])
    r = cust.post("/api/v1/accounts/alice/subdomains", {"parent": "example.org", "label": "x"})
    D.check(field_reason(r, "parent", "not_your_domain"), "refused: a parent the account does not have (not_your_domain)",
            repr(r)[:300])
    r = cust.post("/api/v1/accounts/bob/subdomains", {"parent": "alice.test", "label": "x"})
    D.check(r.status in (403, 404), "a customer cannot add a subdomain to another customer's account", repr(r)[:200])


def subdomains_after_dns(admin, cust, mst):
    r = overview(cust)
    b = r.body or {}
    parents = {p.get("domain"): p for p in b.get("parents", [])}
    D.check(r.status == 200 and b.get("dns_available") is True and (parents.get("alice.test") or {}).get("dns_hosted") is True,
            "with DNS hosting on, alice.test is a hosted parent", repr(r)[:500])
    res = D.eventually(lambda: (lambda a: (a == PUBLIC_IPV4, a))(D.dig("blog.alice.test")), 30, 1)
    D.check(res[0] is True, "the subdomain made before DNS hosting has its address record in the hosted zone", repr(res[1]))
    r = cust.post("/api/v1/accounts/alice/subdomains", {"parent": "alice.test", "label": "news"})
    D.check(r.status == 201 and (r.body or {}).get("domain") == "news.alice.test", "a second subdomain: news.alice.test",
            repr(r)[:300])
    res = D.eventually(lambda: (lambda a: (a == PUBLIC_IPV4, a))(D.dig("news.alice.test")), 30, 1)
    D.check(res[0] is True, "its A record is created in the hosted zone by itself (dig @127.0.0.1)", repr(res[1]))
    good, detail = put_page(cust, "news.alice.test/index.html", "news-ok\n")
    good2, code, body = D.wait_site("news.alice.test", "200", "news-ok")
    D.check(good and good2, "and it is served", f"{detail} {code} {body[:100]}")

    bob = mst.get("bob")
    if bob is not None:
        r = cust.post("/api/v1/accounts/alice/subdomains", {"parent": "bob.test", "label": "x"})
        D.check(field_reason(r, "parent", "not_your_domain"),
                "refused: another customer's domain as the parent (not_your_domain)", repr(r)[:300])
        r = bob.put("/api/v1/sites/shared.alice.test", {"document_root": "shared_html"})
        D.info(f"another customer creating a site inside alice.test: {r!r}"[:300])
        if r.status == 201:
            r2 = cust.post("/api/v1/accounts/alice/subdomains", {"parent": "alice.test", "label": "shared"})
            D.check(field_reason(r2, "label", "belongs_to_another_account") and "bob" not in r2.raw,
                    "refused: a name another account has (belongs_to_another_account, whose is not said)", repr(r2)[:300])
            bob.delete("/api/v1/sites/shared.alice.test")
        else:
            D.check(r.status in (409, 422), "another customer cannot take a name inside alice's zone", repr(r)[:300])
    # The plan's site limit applies to subdomains as to any site.
    acct = (cust.get("/api/v1/accounts/alice").body or {})
    plan_id = acct.get("plan_id") or (acct.get("plan") or {}).get("id")
    pr = admin.get(f"/api/v1/plans/{plan_id}")
    keys = ("name", "memory_max_bytes", "cpu_weight", "io_weight", "tasks_max", "max_sites", "allow_php", "allow_apps",
            "disk_max_bytes", "inodes_max", "max_hosting_accounts", "db_trash_max_bytes", "php_limits", "mail_limits")
    body = {k: (pr.body or {}).get(k) for k in keys if (pr.body or {}).get(k) is not None}
    used = ((overview(cust).body or {}).get("sites") or {}).get("used")
    r = admin.put(f"/api/v1/plans/{plan_id}", dict(body, max_sites=used))
    D.check(r.status == 200, f"the administrator lowers the plan's site limit to what the account uses ({used})", repr(r)[:300])
    r = cust.post("/api/v1/accounts/alice/subdomains", {"parent": "alice.test", "label": "full"})
    D.check(r.status == 403 and r.code == "plan_site_limit", "a subdomain beyond the plan's site limit is refused (403 plan_site_limit)",
            repr(r)[:300])
    D.check(D.sh("test", "-e", "/etc/nginx/oxpanel.d/full.alice.test.conf").returncode != 0, "... and nothing was created", "")
    r = admin.put(f"/api/v1/plans/{plan_id}", body)
    D.check(r.status == 200, "the plan's limit back as it was", repr(r)[:300])
    # A subdomain is an ordinary site: deleted with the site route, its record with it.
    r = cust.delete("/api/v1/sites/news.alice.test")
    D.check(r.status in (200, 204), "the subdomain is deleted with the site route", repr(r)[:200])
    res = D.eventually(lambda: (lambda a: (a == "", a))(D.dig("news.alice.test")), 30, 1)
    D.check(res[0] is True, "its record goes with it", repr(res[1]))


def www(cust):
    """www: a site created with the www option (the UI sends www.<domain> as an
    alias), and www added to an existing site."""
    r = cust.put("/api/v1/sites/alicewww.test", {"document_root": "www_html", "aliases": ["www.alicewww.test"]})
    D.check(r.status == 201 and (r.body or {}).get("aliases") == ["www.alicewww.test"],
            "a site created with www: alicewww.test and www.alicewww.test", repr(r)[:300])
    good, detail = put_page(cust, "www_html/index.html", "www-site-ok\n")
    D.check(good, "its page", detail)
    for name in ("alicewww.test", "www.alicewww.test"):
        good, code, body = D.wait_site(name, "200", "www-site-ok")
        D.check(good, f"it answers as {name}", f"{code} {body[:100]}")
    zones = [z.get("zone") for z in items(cust.get("/api/v1/accounts/alice/dns/zones"))]
    D.info(f"the account's zones after creating alicewww.test: {zones}")
    if "alicewww.test" not in zones:
        r = cust.post("/api/v1/accounts/alice/dns/zones", {"zone": "alicewww.test"})
        D.check(r.status == 201, "the customer adds the zone alicewww.test to this host's DNS", repr(r)[:300])
    for name in ("alicewww.test", "www.alicewww.test"):
        res = D.eventually(lambda n=name: (lambda a: (a == PUBLIC_IPV4, a))(D.dig(n)), 30, 1)
        D.check(res[0] is True, f"the hosted zone answers {name} with the server's address", repr(res[1]))
    # www added later to a site that has none.
    r = cust.put("/api/v1/sites/plainsite.test", {"document_root": "plain_html"})
    D.check(r.status == 201, "a site without www: plainsite.test", repr(r)[:300])
    good, detail = put_page(cust, "plain_html/index.html", "plain-ok\n")
    if "plainsite.test" not in [z.get("zone") for z in items(cust.get("/api/v1/accounts/alice/dns/zones"))]:
        cust.post("/api/v1/accounts/alice/dns/zones", {"zone": "plainsite.test"})
    good, code, _ = D.wait_site("www.plainsite.test", "200", "plain-ok", tries=4)
    D.check(not good, "www.plainsite.test is not served yet", code)
    r = cust.put("/api/v1/sites/plainsite.test", {"document_root": "plain_html", "aliases": ["www.plainsite.test"]})
    D.check(r.status == 200 and (r.body or {}).get("aliases") == ["www.plainsite.test"], "the customer adds www to it",
            repr(r)[:300])
    good, code, body = D.wait_site("www.plainsite.test", "200", "plain-ok")
    D.check(good, "www.plainsite.test is served now", f"{code} {body[:100]}")
    res = D.eventually(lambda: (lambda a: (a == PUBLIC_IPV4, a))(D.dig("www.plainsite.test")), 30, 1)
    D.check(res[0] is True, "and the hosted zone has its record", repr(res[1]))
    for d in ("alicewww.test", "plainsite.test", "blog.alice.test"):
        r = cust.delete(f"/api/v1/sites/{d}")
        D.check(r.status in (200, 204), f"the customer deletes {d}", repr(r)[:200])
    for z in ("alicewww.test", "plainsite.test"):
        cust.delete(f"/api/v1/accounts/alice/dns/zones/{z}")


# ------------------------------------------------------------------ 4. "check again now"
def check_again_now(admin, reseller, cust, domain):
    def status():
        return cust.get(f"/api/v1/sites/{domain}/auto-https").body or {}
    s = status()
    if not (s.get("next_attempt") or 0) > time.time():
        reseller.post(f"/api/v1/sites/{domain}/auto-https/run")
        s = status()
    D.info(f"Automatic HTTPS of {domain}: {json.dumps(s)[:400]}")
    wait = (s.get("next_attempt") or 0) - time.time()
    D.check(wait > 60, f"{domain} waits for its next automatic attempt (back-off: the name does not resolve here)", repr(s)[:300])
    r = cust.post(f"/api/v1/sites/{domain}/auto-https/run")
    ra = r.headers.get("retry-after", "")
    D.check(r.status == 429 and r.code == "retry_later" and ra.isdigit() and abs(int(ra) - wait) < 120,
            "a customer's \"check again now\" inside the back-off: 429 retry_later, Retry-After = until the next attempt",
            f"{r!r} retry-after={ra} wait={wait:.0f}")
    r = cust.post(f"/api/v1/sites/{domain}/certificate/request")
    D.check(r.status == 429 and r.code == "retry_later", "\"get a certificate now\" waits for it too (429 retry_later)", repr(r)[:300])
    r = reseller.post(f"/api/v1/sites/{domain}/auto-https/run")
    D.check(r.status == 200, "the reseller may check again at any time (200)", repr(r)[:300])
    r = admin.post(f"/api/v1/sites/{domain}/auto-https/run")
    D.check(r.status == 200, "so may the administrator (200)", repr(r)[:300])
    r = admin.get("/api/v1/audit?limit=50")
    D.check(r.status == 200 and "auto" in r.raw, "the staff's forced runs are audited", repr(r)[:200])


# ------------------------------------------------------------------ 5. backup download
def stream_get(b, path, dest, sampler=None):
    """GET through Nginx, written to `dest` as it arrives (never held whole)."""
    u = urllib.parse.urlsplit(b.origin)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c = http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx, timeout=600)
    h = {"Host": b.netloc, "Cookie": b.cookie or "", "User-Agent": f"oxpanel-acceptance/{b.name}"}
    t0 = time.time()
    n = 0
    try:
        c.request("GET", path, headers=h)
        r = c.getresponse()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        with open(dest, "wb") as f:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
                n += len(chunk)
        return r.status, hdrs, n, time.time() - t0
    finally:
        c.close()


def check_tar(path):
    """The download is a tar whose first member is manifest.json and whose
    other members match the manifest's sizes and SHA-256. Returns (ok, detail)."""
    with tarfile.open(path, "r:") as t:
        members = t.getmembers()
        if not members or members[0].name != "manifest.json":
            return False, f"first member: {members[0].name if members else None}"
        manifest = json.load(t.extractfile(members[0]))
        want = {m["name"]: m for m in manifest.get("members", [])}
        got = {}
        for m in members[1:]:
            if not m.isreg():
                return False, f"{m.name} is not a regular file"
            h = hashlib.sha256()
            f = t.extractfile(m)
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                h.update(chunk)
            got[m.name] = (m.size, h.hexdigest())
        bad = [n for n in want if got.get(n) != (want[n]["size_bytes"], want[n]["sha256"])]
        if bad or set(got) != set(want):
            return False, f"mismatch: {bad}; members {sorted(got)} vs manifest {sorted(want)}"
        return True, f"{len(got)} members match the manifest ({', '.join(sorted(got))})"


def download_checks(cust, mst, admin, backup):
    bid = backup["id"]
    size = backup.get("download_size_bytes")
    D.check(isinstance(size, int) and size > backup.get("size_bytes", 0),
            "the backup lists the exact size of its download", repr(backup)[:300])
    dest = os.path.join(D.WORK, "backup.tar")
    status, h, n, secs = stream_get(cust, f"/api/v1/accounts/alice/backups/{bid}/download", dest)
    D.check(status == 200 and n == size and h.get("content-length") == str(size),
            f"the customer downloads the backup through Nginx: {n} bytes, exactly Content-Length", f"{status} {h} n={n}")
    disp = h.get("content-disposition", "")
    D.check(h.get("content-type", "").startswith("application/octet-stream") and disp.startswith("attachment")
            and f"alice-{bid}.tar" in disp and h.get("x-content-type-options") == "nosniff"
            and "no-store" in h.get("cache-control", "") and "sandbox" in h.get("content-security-policy", ""),
            "headers: attachment (alice-<id>.tar), application/octet-stream, nosniff, no-store, sandboxed", repr(h))
    good, detail = check_tar(dest)
    D.check(good, "it is a valid tar: manifest.json first, every member's size and SHA-256 as the manifest says", detail)
    D.info(detail)
    os.unlink(dest)
    bob = mst.get("bob")
    if bob is not None:
        r = bob.get(f"/api/v1/accounts/alice/backups/{bid}/download")
        D.check(r.status == 404, "another customer cannot download it (404)", repr(r)[:200])
        r = bob.get(f"/api/v1/accounts/bob/backups/{bid}/download")
        D.check(r.status == 404, "nor through his own account with its id (404)", repr(r)[:200])
    r = admin.get("/api/v1/audit?action=backup.download&limit=20")
    D.check(r.status == 200 and any(e.get("object_id") == bid or bid in json.dumps(e) for e in items(r)),
            "the download is audited (backup.download)", repr(r)[:300])


def proc_rss_kib(pattern_cmd):
    p = D.sh("bash", "-c", pattern_cmd)
    return sum(int(x) for x in p.stdout.split() if x.isdigit())


def large_download(cust, mb=300):
    free = D.sh("bash", "-c", "df -Pm /var/lib | awk 'NR==2{print $4}'").stdout.strip()
    if not free.isdigit() or int(free) < mb * 4:
        mb = max(50, int(free or 0) // 5)
    D.info(f"large backup: {mb} MiB of incompressible data ({free} MiB free on /var/lib)")
    p = D.sh("setpriv", "--reuid=alice", "--regid=alice", "--clear-groups", "--no-new-privs", "--", "dd", "if=/dev/urandom",
             "of=/home/alice/big.bin", "bs=1M", f"count={mb}", "status=none", timeout=600)
    D.check(p.returncode == 0, f"the account holds {mb} MiB of random data", p.stderr)
    r = cust.post("/api/v1/accounts/alice/backups")
    D.check(r.status == 202, "a backup of it", repr(r)[:200], fatal=True)
    j, secs = D.poll_job(cust, "alice", r.body["job"]["id"], timeout=900)
    D.check(j is not None and j.body.get("state") == "succeeded", f"succeeds ({secs:.0f}s)", repr(j)[:300])
    big = items(cust.get("/api/v1/accounts/alice/backups"))[0]
    size = big.get("download_size_bytes") or 0
    D.check(size > mb * 1024 * 1024, f"its download is {size} bytes", repr(big)[:300])

    panel_pid = D.sh("systemctl", "show", "-p", "MainPID", "--value", "oxpanel-panel").stdout.strip()
    panel_rss = f"ps -o rss= -p {panel_pid}"
    nginx_rss = "ps -C nginx -o rss="
    nginx_tmp = "du -sk /var/lib/nginx/tmp 2>/dev/null | cut -f1"
    base = (proc_rss_kib(panel_rss), proc_rss_kib(nginx_rss), proc_rss_kib(nginx_tmp))
    peaks = list(base)
    stop = threading.Event()

    def sample():
        while not stop.is_set():
            now = (proc_rss_kib(panel_rss), proc_rss_kib(nginx_rss), proc_rss_kib(nginx_tmp))
            for i in range(3):
                peaks[i] = max(peaks[i], now[i])
            time.sleep(0.25)
    th = threading.Thread(target=sample, daemon=True)
    th.start()
    dest = os.path.join(D.WORK, "big.tar")
    try:
        status, h, n, secs = stream_get(cust, f"/api/v1/accounts/alice/backups/{big['id']}/download", dest)
    finally:
        stop.set()
        th.join(5)
    D.check(status == 200 and n == size, f"the large backup downloads whole: {n} bytes in {secs:.1f}s "
            f"({n / max(secs, 0.001) / 1048576:.0f} MiB/s)", f"{status} n={n} size={size}")
    D.info(f"memory during the download (KiB): panel {base[0]} -> peak {peaks[0]}; Nginx (all processes) {base[1]} -> "
           f"peak {peaks[1]}; Nginx temporary files {base[2]} -> peak {peaks[2]}")
    D.check(peaks[0] - base[0] < 48 * 1024, "the panel streams it: its memory stays flat (< 48 MiB above where it was)",
            f"{base[0]} -> {peaks[0]}")
    D.check(peaks[1] - base[1] < 32 * 1024 and peaks[2] - base[2] < 4096,
            "Nginx passes it through: no growth in its memory, nothing spooled to its temporary files", f"{base} -> {peaks}")
    good, detail = check_tar(dest)
    D.check(good, "the large download matches its manifest member by member", detail)
    os.unlink(dest)
    r = cust.delete(f"/api/v1/accounts/alice/backups/{big['id']}")
    D.check(r.status == 204, "the large backup is deleted", repr(r)[:200])
    os.unlink("/home/alice/big.bin")


# ------------------------------------------------------------------ 6. a deleted customer's retained backup
def retained_restore(admin, reseller, plan_id):
    r = admin.get("/api/v1/backups/retained")
    mine = [b for b in items(r) if b.get("account") == "alice" and b.get("account_deleted")]
    D.check(r.status == 200 and len(mine) == 1 and mine[0].get("retain_until"),
            "the administrator sees the deleted customer's final backup among the retained ones", repr(r)[:500])
    if not mine:
        return
    bid = mine[0]["id"]
    r = reseller.get("/api/v1/backups/retained")
    D.check(r.status == 403, "a reseller does not reach retained backups of deleted accounts (403)", repr(r)[:200])
    r = admin.post("/api/v1/accounts", {"name": "alice2", "plan_id": plan_id})
    D.check(r.status == 201, "the administrator creates a new account for the returning customer (alice2)", repr(r)[:300])
    r = admin.post(f"/api/v1/backups/retained/alice/{bid}/restore", {"target_account": "alice2", "on_existing": "overwrite"})
    D.check(r.status == 202 and (r.body or {}).get("job", {}).get("id"), "and restores the retained backup into it (202)",
            repr(r)[:300])
    if r.status == 202:
        j, secs = D.poll_job(admin, "alice2", r.body["job"]["id"])
        D.check(j is not None and j.body.get("state") == "succeeded", f"the restore succeeds ({secs:.0f}s)", repr(j)[:400])
    try:
        content = open("/home/alice2/public_html/index.html").read()
        owner = os.stat("/home/alice2/public_html/index.html").st_uid
    except OSError as e:
        content, owner = repr(e), -1
    uid = D.sh("id", "-u", "alice2").stdout.strip()
    D.check(content == "static-ok\n" and str(owner) == uid, "the old account's files are in the new one, owned by it",
            f"{content!r} uid={owner} want {uid}")
    r = admin.delete(f"/api/v1/backups/retained/alice/{bid}")
    D.check(r.status == 204, "the retained backup is deleted early by the administrator", repr(r)[:200])
    r = admin.delete("/api/v1/accounts/alice2?remove_files=true")
    D.check(r.status in (200, 204), "the new account is deleted again", repr(r)[:300])


# ------------------------------------------------------------------ 7. reset-password on the host
def reset_password(url, reseller, username, old_password):
    p = D.sh(SETUP, "reset-password", username)
    m = re.search(r"temporary password: (\S+)", p.stdout)
    D.check(p.returncode == 0 and m is not None, f"oxpanel-panel-setup reset-password {username} prints a temporary password",
            (p.stdout + p.stderr).replace(m.group(1), "<masked>") if m else p.stdout + p.stderr)
    r = reseller.get("/api/v1/accounts")
    D.check(r.status == 401, "the user's sessions are ended", repr(r)[:200])
    b = D.Browser(url, username)
    r = b.post("/api/v1/auth/login", {"username": username, "password": old_password}, csrf=False)
    D.check(r.status == 401, "the old password no longer works", repr(r)[:200])
    if m:
        r = b.first_login(username, m.group(1), old_password + "-reset")
        D.check(r.status == 200 and not r.body.get("restriction"), "with the temporary password, and a new one chosen, the user is in",
                repr(r)[:300])
        p = D.sh("journalctl", "-b", "--no-pager", "-o", "cat")
        D.check(m.group(1) not in p.stdout, "the temporary password is not in the journal", "")
    return b
