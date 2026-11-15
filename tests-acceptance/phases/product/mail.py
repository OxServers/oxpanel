"""Email through the panel's HTTPS API, observed on the real host (phase 25).

Imported by drive.py, which hands over its helpers with `bind()`. The steps
follow the panel's specification of the real-host email drive (panel 0.2.0,
engine 0.3.0): every request goes through Nginx with a signed-in session, and
what each answer claims is then looked at on the host: a message delivered on
port 25 and read over IMAPS with the panel-made password, submission, the
forwarder, catch-all and autoresponder, quota and sending limits, DKIM
signatures checked against the key the panel shows, the DNS records in the
host's own name server, the queue, webmail, suspension, another customer, and
deletion.

No message leaves the VM: every recipient is on this host except one, which is
made to wait in the queue and is deleted there, and while this part runs
outgoing connections to port 25 of any other host are refused by a firewall
rule of the test (the engine's own port-25 probe is switched off on the test
host: OXPANEL_MAIL_PORT25_CHECK=off, set by phase 10).
"""
import json
import os
import re
import time

D = None  # drive.py's module (check, info, sh, eventually, dig, Browser, ...)
MC = "/root/acc/mail-client.py"
MAIL = "/api/v1/accounts/alice/mail"
DOM = "alice.test"
MD = f"{MAIL}/domains/{DOM}"
NFT_TABLE = "oxacc_mailguard"


def bind(module):
    global D
    D = module


# ------------------------------------------------------------------ helpers
def mc(*args, timeout=120):
    p = D.sh("python3", MC, *args, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).strip()


def mc_until(args, want=0, tries=40, delay=0.5):
    """mail-client.py until it exits `want` (delivery is asynchronous)."""
    rc, out = None, ""
    for _ in range(tries):
        rc, out = mc(*args)
        if rc == want:
            return True, rc, out
        time.sleep(delay)
    return False, rc, out


def field_err(r, field, reason):
    fields = ((r.body or {}).get("error") or {}).get("fields") or []
    return r.status == 422 and r.code == "validation_failed" and any(
        f.get("field") == field and f.get("reason") == reason for f in fields)


def items(r):
    return (r.body or {}).get("items", []) if isinstance(r.body, dict) else []


def txt(name):
    out = D.sh("dig", "+short", "+norec", "+time=2", "+tries=1", "@127.0.0.1", name, "TXT").stdout
    return ["".join(re.findall(r'"([^"]*)"', line)) for line in out.splitlines() if line.strip()]


def pubkey(record_value):
    m = re.search(r"\bp=([A-Za-z0-9+/=]+)", record_value or "")
    return m.group(1) if m else ""


def dkim_selector_of(path):
    """The s= tag of the DKIM-Signature header of a saved message."""
    try:
        raw = open(path, "rb").read().decode("utf-8", "replace")
    except OSError:
        return None
    head = raw.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
    m = re.search(r"(?ims)^DKIM-Signature:(.*?)(?=^\S)", head + "\nX-End: x\n")
    if not m:
        return None
    s = re.search(r"\bs=([A-Za-z0-9._-]+)", re.sub(r"\s+", "", m.group(1)).replace(";", "; "))
    return s.group(1) if s else None


def guard_port25(on):
    """While email is driven, no connection to port 25 of another host leaves the VM."""
    if on:
        rules = (f"table inet {NFT_TABLE} {{\n chain out {{\n  type filter hook output priority 0; policy accept;\n"
                 f"  ip daddr != 127.0.0.0/8 tcp dport 25 reject with tcp reset\n"
                 f"  ip6 daddr != ::1 tcp dport 25 reject with tcp reset\n }}\n}}\n")
        D.sh("nft", "delete", "table", "inet", NFT_TABLE)
        p = D.sh("nft", "-f", "-", inp=rules)
        D.check(p.returncode == 0, "test guard: outgoing connections to port 25 of other hosts are refused while"
                " email is driven (no message leaves the VM)", p.stderr, fatal=True)
    else:
        D.sh("nft", "delete", "table", "inet", NFT_TABLE)


def audit(admin):
    r = admin.get("/api/v1/audit?limit=200")
    return r


# ------------------------------------------------------------------ 0. email is on
def step_on(admin, cust, st):
    caps = (admin.get("/api/v1/host/capabilities").body or {})
    if not (caps.get("mail") or {}).get("available"):
        D.fail("email is not on after install.sh --mail (phase 10)", fatal=True)
    r = admin.get("/api/v1/host/capabilities")
    m = (r.body or {}).get("mail") or {}
    client = m.get("client") or {}
    st["host"] = client.get("host")
    D.check(r.status == 200 and m.get("available") is True and st["host"] == "mail.oxacc.test"
            and client.get("imap") == [{"port": 993, "security": "tls"}]
            and client.get("pop3") == [{"port": 995, "security": "tls"}]
            and client.get("smtp") == [{"port": 465, "security": "tls"}, {"port": 587, "security": "starttls"}]
            and m.get("webmail") is True,
            "capabilities: email available, the mail-app settings (IMAPS 993, POP3S 995, SMTP 465 TLS and 587"
            " STARTTLS) and webmail", repr(r)[:600], fatal=True)
    r = admin.get("/api/v1/host/mail")
    b = r.body or {}
    comps = b.get("components") or {}
    warns = [w.get("kind") if isinstance(w, dict) else w for w in b.get("warnings", [])]
    D.check(r.status == 200 and b.get("enabled") is True and b.get("available") is True
            and comps == {"postfix": True, "dovecot": True, "filter": True, "antivirus": False, "webmail": True,
                          "filter_resolver": True}
            and "filter_resolver_down" not in warns,
            "administrator reads the mail server: on, Postfix, Dovecot, filter, the filter's own resolver (running)"
            " and webmail, no antivirus",
            repr(r)[:600])
    D.check("service_not_running" not in warns, "no mail service is reported as not running", repr(warns))
    D.info(f"mail server warnings on the VM: {json.dumps(b.get('warnings'))[:600]}")
    r = admin.get("/api/v1/host")
    hm = (r.body or {}).get("mail") or {}
    D.check(r.status == 200 and hm.get("enabled") is True and hm.get("available") is True
            and hm.get("host_name") == st["host"], "the host overview carries the mail server", repr(hm)[:300])
    r = cust.get("/api/v1/host/mail")
    D.check(r.status == 403 and r.code == "forbidden", "a customer may not read the mail server (403)", repr(r))
    p = D.sh("systemctl", "is-active", "postfix", "dovecot", "rspamd", "oxpanel-mail-policy", "oxpanel-webmail")
    D.check(p.returncode == 0, "Postfix, Dovecot, Rspamd, the policy service and webmail are active", p.stdout)
    checks = "/var/lib/oxpanel-mail/host-checks.json"
    if D.eventually(lambda: os.path.exists(checks), 30, 1) is True:
        hc = json.load(open(checks))
        D.check(hc.get("port25") is None, "the port-25 probe made no connection (OXPANEL_MAIL_PORT25_CHECK=off)",
                json.dumps(hc))
        D.info(f"host checks: {json.dumps(hc)[:400]}")


# ------------------------------------------------------------------ 1. a mail domain
def step_domain(cust, st):
    r = cust.get(f"{MAIL}/domains")
    D.check(r.status == 200 and r.body.get("total") == 0 and items(r) == [], "the account has no mail domain yet",
            repr(r))
    r = cust.put(MD, {"mode": "local"})
    b = r.body or {}
    dk = b.get("dkim") or {}
    D.check(r.status == 201 and b.get("domain") == DOM and b.get("account") == "alice" and b.get("mode") == "local"
            and b.get("external_mx") == [] and b.get("catch_all") == "" and b.get("dns_hosted") is True
            and b.get("records_to_create") == [] and dk.get("selector")
            and dk.get("record_name") == f"{dk.get('selector')}._domainkey"
            and (dk.get("record_value") or "").startswith("v=DKIM1; k=rsa; p=") and dk.get("published") == "yes"
            and b.get("webmail_url") == f"https://webmail.{DOM}/" and b.get("mailbox_count") == 0
            and b.get("forwarder_count") == 0,
            "customer turns email on for alice.test (201): DKIM key published in the hosted zone, webmail address",
            repr(r)[:800], fatal=True)
    st["sel1"], st["rec1"] = dk["selector"], dk["record_value"]
    r = cust.put(MD, {"mode": "local"})
    D.check(r.status == 200 and ((r.body or {}).get("dkim") or {}).get("selector") == st["sel1"],
            "the same request again answers 200 with the same DKIM key", repr(r)[:300])
    r = cust.put(f"{MAIL}/domains/not-mine.test", {"mode": "local"})
    D.check(r.status == 409 and r.code == "mail_domain_not_in_account",
            "a name the account does not hold is refused (409 mail_domain_not_in_account)", repr(r))
    r = cust.put(MD, {"mode": "external"})
    D.check(field_err(r, "external_mx", "external_mx_required"),
            "external without MX hosts is refused (422 external_mx, external_mx_required)", repr(r))
    r = cust.get(MD)
    D.check(r.status == 200 and r.body.get("mode") == "local", "and nothing changed (still local)", repr(r)[:200])
    host = st["host"]
    res = D.eventually(lambda: (lambda a: (a == f"10 {host}.", a))(D.dig(DOM, "MX")), 30, 1)
    D.check(res[0] is True, f"the host's name server answers the MX: 10 {host}.", repr(res[1]))
    res = D.eventually(lambda: (lambda t: (st["rec1"] in t, t))(txt(f"{st['sel1']}._domainkey.{DOM}")), 30, 1)
    D.check(res[0] is True, "it serves the DKIM key the panel shows", repr(res[1])[:300])
    D.check("v=DMARC1; p=none" in txt(f"_dmarc.{DOM}"), "it serves the DMARC record", repr(txt(f"_dmarc.{DOM}")))
    D.check(any(t.startswith("v=spf1") for t in txt(DOM)), "it serves the SPF record", repr(txt(DOM)))
    r = cust.get(f"/api/v1/accounts/alice/dns/zones/{DOM}")
    recs = (r.body or {}).get("records", [])
    mx = [x for x in recs if x.get("type") == "MX"]
    dk = [x for x in recs if x.get("type") == "TXT" and "_domainkey" in (x.get("name") or "")]
    D.check(r.status == 200 and mx and dk and all(x.get("protected") for x in mx + dk),
            "the zone editor lists the mail records as protected", repr(recs)[:600])


# ------------------------------------------------------------------ 2. mailboxes
def step_mailboxes(admin, cust, st):
    r = cust.post(f"{MD}/mailboxes", {"local_part": "info", "quota_bytes": 104857600, "generate_password": True})
    b = r.body or {}
    mb = b.get("mailbox") or {}
    pw = b.get("generated_password") or ""
    D.check(r.status == 201 and mb == {"address": f"info@{DOM}", "local_part": "info", "quota_bytes": 104857600,
                                        "used_bytes": 0, "messages": 0, "enabled": True, "last_login": None}
            and re.fullmatch(r"[^-\s]{5}(-[^-\s]{5}){3}", pw) is not None,
            "customer creates info@alice.test with a generated password, shown once (four groups of five)",
            repr(r)[:400].replace(pw, "<password>") if pw else repr(r)[:400], fatal=True)
    st["p_info"] = pw
    st["p_sales"] = "Coral-Harbour-7731"
    r = cust.post(f"{MD}/mailboxes", {"local_part": "sales", "quota_bytes": 52428800, "password": st["p_sales"]})
    D.check(r.status == 201 and r.body.get("generated_password") is None,
            "customer creates sales@alice.test with a chosen password", repr(r)[:300], fatal=True)
    r = cust.post(f"{MD}/mailboxes", {"local_part": "weak", "quota_bytes": 1048576, "password": "alice-weak-pass"})
    D.check(field_err(r, "password", "weak_password"),
            "a password containing the domain's name is refused (422 weak_password)", repr(r))
    r = cust.post(f"{MD}/mailboxes", {"local_part": "info", "quota_bytes": 1048576, "generate_password": True})
    D.check(r.status == 409 and r.code == "mailbox_exists", "a second info is refused (409 mailbox_exists)", repr(r))
    r = cust.get(f"{MD}/mailboxes")
    D.check(r.status == 200 and r.body.get("total") == 2, "the domain lists two mailboxes", repr(r)[:300])
    D.check(st["p_info"] not in r.raw and st["p_sales"] not in r.raw, "the list holds neither password")

    p = D.sh("stat", "-c", "%U %a", f"/home/alice/mail/{DOM}/info")
    D.check(p.stdout.strip() == "alice 700", "the mailbox's directory belongs to the account, private (alice 700)",
            p.stdout + p.stderr)
    t0 = time.time()
    rc, out = mc("deliver", "25", "a@remote.example", f"info@{DOM}", "--subject", "drive-in")
    D.check(rc == 0, "a message is delivered on port 25 to the panel-made mailbox", out)
    good, rc, out = mc_until(["imap-find", f"info@{DOM}", st["p_info"], "drive-in"])
    D.check(good, "it is read over IMAPS with the password the panel generated", out)
    D.info(f"port 25 to IMAPS: {time.time() - t0:.1f}s")
    rc, out = mc("pop3", f"info@{DOM}", st["p_info"])
    D.check(rc == 0, "POP3S login with the same password", out)
    rc, out = mc("imap-find", f"info@{DOM}", "wrong-password-1", "drive-in")
    D.check(rc == 3, "a wrong password is refused over IMAPS", out)

    def logged_in():
        r2 = cust.get(f"{MD}/mailboxes")
        by = {m.get("local_part"): m for m in items(r2)}
        ll = (by.get("info") or {}).get("last_login")
        return (isinstance(ll, int) and abs(time.time() - ll) < 600 and (by.get("sales") or {}).get("last_login") is None,
                by)
    res = D.eventually(logged_in, 20, 1)
    D.check(res[0] is True, "the panel shows info's last login (just now); sales has none", repr(res[1])[:400])

    rc, out = mc("submit", "587", f"sales@{DOM}", st["p_sales"], f"sales@{DOM}", f"info@{DOM}",
                 "--subject", "drive-signed")
    D.check(rc == 0, "authenticated submission on port 587 (STARTTLS) as sales", out)
    eml = "/root/acc/drive-signed.eml"
    good, rc, out = mc_until(["imap-find", f"info@{DOM}", st["p_info"], "drive-signed", "--out", eml])
    D.check(good, "it arrives in info", out)
    rc, out = mc("dkim-verify", eml, pubkey(st["rec1"]))
    D.check(rc == 0, "its DKIM signature verifies against the key the panel shows", out)
    D.check(dkim_selector_of(eml) == st["sel1"], "signed with the panel's selector", repr(dkim_selector_of(eml)))
    rc, out = mc("submit", "465", f"sales@{DOM}", st["p_sales"], f"sales@{DOM}", f"info@{DOM}",
                 "--subject", "drive-465")
    D.check(rc == 0, "submission on port 465 (implicit TLS) too", out)
    rc, out = mc("submit", "587", f"sales@{DOM}", st["p_sales"], f"info@{DOM}", f"info@{DOM}",
                 "--subject", "drive-spoof")
    D.check(rc == 2, "a mailbox may not send as another mailbox (refused)", out)
    r = admin.get("/api/v1/audit?limit=200")
    D.check(r.status == 200 and "mail.mailbox_create" in r.raw and f"info@{DOM}" in r.raw,
            "the audit log has mail.mailbox_create for info@alice.test", repr(r)[:300])
    D.check(st["p_info"] not in r.raw and st["p_sales"] not in r.raw, "and neither password")


# ------------------------------------------------------------------ 3. forwarders
def step_forwarders(cust, st):
    F = f"{MD}/forwarders"
    r = cust.put(f"{F}/team", {"destinations": [f"info@{DOM}", f"Sales@{DOM}"]})
    D.check(r.status == 201 and r.body == {"address": f"team@{DOM}", "local_part": "team",
                                           "destinations": [f"info@{DOM}", f"sales@{DOM}"], "keep_copy": False},
            "customer creates the forwarder team (201, destinations lower-cased)", repr(r)[:300])
    r = cust.put(f"{F}/team", {"destinations": [f"info@{DOM}"]})
    D.check(r.status == 200, "replacing it answers 200", repr(r))
    r = cust.put(f"{F}/ping", {"destinations": [f"pong@{DOM}"]})
    D.check(r.status == 201, "a forwarder ping -> pong", repr(r))
    r = cust.put(f"{F}/pong", {"destinations": [f"ping@{DOM}"]})
    D.check(field_err(r, "destinations", "forward_loop"), "pong -> ping is refused as a loop (422 forward_loop)",
            repr(r))
    r = cust.put(f"{F}/info", {"destinations": ["x@remote.example"]})
    D.check(r.status == 409 and r.code == "address_in_use", "a forwarder may not take a mailbox's address (409)",
            repr(r))
    r = cust.put(f"{F}/nobox", {"destinations": ["x@remote.example"], "keep_copy": True})
    D.check(field_err(r, "keep_copy", "keep_copy_needs_mailbox"), "keep_copy without a mailbox is refused (422)",
            repr(r))
    r = cust.delete(f"{F}/ping")
    D.check(r.status == 204, "customer deletes ping (204)", repr(r))
    r = cust.delete(f"{F}/ping")
    D.check(r.status == 404, "and again: 404", repr(r))
    r = cust.put(f"{F}/team", {"destinations": [f"info@{DOM}", f"sales@{DOM}"]})
    D.check(r.status == 200, "team forwards to info and sales again", repr(r))
    rc, out = mc("deliver", "25", "a@remote.example", f"team@{DOM}", "--subject", "drive-fwd")
    D.check(rc == 0, "a message to team is accepted on port 25", out)
    for who, pw in (("info", st["p_info"]), ("sales", st["p_sales"])):
        good, rc, out = mc_until(["imap-find", f"{who}@{DOM}", pw, "drive-fwd"])
        D.check(good, f"the forwarder delivered it to {who}", out)


# ------------------------------------------------------------------ 4. catch-all
def step_catch_all(cust, st):
    r = cust.put(MD, {"mode": "local", "catch_all": "boss@remote.example"})
    D.check(field_err(r, "catch_all", "catch_all_not_mailbox"), "a catch-all outside the domain is refused (422)",
            repr(r))
    r = cust.put(MD, {"mode": "local", "catch_all": "info"})
    D.check(r.status == 200 and r.body.get("catch_all") == f"info@{DOM}", "catch-all set to info", repr(r)[:300])
    rc, out = mc("deliver", "25", "a@remote.example", f"nobody-here@{DOM}", "--subject", "drive-catch")
    D.check(rc == 0, "mail to an unknown address is accepted", out)
    good, rc, out = mc_until(["imap-find", f"info@{DOM}", st["p_info"], "drive-catch"])
    D.check(good, "and lands in info (the catch-all)", out)
    r = cust.put(MD, {"mode": "local", "catch_all": ""})
    D.check(r.status == 200 and r.body.get("catch_all") == "", "catch-all removed", repr(r)[:300])
    res = D.eventually(lambda: (lambda x: (x[0] == 2, x))(
        mc("deliver", "25", "a@remote.example", f"nobody-else@{DOM}", "--subject", "drive-nocatch")), 20, 0.5)
    D.check(res[0] is True and "550" in res[1][1], "then an unknown address is refused (550)", repr(res[1]))


# ------------------------------------------------------------------ 5. autoresponder
def step_autoresponder(admin, cust, st):
    A = f"{MD}/mailboxes/info/autoresponder"
    r = cust.get(A)
    D.check(r.status == 200 and r.body == {"address": f"info@{DOM}", "enabled": False, "subject": "", "body": "",
                                           "starts_at": None, "ends_at": None},
            "info has no autoresponder", repr(r)[:300])
    body = "Back on Monday.\nAlice"
    r = cust.put(A, {"enabled": True, "subject": "drive-away", "body": body})
    D.check(r.status == 200 and r.body.get("enabled") is True and r.body.get("subject") == "drive-away"
            and r.body.get("body") == body, "customer sets an autoresponder", repr(r)[:300])
    r = cust.put(A, {"enabled": True, "subject": "a\r\nBcc: x@remote.example", "body": "x"})
    D.check(field_err(r, "subject", "invalid_subject"), "a header injected through the subject is refused (422)",
            repr(r))
    rc, out = mc("submit", "587", f"sales@{DOM}", st["p_sales"], f"sales@{DOM}", f"info@{DOM}",
                 "--subject", "drive-needs-reply")
    D.check(rc == 0, "sales writes to info", out)
    good, rc, out = mc_until(["imap-find", f"sales@{DOM}", st["p_sales"], "drive-away"], tries=60)
    D.check(good, "the autoresponder answers (Sieve -> OxPanel's sendmail -> Postfix)", out)
    r = cust.put(A, {"enabled": False})
    D.check(r.status == 200 and r.body.get("enabled") is False, "and is switched off", repr(r)[:300])
    r = admin.get("/api/v1/audit?limit=200")
    D.check("mail.autoresponder_set" in r.raw and "Back on Monday" not in r.raw,
            "the audit log records the change, not the text", repr(r)[:200])


# ------------------------------------------------------------------ 6, 7. use and limits
RATES = ("max_messages_per_hour_account", "max_messages_per_hour_mailbox")
DEFAULTS = "/api/v1/host/mail/defaults"


def eff(r, field):
    """(value, source) of an effective limit in a usage answer; value None = unlimited."""
    e = ((r.body or {}).get("limits") or {}).get(field) or {}
    return (None if e.get("unlimited") else e.get("value")), e.get("source")


def burst(cust, mailbox, pw, upto, tag):
    """Send from `mailbox` (one recipient each) until a message is refused or
    `upto` were accepted; (accepted, refusal text or None)."""
    sent = 0
    for i in range(upto):
        rc, out = mc("submit", "587", mailbox, pw, mailbox, f"info@{DOM}", "--subject", f"drive-{tag}-{i}")
        if rc != 0:
            return sent, out
        sent += 1
    return sent, None


def deferred(refusal):
    return refusal is not None and re.search(r"\b4\d\d\b", refusal) is not None


def step_limits(admin, reseller, cust, st, plan, plan_id):
    # Counted per clock hour: never straddle the hour (the counts below are exact).
    lt = time.gmtime()
    if lt.tm_min >= 56:
        wait = (60 - lt.tm_min) * 60 - lt.tm_sec + 5
        D.info(f"waiting {wait}s for the next clock hour (the sending counters are per hour)")
        time.sleep(wait)
    r = cust.get(f"{MAIL}/usage")
    b = r.body or {}
    D.check(r.status == 200 and b.get("account") == "alice" and b.get("mailboxes") == 2
            and (b.get("bytes_used") or 0) > 0 and (b.get("messages_sent_this_hour") or 0) >= 2,
            "the account's email use: two mailboxes, space used, messages sent this hour", repr(r)[:400])
    D.info(f"mail usage: {r.raw[:600]}")
    D.check(eff(r, RATES[0]) == (30, "server_default") and eff(r, RATES[1]) == (20, "server_default")
            and eff(r, "max_mailboxes") == (None, "server_default"),
            "a new account follows the server default: 30 messages an hour, 20 per mailbox (source: server default)",
            repr(b.get("limits")))
    D.check("plan_limits" not in b and "account_limits" not in b,
            "the customer sees its effective limits, not the layers behind them", repr(sorted(b)))
    r = reseller.get(f"{MAIL}/usage")
    D.check(r.status == 200 and (r.body or {}).get("plan_limits", {}).get(RATES[0]) == "inherit"
            and (r.body or {}).get("account_limits", {}).get(RATES[0]) == "inherit",
            "staff see the plan and override layers (both inherit here)", repr(r)[:400])
    r = reseller.put("/api/v1/accounts/alice/plan", {"plan_id": plan_id})
    r2 = cust.get(f"{MAIL}/usage")
    D.check(r.status == 200 and eff(r2, RATES[0]) == (30, "server_default"),
            "assigning that plan again keeps the server default (it does not lift the sending limits)",
            repr(r2)[:300])
    r = cust.put(f"{MAIL}/limits", {"max_mailboxes": 5})
    D.check(r.status == 403 and r.code == "forbidden", "a customer may not set its email limits (403)", repr(r))

    # The server default, only for the administrator.
    r = admin.get(DEFAULTS)
    D.check(r.status == 200 and r.body.get(RATES[0]) == 30 and r.body.get(RATES[1]) == 20
            and r.body.get("max_mailboxes") == "unlimited" and (r.body.get("builtin") or {}).get(RATES[1]) == 20,
            "the administrator reads the server default (30 and 20 an hour, mailboxes unlimited)", repr(r)[:300])
    r = reseller.get(DEFAULTS)
    D.check(r.status == 403, "a reseller may not see the server default (403)", repr(r)[:200])
    r = cust.put(DEFAULTS, {RATES[0]: 1000})
    D.check(r.status == 403, "nor a customer change it (403)", repr(r)[:200])
    r = admin.put(DEFAULTS, {RATES[0]: 0})
    D.check(field_err(r, RATES[0], "out_of_range"), "0 is not a server default (422; unlimited is said)", repr(r))
    r = admin.put(DEFAULTS, {RATES[0]: "inherit"})
    D.check(field_err(r, RATES[0], "out_of_range"), "nor is inherit (422)", repr(r))

    # Real sending against the default: a fresh mailbox sends until it is deferred.
    st["p_burst"] = "Amber-Lantern-5520"
    r = cust.post(f"{MD}/mailboxes", {"local_part": "burst", "quota_bytes": 10485760, "password": st["p_burst"]})
    D.check(r.status == 201, "customer creates burst@alice.test", repr(r)[:300], fatal=True)
    n0 = (cust.get(f"{MAIL}/usage").body or {}).get("messages_sent_this_hour") or 0
    expect = min(20, 30 - n0)
    sent, refusal = burst(cust, f"burst@{DOM}", st["p_burst"], 35, "default")
    D.info(f"server default: the account had sent {n0} this hour; burst sent {sent}, then: {refusal}")
    D.check(sent == expect and deferred(refusal),
            f"with the server default, burst sends exactly {expect} (20 per mailbox, 30 per account) and the next is"
            " deferred (4xx)", f"sent={sent} expected={expect} refusal={refusal}")
    burst_sent = sent
    # Raising the server default lifts it, at once, for every account that follows it.
    r = admin.put(DEFAULTS, {RATES[0]: 1000, RATES[1]: 1000})
    D.check(r.status == 200 and r.body.get(RATES[1]) == 1000, "the administrator raises the server default to 1000",
            repr(r)[:300])
    r = cust.get(f"{MAIL}/usage")
    D.check(eff(r, RATES[1]) == (1000, "server_default"), "the account follows it at once", repr(r)[:300])
    good, rc, out = mc_until(["submit", "587", f"burst@{DOM}", st["p_burst"], f"burst@{DOM}", f"info@{DOM}",
                              "--subject", "drive-raised"], tries=20)
    D.check(good, "burst sends again", out)
    burst_sent += 1
    r = admin.get("/api/v1/audit?limit=50")
    D.check(r.status == 200 and "mail.defaults_set" in r.raw, "the change is in the audit log (mail.defaults_set)",
            repr(r)[:200])
    r = admin.put(DEFAULTS, {RATES[0]: 30, RATES[1]: 20})
    D.check(r.status == 200 and r.body.get(RATES[0]) == 30, "the server default back to 30 and 20", repr(r)[:300])
    rc, out = mc("submit", "587", f"burst@{DOM}", st["p_burst"], f"burst@{DOM}", f"info@{DOM}",
                 "--subject", "drive-lowered")
    D.check(rc == 2 and deferred(out), "lowered again, burst is deferred again", out)

    # A plan's limits beat the server default (here higher), on the real host.
    lim = {"max_mailboxes": 3, "max_mailbox_bytes": 209715200, RATES[0]: 100, RATES[1]: 25}
    r = admin.post("/api/v1/plans", dict(plan, name="Standard + mail", mail_limits=lim))
    D.check(r.status == 201 and r.body.get("mail_limits") == lim, "administrator creates a plan with email limits",
            repr(r)[:400], fatal=True)
    mplan = r.body["id"]
    st["mail_plan"] = mplan
    r = reseller.put("/api/v1/accounts/alice/plan", {"plan_id": mplan})
    D.check(r.status == 200, "reseller moves the account to it", repr(r)[:300])
    r = cust.get(f"{MAIL}/usage")
    D.check(r.status == 200 and eff(r, "max_mailboxes") == (3, "plan") and eff(r, RATES[0]) == (100, "plan")
            and eff(r, RATES[1]) == (25, "plan") and eff(r, "max_mailbox_bytes") == (209715200, "plan"),
            "the account's email limits are the plan's (source: plan)", repr(r)[:500])
    sent, refusal = burst(cust, f"burst@{DOM}", st["p_burst"], 30, "plan")
    burst_sent += sent
    D.check(burst_sent == 25 and deferred(refusal),
            "the plan's 25 an hour wins over the server default: burst reaches exactly 25, then is deferred",
            f"burst_sent={burst_sent} refusal={refusal}")
    r = cust.post(f"{MD}/mailboxes", {"local_part": "fourth", "quota_bytes": 1048576, "generate_password": True})
    D.check(r.status == 409 and r.code == "mailbox_limit_reached", "a fourth mailbox is refused at the plan's limit"
            " (409 mailbox_limit_reached)", repr(r))
    r = cust.patch(f"{MD}/mailboxes/info", {"quota_bytes": 314572800})
    D.check(field_err(r, "quota_bytes", "mailbox_quota_above_limit"),
            "a mailbox larger than the plan allows is refused (422 mailbox_quota_above_limit)", repr(r))
    r = cust.patch(f"{MD}/mailboxes/info", {"quota_bytes": 157286400})
    D.check(r.status == 200 and r.body.get("quota_bytes") == 157286400, "info grows to 150 MiB", repr(r)[:300])

    def quota_now():
        p = D.sh("doveadm", "quota", "get", "-u", f"info@{DOM}")
        return (re.search(r"STORAGE\s+\d+\s+153600\b", p.stdout) is not None, p.stdout + p.stderr)
    res = D.eventually(quota_now, 20, 0.5)
    D.check(res[0] is True, "Dovecot enforces the new size (doveadm quota: STORAGE limit 153600 KiB)",
            res[1][:400])

    # A staff override beats the plan.
    r = reseller.put(f"{MAIL}/limits", {RATES[1]: 26})
    D.check(r.status == 200 and eff(r, RATES[1]) == (26, "account") and eff(r, RATES[0]) == (100, "plan"),
            "the reseller overrides one limit for this account (source: account); the others stay the plan's",
            repr(r)[:400])
    sent, refusal = burst(cust, f"burst@{DOM}", st["p_burst"], 5, "override")
    D.check(sent == 1 and deferred(refusal), "the override wins: exactly one more, then deferred",
            f"sent={sent} refusal={refusal}")
    r = admin.get("/api/v1/audit?limit=50")
    D.check(r.status == 200 and "mail.limits_set" in r.raw, "the override is in the audit log", repr(r)[:200])
    rc, out = mc("submit", "587", f"info@{DOM}", st["p_info"], f"info@{DOM}", f"sales@{DOM}",
                 "--subject", "drive-rate-other")
    D.check(rc == 0, "another mailbox of the account still sends", out)

    # Back to a plan without email limits: the server default, never unlimited.
    r = reseller.put("/api/v1/accounts/alice/plan", {"plan_id": plan_id})
    D.check(r.status == 200, "reseller moves the account back to its plan (no email limits)", repr(r)[:300])
    r = reseller.get(f"{MAIL}/usage")
    D.check(r.status == 200 and eff(r, RATES[0]) == (30, "server_default") and eff(r, RATES[1]) == (20, "server_default")
            and (r.body.get("account_limits") or {}).get(RATES[1]) == "inherit",
            "the limits are the server default again (the plan change also ended the override); never unlimited",
            repr(r)[:400])
    rc, out = mc("submit", "587", f"burst@{DOM}", st["p_burst"], f"burst@{DOM}", f"info@{DOM}",
                 "--subject", "drive-after-plan")
    D.check(rc == 2 and deferred(out), "so burst stays deferred", out)
    # Unlimited is an explicit choice (the rest of the drive sends freely).
    r = reseller.put(f"{MAIL}/limits", {RATES[0]: "unlimited", RATES[1]: "unlimited"})
    D.check(r.status == 200 and eff(r, RATES[0]) == (None, "account") and eff(r, RATES[1]) == (None, "account"),
            "the reseller makes the sending limits unlimited for this account, explicitly", repr(r)[:400])
    good, rc, out = mc_until(["submit", "587", f"sales@{DOM}", st["p_sales"], f"sales@{DOM}", f"info@{DOM}",
                              "--subject", "drive-rate-lifted"], tries=20)
    D.check(good, "sales sends again once the limit is lifted", out)
    r = cust.delete(f"{MD}/mailboxes/burst", {"confirm_address": f"burst@{DOM}"})
    D.check(r.status == 204, "customer deletes burst@alice.test", repr(r)[:300])


# ------------------------------------------------------------------ 8. external and back
def step_external(cust, st):
    P = f"{MAIL}/domains/php.{DOM}"
    host = st["host"]
    r = cust.put(P, {"mode": "local"})
    D.check(r.status == 201, "email for php.alice.test (a site of the account)", repr(r)[:300])
    r = cust.put(P, {"mode": "external", "external_mx": ["aspmx.l.google.com", "ALT1.aspmx.l.google.com."]})
    b = r.body or {}
    D.check(r.status == 200 and b.get("mode") == "external"
            and b.get("external_mx") == ["aspmx.l.google.com", "alt1.aspmx.l.google.com"] and b.get("dkim") is None
            and b.get("webmail_url") is None and b.get("records_to_create") == [],
            "switched to an external provider: MX hosts normalised, no DKIM, no webmail", repr(r)[:500])
    r = cust.post(f"{P}/mailboxes", {"local_part": "x", "quota_bytes": 1048576, "generate_password": True})
    D.check(r.status == 409 and r.code == "mail_domain_not_local", "no mailbox on an external domain (409)", repr(r))
    r = cust.post(f"{P}/dkim/rotate")
    D.check(r.status == 409 and r.code == "mail_domain_not_local", "no DKIM rotation on it (409)", repr(r))
    want = {"10 aspmx.l.google.com.", "20 alt1.aspmx.l.google.com."}
    res = D.eventually(lambda: (lambda a: (set(a.splitlines()) == want, a))(D.dig(f"php.{DOM}", "MX")), 30, 1)
    D.check(res[0] is True, "the zone now sends its mail to the provider's MX hosts", repr(res[1]))
    rc, out = mc("deliver", "25", "a@remote.example", f"x@php.{DOM}", "--subject", "drive-ext")
    D.check(rc == 2, "this host no longer accepts mail for it (and never relays it)", out)
    r = cust.put(P, {"mode": "local"})
    D.check(r.status == 200 and (r.body.get("dkim") or {}).get("selector") and r.body.get("webmail_url"),
            "back to local: DKIM and webmail again", repr(r)[:400])
    res = D.eventually(lambda: (lambda a: (a == f"10 {host}.", a))(D.dig(f"php.{DOM}", "MX")), 30, 1)
    D.check(res[0] is True, "the MX points at this host again", repr(res[1]))
    r = cust.post(f"{P}/mailboxes", {"local_part": "back", "quota_bytes": 1048576, "generate_password": True})
    pw = (r.body or {}).get("generated_password") or ""
    D.check(r.status == 201 and pw, "a mailbox on it", repr(r)[:200].replace(pw, "<password>") if pw else repr(r))
    if pw:
        rc, out = mc("deliver", "25", "a@remote.example", f"back@php.{DOM}", "--subject", "drive-back")
        D.check(rc == 0, "local delivery is restored", out)
        good, rc, out = mc_until(["imap-find", f"back@php.{DOM}", pw, "drive-back"])
        D.check(good, "and the message is read over IMAPS", out)
        r = cust.delete(f"{P}/mailboxes/back", {"confirm_address": f"back@php.{DOM}"})
        D.check(r.status == 204, "that mailbox is deleted again", repr(r))
    r = cust.put(P, {"mode": "off"})
    D.check(r.status == 200 and r.body.get("mode") == "off", "email off for php.alice.test", repr(r)[:300])
    res = D.eventually(lambda: (lambda a: (a == "", a))(D.dig(f"php.{DOM}", "MX")), 30, 1)
    D.check(res[0] is True, "and the zone has no MX for it", repr(res[1]))


# ------------------------------------------------------------------ 9. DKIM rotation
def step_dkim(cust, st):
    r = cust.post(f"{MD}/dkim/rotate")
    dk = (r.body or {}).get("dkim") or {}
    D.check(r.status == 200 and dk.get("selector") and dk.get("selector") != st["sel1"] and dk.get("published") == "yes"
            and dk.get("pending") is None,
            "rotation where the zone is hosted here: one call publishes the new key and switches to it",
            repr(r)[:500])
    st["sel2"], st["rec2"] = dk.get("selector"), dk.get("record_value")
    res = D.eventually(lambda: (lambda t: (st["rec2"] in t, t))(txt(f"{st['sel2']}._domainkey.{DOM}")), 30, 1)
    D.check(res[0] is True, "the new key is served", repr(res[1])[:200])
    D.check(st["rec1"] in txt(f"{st['sel1']}._domainkey.{DOM}"),
            "the old key stays published (messages in flight still verify)")
    eml = "/root/acc/drive-rotated.eml"
    rc, out = mc("submit", "587", f"sales@{DOM}", st["p_sales"], f"sales@{DOM}", f"info@{DOM}",
                 "--subject", "drive-rotated")
    D.check(rc == 0, "sales sends after the rotation", out)
    good, rc, out = mc_until(["imap-find", f"info@{DOM}", st["p_info"], "drive-rotated", "--out", eml])
    D.check(good and dkim_selector_of(eml) == st["sel2"], "it is signed with the new selector",
            f"{out} s={dkim_selector_of(eml)}")
    rc, out = mc("dkim-verify", eml, pubkey(st["rec2"]))
    D.check(rc == 0, "and verifies against the new key", out)

    # Two steps where the DNS is elsewhere: a site of the account without a zone here.
    other = "mail2.other.test"
    r = cust.put(f"/api/v1/sites/{other}", {"document_root": "other_html"})
    D.check(r.status == 201, f"customer adds a site {other}", repr(r)[:300])
    r = cust.get("/api/v1/accounts/alice/dns/zones")
    for z in items(r):
        if z.get("zone") in ("other.test", other):
            r2 = cust.delete(f"/api/v1/accounts/alice/dns/zones/{z['zone']}")
            D.check(r2.status == 204, f"its DNS is elsewhere: the zone {z['zone']} the site got here is deleted",
                    repr(r2))
    O = f"{MAIL}/domains/{other}"
    r = cust.put(O, {"mode": "local"})
    b = r.body or {}
    D.check(r.status == 201 and b.get("dns_hosted") is False and len(b.get("records_to_create") or []) >= 3,
            "email for it: the panel lists the records to create at the DNS provider", repr(r)[:600])
    D.info(f"records to create for {other}: {json.dumps(b.get('records_to_create'))[:600]}")
    old = (b.get("dkim") or {}).get("selector")
    r = cust.post(f"{O}/mailboxes", {"local_part": "post", "quota_bytes": 1048576, "generate_password": True})
    ppw = (r.body or {}).get("generated_password") or ""
    D.check(r.status == 201 and ppw, f"a mailbox post@{other}", repr(r)[:200])

    def sent_selector(tag):
        path = f"/root/acc/drive-{tag}.eml"
        rc2, out2 = mc("submit", "587", f"post@{other}", ppw, f"post@{other}", f"info@{DOM}", "--subject", f"drive-{tag}")
        good2, _, out3 = mc_until(["imap-find", f"info@{DOM}", st["p_info"], f"drive-{tag}", "--out", path])
        return (dkim_selector_of(path) if rc2 == 0 and good2 else None), out2 + out3

    r = cust.post(f"{O}/dkim/rotate")
    dk = (r.body or {}).get("dkim") or {}
    pend = dk.get("pending") or {}
    D.check(r.status == 200 and dk.get("selector") == old and pend.get("selector") and pend["selector"] != old
            and pend.get("record_name") == f"{pend.get('selector')}._domainkey" and pend.get("record_value")
            and pend.get("published") == "unknown"
            and any(pend["selector"] in (x.get("name") or "") for x in r.body.get("records_to_create") or []),
            "two-step rotation: a new key is made and shown to publish; the old one still signs", repr(r)[:700])
    new = pend.get("selector")
    sel, out = sent_selector("pending")
    D.check(sel == old, "while the new key waits, mail is still signed with the old selector", f"s={sel} {out}")
    r = cust.post(f"{O}/dkim/rotate")
    dk = (r.body or {}).get("dkim") or {}
    D.check(r.status == 200 and dk.get("selector") == old and (dk.get("pending") or {}).get("selector") == new
            and (dk.get("pending") or {}).get("published") == "no",
            "asked again: the engine looked, the record is not in public DNS, nothing switches", repr(r)[:500])
    r = cust.post(f"{O}/dkim/rotate?force=true")
    dk = (r.body or {}).get("dkim") or {}
    D.check(r.status == 200 and dk.get("selector") == new and dk.get("pending") is None,
            "forced: the new key signs from now on", repr(r)[:500])
    sel, out = sent_selector("forced")
    D.check(sel == new, "mail is now signed with the new selector", f"s={sel} {out}")
    r = cust.delete(f"{O}/mailboxes/post", {"confirm_address": f"post@{other}"})
    D.check(r.status == 204, "the mailbox post goes again", repr(r))
    r = cust.put(O, {"mode": "off"})
    D.check(r.status == 200, f"email off for {other}", repr(r)[:200])
    r = cust.delete(f"/api/v1/sites/{other}")
    D.check(r.status in (200, 204), f"the site {other} goes", repr(r))


# ------------------------------------------------------------------ 10, 11. deliverability and the queue
def step_deliverability_queue(admin, reseller, cust, st):
    names = ["mx", "spf", "dkim", "dmarc", "reverse_dns"]
    r = cust.get(f"{MD}/deliverability")
    checks = (r.body or {}).get("checks") or []
    D.check(r.status == 200 and r.body.get("domain") == DOM and [c.get("name") for c in checks] == names
            and all(c.get("status") in ("ok", "warn", "fail", "unknown") for c in checks)
            and not any("detail" in c for c in checks),
            "customer's deliverability check: mx, spf, dkim, dmarc, reverse_dns, each with a status, no details",
            repr(r)[:600])
    r = admin.get(f"/api/v1/host/mail/deliverability/{DOM}")
    checks = (r.body or {}).get("checks") or []
    D.check(r.status == 200 and [c.get("name") for c in checks] == names and all("detail" in c for c in checks),
            "the administrator's check has the details", repr(r)[:600])
    D.info("deliverability on the VM (alice.test is not in public DNS): "
           + "; ".join(f"{c.get('name')}={c.get('status')}: {c.get('detail')}" for c in checks)[:900])
    r = admin.get("/api/v1/host/mail/deliverability/not-a-mail-domain.test")
    D.check(r.status == 404 and r.code == "not_found", "a domain that is not a mail domain: 404", repr(r))

    # A message that cannot leave (connections to port 25 elsewhere are refused): it waits in the queue.
    rc, out = mc("submit", "587", f"sales@{DOM}", st["p_sales"], f"sales@{DOM}", "someone@[192.0.2.1]",
                 "--subject", "drive-queued")
    D.check(rc == 0, "sales sends to an address this host cannot reach (it stays queued)", out)

    def queued():
        r2 = admin.get("/api/v1/host/mail/queue")
        it = [q for q in items(r2) if q.get("sender") == f"sales@{DOM}"]
        return (r2.status == 200 and bool(it) and bool(it[0].get("reason")), r2)
    res = D.eventually(queued, 60, 1)
    r = res[1]
    mine = [q for q in items(r) if q.get("sender") == f"sales@{DOM}"]
    q = mine[0] if mine else {}
    D.check(res[0] is True and r.body.get("total", 0) >= 1 and q.get("account") == "alice"
            and q.get("recipients_count") == 1,
            "administrator sees it in the queue: sender, account, one recipient, the reason", repr(r)[:600])
    D.info(f"queued: {json.dumps(q)[:400]}")
    qid = q.get("queue_id", "")
    D.check(qid and qid in D.sh("postqueue", "-j").stdout, "postqueue -j lists the same id", qid)
    r = admin.post("/api/v1/host/mail/queue/flush")
    D.check(r.status == 200 and (r.body or {}).get("attempted", 0) >= 1, "flush: delivery is tried again",
            repr(r))
    for who in (reseller, cust):
        r = who.get("/api/v1/host/mail/queue")
        D.check(r.status == 403, f"{who.name} may not read the queue (403)", repr(r))
    if qid:
        r = admin.delete(f"/api/v1/host/mail/queue/{qid}")
        D.check(r.status == 204, "administrator deletes the queued message (204)", repr(r))
        r = admin.delete(f"/api/v1/host/mail/queue/{qid}")
        D.check(r.status == 404, "and again: 404", repr(r))
        res = D.eventually(lambda: qid not in D.sh("postqueue", "-j").stdout, 20, 0.5)
        D.check(res is True, "postqueue no longer lists it")


# ------------------------------------------------------------------ 12. webmail
def step_webmail(cust, st):
    name = f"webmail.{DOM}"
    key, crt = f"/etc/pki/oxpanel-mail/{name}.key", f"/etc/pki/oxpanel-mail/{name}.crt"
    p = D.sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj", f"/CN={name}",
             "-addext", f"subjectAltName=DNS:{name}", "-keyout", key, "-out", crt)
    os.chmod(key, 0o600)
    D.sh("restorecon", "-R", "/etc/pki/oxpanel-mail")
    D.check(p.returncode == 0, "a certificate for the webmail name is put in place (a .test name gets none from"
            " Automatic HTTPS)", p.stderr[-300:])
    st["webmail_cert"] = (key, crt)
    r = cust.get(MD)
    url = (r.body or {}).get("webmail_url")
    D.check(url == f"https://{name}/", "the panel shows the webmail link", repr(url))
    cust.put(MD, {"mode": "local"})  # the engine serves the certificate when it renders the domain again
    jar = os.path.join(D.WORK, "wm.cj")
    base = ["curl", "-sk", "--max-time", "20", "--resolve", f"{name}:443:127.0.0.1", "-b", jar, "-c", jar]
    res = D.eventually(lambda: (lambda o: ("rcmloginuser" in o, o[:300]))(D.sh(*base, url).stdout), 40, 0.5)
    D.check(res[0] is True, "the webmail link answers over HTTPS with Roundcube's login page", repr(res[1]))
    page = D.sh(*base, url).stdout
    m = re.search(r'name="_token" value="([^"]*)"', page)
    tok = m.group(1) if m else ""
    D.sh(*base, "-o", "/dev/null", "--data-urlencode", f"_token={tok}", "-d", "_task=login", "-d", "_action=login",
         "-d", "_timezone=UTC", "-d", "_url=", "--data-urlencode", f"_user=info@{DOM}",
         "--data-urlencode", f"_pass={st['p_info']}", f"{url}?_task=login")
    inbox = D.sh(*base, f"{url}?_task=mail&_mbox=INBOX").stdout
    D.check("Inbox" in inbox and "rcmloginuser" not in inbox,
            "a webmail login with the panel-made password opens the Inbox", inbox[:300])
    p = D.sh("curl", "-s", "--max-time", "10", "-w", "\n%{http_code} %{redirect_url}", "-H", f"Host: {name}",
             "http://127.0.0.1/")
    body, _, status = p.stdout.rpartition("\n")
    D.info(f"webmail over plain HTTP: {status}")
    D.check("rcmloginuser" not in body, "plain HTTP never serves webmail (only HTTPS does)", status)


# ------------------------------------------------------------------ 14. another customer
def step_bob(url, admin, reseller, cust, st, plan_id):
    r = reseller.post("/api/v1/users", {"username": "bob", "role": "customer", "display_name": "Bob",
                                        "plan_id": plan_id, "hosting_account": {"name": "bob", "plan_id": plan_id}})
    D.check(r.status == 201 and r.body.get("temporary_password"), "reseller creates a second customer, bob",
            repr(r)[:300], fatal=True)
    st["bob_id"] = r.body["user"]["id"]
    bob = D.Browser(url, "bob")
    r = bob.first_login("bob", r.body["temporary_password"], "Customer-bob-pass-2")
    D.check(r.status == 200 and not r.body.get("restriction"), "bob signs in", repr(r), fatal=True)
    st["bob"] = bob
    r = bob.put("/api/v1/sites/bob.test", {"document_root": "public_html"})
    D.check(r.status == 201, "bob creates the site bob.test", repr(r)[:300])
    r = bob.put("/api/v1/accounts/bob/mail/domains/bob.test", {"mode": "local"})
    D.check(r.status == 201, "bob turns email on for bob.test", repr(r)[:300])
    r = bob.post("/api/v1/accounts/bob/mail/domains/bob.test/mailboxes",
                 {"local_part": "info", "quota_bytes": 1048576, "generate_password": True})
    p_bob = (r.body or {}).get("generated_password") or ""
    D.check(r.status == 201 and p_bob, "and creates info@bob.test", repr(r)[:200])
    probes = [
        (bob.get("/api/v1/accounts/alice/mail/domains"), 404, None, "bob cannot list alice's mail domains (404)"),
        (bob.get(f"/api/v1/accounts/bob/mail/domains/{DOM}/mailboxes"), 404, None,
         "bob cannot list alice.test's mailboxes through his own account (404)"),
        (bob.put(f"/api/v1/accounts/bob/mail/domains/{DOM}", {"mode": "local"}), 409, "mail_domain_not_in_account",
         "bob cannot take alice.test (409 mail_domain_not_in_account)"),
        (bob.delete(f"/api/v1/accounts/bob/mail/domains/{DOM}/mailboxes/info", {"confirm_address": f"info@{DOM}"}),
         404, None, "bob cannot delete alice's mailbox (404)"),
        (admin.get(f"/api/v1/accounts/bob/mail/domains/{DOM}"), 404, None,
         "the wrong account in the path is 404 even for the administrator"),
        (cust.get("/api/v1/accounts/bob/mail/usage"), 404, None, "alice cannot read bob's email use (404)"),
    ]
    for r, status, code, msg in probes:
        D.check(r.status == status and (code is None or r.code == code), msg, repr(r)[:300])
    leaks = [r.raw for r, _, _, _ in probes
             if any(s in r.raw for s in ("items", "mailbox_count", "@alice.test", "@bob.test", "dkim"))]
    D.check(not leaks, "no refusal shows anything of the other customer's email", repr(leaks)[:400])
    rc, out = mc("submit", "587", "info@bob.test", p_bob, f"info@{DOM}", f"sales@{DOM}", "--subject", "drive-x")
    D.check(rc == 2, "bob's mailbox cannot send as alice's (refused)", out)
    rc, out = mc("imap-find", f"info@{DOM}", p_bob, "drive-in")
    D.check(rc == 3, "bob's password does not open alice's mailbox", out)
    r = D.sh("grep", "-rl", f"info@{DOM}", "/home/bob/mail")
    D.check(r.stdout.strip() == "", "nothing of alice's mail is in bob's home")


def delete_bob(reseller, st):
    r = reseller.post(f"/api/v1/users/{st['bob_id']}/deletion", {"confirm_username": "bob",
                                                                 "final_backup_retain_days": 0})
    D.check(r.status == 202 and (r.body.get("deletion") or {}).get("id"),
            "reseller deletes bob with his account and its email in one step (202)", repr(r)[:400])
    if r.status == 202:
        d, secs = D.poll_deletion(reseller, r.body["deletion"]["id"])
        D.check(d is not None and d.body.get("state") == "succeeded", f"bob's deletion succeeds ({secs:.0f}s)",
                repr(d)[:400])
    D.check(not os.path.exists("/home/bob"), "bob's home and mail are gone")
    rc, out = mc("deliver", "25", "a@remote.example", "info@bob.test", "--subject", "drive-gone")
    D.check(rc == 2, "mail for bob.test is refused now", out)


# ------------------------------------------------------------------ 15. deleting a mailbox
def step_mailbox_delete(cust, st):
    B = f"{MD}/mailboxes"
    r = cust.delete(f"{B}/sales", {"confirm_address": f"info@{DOM}"})
    D.check(field_err(r, "confirm_address", "confirmation_mismatch"),
            "deleting sales with another address typed is refused (422 confirmation_mismatch)", repr(r))
    r = cust.delete(f"{B}/sales", {"confirm_address": f"SALES@{DOM}"})
    D.check(r.status == 204, "customer deletes sales (the address typed again, any case): 204", repr(r))
    t0 = time.time()
    rc, out = mc("imap-find", f"sales@{DOM}", st["p_sales"], "drive-in")
    D.check(rc == 3, "sales can no longer log in, at once", out)
    r = cust.get(B)
    D.check(r.status == 200 and r.body.get("total") == 1 and items(r)[0].get("local_part") == "info",
            "only info is left", repr(r)[:300])
    r = cust.delete(f"{B}/sales", {"confirm_address": f"sales@{DOM}"})
    D.check(r.status == 404, "deleting it again: 404", repr(r))
    r = cust.get(f"{MD}/forwarders")
    team = next((f for f in items(r) if f.get("local_part") == "team"), {})
    D.info(f"the forwarder team after deleting sales: {json.dumps(team)}")
    res = D.eventually(lambda: not os.path.exists(f"/home/alice/mail/{DOM}/sales"), 60, 1)
    D.check(res is True, "the engine removes sales' stored mail in the background")
    D.info(f"sales' mail removed {time.time() - t0:.1f}s after the delete answered")
    t0 = time.time()
    res = D.eventually(lambda: (lambda r2: (r2.status == 201, r2))(
        cust.post(B, {"local_part": "sales", "quota_bytes": 1048576, "generate_password": True})), 60, 1)
    D.check(res[0] is True, "the address can be used for a new mailbox again", repr(res[1])[:300])
    D.info(f"a new sales was accepted {time.time() - t0:.1f}s after the removal")
    if res[0] is True:
        r = cust.delete(f"{B}/sales", {"confirm_address": f"sales@{DOM}"})
        D.check(r.status == 204, "and deleted again", repr(r))


# ------------------------------------------------------------------ the whole email part (before backups)
def drive_mail(url, admin, reseller, cust, plan, plan_id):
    st = {}
    guard_port25(True)
    try:
        step_on(admin, cust, st)
        step_domain(cust, st)
        step_mailboxes(admin, cust, st)
        step_forwarders(cust, st)
        step_catch_all(cust, st)
        step_autoresponder(admin, cust, st)
        step_limits(admin, reseller, cust, st, plan, plan_id)
        step_external(cust, st)
        step_dkim(cust, st)
        step_deliverability_queue(admin, reseller, cust, st)
        step_webmail(cust, st)
        step_bob(url, admin, reseller, cust, st, plan_id)
        step_mailbox_delete(cust, st)
    finally:
        guard_port25(False)
    return st


# ------------------------------------------------------------------ inside the backup section
def before_backup(st):
    good, rc, out = mc_until(["imap-find", f"info@{DOM}", st["p_info"], "drive-in"], tries=4)
    D.check(good, "info holds the message drive-in when the backup is taken", out)


def after_backup(st):
    rc, out = mc("imap-clear", f"info@{DOM}", st["p_info"])
    D.check(rc == 0, "the customer empties info's inbox over IMAP after the backup", out)
    rc, out = mc("imap-find", f"info@{DOM}", st["p_info"], "drive-in")
    D.check(rc == 4, "the message is gone", out)


def after_restore(st):
    good, rc, out = mc_until(["imap-find", f"info@{DOM}", st["p_info"], "drive-in"])
    D.check(good, "after the restore through the panel, the message is back in info (read over IMAPS)", out)
    p = D.sh("bash", "-c", f"test -z \"$(find /home/alice/mail -type f ! -user alice)\"")
    D.check(p.returncode == 0, "every restored mail file belongs to the account")


# ------------------------------------------------------------------ 13. suspended (inside suspend/resume)
def while_suspended(admin, reseller, cust, st):
    B = f"{MD}/mailboxes"
    r = cust.get(B)
    D.check(r.status == 200, "the customer of a suspended account may still look at its mailboxes", repr(r)[:200])
    r = cust.patch(f"{B}/info", {"enabled": False})
    D.check(r.status == 409 and r.code == "account_suspended", "but not change one (409 account_suspended)", repr(r))
    r = reseller.patch(f"{B}/info", {"enabled": False})
    D.check(r.status == 409 and r.code == "account_suspended",
            "the engine freezes a suspended account's email for its reseller too (409)", repr(r))
    r = admin.put(f"{B}/info/password", {"generate": True})
    D.check(r.status == 409 and r.code == "account_suspended", "and for the administrator (409)", repr(r))
    r = reseller.put(f"{MAIL}/limits", {"max_mailboxes": 3, "max_messages_per_hour_account": "unlimited",
                                        "max_messages_per_hour_mailbox": "unlimited"})
    D.check(r.status == 200, "its email limits may still be set (200)", repr(r)[:300])
    rc, out = mc("imap-find", f"info@{DOM}", st["p_info"], "drive-in")
    D.check(rc == 3, "the suspended mailbox cannot log in over IMAPS", out)
    rc, out = mc("pop3", f"info@{DOM}", st["p_info"])
    D.check(rc == 3, "nor over POP3S", out)
    rc, out = mc("submit", "587", f"info@{DOM}", st["p_info"], f"info@{DOM}", f"info@{DOM}", "--subject", "drive-s")
    D.check(rc in (2, 3), "nor send", out)
    rc, out = mc("deliver", "25", "a@remote.example", f"info@{DOM}", "--subject", "drive-deferred")
    D.check(rc == 2 and re.search(r"\b4\d\d\b", out) is not None,
            "mail for it is deferred with a 4xx answer (kept by the sender, not bounced)", out)
    D.info(f"delivery to a suspended account: {out}")


def after_resume(reseller, st):
    good, rc, out = mc_until(["imap-find", f"info@{DOM}", st["p_info"], "drive-in"], tries=30)
    D.check(good, "after resuming, the mailbox logs in again", out)
    good, rc, out = mc_until(["deliver", "25", "a@remote.example", f"info@{DOM}", "--subject", "drive-deferred"],
                             tries=20)
    D.check(good, "and receives mail again", out)
    r = reseller.put(f"{MAIL}/limits", {"max_mailboxes": "unlimited", "max_messages_per_hour_account": "unlimited",
                                        "max_messages_per_hour_mailbox": "unlimited"})
    D.check(r.status == 200 and eff(r, "max_mailboxes") == (None, "account"),
            "its email limits are unlimited again (an explicit override)", repr(r)[:200])


# ------------------------------------------------------------------ 16. deleting the account
def deletion_impact(admin, reseller, cust_id):
    r = reseller.get("/api/v1/accounts/alice/deletion-impact")
    m = (r.body or {}).get("mail") or {}
    doms = {d.get("domain"): d.get("mode") for d in m.get("domains", [])}
    D.check(r.status == 200 and doms.get(DOM) == "local" and doms.get(f"php.{DOM}") == "off"
            and m.get("mailboxes") == [f"info@{DOM}"] and (m.get("mailbox_bytes") or 0) > 0
            and m.get("forwarders") == [f"team@{DOM}"],
            "the deletion preview lists the account's email (domains, mailbox, its size, forwarder)", repr(r)[:600])
    r = admin.get(f"/api/v1/users/{cust_id}/deletion-impact")
    t = (r.body or {}).get("totals") or {}
    D.check(r.status == 200 and t.get("mail_domains") == len(doms) and t.get("mailboxes") == 1
            and t.get("forwarders") == 1, "the customer's deletion preview counts them", repr(r)[:400])


def plain_delete_refused(cust, reseller):
    for _ in range(4):
        r = reseller.delete("/api/v1/accounts/alice?remove_files=true")
        if r.code != "account_has_dns_zones":
            break
        D.info("the account still has DNS zones: they are deleted first")
        for z in items(cust.get("/api/v1/accounts/alice/dns/zones")):
            r2 = cust.delete(f"/api/v1/accounts/alice/dns/zones/{z.get('zone')}")
            D.info(f"delete zone {z.get('zone')}: {r2!r}"[:300])
    D.check(r.status == 409 and r.code == "account_has_mail",
            "a plain deletion is refused while the account has email (409 account_has_mail)", repr(r))


def after_deletion(st):
    p = D.sh("oxpanel-ctl", "mail", "domain-list", "--tenant", "alice")
    D.check(p.returncode != 0 or p.stdout.strip() == "", "the engine has no mail domain of the account",
            p.stdout + p.stderr)
    p = D.sh("bash", "-c", f"grep -rl '{DOM}' /etc/postfix/oxpanel /etc/dovecot/oxpanel* 2>/dev/null")
    D.check(p.stdout.strip() == "", "Postfix and Dovecot no longer mention alice.test", p.stdout)
    p = D.sh("find", "/var/lib/oxpanel-mail", "-name", f"*{DOM}*")
    D.check(p.stdout.strip() == "", "no DKIM key or script of alice.test is left", p.stdout)
    rc, out = mc("deliver", "25", "a@remote.example", f"info@{DOM}", "--subject", "drive-after")
    # No account holds alice.test any more: this host does not take mail for it
    # at all (Postfix answers as for any foreign domain: relay access denied).
    D.check(rc == 2 and re.search(r"\b5\d\d\b", out) is not None, "mail for info@alice.test is refused (5xx)", out)
    D.info(f"mail for the deleted account's address: {out}")
    res = D.eventually(lambda: (lambda a: (a == "", a))(D.dig(DOM, "MX")), 30, 1)
    D.check(res[0] is True, "the host's name server no longer answers alice.test's MX", repr(res[1]))
    p = D.sh("oxpanel-ctl", "host", "reconcile")
    D.check(p.returncode == 0 and "drifts=0" in p.stdout.splitlines(), "reconcile is clean (no mail drift)",
            p.stdout + p.stderr)
    for f in st.get("webmail_cert", ()):
        try:
            os.unlink(f)
        except OSError:
            pass


def domain_reused(st):
    bob = st.get("bob")
    if not bob:
        return
    r = bob.put(f"/api/v1/sites/{DOM}", {"document_root": "alice_html"})
    D.check(r.status == 201, "another customer may now have alice.test as a site", repr(r)[:300])
    r = bob.put(f"/api/v1/accounts/bob/mail/domains/{DOM}", {"mode": "local"})
    D.check(r.status == 201 and (r.body or {}).get("account") == "bob",
            "and use it for email (201): nothing of the deleted account holds the name", repr(r)[:300])
    r = bob.post(f"/api/v1/accounts/bob/mail/domains/{DOM}/mailboxes",
                 {"local_part": "info", "quota_bytes": 1048576, "generate_password": True})
    pw = (r.body or {}).get("generated_password") or ""
    D.check(r.status == 201 and pw, "info@alice.test is created anew for bob", repr(r)[:200])
    if pw:
        rc, out = mc("deliver", "25", "a@remote.example", f"info@{DOM}", "--subject", "drive-new-owner")
        D.check(rc == 0, "mail for it is accepted again", out)
        good, rc, out = mc_until(["imap-find", f"info@{DOM}", pw, "drive-new-owner"])
        D.check(good, "and read by its new owner", out)
        rc, out = mc("imap-find", f"info@{DOM}", pw, "drive-in")
        D.check(rc == 4, "none of the old owner's mail is in it", out)
        p = D.sh("stat", "-c", "%U", f"/home/bob/mail/{DOM}/info")
        D.check(p.stdout.strip() == "bob", "its mail is stored in bob's home", p.stdout + p.stderr)
