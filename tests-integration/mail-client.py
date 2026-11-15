#!/usr/bin/env python3
"""A mail client for the integration and acceptance tests (standard library
only, plus the openssl command for DKIM).

    mail-client.py deliver PORT FROM TO [--from-header A] [--subject S] [--size N] [--host H] [--eicar]
    mail-client.py submit PORT USER PASS FROM TO [--from-header A] [--subject S]
    mail-client.py imap-count USER PASS          (prints the number of messages)
    mail-client.py imap-find USER PASS SUBJECT [--out FILE]
    mail-client.py imap-clear USER PASS
    mail-client.py pop3 USER PASS
    mail-client.py auth-before-tls PORT          (0 if AUTH is not offered before STARTTLS)
    mail-client.py dkim-verify FILE PUBKEY_B64   (0 if the DKIM-Signature verifies)
    mail-client.py authority PORT ZONE LOGFILE  (a tiny authoritative DNS server on
                                                 127.0.0.1:PORT for ZONE: A 192.0.2.53 and
                                                 TXT "v=spf1 -all" for every name in it;
                                                 logs "name type" per question; runs until killed)

Exit status: 0 accepted / found / verified, 2 refused by the server,
3 login failed, 4 not found, 1 anything else.
"""

import base64
import imaplib
import os
import poplib
import re
import smtplib
import ssl
import subprocess
import sys
import tempfile
import time

# Where submission and IMAP connect (MAIL_CLIENT_HOST; the loopback by default).
HOST = os.environ.get("MAIL_CLIENT_HOST", "127.0.0.1")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def opt(args, name, default=None):
    if name in args:
        i = args.index(name)
        v = args[i + 1]
        del args[i : i + 2]
        return v
    return default


def message(frm, to, subject, size):
    body = "hello from the OxPanel tests\r\n"
    if size:
        line = "x" * 76 + "\r\n"
        body += line * (int(size) // len(line) + 1)
    return (
        f"From: {frm}\r\nTo: {to}\r\nSubject: {subject}\r\n"
        f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n"
        f"Message-ID: <{time.time_ns()}@oxpanel.test>\r\n\r\n{body}"
    )


def eicar_message(frm, to, subject):
    """A message with the standard antivirus test file attached (assembled
    here so that no file of the repository holds the whole string)."""
    eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    b = "oxpanel-test-boundary"
    att = base64.b64encode(eicar.encode()).decode()
    return (
        f"From: {frm}\r\nTo: {to}\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\n"
        f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n"
        f"Message-ID: <{time.time_ns()}@oxpanel.test>\r\n"
        f'Content-Type: multipart/mixed; boundary="{b}"\r\n\r\n'
        f"--{b}\r\nContent-Type: text/plain\r\n\r\nsee the attachment\r\n"
        f'--{b}\r\nContent-Type: application/octet-stream; name="eicar.com"\r\n'
        f'Content-Disposition: attachment; filename="eicar.com"\r\n'
        f"Content-Transfer-Encoding: base64\r\n\r\n{att}\r\n--{b}--\r\n"
    )


def deliver(args):
    hdr = opt(args, "--from-header")
    subject = opt(args, "--subject", f"test {time.time_ns()}")
    size = opt(args, "--size")
    host = opt(args, "--host", "127.0.0.1")
    eicar = "--eicar" in args
    if eicar:
        args.remove("--eicar")
    port, frm, to = args
    s = smtplib.SMTP(host, int(port), timeout=60)
    s.ehlo("tester.oxpanel.test")
    try:
        msg = eicar_message(hdr or frm, to, subject) if eicar else message(hdr or frm, to, subject, size)
        s.sendmail(frm, [to], msg)
    except smtplib.SMTPException as e:
        print(f"refused: {e}")
        return 2
    finally:
        try:
            s.quit()
        except Exception:
            pass
    print("accepted")
    return 0


def submit(args):
    hdr = opt(args, "--from-header")
    subject = opt(args, "--subject", f"test {time.time_ns()}")
    port, user, pw, frm, to = args
    if int(port) == 465:
        s = smtplib.SMTP_SSL(HOST, 465, context=CTX, timeout=60)
    else:
        s = smtplib.SMTP(HOST, int(port), timeout=60)
        s.ehlo()
        s.starttls(context=CTX)
        s.ehlo()
    try:
        try:
            s.login(user, pw)
        except smtplib.SMTPAuthenticationError as e:
            print(f"login failed: {e}")
            return 3
        try:
            s.sendmail(frm, [to], message(hdr or frm, to, subject, None))
        except smtplib.SMTPException as e:
            print(f"refused: {e}")
            return 2
    finally:
        try:
            s.quit()
        except Exception:
            pass
    print("accepted")
    return 0


def imap_login(user, pw):
    m = imaplib.IMAP4_SSL(HOST, 993, ssl_context=CTX, timeout=30)
    try:
        m.login(user, pw)
    except imaplib.IMAP4.error as e:
        print(f"login failed: {e}")
        return None
    return m


def imap_count(args):
    m = imap_login(*args)
    if not m:
        return 3
    _, d = m.select("INBOX")
    print(int(d[0]))
    m.logout()
    return 0


def imap_find(args):
    out = opt(args, "--out")
    user, pw, subject = args
    m = imap_login(user, pw)
    if not m:
        return 3
    m.select("INBOX")
    # A literal: the subject may hold quotes.
    m.literal = subject.encode()
    _, d = m.search(None, "SUBJECT")
    ids = d[0].split()
    if not ids:
        m.logout()
        return 4
    _, data = m.fetch(ids[-1], "(RFC822)")
    raw = data[0][1]
    if out:
        with open(out, "wb") as f:
            f.write(raw)
    m.logout()
    return 0


def imap_clear(args):
    m = imap_login(*args)
    if not m:
        return 3
    m.select("INBOX")
    m.store("1:*", "+FLAGS", "\\Deleted")
    m.expunge()
    m.logout()
    return 0


def pop3(args):
    user, pw = args
    p = poplib.POP3_SSL("127.0.0.1", 995, context=CTX)
    try:
        p.user(user)
        p.pass_(pw)
    except poplib.error_proto as e:
        print(f"login failed: {e}")
        return 3
    print(p.stat()[0])
    p.quit()
    return 0


def auth_before_tls(args):
    s = smtplib.SMTP("127.0.0.1", int(args[0]), timeout=30)
    s.ehlo()
    offered = s.has_extn("auth")
    s.quit()
    return 1 if offered else 0


# ---- DKIM (RFC 6376), relaxed/relaxed, rsa-sha256 --------------------------


def unfold(raw):
    """Header fields as (name, raw text incl. name and colon), in order."""
    head = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    fields = []
    for line in head.split("\r\n"):
        if line[:1] in (" ", "\t") and fields:
            fields[-1] = fields[-1] + "\r\n" + line
        else:
            fields.append(line)
    return [(f.split(":", 1)[0].strip().lower(), f) for f in fields if ":" in f]


def relaxed_header(field):
    name, value = field.split(":", 1)
    value = re.sub(r"\r\n", "", value)
    value = re.sub(r"[ \t]+", " ", value).strip()
    return f"{name.strip().lower()}:{value}"


def relaxed_body(raw):
    body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
    lines = body.split(b"\r\n")
    out = [re.sub(rb"[ \t]+", b" ", l).rstrip(b" \t") for l in lines]
    while out and out[-1] == b"":
        out.pop()
    return b"".join(l + b"\r\n" for l in out)


def dkim_verify(args):
    path, pubkey = args
    raw = open(path, "rb").read().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    fields = unfold(raw)
    sig = [f for n, f in fields if n == "dkim-signature"]
    if not sig:
        print("no DKIM-Signature")
        return 4
    sigfield = sig[0]
    tags = {}
    for part in re.sub(r"\s+", "", sigfield.split(":", 1)[1]).split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k] = v
    if tags.get("a") != "rsa-sha256" or tags.get("c") != "relaxed/relaxed":
        print(f"unexpected a= or c=: {tags.get('a')} {tags.get('c')}")
        return 1
    import hashlib

    bh = base64.b64encode(hashlib.sha256(relaxed_body(raw)).digest()).decode()
    if bh != tags["bh"]:
        print("body hash mismatch")
        return 2
    # Signed headers, each name taking the next instance from the bottom.
    remaining = {}
    for n, f in fields:
        remaining.setdefault(n, []).append(f)
    data = ""
    for name in tags["h"].lower().split(":"):
        if remaining.get(name):
            data += relaxed_header(remaining[name].pop()) + "\r\n"
    # Only the b= tag is emptied, not bh=.
    unsigned = re.sub(r"(^|;)(\s*b=)[^;]*", r"\1\2", sigfield)
    data += relaxed_header(unsigned)
    with tempfile.TemporaryDirectory() as d:
        pem = os.path.join(d, "pub.pem")
        with open(pem, "w") as f:
            f.write("-----BEGIN PUBLIC KEY-----\n")
            for i in range(0, len(pubkey), 64):
                f.write(pubkey[i : i + 64] + "\n")
            f.write("-----END PUBLIC KEY-----\n")
        sigbin = os.path.join(d, "sig")
        with open(sigbin, "wb") as f:
            f.write(base64.b64decode(tags["b"]))
        payload = os.path.join(d, "data")
        with open(payload, "wb") as f:
            f.write(data.encode("latin-1"))
        r = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", pem, "-signature", sigbin, payload],
            capture_output=True,
        )
    print(r.stdout.decode().strip() or r.stderr.decode().strip())
    return 0 if r.returncode == 0 else 2


def authority(args):
    """Answers every question for a name in ZONE (no network beyond the
    loopback: the resolver tests never depend on the Internet)."""
    import socket
    import struct
    port, zone, logfile = args
    zone = zone.lower().rstrip(".")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", int(port)))
    log = open(logfile, "a", buffering=1)
    while True:
        data, peer = sock.recvfrom(4096)
        if len(data) < 12:
            continue
        qid, flags, qd = struct.unpack(">HHH", data[:6])
        i, labels = 12, []
        while i < len(data) and data[i] != 0:
            n = data[i]
            labels.append(data[i + 1 : i + 1 + n].decode("ascii", "replace"))
            i += 1 + n
        i += 1
        if qd != 1 or i + 4 > len(data):
            continue
        qtype, qclass = struct.unpack(">HH", data[i : i + 4])
        question = data[12 : i + 4]
        name = ".".join(labels).lower()
        log.write(f"{name} {qtype}\n")
        inside = name == zone or name.endswith("." + zone)
        answers = b""
        count = 0
        if inside and qtype == 1:
            answers = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 53])
            count = 1
        elif inside and qtype == 16:
            txt = b"v=spf1 -all"
            answers = b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 60, len(txt) + 1) + bytes([len(txt)]) + txt
            count = 1
        rcode = 0 if inside else 5  # REFUSED outside the zone
        # QR, AA, RD copied, rcode
        rflags = 0x8400 | (flags & 0x0100) | rcode
        reply = struct.pack(">HHHHHH", qid, rflags, 1, count, 0, 0) + question + answers
        sock.sendto(reply, peer)


def main():
    cmd, args = sys.argv[1], sys.argv[2:]
    return {
        "deliver": deliver,
        "submit": submit,
        "imap-count": imap_count,
        "imap-find": imap_find,
        "imap-clear": imap_clear,
        "pop3": pop3,
        "auth-before-tls": auth_before_tls,
        "dkim-verify": dkim_verify,
        "authority": authority,
    }[cmd](args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, smtplib.SMTPException, imaplib.IMAP4.error) as e:
        print(f"error: {e}")
        sys.exit(1)
