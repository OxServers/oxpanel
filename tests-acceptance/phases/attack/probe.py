# Attack battery, run by a tenant's Python application (see phases/80-attacks.sh).
# GET /probe runs every line of probes.tsv and prints "name<TAB>OPEN|BLOCKED<TAB>want<TAB>detail".
import os, signal, socket, subprocess, sys, time
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn, UnixStreamServer


def run(argv):
    try:
        subprocess.run(argv, check=True, capture_output=True, timeout=5)
        return True, 'exit 0'
    except Exception as e:  # noqa: BLE001
        return False, type(e).__name__


def one(op, arg):
    try:
        if op == 'read':
            open(arg, 'rb').read(1); return True, 'read ok'
        if op == 'cat':
            return run(['/usr/bin/cat', arg])
        if op == 'list':
            os.listdir(arg); return True, 'listed'
        if op == 'write':
            open(arg, 'w').write('x'); return True, 'created'
        if op == 'touch':
            return run(['/usr/bin/touch', arg])
        if op == 'kill':
            os.kill(int(arg), 0); return True, 'signal permitted'
        if op == 'unix':
            s = socket.socket(socket.AF_UNIX); s.settimeout(2)
            try:
                s.connect(arg); return True, 'connected'
            finally:
                s.close()
        if op == 'run':
            return run(arg.split(' '))
    except Exception as e:  # noqa: BLE001
        return False, type(e).__name__
    return False, 'unknown op'


def battery():
    out = ''
    for line in open('/home/ATTACKER/probes.tsv').read().split('\n'):
        if not line:
            continue
        op, name, arg, want = line.split('\t')
        o, d = one(op, arg)
        out += f"{name}\t{'OPEN' if o else 'BLOCKED'}\t{want}\t{d}\n"
        if op == 'read':
            o2, d2 = one('cat', arg)
            out += f"{name}.cat\t{'OPEN' if o2 else 'BLOCKED'}\t{want}\t{d2}\n"
        if op == 'write':
            o2, d2 = one('touch', arg)
            out += f"{name}.touch\t{'OPEN' if o2 else 'BLOCKED'}\t{want}\t{d2}\n"
    st = open('/proc/self/status').read()
    def f(k):
        for l in st.split('\n'):
            if l.startswith(k + ':'):
                return l.split(None, 1)[1]
    out += f"STATUS\tuid={os.getuid()}\tnonewprivs={f('NoNewPrivs')}\tcapeff={f('CapEff')}\tseccomp={f('Seccomp')}\n"
    return out


requests = 0


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, text):
        b = text.encode()
        self.send_response(200); self.send_header('Content-Length', str(len(b))); self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        global requests
        requests += 1
        u = self.path
        if u.startswith('/probe'):
            return self.reply(battery())
        if u.startswith('/echo'):
            return self.reply(repr((requests, u, dict(self.headers))))
        if u.startswith('/count'):
            return self.reply(str(requests))
        if u.startswith('/spawn'):
            subprocess.Popen(['/usr/bin/sleep', '600'], start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return self.reply('spawned')
        if u.startswith('/memhog'):
            keep = []
            while True:
                keep.append(bytearray(b'\x01' * (32 << 20)))
        if u.startswith('/tmpfill'):
            with open('/tmp/fill', 'wb') as f:
                for _ in range(200):
                    f.write(b'\x01' * (1 << 20))
            return self.reply('filled %d' % os.path.getsize('/tmp/fill'))
        if u.startswith('/tmplist'):
            return self.reply(','.join(os.listdir('/tmp')))
        if u.startswith('/fork'):
            n = 0
            while n < 600:
                try:
                    subprocess.Popen(['/usr/bin/sleep', '25'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except OSError:
                    break
                n += 1
            return self.reply('forked %d' % n)
        self.reply('python-attacker ' + u)


class Server(ThreadingMixIn, UnixStreamServer):
    daemon_threads = True


Server(os.environ['PORT'], Handler).serve_forever()
