# Feature attacks, run by a tenant's code (see phases/80-attacks.sh, sections 7-15).
#
# Imported by the attacker's Python application (language API, in-process) and
# run as a child process by its PHP, its Python application and its scheduled
# tasks: `python3 feat.py <action> [args...]`. Every attempt prints one line
#   name<TAB>OPEN|BLOCKED<TAB>want<TAB>detail
# where want is blocked (an attack: OPEN is a hole), open (a control: the
# harness must be able to do what the tenant may do) or info (recorded only).
# Standard library only: the tenant's code has nothing else.
import os, random, socket, struct, subprocess, sys

OUT = []


def emit(name, opened, want, detail):
    detail = str(detail).replace('\t', ' ').replace('\n', ' ')[:160]
    OUT.append(f"{name}\t{'OPEN' if opened else 'BLOCKED'}\t{want}\t{detail}")


def run(argv, stdin=None, timeout=20):
    """(exit status, stdout+stderr) of a child; never raises."""
    try:
        p = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).decode('utf-8', 'replace')
    except Exception as e:  # noqa: BLE001
        return 255, type(e).__name__


# ---------------------------------------------------------------- DNS (wire format, no library)

def qname(name):
    out = b''
    for label in name.rstrip('.').split('.'):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b'\0'


def query(name, qtype, qclass=1, rd=False, opcode=0):
    ident = random.randint(0, 65535)
    flags = (opcode << 11) | (0x0100 if rd else 0)
    return ident, struct.pack('>HHHHHH', ident, flags, 1, 0, 0, 0) + qname(name) + struct.pack('>HH', qtype, qclass)


def header(msg):
    if len(msg) < 12:
        return None
    ident, flags, qd, an, ns, ar = struct.unpack('>HHHHHH', msg[:12])
    return {'id': ident, 'rcode': flags & 0xF, 'ra': bool(flags & 0x80), 'aa': bool(flags & 0x400), 'an': an, 'ns': ns}


def udp(msg, port=53, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, ('127.0.0.1', port))
        return s.recv(65535)
    finally:
        s.close()


def tcp_messages(msg, port=53, timeout=5, limit=20):
    s = socket.create_connection(('127.0.0.1', port), timeout=timeout)
    out = []
    try:
        s.sendall(struct.pack('>H', len(msg)) + msg)
        buf = b''
        while len(out) < limit:
            c = s.recv(65535)
            if not c:
                break
            buf += c
            while len(buf) >= 2 and len(buf) >= 2 + struct.unpack('>H', buf[:2])[0]:
                n = struct.unpack('>H', buf[:2])[0]
                out.append(buf[2:2 + n]); buf = buf[2 + n:]
    except socket.timeout:
        pass
    finally:
        s.close()
    return out


def dns(victim_zone):
    # Zone transfer of another tenant's zone, and of the catalog of every hosted zone, without the TSIG key.
    for name, zone in (('axfr-victim-zone', victim_zone), ('axfr-catalog', 'catalog.oxpanel.invalid')):
        try:
            _, q = query(zone, 252)
            msgs = tcp_messages(q)
            got = sum(h['an'] for h in map(header, msgs) if h and h['rcode'] == 0)
            rc = [h['rcode'] for h in map(header, msgs) if h]
            emit(name, got > 0, 'blocked', f'records={got} rcodes={rc}')
        except Exception as e:  # noqa: BLE001
            emit(name, False, 'blocked', type(e).__name__)
        code, out = run(['/usr/bin/dig', '+tcp', '+time=3', '+tries=1', '@127.0.0.1', zone, 'AXFR'])
        emit(name + '.dig', 'Transfer failed' not in out and ' SOA ' in out.replace('\t', ' '), 'blocked', out.strip().splitlines()[-1:] if out.strip() else code)
    # IXFR too (BIND treats it like AXFR without a journal).
    try:
        _, q = query(victim_zone, 251)
        msgs = tcp_messages(q)
        got = sum(h['an'] for h in map(header, msgs) if h and h['rcode'] == 0)
        emit('ixfr-victim-zone', got > 0, 'blocked', f'records={got}')
    except Exception as e:  # noqa: BLE001
        emit('ixfr-victim-zone', False, 'blocked', type(e).__name__)
    # Recursion: an open resolver on the host would serve amplification and cache poisoning.
    for name, (qn, qt) in (('recursion-external', ('example.org', 1)), ('recursion-reverse', ('1.0.0.127.in-addr.arpa', 12))):
        try:
            _, q = query(qn, qt, rd=True)
            h = header(udp(q))
            emit(name, bool(h and h['rcode'] == 0 and (h['ra'] or h['an'] > 0)), 'blocked', h)
        except Exception as e:  # noqa: BLE001
            emit(name, False, 'blocked', type(e).__name__)
    try:
        _, q = query('version.bind', 16, qclass=3)
        r = udp(q); h = header(r)
        emit('server-version-disclosed', bool(h and h['rcode'] == 0 and h['an'] > 0 and b'9.' in r), 'blocked', h)
    except Exception as e:  # noqa: BLE001
        emit('server-version-disclosed', False, 'blocked', type(e).__name__)
    # A dynamic update (opcode 5) adding a TXT record to the victim's zone.
    try:
        ident = random.randint(0, 65535)
        rr = qname('pwned.' + victim_zone) + struct.pack('>HHIH', 16, 1, 300, 7) + b'\x06pwned!'
        msg = struct.pack('>HHHHHH', ident, 5 << 11, 1, 0, 1, 0) + qname(victim_zone) + struct.pack('>HH', 6, 1) + rr
        h = header(udp(msg))
        emit('dynamic-update-victim-zone', bool(h and h['rcode'] == 0), 'blocked', h)
    except Exception as e:  # noqa: BLE001
        emit('dynamic-update-victim-zone', False, 'blocked', type(e).__name__)
    code, out = run(['/usr/bin/nsupdate'], stdin=f'server 127.0.0.1\nzone {victim_zone}\nupdate add pwned2.{victim_zone} 300 TXT "x"\nsend\n'.encode())
    emit('dynamic-update-victim-zone.nsupdate', code == 0, 'blocked', out.strip()[:120] or code)
    # The control channel: without the key nothing; with the engine's key file (not readable) the server.
    try:
        s = socket.create_connection(('127.0.0.1', 953), timeout=2); s.close()
        emit('rndc-port-connect', True, 'info', 'TCP connect to the control channel succeeds (it needs the HMAC key to do anything)')
    except Exception as e:  # noqa: BLE001
        emit('rndc-port-connect', False, 'info', type(e).__name__)
    for key in ('/etc/named/oxpanel/rndc.key', '/etc/rndc.key'):
        code, out = run(['/usr/sbin/rndc', '-s', '127.0.0.1', '-p', '953', '-k', key, '-y', 'oxpanel-rndc', 'status'])
        emit('rndc-status-with-' + key.replace('/', '_'), code == 0, 'blocked', out.strip()[:120])
    code, out = run(['/usr/sbin/rndc', '-s', '127.0.0.1', '-p', '953', 'status'])
    emit('rndc-status-default', code == 0, 'blocked', out.strip()[:120])
    # The tenant may of course ask the server about hosted zones (control).
    try:
        _, q = query(victim_zone, 6)
        h = header(udp(q))
        emit('authoritative-answer', bool(h and h['rcode'] == 0 and h['aa']), 'open', h)
    except Exception as e:  # noqa: BLE001
        emit('authoritative-answer', False, 'open', type(e).__name__)


# ---------------------------------------------------------------- local listeners and sockets

def listeners(allowed_unix):
    """Every listening TCP/UDP port and UNIX socket on the host, tried from tenant code.

    TCP/UDP listeners are recorded as info (a tenant can reach loopback services: docs/SECURITY.md
    gap 2). UNIX sockets: anything under the engine's, other tenants' or MariaDB's control paths must
    refuse; everything else is info."""
    seen = set()
    for fam, path in (('tcp', '/proc/net/tcp'), ('tcp6', '/proc/net/tcp6')):
        try:
            for line in open(path).read().splitlines()[1:]:
                f = line.split()
                if f[3] != '0A':
                    continue
                addr, port = f[1].split(':'); port = int(port, 16)
                if (fam, port) in seen:
                    continue
                seen.add((fam, port))
                host = '127.0.0.1' if fam == 'tcp' else '::1'
                try:
                    s = socket.create_connection((host, port), timeout=2); s.close(); ok = True; d = 'connected'
                except Exception as e:  # noqa: BLE001
                    ok = False; d = type(e).__name__
                emit(f'listener-{fam}-{port}', ok, 'info', f'bound {addr} {d}')
        except OSError as e:
            emit('proc-net-' + fam, False, 'info', type(e).__name__)
    try:
        lines = open('/proc/net/unix').read().splitlines()[1:]
    except OSError as e:
        emit('proc-net-unix', False, 'info', type(e).__name__); return
    paths = sorted({l.split()[-1] for l in lines if len(l.split()) >= 8 and l.split()[-1].startswith('/') and l.split()[5] == '01'})
    for p in paths:
        sensitive = any(p.startswith(x) for x in ('/run/oxpanel', '/var/run/oxpanel', '/var/lib/oxpanel', '/home/', '/run/oxpanel-php', '/run/oxpanel-app', '/run/named', '/var/named', '/run/systemd/private', '/run/user/0'))
        want = 'blocked' if sensitive else 'info'
        if any(p.startswith(a) for a in allowed_unix):
            want = 'open' if p in allowed_unix else 'info'
        s = socket.socket(socket.AF_UNIX); s.settimeout(2)
        try:
            s.connect(p); ok, d = True, 'connected'
        except Exception as e:  # noqa: BLE001
            ok, d = False, type(e).__name__
        finally:
            s.close()
        emit('unix-' + p, ok, want, d)


# ---------------------------------------------------------------- databases, through the mariadb client

def sql(user, pw, stmt, db=None, timeout=20):
    argv = ['/usr/bin/mariadb', '--no-defaults', '--protocol=socket', '--socket=/var/lib/mysql/mysql.sock',
            '--batch', '--skip-column-names', '--connect-timeout=5', f'--user={user}', f'--password={pw}', '-e', stmt]
    if db:
        argv.insert(-2, f'--database={db}')
    return run(argv, timeout=timeout)


def db(user, pw, own_db, victim_db):
    code, out = sql(user, pw, 'SELECT 41+1', own_db)
    emit('db-own-database', code == 0 and '42' in out, 'open', out.strip()[:80])
    code, out = sql(user, pw, 'SELECT 1', victim_db)
    emit('db-victim-database', code == 0, 'blocked', out.strip()[:100])
    code, out = sql(user, pw, f'SELECT COUNT(*) FROM `{victim_db}`.secrets')
    emit('db-victim-table', code == 0, 'blocked', out.strip()[:100])
    code, out = sql(user, pw, 'SHOW DATABASES')
    others = [d for d in out.split() if d not in ('information_schema', own_db) and code == 0]
    emit('db-other-databases-visible', bool(others), 'blocked', others or out.strip()[:80])
    code, out = sql(user, pw, "SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata WHERE schema_name LIKE 'oxpanel%'")
    emit('db-trash-schemas-visible', code == 0 and out.strip() not in ('', 'NULL'), 'blocked', out.strip()[:100])
    code, out = sql(user, pw, "SELECT LOAD_FILE('/etc/passwd')")
    emit('db-load-file', code == 0 and 'root:' in out, 'blocked', out.strip()[:80])
    code, out = sql(user, pw, "SELECT 'x' INTO OUTFILE '/var/lib/mysql/oxprobe.txt'", own_db)
    emit('db-into-outfile', code == 0, 'blocked', out.strip()[:100])
    code, out = sql(user, pw, "CREATE TABLE IF NOT EXISTS ld (l TEXT); LOAD DATA INFILE '/etc/passwd' INTO TABLE ld", own_db)
    emit('db-load-data-infile', code == 0, 'blocked', out.strip()[:100])
    for name, stmt in (
        ('db-create-user', "CREATE USER 'oxprobe'@'localhost' IDENTIFIED BY 'x'"),
        ('db-grant-self-all', 'GRANT ALL PRIVILEGES ON *.* TO CURRENT_USER'),
        ('db-set-global', 'SET GLOBAL max_connections = 2'),
        ('db-read-account-table', 'SELECT COUNT(*) FROM mysql.global_priv'),
        ('db-read-user-view', 'SELECT COUNT(*) FROM mysql.user'),
        ('db-shutdown', 'SHUTDOWN'),
        ('db-definer-root-procedure', f"CREATE DEFINER=`root`@`localhost` PROCEDURE `{own_db}`.p_root() SELECT 1"),
        ('db-set-password-other', f"SET PASSWORD FOR '{victim_db.split('_')[0]}_app'@'localhost' = PASSWORD('x')"),
        ('db-create-database-outside-prefix', 'CREATE DATABASE oxprobe'),
        ('db-create-database-victim-prefix', f'CREATE DATABASE `{victim_db}_x`'),
        ('db-install-plugin', "INSTALL SONAME 'ha_connect'"),
        ('db-create-function-udf', "CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so'"),
        ('db-kill-connection-1', 'KILL 1'),
        ('db-show-grants-other', f"SHOW GRANTS FOR 'root'@'localhost'"),
    ):
        code, out = sql(user, pw, stmt, own_db)
        emit(name, code == 0, 'blocked', out.strip()[:100])
    code, out = sql(user, pw, 'SELECT COUNT(*) FROM information_schema.processlist')
    emit('db-processlist-count', code == 0, 'info', f'sees {out.strip()} connection(s) (own only without PROCESS)')
    # The server's administrator accounts through the socket's peer credentials.
    for u in ('root', 'mysql', os.environ.get('USER') or ''):
        if not u:
            continue
        code, out = run(['/usr/bin/mariadb', '--no-defaults', '--socket=/var/lib/mysql/mysql.sock', f'--user={u}', '-e', 'SELECT CURRENT_USER()'])
        emit('db-login-as-' + u, code == 0, 'blocked', out.strip()[:100])
    code, out = run(['/usr/bin/mariadb', '--no-defaults', '--socket=/var/lib/mysql/mysql.sock', '-e', 'SELECT CURRENT_USER()'])
    emit('db-login-as-unix-user', code == 0, 'blocked', out.strip()[:100])


def db_connections(user, pw, n):
    """Open n connections at once; how many the server accepts (bounded by MAX_USER_CONNECTIONS)."""
    procs = []
    for _ in range(n):
        procs.append(subprocess.Popen(['/usr/bin/mariadb', '--no-defaults', '--socket=/var/lib/mysql/mysql.sock', '--connect-timeout=5',
                                       f'--user={user}', f'--password={pw}', '-N', '-e', 'SELECT SLEEP(6)'],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))
    ok = 0
    err = ''
    for p in procs:
        try:
            _, e = p.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            p.kill(); continue
        if p.returncode == 0:
            ok += 1
        else:
            err = e.decode('utf-8', 'replace').strip()[:100]
    OUT.append(f'CONNECTIONS\t{ok}\t{n}\t{err}')


def main(argv):
    action = argv[0] if argv else ''
    if action == 'dns':
        dns(argv[1])
    elif action == 'listeners':
        listeners(argv[1:])
    elif action == 'db':
        db(*argv[1:5])
    elif action == 'dbconn':
        db_connections(argv[1], argv[2], int(argv[3]))
    elif action == 'id':
        st = open('/proc/self/status').read()
        f = lambda k: ([l.split(None, 1)[1] for l in st.splitlines() if l.startswith(k + ':')] or [''])[0]
        OUT.append(f"ID\tuid={os.getuid()}\tgid={os.getgid()}\tgroups={','.join(map(str, os.getgroups()))}\tnonewprivs={f('NoNewPrivs')}\tcapeff={f('CapEff')}")
    else:
        OUT.append(f'ERROR\tunknown action {action!r}')
    OUT.append('END\tdone')
    text = '\n'.join(OUT) + '\n'
    OUT.clear()
    return text


if __name__ == '__main__':
    sys.stdout.write(main(sys.argv[1:]))
