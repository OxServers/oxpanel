// Attack battery, run by a tenant's Node.js application (see phases/80-attacks.sh).
// GET /probe runs every line of probes.tsv and prints "name<TAB>OPEN|BLOCKED<TAB>detail".
const http = require('http');
const fs = require('fs');
const net = require('net');
const cp = require('child_process');

function run(bin, args) {
  try { cp.execFileSync(bin, args, { stdio: 'pipe', timeout: 5000 }); return [true, 'exit 0']; }
  catch (e) { return [false, String(e.code || e.status || e.message).slice(0, 60)]; }
}
function unix(path) {
  return new Promise((resolve) => {
    const s = net.connect(path);
    const done = (open, d) => { s.destroy(); resolve([open, d]); };
    s.setTimeout(2000, () => done(false, 'timeout'));
    s.on('connect', () => done(true, 'connected'));
    s.on('error', (e) => done(false, e.code));
  });
}
async function one(op, arg) {
  try {
    switch (op) {
      case 'read': fs.readFileSync(arg); return [true, 'read ok'];
      case 'cat': return run('/usr/bin/cat', [arg]);
      case 'list': fs.readdirSync(arg); return [true, 'listed'];
      case 'write': fs.writeFileSync(arg, 'x'); return [true, 'created'];
      case 'touch': return run('/usr/bin/touch', [arg]);
      case 'kill': process.kill(Number(arg), 0); return [true, 'signal permitted'];
      case 'unix': return await unix(arg);
      case 'run': { const [b, ...a] = arg.split(' '); return run(b, a); }
      default: return [false, 'unknown op'];
    }
  } catch (e) { return [false, e.code || String(e).slice(0, 60)]; }
}
async function battery() {
  let out = '';
  for (const line of fs.readFileSync('/home/ATTACKER/probes.tsv', 'utf8').split('\n')) {
    if (!line) continue;
    const [op, name, arg, want] = line.split('\t');
    const [open, detail] = await one(op, arg);
    out += `${name}\t${open ? 'OPEN' : 'BLOCKED'}\t${want}\t${detail}\n`;
    if (op === 'read') {            // the same file again through a child process: no language sandbox
      const [o2, d2] = await one('cat', arg);
      out += `${name}.cat\t${o2 ? 'OPEN' : 'BLOCKED'}\t${want}\t${d2}\n`;
    }
    if (op === 'write') {
      const [o2, d2] = await one('touch', arg);
      out += `${name}.touch\t${o2 ? 'OPEN' : 'BLOCKED'}\t${want}\t${d2}\n`;
    }
  }
  const st = fs.readFileSync('/proc/self/status', 'utf8');
  const f = (k) => (st.match(new RegExp('^' + k + ':\\s+(.*)$', 'm')) || [])[1];
  out += `STATUS\tuid=${process.getuid()}\tnonewprivs=${f('NoNewPrivs')}\tcapeff=${f('CapEff')}\tseccomp=${f('Seccomp')}\n`;
  return out;
}
let requests = 0;
http.createServer(async (req, res) => {
  requests++;
  const u = req.url;
  if (u.startsWith('/probe')) { res.end(await battery()); return; }
  if (u.startsWith('/echo')) { res.end(JSON.stringify({ n: requests, url: u, headers: req.headers })); return; }
  if (u.startsWith('/count')) { res.end(String(requests)); return; }
  if (u.startsWith('/spawn')) {   // a detached process that outlives the request
    cp.spawn('/usr/bin/sleep', ['600'], { detached: true, stdio: 'ignore' }).unref();
    res.end('spawned'); return;
  }
  if (u.startsWith('/memhog')) {  // allocate and touch until the cgroup kills us
    const keep = [];
    for (;;) { const b = Buffer.alloc(32 << 20, 1); keep.push(b); }
  }
  if (u.startsWith('/tmpfill')) { // 200 MiB into the private /tmp
    const fd = fs.openSync('/tmp/fill', 'w'); const chunk = Buffer.alloc(1 << 20, 1);
    for (let i = 0; i < 200; i++) fs.writeSync(fd, chunk);
    fs.closeSync(fd); res.end('filled ' + fs.statSync('/tmp/fill').size); return;
  }
  if (u.startsWith('/tmplist')) { res.end(fs.readdirSync('/tmp').join(',')); return; }
  if (u.startsWith('/fork')) {    // start sleepers until the kernel refuses
    let n = 0;
    for (; n < 600; n++) {
      try { const c = cp.spawn('/usr/bin/sleep', ['25'], { stdio: 'ignore' }); c.on('error', () => {}); if (c.pid === undefined) break; c.unref(); } catch (e) { break; }
    }
    setTimeout(() => res.end('forked ' + n), 1500); return;
  }
  res.end('node-attacker ' + u);
}).listen(process.env.PORT);
