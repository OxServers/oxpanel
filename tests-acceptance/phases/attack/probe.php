<?php
// Attack battery, run by a tenant's PHP (see phases/80-attacks.sh).
// GET /probe.php prints "name<TAB>OPEN|BLOCKED<TAB>want<TAB>detail" per probe.
// /probe.php?do=fork|spawn|tmpfill|tmplist|echo run the heavier attacks.
function run($argv) { exec(implode(' ', array_map('escapeshellarg', $argv)) . ' 2>&1', $o, $rc); return [$rc === 0, "exit $rc"]; }
function one($op, $arg) {
  switch ($op) {
    case 'read': return [@file_get_contents($arg, false, null, 0, 1) !== false, 'file_get_contents'];
    case 'cat': return run(['/usr/bin/cat', $arg]);
    case 'list': return [@scandir($arg) !== false, 'scandir'];
    case 'write': $ok = @file_put_contents($arg, 'x') !== false; return [$ok, 'file_put_contents'];
    case 'touch': return run(['/usr/bin/touch', $arg]);
    case 'kill': return run(['/usr/bin/kill', '-0', $arg]);
    case 'unix': $s = @stream_socket_client("unix://$arg", $en, $es, 2); if ($s) { fclose($s); return [true, 'connected']; } return [false, "errno $en"];
    case 'run': return run(explode(' ', $arg));
  }
  return [false, 'unknown op'];
}
$do = $_GET['do'] ?? 'probe';
if ($do === 'echo') { echo json_encode(['url' => $_SERVER['REQUEST_URI'], 'host' => $_SERVER['HTTP_HOST'] ?? '', 'headers' => getallheaders()]); exit; }
if ($do === 'spawn') { exec('/usr/bin/setsid /usr/bin/sleep 600 >/dev/null 2>&1 &'); echo 'spawned'; exit; }
if ($do === 'tmpfill') { $f = fopen('/tmp/fill', 'w'); $c = str_repeat('x', 1 << 20); for ($i = 0; $i < 200; $i++) fwrite($f, $c); fclose($f); echo 'filled ' . filesize('/tmp/fill'); exit; }
if ($do === 'tmplist') { echo implode(',', array_diff(scandir('/tmp'), ['.', '..'])); exit; }
if ($do === 'memhog') { ini_set('memory_limit', '-1'); $a = []; for (;;) { $a[] = str_repeat(chr(65 + count($a) % 26), 32 << 20); } }
if ($do === 'fork') {
  $n = 0;
  for (; $n < 600; $n++) {
    $p = @proc_open(['/usr/bin/sleep', '25'], [], $pipes);
    if ($p === false) break;
    // proc_open succeeds even when fork fails in the child on some builds: confirm it started
    $st = proc_get_status($p); if (!$st['running'] && $st['exitcode'] > 0) break;
  }
  echo "forked $n"; exit;
}
foreach (explode("\n", file_get_contents('/home/ATTACKER/probes.tsv')) as $line) {
  if ($line === '') continue;
  [$op, $name, $arg, $want] = explode("\t", $line);
  [$o, $d] = one($op, $arg);
  echo "$name\t" . ($o ? 'OPEN' : 'BLOCKED') . "\t$want\t$d\n";
  if ($op === 'read') { [$o2, $d2] = one('cat', $arg); echo "$name.cat\t" . ($o2 ? 'OPEN' : 'BLOCKED') . "\t$want\t$d2\n"; }
  if ($op === 'write') { [$o2, $d2] = one('touch', $arg); echo "$name.touch\t" . ($o2 ? 'OPEN' : 'BLOCKED') . "\t$want\t$d2\n"; }
}
$st = file_get_contents('/proc/self/status');
$f = function ($k) use ($st) { preg_match('/^' . $k . ':\s+(.*)$/m', $st, $m); return $m[1] ?? ''; };
echo "STATUS\tuid=" . (int)trim(shell_exec('/usr/bin/id -u')) . "\tnonewprivs=" . $f('NoNewPrivs') . "\tcapeff=" . $f('CapEff') . "\tseccomp=" . $f('Seccomp') . "\n";
