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
if ($do === 'feat') { // feature attacks (feat.py) as a child of PHP-FPM; arguments separated by tabs
  $args = array_map('escapeshellarg', explode("\t", $_GET['args'] ?? ''));
  echo shell_exec('/usr/bin/python3 /home/ATTACKER/feat.py ' . implode(' ', $args) . ' 2>&1'); exit;
}
if ($do === 'ini') { // the settings this site's scripts run with (and whether .user.ini lifted any)
  foreach (['memory_limit', 'upload_max_filesize', 'post_max_size', 'open_basedir', 'allow_url_include', 'auto_prepend_file', 'disable_functions', 'max_execution_time'] as $k) echo "$k=" . ini_get($k) . "\n";
  exit;
}
if ($do === 'db') { // database attacks through PHP's own client (mysqli), the language API
  mysqli_report(MYSQLI_REPORT_OFF);
  $u = $_GET['u']; $pw = $_GET['p']; $own = $_GET['own']; $victim = $_GET['victim'];
  $q = function ($name, $sql, $want, $db = null, $check = null) use ($u, $pw) {
    $c = @mysqli_connect('localhost', $u, $pw, $db ?? '', 0, '/var/lib/mysql/mysql.sock');
    if (!$c) { echo "$name\tBLOCKED\t$want\tconnect: " . mysqli_connect_errno() . "\n"; return; }
    $r = @mysqli_query($c, $sql);
    $ok = $r !== false; $detail = $ok ? 'ok' : mysqli_errno($c) . ' ' . substr(mysqli_error($c), 0, 60);
    if ($ok && $check !== null && $r instanceof mysqli_result) { $row = mysqli_fetch_row($r); $ok = $check($row ? $row[0] : null); $detail = 'value ' . substr((string)($row[0] ?? 'NULL'), 0, 40); }
    echo "$name\t" . ($ok ? 'OPEN' : 'BLOCKED') . "\t$want\t" . str_replace(["\t", "\n"], ' ', $detail) . "\n";
    mysqli_close($c);
  };
  $q('php-db-own', 'SELECT 41+1', 'open', $own, fn($v) => $v == 42);
  $q('php-db-victim', 'SELECT 1', 'blocked', $victim);
  $q('php-db-victim-table', "SELECT COUNT(*) FROM `$victim`.secrets", 'blocked');
  $q('php-db-load-file', "SELECT LOAD_FILE('/etc/passwd')", 'blocked', null, fn($v) => $v !== null && str_contains($v, 'root:'));
  $q('php-db-outfile', "SELECT 'x' INTO OUTFILE '/var/lib/mysql/oxprobe-php.txt'", 'blocked', $own);
  $q('php-db-create-user', "CREATE USER 'oxprobe2'@'localhost'", 'blocked');
  $q('php-db-grant', 'GRANT ALL ON *.* TO CURRENT_USER', 'blocked');
  $q('php-db-global', 'SET GLOBAL max_connections = 2', 'blocked');
  $q('php-db-accounts', 'SELECT COUNT(*) FROM mysql.global_priv', 'blocked');
  $q('php-db-trash', "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name LIKE 'oxpanel%'", 'blocked', null, fn($v) => $v > 0);
  $q('php-db-other-schemas', "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name NOT IN ('information_schema', '$own')", 'blocked', null, fn($v) => $v > 0);
  $q('php-db-definer-root', "CREATE DEFINER=`root`@`localhost` PROCEDURE `$own`.pr() SELECT 1", 'blocked');
  $q('php-db-create-db', 'CREATE DATABASE oxprobe_php', 'blocked');
  $c = @mysqli_connect('localhost', 'root', '', '', 0, '/var/lib/mysql/mysql.sock');
  echo "php-db-root-via-socket\t" . ($c ? 'OPEN' : 'BLOCKED') . "\tblocked\t" . mysqli_connect_errno() . "\n";
  $c = @mysqli_connect('localhost', explode('_', $victim)[0] . '_app', '', '', 0, '/var/lib/mysql/mysql.sock');
  echo "php-db-victim-user-no-password\t" . ($c ? 'OPEN' : 'BLOCKED') . "\tblocked\t" . mysqli_connect_errno() . "\n";
  exit;
}
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
