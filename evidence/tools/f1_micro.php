<?php
// F1 micro-benchmark of the primitives alone (no HTTP), inside the dvwa container. Run: php evidence/tools/f1_micro.php [mode]
require __DIR__ . '/../../vulnerabilities/cryptography/source/secure_crypto.php';
require __DIR__ . '/../../dvwa/includes/password_hashing.php';
function hwm() { preg_match('/VmHWM:\s+(\d+) kB/', file_get_contents('/proc/self/status'), $m); return (int)$m[1]; }
$mode = $argv[1] ?? 'all';
if ($mode === 'rss-md5')    { $a = hwm(); md5('password');    echo "md5:      peak RSS before " . $a . " kB, after " . hwm() . " kB\n"; exit; }
if ($mode === 'rss-argon')  { $a = hwm(); ph_hash('password'); echo "argon2id: peak RSS before " . $a . " kB, after " . hwm() . " kB (delta " . (hwm()-$a) . " kB; memory_cost=" . PH_OPTIONS['memory_cost'] . " KiB)\n"; exit; }
function pct($xs, $p) { sort($xs); return $xs[(int)ceil($p * count($xs)) - 1]; }
function bench($name, $n, $fn) { $t = []; for ($i = 0; $i < $n; $i++) { $s = hrtime(true); $fn(); $t[] = (hrtime(true) - $s) / 1e3; }
  printf("| %-58s | %6d | %10.2f | %10.2f |\n", $name, $n, array_sum($t) / $n, pct($t, 0.95)); }
function xor_this($c, $k) { $o = ''; for ($i = 0; $i < strlen($c);) { for ($j = 0; ($j < strlen($k) && $i < strlen($c)); $j++, $i++) { $o .= $c[$i] ^ $k[$j]; } } return $o; }
$msg = "Your new password is: Olifant"; $key = random_bytes(32); $h = ph_hash('password'); $m5 = md5('password');
echo "| operation (PHP " . PHP_VERSION . ", " . OPENSSL_VERSION_TEXT . ") | n | mean us | p95 us |\n|---|---:|---:|---:|\n";
bench("XOR encode, key 'wachtwoord' + base64 (old low.php)", 2000, fn() => base64_encode(xor_this($msg, "wachtwoord")));
bench("AES-256-GCM sc_encrypt (random nonce, base64)", 2000, fn() => sc_encrypt($msg, $key));
bench("AES-256-GCM sc_decrypt (tag check)", 2000, fn() => sc_decrypt(sc_encrypt($msg, $key), $key));
bench("HKDF-SHA-256 derive one 32-byte key", 2000, fn() => hash_hkdf('sha256', $key, 32, SC_INFO_MSG));
bench("md5(password) compare (old login)", 2000, fn() => hash_equals($m5, md5('password')));
bench("Argon2id password_verify (m=19456 KiB, t=2, p=1)", 200, fn() => password_verify('password', $h));
bench("Argon2id password_hash (new hash, same params)", 200, fn() => ph_hash('password'));
