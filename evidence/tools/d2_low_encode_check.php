<?php
// D2: call the Low Cryptography code (low.php) directly inside the dvwa container and show what the user would see.
// Needed because without the master key the UI cannot switch to Low (the level cookie cannot be signed).
//   docker compose exec dvwa php evidence/tools/d2_low_encode_check.php
$k = getenv('CRYPTO_KEY_FILE');
echo "CRYPTO_KEY_FILE=$k -> " . (is_dir($k) ? "a DIRECTORY (Docker created it because the host file was missing)"
     : (is_file($k) ? "a file of " . filesize($k) . " bytes" : "does not exist")) . "\n";
chdir(__DIR__ . '/../../vulnerabilities/cryptography/source');
$_SERVER['REQUEST_METHOD'] = 'POST'; $_SERVER['PHP_SELF'] = '/vulnerabilities/cryptography/';
$_POST = ['message' => 'hello', 'direction' => 'encode'];
include 'low.php';
preg_match('/<div class="warning">(.*?)<\/div>/s', $html, $m);
echo "low.php Encode('hello'): encoded=" . var_export($encoded, true) . "\n";
echo "message shown to the user: " . ($m[1] ?? '(none)') . "\n";
