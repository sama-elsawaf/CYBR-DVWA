<?php
/**
 * Preliminary tests for secure_crypto.php  -  run:  php test_secure_crypto.php
 * Each line prints PASS/FAIL. Copy the output into your progress report as evidence.
 */
require __DIR__ . '/../vulnerabilities/cryptography/source/secure_crypto.php';   // the deployed module, not a copy

$pass = 0; $fail = 0;
function check(string $name, bool $ok): void {
    global $pass, $fail;
    $ok ? $pass++ : $fail++;
    echo ($ok ? "PASS  " : "FAIL  ") . $name . "\n";
}

$key = random_bytes(32);
$msg = "Your new password is: Olifant";

// T1 functional: round trip
check("round trip (ASCII)", sc_decrypt(sc_encrypt($msg, $key), $key) === $msg);
check("round trip (unicode)", sc_decrypt(sc_encrypt("كلمة السر ✓", $key), $key) === "كلمة السر ✓");
check("round trip (empty message)", sc_decrypt(sc_encrypt("", $key), $key) === "");

// T2 confidentiality: same plaintext must give different ciphertexts (fresh nonce)
check("same plaintext -> different ciphertext", sc_encrypt($msg, $key) !== sc_encrypt($msg, $key));

// T3 integrity: flip ONE bit in EVERY byte of the message; every change must be rejected
$raw = base64_decode(sc_encrypt($msg, $key));
$rejected = 0;
for ($i = 0; $i < strlen($raw); $i++) {
    $bad = $raw; $bad[$i] = chr(ord($bad[$i]) ^ 1);
    if (sc_decrypt(base64_encode($bad), $key) === false) { $rejected++; }
}
check("tamper: 1-bit flip at all " . strlen($raw) . " positions rejected ($rejected)", $rejected === strlen($raw));

// T4 truncation / garbage
check("truncated message rejected", sc_decrypt(substr(sc_encrypt($msg, $key), 0, 20), $key) === false);
check("garbage input rejected", sc_decrypt("not-base64!!", $key) === false);

// T5 authentication: wrong key, wrong associated data
check("wrong key rejected", sc_decrypt(sc_encrypt($msg, $key), random_bytes(32)) === false);
check("AAD match accepted", sc_decrypt(sc_encrypt($msg, $key, "user:2"), $key, "user:2") === $msg);
check("AAD mismatch rejected", sc_decrypt(sc_encrypt($msg, $key, "user:2"), $key, "user:3") === false);

// T6 key handling: the master key comes ONLY from the file in CRYPTO_KEY_FILE; anything else fails closed
$kf = tempnam(sys_get_temp_dir(), 'key');
putenv('CRYPTO_KEY_FILE');
check("CRYPTO_KEY_FILE unset -> sc_load_key() false", sc_load_key() === false);
putenv('CRYPTO_KEY_B64=' . base64_encode($key));
check("old CRYPTO_KEY_B64 env var is ignored (no env fallback)", sc_load_key() === false);
putenv("CRYPTO_KEY_FILE=$kf.missing");
check("missing key file -> false", sc_load_key() === false);
file_put_contents($kf, '');
putenv("CRYPTO_KEY_FILE=$kf");
check("empty key file -> false", sc_load_key() === false);
file_put_contents($kf, base64_encode("short"));
check("short (5-byte) key file -> false", sc_load_key() === false);
file_put_contents($kf, base64_encode($key) . "\n");
check("valid 32-byte master key accepted (trailing newline ok)", sc_load_master() === $key);
check("sc_encrypt refuses a 5-byte key", sc_encrypt($msg, "short") === false);

// T6b HKDF key separation: K_msg != K_cookie != master, both 32 bytes, deterministic
$km = sc_load_key(); $kc = sc_cookie_key();
check("K_msg and K_cookie are 32 bytes", strlen($km) === 32 && strlen($kc) === 32);
check("K_msg != K_cookie != master", $km !== $kc && $km !== $key && $kc !== $key);
check("K_msg = HKDF-SHA-256(master, info)", $km === hash_hkdf('sha256', $key, 32, SC_INFO_MSG));
check("message encrypted with K_cookie does not decrypt with K_msg", sc_decrypt(sc_encrypt($msg, $kc), $km) === false);
// RFC 5869 Test Case 1 (HKDF-SHA-256 known-answer) -> hash_hkdf is the standard construction
$okm = hash_hkdf('sha256', hex2bin('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'), 42,
                 hex2bin('f0f1f2f3f4f5f6f7f8f9'), hex2bin('000102030405060708090a0b0c'));
check("HKDF known-answer (RFC 5869 TC1)", bin2hex($okm) ===
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
unlink($kf); putenv('CRYPTO_KEY_B64');

// T7 nonce uniqueness over 100,000 messages
$seen = []; $dup = 0;
for ($i = 0; $i < 100000; $i++) {
    $n = substr(base64_decode(sc_encrypt("x", $key)), 1, 12);
    if (isset($seen[$n])) { $dup++; }
    $seen[$n] = 1;
}
check("100,000 nonces, duplicates = $dup", $dup === 0);

// T8 known-answer test: AES-256-GCM, McGrew & Viega GCM spec, Test Case 15
$K = hex2bin("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
$IV = hex2bin("cafebabefacedbaddecaf888");
$P = hex2bin("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
$tag = '';
$C = openssl_encrypt($P, 'aes-256-gcm', $K, OPENSSL_RAW_DATA, $IV, $tag, '', 16);
check("known-answer ciphertext matches published vector",
      bin2hex($C) === "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad");
check("known-answer tag matches published vector", bin2hex($tag) === "b094dac5d93471bdec1a502270e3cc6c");

// T9 performance (1 KB message, 20,000 operations) : XOR (old) vs AES-GCM (new)
$data = random_bytes(1024); $xk = "wachtwoord"; $N = 20000;
$t = hrtime(true);
for ($i = 0; $i < $N; $i++) { $o = ''; for ($j = 0; $j < 1024; $j++) { $o .= $data[$j] ^ $xk[$j % 10]; } }
$xor_ms = (hrtime(true) - $t) / 1e6;
$t = hrtime(true);
for ($i = 0; $i < $N; $i++) { sc_decrypt(sc_encrypt($data, $key), $key); }
$gcm_ms = (hrtime(true) - $t) / 1e6;
// NOTE: not a fair comparison. The XOR side is a slow pure-PHP loop, while AES-GCM runs in native OpenSSL
// (and uses hardware AES instructions). Report it as "AES-GCM adds negligible overhead", NOT "GCM is faster".
printf("INFO  1 KB x %d: XOR (pure-PHP loop) = %.0f ms | AES-256-GCM encrypt+decrypt (OpenSSL) = %.0f ms\n", $N, $xor_ms, $gcm_ms);

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
