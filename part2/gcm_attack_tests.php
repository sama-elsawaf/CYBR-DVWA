<?php
/**
 * A1 (AFTER-test): the four attacks from part2/xor_attack.py, replayed against the new
 * AES-256-GCM helpers in vulnerabilities/cryptography/source/secure_crypto.php.
 * Run:  php part2/gcm_attack_tests.php      (exit code 0 = every attack failed, as intended)
 */
require __DIR__ . '/../vulnerabilities/cryptography/source/secure_crypto.php';

$ok = 0; $bad = 0;
function result(string $name, bool $defended): void {
    global $ok, $bad; $defended ? $ok++ : $bad++;
    echo ($defended ? "DEFENDED  " : "VULNERABLE  ") . $name . "\n";
}
$KEY = random_bytes(32);                       // the server's key; the attacker never sees it
$oracle = fn(string $m) => base64_decode(sc_encrypt($m, $KEY));   // the Encode box
$ct_of = fn(string $raw) => substr($raw, 13, -16);                // ciphertext bytes only
$xor = fn(string $a, string $b) => $a ^ $b;
$secret = "Your new password is: Olifant";
$intercepted = sc_encrypt($secret, $KEY);

// [1] key from source: the old hardcoded key and any guessable key must not decrypt
$old = "wachtwoord";
result("[1] old source key 'wachtwoord' rejected by sc_decrypt (key length check)", sc_decrypt($intercepted, $old) === false);
result("[1] key now loaded from env, not source: no 'wachtwoord' in low.php",
       strpos(file_get_contents(__DIR__ . '/../vulnerabilities/cryptography/source/low.php'), 'wachtwoord') === false);

// [2] chosen-plaintext oracle: XOR(oracle output, chosen text) must NOT give a reusable keystream
$chosen = str_repeat("A", 30);
$ks1 = $xor($ct_of($oracle($chosen)), $chosen);
$ks2 = $xor($ct_of($oracle($chosen)), $chosen);
result("[2] oracle keystream differs between two requests (fresh nonce)", $ks1 !== $ks2);
$guess = $xor($ct_of(base64_decode($intercepted)), substr($ks1, 0, strlen($secret)) . str_repeat("\0", 99));
result("[2] recovered 'keystream' does not decrypt the intercepted message", strpos($guess, "Olifant") === false);

// [3] two-time pad: c1 XOR c2 must NOT equal p1 XOR p2
$p1 = "Meet me at the library at 9"; $p2 = "Password for the lab is: 1234";
$c1 = $ct_of($oracle($p1)); $c2 = $ct_of($oracle($p2));
$n = min(strlen($p1), strlen($p2));
result("[3] c1^c2 != p1^p2 (key stream not reused)", substr($c1 ^ $c2, 0, $n) !== substr($p1 ^ $p2, 0, $n));

// [4] malleability: flip ciphertext bits to turn "Olifant" into "Hackers" (the old attack), must be rejected
$raw = base64_decode($intercepted); $pos = 13 + strpos($secret, "Olifant");
for ($i = 0; $i < 7; $i++) { $raw[$pos + $i] = $raw[$pos + $i] ^ chr(ord("Olifant"[$i]) ^ ord("Hackers"[$i])); }
result("[4] Olifant->Hackers bit-flip rejected (tag check fails, no plaintext)", sc_decrypt(base64_encode($raw), $KEY) === false);

echo "\n$ok attacks defended, $bad succeeded\n";
exit($bad === 0 ? 0 : 1);
