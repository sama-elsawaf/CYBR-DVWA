<?php
/**
 * secure_crypto.php  -  AES-256-GCM helpers to replace the repeating-key XOR in DVWA.
 *
 * Output format (then base64):   version(1) | nonce(12) | ciphertext | tag(16)
 *
 * Design choices (explain these in the report):
 *  - AES-256-GCM  : authenticated encryption = confidentiality + integrity in one step (NIST SP 800-38D).
 *  - random nonce : a fresh 12-byte value from the OS CSPRNG for EVERY message. Reusing a nonce with the
 *                   same key breaks GCM, so the nonce is never chosen by the caller.
 *  - key handling : the key is NOT in the source code or in the environment. A 32-byte master secret
 *                   is read from a Docker secret file (CRYPTO_KEY_FILE) and HKDF-SHA-256 derives
 *                   separate keys: K_msg (this file) and K_cookie (security cookie HMAC).
 *  - AAD          : optional "associated data" (e.g. the user id) is authenticated but not encrypted,
 *                   so a ciphertext cannot be moved to another context.
 *  - fail closed  : any problem returns false. No partial plaintext is ever returned.
 */

const SC_CIPHER    = 'aes-256-gcm';
const SC_VERSION   = "\x01";
const SC_NONCE_LEN = 12;
const SC_TAG_LEN   = 16;
const SC_KEY_LEN   = 32;

/**
 * Read the 32-byte MASTER secret from the Docker secret file named by CRYPTO_KEY_FILE
 * (e.g. /run/secrets/crypto_master_key, content = base64 of 32 random bytes).
 * There is deliberately NO fallback: no environment variable, no default key.
 * Returns the raw 32 bytes, or false (fail closed). The reason goes to the server log only.
 */
function sc_load_master() {
    $file = getenv('CRYPTO_KEY_FILE');
    if (!$file || !is_file($file) || !is_readable($file)) {
        error_log('secure_crypto: CRYPTO_KEY_FILE is not set or not readable');
        return false;
    }
    $key = base64_decode(trim((string) file_get_contents($file)), true);
    if ($key === false || strlen($key) !== SC_KEY_LEN) {
        error_log('secure_crypto: master key file must contain base64 of exactly 32 bytes');
        return false;
    }
    return $key;
}

/**
 * HKDF-SHA-256 (RFC 5869) key separation: one master secret -> independent keys per purpose,
 * so the message key and the cookie MAC key are never the same bytes.
 */
const SC_INFO_MSG    = 'CYBR-DVWA v1 | K_msg | AES-256-GCM message encryption';
const SC_INFO_COOKIE = 'CYBR-DVWA v1 | K_cookie | HMAC-SHA-256 security cookie';

function sc_derive(string $master, string $info): string {
    return hash_hkdf('sha256', $master, SC_KEY_LEN, $info);
}

/** K_msg: key for sc_encrypt / sc_decrypt. Returns false if the master secret is unavailable. */
function sc_load_key() {
    $m = sc_load_master();
    return $m === false ? false : sc_derive($m, SC_INFO_MSG);
}

/** K_cookie: key for the security-cookie HMAC. Returns false if the master secret is unavailable. */
function sc_cookie_key() {
    $m = sc_load_master();
    return $m === false ? false : sc_derive($m, SC_INFO_COOKIE);
}

/** Encrypt. Returns base64 string, or false on error. */
function sc_encrypt(string $plaintext, string $key, string $aad = '') {
    if (strlen($key) !== SC_KEY_LEN) {
        return false;
    }
    $nonce = random_bytes(SC_NONCE_LEN);          // fresh random nonce every time
    $tag   = '';
    $ct = openssl_encrypt($plaintext, SC_CIPHER, $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, SC_TAG_LEN);
    if ($ct === false) {
        return false;
    }
    return base64_encode(SC_VERSION . $nonce . $ct . $tag);
}

/** Decrypt. Returns plaintext, or false if the message is malformed or fails authentication. */
function sc_decrypt(string $b64, string $key, string $aad = '') {
    if (strlen($key) !== SC_KEY_LEN) {
        return false;
    }
    $raw = base64_decode($b64, true);
    if ($raw === false || strlen($raw) < 1 + SC_NONCE_LEN + SC_TAG_LEN || $raw[0] !== SC_VERSION) {
        return false;
    }
    $nonce = substr($raw, 1, SC_NONCE_LEN);
    $tag   = substr($raw, -SC_TAG_LEN);
    $ct    = substr($raw, 1 + SC_NONCE_LEN, -SC_TAG_LEN);
    // openssl_decrypt checks the tag BEFORE returning anything; on mismatch it returns false.
    return openssl_decrypt($ct, SC_CIPHER, $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
}
