<?php
/**
 * password_hashing.php  -  R2: replace DVWA's unsalted md5() with Argon2id + upgrade-on-login.
 *
 * Why: md5() is fast and unsalted, so a stolen `users` table can be cracked at billions of guesses
 * per second, and identical passwords show identical hashes (admin and smithy both use "password").
 * Argon2id is salted (automatic, 16 random bytes) and memory-hard, which makes every guess expensive.
 *
 * Parameters follow the OWASP Password Storage Cheat Sheet minimum for Argon2id
 * (19 MiB memory, 2 iterations, 1 thread).
 *
 * Works with both database handles used in DVWA: mysqli ($GLOBALS["___mysqli_ston"]) and PDO ($db).
 * The `users.password` column is VARCHAR(255) (an Argon2id hash is ~97 characters).
 */
const PH_OPTIONS = ['memory_cost' => 19456, 'time_cost' => 2, 'threads' => 1];

function ph_hash(string $plain): string {
    return password_hash($plain, PASSWORD_ARGON2ID, PH_OPTIONS);
}

/** Pure check of one password against one stored value (Argon2id, or a legacy 32-hex MD5 row). */
function ph_check(string $plain, string $stored): bool {
    if (str_starts_with($stored, '$argon2id$')) {
        return password_verify($plain, $stored);
    }
    if (strlen($stored) === 32 && ctype_xdigit($stored)) {
        return hash_equals(strtolower($stored), md5($plain));
    }
    return false;
}

/** [user_id, stored_hash] for a user name, or null. Prepared statement for both drivers. */
function ph_fetch($db, string $user): ?array {
    if ($db instanceof PDO) {
        $st = $db->prepare('SELECT user_id, password FROM users WHERE user = ? LIMIT 1');
        $st->execute([$user]);
        $row = $st->fetch(PDO::FETCH_NUM);
        return $row ? [(int) $row[0], (string) $row[1]] : null;
    }
    $st = mysqli_prepare($db, 'SELECT user_id, password FROM users WHERE user = ? LIMIT 1');
    mysqli_stmt_bind_param($st, 's', $user);
    mysqli_stmt_execute($st);
    mysqli_stmt_bind_result($st, $uid, $stored);
    $found = mysqli_stmt_fetch($st);
    mysqli_stmt_close($st);
    return $found ? [(int) $uid, (string) $stored] : null;
}

/** Store a fresh Argon2id hash of $plain for a user id. */
function ph_store($db, int $uid, string $plain): void {
    $new = ph_hash($plain);
    if ($db instanceof PDO) {
        $db->prepare('UPDATE users SET password = ? WHERE user_id = ?')->execute([$new, $uid]);
        return;
    }
    $up = mysqli_prepare($db, 'UPDATE users SET password = ? WHERE user_id = ?');
    mysqli_stmt_bind_param($up, 'si', $new, $uid);
    mysqli_stmt_execute($up);
    mysqli_stmt_close($up);
}

/**
 * Check a password. Returns true if valid.
 * Old rows still holding an MD5 hash are accepted once, then silently upgraded to Argon2id.
 */
function ph_verify_and_upgrade($db, string $user, string $plain): bool {
    $row = ph_fetch($db, $user);
    if ($row === null) {
        password_verify($plain, ph_hash('dummy'));   // spend similar time so unknown users are not revealed
        return false;
    }
    [$uid, $stored] = $row;
    $ok = ph_check($plain, $stored);
    // Upgrade legacy MD5 rows, and Argon2id rows made with weaker parameters, on successful login.
    if ($ok && (!str_starts_with($stored, '$argon2id$')
                || password_needs_rehash($stored, PASSWORD_ARGON2ID, PH_OPTIONS))) {
        ph_store($db, $uid, $plain);
    }
    return $ok;
}
