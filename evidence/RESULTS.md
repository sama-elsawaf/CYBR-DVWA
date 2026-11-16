# Milestone 2 – test results (CYBR 470, Track 1)

Branch `milestone2-impl`. Every result below comes from a real run; the raw output is in the named file.
Failed runs are kept next to the reruns (`*_FAIL*.txt`).

## Where and how the tests ran (read this first)

- **Host:** these runs were made in a Linux cloud container (Docker Engine 29.9.2, Compose v5.6.1, 4 vCPU Xeon 2.1 GHz),
  **not** on your Windows Docker Desktop. On Windows, use the same commands; for C1, capture on Wireshark's
  *Adapter for loopback traffic capture* (Npcap) instead of `lo`.
- **DVWA image:** the repo `Dockerfile` (php:8-apache + Debian apt) could not build there. deb.debian.org and ghcr.io blob downloads
  were blocked by the network policy, and Docker Hub sometimes answered 429. So the evidence uses
  `evidence/sandbox/Dockerfile.sandbox`: Ubuntu 24.04, Apache 2.4.58, PHP 8.3.6, OpenSSL 3.0.13, with mysqli/gd.
  It runs with `docker compose -f compose.yml -f evidence/sandbox/compose.sandbox.yml up -d`. The override only swaps the
  dvwa image and mounts `99-sandbox.ini` (sessions in /tmp, as in php:8-apache). **`compose.yml`, the app code and all
  settings under test are the committed ones.** The proxy is the real `nginx:1.28-alpine` (1.28.3, OpenSSL 3.5.5) and the DB is `mariadb:10`.
- The application code is identical. Exact timings (F1) will differ on your machine.

## Summary

| ID | Result | One line |
|---|---|---|
| UNIT | PASS | `test_secure_crypto.php` 25/25, `test_password_hashing.php` 14/14, run in the dvwa container against the deployed modules |
| A1 | PASS | `gcm_attack_tests.php` 6/6 defended. Web form: all 4 XOR attacks fail against AES-256-GCM (7/7 checks) |
| B1 | PASS | `VARCHAR(255)`. Five legacy MD5 rows become `$argon2id$v=19$m=19456,t=2,p=1$…` after one login each; admin ≠ smithy |
| C1 | PASS | Loopback capture: TLS 1.3, TLS_AES_256_GCM_SHA384, x25519, 0 frames containing credentials. `-tls1_2` (and 1.1/1.0) refused with alert 70 |
| C2 | PASS | `http://127.0.0.1` → `301 https://127.0.0.1/`. HTTPS responses carry `Strict-Transport-Security: max-age=31536000; includeSubDomains` |
| D1 | PASS after fix | No old literals in config, image history, `compose config` or `inspect`. **Found and fixed a real leak:** `secrets/*.txt` and `certs/server.key` were downloadable from the web root |
| D2 | PASS | Missing key file: `compose up` fails (exit 1). Empty or 16-byte key: app refuses to encrypt with a generic message, and the security level is pinned to impossible |
| E1 | PASS | PHPSESSID and security are `Secure; HttpOnly; SameSite`. The session id changes at login, and the old id is dead |
| E2 | PASS | 8 hand-edited `security` values are all ignored (the level falls back to impossible and the server re-issues a signed cookie). Valid signed values still work |
| F1 | Measured | Encode: XOR 3.92 ms vs GCM 3.75 ms mean (no measurable difference end to end). Login: MD5 4.22 ms vs Argon2id 34.72 ms mean. Argon2id uses about 19 MiB per hash |

---

## UNIT – existing unit tests inside the container
- **Command:** `docker compose exec dvwa php tests/test_secure_crypto.php`, `docker compose exec dvwa php tests/test_password_hashing.php`
- **Expected:** all PASS, exit 0.
- **Actual:** **PASS.** 25 passed / 0 failed and 14 passed / 0 failed, exit 0 for both. They were rerun on the final state in `07_final_regression.txt`.
- **Note:** before this milestone, `tests/` held *copies* of the helpers, and the password one was a different (PDO) implementation from production.
  The tests now `require` the deployed files. New cases cover the key file only, the ignored env var, the empty and short key file, HKDF separation and the RFC 5869 KAT, `ph_check`, and the Argon2id parameters.
- **Evidence:** `UNIT_test_secure_crypto.txt`, `UNIT_test_password_hashing.txt`, `07_final_regression.txt`

## A1 – XOR attacks replayed against AES-256-GCM
- **Commands/steps:**
  1. `docker compose exec dvwa php part2/gcm_attack_tests.php`
  2. `python3 evidence/tools/a1_web_attacks.py` runs the four `xor_attack.py` ideas through the real Cryptography form (https, Low level, Encode/Decode).
  3. Browser run (Playwright Chromium): Encode, flip bits Olifant→Hackers, then Decode.
- **Expected:** every attack fails. Bit-flipped ciphertext is rejected with no plaintext.
- **Actual:** **PASS.**
  - PHP: 6 attacks defended, 0 succeeded, exit 0.
  - Web: [1] XOR with `wachtwoord` gives random bytes, and the old XOR "intercepted" message is rejected by Decode.
    [2] Two `Encode('A'*30)` keystreams differ, have no repeating period, and do not decrypt the secret.
    [3] `c1⊕c2 ≠ p1⊕p2`. [4] The bit-flipped ciphertext gets "Message rejected: it failed the authentication check." and no plaintext. The untouched ciphertext still decodes.
  - Before (contrast): `xor_attack.py` against the old cipher recovers the key, decrypts, shows `c1^c2 == p1^p2: True`, and the tamper is accepted.
- **Evidence:** `A1_gcm_attack_tests_php.txt`, `A1_web_form_attacks.txt`, `A1_before_xor_attack_py.txt`, `screenshots/A1_browser_encode.png`, `screenshots/A1_browser_bitflip_rejected.png`

## B1 – password storage
- **Steps:** `sh evidence/tools/b1_password_storage.sh "<compose cmd>"`:
  1. `DESCRIBE users password`
  2. Reset the DB via setup.php.
  3. Set all five rows to unsalted `MD5(...)`. The new seeding already writes Argon2id, so this simulates a legacy DB.
  4. Log in once as admin/password, gordonb/abc123, 1337/charley, pablo/letmein and smithy/password through https.
  5. `SELECT user, password FROM users;`
  6. Count Argon2id rows and compare admin vs smithy.
  7. Log in again.
- **Expected:** `varchar(255)`. All five rows `$argon2id$`. Same plaintext gives different hashes. Logins keep working.
- **Actual:** **PASS.** `password varchar(255)`. After setup all five rows are already Argon2id. After the MD5 simulation and one login each, all five are `$argon2id$v=19$m=19456,t=2,p=1$…` (`argon2id_rows=5 total_rows=5 max_len=97`). `admin_equals_smithy_same_plaintext = 0`. The second logins all succeed.
- **Evidence:** `B1_password_storage.txt`

## C1 – login traffic capture
- **Steps:**
  1. `tshark -i lo -f "tcp port 443 or tcp port 80" -w C1_lo_login_https.pcapng`, then log in admin/password through https://127.0.0.1.
  2. Decode the handshake and search the raw frames for `username=`, `password=`, `admin`, `PHPSESSID`, `POST /login.php` and `HTTP/1.1`.
  3. `openssl s_client -connect 127.0.0.1:443 -tls1_3` / `-tls1_2` / each cipher suite / groups / TLS 1.1 and 1.0 (forced with `SECLEVEL=0`).
  4. Browser (Chromium, lab CA trusted, certificate errors **not** ignored) security details.
- **Expected:** TLS 1.3 handshake and no readable credentials. `-tls1_3` OK, `-tls1_2` refused.
- **Actual:** **PASS.**
  - ServerHello: Supported Version TLS 1.3 (0x0304), Cipher Suite TLS_AES_256_GCM_SHA384 (0x1302), key share x25519. The client offered X25519MLKEM768 and x25519; the server picked x25519.
  - Frames containing any of the search strings: **0**.
  - s_client `-tls1_3`: `New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384`, `Server Temp Key: X25519`, `Peer signature type: ECDSA`, cert `CN=localhost` issued by `CYBR470 DVWA Lab CA`, ecdsa-with-SHA256, `Verification: OK`.
  - `-tls1_2`: `tlsv1 alert protocol version … alert number 70`, `Cipher is (NONE)`, exit 1. TLS 1.1 and 1.0 (forced): alert 70.
  - Each of the 3 allowed suites negotiates. TLS_AES_128_CCM_SHA256 is refused (alert 40). `-groups P-256` is refused (alert 40).
  - Chromium: TLS 1.3, X25519, AES_128_GCM (the client's choice among the allowed suites), no interstitial.
- **Honest limits:**
  - (a) TLS ends at nginx. The hop nginx→dvwa on the internal Docker bridge is plain HTTP, and the capture there shows the POST body (`C1_internal_hop_docker_bridge.txt`). It is host-internal with no published port, but it is not encrypted.
  - (b) A client that POSTs straight to `http://` sends the form in cleartext before it gets the 301 (`C1_http_post_before_redirect.txt`). HSTS prevents this after the first HTTPS visit to a *hostname*; browsers ignore HSTS for bare IPs.
- **Contrast (old):** your earlier HTTP capture on port 4280 showed the login POST (`username=admin&password=password`) and the session cookie in clear text. That capture was not redone here; port 4280 is now closed (`C2_redirect_hsts.txt`).
- **Evidence:** `C1_wireshark.txt`, `C1_lo_login_https.pcapng`, `C1_openssl_s_client.txt`, `E1_C1_browser_devtools.txt`, `screenshots/C1_browser_login_https.png`, `C1_internal_hop_docker_bridge.txt` (+ `.pcapng`), `C1_http_post_before_redirect.txt` (+ `.pcapng`). The pcaps contain only the public default lab credentials.

## C2 – redirect and HSTS
- **Commands:** `curl -k -I http://127.0.0.1`, `curl -k -I https://127.0.0.1`, plus `/login.php` and `https://localhost` variants, and `curl -I http://127.0.0.1:4280/`.
- **Expected:** 301 to https, HSTS on https, and 4280 closed.
- **Actual:** **PASS.** `HTTP/1.1 301 Moved Permanently` / `Location: https://127.0.0.1/` (path kept for `/login.php`). HTTPS responses show `Strict-Transport-Security: max-age=31536000; includeSubDomains`. Port 4280: connection refused (curl exit 7). Rechecked after the D1 fix in `07_final_regression.txt`.
- **Evidence:** `C2_redirect_hsts.txt`, `07_final_regression.txt`

## D1 – old secret literals and real leaks
- **Steps:**
  - `git grep` for `wachtwoord`, `p@ssw0rd` and `dvwa`-as-password patterns.
  - `docker compose config`, `docker inspect` (env of all containers), `docker history --no-trunc` of the 3 images: searched for the literals **and for the current secret values** (values not printed).
  - Web-root check: `curl https://localhost/secrets/...`.
  - Build-context check: a `FROM scratch` + `COPY . .` build with the repo's `.dockerignore` (`evidence/tools/d1_build_context_check.sh`).
- **Expected:** no config leaks. The remaining hits are only teaching or docs content.
- **Actual:** **PASS after fixing a real leak.**
  - Literals: `wachtwoord` appears only in the help page, the xor_theory demo, part2 attack tests and the unit-test XOR baseline (teaching/test). `p@ssw0rd` appears only in upstream README translations (manual-install docs) and one line of `docs/MILESTONE2_SETUP.md`. There are no `dvwa`-as-password hits; `MARIADB_DATABASE/USER=dvwa` are names. compose config, inspect and history have 0 hits for the literals and 0 for the current secret values; the env only holds `*_FILE` paths.
  - Git history still has the upstream defaults in old `compose.yml` commits. They are no longer used.
  - **Real leak (caused by step a, fixed):** DVWA bind-mounts the repo as its web root, so `/secrets/crypto_master_key.txt`, `/secrets/db_password.txt`, `/certs/server.key` and the `/secrets/` listing returned **200**. Also, `COPY . .` would have put `secrets/*.txt` and `certs/*.key` into an image layer.
  - Fix (commit "D1 fix"): tmpfs over `/var/www/html/{secrets,certs}`, an nginx 404 rule, and `.dockerignore` entries. After the fix everything returns 404, both through the proxy and directly against Apache, and the build context has only the `.example` files. The master key, both DB passwords and the server key were **rotated**.
- **Evidence:** `D1_literal_sweep.txt`, `D1_webroot_leak_before_fix.txt`, `D1_webroot_leak_after_fix.txt`, `D1_build_context_before_fix.txt`, `D1_build_context_after_fix.txt`

## D2 – master key missing / empty / wrong length
- **Steps:**
  - Remove `secrets/crypto_master_key.txt`: run `up -d --force-recreate dvwa`, then a clean `down` + `up -d`.
  - Empty file, then 16-byte key: recreate, then log in, try Low, Encode/Decode, read the server log, and POST to `low.php` directly.
  - Restore the key and run the smoke test.
- **Expected:** compose fails, or the app refuses to encrypt.
- **Actual:** **PASS.**
  - Missing: `Error response from daemon: invalid mount config for type "bind": bind source path does not exist: …/secrets/crypto_master_key.txt`, exit 1. On a clean start dvwa is never created and https gives no answer (000). Note: on `--force-recreate` the *previous* container kept running with the old key.
  - Empty / 16 bytes: the stack starts, `sc_load_key()` and `sc_cookie_key()` return `false`, and the log says `master key file must contain base64 of exactly 32 bytes`. `low.php` shows "The encryption service is not available. Please contact the administrator." with `encoded=NULL`. The security level stays `impossible` because no cookie can be signed. Login still works.
  - Restored: SMOKE PASS.
- **Evidence:** `D2_missing_master_key.txt`

## E1 – cookie flags and session id rotation
- **Steps:** `bash evidence/tools/e1_cookies.sh` (curl `-i -c jar -b jar` against https://localhost: GET login, POST login, old id, new id). Browser: Chromium DevTools-protocol `Network.getAllCookies` and `document.cookie`.
- **Expected:** Secure, HttpOnly and SameSite on PHPSESSID and security. The id changes at login.
- **Actual:** **PASS.**
  - `Set-Cookie: PHPSESSID=…; path=/; secure; HttpOnly; SameSite=Strict` and `security=impossible.<mac>; path=/; secure; HttpOnly; SameSite=Strict`.
  - PHPSESSID `bfa67c1b…` → `47ffb9f6…` at login. The old id is redirected to login.php; the new id gets 200 and Logout.
  - Browser: both cookies `Secure=true HttpOnly=true`, `document.cookie = ""`, and PHPSESSID changed at login. At Low level PHPSESSID is `SameSite=Lax` (Strict at impossible); the security cookie is always Strict.
  - The first script run failed because of a test-script bug (glob-expanded `--noproxy *`, so the request went to the sandbox's outbound proxy and got 403). It was fixed and rerun.
- **Evidence:** `E1_set_cookie_curl.txt`, `E1_C1_browser_devtools.txt`, `screenshots/E1_browser_logged_in.png`, `E1_run1_FAIL_script_bug.txt`

## E2 – hand-edited security cookie
- **Steps:** `python3 evidence/tools/e2_security_cookie.py`. A fresh login is made at *medium* for each case, then `curl -i --cookie 'PHPSESSID=…; security=<value>' https://localhost/vulnerabilities/brute/`.
- **Expected:** edited values are rejected or ignored and fall back to the safe level.
- **Actual:** **PASS (10/10).**
  - The signed `low` and `medium` controls are accepted.
  - Ignored, with the page at `impossible` and a re-issued `Set-Cookie: security=impossible.<mac>`: `low`, `impossible`, `medium` (plain), `low.`+MAC(impossible), one MAC character changed, a random MAC, an empty MAC, and `admin.`+MAC. The server log records `dvwa: rejected security cookie with invalid HMAC`.
  - The first run showed 7 FAILs because of the test design: a rejected cookie also rotates the session id (`session_regenerate_id(true)`), and the test reused the old id. It was fixed with a fresh login per case.
- **Evidence:** `E2_security_cookie_tamper.txt`, `E2_run1_FAIL_reused_session.txt`

## F1 – latency and overhead
- **Steps:** `python3 evidence/tools/f1_latency.py`, 200 sequential requests per row.
  - OLD = the original upstream commit `a1978a2` (XOR `low.php`, MD5 login) in a throwaway container with its own MariaDB on :4281.
  - NEW direct = the same new code and DB in a throwaway container on :4282 over plain HTTP. `FORCE_SECURE_COOKIES` is off there, otherwise the Secure cookies are correctly not sent over http (`F1_run1_FAIL_secure_cookies_over_http.txt`).
  - NEW TLS = the real stack through nginx.
  - Plus `php evidence/tools/f1_micro.php` in the container (primitives only, plus peak RSS).

| Path (200 requests) | mean ms | median ms | p95 ms |
|---|---:|---:|---:|
| Encode, OLD XOR (direct HTTP) | 3.92 | 3.87 | 4.48 |
| Encode, NEW AES-256-GCM (direct HTTP) | 3.75 | 3.64 | 4.54 |
| Encode, NEW AES-256-GCM via TLS 1.3 proxy | 4.20 | 4.15 | 5.20 |
| Login POST, OLD MD5 (direct HTTP) | 4.22 | 4.12 | 5.30 |
| Login POST, NEW Argon2id (direct HTTP) | 34.72 | 33.37 | 43.31 |
| Login POST, NEW Argon2id via TLS 1.3 proxy | 35.87 | 35.73 | 43.20 |

| Primitive (in container) | mean µs | p95 µs |
|---|---:|---:|
| XOR encode + base64 (old) | 2.54 | 3.04 |
| AES-256-GCM `sc_encrypt` | 3.30 | 2.66 |
| AES-256-GCM `sc_decrypt` (incl. encrypt) | 5.04 | 6.02 |
| HKDF-SHA-256 one key | 4.42 | 4.98 |
| md5 compare (old login) | 0.38 | 0.39 |
| Argon2id `password_verify` | 23 830 | 31 682 |
| Argon2id `password_hash` | 23 884 | 28 586 |

- **Argon2id cost:** memory_cost 19456 KiB (19 MiB), time_cost 2, threads 1 (OWASP minimum). Measured peak RSS grew by **19 620 kB** during one hash (md5: +264 kB). About 24 ms per verify on this CPU.
- **Reading it honestly:**
  - The XOR vs GCM page comparison is **not apples-to-apples**: the NEW request also does the HMAC cookie check, two HKDF derivations and the session hardening, and runs different page code. What it shows is that the crypto cost (a few µs) is lost in the ~4 ms request time; the difference is inside the noise.
  - The `sc_encrypt` mean is above its p95 because a few slow outliers (first calls) pull the mean up.
  - The TLS proxy adds about 0.5 ms on a keep-alive connection; a new TLS handshake per request is not measured here.
  - The Argon2id login is about **8× slower per request (+30 ms)**. That cost is intended: it makes offline guessing about 60 000× more expensive per guess than MD5.
- **Evidence:** `F1_latency_http.txt`, `F1_micro_benchmark.txt`, `F1_run1_FAIL_secure_cookies_over_http.txt`

## Smoke checks after each build step
`00_baseline_smoke_before_changes.txt` (original state), `01_…step_a`, `02_…step_b`, `03a…FAIL` → `03b`/`03c` (step c, sandbox session-GC issue found and fixed), `05_…step_d`, `06_…D1_fix`, `07_final_regression.txt`.
Each confirms: setup works, admin/password logs in, and the Cryptography page encodes/decodes.

## Not working / open items
1. **Brute Force lab behaviour changed:** the password is now checked with Argon2id in PHP. Brute forcing still works (slower), and UNION-based SQLi still logs in at Low, but the `admin' -- ` comment-out bypass no longer does (`04_brute_lab_sqli_after_R2.txt`).
2. **Teaching-lab side effects of R9 (by design, documented in `docs/MILESTONE2_SETUP.md`):** the XSS cookie-theft demo cannot read PHPSESSID (HttpOnly), session fixation no longer works at low levels, cross-site POST CSRF is blocked by SameSite, and the security level can only be changed on the Security page.
3. **Internal hop is plain HTTP** (nginx→Apache on the Docker bridge). It is not reachable from outside.
4. `dvwaPage.inc.php` still makes the anti-CSRF token with `md5(uniqid())`. It is not a password, so it is outside R2, but it is predictable and should become `bin2hex(random_bytes(32))`.
5. `X-Powered-By: PHP/x.y` is still sent through the proxy (version disclosure). `proxy_hide_header X-Powered-By;` would remove it.
6. A fresh visit gets two `Set-Cookie: PHPSESSID` headers (start + regenerate). This is harmless; the browser keeps the last one.
7. Everything was verified on the Linux sandbox image, **not** on your Windows Docker Desktop with the `php:8-apache` image. Please run `docker compose up -d` there once and repeat the smoke check.
