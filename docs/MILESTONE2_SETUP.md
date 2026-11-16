# Milestone 2 – running the hardened DVWA (CYBR 470, Track 1)

## 1. One-time setup

Run these from the repository root (Git Bash or WSL on Windows; PowerShell alternative shown for secrets).

```bash
sh scripts/gen_secrets.sh
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts\gen_secrets.ps1
```

```bash
sh scripts/gen_lab_certs.sh
```

This creates (all gitignored, never committed):

| File | What it is |
|---|---|
| `secrets/crypto_master_key.txt` | base64 of 32 random bytes; HKDF-SHA-256 derives `K_msg` (AES-256-GCM) and `K_cookie` (HMAC) from it |
| `secrets/db_password.txt` | MariaDB password of the `dvwa` user |
| `secrets/db_root_password.txt` | MariaDB root password |
| `certs/lab-ca.crt` / `lab-ca.key` | the local lab CA (ECDSA P-256). Only the `.crt` is ever shared; the key is never mounted |
| `certs/server.crt` / `server.key` | ECDSA P-256 server certificate for `localhost`, `dvwa.lab`, `127.0.0.1` |

If you had the old stack running, the database volume still has the old password (`p@ssw0rd`), so recreate it once:

```bash
docker compose down -v
```

```bash
docker compose up -d
```

Open **https://localhost/** (or https://127.0.0.1/), click *Create / Reset Database*, log in with `admin` / `password`.
Only ports 443 and 80 (redirect) are published, both on 127.0.0.1. DVWA's own port 4280 is no longer published.

> `compose.yml` still says `pull_policy: always` (upstream image). The application code comes from the
> `./` bind mount either way. To build from the local Dockerfile change it to `pull_policy: build`.

## 2. Trust the lab CA in the browser

The server certificate is signed by your own lab CA, so the browser shows a warning until you trust `certs/lab-ca.crt`.

**Windows (Chrome / Edge use the Windows store):**
1. Double-click `certs\lab-ca.crt` → *Install Certificate…*
2. *Current User* → *Place all certificates in the following store* → *Browse* → **Trusted Root Certification Authorities** → Finish → accept the security warning.
3. Restart the browser and open https://localhost/ – the padlock shows "Connection is secure", issued by *CYBR470 DVWA Lab CA*.

PowerShell alternative:

```powershell
Import-Certificate -FilePath certs\lab-ca.crt -CertStoreLocation Cert:\CurrentUser\Root
```

**Firefox (own store):** Settings → Privacy & Security → Certificates → *View Certificates* → *Authorities* → *Import…* → `lab-ca.crt` → tick *Trust this CA to identify websites*.

**Remove it after the course:** `certmgr.msc` → Trusted Root Certification Authorities → Certificates → delete *CYBR470 DVWA Lab CA* (Firefox: Authorities tab → Delete).

Because the CA private key stays on your machine, trusting it only affects certificates *you* issue. Still, remove it when you are done.

**HSTS note:** browsers ignore `Strict-Transport-Security` on bare IP addresses. Use `https://localhost/` to see HSTS take effect (DevTools → Network → response headers).

## 3. TLS settings (proxy/nginx.conf)

- TLS 1.3 only (`ssl_protocols TLSv1.3`); TLS 1.2 and below are refused.
- Cipher suites: `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`.
- Key exchange group: X25519. Certificate: ECDSA P-256 (SHA-256 signature) from the lab CA.
- HTTP → HTTPS `301`, `Strict-Transport-Security: max-age=31536000; includeSubDomains`.

## 4. Behaviour changes in the teaching labs (trade-offs)

| Change | Effect on labs |
|---|---|
| Session cookie is `HttpOnly` at every level | XSS labs can still run script, but `document.cookie` no longer shows `PHPSESSID` (cookie theft demo does not work) |
| Session id regenerated at login at every level | Session fixation no longer works at low/medium/high |
| `SameSite=Lax` (Strict at impossible) | Cross-site POST CSRF is blocked by the browser; the GET-based CSRF lab still works from a top-level link |
| Brute Force lab checks the password with Argon2id in PHP | Brute forcing still works but is slower; the `admin' -- ` comment-out bypass no longer logs in (UNION-based injection still works at low) |
| `security` cookie is HMAC-signed | Changing the level by editing the cookie no longer works; use the DVWA Security page |
