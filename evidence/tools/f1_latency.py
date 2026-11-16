#!/usr/bin/env python3
"""
F1: latency of the OLD (original DVWA commit a1978a2: XOR + MD5) vs NEW (AES-256-GCM + Argon2id) code paths.
Both apps run in the SAME sandbox image (Apache + PHP 8.3) on the same host, each with its own MariaDB.
"direct" = plain HTTP straight to the container's Apache (no TLS), so the only difference is the PHP code.
"""
import re, statistics, subprocess, sys, time
sys.path.insert(0, __file__.rsplit('/', 1)[0])
from dvwa_client import DVWA
N = 200
OLD = "http://127.0.0.1:4281"
# Throwaway container 'f1new-dvwa': the SAME new code, secrets and DB as the compose stack, published on :4282
# over plain HTTP and without FORCE_SECURE_COOKIES (otherwise its cookies are Secure and a client correctly
# refuses to send them over http). Only for this measurement.
NEW_DIRECT = "http://127.0.0.1:4282"
NEW_TLS = "https://localhost"

def stats(xs):
    xs = sorted(x * 1000 for x in xs)
    p95 = xs[int(round(0.95 * len(xs))) - 1]
    return statistics.mean(xs), statistics.median(xs), p95, xs[0], xs[-1]

def session(base, verify=True):
    d = DVWA(base, verify)
    if not d.login("admin", "password")[0]: raise SystemExit(f"login failed on {base}")
    d.set_security("low")
    return d

def bench_encode(d, label):
    msg = "Your new password is: Olifant"
    d.s.post(d.url("vulnerabilities/cryptography/"), data={"message": msg, "direction": "encode"})  # warm-up
    t = []
    for _ in range(N):
        t0 = time.perf_counter()
        r = d.s.post(d.url("vulnerabilities/cryptography/"), data={"message": msg, "direction": "encode"})
        t.append(time.perf_counter() - t0)
        assert r.status_code == 200 and "Security Level:</em> low" in r.text, label
    return t

def bench_login(base, verify=True):
    t = []
    for _ in range(N):
        d = DVWA(base, verify)
        tok = d.token(d.s.get(d.url("login.php")).text)
        t0 = time.perf_counter()
        r = d.s.post(d.url("login.php"), data={"username": "admin", "password": "password", "Login": "Login", "user_token": tok}, allow_redirects=False)
        t.append(time.perf_counter() - t0)
        assert r.headers.get("Location") == "index.php", (base, r.status_code)
    return t

rows = []
def row(name, xs): m, med, p95, lo, hi = stats(xs); rows.append((name, m, med, p95, lo, hi)); print(f"done: {name}", flush=True)

row("Encode, OLD XOR low.php (direct HTTP)", bench_encode(session(OLD), "old"))
row("Encode, NEW AES-256-GCM low.php (direct HTTP)", bench_encode(session(NEW_DIRECT), "new"))
row("Encode, NEW AES-256-GCM via TLS 1.3 proxy (end to end)", bench_encode(session(NEW_TLS, "certs/lab-ca.crt"), "tls"))
row("Login POST, OLD MD5 (direct HTTP)", bench_login(OLD))
row("Login POST, NEW Argon2id (direct HTTP)", bench_login(NEW_DIRECT))
row("Login POST, NEW Argon2id via TLS 1.3 proxy", bench_login(NEW_TLS, "certs/lab-ca.crt"))

print(f"\n### F1 results: {N} sequential requests per row (client: python requests, keep-alive session; time = full request/response)")
print(f"| Path | mean ms | median ms | p95 ms | min ms | max ms |\n|---|---:|---:|---:|---:|---:|")
for r in rows: print(f"| {r[0]} | {r[1]:.2f} | {r[2]:.2f} | {r[3]:.2f} | {r[4]:.2f} | {r[5]:.2f} |")
