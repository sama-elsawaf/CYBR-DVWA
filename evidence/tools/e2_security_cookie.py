#!/usr/bin/env python3
"""E2: hand-edited `security` cookies are rejected. Uses curl --cookie for the tampered requests."""
import os, re, subprocess, sys
sys.path.insert(0, __file__.rsplit('/', 1)[0])
from dvwa_client import DVWA
B = "https://localhost"
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))   # repo root, for certs/lab-ca.crt
# Windows curl (Schannel) fails the revocation check for the lab CA unless --ssl-no-revoke (cert is still verified)
CURL_TLS = ["--cacert", "certs/lab-ca.crt"] + (["--ssl-no-revoke"] if "schannel" in subprocess.run(
    ["curl", "--version"], capture_output=True, text=True).stdout.lower() else [])
d = DVWA(B, "certs/lab-ca.crt"); assert d.login("admin", "password")[0]
d.set_security("low")
if not re.fullmatch(r"low\.[A-Za-z0-9_-]{43}", d.s.cookies.get("security") or ""):
    raise SystemExit(f"STOP: security cookie is {d.s.cookies.get('security')!r}, not signed. The master key is missing "
                     "or invalid (app is fail-closed), so E2 cannot be tested. Restore secrets/crypto_master_key.txt first.")
sid = d.s.cookies.get("PHPSESSID"); good_low = d.s.cookies.get("security")
d.set_security("impossible"); good_imp = d.s.cookies.get("security")
d.set_security("medium"); sid = d.s.cookies.get("PHPSESSID"); good_med = d.s.cookies.get("security")
print(f"Valid cookies issued by security.php:\n  low        = {good_low}\n  impossible = {good_imp}\n  medium     = {good_med}\n")
mac_imp = good_imp.split(".")[1]
cases = [
    ("valid signed low (control)", good_low),
    ("valid signed medium (control)", good_med),
    ("plain 'low' (old DVWA format)", "low"),
    ("plain 'impossible'", "impossible"),
    ("plain 'medium'", "medium"),
    ("level changed, MAC kept: 'low.' + MAC(impossible)", "low." + mac_imp),
    ("one MAC char changed", good_low[:-1] + ("A" if good_low[-1] != "A" else "B")),
    ("random MAC", "low.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    ("empty MAC 'low.'", "low."),
    ("unknown level 'admin.' + MAC", "admin." + mac_imp),
]
ok_all = True
for name, val in cases:
    # fresh login per case: a rejected cookie also rotates the session id (old session deleted)
    d = DVWA(B, "certs/lab-ca.crt"); d.login("admin", "password"); d.set_security("medium")
    sid = d.s.cookies.get("PHPSESSID")
    cmd = ["curl", "-sS", "-i", "--noproxy", "localhost,127.0.0.1", *CURL_TLS,
           "--cookie", f"PHPSESSID={sid}; security={val}", f"{B}/vulnerabilities/brute/"]
    cp = subprocess.run(cmd, capture_output=True, text=True); out = cp.stdout
    if cp.returncode != 0 or not out:
        raise SystemExit(f"curl failed (exit {cp.returncode}): {cp.stderr.strip()}\n  command: {' '.join(cmd)}")
    level = re.findall(r"<em>Security Level:</em> (\w+)", out)
    reset = re.findall(r"(?im)^set-cookie: (security=[^;]*)", out)
    expected = val.split(".")[0] if val in (good_low, good_med) else "impossible"
    ok = level == [expected]; ok_all &= ok
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
    print(f"      $ curl -i --cookie 'PHPSESSID=<sid>; security={val}' {B}/vulnerabilities/brute/")
    print(f"      (session's real level before the request: medium)")
    print(f"      page shows Security Level: {level[0] if level else '?'} (expected {expected}); "
          f"server Set-Cookie: {reset[0] if reset else '(none)'}")
print("\nALL PASS" if ok_all else "\nSOME FAILED"); sys.exit(0 if ok_all else 1)
