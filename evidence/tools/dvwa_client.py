#!/usr/bin/env python3
"""
Small DVWA client used to produce the Milestone 2 evidence through the REAL web forms.

  python3 evidence/tools/dvwa_client.py --base https://127.0.0.1 --cafile certs/lab-ca.crt smoke
  python3 evidence/tools/dvwa_client.py --base https://127.0.0.1 --cafile certs/lab-ca.crt reset

Every request goes through the normal pages (setup.php, login.php, security.php,
vulnerabilities/cryptography/), including the anti-CSRF user_token.
"""
import argparse
import re
import sys

import requests

requests.packages.urllib3.disable_warnings()  # only used when --insecure is given


class DVWA:
    def __init__(self, base, verify=True):
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.s.trust_env = False          # never send lab traffic through an outside proxy
        self.s.verify = verify

    def url(self, path):
        return f"{self.base}/{path.lstrip('/')}"

    def token(self, html):
        m = re.search(r"name='user_token' value='([0-9a-f]+)'", html)
        return m.group(1) if m else ""

    def reset_db(self):
        r = self.s.get(self.url("setup.php"))
        r = self.s.post(self.url("setup.php"),
                        data={"create_db": "Create / Reset Database", "user_token": self.token(r.text)})
        return "Setup successful" in r.text or "Database has been created" in r.text, r

    def login(self, user, password):
        r = self.s.get(self.url("login.php"))
        r = self.s.post(self.url("login.php"),
                        data={"username": user, "password": password, "Login": "Login",
                              "user_token": self.token(r.text)})
        return ("Logout" in r.text and "Login failed" not in r.text), r

    def set_security(self, level):
        r = self.s.get(self.url("security.php"))
        r = self.s.post(self.url("security.php"),
                        data={"security": level, "seclev_submit": "Submit", "user_token": self.token(r.text)})
        return r

    def crypto(self, message, direction="encode"):
        r = self.s.post(self.url("vulnerabilities/cryptography/"),
                        data={"message": message, "direction": direction})
        out = re.findall(r"id='encoded' name='encoded'>([^<]*)</textarea>", r.text)
        warn = re.findall(r'<div class="warning">(.*?)</div>', r.text, re.S)
        # The first 'encoded' textarea is the result box (when present); the last is the fixed "intercepted" one.
        result = out[0] if len(out) == 2 else None
        return result, (warn[0] if warn else None), r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="https://127.0.0.1")
    ap.add_argument("--cafile")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("cmd", choices=["smoke", "reset"])
    a = ap.parse_args()
    verify = False if a.insecure else (a.cafile or True)
    d = DVWA(a.base, verify)
    ok, _ = d.reset_db()
    print(f"setup.php reset: {'OK' if ok else 'FAILED'}")
    if a.cmd == "reset":
        return 0 if ok else 1
    ok, r = d.login("admin", "password")
    print(f"login admin/password: {'OK' if ok else 'FAILED'} (final URL {r.url})")
    d.set_security("low")
    ct, warn, r = d.crypto("hello milestone 2")
    print(f"crypto encode (low): {ct!r} warn={warn!r} HTTP {r.status_code}")
    if ct:
        pt, warn, _ = d.crypto(ct, "decode")
        print(f"crypto decode (low): {pt!r} warn={warn!r}")
        ok = ok and pt == "hello milestone 2"
    else:
        ok = False
    print("SMOKE", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
