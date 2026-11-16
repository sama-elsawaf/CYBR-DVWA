#!/usr/bin/env python3
"""Step (c) functional check: labs that used md5() for passwords still work with Argon2id."""
import re, sys
sys.path.insert(0, __file__.rsplit('/', 1)[0])
from dvwa_client import DVWA

base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:4280"
verify = sys.argv[2] if len(sys.argv) > 2 else True
d = DVWA(base, verify); ok_all = True
def chk(name, ok):
    global ok_all; ok_all &= bool(ok); print(("PASS  " if ok else "FAIL  ") + name)

chk("setup.php reset", d.reset_db()[0])
chk("login admin/password (seeded Argon2id)", d.login("admin", "password")[0])
for lvl in ["low", "medium", "high", "impossible"]:
    d.set_security(lvl)
    if lvl == "impossible":
        r = d.s.get(d.url("vulnerabilities/brute/")); tok = d.token(r.text)
        r = d.s.post(d.url("vulnerabilities/brute/"), data={"username": "gordonb", "password": "abc123", "Login": "Login", "user_token": tok})
    else:
        tok = d.token(d.s.get(d.url("vulnerabilities/brute/")).text)
        r = d.s.get(d.url("vulnerabilities/brute/"), params={"username": "gordonb", "password": "abc123", "Login": "Login", "user_token": tok})
    chk(f"brute [{lvl}] correct password accepted", "Welcome to the password protected area" in r.text)
    tok = d.token(r.text)
    if lvl == "impossible":
        r = d.s.post(d.url("vulnerabilities/brute/"), data={"username": "gordonb", "password": "wrong", "Login": "Login", "user_token": tok})
    else:
        r = d.s.get(d.url("vulnerabilities/brute/"), params={"username": "gordonb", "password": "wrong", "Login": "Login", "user_token": tok})
    chk(f"brute [{lvl}] wrong password rejected", "Username and/or password incorrect" in r.text)

d.set_security("low")
r = d.s.get(d.url("vulnerabilities/csrf/"), params={"password_new": "N3w-pass'!", "password_conf": "N3w-pass'!", "Change": "Change"})
chk("csrf [low] password change accepted", "Password Changed" in r.text)
r = d.s.post(d.url("vulnerabilities/csrf/test_credentials.php"), data={"username": "admin", "password": "N3w-pass'!", "Login": "Login"})
chk("csrf test_credentials: new password valid", "Valid password for" in r.text)
r = d.s.post(d.url("vulnerabilities/csrf/test_credentials.php"), data={"username": "admin", "password": "password", "Login": "Login"})
chk("csrf test_credentials: old password now wrong", "Wrong password for" in r.text)

d.set_security("impossible")
tok = d.token(d.s.get(d.url("vulnerabilities/csrf/")).text)
r = d.s.get(d.url("vulnerabilities/csrf/"), params={"password_current": "N3w-pass'!", "password_new": "password", "password_conf": "password", "Change": "Change", "user_token": tok})
chk("csrf [impossible] change with correct current password", "Password Changed" in r.text)
tok = d.token(r.text)
r = d.s.get(d.url("vulnerabilities/csrf/"), params={"password_current": "WRONG", "password_new": "x", "password_conf": "x", "Change": "Change", "user_token": tok})
chk("csrf [impossible] wrong current password rejected", "current password incorrect" in r.text)

d2 = DVWA(base, verify)
chk("fresh login admin/password after the round trip", d2.login("admin", "password")[0])
print("ALL PASS" if ok_all else "SOME FAILED"); sys.exit(0 if ok_all else 1)
