import sys, re
sys.path.insert(0, __file__.rsplit('/', 1)[0])  # 150 logins in a row; prints any failure
from dvwa_client import DVWA
d0=DVWA("http://127.0.0.1:4280"); d0.reset_db()
bad=0
for i in range(40):
    d=DVWA("http://127.0.0.1:4280")
    r=d.s.get(d.url("login.php")); tok=d.token(r.text); c1=dict(d.s.cookies)
    r=d.s.post(d.url("login.php"), data={"username":"admin","password":"password","Login":"Login","user_token":tok}, allow_redirects=False)
    loc=r.headers.get("Location"); sc=r.headers.get("Set-Cookie")
    if loc!="index.php":
        bad+=1; r2=d.s.get(d.url("login.php")); print(i, r.status_code, dict(r.headers), r.text[:600])
print("bad", bad)
