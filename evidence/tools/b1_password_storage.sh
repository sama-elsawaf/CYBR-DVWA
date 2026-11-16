#!/bin/sh
# B1: password storage after R2. Run from the repo root with the stack up.
# Usage: sh evidence/tools/b1_password_storage.sh "<docker compose command>"
C=${1:-docker compose}
SQL() { $C exec -T db sh -c 'MYSQL_PWD="$(cat /run/secrets/db_password)" mariadb -udvwa dvwa -e "$0"' "$1"; }
CLI="python3 evidence/tools/dvwa_client.py --base https://127.0.0.1 --cafile certs/lab-ca.crt"
login() { python3 - "$1" "$2" <<'PY'
import sys; sys.path.insert(0, "evidence/tools")
from dvwa_client import DVWA
ok, r = DVWA("https://127.0.0.1", "certs/lab-ca.crt").login(sys.argv[1], sys.argv[2])
print(f"  login {sys.argv[1]:8s} via https://127.0.0.1/login.php -> {'OK' if ok else 'FAILED'}")
PY
}
loginall() { login admin password; login gordonb abc123; login 1337 charley; login pablo letmein; login smithy password; }

echo "== 1. Column type"; SQL "DESCRIBE users password;"
echo; echo "== 2. Reset DB through setup.php (new seeding)"; $CLI reset
SQL "SELECT user, password FROM users ORDER BY user_id;"
echo; echo "== 3. Simulate a LEGACY database (rows as the original DVWA stored them: unsalted MD5)"
SQL "UPDATE users SET password=MD5(CASE user WHEN 'admin' THEN 'password' WHEN 'gordonb' THEN 'abc123' WHEN '1337' THEN 'charley' WHEN 'pablo' THEN 'letmein' WHEN 'smithy' THEN 'password' END); SELECT user, password FROM users ORDER BY user_id;"
echo; echo "== 4. Log in once as every legacy user (default DVWA passwords)"; loginall
echo; echo "== 5. After login: SELECT user, password FROM users;"
SQL "SELECT user, password FROM users ORDER BY user_id;"
echo; echo "== 6. Checks"
SQL "SELECT SUM(password LIKE '\$argon2id\$v=19\$m=19456,t=2,p=1\$%') AS argon2id_rows, COUNT(*) AS total_rows, MAX(LENGTH(password)) AS max_len FROM users;"
SQL "SELECT (SELECT password FROM users WHERE user='admin') = (SELECT password FROM users WHERE user='smithy') AS admin_equals_smithy_same_plaintext;"
echo; echo "== 7. Second login still works (now verified against Argon2id)"; loginall
