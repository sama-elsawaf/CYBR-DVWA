#!/bin/bash
# E1: cookie flags and session id change at login (curl, cookie jar). Run from repo root, stack up.
cd "$(dirname "$0")/../.." && . evidence/tools/curl_opts.sh && curl_selftest
# cookie jar in the repo folder (a /tmp path breaks native Windows curl); deleted at the end
J=.e1_cookiejar.txt; rm -f $J; B="https://localhost"; CURL="$CURL_BASE -c $J -b $J"
echo "# curl: $(curl --version | head -1)"
echo "## 1) GET /login.php (anonymous)   \$ curl -i -c jar -b jar $B/login.php"
R=$($CURL -i "$B/login.php"); echo "$R" | grep -iE "^HTTP/|^set-cookie"
TOKEN=$(echo "$R" | grep -o "name='user_token' value='[0-9a-f]*'" | grep -o "[0-9a-f]\{32\}")
SID_BEFORE=$(awk '$6=="PHPSESSID"{print $7}' $J)
echo; echo "PHPSESSID before login (from jar): $SID_BEFORE"
echo; echo "## 2) POST /login.php admin/password   \$ curl -i -c jar -b jar -d 'username=admin&password=password&Login=Login&user_token=...'"
$CURL -i -d "username=admin&password=password&Login=Login&user_token=$TOKEN" "$B/login.php" | grep -iE "^HTTP/|^set-cookie|^location"
SID_AFTER=$(awk '$6=="PHPSESSID"{print $7}' $J)
echo; echo "PHPSESSID after login (from jar):  $SID_AFTER"
[ -n "$SID_AFTER" ] && [ "$SID_BEFORE" != "$SID_AFTER" ] && echo "=> session id CHANGED at login" || echo "=> session id did NOT change"
echo; echo "## 3) Old (pre-login) id is dead: request index.php with ONLY the old PHPSESSID"
$CURL_BASE -i -b "PHPSESSID=$SID_BEFORE" "$B/index.php" | grep -iE "^HTTP/|^location"
echo; echo "## 4) New id works: GET /index.php with the jar"
$CURL -i "$B/index.php" | grep -iE "^HTTP/|^location|Logout" | head -3
echo; echo "## 5) Cookie jar (curl marks HttpOnly cookies with the #HttpOnly_ prefix; column 4 TRUE = Secure)"
grep -v "^# " $J | sed '/^$/d'
rm -f $J
