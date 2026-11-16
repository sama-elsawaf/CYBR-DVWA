#!/bin/bash
# F1: start the two throwaway containers f1_latency.py measures. Run from the repo root with the stack up.
#   OLD  http://127.0.0.1:4281  original DVWA code (commit a1978a2: XOR + MD5) with its own MariaDB
#   NEW  http://127.0.0.1:4282  this branch's code, same DB + secrets as the stack, plain HTTP, no FORCE_SECURE_COOKIES
# Both use the SAME image as your dvwa service. Remove everything afterwards with: bash evidence/tools/f1_teardown.sh
set -eu
export MSYS_NO_PATHCONV=1                       # Git Bash/MSYS2: do not rewrite /run/secrets/... paths
cd "$(dirname "$0")/../.."
HOST=$(pwd -W 2>/dev/null || pwd)               # C:/Users/... on Windows, /home/... on Linux
IMG=$(docker inspect -f '{{.Config.Image}}' "$(docker compose ps -q dvwa)")
NET=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$(docker compose ps -q dvwa)")
EXTRA=""; [ "$IMG" = "dvwa-sandbox:latest" ] && EXTRA="-v $HOST/evidence/sandbox/99-sandbox.ini:/etc/php/8.3/apache2/conf.d/99-sandbox.ini:ro"
echo "image=$IMG network=$NET"

rm -rf ../f1-old && git worktree prune && git worktree add --detach ../f1-old a1978a2
cp ../f1-old/config/config.inc.php.dist ../f1-old/config/config.inc.php
OLD=$(cd ../f1-old && (pwd -W 2>/dev/null || pwd))

docker network create f1old >/dev/null
docker run -d --name f1old-db --network f1old -e MARIADB_ROOT_PASSWORD=f1root -e MARIADB_DATABASE=dvwa \
  -e MARIADB_USER=dvwa -e MARIADB_PASSWORD=p@ssw0rd docker.io/library/mariadb:10 >/dev/null
docker run -d --name f1old-dvwa --network f1old -e DB_SERVER=f1old-db -v "$OLD:/var/www/html" $EXTRA \
  -p 127.0.0.1:4281:80 "$IMG" >/dev/null
docker run -d --name f1new-dvwa --network "$NET" -e DB_SERVER=db \
  -e CRYPTO_KEY_FILE=/run/secrets/crypto_master_key -e DB_PASSWORD_FILE=/run/secrets/db_password \
  -v "$HOST/secrets/crypto_master_key.txt:/run/secrets/crypto_master_key:ro" \
  -v "$HOST/secrets/db_password.txt:/run/secrets/db_password:ro" \
  -v "$HOST:/var/www/html" -v "$HOST/config/config.inc.php.dist:/var/www/html/config/config.inc.php:ro" $EXTRA \
  -p 127.0.0.1:4282:80 "$IMG" >/dev/null
echo "waiting 20 s for MariaDB..."; sleep 20
PY=$(command -v python3 || command -v python)
"$PY" evidence/tools/dvwa_client.py --base http://127.0.0.1:4281 reset    # creates the OLD database (MD5 users)
"$PY" evidence/tools/dvwa_client.py --base http://127.0.0.1:4282 smoke    # NEW code over plain HTTP
