#!/bin/sh
# Create the Docker secret files in ./secrets (gitignored). Existing files are kept.
#   sh scripts/gen_secrets.sh        (Git Bash / WSL / Linux / macOS)
# After changing DB passwords on an existing install: docker compose down -v (wipes the DB volume).
set -eu
cd "$(dirname "$0")/.."
mkdir -p secrets
# If `docker compose up` ran before these files existed, Docker Desktop created EMPTY FOLDERS with
# the secret file names. Remove those (only empty ones) so the files can be written.
for f in crypto_master_key.txt db_password.txt db_root_password.txt; do
  [ -d "secrets/$f" ] && rmdir "secrets/$f" && echo "removed empty folder secrets/$f (created by Docker)"
done
umask 022   # the files must be readable by the container user (www-data / mysql)
mk() { [ -s "secrets/$1" ] && { echo "keep    secrets/$1"; return; }; printf '%s' "$2" > "secrets/$1"; echo "created secrets/$1"; }
rnd() { php -r "echo base64_encode(random_bytes($1));" 2>/dev/null || openssl rand -base64 "$1"; }
mk crypto_master_key.txt "$(rnd 32)"                       # base64 of exactly 32 random bytes
mk db_password.txt       "$(rnd 24 | tr -d '/+=')"
mk db_root_password.txt  "$(rnd 24 | tr -d '/+=')"
