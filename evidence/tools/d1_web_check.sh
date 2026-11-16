#!/bin/sh
# D1: secret files must NOT be downloadable from the web root. Expect 404 for each. Run from repo root, stack up.
cd "$(dirname "$0")/../.." && . evidence/tools/curl_opts.sh && curl_selftest
echo "# $(curl --version | head -1)"
for p in secrets/crypto_master_key.txt secrets/db_password.txt certs/server.key certs/lab-ca.key secrets/ .git/config; do
  printf '%-32s -> ' "/$p"; $CURL_BASE -o /dev/null -w '%{http_code} (%{size_download} bytes)\n' "https://localhost/$p"
done
