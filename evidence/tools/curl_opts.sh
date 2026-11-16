# Sourced by the evidence shell scripts. Picks curl options that work on Linux, Git Bash, MSYS2 and WSL.
# - Windows curl built on Schannel checks certificate revocation; the lab CA has no revocation list,
#   so verification fails silently unless --ssl-no-revoke is given (the certificate is STILL verified).
# - -sS: quiet, but curl errors are printed instead of an empty result.
CURL_TLS="--cacert certs/lab-ca.crt"
if curl --version 2>/dev/null | grep -qi schannel; then CURL_TLS="$CURL_TLS --ssl-no-revoke"; fi
CURL_BASE="curl -sS --noproxy localhost,127.0.0.1 $CURL_TLS"
# Fail early with the real reason if the HTTPS check does not work at all.
curl_selftest() {
  if ! $CURL_BASE -o /dev/null "https://localhost/login.php"; then
    echo "!! curl cannot reach https://localhost with the lab CA (see the curl error above). Is the stack up (docker compose ps)?"
    exit 1
  fi
}
