#!/bin/sh
# R1: create a local lab CA and an ECDSA P-256 server certificate for the TLS proxy, in ./certs (gitignored).
#   sh scripts/gen_lab_certs.sh          (Git Bash on Windows, WSL, Linux, macOS: needs openssl 1.1.1+)
# Re-running keeps an existing CA (so the browser trust stays valid) and re-issues the server cert.
set -eu
cd "$(dirname "$0")/.."
mkdir -p certs && cd certs
# Empty folders named like the cert files appear if `docker compose up` ran first (Docker Desktop
# creates missing bind-mount sources as folders). Remove those so the files can be written.
for f in server.crt server.key lab-ca.crt lab-ca.key; do
  [ -d "$f" ] && rmdir "$f" && echo "removed empty folder certs/$f (created by Docker)"
done
umask 077
if [ ! -s lab-ca.key ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out lab-ca.key
  openssl req -x509 -new -key lab-ca.key -sha256 -days 825 -out lab-ca.crt \
    -subj "/CN=CYBR470 DVWA Lab CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
  echo "created lab CA: certs/lab-ca.crt (import this into the browser / OS trust store)"
fi
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
cat > server.ext <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:dvwa.lab,IP:127.0.0.1
EXT
openssl x509 -req -in server.csr -CA lab-ca.crt -CAkey lab-ca.key -CAcreateserial \
  -days 397 -sha256 -extfile server.ext -out server.crt
rm -f server.csr server.ext
chmod 644 lab-ca.crt server.crt
chmod 644 server.key   # read by the nginx container (bind mount); the CA key stays 600 and is never mounted
openssl x509 -in server.crt -noout -subject -issuer -ext subjectAltName
