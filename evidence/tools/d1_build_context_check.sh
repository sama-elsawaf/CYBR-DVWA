#!/bin/sh
# D1: does `COPY . .` (repo Dockerfile) put secrets/certs into an image layer? Builds a FROM-scratch image
# with the SAME build context and .dockerignore as the real Dockerfile, then lists the copied files.
set -e
printf 'FROM scratch\nCOPY . /var/www/html/\n' | docker build -q -t d1-context-check -f - . >/dev/null
id=$(docker create d1-context-check /x)
docker export "$id" | tar -t | grep -E "secrets/|certs/|\.env" || echo "(no secrets/, certs/ or .env files in the image)"
docker rm "$id" >/dev/null; docker rmi -f d1-context-check >/dev/null
