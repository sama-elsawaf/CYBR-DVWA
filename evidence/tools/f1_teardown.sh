#!/bin/bash
# Remove everything f1_setup.sh created. Your compose stack and its data are not touched.
cd "$(dirname "$0")/../.."
docker rm -f f1old-dvwa f1old-db f1new-dvwa 2>/dev/null; docker network rm f1old 2>/dev/null
git worktree remove --force ../f1-old 2>/dev/null; git worktree prune; echo "F1 containers removed"
