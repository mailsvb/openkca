#!/usr/bin/env bash
# Writes a database with go-ca's code and lets the real XCA command line read
# it, add to it and sign a CRL with a CA key go-ca generated.
set -euo pipefail
export XCA_NO_GUI=1 QT_QPA_PLATFORM=offscreen
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
cd "$(dirname "$0")/../.."
GOCA_XCA_DIR="$dir" go test -count=1 -run TestWriteForXCA ./internal/store/ >/dev/null
db="$dir/goca.xdb"
strip() { sed 's/\x1b\[[0-9;]*m//g'; }
echo "== items as XCA lists them"
xca --database="$db" --password=pass:secret --list-items 2>&1 | strip
echo "== XCA signs a CRL with the go-ca generated CA key"
xca --database="$db" --password=pass:secret --crlgen="GoCA RSA Sub" --name="CRL by XCA" 2>&1 | strip | tail -1
echo "== XCA adds a key"
xca --database="$db" --password=pass:secret --keygen=EC:secp384r1 --name="added by XCA" 2>&1 | strip | grep -v Generating | tail -1
echo "== issuers XCA knows"
xca --database="$db" --password=pass:secret --issuers 2>&1 | strip
sqlite3 "$db" "PRAGMA integrity_check; SELECT id, name, stamp FROM items ORDER BY id"
