#!/usr/bin/env bash
# Writes a database with go-ca's code and lets the real XCA command line read
# it, add to it and sign a CRL with a CA key go-ca generated.
set -euo pipefail
export XCA_NO_GUI=1 QT_QPA_PLATFORM=offscreen
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
cd "$(dirname "$0")/../.."
GOCA_XCA_DIR="$dir" go test -count=1 -run 'TestWrite.*ForXCA' ./internal/store/ >/dev/null
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

echo "== revocations: go-ca revoked two certificates and wrote a CRL; XCA reads it and signs its own"
db="$dir/revoked.xdb"
xca --database="$db" --password=pass:secret --list-items 2>&1 | strip | grep -i "revocation"
xca --database="$db" --password=pass:secret --crlgen="Example Issuing CA" --name="CRL by XCA after go-ca" 2>&1 | strip | tail -1
for name in "CRL by go-ca" "CRL by XCA after go-ca"; do
  echo "-- $name"
  sqlite3 "$db" "SELECT crl FROM crls JOIN items ON items.id = crls.item WHERE name='$name'" | base64 -d |
    openssl crl -inform DER -noout -text | grep -E "Serial Number|CRL Reason|Key Compromise|Superseded|CRL Number|Invalidity" -A1 | grep -v "^--"
done
sqlite3 "$db" "SELECT caId, serial, reasonBit, crlNo FROM revocations ORDER BY serial"
