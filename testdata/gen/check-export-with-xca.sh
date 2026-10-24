#!/usr/bin/env bash
# Exports a small hierarchy in every format OpenKCA offers and lets the real
# XCA command line import each file into a new database. Encrypted files
# get the password "export" through a pseudo terminal.
set -euo pipefail
export XCA_NO_GUI=1 QT_QPA_PLATFORM=offscreen
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
cd "$(dirname "$0")/../.."
OPENKCA_XCA_DIR="$dir" go test -count=1 -run 'TestExportForXCA' ./internal/store/ >/dev/null
db="$dir/imported.xdb"
strip() { sed 's/\x1b\[[0-9;]*m//g' | tr -d '\r'; }
# a key first, so that the database password is set before the imports
xca --database="$db" --password=pass:secret --keygen=EC:prime256v1 --name=init >/dev/null 2>&1
# XCA asks for the file password and, for keys, the database password on the
# terminal (it does not use --password for that); answer both, in turn.
answers() { for _ in 1 2 3; do sleep 2; echo export; sleep 2; echo secret; done; }
cd "$dir/export"
for f in *; do
  case "$f" in
    *.ics|*.jwk|*.conf|*.txt|*.ovpn) continue ;; # not importable by XCA
    *-10[0-9].*) continue ;; # OpenKCA's SSH formats, which XCA does not offer
    *-11[0-9].*) continue ;; # OpenKCA's OpenPGP formats, which XCA does not offer
    *-23.pub) case "$f" in spare-*) continue ;; esac ;; # XCA reads only nistp256 SSH keys
  esac
  out=$(answers |
    timeout 30 script -qfec "xca --database='$db' --password=pass:secret --import '$f'" /dev/null 2>&1 | strip || true)
  out=$(echo "$out" | grep -v "Password verify error" || true)
  if echo "$out" | grep -qiE "error|fail|unable|killed"; then
    echo "FAIL $f: $(echo "$out" | grep -iE "error|fail|unable|killed" | head -2 | tr '\n' ' ')"
  else
    echo "ok   $f"
  fi
done
echo "== items in the XCA database"
xca --database="$db" --password=pass:secret --list-items 2>&1 | strip
