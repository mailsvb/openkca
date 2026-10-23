#!/usr/bin/env bash
# Generates XCA test databases with the real XCA command line (2.6.x) and
# openssl. Output goes to testdata/xdb. Requires: xca, openssl, sqlite3.
set -euo pipefail
hex() { od -An -tx1 -v | tr -d ' \n'; }
unhex() { perl -e 'print pack("H*", shift)' "$1"; }
export XCA_NO_GUI=1 QT_QPA_PLATFORM=offscreen

here=$(cd "$(dirname "$0")" && pwd)
out="$here/../xdb"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
cd "$work"

db="$out/sample.xdb"
pw=secret
rm -f "$db"
xcadb() { xca --database="$db" --password="pass:$pw" "$@" 2>&1 | sed "s/\x1b\[[0-9;]*m//g" | grep -v "Generating" || true; }

# Root CA (RSA 3072), intermediate CA (EC P-384), leaves.
openssl req -x509 -newkey rsa:3072 -nodes -keyout root.key -out root.crt -days 3650 \
  -subj "/C=DE/O=Example Org/CN=Example Root CA" \
  -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -keyout inter.key -out inter.csr \
  -subj "/C=DE/O=Example Org/OU=Issuing/CN=Example Issuing CA" 2>/dev/null
cat > inter.ext <<X
basicConstraints=critical,CA:true,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
X
openssl x509 -req -in inter.csr -CA root.crt -CAkey root.key -set_serial 0x1001 -days 1825 -extfile inter.ext -out inter.crt 2>/dev/null

leaf() { # name subj serial days extra-san
  openssl req -new -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "$2" 2>/dev/null
  printf 'basicConstraints=CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=%s\nauthorityKeyIdentifier=keyid\n' "$5" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA inter.crt -CAkey inter.key -set_serial "$3" -days "$4" -extfile "$1.ext" -out "$1.crt" 2>/dev/null
}
leaf www   "/C=DE/O=Example Org/CN=www.example.org"  0x2001 397 "DNS:www.example.org,DNS:example.org"
leaf mail  "/C=DE/O=Example Org/CN=mail.example.org" 0x2002 20  "DNS:mail.example.org"
leaf alice "/C=DE/O=Example Org/CN=Alice"            0x2003 365 "email:alice@example.org"

# An already expired certificate (backdated with -not_after unavailable in 3.0: use faketime-free trick)
openssl req -new -newkey rsa:2048 -nodes -keyout old.key -out old.csr -subj "/C=DE/O=Example Org/CN=old.example.org" 2>/dev/null
openssl x509 -req -in old.csr -CA inter.crt -CAkey inter.key -set_serial 0x2004 -days 0 -out old.crt 2>/dev/null || true

# Ed25519 key with a self-signed certificate
openssl genpkey -algorithm ed25519 -out ed.key
openssl req -x509 -key ed.key -out ed.crt -days 365 -subj "/CN=Ed25519 Test" 2>/dev/null

# Unsigned CSR whose key stays in the database
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout pending.key -out pending.csr \
  -subj "/C=DE/O=Example Org/CN=pending.example.org" 2>/dev/null

# CRL from the intermediate revoking alice (needs a tiny openssl ca setup)
mkdir -p ca && : > ca/index.txt && echo 01 > ca/crlnumber
cat > ca.cnf <<X
[ca]
default_ca=x
[x]
database=$work/ca/index.txt
crlnumber=$work/ca/crlnumber
default_md=sha256
default_crl_days=30
X
openssl ca -config ca.cnf -revoke alice.crt -keyfile inter.key -cert inter.crt -crl_reason keyCompromise 2>/dev/null
openssl ca -config ca.cnf -gencrl -keyfile inter.key -cert inter.crt -out inter.crl 2>/dev/null

xcadb --keygen=RSA:2048 --name="Spare RSA key"
xcadb --keygen=DSA:2048 --name="Old DSA key"
xcadb --import --import-names="Example Root CA" root.crt root.key
xcadb --import inter.crt inter.key
for f in www mail alice old ed; do xcadb --import "$f.crt" "$f.key"; done
xcadb --import pending.csr pending.key
xcadb --import inter.crl
xcadb --import /usr/share/xca/CA.xca /usr/share/xca/TLS_server.xca /usr/share/xca/TLS_client.xca
xcadb --crlgen="Example Root CA" --name="Root CRL"

xca --database="$db" --password="pass:$pw" --list-items 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'

# ---- Crafted variants (things the XCA CLI cannot produce) ----
v="$out/variants.xdb"
cp "$db" "$v"
# Old S-form password hash: salt "S" + 4 chars, one SHA-512 round over salt+password.
salt=S1a2b
shash=$(printf '%s%s' "$salt" "$pw" | openssl dgst -sha512 -binary | hex | tr a-f A-F)
# Legacy 3DES key (pre-PKCS#8 XCA): 8 byte IV, key = EVP_BytesToKey(SHA-1, salt=IV, 1 round),
# payload = type-specific DER (PKCS#1 for RSA).
openssl rsa -in www.key -traditional -outform DER -out www.pkcs1 2>/dev/null
iv=0011223344556677
key=$(openssl enc -des-ede3-cbc -md sha1 -S $iv -pass "pass:$pw" -P 2>/dev/null | sed -n 's/^key=//p')
{ unhex "$iv"; openssl enc -des-ede3-cbc -K "$key" -iv "$iv" -in www.pkcs1; } | base64 -w0 > legacy.b64
# Key with its own password (ownPass = 1), password "mailpass".
openssl pkcs8 -topk8 -in mail.key -v2 aes-256-cbc -passout pass:mailpass -outform DER | base64 -w0 > own.b64
sqlite3 "$v" "UPDATE settings SET value='$salt$shash' WHERE key_='pwhash';
  UPDATE private_keys SET private='$(cat legacy.b64)' WHERE item=8;
  UPDATE private_keys SET private='$(cat own.b64)', ownPass=1 WHERE item=10;
  UPDATE items SET del=1 WHERE id=1; DELETE FROM private_keys WHERE item=1; DELETE FROM public_keys WHERE item=1;"

# MD5 password hash (colon separated, upper case)
m="$out/md5.xdb"; cp "$db" "$m"
mhash=$(printf '%s' "$pw" | openssl dgst -md5 -binary | hex | tr a-f A-F | sed 's/../&:/g; s/:$//')
sqlite3 "$m" "UPDATE settings SET value='$mhash' WHERE key_='pwhash'"

# Schema 8 (XCA >= 2.7): the 7 -> 8 step from database_schema.cpp
s8="$out/schema8.xdb"; cp "$db" "$s8"
sqlite3 "$s8" "CREATE TABLE takeys (item INTEGER UNIQUE, value TEXT, FOREIGN KEY (item) REFERENCES items (id));
  UPDATE settings SET value='8' WHERE key_='schema'"

# Newer schema, refused
n="$out/newer.xdb"; cp "$db" "$n"; sqlite3 "$n" "UPDATE settings SET value='9' WHERE key_='schema'"
# Pre-2.0 legacy file (magic CA DB 19 69) and a non-database file
printf '\xca\xdb\x19\x69legacy-xca-database' > "$out/legacy.xdb"
printf 'not a database' > "$out/garbage.xdb"
