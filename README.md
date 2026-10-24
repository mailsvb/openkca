# go-ca

A web based certificate authority with SSH and OpenPGP keys, written in Go.
One statically linked binary serves the UI over HTTPS. It started as a web
UI for [XCA](https://github.com/chris2511/xca) databases and still takes
them over: an XCA `.xdb` file is imported once into a go-ca database
(`.gca`), which has go-ca's own schema and encryption.

## Features

**Databases**

- Lists every go-ca database (`.gca`) and every XCA database waiting to be
  imported (`.xdb`) in the data folder; create new databases and upload
  existing ones (either kind) from the start page. Several databases can
  be open at the same time, each with its own password (at least 8
  characters for new ones).
- Shows keys, certificate signing requests, certificates (as a tree under
  their issuers), templates and revocation lists, with search, a column
  chooser and expiry colours, plus XCA's shared options.
- An XCA database (or one from an older go-ca) is imported at its first
  login into a new go-ca database of the same name, with a progress page
  while the keys are re-encrypted. Item IDs, names, comments, dates and all
  links carry over; items XCA had marked deleted go to the trash. Once the
  new database has been verified (every item and link is there, the
  password opens it, every key opens), the `.xdb` file and its backups are
  deleted, so no copy with XCA's encryption remains.
- Deleting an item moves it to the trash: it disappears from the lists,
  links to it read as unknown and come back when it is restored. Items are
  deleted for good, private keys included, only from the trash.
- An append-only audit log records every change (keys generated, imported
  and exported, certificates issued, renewed and revoked, CRLs, options,
  password changes, trash, failed and successful logins) with time and
  client address, never secrets. It is shown per database and per item.
- Private keys are stored with envelope encryption. The database password
  is stretched with Argon2id (256 MiB, 3 passes by default, adjustable per
  database) into a key that wraps a random 256-bit data key; the data key
  seals every private key with AES-256-GCM, bound to the key's public key.
  Unwrapping the data key is the password check: no password hash is
  stored. A key with its own password is sealed with a key derived from
  that password instead. Changing the password (or the Argon2id cost)
  replaces the data key and re-seals all keys.
- XCA's key encryption (PBKDF2 with 2048 iterations, the legacy 3DES form,
  the "Bogus" password) and its password hash are left behind: keys under
  the database password during the import, keys with their own password
  the next time that password opens them; the key list points out the keys
  still waiting.

**Keys, requests and certificates**

- "New…" starts from the purpose: root CA, intermediate CA, TLS server,
  TLS client, S/MIME, code signing, SSH key or OpenPGP key. Each purpose
  asks only for what it needs (host names, a name or an e-mail address,
  the issuing CA, the lifetime) and fills in the rest: ECDSA P-256 keys
  (P-384 for a root CA, RSA 3072 for S/MIME, Ed25519 for SSH and OpenPGP),
  key usage and extended key usage, basic constraints. A side panel shows
  the resulting certificate as it is typed, with warnings (a TLS server
  certificate longer than Apple accepts, a certificate that outlives its
  CA). The form can be handed to the full editor with its values; a CA's
  "Issue" and a request's "Sign" lead to the purposes too. The database's
  own templates are offered next to them.
- Simple by default, deep for experts: the key type picker offers three
  recommended types first and folds the others by family; post-quantum
  keys, RSA-PSS and key agreement keys, the signature hash, issuer
  alternative names, name constraints, OCSP must-staple, further
  extensions and Netscape extensions are shown when the database's
  "Show expert fields" option is on (values they hold are kept and
  pointed out while hidden). Composite keys are marked as drafts.
- The signature hash follows the signing key by default (SHA-256 for
  P-256 and RSA up to 4096 bit, SHA-384 for P-384, SHA-512 for P-521);
  serial numbers are 128 bit random. Databases imported with XCA's
  defaults (SHA-256, 64 bit) switch to these.
- Generate RSA (also as RSA-PSS keys that sign with PSS only), ECDSA
  (P-256/384/521, brainpoolP256r1/384r1/512r1, secp256k1), Ed25519, Ed448,
  X25519 and X448 keys, and the post-quantum ML-DSA (FIPS 204), SLH-DSA
  (FIPS 205, all twelve parameter sets), ML-KEM (FIPS 203), Composite
  ML-DSA and Composite ML-KEM keys (draft-ietf-lamps-pq-composite-sigs and
  -kem); give keys their own password or reset it; check that a private
  key matches its public key. Brainpool and secp256k1 keys are computed
  with Go's generic, not constant-time elliptic curve code.
- Every key that can sign signs certificates, requests and CRLs; RSA keys
  sign with PKCS#1 v1.5 or, with the `-pss` hash choices, with PSS. Keys
  that cannot sign (X25519, X448, ML-KEM, Composite ML-KEM) get their
  certificates from a CA. Certificates, requests and CRLs of all these
  algorithms are read and their signatures verified, also those Go's
  crypto/x509 refuses.
- Create requests and certificates in an editor modelled on XCA's, which
  starts from a purpose or template, folds key, validity and extensions
  into one-line summaries and lists where the form differs from its
  purpose:
  self-signed or signed by a CA, from a request, with subject, validity,
  basic constraints, key identifiers, key usage, extended key usage,
  alternative names (including `DNS:copycn` and `email:copy`), CRL
  distribution points, AIA, name constraints, OCSP must-staple and Netscape
  extensions, with a preview.
- Further extensions in OpenSSL configuration syntax (XCA's "advanced" tab):
  certificate policies with qualifiers, policy constraints and mappings,
  inhibitAnyPolicy, noCheck, dirName and otherName/UPN names, sections and
  any extension as `DER:` or `ASN1:` value.
- Sign requests, create similar certificates and requests, turn a
  certificate into a request, extract public keys, mark requests signed,
  rename, comment and delete items.

**SSH keys**

- Generate SSH keys (Ed25519, ECDSA, RSA) with an SSH comment. Every key
  SSH can use has an SSH page with its `authorized_keys` line, its SSH
  fingerprint and a download of the key pair as a ZIP archive: for
  OpenSSH (private key and `.pub`), for PuTTY (`.ppk` version 3 and the
  RFC 4716 public key) or for older PuTTY versions and WinSCP (`.ppk`
  version 2), optionally protected by a passphrase.
- SSH keys are ordinary keys of the database.

**OpenPGP keys**

- Generate OpenPGP keys (Ed25519 with an X25519 encryption subkey, Ed448
  with X448, ECDSA with ECDH on P-256/384/521 and brainpoolP256r1/384r1/
  512r1, RSA 3072/4096) with any number of user IDs and an expiry, as
  OpenPGP v4 keys for GnuPG and every other program or as v6 keys (RFC
  9580) for Sequoia, OpenPGP.js and gopenpgp. Post-quantum v6 keys (RFC
  9980) are ML-DSA-65+Ed25519 with an ML-KEM-768+X25519 subkey or
  ML-DSA-87+Ed448 with ML-KEM-1024+X448; they are go-ca's Composite ML-DSA
  and ML-KEM keys. GnuPG 2.4 knows neither Ed448/X448 as RFC 9580 keys nor
  the post-quantum algorithms.
- Any stored RSA, ECDSA (also on secp256k1), EdDSA or ML-DSA composite
  key, for example an SSH key, can become the primary key of an OpenPGP
  key; further subkeys can be bound to it, such as an SSH key as
  authentication subkey for gpg-agent.
- Every OpenPGP key has a page with its fingerprint, user IDs, subkeys and
  armored public key, and a download of the key pair as a ZIP archive
  (public key, secret key, revocation certificate, as GnuPG keeps them),
  optionally protected by a passphrase.
- Primary keys and subkeys are ordinary keys of the database; the OpenPGP
  certificate (user IDs and signatures) is stored with the primary key.

**Certificate authorities**

- Revoke and unrevoke certificates, manage a CA's revocations (also of
  serials not in the database), set the CRL interval and default template,
  generate CRLs with XCA's options and renew certificates (new or same
  serial, optionally revoking or deleting the old one).
- An OpenSSL `ca` style index per CA in
  `<data-dir>/index/<database>/<CA>/index.txt` (plus `index.txt.attr`),
  kept current and usable directly with `openssl ocsp -index`.

**Templates**

- Create, edit and duplicate templates in XCA's format, apply them (all,
  subject only or extensions only), turn certificates and requests into
  templates; a CA's default template applies when issuing with it.

**Import and export**

- Export in every format XCA offers except the OpenVPN tls-auth key:
  certificates as PEM, PEM chain, PEM with key (plain or PKCS#8), DER,
  PKCS#7 (single, selected, chain), PKCS#12 (with or without chain, every
  certificate under its name, using the `pkcs12_enc_algo` option:
  AES-256-CBC by default, PBE-SHA1-3DES and RC2-40 for old Windows and
  Java; AES-256-CBC files use `pkcs12_iterations`, 200 000 by default,
  for the MAC and both encryptions, the most Windows and .NET import
  (OpenSSL writes 2048)), OpenVPN inline tags, OpenSSL config,
  vCalendar reminders, JSON Web Key and the OpenSSL index; keys as PEM
  (public, private, encrypted), DER, PKCS#8, SSH, PVK and JWK; requests,
  CRLs and templates in their formats. Only the formats that can hold a
  key are offered: encrypted traditional PEM takes RSA, EC and DSA keys;
  keys without a traditional form are written as PKCS#8, as OpenSSL 3
  does. PKCS#12 takes every key type; OpenSSL reads the post-quantum ones
  from version 3.5 on, and nothing outside go-ca reads composite keys yet.
- Beyond XCA, keys also export as OpenSSH private keys with their comment
  (plain or passphrase protected, as ssh-keygen writes them), as PuTTY
  private keys (`.ppk` version 3 or 2, plain or encrypted) and as RFC 4716
  public keys. The first line of a key's comment is its SSH comment.
  OpenPGP keys export as armored or binary public keys, as secret keys
  (plain or passphrase protected: iterated SHA-256 and AES-256 for v4,
  Argon2 and AES-256-OCB for v6) and as revocation certificates. Select
  several items in a list to export them together; text formats can be
  shown and copied.
- Import PEM (any number of blocks), DER, PKCS#7, PKCS#8 (encrypted with
  PBES2 using PBKDF2 or scrypt, with the PKCS#12 schemes such as
  PBE-SHA1-3DES, old OpenSSL's default, or with PBES1 MD5/SHA-1 and DES or
  RC2; a scheme go-ca cannot decrypt, such as Camellia, is reported as
  such, not as a wrong password), PKCS#12 (any
  number of keys and certificates, also certificates or a key alone; a key
  of an unknown type is reported and its certificate still imported), SSH
  keys (`authorized_keys` lines, RFC 4716 public keys, OpenSSH private
  keys in any cipher ssh-keygen offers except 3DES and ChaCha20, PuTTY
  `.ppk` files of version 2 and 3), OpenPGP keys (armored or binary, any
  number of keys, public, secret or secret subkeys only, v4 and v6), PVK,
  CRLs and XCA templates, from files or pasted text. An SSH key's comment
  becomes the item's comment and suggested name, an OpenPGP key's first
  user ID its name; only signatures that verify are kept. Everything
  found is listed for review, with names that can be changed, before
  anything is stored. As in XCA, existing items are skipped, a private key
  completes a stored public key and an imported CRL adds its revocations to
  the CA. An OpenPGP certificate is stored with its primary key, also when
  the keys are already in the database.
- Download a whole database as a ZIP of PEM files (XCA's "Dump database"),
  with the OpenPGP public keys next to their keys and the private keys
  encrypted with a password chosen for the dump.

**Tools**

- Diffie-Hellman parameters (1024 to 4096 bit), generated in the background.
- An OID resolver.

| Database                                  | go-ca                                          |
| ----------------------------------------- | ---------------------------------------------- |
| go-ca `.gca` (schema 3)                   | supported                                      |
| XCA schema 5 to 8 (XCA 2.x and later)     | imported into a new `.gca` on first login      |
| go-ca 0.10 and earlier (`.xdb`, schema 1/2) | imported; schema 2 keeps its data key and keys |
| XCA schema below 5, pre-2.0 format        | refused                                        |
| newer XCA or go-ca schema                 | refused until supported                        |

A go-ca database is an SQLite file with its own schema (`internal/gcadb`)
and SQLite's application ID `gca1`: DER objects as BLOBs with SHA-256
fingerprints, links as foreign keys, templates as JSON, a trash and an
append-only audit table. The `kdf` and `dek` settings hold the Argon2id
parameters and the wrapped data key; private keys are sealed by
`internal/vault`. Reading XCA's schema is `internal/xcaimport`'s job only,
and it opens `.xdb` files read-only. Templates and the database dump can
still be exported in XCA's formats.

## Download

Releases with binaries for Linux (amd64, arm64), Windows (amd64) and macOS
(amd64, arm64) are on the
[releases page](https://github.com/mailsvb/go-ca/releases). `go-ca version`
prints the version of a binary.

## Build

Requires Go 1.27 or later (the toolchain is downloaded automatically by older
`go` commands). No C compiler is needed:

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(cat VERSION)" -o go-ca ./cmd/go-ca
```

## Versions and releases

`VERSION` holds the current version (semantic versioning, `X.Y.Z`).

- Every push runs `.github/workflows/build.yml`, which builds all platforms
  as `<VERSION>-dev-<yyyyMMdd>-<HHmmss>` (UTC) and keeps the archives as
  artifacts of the workflow run.
- Running the same workflow manually (Actions → Build → Run workflow, on
  `main`) makes an official release: enter a version `X.Y.Z`, or leave it
  empty to increase the fix number of `VERSION` by one. The release is
  tested, built, tagged `v<version>` and published as a GitHub release with
  the archives and their SHA-256 checksums; `VERSION` on `main` is then set
  to the released version.
- `.github/workflows/test.yml` checks formatting and runs `go vet` and
  `go test -race` on every push to `main`.

## Run

```sh
# once: set the server password (stored as an argon2id hash)
./go-ca set-password --data-dir /srv/xca

# serve the databases in the folder on https://<host>:8443/
./go-ca --data-dir /srv/xca

# print the version
./go-ca version
```

| Flag             | Default  | Meaning                                                          |
| ---------------- | -------- | ---------------------------------------------------------------- |
| `--data-dir`     | required | folder with the `.gca` and `.xdb` files, rescanned on every page load |
| `--listen`       | `:8443`  | listen address (all interfaces by default)                       |
| `--tls-cert`     |          | PEM certificate; without it a self-issued certificate is used    |
| `--tls-key`      |          | PEM key for `--tls-cert`                                         |
| `--idle-timeout` | `30m`    | idle timeout of server and database sessions                     |
| `--max-upload`   | `256`    | largest upload (database file or items to import), in MB         |

Without `--tls-cert`, go-ca creates a self-signed certificate (CN `go-ca`,
SANs `localhost`, `127.0.0.1`, `::1`, valid 365 days) on first start, reuses it
and replaces it automatically once it has expired. Browsers on other machines
will warn about the name until you pass a certificate for the real host name.

### Data folder

```
/srv/xca/
├── ca-root.gca           go-ca databases, listed on the login page
├── ca-root.gca.lock      lock held while go-ca has the database open
├── old-ca.xdb            an XCA database, imported (and deleted) at its first login
└── .go-ca/               server state (never listed)
    ├── server-password   argon2id hash
    ├── tls.crt, tls.key  self-issued certificate
    └── backup/           <name>.<yyyyMMddHHmmss>.gca
/srv/xca/index/<database>/<CA>/index.txt   per-CA certificate index
```

A backup is written right after an import and before every change that
rewrites a whole database (database password or Argon2id cost change),
using SQLite's `VACUUM INTO`, which copies within one read transaction.
How many are kept is a database option: at most 10 and none older than
90 days by default (the newest always stays). After a password change
every older backup is deleted, since they still open with the old
password, and a new one is written.

Two go-ca processes cannot open the same database (`flock` on the `.lock`
file).

## Security

- One server password protects the whole UI; database passwords still apply
  after it. Both logins are rate limited, and at most two Argon2id runs
  happen at a time, so parallel login attempts cannot exhaust memory.
- New database passwords need at least 8 characters.
- HTTPS only, HSTS, strict Content Security Policy without inline scripts,
  `SameSite=Strict` cookies plus CSRF tokens.
- A database password is used once per login to unwrap the data key; a
  session keeps only the data key in memory and wipes it on logout and
  after the idle timeout (as far as Go allows: the runtime may keep
  copies). Private keys are decrypted in memory only when needed.
- SQLite's `secure_delete` is on, and the file is vacuumed after keys are
  re-encrypted and after items are deleted from the trash, so replaced or
  deleted key blobs do not stay in the file.

## Translations

The UI is English, but no template contains literal text: every string comes
from `internal/i18n/locales/en.json` (plural forms supported). To add a
language, copy `en.json` to e.g. `de.json` and translate the values; the
browser's `Accept-Language` selects it, falling back to English. A test fails
the build on untranslated text in a template or a missing message key.

## Development

```sh
go test -race ./...
```

Some tests compare against the `openssl`, `ssh-keygen`, `puttygen`
(`putty-tools` on Debian and Ubuntu) and `gpg` command lines and are
skipped where those are missing. The OpenPGP tests have gpg import
go-ca's keys, encrypt to them, verify their signatures and import their
revocation certificates, and read keys gpg generated in each export form.

`testdata/xdb/` holds databases generated with the real XCA command line and
crafted variants (old password hashes, a legacy 3DES key, a key with its own
password, schema 8 and 9, a pre-2.0 file); the tests import them into
go-ca databases, also as go-ca 0.10's schema 2. Regenerate them with `testdata/gen/gen-fixtures.sh` (needs
`xca`, `openssl`, `sqlite3`, `perl`).
`testdata/gen/check-export-with-xca.sh` exports a hierarchy in every format
and lets the XCA command line import each file, except go-ca's own SSH
and OpenPGP formats.

Third-party code: [htmx](https://htmx.org) 2.0.11 (BSD Zero Clause License,
`internal/web/static/htmx.LICENSE`);
[ProtonMail/go-crypto](https://github.com/ProtonMail/go-crypto) for
OpenPGP and [cloudflare/circl](https://github.com/cloudflare/circl), which
it uses (both BSD 3-Clause License).
