# go-ca

A web based certificate authority with SSH and OpenPGP keys, written in Go.
One statically linked binary serves the UI over HTTPS. It started as a web
UI for [XCA](https://github.com/chris2511/xca) databases and still takes
them over: an XCA `.xdb` file opens in go-ca and is converted to go-ca's
format, which builds on XCA's schema but is no longer opened by desktop
XCA.

## Features

**Databases**

- Lists every `.xdb` file in the data folder; create new databases and
  upload existing ones from the start page. Several databases can be open
  at the same time, each with its own password.
- Shows keys, certificate signing requests, certificates (as a tree under
  their issuers), templates and revocation lists, with search, a column
  chooser and expiry colours, plus XCA's shared options.
- XCA databases are converted to go-ca's format on first login, after a
  backup (see the table below); private keys in XCA's legacy 3DES format
  are re-encrypted as PKCS#8.

**Keys, requests and certificates**

- Generate RSA, ECDSA (P-256/384/521) and Ed25519 keys; give keys their own
  password or reset it; check that a private key matches its public key.
- Create requests and certificates in an editor modelled on XCA's:
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

- Generate OpenPGP keys (Ed25519 with an X25519 encryption subkey, ECDSA
  with ECDH on P-256/384/521, RSA 3072/4096) with any number of user IDs
  and an expiry, as OpenPGP v4 keys for GnuPG and every other program or
  as v6 keys (RFC 9580) for Sequoia, OpenPGP.js and gopenpgp.
- Any stored RSA, ECDSA or Ed25519 key, for example an SSH key, can become
  the primary key of an OpenPGP key; further subkeys can be bound to it,
  such as an SSH key as authentication subkey for gpg-agent.
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
  PKCS#7 (single, selected, chain), PKCS#12 (with or without chain, using
  the `pkcs12_enc_algo` option), OpenVPN inline tags, OpenSSL config,
  vCalendar reminders, JSON Web Key and the OpenSSL index; keys as PEM
  (public, private, encrypted), DER, PKCS#8, SSH, PVK and JWK; requests,
  CRLs and templates in their formats.
- Beyond XCA, keys also export as OpenSSH private keys with their comment
  (plain or passphrase protected, as ssh-keygen writes them), as PuTTY
  private keys (`.ppk` version 3 or 2, plain or encrypted) and as RFC 4716
  public keys. The first line of a key's comment is its SSH comment.
  OpenPGP keys export as armored or binary public keys, as secret keys
  (plain or passphrase protected: iterated SHA-256 and AES-256 for v4,
  Argon2 and AES-256-OCB for v6) and as revocation certificates. Select
  several items in a list to export them together; text formats can be
  shown and copied.
- Import PEM (any number of blocks), DER, PKCS#7, PKCS#8, PKCS#12, SSH
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
  with the OpenPGP public keys next to their keys.

**Tools**

- Diffie-Hellman parameters (1024 to 4096 bit), generated in the background.
- An OID resolver.

| Database                            | go-ca                                                 |
| ----------------------------------- | ----------------------------------------------------- |
| go-ca                               | supported                                             |
| XCA schema 8 (XCA 2.7 and later)    | converted to go-ca's format on first login, after a backup |
| XCA schema 5 to 7 (XCA 2.x to 2.6)  | upgraded to schema 8 and converted, after a backup    |
| XCA schema below 5, pre-2.0 format  | refused                                               |
| newer XCA or go-ca schema           | refused until supported                               |

A go-ca database is XCA's schema 8 plus go-ca's own tables (OpenPGP
certificates). Its `schema` setting is `1000`, so desktop XCA refuses it
instead of losing go-ca's data, and `gca_schema` holds go-ca's own schema
version. The backup taken before the conversion is still an XCA database.

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

# serve all *.xdb files in the folder on https://<host>:8443/
./go-ca --data-dir /srv/xca

# print the version
./go-ca version
```

| Flag             | Default  | Meaning                                                          |
| ---------------- | -------- | ---------------------------------------------------------------- |
| `--data-dir`     | required | folder with the `.xdb` files, rescanned on every page load       |
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
├── ca-root.xdb           databases, listed on the login page
├── ca-root.xdb.lock      lock held while go-ca has the database open
└── .go-ca/               server state (never listed)
    ├── server-password   argon2id hash
    ├── tls.crt, tls.key  self-issued certificate
    └── backup/           <name>.<yyyyMMddHHmmss>.xdb, newest 10 per database
/srv/xca/index/<database>/<CA>/index.txt   per-CA certificate index
```

A backup is written before every change that rewrites a whole database
(conversion of an XCA database, schema upgrade, 3DES key conversion,
database password change), using
SQLite's `VACUUM INTO`, which copies within one read transaction.

Two go-ca processes cannot open the same database (`flock` on the `.lock`
file).

## Security

- One server password protects the whole UI; database passwords still apply
  after it. Both logins are rate limited.
- HTTPS only, HSTS, strict Content Security Policy without inline scripts,
  `SameSite=Strict` cookies plus CSRF tokens.
- Database passwords live only in memory and are zeroed on logout and after
  the idle timeout. Private keys are decrypted in memory only when needed.

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
password, schema 8 and 9, a pre-2.0 file); the tests convert them to
go-ca's format. Regenerate them with `testdata/gen/gen-fixtures.sh` (needs
`xca`, `openssl`, `sqlite3`, `perl`).
`testdata/gen/check-export-with-xca.sh` exports a hierarchy in every format
and lets the XCA command line import each file, except go-ca's own SSH
and OpenPGP formats.

Third-party code: [htmx](https://htmx.org) 2.0.11 (BSD Zero Clause License,
`internal/web/static/htmx.LICENSE`);
[ProtonMail/go-crypto](https://github.com/ProtonMail/go-crypto) for
OpenPGP and [cloudflare/circl](https://github.com/cloudflare/circl), which
it uses (both BSD 3-Clause License).
