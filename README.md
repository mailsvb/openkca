# go-ca

A web UI for [XCA](https://github.com/chris2511/xca) certificate databases,
written in Go. One statically linked binary serves the UI over HTTPS and works
directly on XCA's SQLite `.xdb` files, so the same file keeps opening in
desktop XCA.

## Features

**Databases**

- Lists every `.xdb` file in the data folder; create new databases and
  upload existing ones from the start page. Several databases can be open
  at the same time, each with its own password.
- Shows keys, certificate signing requests, certificates (as a tree under
  their issuers), templates and revocation lists, with search, a column
  chooser and expiry colours, plus XCA's shared options.
- Writes everything the way XCA does (items, hashes, key and issuer links,
  `stamp`), so a desktop XCA with the same file open picks the changes up,
  and reloads when desktop XCA changes the file.
- Older databases are upgraded after a backup (see the table below);
  private keys in XCA's legacy 3DES format are re-encrypted as PKCS#8.

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
  CRLs and templates in their formats. Select several items in a list to
  export them together; text formats can be shown and copied.
- Import PEM (any number of blocks), DER, PKCS#7, PKCS#8, PKCS#12, SSH
  keys, PVK, CRLs and XCA templates, from files or pasted text. Everything
  found is listed for review, with names that can be changed, before
  anything is stored. As in XCA, existing items are skipped, a private key
  completes a stored public key and an imported CRL adds its revocations to
  the CA.
- Download a whole database as a ZIP of PEM files (XCA's "Dump database").

**Tools**

- Diffie-Hellman parameters (1024 to 4096 bit), generated in the background.
- An OID resolver.

| XCA database                        | go-ca                                          |
| ----------------------------------- | ---------------------------------------------- |
| schema 8 (XCA 2.7 and later)        | supported                                      |
| schema 5 to 7 (XCA 2.x up to 2.6)   | upgraded to 8 on first login, after a backup   |
| schema below 5, pre-2.0 format      | refused                                        |
| newer schema                        | refused until supported                        |

XCA 2.6 still opens a database upgraded to schema 8.

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
(schema upgrade, 3DES key conversion, database password change), using
SQLite's `VACUUM INTO`, which copies within one read transaction.

Two go-ca processes cannot open the same database (`flock` on the `.lock`
file). Desktop XCA can keep the same file open: go-ca polls `MAX(items.stamp)`
and reloads when XCA changes something.

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

`testdata/xdb/` holds databases generated with the real XCA command line and
crafted variants (old password hashes, a legacy 3DES key, a key with its own
password, schema 8 and 9, a pre-2.0 file). Regenerate them with
`testdata/gen/gen-fixtures.sh` (needs `xca`, `openssl`, `sqlite3`, `perl`).
`testdata/gen/check-with-xca.sh` writes databases with go-ca's code and has
the XCA command line list them, sign CRLs with go-ca CAs and over
revocations go-ca recorded, and add a key.
`testdata/gen/check-export-with-xca.sh` exports a hierarchy in every format
and lets the XCA command line import each file.

Third-party code: [htmx](https://htmx.org) 2.0.11 (BSD Zero Clause License,
`internal/web/static/htmx.LICENSE`).
