# go-ca

A web UI for [XCA](https://github.com/chris2511/xca) certificate databases,
written in Go. One statically linked binary serves the UI over HTTPS and works
directly on XCA's SQLite `.xdb` files, so the same file keeps opening in
desktop XCA.

## Status

**Phase 2 of 6: databases.** go-ca opens XCA databases and shows keys,
certificate signing requests, certificates (as a tree under their issuers),
templates, revocation lists and the shared options. It decrypts every private
key on request, including keys with their own password. On the login page you
can create new databases and import existing `.xdb` files.

Opening an older database (schema 5 to 7, written by XCA 2.6 or earlier)
first saves a backup and then upgrades it to schema 8, as XCA 2.7 and later
do; XCA 2.6 still opens the upgraded file. Private keys still in XCA's legacy
3DES format are re-encrypted as PKCS#8 at the same time. Apart from that and
upgrading an old password hash after a correct login, nothing is written yet.

Later phases add key and certificate generation, CA operations (revocation,
CRLs, renewal), templates and every import and export format.

| XCA database                        | go-ca                                          |
| ----------------------------------- | ---------------------------------------------- |
| schema 8 (XCA 2.7 and later)        | supported                                      |
| schema 5 to 7 (XCA 2.x up to 2.6)   | upgraded to 8 on first login, after a backup   |
| schema below 5, pre-2.0 format      | refused                                        |
| newer schema                        | refused until supported                        |

## Build

Requires Go 1.26 or later (the toolchain is downloaded automatically by older
`go` commands). No C compiler is needed:

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o go-ca ./cmd/go-ca
```

## Run

```sh
# once: set the server password (stored as an argon2id hash)
./go-ca set-password --data-dir /srv/xca

# serve all *.xdb files in the folder on https://<host>:8443/
./go-ca --data-dir /srv/xca
```

| Flag             | Default  | Meaning                                                          |
| ---------------- | -------- | ---------------------------------------------------------------- |
| `--data-dir`     | required | folder with the `.xdb` files, rescanned on every page load       |
| `--listen`       | `:8443`  | listen address (all interfaces by default)                       |
| `--tls-cert`     |          | PEM certificate; without it a self-issued certificate is used    |
| `--tls-key`      |          | PEM key for `--tls-cert`                                         |
| `--idle-timeout` | `30m`    | idle timeout of server and database sessions                     |
| `--max-upload`   | `256`    | largest database file accepted for import, in MB                 |

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
```

A backup is written before every change that rewrites a whole database
(schema upgrade, 3DES key conversion and, from phase 3, a database password
change), using SQLite's `VACUUM INTO`, which copies within one read
transaction.

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

Third-party code: [htmx](https://htmx.org) 2.0.4 (BSD Zero Clause License,
`internal/web/static/htmx.LICENSE`).
