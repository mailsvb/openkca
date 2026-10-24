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
- An XCA database is imported at its first
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

- Revoke and unrevoke certificates, manage a CA's revocations (of
  certificates in the database, live or in the trash), set the CRL interval
  and default template, generate CRLs with XCA's options or with one click,
  and renew certificates (new or same serial, optionally revoking or
  deleting the old one).
- CRLs and CA certificates are published over plain HTTP and, in
  databases kept open in the background, CRLs are signed automatically
  (see [CRL publishing](#crl-publishing)). New certificates point to their
  issuer's published CRL and certificate (CDP and AIA) when the user keeps
  the boxes checked.
- An OpenSSL `ca` style index per CA in
  `<data-dir>/ca/<database>/<authority ID>/index.txt` (plus `index.txt.attr`),
  kept current and usable directly with `openssl ocsp -index`. Every item
  has a UUID that never changes. A CA's folder is named after its authority
  ID: its certificate's UUID for a new CA, taken over by a renewal with the
  same subject and key, so the folder survives renaming, renewing and a trip
  through the trash. A renewed CA certificate still live gets a new
  authority ID; one in the trash keeps its ID and cannot be restored while
  the renewal holding it is live. The item page shows the UUID and, for a
  CA, its authority ID and folder.

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
| go-ca `.gca` (schema 1)                   | supported                                      |
| older go-ca `.gca` schema (none yet)      | upgraded in place when opened, after a backup  |
| XCA schema 5 to 8 (XCA 2.x and later)     | imported into a new `.gca` on first login      |
| XCA schema below 5, pre-2.0 format        | refused                                        |
| go-ca's former XCA based `.xdb` format    | refused                                        |
| newer XCA or go-ca schema                 | refused until supported                        |

The go-ca schema was reset to 1 during development: `.gca` files from
earlier development versions are not supported; import them again from
XCA. From schema 1 on, every schema change comes with a migration step
(`internal/gcadb`, `steps`) that upgrades older databases when they are
opened.

A go-ca database is an SQLite file with its own schema (`internal/gcadb`)
and SQLite's application ID `gca1`: every item with a UUID (version 7)
next to its row ID, DER objects as BLOBs with SHA-256
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

All settings are in a YAML configuration file. go-ca reads `config.yaml`
next to its executable, or the file given with `--config`, the only command
line option. `config.example.yaml` describes every setting.

```sh
# once: create a server password hash and put the printed line into the
# general section of config.yaml
./go-ca set-password

# serve on https://<host>:8443/ (the listen address is in the config)
./go-ca                          # config.yaml next to the executable
./go-ca --config /etc/go-ca/config.yaml

# print the version
./go-ca version
```

```yaml
general:
  data_dir: /srv/xca
  listen: ":8443"
  password_hash: "$argon2id$v=19$m=65536,t=3,p=2$…"
crl:
  listen: ":8080"
  base_urls:
    - http://pki.example.org
    - http://pki.lan:8080
databases:
  - name: Home Lab CA
    type: file
    path: homelab.gca
    password: "…"
```

| `general` key    | Default  | Meaning                                                          |
| ---------------- | -------- | ---------------------------------------------------------------- |
| `data_dir`       | required | folder with the `.gca` and `.xdb` files, rescanned on every page load |
| `listen`         | `:8443`  | listen address (all interfaces by default)                       |
| `tls_cert`       |          | PEM certificate; without it a self-issued certificate is used    |
| `tls_key`        |          | PEM key for `tls_cert`                                           |
| `idle_timeout`   | `30m`    | idle timeout of server and database sessions                     |
| `max_upload_mb`  | `256`    | largest upload (database file or items to import), in MB         |
| `password_hash`  | required | argon2id hash of the server password, from `go-ca set-password`  |

Relative paths (`data_dir`, `tls_cert`, `tls_key`) are relative to the
configuration file's folder; unknown keys are an error.

| `crl` key   | Default | Meaning                                                                  |
| ----------- | ------- | ------------------------------------------------------------------------ |
| `listen`    | `:8080` | plain HTTP address for CRLs and CA certificates; `""` turns it off       |
| `base_urls` |         | `http://` URLs under which that server is reachable, in the order clients should try them |

### Databases

Each entry of `databases` names one go-ca database:

| Key        | Meaning                                                                    |
| ---------- | -------------------------------------------------------------------------- |
| `name`     | the name shown in the web UI (unique)                                       |
| `type`     | `file`, the only type: a `.gca` file                                        |
| `path`     | the file, relative to `data_dir`; may be in a subfolder, never outside it   |
| `password` | optional: the database password, to keep the database open in the background |

A database with a `password` is opened when go-ca starts and stays open
with its data key unlocked, so that go-ca can do CA work on it on its own.
go-ca refuses to start when such a database is missing, locked by another
process or the password is wrong. Logging into it in the web UI still needs
the database password; the web session unlocks its own copy of the key.
Its password cannot be changed in the web UI, since that would replace the
data key under the running background session: remove the password from
the configuration, restart, change it, put the new one in and restart
again. Keep a configuration file with passwords readable by its owner only;
go-ca warns at startup otherwise.

A database without `password` is only listed under its name. Configured
databases come first on the login page; all other `.gca` and `.xdb` files
directly in the data folder are listed after them and work as before.
A configured name (the file name without `.gca`) is taken for new and
uploaded databases. Only `.gca` files can be configured: open an XCA
database once in the web UI to convert it, then configure the `.gca` file.

Upgrading from the command line options: `--data-dir`, `--listen`,
`--tls-cert`, `--tls-key`, `--idle-timeout` and `--max-upload` became
`data_dir`, `listen`, `tls_cert`, `tls_key`, `idle_timeout` and
`max_upload_mb`. The server password hash moved from
`<data-dir>/.go-ca/server-password` into `password_hash`: copy it over, or
run `go-ca set-password` again.

### CRL publishing

Every CA (root and subordinate) publishes two files, addressed by its
authority ID, which survives renaming and renewing with the same key:

| URL                        | Content                                        |
| -------------------------- | ---------------------------------------------- |
| `/<authority ID>.crl`      | the CA's newest CRL (DER, `application/pkix-crl`) |
| `/<authority ID>.crt`      | the CA certificate (DER, `application/pkix-cert`) |
| `/<authority ID>.pem`      | the CA certificate (PEM)                       |

The plain HTTP server (`crl.listen`) answers only these, with ETag,
Last-Modified and a 5 minute `max-age`, for the CAs of all databases,
open or not; anything else is 404. Only the last path element counts, so
a base URL may have a path (`http://host/pki`) whether or not a proxy
strips it. The files are kept in the CA's folder (`ca.crt`, `crl.der`)
and only replaced, never removed: a CA in the trash keeps serving them.
Behind a reverse proxy or an ingress on port 80, the base URLs need no
port; otherwise include `:8080`. CRLs are served over HTTP, not HTTPS,
as RFC 5280 recommends, which avoids a validation loop.

The CA page lists its URLs below every base URL. With base URLs
configured, the editor, the purpose profiles and the renew dialog offer
"CRL distribution point" and "CA issuer (AIA)", checked by default:

- **CDP:** all base URLs, as mirrors of one CRL in one distribution point,
  which clients try in order. Put first the address most clients reach.
- **AIA:** one `caIssuers` entry per base URL.
- Free-text entries in the editor are added after them (one distribution
  point each, as OpenSSL does); entries naming the same URLs are dropped.
- Templates store both choices and set the boxes when applied (XCA's
  template export leaves them out).
- Renewing with the boxes checked replaces earlier published URLs with
  the current ones and keeps other entries; unchecked, the extensions are
  copied unchanged.
- Self-signed certificates and requests never get them.

**What is on a CRL.** A revocation is listed while its certificate is in
the database (live or in the trash) and until 30 days after it expired.
The certificate's expiry is recorded with the revocation, so a revoked
certificate purged from the trash stays listed until then. Only
certificates the CA issued that are in the database can be revoked;
revocations without a known certificate (from older versions) are kept
but not published, as the revocations page shows. A generated CRL
replaces the CA's previously generated one (the CRL number keeps
counting); imported CRLs stay.

**Automatic signing.** In databases kept open in the background, go-ca
signs a new CRL for every CA whose key is protected by the database
password: a first one, after every change of its revocations
(revoke, unrevoke, edit, renewal with revocation, entries aging out) and
once half of the current CRL's validity has passed. A CA key with its own
password, and every database without a configured password, is signed
by hand: the CA page's "Re-sign CRL now" uses the CA's defaults, "Generate
CRL…" offers XCA's options. The CA page says which applies.

**CRL interval.** New root CAs get 180 days, new subordinate CAs 7 days
(database options; each CA's value can be changed on its page). Clients
cache a CRL until its next update, so a revocation reaches them only
then: keep the interval of CAs that issue end-entity certificates short.

**Expiry monitoring.** go-ca checks every published CRL hourly, logs a
warning 7 days before its next update and an error once it has passed,
and shows the same on the databases page. An expired CRL makes many
clients reject every certificate below that CA.

Without `tls_cert`, go-ca creates a self-signed certificate (CN `go-ca`,
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
    ├── tls.crt, tls.key  self-issued certificate
    └── backup/           <name>.<yyyyMMddHHmmss>.gca
/srv/xca/ca/<database>/<authority ID>/   per-CA folder:
    index.txt, index.txt.attr             certificate index (openssl ocsp -index)
    ca.crt, crl.der                       published CA certificate and newest CRL
```

A backup is written right after an import, before a database of an
older schema is upgraded on opening, and before every
change that rewrites a whole database (database password or Argon2id
cost change),
using SQLite's `VACUUM INTO`, which copies within one read transaction.
How many are kept is a database option: at most 10 and none older than
90 days by default (the newest always stays). After a password change
every older backup is deleted, since they still open with the old
password, and a new one is written.

Two go-ca processes cannot open the same database (`flock` on the `.lock`
file); a database kept open in the background holds its lock as long as
go-ca runs.

## Security

- One server password protects the whole UI; database passwords still apply
  after it. Both logins are rate limited, and at most two Argon2id runs
  happen at a time, so parallel login attempts cannot exhaust memory.
- New database passwords need at least 8 characters.
- A database configured with a `password` has its data key in memory for
  as long as go-ca runs, and the password is stored in plain text in the
  configuration file: anyone who can read that file or the process memory
  can sign with its CA keys. Configure passwords only for databases that
  need unattended CA work. Keys with their own password stay locked.
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
go-ca databases. Regenerate them with `testdata/gen/gen-fixtures.sh` (needs
`xca`, `openssl`, `sqlite3`, `perl`).
`testdata/gen/check-export-with-xca.sh` exports a hierarchy in every format
and lets the XCA command line import each file, except go-ca's own SSH
and OpenPGP formats.

Third-party code: [htmx](https://htmx.org) 2.0.11 (BSD Zero Clause License,
`internal/web/static/htmx.LICENSE`);
[ProtonMail/go-crypto](https://github.com/ProtonMail/go-crypto) for
OpenPGP and [cloudflare/circl](https://github.com/cloudflare/circl), which
it uses (both BSD 3-Clause License).
