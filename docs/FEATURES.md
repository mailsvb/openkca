# Features

[← Back to README](../README.md)

**Databases**

- Lists every OpenKCA database (`.okca`) and every XCA database waiting to be
  imported (`.xdb`) in the data folder; create new databases and upload
  existing ones (either kind) from the start page. Several databases can
  be open at the same time, each with its own unlock methods.
- Unlock methods: a database opens with any of its passwords (up to 5, at
  least 8 characters each), security keys such as a YubiKey and passkeys
  (up to 16 together, through WebAuthn with the PRF extension, when
  `general.webauthn.rp_id` is set) or its one-time backup code. Each
  method wraps the same data key, so methods are added, renamed, changed
  and removed without touching a private key. Changes need a confirmation
  with an existing method in the last 5 minutes (logging in counts). The
  last password cannot be removed; the one the configuration file uses
  cannot be changed or removed. Until a backup code exists, every database
  page shows a notice. Removing or changing a method deletes the backups,
  which would still open with it. "Replace the data key" makes a new data
  key, re-seals every key and keeps only the password typed with it: the
  way to lock out a lost key or a leaked password for good.
- Shows keys, certificate signing requests, certificates (as a tree under
  their issuers), templates and revocation lists, with search, a column
  chooser and expiry colours, plus XCA's shared options.
- An XCA database is imported at its first
  login into a new OpenKCA database of the same name, with a progress page
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
  unlock method changes, trash, failed and successful logins) with time and
  client address, never secrets. It is shown per database and per item.
- Private keys are stored with envelope encryption. A random 256-bit data
  key seals every private key with AES-256-GCM, bound to the key's public
  key. Each unlock method wraps that data key with AES-256-GCM under its
  own key: a password's is stretched with Argon2id (256 MiB, 3 passes by
  default, adjustable per database for passwords set later), a security
  key's or passkey's comes from its PRF output and the backup code's from
  its 128 random bits, both through HKDF-SHA256. The wrap is bound to the
  method's ID, type and parameters. Unwrapping the data key is the check:
  no password hash is stored. A key with its own password is sealed with a
  key derived from that password instead.
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
  ML-DSA-87+Ed448 with ML-KEM-1024+X448; they are OpenKCA's Composite ML-DSA
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
  (see [CRL publishing](CONFIGURATION.md#crl-publishing)). New certificates point to their
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
  from version 3.5 on, and nothing outside OpenKCA reads composite keys yet.
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
  RC2; a scheme OpenKCA cannot decrypt, such as Camellia, is reported as
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

## Database format

| Database                                | OpenKCA                                       |
| --------------------------------------- | --------------------------------------------- |
| OpenKCA `.okca` (schema 1)              | supported                                     |
| older OpenKCA `.okca` schema (none yet) | upgraded in place when opened, after a backup |
| XCA schema 5 to 8 (XCA 2.x and later)   | imported into a new `.okca` on first login    |
| XCA schema below 5, pre-2.0 format      | refused                                       |
| newer XCA or OpenKCA schema             | refused until supported                       |

OpenKCA was called go-ca until version 0.11.0. Its `.gca` files from
those development versions are not supported; import the databases again
from XCA. From schema 1 on, every schema change comes with a migration step
(`internal/db`, `steps`) that upgrades older databases when they are
opened.

An OpenKCA database is an SQLite file with its own schema (`internal/db`)
and SQLite's application ID `okc1`: every item with a UUID (version 7)
next to its row ID, DER objects as BLOBs with SHA-256
fingerprints, links as foreign keys, templates as JSON, a trash and an
append-only audit table. The `unlock_methods` table holds one wrapped data
key per unlock method (and, for security keys and passkeys, the WebAuthn
credential and PRF salt); the `argon2id` setting is the cost for new
passwords. Private keys and wraps are sealed by `internal/vault`. The
schema was reset to 1 for 0.12.0: databases from earlier development
versions are listed as invalid. Reading XCA's schema is `internal/xcaimport`'s job only,
and it opens `.xdb` files read-only. Templates and the database dump can
still be exported in XCA's formats.
