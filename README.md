# OpenKCA

**Open Key and Certificate Authority** (formerly go-ca) – a web based
certificate authority for X.509 certificates, SSH and OpenPGP keys. One
statically linked Go binary serves the UI over HTTPS. Existing
[XCA](https://github.com/chris2511/xca) databases are imported on first use.

## Features

- Keys, requests, certificates, templates and CRLs – created by purpose
  (root/intermediate CA, TLS, S/MIME, code signing, SSH, OpenPGP) or in a
  full XCA-style editor
- Classic and post-quantum algorithms (RSA, ECDSA, EdDSA, ML-DSA, SLH-DSA,
  ML-KEM, composite keys)
- CA operations: revocation, renewal, automatic CRL signing and publishing
  over HTTP, OpenSSL index for OCSP
- Import and export in all common formats (PEM, DER, PKCS#7/8/12, OpenSSH,
  PuTTY, OpenPGP, JWK, …)
- Encrypted databases (Argon2id, AES-256-GCM), trash and audit log

## Download

Binaries for Linux, Windows and macOS are on the
[releases page](https://github.com/mailsvb/openkca/releases).

## Quick start

```sh
./openkca set-password   # put the printed hash into config.yaml
./openkca                # serves https://<host>:8443/
```

All settings live in one YAML file: `config.yaml` next to the binary, or the
file given with `--config`. `config.example.yaml` describes every setting.

```yaml
general:
  data_dir: /srv/openkca
  password_hash: "$argon2id$…"
```

## More

Building, releases, the full configuration reference, CRL publishing, the
data folder, security model, translations and tests are described in
[DEVELOPMENT.md](DEVELOPMENT.md).
