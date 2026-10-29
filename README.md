# OpenKCA

**Your own certificate authority, in one binary.**

OpenKCA (Open Key and Certificate Authority, formerly go-ca) runs a complete
PKI from your browser: X.509 certificates, SSH keys and OpenPGP keys. It is a
single Go binary with no dependencies and no C compiler, serving HTTPS out of
the box. Coming from [XCA](https://github.com/chris2511/xca)? Drop in your
`.xdb` file and it is imported on first login.

## Why OpenKCA

- **Pick a purpose, get a certificate.** Root CA, intermediate, TLS server,
  S/MIME, code signing, SSH or OpenPGP: sane defaults, live preview. The full
  XCA-style editor is there when you need it.
- **Post-quantum ready.** ML-DSA, SLH-DSA, ML-KEM and composite keys sit next
  to RSA, ECDSA and EdDSA.
- **CA work on autopilot.** CRLs are signed and published over HTTP
  automatically, with an OpenSSL index for OCSP.
- **Speaks every format.** PEM, DER, PKCS#7/8/12, OpenSSH, PuTTY, OpenPGP,
  JWK and more, both in and out.
- **Locked down.** Argon2id and AES-256-GCM encrypted databases that open
  with passwords, YubiKeys, passkeys or a one-time backup code, a trash can
  and an append-only audit log.

## Get it

Grab a binary for Linux, Windows or macOS (Apple silicon) from the
[releases page](https://github.com/mailsvb/openkca/releases), the Windows
installer (`.msi`, runs OpenKCA as a service;
[details](docs/CONFIGURATION.md#windows-msi)), or install the rpm on
openSUSE and SLES (Fedora and RHEL: see the
[package page](https://mailsvb.github.io/openkca/)):

```sh
sudo zypper addrepo https://mailsvb.github.io/openkca/rpm/openkca.repo
sudo zypper refresh && sudo zypper install openkca
sudo cat /etc/openkca/initial-password   # → https://<host>:9443/
sudo openkca setup                       # optional: HTTP/HTTPS, ports, password
```

The service is configured in `/etc/openkca/config.yaml`
([details](docs/CONFIGURATION.md#rpm-package)).

## Run it

```sh
./openkca                # → https://<host>:9443/
```

The first start asks whether to serve HTTPS or plain HTTP behind a TLS
proxy, for the web UI port (9443), the CRL port (9080) and the server
password, and writes `config.yaml` next to the binary. Run
`./openkca setup` to change them later. Every setting is explained in
`config.example.yaml`.

> **Security note:** a database password in `config.yaml` is stored in plain
> text and keeps that CA's keys unlocked while OpenKCA runs. Set one only for
> databases that need unattended CRL signing, and keep the file `chmod 600`.

## Learn more

| Document | Covers |
| --- | --- |
| [Features](docs/FEATURES.md) | everything OpenKCA does, database format |
| [Configuration](docs/CONFIGURATION.md) | all settings, CRL publishing, data folder |
| [Security](docs/SECURITY.md) | password handling, encryption, web hardening |
| [Development](docs/DEVELOPMENT.md) | building, releases, translations, tests |

## License

Bundles [htmx](https://htmx.org) (0BSD),
[ProtonMail/go-crypto](https://github.com/ProtonMail/go-crypto) and
[cloudflare/circl](https://github.com/cloudflare/circl) (both BSD-3-Clause);
details in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md#third-party-code).
