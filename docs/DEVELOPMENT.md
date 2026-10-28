# Development

[← Back to README](../README.md)

## Build

Requires Go 1.27 or later (the toolchain is downloaded automatically by older
`go` commands). No C compiler is needed:

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(cat VERSION)" -o openkca ./cmd/openkca
```

## Versions and releases

`VERSION` holds the current version (semantic versioning, `X.Y.Z`).

- Every push runs `.github/workflows/build.yml`, which builds all platforms
  as `<VERSION>-dev-<yyyyMMdd>-<HHmmss>` (UTC) and keeps the archives and
  unsigned rpm packages (version `<VERSION>~dev.<yyyyMMdd>.<HHmmss>`) as
  artifacts of the workflow run.
- Running the same workflow manually (Actions → Build → Run workflow, on
  `main`) makes an official release: enter a version `X.Y.Z`, or leave it
  empty to increase the fix number of `VERSION` by one. The release is
  tested, built, tagged `v<version>` and published as a GitHub release with
  the archives, the signed rpm packages and their SHA-256 checksums;
  `VERSION` on `main` is then set to the released version.
- After a release the rpm repository on GitHub Pages
  (`https://mailsvb.github.io/openkca/`) is rebuilt from the rpms of the
  five newest releases by `packaging/repo/build.sh`, with `repomd.xml`
  signed.

The rpm package is described by `packaging/linux/nfpm.yaml` (built with
[nfpm](https://nfpm.goreleaser.com)): the binary, the `openkca` systemd
service running as the `openkca` user, the configuration
`packaging/linux/config.yaml` as `/etc/openkca/config.yaml` and the data
folder `/var/lib/openkca`. On the first install the postinstall script sets
a random server password, kept in `/etc/openkca/initial-password`, and
starts the service.

Releases need two repository secrets, the same as go-fs's:
`PACKAGE_SIGNING_KEY`, the armored PGP private key
(`gpg --armor --export-secret-keys <key id>`), and
`PACKAGE_SIGNING_PASSPHRASE` if the key has one. GitHub Pages must be set to
deploy from GitHub Actions (Settings → Pages → Source).
- `.github/workflows/test.yml` checks formatting and runs `go vet` and
  `go test -race` on every push to `main`.

## Translations

The UI is English, but no template contains literal text: every string comes
from `internal/i18n/locales/en.json` (plural forms supported). To add a
language, copy `en.json` to e.g. `de.json` and translate the values; the
browser's `Accept-Language` selects it, falling back to English. A test fails
the build on untranslated text in a template or a missing message key.

## Testing

```sh
go test -race ./...
```

Some tests compare against the `openssl`, `ssh-keygen`, `puttygen`
(`putty-tools` on Debian and Ubuntu) and `gpg` command lines and are
skipped where those are missing. The OpenPGP tests have gpg import
OpenKCA's keys, encrypt to them, verify their signatures and import their
revocation certificates, and read keys gpg generated in each export form.

`testdata/xdb/` holds databases generated with the real XCA command line and
crafted variants (old password hashes, a legacy 3DES key, a key with its own
password, schema 8 and 9, a pre-2.0 file); the tests import them into
OpenKCA databases. Regenerate them with `testdata/gen/gen-fixtures.sh` (needs
`xca`, `openssl`, `sqlite3`, `perl`).
`testdata/gen/check-export-with-xca.sh` exports a hierarchy in every format
and lets the XCA command line import each file, except OpenKCA's own SSH
and OpenPGP formats.

## Third-party code

Third-party code: [htmx](https://htmx.org) 2.0.11 (BSD Zero Clause License,
`internal/web/static/htmx.LICENSE`);
[ProtonMail/go-crypto](https://github.com/ProtonMail/go-crypto) for
OpenPGP and [cloudflare/circl](https://github.com/cloudflare/circl), which
it uses (both BSD 3-Clause License);
[go-webauthn/webauthn](https://github.com/go-webauthn/webauthn) for security
keys and passkeys (BSD 3-Clause License).
