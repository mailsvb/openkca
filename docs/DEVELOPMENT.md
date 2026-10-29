# Development

[← Back to README](../README.md)

## Build

Requires Go 1.27 or later (the toolchain is downloaded automatically by older
`go` commands). No C compiler is needed:

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(cat VERSION)" -o openkca ./cmd/openkca
```

A package build also sets the configuration file its service reads, so that
`openkca setup` finds it without `--config` (`$VAR` and `${VAR}` are
expanded at run time):

```sh
-X github.com/mailsvb/openkca/internal/config.packagedPath=/etc/openkca/config.yaml      # rpm
-X 'github.com/mailsvb/openkca/internal/config.packagedPath=${ProgramData}\OpenKCA\config.yaml'  # MSI
```

## Versions and releases

`VERSION` holds the current version (semantic versioning, `X.Y.Z`).

- Builds run only manually: `.github/workflows/build.yml` (Actions → Build →
  Run workflow, on `main`) makes an official release. Enter a version
  `X.Y.Z` to build exactly that version, or leave it empty to increase the
  fix number of `VERSION` by one. The release is
  tested, built, tagged `v<version>` and published as a GitHub release with
  the archives (Linux amd64 and arm64, Windows amd64, macOS arm64), the
  signed rpm packages, the Windows MSI and their SHA-256 checksums;
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
a random server password, kept in `/etc/openkca/initial-password`,
starts the service and points to `openkca setup` for other ports and
another password (an rpm scriptlet cannot ask questions).

The Windows MSI is described by `packaging/windows/openkca.wxs` and
`ui.wxs` and built with [WiX](https://wixtoolset.org) v5 on a Windows
runner: `openkca.exe` in `C:\Program Files\OpenKCA`, run as the `OpenKCA`
service (LocalSystem) with its configuration and data in
`C:\ProgramData\OpenKCA`, which only SYSTEM and Administrators can open.
The first install asks for HTTPS, the TLS files, the ports and the server
password and runs `openkca setup` with them (a deferred custom action that
keeps its command line out of the log); upgrades skip the dialog and keep
the configuration. The MSI is not code-signed, so SmartScreen warns about
it. Build it on Windows with:

```sh
dotnet tool install --global wix --version 5.0.2
for ext in UI Util Firewall; do wix extension add --global WixToolset.$ext.wixext/5.0.2; done
wix build packaging/windows/openkca.wxs packaging/windows/ui.wxs -arch x64 \
  -d Version=$(cat VERSION) -d BinDir=<folder with openkca.exe> -d RepoDir=. \
  -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext -ext WixToolset.Firewall.wixext \
  -o openkca.msi
```

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
