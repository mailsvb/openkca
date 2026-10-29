# Configuration

[← Back to README](../README.md)

All settings are in a YAML configuration file. OpenKCA reads `config.yaml`
next to its executable, or the file given with `--config`, the only command
line option of `serve`. The rpm and MSI builds read their package's file
instead (`/etc/openkca/config.yaml`, `C:\ProgramData\OpenKCA\config.yaml`).
`config.example.yaml` describes every setting.

```sh
# serve on https://<host>:9443/ (the listen address is in the config)
./openkca                          # config.yaml next to the executable
./openkca --config /etc/openkca/config.yaml

# ask for HTTPS or plain HTTP, the TLS certificate, the web UI port, the
# CRL port and the server password and write them into the config (a new
# one if there is none)
./openkca setup [--config FILE]

# the same without questions, for scripts and installers
echo "$PASSWORD" | ./openkca setup --https=false --port 8080 --password-stdin

# print a server password hash for password_hash
./openkca set-password

# print the version
./openkca version
```

Started in a terminal without a configuration file, or with one without
`password_hash`, OpenKCA runs `setup` first and then serves. Without a
terminal (as a service) it stops with an error instead. `setup` changes
only the lines it asks about and keeps everything else in the file,
comments included. When it changed the configuration of the rpm's or the
MSI's service it offers to restart it; otherwise restart OpenKCA yourself.

| `setup` flag            | Meaning                                                    |
| ----------------------- | ---------------------------------------------------------- |
| `--https=true\|false`   | serve HTTPS, or plain HTTP behind a TLS proxy              |
| `--port N`              | web UI port                                                |
| `--crl-port N`          | CRL server port, `0` turns it off                          |
| `--tls-cert F --tls-key F` | PEM certificate and key, checked to be a pair; both empty: self-issued |
| `--copy-tls`            | copy them next to the configuration (`tls.crt`, `tls.key`) |
| `--password-stdin`      | read the server password from stdin                        |
| `--password P`          | the server password (visible to other processes); empty keeps the current one |

With any of these flags `setup` asks nothing; what is not given keeps its
current value.

```yaml
general:
  data_dir: /srv/xca
  listen: ":9443"
  password_hash: "$argon2id$v=19$m=65536,t=3,p=2$…"
crl:
  listen: ":9080"
  base_urls:
    - http://pki.example.org
    - http://pki.lan:9080
databases:
  - name: Home Lab CA
    type: file
    path: homelab.okca
    password: "…"
```

| `general` key    | Default  | Meaning                                                          |
| ---------------- | -------- | ---------------------------------------------------------------- |
| `data_dir`       | required | folder with the `.okca` and `.xdb` files, rescanned on every page load |
| `listen`         | `:9443`  | listen address (all interfaces by default)                       |
| `https`          | `true`   | `false` serves plain HTTP, for a TLS proxy in front (below)      |
| `tls_cert`       |          | PEM certificate; without it a self-issued certificate is used    |
| `tls_key`        |          | PEM key for `tls_cert`                                           |
| `trusted_proxies`|          | IP addresses or CIDR ranges of reverse proxies whose `X-Forwarded-For` and `X-Forwarded-Proto` count |
| `idle_timeout`   | `30m`    | idle timeout of server and database sessions                     |
| `max_upload_mb`  | `256`    | largest upload (database file or items to import), in MB         |
| `password_hash`  | required | argon2id hash of the server password, from `openkca setup` or `openkca set-password` |
| `webauthn`       |          | security keys and passkeys as unlock methods (below)             |

| `webauthn` key | Default | Meaning |
| -------------- | ------- | ------- |
| `rp_id`   |  | the host name users open OpenKCA with (a domain name, not an IP address); without it security keys and passkeys are off |
| `rp_name` | `OpenKCA` | the name authenticators show |
| `origins` | `https://<rp_id>` and `https://<rp_id>:<port of listen>` (with `https: false` only `https://<rp_id>`) | `https://` origins on `rp_id` or a subdomain that may use them |

Security keys and passkeys are bound to `rp_id`: one added under
`ca.example.org` does not work when OpenKCA is opened by another name or
an IP address, so every database keeps at least one password. Browsers
refuse WebAuthn on a certificate warning, so the browser must trust
OpenKCA's TLS certificate (for example one issued by one of your CAs).

Relative paths (`data_dir`, `tls_cert`, `tls_key`) are relative to the
configuration file's folder; unknown keys are an error.

| `crl` key   | Default | Meaning                                                                  |
| ----------- | ------- | ------------------------------------------------------------------------ |
| `listen`    | `:9080` | plain HTTP address for CRLs and CA certificates; `""` turns it off       |
| `base_urls` |         | `http://` URLs under which that server is reachable, in the order clients should try them |

Before 0.13.0 the defaults were `:8443` and `:8080`. A configuration that
leaves out `general.listen` or `crl.listen` moves to the new ports; set
`crl.listen: ":8080"` to keep serving the CRL URLs already written into
certificates with that port. The rpm configuration sets both explicitly.

## Behind a TLS proxy

With `https: false` OpenKCA serves the web UI over plain HTTP and leaves TLS
to a reverse proxy (nginx, Caddy, Traefik, a Cloudflare Tunnel, ...). List
the proxy in `trusted_proxies`:

```yaml
general:
  listen: "127.0.0.1:9443"   # only the proxy on this host reaches it
  https: false
  trusted_proxies: ["127.0.0.1"]
```

For requests from a trusted proxy the client is the rightmost address in
`X-Forwarded-For` that is not a trusted proxy itself, which the login rate
limit and the audit log use, and the request counts as encrypted when the
first `X-Forwarded-Proto` is `https`: then the cookies are `Secure` and
HSTS is sent. Forwarding headers from anyone else are ignored. Without
`trusted_proxies` every client looks like the proxy: one client's failed
logins lock out everyone for a minute, and OpenKCA warns at startup.

OpenKCA can be opened over plain HTTP directly as well (the cookies are
then not `Secure`, and the login page warns), but the server password and
the session then travel in clear text: do that only on a trusted network
or `localhost`.

## TLS certificate

Without `tls_cert`, OpenKCA creates a self-signed certificate (CN `OpenKCA`,
SANs `localhost`, `127.0.0.1`, `::1`, valid 365 days) on first start, reuses it
and replaces it automatically once it has expired. Browsers on other machines
will warn about the name until you pass a certificate for the real host name.

## Databases

Each entry of `databases` names one OpenKCA database:

| Key        | Meaning                                                                    |
| ---------- | -------------------------------------------------------------------------- |
| `name`     | the name shown in the web UI (unique)                                       |
| `type`     | `file`, the only type: a `.okca` file                                        |
| `path`     | the file, relative to `data_dir`; may be in a subfolder, never outside it   |
| `password` | optional: one of the database's passwords, to keep it open in the background |

A database with a `password` is opened when OpenKCA starts and stays open
with its data key unlocked, so that OpenKCA can do CA work on it on its own.
OpenKCA refuses to start when such a database is missing, locked by another
process or the password is wrong. Logging into it in the web UI still needs
one of its unlock methods; the web session unlocks its own copy of the key.
The password the configuration file uses cannot be changed or removed in
the web UI, and the data key cannot be replaced there, since that would
leave the running background session behind: remove the password from the
configuration, restart, change it, put the new one in and restart again.
Other unlock methods can be added and removed as usual. Keep a
configuration file with passwords readable by its owner only; OpenKCA
warns at startup otherwise.

A database without `password` is only listed under its name. Configured
databases come first on the login page; all other `.okca` and `.xdb` files
directly in the data folder are listed after them and work as before.
A configured name (the file name without `.okca`) is taken for new and
uploaded databases. Only `.okca` files can be configured: open an XCA
database once in the web UI to convert it, then configure the `.okca` file.

## CRL publishing

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
port; otherwise include `:9080`. CRLs are served over HTTP, not HTTPS,
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

**Automatic signing.** In databases kept open in the background, OpenKCA
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

**Expiry monitoring.** OpenKCA checks every published CRL hourly, logs a
warning 7 days before its next update and an error once it has passed,
and shows the same on the databases page. An expired CRL makes many
clients reject every certificate below that CA.

## rpm package

The rpm package (see the [README](../README.md#get-it)) runs OpenKCA as the
`openkca` systemd service, under the `openkca` user:

| Path                              | What                                              |
| --------------------------------- | ------------------------------------------------- |
| `/etc/openkca/config.yaml`        | configuration, kept as it is on updates           |
| `/etc/openkca/initial-password`   | server password set at the first install (root only) |
| `/var/lib/openkca`                | data folder                                       |
| `/usr/share/doc/openkca/`         | `config.example.yaml` and these documents         |

Restart the service after changing the configuration:
`sudo systemctl restart openkca`. To change the ports or the server
password, or to switch to plain HTTP behind a TLS proxy, run
`sudo openkca setup`, which finds `/etc/openkca/config.yaml` by itself and
offers to restart the service; a new password also deletes
`initial-password`. TLS files given to the service must be readable by the
`openkca` user and must not be under `/home` or `/root`
(`ProtectHome=yes`). The service may only write to `/var/lib/openkca`; a
data folder or TLS files elsewhere need a drop-in (`systemctl edit openkca`)
with `ReadWritePaths=`.

## Windows MSI

The MSI (`openkca_<version>_windows_amd64.msi` on the releases page)
installs OpenKCA as the `OpenKCA` Windows service. The first install asks
for HTTPS (clear the box for plain HTTP behind a TLS proxy), the TLS
certificate and key (PEM files, copied into the data folder; empty for a
self-issued certificate), the web UI and CRL ports and the server password.

| Path                                   | What                                       |
| -------------------------------------- | ------------------------------------------ |
| `C:\Program Files\OpenKCA\`            | `openkca.exe`, `config.example.yaml`, docs |
| `C:\ProgramData\OpenKCA\config.yaml`   | configuration, kept on updates             |
| `C:\ProgramData\OpenKCA\tls.crt`, `tls.key` | the certificate and key given at install |
| `C:\ProgramData\OpenKCA\data\`         | data folder                                |

`C:\ProgramData\OpenKCA` can be opened by SYSTEM and Administrators only,
and stays when OpenKCA is removed. The service logs to the Application
event log (source `OpenKCA`), restarts after a failure, and Windows
Firewall lets `openkca.exe` accept connections. To change the settings
later, run `openkca setup` in a terminal opened as Administrator
(`C:\Program Files\OpenKCA\openkca.exe setup`); it offers to restart the
service. Updates keep the configuration and skip the questions.

Silent install, for instance with plain HTTP on port 8080:

```bat
msiexec /i openkca_X.Y.Z_windows_amd64.msi /qn OKCA_PASSWORD=... OKCA_HTTPS=0 OKCA_PORT=8080
```

Properties: `OKCA_HTTPS` (`1`, `0` for plain HTTP), `OKCA_PORT` (`9443`),
`OKCA_CRL_PORT` (`9080`, `0` = off), `OKCA_TLS_CERT` and `OKCA_TLS_KEY`
(full paths), `OKCA_PASSWORD` (at least 8 characters, no `"`, not ending
in `\`). The MSI is not code-signed, so SmartScreen asks before running it.

## Data folder

```
/srv/xca/
├── ca-root.okca           OpenKCA databases, listed on the login page
├── ca-root.okca.lock      lock held while OpenKCA has the database open
├── old-ca.xdb            an XCA database, imported (and deleted) at its first login
└── .openkca/               server state (never listed)
    ├── tls.crt, tls.key  self-issued certificate
    └── backup/           <name>.<yyyyMMddHHmmss>.okca
/srv/xca/ca/<database>/<authority ID>/   per-CA folder:
    index.txt, index.txt.attr             certificate index (openssl ocsp -index)
    ca.crt, crl.der                       published CA certificate and newest CRL
```

A backup is written right after an import, before a database of an
older schema is upgraded on opening, and before every
change that rewrites a whole database (replacing the data key),
using SQLite's `VACUUM INTO`, which copies within one read transaction.
How many are kept is a database option: at most 10 and none older than
90 days by default (the newest always stays). After a password change,
the removal of an unlock method, a new backup code or a new data key
every older backup is deleted, since they still open with what was
replaced, and a new one is written.

Two OpenKCA processes cannot open the same database (`flock` on the `.lock`
file); a database kept open in the background holds its lock as long as
OpenKCA runs.
