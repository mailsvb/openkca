# Security

[← Back to README](../README.md)

- One server password protects the whole UI; a database's unlock methods
  still apply after it. Both logins are rate limited, and at most two Argon2id runs
  happen at a time, so parallel login attempts cannot exhaust memory.
- Database passwords need at least 8 characters. A database is only as
  strong as its weakest unlock method.
- Adding, changing or removing an unlock method needs a confirmation with
  an existing method (not the backup code) in the last 5 minutes.
- Removing or changing a method does not revoke it in copies of the file
  made before (OpenKCA deletes its own backups). To lock out a lost key or
  a leaked password, replace the data key.
- Security keys and passkeys unlock through WebAuthn's PRF extension: the
  authenticator computes an HMAC over a salt OpenKCA stores, and HKDF turns
  that output into the key that wraps the data key. The output travels to
  the server inside TLS and is cleared right after use. The assertion is
  verified too (challenge, origin, signature, user verification) with
  `github.com/go-webauthn/webauthn`. A synced passkey makes the account it
  syncs with a way into the database.
- The backup code is 128 random bits, shown once, and deleted when it is
  used to log in.
- A database configured with a `password` has its data key in memory for
  as long as OpenKCA runs, and the password is stored in plain text in the
  configuration file: anyone who can read that file or the process memory
  can sign with its CA keys. Configure passwords only for databases that
  need unattended CA work. Keys with their own password stay locked.
- HTTPS by default, HSTS, strict Content Security Policy without inline
  scripts, `SameSite=Strict` cookies plus CSRF tokens.
- With `https: false` OpenKCA serves plain HTTP for a TLS proxy in front of
  it. A request counts as encrypted only when it came over TLS, or from a
  proxy in `trusted_proxies` with `X-Forwarded-Proto: https`; only then are
  the cookies `Secure` and HSTS sent. Opened directly over plain HTTP, the
  login page warns that the password and the session travel in clear
  text. The client address for the login rate limit and the audit log is
  taken from `X-Forwarded-For` only for requests from `trusted_proxies`
  (the rightmost address that is not one of them), so clients cannot forge
  it.
- An unlock method is used once per login to unwrap the data key; a
  session keeps only the data key in memory and wipes it on logout and
  after the idle timeout (as far as Go allows: the runtime may keep
  copies). Private keys are decrypted in memory only when needed.
- SQLite's `secure_delete` is on, and the file is vacuumed after keys are
  re-encrypted and after items are deleted from the trash, so replaced or
  deleted key blobs do not stay in the file.
