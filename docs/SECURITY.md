# Security

[← Back to README](../README.md)

- One server password protects the whole UI; database passwords still apply
  after it. Both logins are rate limited, and at most two Argon2id runs
  happen at a time, so parallel login attempts cannot exhaust memory.
- New database passwords need at least 8 characters.
- A database configured with a `password` has its data key in memory for
  as long as OpenKCA runs, and the password is stored in plain text in the
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
