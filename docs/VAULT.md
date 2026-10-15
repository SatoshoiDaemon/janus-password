# Architecture, formats and threat model

## Process and storage

The dependency-free browser interface talks to a local Waitress/Flask process.
SQLite stores accounts, wrapped data keys, credentials, encrypted extended data,
revision history, structured items, attachments, notes and hashed pairing tokens.
One local process per named vault holds ephemeral unlock keys; a native file lock
prevents a second launcher from opening the same name. Vaults have independent
SQLite files under the platform-specific Janus data directory. Application
binaries/installers live separately, so replacing them does not replace user data.

`app.py` handles authentication, request boundaries and the original credential/
note APIs. `vault.py` owns unlock, key lifecycle, migration and backup transactions;
`auth.py` implements compatible KDF/crypto readers. `entries.py`, `importers.py`,
`features.py`, `browser_bridge.py`, `local.py`, `run.py` and `cli.py` implement the
management layer, offline imports, bridge, application lifecycle and CLI.

All credential mutations run in a transaction under the process lock. SQLite
uses `BEGIN IMMEDIATE`, foreign-key enforcement and a busy timeout. The schema
migration ledger records versions 1 (vault lifecycle) and 2 (extended tables).
Initialization is idempotent and does not drop or rewrite existing records.

## Passwords and versioned keys

Account login and vault unlock are distinct. New password hashes use Argon2id
PHC strings (`$argon2id$…`), with 64 MiB memory, three iterations and one lane.
Legacy salted PBKDF2-HMAC-SHA256 (100,000 iterations) hashes remain readable and
upgrade only after successful login. Note hashes/content similarly upgrade on
successful note access. Legacy values are not erased after failed authentication.

New password-encrypted values use:

```text
v3$argon2id$65536,3,1$<base64 salt>$<Fernet token>
```

The salt is random, 16 bytes; Argon2id derives a 32-byte Fernet key. Readers bound
memory/time/parallelism before deriving to reject resource-exhaustion parameters.
The current reader accepts existing `v1$<salt>$<token>` PBKDF2 values. Unknown
versions and malformed ciphertext are rejected.

A vault has one random Fernet data key. Its master password encrypts that key in
a `v3` envelope. Credential passwords and encrypted metadata/history/item/attachment
payloads use `v2$<Fernet token>` with the random data key; `crypto_version=2`
identifies this data-key arrangement independently from the envelope's KDF.
Changing the master password authenticates the existing envelope/credentials,
rewraps the data key atomically and invalidates every active account unlock.
It does not rewrite every credential or change the login password.

The signed Flask cookie carries an opaque unlock handle, never a password/key.
The process registry holds expiring key bytearrays. Status polling and extension
use do not extend unlock lifetime. Key lookup enforces expiry immediately, and a
daemon removes idle keys at most 30 seconds after their deadline. Explicit lock,
logout, password change and shutdown wipe registry bytearrays. Python and browser
immutable copies cannot be guaranteed erased; memory/clipboard cleanup is
best-effort and never represented as OS-wide secure erasure.

The original credential names/login/email and structured item display names
remain plaintext database metadata. Extended fields, secrets, history and
attachment names/content are encrypted. Entire portable backup payloads, including
all names/metadata, are encrypted. Independent secure notes retain their separate
note passwords; vault-key notes are available as structured note items.

## Upgrade and recovery

Stop Janus and copy the original database, including SQLite WAL/SHM companions if
present, before upgrading. Preserve that copy separately.

Without existing vault metadata, first unlock decrypts **all** legacy v1
credentials before writing a wrapped data key and converting credentials in one
transaction. A wrong password, corrupted item or failed commit leaves records
unchanged. Existing key envelopes are authenticated and upgraded from PBKDF2 to
Argon2id on successful unlock without changing the underlying data key.

Older Janus allowed different passwords per credential. A failed migration names
the failing record. Recover through authenticated/CSRF-protected local unlock:

```json
{
  "master_password": "the-password-for-the-migrated-vault",
  "legacy_passwords": {"12": "original-item-password", "19": "another-original-password"}
}
```

Every original item password must be known. Pre-v1 fixed-salt records remain
unsupported, are not deleted or silently overwritten, and must be recovered with
the original compatible version against a separate copy before recreation/import.
No migration can reconstruct unavailable keys or actually destroyed ciphertext.

## Portable backups

`.janus` format 2 contains a wrapped data key plus a Fernet-authenticated encrypted
payload. The authenticated payload binds the same envelope and includes all
credentials, notes, metadata, history, trash, identities/cards and attachments.
Format 1 backups from the initial lifecycle implementation remain readable.
Unknown versions, bad passwords and malformed/tampered payloads are rejected.

Restore into an empty local account. Validate/decrypt before writing, remap all
credential/attachment/history relationships, and commit all tables atomically.
Old note links are replaced/revoked. Account login credentials, pairing tokens,
configuration and machine-specific paths are not portable vault contents.
Independent notes retain their own passwords: restoring validates their bytes
through authenticated backup encryption, but cannot prove their original content
was decryptable without each note password.

Automatic backups use the same format before mutations. The local launcher enables
them in a per-vault directory; interval and retention are configurable. Master
password changes force a snapshot when configured. Files use restrictive tempfile
permissions, flush/fsync and atomic rename before retention pruning. A snapshot
failure aborts the mutation. These are recovery points, not a scheduler running
while the application is closed. Use explicit export for final latest-state
migration. A prior backup still needs the password used when it was created;
changing a password cannot revoke an already-copied offline backup.

Attachments are limited to 8 MiB each. HTTP/backup requests default to 256 MiB
(`JANUS_MAX_BACKUP_BYTES`). Oversized export is explicitly rejected so the app
never hands out a backup that exceeds its configured restore limit. Large vaults
may raise that limit, subject to local RAM. Keep another backup on a different
device; application transactions cannot prevent hardware/media destruction.

## Import and browser boundary

Importers parse and validate all rows before writes. Preview returns item names/
types, not passwords. Commit requires explicit confirmation and is one transaction.
CSV aliases, KeePass XML, password/keyfile-protected KDBX with attachments and
Bitwarden login/card/identity/note JSON are supported. Duplicate credential policy
is explicit. Unknown types, passkeys and references to absent binary attachments
fail explicitly rather than silently losing data. XML uses defusedxml; input
limits and type checks reject malformed or entity-bearing documents.

The bridge is separate from cookie authentication. An unlocked owner creates a
revocable extension-specific random token; only its SHA-256 digest is stored.
Bridge requests require that token and the registered extension origin. Registered
extension origins alone receive CORS allowance. Bridge endpoints do not accept
account/master passwords or unlock a locked vault. Pairings are installation-local
and are not restored from portable backups.

Domain matching is exact over scheme + IDNA hostname + effective port; no suffix
or parent-domain wildcard exists. The extension rechecks active tab identity and
origin after secret retrieval, injects only the top frame, checks the document
origin again and refuses forms targeting another origin. Filling requires a
specific user-selected credential and does not submit. Capture requires an
explicit read followed by an explicit save on the same current origin.

## Threat model and verification status

Controls cover wrong-password writes, partial migrations, account isolation,
CSRF, unexpected local Host/DNS rebinding, cross-origin writes, stale unlocks,
common domain confusion, corruption replacement, restore overwrite mistakes and
accidental cached secret responses. The service rejects non-loopback binds.

Not covered: compromised OS/browser/extension, keyloggers, process memory
inspection, a stolen authenticated unlocked session, offline guessing of weak
passwords, plaintext database metadata, rollback to an older valid database,
loss of every backup or physical media failure. A paired compromised extension
can act with its pairing permissions while the vault is unlocked. Pairings are
revocable; they are not a defense against an already-compromised user account.

Tests cover Argon2/PBKDF2 upgrades, RFC 6238 TOTP vectors, importer fixtures and
KDBX attachments, history/trash, rollback/failure injection, full portable restore,
strict bridge matching/revocation, single-instance launcher and shutdown. CI builds
Linux and Windows, smoke-tests native CLI/installation and checks same-runner
binary/extension reproducibility. Tagged releases produce signed GitHub build
provenance. OS vendor/store certificates are different from provenance signatures.

An independent professional security audit has **not** been completed. An attempted
CodeRabbit external automated review was blocked by unavailable authentication in
this environment; it is not counted as a completed review. Security-sensitive
changes require external reviewer attention before claims of audited stability.
