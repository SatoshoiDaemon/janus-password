# Vault architecture and recovery

## Local process and keys

Run `python -m src.backend.run` as one local process. The service binds only to
`127.0.0.1`/`localhost`, accepts those Host names, rejects cross-origin writes,
and requires login, CSRF tokens and an unlocked vault for owner operations.
An arbitrary local process does not get vault access merely by knowing the port;
it still needs the authenticated session and unlock. There is no defense against
an attacker already able to inspect this process, browser or OS account.

Account passwords authenticate login. The independent master password unlocks
the vault. Registering/logging in does not unlock a vault. Initial setup of an
empty vault requires a master password of at least 12 characters. An existing
vault's actual password is validated by authenticating its encrypted key and all
credentials, including when it contains zero credentials.

Each local account has one random Fernet data key. The master password wraps
that key with the existing salted PBKDF2-HMAC-SHA256 + Fernet `v1` encryption.
Credential passwords are `v2$<Fernet token>` encrypted with the random data key.
`vaults.crypto_version = 2` identifies this arrangement. This version number
does **not** mean Argon2id is already implemented.

The signed Flask cookie contains an opaque random unlock handle, never a key or
master password. The server holds the key in an expiring, process-only registry.
`VAULT_TIMEOUT` defaults to 300 seconds since the last vault operation. Status
polls do not refresh it. Explicit lock, logout, process exit and password changes
remove keys. A daemon prunes idle keys at least every 30 seconds, while every key
lookup enforces expiry immediately. Registry bytearrays are overwritten on
removal; Python, cryptography and browsers can retain immutable copies, so this
is best-effort cleanup rather than guaranteed memory erasure.

One process is required because unlock handles are process-local. Threads are
serialized for vault mutations. SQLite transactions use `BEGIN IMMEDIATE`; the
optional SQL adapters lock the account row. Multi-worker hosting and shared
network use are not supported by this lifecycle. External database compatibility
has not been integration-tested by this change.

Credential metadata remains plaintext in the database, as before. Backup payloads
encrypt metadata as well. Notes retain their independently password-encrypted
`v1` content and password hashes. Public note links, if explicitly used, require
their own password/token and do not inherit the owner's vault lock.

## Migration and recovery

Before upgrading, stop Janus and make an offline copy of the complete database
(including SQLite WAL/SHM files if present). Do not overwrite that copy.
`init_db()` adds the vault table and migration ledger and records schema version
1 after the existing note-token column upgrades. It never deletes data.

On first unlock without vault metadata, the service decrypts **all** existing
`v1$<salt>$<token>` credentials before writing anything. Only then does one
transaction create the wrapped key and convert all passwords to `v2`. A bad
password, damaged item, unsupported format or failed commit leaves the original
records unchanged. Repeated initialization and unlocks are idempotent.

Older Janus versions allowed separate master passwords per credential. If these
were used, unlock returns HTTP 409 and the failing credential ID. Recover by
providing the original passwords through the local API (with login and CSRF):

```json
POST /api/vault/unlock
{
  "master_password": "the-password-to-protect-the-migrated-vault",
  "legacy_passwords": {
    "12": "original-password-of-item-12",
    "19": "original-password-of-item-19"
  }
}
```

All original passwords must be known; there is no bypass. Records from the
pre-`v1` fixed-salt implementation remain unsupported, are never erased or
silently replaced, and must be recovered with the original compatible version
against a separate database copy before importing/recreating them. No recovery
promise is made for unavailable encryption keys or actually corrupted data.

To change the master password, unlock first and submit the current and new
passwords to `/api/vault/change-password`. The server authenticates the existing
envelope and credentials, rewraps only the data key in one transaction, increments
the revision and invalidates all process-local unlocks for that account. The
login password is unchanged. Old backups remain protected by the master password
used when those backups were created; a password change cannot revoke an offline
backup. Re-export after changing it.

## Backup and clean installation restoration

From the dashboard, unlock and select **Exportar backup criptografado**. Store
the `.janus` file separately from the computer. It contains a versioned JSON
container with a PBKDF2-wrapped key and a Fernet-authenticated encrypted payload
containing all credential/secure-note rows and the bound key envelope. Titles,
login names, hashes and secret values are inside the encrypted payload.

On the destination:

1. Install Janus and register a local account (its login password may differ).
2. In the dashboard, select the `.janus` file and enter the backup's master password.
3. Restore into this **empty** account; unlock with the backup's master password.
4. Verify credentials and notes before removing the original installation.

Restoration authenticates the container and every credential, validates the
format/record structure, and inserts everything in one transaction. It remaps
account/record IDs, leaves the new login credentials intact, revokes old public
note links and refuses nonempty accounts. Notes keep their original passwords;
the master password cannot decrypt them individually. Their ciphertext is
preserved by backup authentication, but without the note password restoration
cannot validate whether the original note was already corrupt. Account login
passwords, `.env`, database-server configuration and OS settings are not portable
vault contents. Default request limit is 16 MiB of JSON, including encryption
overhead; this is not yet suitable for large attachments.

Automatic backups are optional pre-mutation recovery snapshots:

```dotenv
JANUS_BACKUP_DIR=/absolute/path/to/janus-backups
JANUS_BACKUP_INTERVAL=3600
JANUS_BACKUP_RETENTION=10
```

Snapshots are evaluated on credential/note mutations, not by a scheduler while
Janus is closed. The interval is the minimum time between snapshots. A snapshot
contains the state **before** the mutation; use manual export for the final
latest-state copy before moving machines. Password changes force a snapshot
when enabled. Files are created with restrictive tempfile permissions, flushed,
fsynced and atomically renamed; only then are older snapshots pruned. A configured
backup failure aborts the requested mutation rather than silently continuing.
This is not a guarantee against hardware-level power-loss/filesystem failures;
OS-specific durability tests remain on the roadmap. Keep at least one backup on
a different device. Snapshots of an empty vault are valid but contain no secrets.

## Argon2id migration plan

PBKDF2 remains at the current 100,000 iterations for compatibility in this change.
Before switching defaults:

1. Benchmark Argon2id memory/time parameters on supported low-memory hardware;
   store algorithm and bounded parameters in a new versioned envelope.
2. Add known-answer, wrong-password, tampering and parameter-bound tests, including
   historical fixtures for current `v1` envelopes and password hashes.
3. Read legacy envelopes, authenticate the whole vault and rewrap the random data
   key using Argon2id in one transaction after successful unlock. Do not re-encrypt
   every credential solely to change KDFs.
4. Keep old formats readable through an explicit compatibility window and document
   older-app downgrade incompatibility, backup passwords and recovery.
5. Independently review the migration and fault-injection tests before promoting
   the new writer. Migrate login/note hashes and note-content KDFs separately.

## Threat model and verification limits

Protected: wrong-password writes, partial key migration, unauthenticated vault
access, account isolation, GET bodies containing secrets, routine CSRF, DNS
rebinding via unexpected Host, cross-origin writes, accidental cached responses,
silent replacement of damaged credentials and restore-overwrite mistakes.

Not protected: compromised OS/browser/extensions, process memory inspection,
keyloggers, stolen authenticated unlocked sessions, plaintext database metadata,
offline password guessing against weak master/note passwords, physical media
failure without an independent backup, rollback to an older valid database, or
all effects of malicious browser/local processes. The Flask development server
is still a development server; signed installers, process pairing and an
independent audit remain future work. Clipboard cleanup depends on browser
permissions and does not claim reliable OS-wide memory/clipboard erasure.

Local tests cover migration concurrency, rollback on failed migration/commit,
wrong passwords, damaged SQLite files/ciphertexts, session expiry/key clearing,
backup tampering, retention and restoration into a new database and login session.
They do not replace independent cryptographic review or OS packaging tests.
