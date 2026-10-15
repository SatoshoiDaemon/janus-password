# Changelog

## 0.3.0 — release candidate

### Vault and recovery

- Separate login/unlock, random vault data key, automatic lock and validated writes.
- Argon2id hashes/envelopes with compatible PBKDF2 migration on authenticated use.
- Atomic migration/password changes, complete encrypted versioned backup/restore,
  automatic recovery snapshots and failure-injection coverage.
- CSV, Bitwarden JSON, KeePass XML and encrypted KDBX/password/keyfile imports,
  previews, duplicate policy and attachment preservation.

### Management

- Instant search, folders, tags, favorites, multiple URLs and encrypted custom fields.
- Credential revision history, trash/restore and separate permanent deletion.
- Weak/reused/old password indicators, shortcuts and timed clipboard clearing.
- TOTP, encrypted attachments, identities, cards and local EFF-list passphrases.

### Local application and browser

- Named independent vaults, native chooser, Waitress startup/shutdown, instance
  locks, per-user paths, settings and CLI.
- Chromium/Firefox extensions with explicit fill/capture/generation, authenticated
  revocable pairing and exact-origin matching.
- Linux portable installer and Windows Setup recipe with clean-install smoke tests.
- Hashed dependency lock, reproducibility checks, checksums, tagged release workflow
  and signed GitHub build provenance.

### Compatibility

- API clients must unlock first and reveal secrets using POST endpoints.
- Old v1 credentials/backups remain readable; pre-v1 records require the original
  compatible reader against a separate database copy.
- Independent notes keep their own passwords; browser pairings stay local and
  old public note links are revoked after restoration.
- Release candidate status is intentional: an independent audit and OS vendor/store
  signing are not implied by implemented features or GitHub provenance signatures.
