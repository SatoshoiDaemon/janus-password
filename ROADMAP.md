# Janus roadmap

Janus is an offline-first **local application**. Keep Flask, HTML/CSS/JavaScript
and SQLite. No synchronization, remote infrastructure, frontend framework or
full rewrite is needed for this roadmap. Existing optional database drivers are
compatibility features, not the product's default or the focus of development.

Order: **vault reliability → data protection/recovery → everyday usability →
operating-system integration → advanced functionality**.

Checkmarks below mean implemented in this change, not independently audited.
Version numbers are suggested milestones, not the repository's current version.

## P0 — Janus — Vault Reliability

Five deliveries, in dependency order:

1. [x] Separate account login from vault unlock; use one validated vault key;
   change the master password without rewriting every credential.
2. [x] Test incorrect passwords, corrupted records/database, partial migration,
   concurrent migration, commit failure and recovery after errors.
3. [x] Introduce a schema migration ledger and versioned vault, item and backup
   formats; migrate existing `v1` credentials atomically on first unlock.
4. [x] Export and restore an encrypted backup containing all the account's
   credentials and notes. Verify restoration in a new database and session.
5. [x] Add idle lock, explicit lock/logout, server-only ephemeral keys and UI
   secret clearing; protect the local HTTP boundary.

Further P0 acceptance work:

- [ ] Benchmark and migrate password KDFs to Argon2id using the envelope plan in
  [VAULT.md](docs/VAULT.md), retaining successful reads of existing formats.
- [ ] Independently review the new key lifecycle and recovery paths.
- [ ] Exercise filesystem/power-loss recovery on Linux and Windows, beyond
  simulated write failures.

Acceptance: no ordinary save, update, password change or migration silently
makes a credential unreadable. Known unsupported or damaged legacy records are
reported explicitly; migration leaves the original data unchanged.

## P0 — Backup, restoration and portability

- [x] Versioned encrypted `.janus` exports and full per-account restoration.
- [x] Configurable automatic local recovery snapshots, interval and retention.
- [x] Restore credentials and notes in a fresh installation, retaining note passwords.
- [x] Refuse unsupported versions, bad passwords and nonempty destinations.
- [ ] CSV import with preview, mapping and explicit rejection/error reporting.
- [ ] KeePass import, including deciding between XML export and encrypted KDBX.
- [ ] Bitwarden import with explicit handling of unsupported item types/fields.
- [ ] Add fixtures for imported real-world export formats and duplicate handling.

Acceptance: move the vault to another machine without losing credentials. The
current backup restores into a newly registered, empty local account; it does
not restore the old login password or machine configuration. Importers are not
implemented yet. Automatic snapshots are pre-write recovery points; create an
explicit export to capture the latest state before migrating machines.

## P1 — Complete credential management

- [ ] Instant search across names, login, email, URLs and tags.
- [ ] Folders, tags and favorites.
- [ ] Encrypted custom fields and multiple URLs.
- [ ] Credential revision history.
- [ ] Trash with restoration and explicit permanent deletion.
- [ ] Weak, reused and old password indicators, calculated locally.
- [x] Escape closes secret dialogs; Ctrl+Shift+L locks the vault.
- [x] Clipboard clearing after 30 seconds where browser permissions allow it,
  without erasing newer clipboard contents.
- [ ] Broader keyboard navigation and accessible search shortcuts.

Acceptance: finding and maintaining hundreds of credentials remains fast.

## P1 — Distribution as a local application

- [ ] Linux and Windows packaging; smoke tests on clean systems.
- [ ] Controlled local process startup/shutdown and single-instance behavior.
- [x] Loopback bind by default; reject nonlocal Host and cross-origin writes.
- [x] Configurable local port and authenticated/CSRF-protected vault operations.
- [ ] Platform-appropriate application-data, config and backup directories;
  explicit migration from the existing `database.db` path.
- [ ] Update/install without replacing the database or losing backups.
- [ ] Assess stronger process pairing for browser/CLI integrations.

Acceptance: install, open and use Janus like an ordinary local application.

## P2 — Browser integration

- [ ] Chromium and Firefox extension.
- [ ] Fill only after a user action; do not silently submit forms.
- [ ] Offer to capture newly entered credentials.
- [ ] Integrated generator.
- [ ] Authenticated, paired communication with local Janus; revocable pairing.
- [ ] Strict origin/domain matching, including IDNs, subdomains and lookalikes.
- [ ] Tests against phishing pages, frames and malicious local clients.

Acceptance: use stored credentials without manual copy/paste.

## P2 — Advanced workflows

- [ ] TOTP.
- [ ] Encrypted attachments, with size limits and backup support.
- [ ] Identities and cards, with encrypted structured fields.
- [ ] Passphrase generator.
- [ ] CLI for developers.
- [ ] Multiple independent local vaults (not merely multiple login accounts).

Acceptance: advanced workflows do not make basic credential management harder.

## P3 — Open-source maturity (work begins immediately)

- [x] Document architecture, key lifecycle and threat model.
- [x] Contribution guide and local CI quality checks.
- [ ] Versioned releases and maintained changelog.
- [ ] Reproducible, signed builds with verification instructions.
- [ ] Clean-install and upgrade testing across supported OS versions.
- [ ] Independent security audit before declaring a stable alternative.

Acceptance: others can understand, inspect, install, verify and contribute.
Security review accompanies each sensitive change, not just v1.0.

## Suggested release milestones

| Milestone | Goal | State after this change |
| --- | --- | --- |
| v0.2 | Integrity, security, explicit unlock | Core implemented; Argon2id/review remain |
| v0.3 | Backup, restoration and import | Backup/restore implemented; importers remain |
| v0.4 | Search, folders, history, complete management | Planned |
| v0.5 | Linux/Windows installers | Planned |
| v0.6 | Browser extension | Planned |
| v0.7 | TOTP, CLI and advanced features | Planned |
| v1.0 | Stable UX, docs, verification and security review | Planned |

The first release target is the **v0.3 capability set**: a vault that is reliable,
recoverable and portable. Stable releases should follow verified capabilities,
not the suggested numbering alone.
