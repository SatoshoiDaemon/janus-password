# Janus

Janus is an offline-first password manager that runs on your computer. Flask,
plain HTML/CSS/JavaScript and SQLite remain its core. No hosted account,
synchronization service, Docker stack or remote database is required.

## What is included

- Separate local login and vault unlock; five-minute idle lock by default.
- Argon2id password hashes and encrypted key envelopes, with compatible PBKDF2
  readers and automatic upgrades after valid authentication.
- Transactional vault migration, master-password changes, encrypted backups,
  complete restoration and configurable automatic local snapshots.
- CSV, Bitwarden JSON, KeePass XML and encrypted KDBX import, with preview,
  confirmation, duplicate handling and rollback on failure.
- Instant search, folders, tags, favorites, multiple URLs, custom fields,
  credential history, trash and restoration.
- Local checks for weak, reused and old passwords; keyboard shortcuts and
  best-effort timed clipboard clearing.
- TOTP, encrypted attachments, identities, cards, secure notes and passphrases.
- Independent named local vaults, desktop chooser and developer CLI.
- Chromium/Firefox extensions with revocable pairing, explicit fill/capture and
  exact-origin matching.
- Native Linux/Windows build recipes, Linux installer, Windows Setup installer,
  reproducibility verification, release checksums and signed build provenance.

This is not a claim that Janus has passed an independent security audit. The
implemented controls and their limitations are documented in
[the threat model](docs/VAULT.md). External review must be recorded as external
review; automated tests and build signatures do not establish cryptographic safety.

## Install and open

Native builds are produced by the **Local application builds** workflow in
[Actions](https://github.com/SatoshoiDaemon/janus-password/actions). Pull requests
produce review artifacts; version tags produce releases and build attestations.
A workflow definition is not itself a published release or OS-vendor signature.

**Linux:** extract `Janus-Linux.tar.gz`, run `sh install.sh`, and open Janus from
the applications menu. The portable executables also work without installation.
**Windows:** run `Janus-0.3.0-Windows-Setup.exe`; it installs for the current user.
Neither installer requires Python on the target machine.

The desktop chooser opens an existing named vault or creates one by name. Each
vault uses its own SQLite file. The app starts a loopback-only Waitress process,
opens the browser, and provides **Encerrar Janus** in the local settings. A file
lock prevents two processes opening the same named vault simultaneously. Choose
another port when running different vaults simultaneously.

Upgrades replace application binaries separately from user data. The default
user data directory is `~/.local/share/Janus` on Linux and `%LOCALAPPDATA%\Janus`
on Windows. `JANUS_HOME` overrides it. It contains `vaults`, `backups` and
`config.json`. Existing source-tree `database.db` files remain supported and are
not silently moved or deleted.

## Run from source

```bash
python -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
python -m src.backend.run
```

Open `http://127.0.0.1:5000`. Register a local account, log in, and set/unlock the
independent master password in **Cofre e backup**. Initial empty vaults require
at least 12 characters. No email is sent; the email field is local account metadata.

```bash
python -m src.backend.run --vault personal --port 5000
python -m src.backend.run --vault work --port 5001 --no-browser
python -m src.backend.run --list-vaults
```

Keep the process local. `HOST=0.0.0.0` is rejected. The independent unlock registry
requires one process per vault, although the HTTP server uses multiple threads.
Existing optional PostgreSQL/MySQL adapters remain source compatibility features;
the native local workflow and integration tests target SQLite.

## Everyday use

**Credenciais** supports instant search by name, login, email, URL, folder and
tag, plus folder/favorite filters. Edit a credential to manage its multiple URLs,
custom fields and TOTP seed. “Histórico” lists previous versions; restoring a
version preserves the version it replaces. Deletion first moves to the trash;
permanent deletion requires a separate action from the trash.

**Itens e anexos** stores identities, cards and vault-key-protected notes with
editable labeled fields. Attachments are encrypted and may be independent or
associated with a credential; each file is limited to 8 MiB.

**Notas seguras** preserves the original independently password-protected note
model. Public local links have token/password/expiration/revocation controls.
These notes keep their own passwords when exported/restored.

`Ctrl+K` searches credentials, `Ctrl+Shift+L` locks and `Escape` clears/closes
secret dialogs. Clipboard clearing after 30 seconds depends on browser permission
and does not erase clipboard contents replaced by another application.

## Backup and import

Unlock, then choose **Exportar backup criptografado**. Restore the `.janus` file
into an empty local account using the backup's master password. Backups contain
credentials, metadata, history, trash, structured items, notes and attachments.
Restoration remaps IDs and revokes old note links. Login passwords, machine
configuration and browser pairing tokens are intentionally installation-local.

Automatic snapshots are pre-write recovery points. The launcher enables them in
the per-vault backup directory. Configure interval/retention in the interface or
with `JANUS_BACKUP_DIR`, `JANUS_BACKUP_INTERVAL`, `JANUS_BACKUP_RETENTION`.
Use manual export to capture the final latest state before moving computers.
The JSON request/backup limit defaults to 256 MiB and can be raised with
`JANUS_MAX_BACKUP_BYTES`; an oversized export fails explicitly.

Import is local: select CSV, Bitwarden unencrypted JSON, KeePass XML or KDBX;
provide the KDBX password/keyfile if required; inspect the preview and confirm.
KDBX preserves entry attachments. Bitwarden login, card, identity and note types
are supported. Unknown types, unexported attachments/passkeys and unsupported
values produce an explicit error instead of silently skipping data. CSV supports
common KeePass/Bitwarden column aliases and preserves unknown columns as custom
fields. Do not leave plaintext export files on disk after verifying the import.

See [VAULT.md](docs/VAULT.md) for legacy migration and recovery details.

## Browser extensions

Download/extract `janus-chromium.zip` or `janus-firefox.zip` from the build:

1. Chromium: enable developer mode at `chrome://extensions` and load unpacked.
   Firefox: load its manifest through `about:debugging` for local development.
   Permanent Firefox installation requires Mozilla signing; the source ZIP and
   GitHub build provenance do not replace that store requirement.
2. Open the extension and copy its displayed `chrome-extension://…` or
   `moz-extension://…` origin.
3. In Janus, open **Cofre e backup → Parear navegador**, enter the origin and a
   recognizable name, and create a token. Paste the token into the extension.
4. Unlock Janus locally. On a login page, choose **Buscar acessos desta página**,
   then click a specific credential to fill it. Capture and saving also require
   explicit user actions; forms are never automatically submitted.

Matching includes scheme, IDNA hostname and effective port. Parent/subdomains,
lookalikes and HTTP/HTTPS transitions do not inherit credentials. Filling is
restricted to the top frame and a single visible password form whose action
stays on the same origin; ambiguous/cross-origin forms are refused. Tokens can be
revoked from Janus. A paired extension cannot unlock a locked vault or retrieve
credentials for an unrelated origin.

## CLI

The installer supplies `janus-cli` / `JanusCLI.exe`. From source, replace the
executable with `python -m src.backend.cli`:

```bash
janus-cli vaults
janus-cli create-vault work
janus-cli --vault work open --port 5001
janus-cli --vault work list
janus-cli --vault work add Example --login alice --url https://example.com
janus-cli --vault work get 1 --show-password
janus-cli --vault work export backup.janus
janus-cli --vault work restore backup.janus
janus-cli --vault work import keepass-kdbx passwords.kdbx
janus-cli passphrase
```

Login/master/credential passwords are read with `getpass`, not command-line
arguments. Secret output requires `--show-password`. Restore can initialize an
empty local account after confirming its new login password. CLI exports refuse
to overwrite an existing file.

## Build, verify and contribute

```bash
python -m pip install --require-hashes -r requirements-lock.txt
make check
python scripts/build_app.py
python scripts/build_extension.py
python scripts/verify_reproducible.py
```

Build natively on Linux or Windows; cross-compiling Windows from Linux is not
supported. The lock pins build/runtime/test dependencies with hashes. Two builds
on the same OS/runtime must be byte-identical or CI fails. This does not claim
identical native binaries across operating systems or Python toolchains.

Tagged releases use GitHub OIDC build-provenance attestations and SHA-256
checksums. Verify artifacts with:

```bash
gh attestation verify Janus-Linux.tar.gz --repo SatoshoiDaemon/janus-password
sha256sum --check Janus-Linux-SHA256SUMS.txt
```

These attestations sign provenance, not Windows Authenticode or Mozilla add-on
certificates. See [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md),
[architecture/threat model](docs/VAULT.md) and [security reporting](SECURITY.md).

No telemetry, CDN assets, synchronization or hosted authentication is included.

## Licenses

Janus's own source remains MIT. The KDBX importer uses GPL-3.0-licensed PyKeePass;
its license and source are distributed with native builds, and its terms still
apply to combined distributions. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
The build also includes `janus-sources.zip` beside executables. This source/notice
handling does not turn the GPL dependency into an MIT-licensed dependency.
