# Contributing

1. Create a virtual environment and install `requirements-dev.txt`.
2. Make focused changes and add or update tests.
3. Run `make check` before opening a pull request.
4. Describe security-sensitive changes clearly in the pull request.

Do not commit `.env` files, database files, credentials, tokens, or other
personal data. Please report suspected vulnerabilities privately to the
repository owner instead of opening a public issue.

## Native application and extension changes

Install the hash-locked build/test environment with
`python -m pip install --require-hashes -r requirements-lock.txt`. Run `make check`,
then `python scripts/build_app.py`, `python scripts/build_extension.py` and
`python scripts/verify_reproducible.py`. Build natively on the target OS. Generated
`dist/`, `build/` and PyInstaller `.spec` files do not belong in commits.

Run JavaScript syntax checks on `src/frontend/js/*.js` and `extension/*.js` when
changing the interface/bridge. Test filling/capture against hostile lookalike
origins, cross-origin form actions, multiple visible password fields and tab
navigation during an in-flight request. Never weaken matching to broad suffixes.

Changes to schema, ciphertext or backup formats need historical fixtures, failed
password/commit tests and full restoration coverage for new tables. Preserve
compatible readers or explicitly fail without rewriting old data. Secrets must
not enter logs, command arguments, URLs or client-side Flask cookies. External
review is required before describing a release as independently audited.

Create a version tag only after the Linux/Windows build and quality workflows pass.
The release workflow generates checksums and keyless GitHub provenance attestations.
Do not describe these as Authenticode or Mozilla signatures.
