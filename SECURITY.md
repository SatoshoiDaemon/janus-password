# Security Policy

## Supported versions

Only the latest version on the default branch is currently supported.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use
GitHub's private vulnerability reporting feature when enabled, or contact the
repository owner privately with:

- a clear description of the issue;
- reproduction steps or a minimal proof of concept;
- the affected version and environment;
- the potential impact.

Please do not include real passwords, tokens, database credentials, or
personal data in a report.

You can expect an acknowledgement within seven days. The project will
validate the report, coordinate a fix, and publish a security advisory when
appropriate.

## Scope

Janus is a local-first educational project. Deployments that expose the
development server directly to the public internet are out of scope.

## Vault lifecycle

See [vault architecture and recovery](docs/VAULT.md) for key formats, migration,
backup restoration, known limitations and the Argon2id migration plan. Login and
vault unlock are independent. Use one local process; never expose this local
service directly to a network. An independent security audit is still pending.
