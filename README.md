# Janus

Janus is a local-first password manager for ordinary personal use. It is
designed to run on a user's own computer, keep the default setup small, and
avoid requiring a hosted account or a container platform.

The project is intentionally close to a self-hosted application in spirit:
the owner controls the process, database, credentials, and network exposure.
It is not a managed cloud service. The current distribution is a local Flask
application rather than a complete production self-hosting package with a
reverse proxy, TLS automation, backups, and an operations console.

> Janus is an educational and personal-use project. It is not presented as a
> replacement for a professionally audited password manager. Review the
> threat model before storing important secrets.

## Why Janus exists

Janus is built for a simple use case: a person wants a private tool that can
run locally, store credentials in a local database, and remain useful without
depending on an external service.

That leads to several deliberate decisions:

- SQLite is the default because it is portable, easy to back up, and requires
  no database server.
- Docker is not required because the primary target is a local application,
  not a multi-service deployment.
- The frontend uses plain HTML, CSS, and JavaScript so it remains easy to
  inspect, modify, and run.
- SQLAlchemy provides an upgrade path to PostgreSQL or MySQL.
- Security-sensitive behavior is implemented in the backend and exercised by
  local automated tests.

## Features

- Cryptographically secure password generation.
- User registration and session-based authentication.
- PBKDF2-HMAC-SHA256 password hashing with a unique random salt per hash.
- Credential encryption with a unique random salt per encrypted item.
- Secure notes encrypted with the note's own password.
- Public note links protected by a note password, expiration, and revocation.
- CSRF protection, rate limiting, restricted CORS, and secure production
  cookies.
- SQLite by default, with optional PostgreSQL and MySQL drivers.

## Architecture

Janus is a small layered web application:

~~~text
Browser
  │ HTML/CSS/JavaScript + Fetch API
  ▼
Flask application (src/backend/app.py)
  ├── Request security
  │     ├── Session authentication
  │     ├── CSRF validation
  │     ├── Rate limiting
  │     └── CORS policy
  ├── Application routes
  │     ├── Authentication
  │     ├── Password generation
  │     ├── Credentials
  │     └── Secure notes
  ├── Cryptography services (src/backend/auth.py)
  │     ├── PBKDF2 password hashing
  │     ├── Fernet encryption
  │     └── Public access tokens
  └── Database adapter (src/backend/database.py)
        └── SQLAlchemy → SQLite, PostgreSQL, or MySQL
~~~

### Backend

The Flask application serves both the API and the static frontend. Routes
live in src/backend/app.py, while cryptographic primitives live in
src/backend/auth.py.

The backend owns authorization decisions. Every credential and note query is
scoped to the authenticated user's ID. Public note access is a separate
route that requires both a valid token and the note password.

### Frontend

The frontend is dependency-free. HTML screens live in src/frontend, shared
styles live in src/frontend/css/style.css, and dashboard behavior lives in
src/frontend/js/script.js.

The frontend never receives database credentials or server-side encryption
keys. It sends user actions to the Flask API over the local session and
renders the responses.

### Database

SQLAlchemy is the portability layer. The schema contains users, encrypted
credentials, and secure notes. SQLite foreign-key enforcement is enabled for
application connections.

SQLite uses a local connection strategy suitable for a single-user or small
local process: connections are not pooled, writes have an explicit busy
timeout, and read/write contention is handled more gracefully.

## Security model

Janus separates account authentication, private credential access, and public
note sharing.

### Account password

The account password is never stored in plaintext. It is hashed with
PBKDF2-HMAC-SHA256 and a unique 32-byte random salt. Verification derives a
new key with the stored salt and compares the result in constant time.

### Private credentials

Credential passwords are encrypted before storage. The user's master password
derives the Fernet key, and every encrypted item receives its own random
16-byte salt. Stored ciphertexts use this versioned format:

~~~text
v1$<base64 salt>$<Fernet token>
~~~

The master password is supplied when a credential is created, viewed, or
updated. Janus does not store the master password.

### Secure notes

Notes deliberately use a different model:

- The note password is the access password.
- The note password is hashed for verification.
- The content is encrypted with a key derived from that same note password.
- Public access still requires the note password; the token alone is not
  sufficient.
- Public tokens expire and can be revoked without deleting the note.

### Request protection

- Authenticated routes require a signed session.
- Authenticated state-changing API requests require a CSRF token.
- Login, registration, generation, writes, and public note access are rate
  limited.
- CORS is disabled unless an explicit allowlist is configured.
- Production cookies can be HttpOnly, SameSite, and Secure.
- Internal exception details are logged server-side, not returned to users.
- Public note tokens have expiration and revocation state.

## Threat model and limitations

Janus protects against common application-level mistakes such as plaintext
password storage, cross-user record access, missing CSRF checks, and
unrestricted public note tokens.

It does not protect a machine that is already compromised. In particular:

- a process with access to the running application may inspect memory or
  intercept input;
- losing both the database and the required passwords may make recovery
  impossible;
- the development Flask server should not be exposed directly to the public
  internet;
- SQLite files still need secure operating-system permissions and backups;
- HTTPS, reverse proxy configuration, monitoring, and backup automation are
  deployment responsibilities;
- records from the pre-security fixed-salt implementation must be recreated.

For a serious deployment, place Janus behind a production WSGI server and
reverse proxy, use HTTPS, configure a strong secret key, restrict network
access, and establish encrypted backups.

## Screenshots

### Sign in

![Janus sign-in screen](docs/screenshots/login.png)

### Create an account

![Janus registration screen](docs/screenshots/register.png)

## Technology choices

- Python 3.11+ for a mature runtime and broad library support.
- Flask for a small, explicit local web service.
- SQLAlchemy for one database interface across supported engines.
- SQLite for a zero-setup, file-based default.
- PostgreSQL and MySQL drivers for users who already operate a server.
- Fernet for authenticated symmetric encryption.
- PBKDF2-HMAC-SHA256 for password-based key derivation and hashing.
- Vanilla JavaScript for a minimal frontend supply-chain surface.
- Pytest, Ruff, Black, and Bandit for repeatable quality checks.

## Quick start

~~~bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
python -m pip install -r requirements-dev.txt
python -m src.backend.database
python -m src.backend.run
~~~

Open http://127.0.0.1:5000.

The default database is database.db in the project root. It is ignored by
Git and is created automatically. Janus can be used entirely offline after
its dependencies are installed.

## Database configuration

### Default: local SQLite

No database server or Docker is required:

~~~bash
DB_ENGINE=sqlite
DB_PATH=database.db
~~~

### Optional PostgreSQL or MySQL

Set DATABASE_URL to a SQLAlchemy URL:

~~~bash
# PostgreSQL with TLS required
DATABASE_URL='postgresql+psycopg://user:password@host:5432/janus?sslmode=require'

# MySQL
DATABASE_URL='mysql+pymysql://user:password@host:3306/janus'
~~~

Alternatively, configure DB_ENGINE, DB_HOST, DB_PORT, DB_NAME, DB_USER,
DB_PASSWORD, and the optional SSL variables shown in .env.example.
DATABASE_URL takes precedence. Never commit credentials, connection strings,
database dumps, or real secrets.

## Development commands

~~~bash
make install   # Install runtime and development dependencies
make run       # Initialize the configured database and start Flask
make test      # Run tests with coverage
make lint      # Run Ruff and Black checks
make security  # Run Bandit
make check     # lint + security + tests
~~~

The test suite covers password hashing, encryption, password generation,
registration, login, logout, user isolation, credential CRUD, note CRUD,
public token access, wrong passwords, validation, authorization, CSRF, and
the dashboard identity endpoint.

## Project structure

~~~text
Janus/
├── src/
│   ├── backend/
│   │   ├── app.py              # Flask routes and API
│   │   ├── auth.py             # Hashing, encryption, and tokens
│   │   ├── database.py         # SQLAlchemy configuration and schema
│   │   └── run.py              # Local application entry point
│   └── frontend/
│       ├── css/style.css       # Shared interface styles
│       ├── js/script.js        # Dashboard behavior
│       └── *.html              # Application screens
├── tests/                      # Unit and HTTP integration tests
├── docs/screenshots/           # README interface screenshots
├── .github/                    # CI, Dependabot, and templates
├── Makefile                    # Standard local commands
├── pyproject.toml              # Tool configuration
├── requirements.txt            # Runtime dependencies
└── LICENSE                     # MIT license
~~~

## GitHub and maintenance

The repository includes GitHub Actions for tests, Ruff, Black, and Bandit;
Dependabot updates for Python dependencies and Actions; issue templates; a
pull-request template; and contribution, security, and conduct policies.

See CONTRIBUTING.md before submitting a change. Behavior changes should
include or update tests, and local changes should pass make check.

## Local backup guidance

With SQLite, a basic backup is a copy of database.db while the application is
stopped. For a more robust workflow, use SQLite's backup facilities or a
database-aware backup tool. Backups contain encrypted secret values but still
contain account metadata, tokens, and ciphertexts, so protect them with
appropriate filesystem permissions and encryption.

For PostgreSQL or MySQL, use the backup and restore procedures appropriate to
the chosen database server.

## Security reporting

Read SECURITY.md before reporting a vulnerability. Never include passwords,
access tokens, database credentials, or personal data in a public issue.

## Contributing

See CONTRIBUTING.md.

## License

Janus is released under the MIT License.
