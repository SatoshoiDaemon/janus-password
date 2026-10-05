# Janus

Janus is a local-first password manager built with Flask and a vanilla
JavaScript frontend. It stores credentials encrypted with a master password,
protects secure notes with their own password, and can share notes through
expiring, revocable public tokens.

> This project is intended for education, experimentation, and personal use.
> Review the threat model carefully before storing real secrets.

## Features

- Secure password generation with configurable character sets.
- User registration and session-based authentication.
- Credentials encrypted with a per-item random salt and a master password.
- Secure notes encrypted with a per-note password.
- Public note links protected by a note password, expiration, and revocation.
- CSRF protection, rate limiting, restricted CORS, and secure production cookies.
- SQLite as the default local database.
- Optional PostgreSQL and MySQL support through SQLAlchemy.

## Screenshots

### Sign in

![Janus sign-in screen](docs/screenshots/login.png)

### Create an account

![Janus registration screen](docs/screenshots/register.png)

## Tech stack

- Python 3.11+
- Flask
- SQLAlchemy
- SQLite by default; PostgreSQL and MySQL optional
- Cryptography/Fernet and PBKDF2-HMAC-SHA256
- Vanilla HTML, CSS, and JavaScript
- Pytest, Ruff, Black, Bandit, and GitHub Actions

## Quick start

~~~bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
python -m pip install -r requirements-dev.txt
python -m src.backend.database
python -m src.backend.run
~~~

Open http://127.0.0.1:5000.

The default database is database.db in the project root. It is ignored by Git
and is created automatically.

## Database configuration

SQLite is the default and requires no server or Docker. To use an external
database, set DATABASE_URL to a SQLAlchemy URL:

~~~bash
# PostgreSQL with TLS required
DATABASE_URL='postgresql+psycopg://user:password@host:5432/janus?sslmode=require'

# MySQL
DATABASE_URL='mysql+pymysql://user:password@host:3306/janus'
~~~

As an alternative, configure DB_ENGINE, DB_HOST, DB_PORT, DB_NAME, DB_USER,
DB_PASSWORD, and the optional SSL variables shown in .env.example.
DATABASE_URL takes precedence. Never commit credentials or .env files.

## Development commands

~~~bash
make install   # Install runtime and development dependencies
make run       # Initialize the configured database and start Flask
make test      # Run tests with coverage
make lint      # Run Ruff and Black checks
make security  # Run Bandit
make check     # lint + security + tests
~~~

The test suite covers authentication, password hashing and encryption,
credential/note CRUD, user isolation, public note access, CSRF, validation,
and authorization.

## Project structure

~~~text
Janus/
├── src/
│   ├── backend/
│   │   ├── app.py
│   │   ├── auth.py
│   │   ├── database.py
│   │   └── run.py
│   └── frontend/
│       ├── css/
│       ├── js/
│       └── *.html
├── tests/
├── docs/screenshots/
├── .github/
├── Makefile
├── pyproject.toml
└── LICENSE
~~~

## Security notes

- Set a strong SECRET_KEY outside local development.
- Use HTTPS and secure session cookies in production.
- Use a shared rate-limit backend such as Redis when running multiple workers.
- Keep external database credentials in environment variables or a secret
  manager.
- Data created with the pre-security fixed-salt format must be recreated.

Please read [SECURITY.md](SECURITY.md) before reporting a vulnerability.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All changes should include tests when
behavior changes and pass make check.

## License

Janus is released under the [MIT License](LICENSE).
