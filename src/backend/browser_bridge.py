"""Revocable browser pairing; no cookies or passwords are accepted by the bridge."""

import hashlib
import hmac
import secrets
from functools import wraps
from urllib.parse import urlsplit

from flask import jsonify, request, session
from sqlalchemy import select

from . import database as db, entries, vault


def origin(url):
    try:
        if not isinstance(url, str):
            raise ValueError("URL must be text")
        parsed = urlsplit(url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.hostname.endswith(".")
        ):
            raise ValueError("Unsafe URL")
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        port = parsed.port
        if ":" in host:
            host = f"[{host}]"
        suffix = f":{port}" if port and port != {"http": 80, "https": 443}[parsed.scheme] else ""
        return f"{parsed.scheme}://{host}{suffix}"
    except (ValueError, UnicodeError, TypeError) as exc:
        raise vault.VaultError("URL inválida.") from exc


def extension_origin(value):
    if not isinstance(value, str):
        raise vault.VaultError("Origem da extensão inválida.")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"chrome-extension", "moz-extension"}
        or not parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username
    ):
        raise vault.VaultError("Informe a origem exibida pela extensão, sem caminho.")
    return value


def cors_origin_allowed(value):
    if not value:
        return False
    with db.engine.connect() as conn:
        return (
            conn.execute(select(db.browser_pairings.c.id).where(db.browser_pairings.c.origin == value)).first()
            is not None
        )


def install(app, login_required, operation):
    @app.route("/api/browser/pairings", methods=["GET", "POST"])
    @login_required
    @operation
    def pairings(conn, key):
        if request.method == "GET":
            rows = conn.execute(
                select(
                    db.browser_pairings.c.id,
                    db.browser_pairings.c.name,
                    db.browser_pairings.c.origin,
                    db.browser_pairings.c.created_at,
                ).where(db.browser_pairings.c.user_id == session["user_id"])
            ).mappings()
            return jsonify({"pairings": [dict(row) for row in rows]})
        data = request.get_json() or {}
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise vault.VaultError("Nome do navegador é obrigatório.")
        allowed = extension_origin(data.get("origin", ""))
        token = secrets.token_urlsafe(32)
        result = conn.execute(
            db.browser_pairings.insert().values(
                user_id=session["user_id"],
                name=name,
                origin=allowed,
                token_hash=hashlib.sha256(token.encode()).hexdigest(),
                created_at=entries.now(),
            )
        )
        return jsonify({"id": result.inserted_primary_key[0], "token": token}), 201

    @app.delete("/api/browser/pairings/<int:pairing_id>")
    @login_required
    @operation
    def revoke_pairing(conn, key, pairing_id):
        conn.execute(
            db.browser_pairings.delete().where(
                db.browser_pairings.c.id == pairing_id, db.browser_pairings.c.user_id == session["user_id"]
            )
        )
        return jsonify({"message": "Pareamento revogado."})

    def paired(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            token = request.headers.get("Authorization", "").removeprefix("Bearer ")
            if len(token) < 32 or len(token) > 128:
                raise vault.VaultError("Pareamento inválido.", 401)
            with vault.mutex, db.engine.connect() as lookup:
                row = (
                    lookup.execute(
                        select(db.browser_pairings).where(
                            db.browser_pairings.c.token_hash == hashlib.sha256(token.encode()).hexdigest()
                        )
                    )
                    .mappings()
                    .first()
                )
                supplied = request.headers.get("X-Janus-Extension-Origin", "")
                if (
                    not row
                    or not hmac.compare_digest(row["origin"], supplied)
                    or request.headers.get("Origin", row["origin"]) != row["origin"]
                ):
                    raise vault.VaultError("Pareamento inválido.", 401)
                user_id = row["user_id"]
            with vault.mutex, vault.transaction(user_id) as conn:
                if (
                    conn.execute(
                        select(db.browser_pairings.c.id).where(
                            db.browser_pairings.c.id == row["id"], db.browser_pairings.c.token_hash == row["token_hash"]
                        )
                    ).first()
                    is None
                ):
                    raise vault.VaultError("Pareamento revogado.", 401)
                key = None
                for handle, entry in list(vault._sessions.items()):
                    if entry["user_id"] == user_id:
                        try:
                            key = vault.key_for(conn, user_id, handle, touch=False)
                            break
                        except vault.VaultError:
                            pass
                if key is None:
                    raise vault.VaultError("Desbloqueie o cofre no Janus local.", 423)
                # Pairing use does not indefinitely extend the dashboard unlock.
                return function(conn, user_id, key, *args, **kwargs)

        return wrapped

    @app.post("/api/browser/matches")
    @paired
    def browser_matches(conn, user_id, key):
        requested = origin((request.get_json() or {}).get("url", ""))
        items = entries.list_credentials(conn, user_id, key)
        return jsonify(
            {
                "origin": requested,
                "credentials": [
                    {"id": row["id"], "site_name": row["site_name"], "login": row["login"]}
                    for row in items
                    if requested in {origin(url) for url in row["urls"]}
                ],
            }
        )

    @app.post("/api/browser/reveal")
    @paired
    def browser_reveal(conn, user_id, key):
        data = request.get_json() or {}
        requested = origin(data.get("url", ""))
        item = entries.reveal(conn, user_id, data.get("id"), key)
        if requested not in {origin(url) for url in item["urls"]}:
            raise vault.VaultError("Domínio não corresponde à credencial.", 403)
        return jsonify({"origin": requested, "login": item["login"] or item["email"], "password": item["password"]})

    @app.post("/api/browser/capture")
    @paired
    def browser_capture(conn, user_id, key):
        data = request.get_json() or {}
        url = origin(data.get("url", ""))
        vault.automatic_backup(conn, user_id, key)
        item_id = entries.write(
            conn,
            user_id,
            key,
            {
                "site_name": data.get("name") or urlsplit(url).hostname,
                "login": data.get("login", ""),
                "password": data.get("password", ""),
                "urls": [url],
            },
        )
        return jsonify({"id": item_id}), 201

    @app.post("/api/browser/generate")
    @paired
    def browser_generate(conn, user_id, key):
        from .auth import generate_secure_password

        return jsonify({"password": generate_secure_password(24)})
