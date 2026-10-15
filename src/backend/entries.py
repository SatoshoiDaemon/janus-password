"""Encrypted credential metadata, history, trash and advanced vault items."""

import base64
import hashlib
import json
import secrets
from datetime import datetime, timezone
from urllib.parse import urlsplit

import pyotp
from sqlalchemy import select

from . import database as db, vault


def now():
    return datetime.now(timezone.utc).isoformat()


def encode(value, key):
    return vault.seal(json.dumps(value, ensure_ascii=False), key)


def decode(value, key):
    try:
        return json.loads(vault.unseal(value, key))
    except (ValueError, TypeError) as exc:
        raise vault.VaultError("Dados estruturados corrompidos.", 409) from exc


def fields(data):
    result = {"urls": [], "tags": [], "folder": "", "favorite": False, "custom_fields": [], "notes": "", "totp": ""}
    for name in result:
        if name in data:
            result[name] = data[name]
    if not isinstance(result["urls"], list) or not all(
        isinstance(url, str)
        and urlsplit(url).scheme in {"https", "http"}
        and urlsplit(url).hostname
        and not urlsplit(url).username
        for url in result["urls"]
    ):
        raise vault.VaultError("URLs devem ser endereços HTTP/HTTPS completos sem credenciais embutidas.")
    if not isinstance(result["tags"], list) or not all(
        isinstance(tag, str) and len(tag) <= 100 for tag in result["tags"]
    ):
        raise vault.VaultError("Tags inválidas.")
    if not all(isinstance(result[k], str) for k in ("folder", "notes", "totp")) or type(result["favorite"]) is not bool:
        raise vault.VaultError("Metadados inválidos.")
    if not isinstance(result["custom_fields"], list) or not all(
        isinstance(f, dict) and set(f) == {"name", "value"} and all(isinstance(v, str) for v in f.values())
        for f in result["custom_fields"]
    ):
        raise vault.VaultError("Campos personalizados devem conter name e value de texto.")
    if result["totp"]:
        totp(result["totp"])
    return result


def totp(secret, at=None):
    try:
        generator = pyotp.parse_uri(secret) if secret.startswith("otpauth://") else pyotp.TOTP(secret.replace(" ", ""))
        if (
            not isinstance(generator, pyotp.TOTP)
            or generator.interval not in {15, 30, 60}
            or generator.digits not in {6, 8}
        ):
            raise ValueError("Unsupported TOTP")
        instant = int(datetime.now(timezone.utc).timestamp()) if at is None else int(at)
        return {"code": generator.at(instant), "remaining": generator.interval - instant % generator.interval}
    except (ValueError, TypeError, base64.binascii.Error) as exc:
        raise vault.VaultError("Segredo TOTP inválido; use Base32 ou URI otpauth TOTP.") from exc


def owned(conn, user_id, item_id, key, include_deleted=False):
    row = (
        conn.execute(select(db.credentials).where(db.credentials.c.user_id == user_id, db.credentials.c.id == item_id))
        .mappings()
        .first()
    )
    if row is None:
        raise vault.VaultError("Credencial não encontrada.", 404)
    state = (
        conn.execute(
            select(db.credential_data).where(
                db.credential_data.c.credential_id == item_id, db.credential_data.c.user_id == user_id
            )
        )
        .mappings()
        .first()
    )
    if state and state["deleted_at"] and not include_deleted:
        raise vault.VaultError("Credencial está na lixeira.", 404)
    extra = decode(state["payload"], key) if state else fields({})
    return {**dict(row), **extra, "deleted_at": state["deleted_at"] if state else None}


def list_credentials(conn, user_id, key, trash=False):
    result = []
    for row in vault._credentials(conn, user_id):
        item = owned(conn, user_id, row["id"], key, True)
        if bool(item["deleted_at"]) == trash:
            # Custom fields, notes and TOTP secrets are only revealed explicitly.
            result.append(
                {
                    k: v
                    for k, v in item.items()
                    if k not in {"password_encrypted", "user_id", "notes", "custom_fields", "totp"}
                }
            )
    return sorted(result, key=lambda r: (not r["favorite"], r["site_name"].casefold(), r["id"]))


def reveal(conn, user_id, item_id, key, include_deleted=False):
    item = owned(conn, user_id, item_id, key, include_deleted)
    item["password"] = vault.unseal(item.pop("password_encrypted"), key)
    item.pop("user_id", None)
    return item


def write(conn, user_id, key, data, item_id=None):
    current = reveal(conn, user_id, item_id, key) if item_id else {}
    merged = {**current, **data}
    site, password = merged.get("site_name"), merged.get("password")
    if not isinstance(site, str) or not site.strip() or not isinstance(password, str) or not password:
        raise vault.VaultError("Nome e senha são obrigatórios.")
    if not all(isinstance(merged.get(k, ""), str) for k in ("login", "email")):
        raise vault.VaultError("Login e email devem ser texto.")
    extra = fields(merged)
    values = {
        "site_name": site.strip(),
        "login": merged.get("login", ""),
        "email": merged.get("email", ""),
        "password_encrypted": vault.seal(password, key),
        "updated_at": now(),
    }
    if item_id:
        conn.execute(
            db.credential_history.insert().values(
                user_id=user_id, credential_id=item_id, payload=encode(current, key), created_at=now()
            )
        )
        conn.execute(
            db.credentials.update()
            .where(db.credentials.c.id == item_id, db.credentials.c.user_id == user_id)
            .values(**values)
        )
        conn.execute(
            db.credential_data.delete().where(
                db.credential_data.c.credential_id == item_id, db.credential_data.c.user_id == user_id
            )
        )
    else:
        result = conn.execute(db.credentials.insert().values(user_id=user_id, **values))
        item_id = result.inserted_primary_key[0]
    conn.execute(db.credential_data.insert().values(credential_id=item_id, user_id=user_id, payload=encode(extra, key)))
    return item_id


def trash(conn, user_id, key, item_id, action):
    item = owned(conn, user_id, item_id, key, True)
    if action == "purge":
        if not item["deleted_at"]:
            raise vault.VaultError("Mova para a lixeira antes de excluir permanentemente.", 409)
        for table in (db.credential_history, db.attachments, db.credential_data):
            conn.execute(table.delete().where(table.c.user_id == user_id, table.c.credential_id == item_id))
        conn.execute(db.credentials.delete().where(db.credentials.c.id == item_id, db.credentials.c.user_id == user_id))
        return
    state = conn.execute(
        select(db.credential_data).where(
            db.credential_data.c.credential_id == item_id, db.credential_data.c.user_id == user_id
        )
    ).first()
    deleted = None if action == "restore" else now()
    if state:
        conn.execute(
            db.credential_data.update()
            .where(db.credential_data.c.credential_id == item_id, db.credential_data.c.user_id == user_id)
            .values(deleted_at=deleted)
        )
    else:
        conn.execute(
            db.credential_data.insert().values(
                credential_id=item_id, user_id=user_id, payload=encode(fields(item), key), deleted_at=deleted
            )
        )


def health(conn, user_id, key):
    items = [reveal(conn, user_id, i["id"], key) for i in list_credentials(conn, user_id, key)]
    counts = {}
    for item in items:
        digest = hashlib.sha256(item["password"].encode()).hexdigest()
        counts[digest] = counts.get(digest, 0) + 1
    result = []
    for item in items:
        password = item["password"]
        age = datetime.now(timezone.utc) - datetime.fromisoformat(item["updated_at"].replace(" ", "T")).replace(
            tzinfo=timezone.utc
        )
        weak = len(password) < 12 or len(set(password)) < 5
        result.append(
            {
                "id": item["id"],
                "weak": weak,
                "reused": counts[hashlib.sha256(password.encode()).hexdigest()] > 1,
                "old": age.days >= 180,
                "age_days": age.days,
            }
        )
    return result


def write_item(conn, user_id, key, data, item_id=None):
    kind = data.get("kind")
    name = data.get("name")
    body = data.get("fields")
    if (
        kind not in {"identity", "card", "note"}
        or not isinstance(name, str)
        or not name.strip()
        or not isinstance(body, dict)
        or not all(isinstance(k, str) and isinstance(v, str) for k, v in body.items())
    ):
        raise vault.VaultError("Item inválido: informe kind, name e fields de texto.")
    values = {"kind": kind, "name": name, "payload": encode(body, key), "updated_at": now()}
    if item_id:
        existing = conn.execute(
            select(db.vault_items).where(
                db.vault_items.c.id == item_id,
                db.vault_items.c.user_id == user_id,
                db.vault_items.c.deleted_at.is_(None),
            )
        ).first()
        if not existing:
            raise vault.VaultError("Item não encontrado.", 404)
        decode(existing._mapping["payload"], key)
        conn.execute(
            db.vault_items.update()
            .where(db.vault_items.c.id == item_id, db.vault_items.c.user_id == user_id)
            .values(**values)
        )
        return item_id
    return conn.execute(db.vault_items.insert().values(user_id=user_id, **values)).inserted_primary_key[0]


def add_attachment(conn, user_id, key, data):
    try:
        content = base64.b64decode(data["content"], validate=True)
        name = data["name"]
        if not isinstance(name, str) or not name or len(content) > 8 * 1024 * 1024:
            raise ValueError("Invalid file")
    except (KeyError, ValueError, TypeError) as exc:
        raise vault.VaultError("Anexo inválido; limite de 8 MiB por arquivo.") from exc
    credential_id = data.get("credential_id")
    if credential_id is not None:
        owned(conn, user_id, credential_id, key)
    return conn.execute(
        db.attachments.insert().values(
            user_id=user_id,
            credential_id=credential_id,
            payload=encode(
                {
                    "name": name,
                    "content": base64.b64encode(content).decode(),
                    "mime": data.get("mime", "application/octet-stream"),
                    "size": len(content),
                },
                key,
            ),
            created_at=now(),
        )
    ).inserted_primary_key[0]


def passphrase(count=6, separator="-"):
    # Bundled EFF long list: no network fetch or small hand-written vocabulary.
    from pathlib import Path

    words = Path(__file__).with_name("wordlist.txt").read_text().splitlines()
    if type(count) is not int or not 4 <= count <= 12 or not isinstance(separator, str) or len(separator) > 8:
        raise vault.VaultError("Use de 4 a 12 palavras e separador de até 8 caracteres.")
    return separator.join(secrets.choice(words) for _ in range(count))
