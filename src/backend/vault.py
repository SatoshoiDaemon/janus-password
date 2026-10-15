"""Local vault key lifecycle, atomic migration and portable encrypted backups.

Only random data keys live in the process. Passwords and keys never enter Flask's
client-side signed cookie. Run one local process; multiple workers are unsupported.
"""

import json
import os
import secrets
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select

from . import database as db
from .auth import decrypt_password, encrypt_password

FORMAT_VERSION = 1
CRYPTO_VERSION = 2
TIMEOUT = max(1, int(os.environ.get("VAULT_TIMEOUT", "300")))
mutex = threading.RLock()
_sessions = {}


class VaultError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


@contextmanager
def transaction(user_id):
    """Serialize vault operations, including across SQLite processes."""
    with db.engine.connect() as conn:
        if db.engine.dialect.name == "sqlite":
            conn.exec_driver_sql("BEGIN IMMEDIATE")
        else:
            conn.begin()
            conn.execute(select(db.users.c.id).where(db.users.c.id == user_id).with_for_update())
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def _metadata(conn, user_id):
    meta = conn.execute(select(db.vaults).where(db.vaults.c.user_id == user_id)).mappings().first()
    if meta and meta["crypto_version"] != CRYPTO_VERSION:
        raise VaultError("Versão criptográfica do cofre não suportada.", 409)
    return meta


def _credentials(conn, user_id):
    return conn.execute(select(db.credentials).where(db.credentials.c.user_id == user_id)).mappings().all()


def _forget(token):
    entry = _sessions.pop(token, None)
    if entry:
        entry["key"][:] = b"\0" * len(entry["key"])


def _prune():
    for token, entry in list(_sessions.items()):
        if time.monotonic() - entry["last_used"] >= TIMEOUT:
            _forget(token)


def invalidate(user_id):
    for token, entry in list(_sessions.items()):
        if entry["user_id"] == user_id:
            _forget(token)


def lock(token):
    with mutex:
        _forget(token)


def _open(user_id, key, revision):
    _prune()
    token = secrets.token_urlsafe(32)
    _sessions[token] = {"user_id": user_id, "key": bytearray(key), "revision": revision, "last_used": time.monotonic()}
    return token


def key_for(conn, user_id, token, touch=True):
    _prune()
    entry = _sessions.get(token)
    meta = _metadata(conn, user_id)
    if not entry or entry["user_id"] != user_id or not meta or meta["revision"] != entry["revision"]:
        _forget(token)
        raise VaultError("Cofre bloqueado. Desbloqueie com a senha mestra.", 423)
    if touch:
        entry["last_used"] = time.monotonic()
    return bytes(entry["key"])


def seal(value, key):
    return "v2$" + Fernet(key).encrypt(value.encode("utf-8")).decode("ascii")


def unseal(value, key):
    try:
        if not isinstance(value, str) or not value.startswith("v2$"):
            raise ValueError("Unsupported ciphertext")
        return Fernet(key).decrypt(value[3:].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise VaultError("Registro corrompido ou formato não suportado; nenhum dado foi alterado.", 409) from exc


def unwrap(wrapped, password):
    key = decrypt_password(wrapped, password)
    if key is None:
        raise VaultError("Senha mestra incorreta ou envelope corrompido.", 401)
    try:
        encoded = key.encode("ascii")
        Fernet(encoded)
        return encoded
    except (ValueError, UnicodeError) as exc:
        raise VaultError("Envelope de chave inválido.", 409) from exc


def unlock(user_id, password, legacy_passwords=None):
    if not isinstance(password, str) or not password:
        raise VaultError("Senha mestra é obrigatória.")
    with mutex, transaction(user_id) as conn:
        meta = _metadata(conn, user_id)
        if meta:
            key = unwrap(meta["wrapped_key"], password)
            for row in _credentials(conn, user_id):
                unseal(row["password_encrypted"], key)
            revision = meta["revision"]
        else:
            # Authenticate every legacy item BEFORE establishing a vault password.
            # Mixed-password legacy vaults may provide per-item recovery passwords.
            rows = _credentials(conn, user_id)
            if not rows and len(password) < 12:
                raise VaultError("A senha mestra de um cofre novo deve ter pelo menos 12 caracteres.")
            recovered = []
            for row in rows:
                item_password = (legacy_passwords or {}).get(str(row["id"]), password)
                value = decrypt_password(row["password_encrypted"], item_password)
                if value is None:
                    raise VaultError(f"Não foi possível recuperar a credencial {row['id']}; migração cancelada.", 409)
                recovered.append((row["id"], value))
            key = Fernet.generate_key()
            revision = 1
            conn.execute(
                db.vaults.insert().values(
                    user_id=user_id,
                    wrapped_key=encrypt_password(key.decode(), password),
                    revision=revision,
                    crypto_version=CRYPTO_VERSION,
                )
            )
            for item_id, value in recovered:
                conn.execute(
                    db.credentials.update()
                    .where(db.credentials.c.id == item_id)
                    .values(password_encrypted=seal(value, key))
                )
        # Commit succeeds before publishing a session.
    with mutex:
        return _open(user_id, key, revision)


def change_password(user_id, token, current_password, new_password):
    if not isinstance(new_password, str) or len(new_password) < 12:
        raise VaultError("A nova senha mestra deve ter pelo menos 12 caracteres.")
    with mutex, transaction(user_id) as conn:
        key = key_for(conn, user_id, token)
        meta = _metadata(conn, user_id)
        if not secrets.compare_digest(unwrap(meta["wrapped_key"], current_password), key):
            raise VaultError("Senha mestra incorreta.", 401)
        for row in _credentials(conn, user_id):
            unseal(row["password_encrypted"], key)
        automatic_backup(conn, user_id, key, force=True)
        conn.execute(
            db.vaults.update()
            .where(db.vaults.c.user_id == user_id)
            .values(wrapped_key=encrypt_password(key.decode(), new_password), revision=meta["revision"] + 1)
        )
    with mutex:
        invalidate(user_id)


def snapshot(conn, user_id, key):
    meta = _metadata(conn, user_id)
    credentials = [dict(row) for row in _credentials(conn, user_id)]
    for row in credentials:
        unseal(row["password_encrypted"], key)
    notes = [
        dict(row)
        for row in conn.execute(select(db.secure_notes).where(db.secure_notes.c.user_id == user_id)).mappings()
    ]
    for row in notes:
        if not isinstance(row["content_encrypted"], str) or not row["content_encrypted"].startswith("v1$"):
            raise VaultError(f"Nota {row['id']} usa formato não suportado. Recupere-a antes de exportar.", 409)
    payload = {"version": FORMAT_VERSION, "credentials": credentials, "notes": notes}
    # The entire payload, including names and note password hashes, is encrypted.
    # Bind the envelope to the authenticated payload to detect envelope tampering.
    payload["wrapped_key"] = meta["wrapped_key"]
    return {
        "format": "janus-backup",
        "version": FORMAT_VERSION,
        "crypto_version": CRYPTO_VERSION,
        "wrapped_key": meta["wrapped_key"],
        "payload": seal(json.dumps(payload, ensure_ascii=False), key),
    }


def export_backup(user_id, token):
    with mutex, transaction(user_id) as conn:
        key = key_for(conn, user_id, token)
        return snapshot(conn, user_id, key)


def _validate_backup(backup, password):
    if (
        not isinstance(backup, dict)
        or backup.get("format") != "janus-backup"
        or backup.get("version") != FORMAT_VERSION
        or backup.get("crypto_version") != CRYPTO_VERSION
    ):
        raise VaultError("Formato ou versão de backup não suportado.")
    try:
        key = unwrap(backup["wrapped_key"], password)
        payload = json.loads(unseal(backup["payload"], key))
        if payload["version"] != FORMAT_VERSION or payload["wrapped_key"] != backup["wrapped_key"]:
            raise ValueError("Envelope mismatch")
        for table_name, table in (("credentials", db.credentials), ("notes", db.secure_notes)):
            rows = payload[table_name]
            if not isinstance(rows, list):
                raise ValueError("Invalid records")
            expected = set(table.columns.keys())
            ids = set()
            for row in rows:
                if not isinstance(row, dict) or set(row) != expected or type(row["id"]) is not int or row["id"] in ids:
                    raise ValueError("Invalid record fields")
                ids.add(row["id"])
                if any(value is not None and not isinstance(value, (str, int)) for value in row.values()):
                    raise ValueError("Invalid field type")
                if table_name == "credentials":
                    unseal(row["password_encrypted"], key)
                elif not isinstance(row["content_encrypted"], str) or not row["content_encrypted"].startswith("v1$"):
                    raise ValueError("Unsupported note format")
        return key, payload
    except (KeyError, TypeError, ValueError) as exc:
        raise VaultError("Backup inválido; nenhum dado foi alterado.") from exc


def restore_backup(user_id, backup, password):
    key, payload = _validate_backup(backup, password)
    with mutex, transaction(user_id) as conn:
        count_notes = conn.execute(select(db.secure_notes.c.id).where(db.secure_notes.c.user_id == user_id)).first()
        if _credentials(conn, user_id) or count_notes:
            raise VaultError("Restaure em uma conta local vazia para evitar sobrescrever dados.", 409)
        previous = _metadata(conn, user_id)
        revision = previous["revision"] + 1 if previous else 1
        conn.execute(db.vaults.delete().where(db.vaults.c.user_id == user_id))
        conn.execute(
            db.vaults.insert().values(
                user_id=user_id, wrapped_key=backup["wrapped_key"], revision=revision, crypto_version=CRYPTO_VERSION
            )
        )
        for table_name, table in (("credentials", db.credentials), ("notes", db.secure_notes)):
            for row in payload[table_name]:
                values = {k: v for k, v in row.items() if k not in {"id", "user_id"}}
                values["user_id"] = user_id
                if table_name == "notes":
                    # Old local links must never become active on the new installation.
                    values["access_token"] = secrets.token_urlsafe(32)
                    values["access_token_revoked_at"] = "1970-01-01 00:00:00"
                conn.execute(table.insert().values(**values))
    with mutex:
        invalidate(user_id)
    return {"credentials": len(payload["credentials"]), "notes": len(payload["notes"])}


def automatic_backup(conn, user_id, key, force=False):
    """Pre-mutation, encrypted recovery point. Failure aborts the mutation.

    Configured interval is a minimum interval between snapshots, evaluated on
    writes. No scheduler or online service is required.
    """
    directory = os.environ.get("JANUS_BACKUP_DIR")
    if not directory:
        return
    folder = Path(directory).expanduser() / f"user-{user_id}"
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    existing = sorted(folder.glob("*.janus"), key=lambda p: p.stat().st_mtime)
    interval = max(0, int(os.environ.get("JANUS_BACKUP_INTERVAL", "3600")))
    if not force and existing and time.time() - existing[-1].stat().st_mtime < interval:
        return
    backup = snapshot(conn, user_id, key)
    descriptor, temporary = tempfile.mkstemp(prefix=".janus-", dir=folder)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(backup, output, ensure_ascii=False)
            output.flush()
            os.fsync(output.fileno())
        destination = folder / f"{time.time_ns()}-{secrets.token_hex(4)}.janus"
        os.replace(temporary, destination)
        retention = max(1, int(os.environ.get("JANUS_BACKUP_RETENTION", "10")))
        for old in existing[: max(0, len(existing) + 1 - retention)]:
            old.unlink()
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _expiry_worker():
    while True:
        time.sleep(max(1, min(30, TIMEOUT)))
        with mutex:
            _prune()


threading.Thread(target=_expiry_worker, name="janus-vault-expiry", daemon=True).start()
