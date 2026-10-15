import copy
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import event, select, text
from sqlalchemy.exc import OperationalError

from src.backend import database as db, vault
from src.backend.app import app
from src.backend.auth import encrypt_password
from .conftest import csrf_headers
from .test_api import register_and_login


MASTER = "master-secret"


def unlock(client, password=MASTER, **extra):
    return client.post("/api/vault/unlock", json={"master_password": password, **extra}, headers=csrf_headers(client))


def create(client, password="stored-secret"):
    return client.post(
        "/api/credentials", json={"site_name": "Example", "password": password}, headers=csrf_headers(client)
    )


def reveal(client, item_id):
    return client.post(f"/api/credentials/{item_id}/reveal", headers=csrf_headers(client))


def test_login_is_not_unlock_and_old_api_cannot_write(client):
    register_and_login(client)
    headers = csrf_headers(client)
    assert client.post("/api/vault/lock", headers=headers).status_code == 200
    assert client.get("/api/credentials").status_code == 423
    assert create(client).status_code == 423
    assert client.get("/api/notes").status_code == 423
    assert client.get("/api/user-info").status_code == 200
    assert unlock(client).status_code == 200
    bad = client.post(
        "/api/credentials", json={"site_name": "Bad", "password": "secret", "master_password": "typo"}, headers=headers
    )
    assert bad.status_code == 400
    assert client.get("/api/credentials").json["credentials"] == []


def test_password_change_preserves_ciphertext_and_revokes_sessions(authenticated_client):
    client = authenticated_client
    item_id = create(client).json["id"]
    with db.engine.connect() as conn:
        original = conn.execute(select(db.credentials.c.password_encrypted)).scalar_one()
    assert (
        client.post(
            "/api/vault/change-password",
            json={"current_password": "wrong", "new_password": "new-master-password"},
            headers=csrf_headers(client),
        ).status_code
        == 401
    )
    assert reveal(client, item_id).json["password"] == "stored-secret"
    response = client.post(
        "/api/vault/change-password",
        json={"current_password": MASTER, "new_password": "new-master-password"},
        headers=csrf_headers(client),
    )
    assert response.status_code == 200
    assert reveal(client, item_id).status_code == 423
    assert unlock(client).status_code == 401
    assert unlock(client, "new-master-password").status_code == 200
    assert reveal(client, item_id).json["password"] == "stored-secret"
    with db.engine.connect() as conn:
        assert conn.execute(select(db.credentials.c.password_encrypted)).scalar_one() == original


def test_lock_expiry_restart_and_cookie_contain_no_keys(authenticated_client, monkeypatch):
    client = authenticated_client
    item_id = create(client).json["id"]
    with client.session_transaction() as session:
        token = session["vault_token"]
        encoded = json.dumps(dict(session))
        assert MASTER not in encoded
        assert bytes(vault._sessions[token]["key"]).decode() not in encoded
    key_buffer = vault._sessions[token]["key"]
    before = vault._sessions[token]["last_used"]
    monkeypatch.setattr(vault.time, "monotonic", lambda: before + vault.TIMEOUT + 1)
    assert client.get("/api/vault/status").json["unlocked"] is False
    assert bytes(key_buffer) == b"\0" * len(key_buffer)
    assert reveal(client, item_id).status_code == 423
    assert unlock(client).status_code == 200
    with vault.mutex:
        for token in list(vault._sessions):
            vault.lock(token)
    assert reveal(client, item_id).status_code == 423
    assert unlock(client).status_code == 200
    assert reveal(client, item_id).json["password"] == "stored-secret"


def test_wrong_unlock_does_not_modify_data(authenticated_client):
    client = authenticated_client
    item_id = create(client).json["id"]
    with db.engine.connect() as conn:
        original = conn.execute(select(db.credentials)).mappings().all()
    assert unlock(client, "wrong").status_code == 401
    with db.engine.connect() as conn:
        assert conn.execute(select(db.credentials)).mappings().all() == original
    assert reveal(client, item_id).json["password"] == "stored-secret"


def test_corrupt_record_blocks_reveal_update_export_and_unlock(authenticated_client):
    client = authenticated_client
    item_id = create(client).json["id"]
    with db.engine.begin() as conn:
        original = conn.execute(select(db.credentials.c.password_encrypted)).scalar_one()
        conn.execute(db.credentials.update().values(password_encrypted="v2$corrupt"))
    assert reveal(client, item_id).status_code == 409
    assert (
        client.put(
            f"/api/credentials/{item_id}", json={"password": "replacement"}, headers=csrf_headers(client)
        ).status_code
        == 409
    )
    assert client.post("/api/vault/export", headers=csrf_headers(client)).status_code == 409
    assert unlock(client).status_code == 409
    with db.engine.begin() as conn:
        assert conn.execute(select(db.credentials.c.password_encrypted)).scalar_one() == "v2$corrupt"
        conn.execute(db.credentials.update().values(password_encrypted=original))
    assert reveal(client, item_id).json["password"] == "stored-secret"


def legacy_rows(client):
    register_and_login(client)
    with db.engine.begin() as conn:
        conn.execute(db.vaults.delete())
        for password, value in ((MASTER, "first"), ("other-password", "second")):
            conn.execute(
                db.credentials.insert().values(
                    user_id=1, site_name=value, password_encrypted=encrypt_password(value, password, legacy=True)
                )
            )


def test_mixed_legacy_passwords_require_explicit_recovery(client):
    legacy_rows(client)
    with db.engine.connect() as conn:
        original = conn.execute(select(db.credentials)).mappings().all()
    assert unlock(client).status_code == 409
    with db.engine.connect() as conn:
        assert conn.execute(select(db.credentials)).mappings().all() == original
        assert not conn.execute(select(db.vaults)).first()
    assert unlock(client, legacy_passwords={"2": "other-password"}).status_code == 200
    assert reveal(client, 1).json["password"] == "first"
    assert reveal(client, 2).json["password"] == "second"
    db.init_db()  # Repeated schema migration never re-encrypts or deletes records.
    assert reveal(client, 2).json["password"] == "second"


def test_migration_write_failure_rolls_back_entire_vault(client):
    legacy_rows(client)

    def fail_second(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("UPDATE credentials") and parameters[-1] == 2:
            raise OperationalError(statement, parameters, Exception("simulated disk full"))

    event.listen(db.engine, "before_cursor_execute", fail_second)
    try:
        with pytest.raises(OperationalError):
            vault.unlock(1, MASTER, {"2": "other-password"})
    finally:
        event.remove(db.engine, "before_cursor_execute", fail_second)
    with db.engine.connect() as conn:
        assert not conn.execute(select(db.vaults)).first()
        assert all(row.startswith("v1$") for row in conn.execute(select(db.credentials.c.password_encrypted)).scalars())
    assert unlock(client, legacy_passwords={"2": "other-password"}).status_code == 200


def test_commit_failure_leaves_old_value_readable(authenticated_client):
    client = authenticated_client
    item_id = create(client).json["id"]

    def fail_commit(conn):
        raise OperationalError("COMMIT", {}, Exception("simulated commit failure"))

    event.listen(db.engine, "commit", fail_commit)
    try:
        with pytest.raises(OperationalError):
            client.put(f"/api/credentials/{item_id}", json={"password": "new"}, headers=csrf_headers(client))
    finally:
        event.remove(db.engine, "commit", fail_commit)
    assert reveal(client, item_id).json["password"] == "stored-secret"


def test_backup_round_trip_into_clean_installation(authenticated_client, tmp_path):
    client = authenticated_client
    create(client)
    note = client.post(
        "/api/notes",
        json={"title": "Private note", "content": "sensitive note", "note_password": "note-secret"},
        headers=csrf_headers(client),
    ).json
    exported = client.post("/api/vault/export", headers=csrf_headers(client))
    assert exported.status_code == 200
    backup = exported.json
    for secret in ("Example", "stored-secret", "Private note", "sensitive note", MASTER):
        assert secret not in json.dumps(backup)
    assert backup["version"] == 2
    assert backup["crypto_version"] == 2
    # No source database, session, user IDs, or SECRET_KEY reused.
    db.configure_database(f"sqlite:///{tmp_path / 'clean-install.db'}")
    db.init_db()
    vault._sessions.clear()
    app.config["SECRET_KEY"] = "another-install-secret"
    with app.test_client() as clean:
        register_and_login(clean, "new-local-user")
        headers = csrf_headers(clean)
        restored = clean.post("/api/vault/restore", json={"backup": backup, "master_password": MASTER}, headers=headers)
        assert restored.status_code == 200
        assert restored.json["credentials"] == 1 and restored.json["notes"] == 1
        assert clean.get("/api/credentials").status_code == 423
        assert unlock(clean).status_code == 200
        item_id = clean.get("/api/credentials").json["credentials"][0]["id"]
        assert reveal(clean, item_id).json["password"] == "stored-secret"
        note_id = clean.get("/api/notes").json["notes"][0]["id"]
        assert (
            clean.post(f"/api/notes/{note_id}/reveal", json={"note_password": "note-secret"}, headers=headers).json[
                "content"
            ]
            == "sensitive note"
        )
        assert (
            clean.post(f"/api/notes/access/{note['access_token']}", json={"note_password": "note-secret"}).status_code
            == 404
        )


@pytest.mark.parametrize("mutation", ["password", "payload", "version", "envelope"])
def test_invalid_backup_never_writes(authenticated_client, mutation):
    client = authenticated_client
    create(client)
    backup = copy.deepcopy(client.post("/api/vault/export", headers=csrf_headers(client)).json)
    register_and_login(client, "restore-target")
    password = MASTER
    if mutation == "password":
        password = "wrong-password"
    if mutation == "payload":
        backup["payload"] = backup["payload"][:-10] + "corruption"
    if mutation == "version":
        backup["version"] = 999
    if mutation == "envelope":
        backup["wrapped_key"] = "v1$invalid"
    response = client.post(
        "/api/vault/restore", json={"backup": backup, "master_password": password}, headers=csrf_headers(client)
    )
    assert response.status_code in {400, 401, 409}
    assert client.get("/api/credentials").json["credentials"] == []


def test_restore_rejects_nonempty_vault(authenticated_client):
    client = authenticated_client
    item_id = create(client).json["id"]
    backup = client.post("/api/vault/export", headers=csrf_headers(client)).json
    assert (
        client.post(
            "/api/vault/restore", json={"backup": backup, "master_password": MASTER}, headers=csrf_headers(client)
        ).status_code
        == 409
    )
    assert reveal(client, item_id).json["password"] == "stored-secret"


def test_backup_rotation_and_failure_abort_writes(authenticated_client, tmp_path, monkeypatch):
    client = authenticated_client
    monkeypatch.setenv("JANUS_BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setenv("JANUS_BACKUP_INTERVAL", "0")
    monkeypatch.setenv("JANUS_BACKUP_RETENTION", "2")
    item_id = create(client).json["id"]
    create(client, "another-secret")
    create(client, "third-secret")
    files = list((tmp_path / "backups" / "user-1").glob("*.janus"))
    assert len(files) == 2
    assert all("stored-secret" not in path.read_text() for path in files)
    monkeypatch.setattr(vault.os, "replace", lambda *_: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        client.put(f"/api/credentials/{item_id}", json={"password": "lost-secret"}, headers=csrf_headers(client))
    assert reveal(client, item_id).json["password"] == "stored-secret"


def test_parallel_migration_creates_one_key(client):
    legacy_rows(client)
    with ThreadPoolExecutor(max_workers=4) as pool:
        tokens = list(pool.map(lambda _: vault.unlock(1, MASTER, {"2": "other-password"}), range(4)))
    with db.engine.connect() as conn:
        keys = [vault.key_for(conn, 1, token) for token in tokens]
        assert len(set(keys)) == 1
        assert len(conn.execute(select(db.vaults)).all()) == 1
        for row in conn.execute(select(db.credentials)).mappings():
            assert vault.unseal(row["password_encrypted"], keys[0]) == row["site_name"]


def test_schema_records_version_and_sqlite_corruption_is_reported(client, tmp_path):
    with db.engine.connect() as conn:
        assert conn.execute(select(db.schema_migrations.c.version)).scalars().all() == [1, 2]
        assert conn.execute(text("PRAGMA integrity_check")).scalar_one() == "ok"
    damaged = tmp_path / "damaged.db"
    damaged.write_bytes(b"this is not an sqlite database")
    db.configure_database(f"sqlite:///{damaged}")
    with pytest.raises(Exception, match="not a database"):
        db.init_db()
    assert damaged.read_bytes() == b"this is not an sqlite database"


def test_host_origin_and_no_store(client):
    assert client.get("/login", base_url="http://evil.example").status_code == 403
    assert client.post("/api/login", headers={"Origin": "https://evil.example"}, json={}).status_code == 403
    assert client.get("/login").headers["Cache-Control"] == "no-store"
    assert client.post("/api/vault/unlock", json={"master_password": MASTER}).status_code == 403


def test_restore_insert_failure_rolls_back_every_record(authenticated_client):
    client = authenticated_client
    create(client)
    assert (
        client.post(
            "/api/notes",
            json={"title": "Note", "content": "text", "note_password": "note-password"},
            headers=csrf_headers(client),
        ).status_code
        == 201
    )
    backup = client.post("/api/vault/export", headers=csrf_headers(client)).json
    register_and_login(client, "empty-restore-target")

    def fail_note_insert(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO secure_notes"):
            raise OperationalError(statement, parameters, Exception("simulated disk error"))

    event.listen(db.engine, "before_cursor_execute", fail_note_insert)
    try:
        with pytest.raises(OperationalError):
            client.post(
                "/api/vault/restore", json={"backup": backup, "master_password": MASTER}, headers=csrf_headers(client)
            )
    finally:
        event.remove(db.engine, "before_cursor_execute", fail_note_insert)
    assert client.get("/api/credentials").json["credentials"] == []
    assert client.get("/api/notes").json["notes"] == []
    assert unlock(client).status_code == 200


def test_automatic_snapshot_is_restorable(authenticated_client, tmp_path, monkeypatch):
    client = authenticated_client
    item_id = create(client).json["id"]
    monkeypatch.setenv("JANUS_BACKUP_DIR", str(tmp_path / "snapshots"))
    assert (
        client.put(
            f"/api/credentials/{item_id}", json={"password": "new-secret"}, headers=csrf_headers(client)
        ).status_code
        == 200
    )
    file = next((tmp_path / "snapshots" / "user-1").glob("*.janus"))
    backup = json.loads(file.read_text())
    register_and_login(client, "snapshot-recovery")
    assert (
        client.post(
            "/api/vault/restore", json={"backup": backup, "master_password": MASTER}, headers=csrf_headers(client)
        ).status_code
        == 200
    )
    assert unlock(client).status_code == 200
    restored_id = client.get("/api/credentials").json["credentials"][0]["id"]
    assert reveal(client, restored_id).json["password"] == "stored-secret"


def test_password_change_revokes_other_unlocks(authenticated_client):
    client = authenticated_client
    with client.session_transaction() as session:
        user_id = session["user_id"]
    other_token = vault.unlock(user_id, MASTER)
    key_buffer = vault._sessions[other_token]["key"]
    assert (
        client.post(
            "/api/vault/change-password",
            json={"current_password": MASTER, "new_password": "new-master-password"},
            headers=csrf_headers(client),
        ).status_code
        == 200
    )
    assert other_token not in vault._sessions
    assert bytes(key_buffer) == b"\0" * len(key_buffer)


def test_schema_migrates_old_note_columns_without_replacing_records(client, tmp_path):
    db.configure_database(f"sqlite:///{tmp_path / 'old-schema.db'}")
    with db.engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, email TEXT UNIQUE, password_hash TEXT, created_at TEXT)"
            )
        )
        conn.execute(
            text(
                "CREATE TABLE secure_notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, content_encrypted TEXT, note_password_hash TEXT, access_token TEXT, created_at TEXT, updated_at TEXT)"
            )
        )
        conn.execute(text("INSERT INTO users VALUES (1, 'old', 'old@example.test', 'old-hash', '2020-01-01')"))
        conn.execute(
            text(
                "INSERT INTO secure_notes VALUES (1, 1, 'Retain me', 'old-ciphertext', 'old-hash', 'old-token', '2020-01-01', '2020-01-01')"
            )
        )
    db.init_db()
    db.init_db()
    with db.engine.connect() as conn:
        row = conn.execute(select(db.secure_notes)).mappings().one()
        assert row["title"] == "Retain me"
        assert row["content_encrypted"] == "old-ciphertext"
        assert row["access_token_expires_at"] is not None
        assert conn.execute(select(db.schema_migrations.c.version)).scalars().all() == [1, 2]


@pytest.mark.parametrize("payload", [[], {"master_password": []}, {"master_password": None}])
def test_malformed_api_input_is_rejected(authenticated_client, payload):
    assert (
        authenticated_client.post(
            "/api/vault/unlock", json=payload, headers=csrf_headers(authenticated_client)
        ).status_code
        == 400
    )


def test_invalid_backup_envelope_type_is_rejected(authenticated_client):
    response = authenticated_client.post(
        "/api/vault/restore",
        json={
            "master_password": MASTER,
            "backup": {
                "format": "janus-backup",
                "version": 1,
                "crypto_version": 2,
                "wrapped_key": 42,
                "payload": "anything",
            },
        },
        headers=csrf_headers(authenticated_client),
    )
    assert response.status_code == 401


def test_export_reports_unsupported_note_format(authenticated_client):
    client = authenticated_client
    assert (
        client.post(
            "/api/notes",
            json={"title": "Note", "content": "text", "note_password": "note-password"},
            headers=csrf_headers(client),
        ).status_code
        == 201
    )
    with db.engine.begin() as conn:
        conn.execute(db.secure_notes.update().values(content_encrypted="legacy-unsupported-content"))
    assert client.post("/api/vault/export", headers=csrf_headers(client)).status_code == 409
    with db.engine.connect() as conn:
        assert conn.execute(select(db.secure_notes.c.content_encrypted)).scalar_one() == "legacy-unsupported-content"
