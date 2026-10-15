import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from pykeepass import create_database
from sqlalchemy import select

from src.backend import database as db, entries, local, vault
from src.backend.auth import decrypt_password, encrypt_password, hash_password, legacy_hash_password, verify_password
from .conftest import csrf_headers
from .test_api import register_and_login


def api(client, path, method="POST", data=None):
    return client.open(path, method=method, json=data, headers=csrf_headers(client))


def create(client, **fields):
    return api(client, "/api/credentials", data={"site_name": "Example", "password": "stored-secret", **fields})


def test_argon2_hashes_ciphertexts_and_bounded_parameters():
    hashed = hash_password("password")
    assert hashed.startswith("$argon2id$")
    assert verify_password("password", hashed)
    assert not verify_password("wrong", hashed)
    legacy = legacy_hash_password("old-password")
    assert verify_password("old-password", legacy)
    for old in (False, True):
        encrypted = encrypt_password("secret", "password", legacy=old)
        assert encrypted.startswith("v1$" if old else "v3$argon2id$")
        assert decrypt_password(encrypted, "password") == "secret"
        assert decrypt_password(encrypted, "wrong") is None
    assert decrypt_password("v3$argon2id$999999999,3,1$AAAA$AAAA", "password") is None
    assert not verify_password("password", hashed.replace("m=65536", "m=999999999"))


def test_legacy_login_and_envelope_upgrade_preserves_data(client):
    with db.engine.begin() as conn:
        user_id = conn.execute(
            db.users.insert().values(
                username="legacy", email="old@test.invalid", password_hash=legacy_hash_password("login-password")
            )
        ).inserted_primary_key[0]
        key = Fernet.generate_key()
        conn.execute(
            db.vaults.insert().values(
                user_id=user_id,
                wrapped_key=encrypt_password(key.decode(), "master-secret", legacy=True),
                revision=1,
                crypto_version=2,
            )
        )
        conn.execute(
            db.credentials.insert().values(
                user_id=user_id, site_name="Example", password_encrypted=vault.seal("old-secret", key)
            )
        )
    assert client.post("/api/login", json={"username": "legacy", "password": "login-password"}).status_code == 200
    assert api(client, "/api/vault/unlock", data={"master_password": "master-secret"}).status_code == 200
    with db.engine.connect() as conn:
        assert conn.execute(select(db.users.c.password_hash)).scalar_one().startswith("$argon2id$")
        assert conn.execute(select(db.vaults.c.wrapped_key)).scalar_one().startswith("v3$argon2id$")
        assert vault.unseal(conn.execute(select(db.credentials.c.password_encrypted)).scalar_one(), key) == "old-secret"


def test_metadata_history_trash_and_health(authenticated_client):
    client = authenticated_client
    created = create(
        client,
        urls=["https://example.com", "https://accounts.example.com/login"],
        tags=["work"],
        folder="Work",
        favorite=True,
        custom_fields=[{"name": "PIN", "value": "1234"}],
        totp="JBSWY3DPEHPK3PXP",
    )
    assert created.status_code == 201
    item_id = created.json["id"]
    listed = client.get("/api/credentials").json["credentials"][0]
    assert listed["folder"] == "Work" and listed["favorite"]
    assert "custom_fields" not in listed and "totp" not in listed
    assert api(client, f"/api/credentials/{item_id}/reveal").json["custom_fields"][0]["value"] == "1234"
    assert api(client, f"/api/credentials/{item_id}", "PUT", {"password": "new-secret"}).status_code == 200
    history = client.get(f"/api/credentials/{item_id}/history").json["history"]
    assert len(history) == 1
    version = history[0]["id"]
    assert api(client, f"/api/credentials/{item_id}/history/{version}/reveal").json["password"] == "stored-secret"
    assert api(client, f"/api/credentials/{item_id}/history/{version}/restore").status_code == 200
    assert api(client, f"/api/credentials/{item_id}/reveal").json["password"] == "stored-secret"
    create(client)
    assert all(row["reused"] for row in client.get("/api/vault/health").json["items"])
    assert api(client, f"/api/credentials/{item_id}", "DELETE").status_code == 200
    assert api(client, f"/api/credentials/{item_id}/reveal").status_code == 404
    assert client.get("/api/credentials?trash=1").json["credentials"][0]["id"] == item_id
    assert api(client, f"/api/credentials/{item_id}/restore").status_code == 200
    assert api(client, f"/api/credentials/{item_id}/purge", "DELETE").status_code == 409
    api(client, f"/api/credentials/{item_id}", "DELETE")
    assert api(client, f"/api/credentials/{item_id}/purge", "DELETE").status_code == 200
    assert client.get(f"/api/credentials/{item_id}/history").status_code == 404


def test_totp_rfc6238_vector():
    # SHA1, 8 digits, epoch 59 from RFC 6238 test vectors.
    result = entries.totp("otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30", at=59)
    assert result == {"code": "94287082", "remaining": 1}
    with pytest.raises(vault.VaultError):
        entries.totp("not base32!")


def test_portable_backup_includes_history_trash_items_and_attachments(authenticated_client):
    client = authenticated_client
    item_id = create(client, folder="Work", custom_fields=[{"name": "secret", "value": "custom-secret"}]).json["id"]
    api(client, f"/api/credentials/{item_id}", "PUT", {"password": "second-secret"})
    attached = api(
        client,
        "/api/attachments",
        data={"credential_id": item_id, "name": "secret.txt", "content": base64.b64encode(b"file-secret").decode()},
    )
    assert attached.status_code == 201
    card = api(
        client,
        "/api/items",
        data={"kind": "card", "name": "My card", "fields": {"number": "4111111111111111", "cvv": "123"}},
    )
    assert card.status_code == 201
    backup = api(client, "/api/vault/export").json
    encoded = json.dumps(backup)
    for secret in ("file-secret", "4111111111111111", "custom-secret", "second-secret"):
        assert secret not in encoded
    register_and_login(client, "restore-all")
    assert (
        api(client, "/api/vault/restore", data={"backup": backup, "master_password": "master-secret"}).status_code
        == 200
    )
    assert api(client, "/api/vault/unlock", data={"master_password": "master-secret"}).status_code == 200
    restored = client.get("/api/credentials").json["credentials"][0]
    assert restored["folder"] == "Work"
    attachments = client.get("/api/attachments").json["attachments"]
    assert attachments[0]["credential_id"] == restored["id"]
    assert (
        base64.b64decode(api(client, f"/api/attachments/{attachments[0]['id']}/reveal").json["content"])
        == b"file-secret"
    )
    cards = client.get("/api/items").json["items"]
    assert api(client, f"/api/items/{cards[0]['id']}/reveal").json["fields"]["number"] == "4111111111111111"
    assert len(client.get(f"/api/credentials/{restored['id']}/history").json["history"]) == 1


@pytest.mark.parametrize(
    "format_name,content",
    [
        ("csv", "name,username,password,url,folder,custom\nExample,alice,secret,https://example.com,Work,extra"),
        (
            "bitwarden",
            json.dumps(
                {
                    "encrypted": False,
                    "folders": [{"id": "f", "name": "Work"}],
                    "items": [
                        {
                            "type": 1,
                            "name": "Example",
                            "folderId": "f",
                            "login": {
                                "username": "alice",
                                "password": "secret",
                                "uris": [{"uri": "https://example.com"}],
                            },
                            "fields": [{"name": "custom", "value": "extra"}],
                        }
                    ],
                }
            ),
        ),
        (
            "keepass-xml",
            "<KeePassFile><Root><Group><Name>Work</Name><Entry><String><Key>Title</Key><Value>Example</Value></String><String><Key>UserName</Key><Value>alice</Value></String><String><Key>Password</Key><Value>secret</Value></String><String><Key>URL</Key><Value>https://example.com</Value></String><String><Key>custom</Key><Value>extra</Value></String></Entry></Group></Root></KeePassFile>",
        ),
    ],
)
def test_importers_preview_commit_and_duplicates(authenticated_client, format_name, content):
    client = authenticated_client
    data = {"format": format_name, "content": content}
    preview = api(client, "/api/vault/import/preview", data=data)
    assert preview.status_code == 200 and preview.json["count"] == 1
    assert client.get("/api/credentials").json["credentials"] == []
    assert api(client, "/api/vault/import", data=data).status_code == 400
    assert api(client, "/api/vault/import", data={**data, "confirmed": True}).json == {"imported": 1, "skipped": 0}
    assert api(client, "/api/vault/import", data={**data, "confirmed": True}).json == {"imported": 0, "skipped": 1}
    item = client.get("/api/credentials").json["credentials"][0]
    revealed = api(client, f"/api/credentials/{item['id']}/reveal").json
    assert revealed["password"] == "secret" and revealed["folder"] == "Work"
    assert revealed["custom_fields"] == [{"name": "custom", "value": "extra"}]


def test_kdbx_import_password_and_attachments(authenticated_client, tmp_path):
    path = tmp_path / "source.kdbx"
    kp = create_database(path, password="keepass-password")
    item = kp.add_entry(kp.root_group, "Example", "alice", "secret", url="https://example.com")
    binary = kp.add_binary(b"attached secret")
    item.add_attachment(binary, "private.txt")
    kp.save()
    data = {
        "format": "keepass-kdbx",
        "content": base64.b64encode(path.read_bytes()).decode(),
        "password": "wrong",
        "confirmed": True,
    }
    assert api(authenticated_client, "/api/vault/import", data=data).status_code == 400
    data["password"] = "keepass-password"
    response = api(authenticated_client, "/api/vault/import", data=data)
    assert response.status_code == 200, response.json
    assert response.json["imported"] == 1
    attachment = authenticated_client.get("/api/attachments").json["attachments"][0]
    assert attachment["name"] == "private.txt"


def test_import_failure_is_atomic_and_xml_entities_are_rejected(authenticated_client):
    client = authenticated_client
    csv = "name,username,password\nGood,alice,secret\nBad,bob,\n"
    assert (
        api(client, "/api/vault/import", data={"format": "csv", "content": csv, "confirmed": True}).status_code == 400
    )
    assert client.get("/api/credentials").json["credentials"] == []
    xml = '<!DOCTYPE x [<!ENTITY leak SYSTEM "file:///etc/passwd">]><KeePassFile>&leak;</KeePassFile>'
    assert api(client, "/api/vault/import/preview", data={"format": "keepass-xml", "content": xml}).status_code == 400


def test_bitwarden_structured_items(authenticated_client):
    data = {
        "items": [
            {"name": "card", "type": 3, "card": {"number": "4111111111111111"}},
            {"name": "identity", "type": 4, "identity": {"firstName": "Alice"}},
            {"name": "note", "type": 2, "notes": "secret note"},
        ]
    }
    response = api(
        authenticated_client,
        "/api/vault/import",
        data={"format": "bitwarden", "content": json.dumps(data), "confirmed": True},
    )
    assert response.json["imported"] == 3
    assert {item["kind"] for item in authenticated_client.get("/api/items").json["items"]} == {
        "card",
        "identity",
        "note",
    }


def test_browser_pairing_exact_origins_lock_and_revocation(authenticated_client):
    client = authenticated_client
    item_id = create(client, urls=["https://example.com"]).json["id"]
    extension = "chrome-extension://" + "a" * 32
    paired = api(client, "/api/browser/pairings", data={"name": "Chrome", "origin": extension})
    assert paired.status_code == 201
    token = paired.json["token"]
    headers = {"Authorization": "Bearer " + token, "X-Janus-Extension-Origin": extension, "Origin": extension}

    def bridge(path, data):
        return client.post("/api/browser/" + path, json=data, headers=headers)

    assert bridge("matches", {"url": "https://example.com/path"}).json["credentials"][0]["id"] == item_id
    assert bridge("reveal", {"url": "https://example.com", "id": item_id}).json["password"] == "stored-secret"
    for url in (
        "http://example.com",
        "https://evil.example.com",
        "https://example.com.evil.test",
        "https://example.com:444",
        "https://exаmple.com",
    ):
        assert bridge("reveal", {"url": url, "id": item_id}).status_code == 403
    assert client.post("/api/browser/reveal", json={"url": "https://example.com", "id": item_id}).status_code == 401
    assert (
        bridge("capture", {"url": "https://new.example", "login": "alice", "password": "new-secret"}).status_code == 201
    )
    api(client, "/api/vault/lock")
    assert bridge("reveal", {"url": "https://example.com", "id": item_id}).status_code == 423
    api(client, "/api/vault/unlock", data={"master_password": "master-secret"})
    assert api(client, f"/api/browser/pairings/{paired.json['id']}", "DELETE").status_code == 200
    assert bridge("reveal", {"url": "https://example.com", "id": item_id}).status_code in {401, 403}
    with db.engine.connect() as conn:
        assert conn.execute(select(db.browser_pairings)).first() is None
    assert hashlib.sha256(token.encode()).hexdigest() != token


def test_items_trash_and_account_isolation(authenticated_client):
    client = authenticated_client
    item = api(
        client, "/api/items", data={"kind": "identity", "name": "Identity", "fields": {"email": "alice@example.com"}}
    ).json["id"]
    assert api(client, f"/api/items/{item}", "DELETE").status_code == 200
    assert api(client, f"/api/items/{item}/reveal").status_code == 404
    assert api(client, f"/api/items/{item}/restore").status_code == 200
    register_and_login(client, "another-owner")
    assert api(client, f"/api/items/{item}/reveal").status_code == 404


def test_local_paths_settings_and_passphrases(authenticated_client, tmp_path, monkeypatch):
    monkeypatch.setenv("JANUS_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(vault, "TIMEOUT", vault.TIMEOUT)
    monkeypatch.setenv("JANUS_BACKUP_INTERVAL", "3600")
    monkeypatch.setenv("JANUS_BACKUP_RETENTION", "10")
    client = authenticated_client
    assert api(client, "/api/local/vaults", data={"name": "work"}).status_code == 200
    assert local.vault_path("work").exists()
    assert api(client, "/api/local/vaults", data={"name": "../bad"}).status_code == 400
    assert (
        api(
            client, "/api/local/settings", "PUT", {"vault_timeout": 60, "backup_interval": 0, "backup_retention": 3}
        ).status_code
        == 200
    )
    assert local.settings()["vault_timeout"] == 60
    assert vault.TIMEOUT == 60
    assert api(client, "/api/local/settings", "PUT", {"vault_timeout": -1}).status_code == 400
    phrase = api(client, "/api/generate-passphrase", data={"words": 6}).json["password"]
    words = Path(entries.__file__).with_name("wordlist.txt").read_text().splitlines()
    assert len(words) == 7776
    assert len(phrase.split("-")) == 6 and all(word in words for word in phrase.split("-"))


def test_legacy_note_crypto_upgrades_on_successful_access(authenticated_client):
    client = authenticated_client
    response = api(
        client, "/api/notes", data={"title": "Old note", "content": "old content", "note_password": "note-password"}
    )
    note_id = response.json["id"]
    with db.engine.begin() as conn:
        conn.execute(
            db.secure_notes.update()
            .where(db.secure_notes.c.id == note_id)
            .values(
                content_encrypted=encrypt_password("old content", "note-password", legacy=True),
                note_password_hash=legacy_hash_password("note-password"),
            )
        )
    assert api(client, f"/api/notes/{note_id}/reveal", data={"note_password": "wrong"}).status_code == 401
    with db.engine.connect() as conn:
        assert conn.execute(select(db.secure_notes.c.content_encrypted)).scalar_one().startswith("v1$")
    assert (
        api(client, f"/api/notes/{note_id}/reveal", data={"note_password": "note-password"}).json["content"]
        == "old content"
    )
    with db.engine.connect() as conn:
        note = conn.execute(select(db.secure_notes)).mappings().one()
        assert note["content_encrypted"].startswith("v3$argon2id$")
        assert note["note_password_hash"].startswith("$argon2id$")
