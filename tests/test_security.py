from src.backend.auth import decrypt_password, encrypt_password
from .conftest import csrf_headers


def test_encrypted_values_use_a_random_salt_and_reject_legacy_values():
    first = encrypt_password("secret", "master-password")
    second = encrypt_password("secret", "master-password")

    assert first != second
    assert first.startswith("v1$")
    assert decrypt_password(first, "master-password") == "secret"
    assert decrypt_password(first, "wrong-password") is None
    assert decrypt_password("legacy-ciphertext", "master-password") is None


def test_public_note_uses_note_password_and_can_be_revoked(client):
    username = "note-user"
    password = "correct-password"
    registration = client.post(
        "/api/register",
        json={
            "username": username,
            "email": f"{username}@example.test",
            "password": password,
            "password_confirm": password,
        },
    )
    assert registration.status_code == 201
    assert client.post("/api/login", json={"username": username, "password": password}).status_code == 200

    headers = csrf_headers(client)
    created = client.post(
        "/api/notes",
        json={"title": "Test note", "content": "private content", "note_password": "note-secret"},
        headers=headers,
    )
    assert created.status_code == 201
    payload = created.get_json()
    assert payload["access_token_expires_at"]

    public = client.post(
        f"/api/notes/access/{payload['access_token']}",
        json={"note_password": "note-secret"},
    )
    assert public.status_code == 200
    assert public.get_json()["content"] == "private content"

    revoked = client.post(f"/api/notes/{payload['id']}/revoke-access", headers=headers)
    assert revoked.status_code == 200
    assert (
        client.post(
            f"/api/notes/access/{payload['access_token']}",
            json={"note_password": "note-secret"},
        ).status_code
        == 404
    )


def test_mutating_authenticated_routes_require_csrf(client):
    username = "csrf-user"
    password = "correct-password"
    client.post(
        "/api/register",
        json={
            "username": username,
            "email": f"{username}@example.test",
            "password": password,
            "password_confirm": password,
        },
    )
    client.post("/api/login", json={"username": username, "password": password})

    response = client.post(
        "/api/notes",
        json={"title": "Blocked", "content": "content", "note_password": "secret"},
    )
    assert response.status_code == 403
