import uuid

from src.backend.auth import generate_secure_password, hash_password, verify_password
from .conftest import csrf_headers


def register_and_login(client, username=None, password="correct-password"):
    username = username or f"user-{uuid.uuid4().hex[:10]}"
    response = client.post(
        "/api/register",
        json={
            "username": username,
            "email": f"{username}@example.test",
            "password": password,
            "password_confirm": password,
        },
    )
    assert response.status_code == 201
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return username


def test_authenticated_user_info(authenticated_client):
    response = authenticated_client.get("/api/user-info")

    assert response.status_code == 200
    assert response.get_json()["username"].startswith("user-")


def test_hash_and_password_generation():
    password_hash = hash_password("strong-password")
    assert password_hash != "strong-password"
    assert verify_password("strong-password", password_hash)
    assert not verify_password("wrong-password", password_hash)

    generated = generate_secure_password(32, True, True, True, True)
    assert len(generated) == 32
    assert any(character.isupper() for character in generated)
    assert any(character.islower() for character in generated)
    assert any(character.isdigit() for character in generated)


def test_registration_validation_and_login_errors(client):
    response = client.post(
        "/api/register",
        json={"username": "ab", "email": "invalid", "password": "short", "password_confirm": "different"},
    )
    assert response.status_code == 400

    username = register_and_login(client)
    duplicate = client.post(
        "/api/register",
        json={
            "username": username,
            "email": f"{username}@example.test",
            "password": "correct-password",
            "password_confirm": "correct-password",
        },
    )
    assert duplicate.status_code == 400

    wrong_login = client.post("/api/login", json={"username": username, "password": "wrong-password"})
    assert wrong_login.status_code == 401


def test_logout_removes_authorization(client):
    register_and_login(client)
    headers = csrf_headers(client)
    assert client.get("/api/credentials").status_code == 200
    assert client.post("/api/logout", headers=headers).status_code == 200
    assert client.get("/api/credentials").status_code == 401


def test_credential_crud_and_wrong_master_password(authenticated_client):
    client = authenticated_client
    headers = csrf_headers(client)
    created = client.post(
        "/api/credentials",
        json={
            "site_name": "Example",
            "login": "alice",
            "email": "alice@example.test",
            "password": "stored-secret",
            "master_password": "master-secret",
        },
        headers=headers,
    )
    assert created.status_code == 201
    credential_id = created.get_json()["id"]

    listed = client.get("/api/credentials")
    assert listed.status_code == 200
    assert listed.get_json()["credentials"][0]["site_name"] == "Example"
    assert "password_encrypted" not in listed.get_json()["credentials"][0]

    wrong = client.get(
        f"/api/credentials/{credential_id}",
        json={"master_password": "wrong-master"},
    )
    assert wrong.status_code == 401
    retrieved = client.get(
        f"/api/credentials/{credential_id}",
        json={"master_password": "master-secret"},
    )
    assert retrieved.status_code == 200
    assert retrieved.get_json()["password"] == "stored-secret"

    updated = client.put(
        f"/api/credentials/{credential_id}",
        json={
            "site_name": "Updated Example",
            "login": "alice-2",
            "email": "alice2@example.test",
            "password": "updated-secret",
            "master_password": "master-secret",
        },
        headers=headers,
    )
    assert updated.status_code == 200
    assert client.delete(f"/api/credentials/{credential_id}", headers=headers).status_code == 200
    assert client.get("/api/credentials").get_json()["credentials"] == []


def test_credentials_are_isolated_between_users(client):
    register_and_login(client, "first-user")
    headers = csrf_headers(client)
    created = client.post(
        "/api/credentials",
        json={"site_name": "Private", "password": "secret", "master_password": "master"},
        headers=headers,
    )
    credential_id = created.get_json()["id"]
    client.post("/api/logout", headers=headers)

    register_and_login(client, "second-user")
    assert client.get("/api/credentials").get_json()["credentials"] == []
    assert (
        client.get(
            f"/api/credentials/{credential_id}",
            json={"master_password": "master"},
        ).status_code
        == 404
    )


def test_note_crud_and_wrong_note_password(authenticated_client):
    client = authenticated_client
    headers = csrf_headers(client)
    created = client.post(
        "/api/notes",
        json={"title": "Original", "content": "Secret text", "note_password": "note-secret"},
        headers=headers,
    )
    assert created.status_code == 201
    note_id = created.get_json()["id"]

    wrong = client.get(f"/api/notes/{note_id}", json={"note_password": "wrong"})
    assert wrong.status_code == 401
    note = client.get(f"/api/notes/{note_id}", json={"note_password": "note-secret"})
    assert note.status_code == 200
    assert note.get_json()["content"] == "Secret text"

    updated = client.put(
        f"/api/notes/{note_id}",
        json={"title": "Updated", "content": "Updated text", "note_password": "note-secret"},
        headers=headers,
    )
    assert updated.status_code == 200
    assert (
        client.get(f"/api/notes/{note_id}", json={"note_password": "note-secret"}).get_json()["content"]
        == "Updated text"
    )

    assert client.delete(f"/api/notes/{note_id}", headers=headers).status_code == 200
    assert client.get(f"/api/notes/{note_id}", json={"note_password": "note-secret"}).status_code == 404


def test_authorization_and_password_generator_validation(client):
    assert client.get("/api/credentials").status_code == 401
    assert client.post("/api/generate-password", json={"length": 1}).status_code == 400

    response = client.post("/api/generate-password", json={"length": 24, "use_digits": False})
    assert response.status_code == 200
    assert len(response.get_json()["password"]) == 24


def test_frontend_routes_are_served(client):
    assert client.get("/login").status_code == 200
    assert client.get("/register").status_code == 200
