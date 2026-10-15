import uuid

import pytest

from src.backend import database, vault
from src.backend.app import app, limiter


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("JANUS_HOME", str(tmp_path / "home"))
    vault._sessions.clear()
    database.configure_database(f"sqlite:///{tmp_path / 'test.db'}")
    database.init_db()
    app.config.update(TESTING=True, SECRET_KEY="test-secret", RATELIMIT_ENABLED=False)
    limiter.enabled = False
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture()
def authenticated_client(client):
    username = f"user-{uuid.uuid4().hex[:10]}"
    password = "correct-password"
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
    assert (
        client.post(
            "/api/vault/unlock", json={"master_password": "master-secret"}, headers=csrf_headers(client)
        ).status_code
        == 200
    )
    return client


def csrf_headers(client):
    response = client.get("/api/csrf-token")
    assert response.status_code == 200
    return {"X-CSRF-Token": response.get_json()["csrf_token"]}
