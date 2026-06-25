"""GitHub OAuth device-flow gating + token storage (no live HTTP)."""
import pytest
from fastapi.testclient import TestClient

from app import github_oauth, connections
from app.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_unconfigured_without_client_id(client, monkeypatch):
    monkeypatch.delenv("GITHUB_OAUTH_CLIENT_ID", raising=False)
    assert github_oauth.configured() is False
    assert github_oauth.start()["ok"] is False
    assert github_oauth.poll("x")["status"] == "error"
    assert client.get("/api/connections/git/github").json() == {"configured": False}


def test_configured_with_client_id(client, monkeypatch):
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "Iv1.abc123")
    assert github_oauth.configured() is True
    assert client.get("/api/connections/git/github").json() == {"configured": True}


def test_select_sast_team_requires_connection(client):
    # No SAST connection in a fresh store path -> guarded.
    from app import connections
    connections._STORE.pop("sast", None)
    r = client.post("/api/connections/sast/team", json={"team_id": 3, "team_name": "/CxServer/SP/APAC"})
    assert r.json()["ok"] is False


def test_select_sast_team_records_and_feeds_status(client):
    from app import connections
    connections._STORE["sast"] = {"server_url": "https://cx", "username": "u", "password": "p"}
    r = client.post("/api/connections/sast/team", json={"team_id": 3, "team_name": "/CxServer/SP/APAC"})
    assert r.json() == {"ok": True, "team_id": 3, "team_name": "/CxServer/SP/APAC"}
    status = client.get("/api/connections").json()
    assert status["sast"]["team_id"] == 3 and status["sast"]["team_name"] == "/CxServer/SP/APAC"


def test_store_git_token_is_resolvable_by_host():
    connections.store_git_token("github.com", "x-access-token", "gho_secret")
    creds = connections.git_auth_for("https://github.com/org/repo.git")
    assert creds == {"username": "x-access-token", "token": "gho_secret"}
    # github.com creds must not leak to a different host.
    assert connections.git_auth_for("https://gitlab.com/org/repo.git") is None
