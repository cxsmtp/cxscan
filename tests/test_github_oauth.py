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


def test_store_git_token_is_resolvable_by_host():
    connections.store_git_token("github.com", "x-access-token", "gho_secret")
    creds = connections.git_auth_for("https://github.com/org/repo.git")
    assert creds == {"username": "x-access-token", "token": "gho_secret"}
    # github.com creds must not leak to a different host.
    assert connections.git_auth_for("https://gitlab.com/org/repo.git") is None
