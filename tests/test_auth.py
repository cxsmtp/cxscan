"""Auth middleware: off when unconfigured, enforced when both env vars are set."""
import pytest
from fastapi.testclient import TestClient

from app import auth
from app.app import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def configured_auth(monkeypatch):
    monkeypatch.setenv("CXSCAN_AUTH_USER", "admin")
    monkeypatch.setenv("CXSCAN_AUTH_PASSWORD", "hunter2")


def test_check_accepts_correct_and_rejects_wrong():
    import base64
    good = "Basic " + base64.b64encode(b"admin:hunter2").decode()
    bad = "Basic " + base64.b64encode(b"admin:nope").decode()
    assert auth._check(good, "admin", "hunter2") is True
    assert auth._check(bad, "admin", "hunter2") is False
    assert auth._check(None, "admin", "hunter2") is False
    assert auth._check("Bearer xyz", "admin", "hunter2") is False


def test_disabled_when_unconfigured(client, monkeypatch):
    monkeypatch.delenv("CXSCAN_AUTH_USER", raising=False)
    monkeypatch.delenv("CXSCAN_AUTH_PASSWORD", raising=False)
    assert auth.enabled() is False
    assert client.get("/api/connections").status_code == 200


def test_requires_credentials_when_configured(client, configured_auth):
    assert auth.enabled() is True
    assert client.get("/api/connections").status_code == 401
    ok = client.get("/api/connections", auth=("admin", "hunter2"))
    assert ok.status_code == 200
    assert ok.json()["app_auth"] is True


def test_rejects_wrong_password(client, configured_auth):
    assert client.get("/api/connections", auth=("admin", "wrong")).status_code == 401
