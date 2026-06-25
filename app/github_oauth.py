"""GitHub OAuth device flow for the 'Authenticate with GitHub' button.

Device flow is the right fit for a localhost tool: it needs only a PUBLIC client
id (no client secret, no redirect URL). The user clicks the button, we show them a
short code + a github.com URL, they approve in their browser, and we poll for the
access token. The token is stored in-memory only (connections._STORE), same posture
as every other credential here — never written to disk or returned to the UI.

Setup: register a GitHub OAuth App with "Enable Device Flow" on, then export its
client id as GITHUB_OAUTH_CLIENT_ID. The id is not a secret; it's safe to expose.
"""
from __future__ import annotations
import json
import os
import urllib.parse
import urllib.request

_DEVICE_CODE_URL = "https://github.com/login/device/code"
_TOKEN_URL = "https://github.com/login/oauth/access_token"
# 'repo' scope so the minted token can clone private repos; drop to 'public_repo'
# if you only ever scan public source.
_SCOPE = "repo"


def client_id() -> str | None:
    return os.environ.get("GITHUB_OAUTH_CLIENT_ID") or None


def configured() -> bool:
    return client_id() is not None


def _post(url: str, fields: dict, timeout: int = 30) -> dict:
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Accept": "application/json",
                 "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


def start() -> dict:
    """Begin device flow. Returns the user-facing code + URL and the device_code
    the front-end echoes back to poll(). device_code is short-lived, not a secret."""
    cid = client_id()
    if not cid:
        return {"ok": False, "error": "GITHUB_OAUTH_CLIENT_ID is not set"}
    try:
        r = _post(_DEVICE_CODE_URL, {"client_id": cid, "scope": _SCOPE})
        if "device_code" not in r:
            return {"ok": False, "error": r.get("error_description") or "device code request failed"}
        return {"ok": True, "device_code": r["device_code"], "user_code": r["user_code"],
                "verification_uri": r["verification_uri"],
                # GitHub returns a URL with the code embedded — open this so the
                # user only has to click "Authorize", no copy/paste.
                "verification_uri_complete": r.get("verification_uri_complete"),
                "interval": r.get("interval", 5), "expires_in": r.get("expires_in", 900)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def poll(device_code: str) -> dict:
    """Poll once for the token. Status is one of:
    pending (keep polling), slow_down (back off), connected (token stored), error."""
    cid = client_id()
    if not cid:
        return {"status": "error", "error": "GITHUB_OAUTH_CLIENT_ID is not set"}
    try:
        r = _post(_TOKEN_URL, {
            "client_id": cid, "device_code": device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code"})
    except Exception as e:
        return {"status": "error", "error": str(e)}
    token = r.get("access_token")
    if token:
        from . import connections
        # GitHub accepts the OAuth token as the password with any username; the
        # canonical pairing is x-access-token:<token>. Stored under github.com so
        # the existing clone path (git_auth_for -> user:token@host) just works.
        connections.store_git_token("github.com", "x-access-token", token)
        return {"status": "connected", "host": "github.com"}
    err = r.get("error")
    if err in ("authorization_pending", "slow_down"):
        return {"status": "pending" if err == "authorization_pending" else "slow_down",
                "interval": r.get("interval")}
    return {"status": "error", "error": r.get("error_description") or err or "unknown error"}
