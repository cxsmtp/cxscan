"""Credential configuration + live connection tests for CxSAST and CxOne.

SECURITY: secrets are held in process memory only (this module-level _STORE),
never written to config on disk and never returned to the UI. This is a POC-grade
floor — before multi-user/hosted use, move to an OS secret store and put auth in
front of the app. The UI only ever sees derived, non-secret fields + live status.

CxSAST: URL + user + password -> token at /cxrestapi/auth/identity/connect/token.
CxOne:  a single API key (a JWT refresh token) whose `iss` claim encodes the IAM
        URL + tenant. We decode it (no verification needed — the refresh call
        proves authenticity), derive base/auth URLs + tenant, refresh for an
        access token, and ping the tenant to confirm the connection is live.
"""
from __future__ import annotations
import base64
import json
import time
import urllib.parse
import urllib.request
from urllib.parse import urlparse

# In-memory only. Keys: "sast", "cxone". Values include secrets + derived fields.
_STORE: dict[str, dict] = {}


def _post_form(url: str, fields: dict, timeout=30) -> dict:
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _get(url: str, token: str, timeout=30):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


# ---- CxSAST ------------------------------------------------------------------
def sast_test_and_store(url: str, username: str, password: str) -> dict:
    base = url.rstrip("/")
    try:
        tok = _post_form(f"{base}/cxrestapi/auth/identity/connect/token", {
            "username": username, "password": password, "grant_type": "password",
            "scope": "sast_rest_api", "client_id": "resource_owner_client",
            "client_secret": "014DF517-39D1-4453-B7B3-9930C563627C",
        })
        access = tok["access_token"]
        # Prove it works and surface teams so the user can pick team_id.
        teams = _get(f"{base}/cxrestapi/auth/teams", access)
        _STORE["sast"] = {"server_url": base, "username": username,
                          "password": password, "connected_at": time.time()}
        return {"ok": True, "server_url": base, "live": True,
                "teams": [{"id": t.get("id"), "name": t.get("fullName")} for t in teams][:50],
                "note": "authenticated; pick a team below for SAST scans"}
    except urllib.error.HTTPError as e:
        return {"ok": False, "live": False, "error": f"HTTP {e.code} — check URL / credentials"}
    except Exception as e:
        return {"ok": False, "live": False, "error": str(e)}


# ---- CxOne -------------------------------------------------------------------
def _decode_jwt(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)            # pad base64url
    return json.loads(base64.urlsafe_b64decode(payload))


def cxone_derive(api_key: str) -> dict:
    """From the API key alone: iss (auth realm URL), tenant, derived base API URL."""
    claims = _decode_jwt(api_key)
    iss = claims["iss"].rstrip("/")                 # e.g. https://eu.iam.checkmarx.net/auth/realms/<tenant>
    tenant = iss.split("/realms/")[-1]
    host = urlparse(iss).netloc                     # eu.iam.checkmarx.net
    labels = ["ast" if l == "iam" else l for l in host.split(".")]
    base_uri = f"https://{'.'.join(labels)}"        # eu.ast.checkmarx.net
    return {"iam_url": iss, "tenant": tenant, "base_uri": base_uri,
            "token_url": f"{iss}/protocol/openid-connect/token"}


def cxone_test_and_store(api_key: str) -> dict:
    try:
        d = cxone_derive(api_key)
    except Exception:
        return {"ok": False, "live": False, "error": "not a valid Checkmarx One API key (JWT)"}
    try:
        tok = _post_form(d["token_url"], {"grant_type": "refresh_token",
                                          "client_id": "ast-app", "refresh_token": api_key})
        access = tok["access_token"]
        reachable = True
        try:
            _get(f"{d['base_uri']}/api/projects?limit=1", access)
        except Exception:
            reachable = False                       # derived base may need override (custom domain)
        _STORE["cxone"] = {**d, "api_key": api_key, "connected_at": time.time()}
        return {"ok": True, "live": True, "tenant": d["tenant"],
                "base_uri": d["base_uri"], "iam_url": d["iam_url"],
                "api_reachable": reachable,
                "note": ("tenant authenticated" if reachable else
                         "authenticated, but derived base URL didn't answer — "
                         "single-tenant/custom domain may need a manual base_uri")}
    except urllib.error.HTTPError as e:
        return {"ok": False, "live": False, "tenant": d.get("tenant"),
                "error": f"HTTP {e.code} — key may be expired or revoked"}
    except Exception as e:
        return {"ok": False, "live": False, "error": str(e)}


# ---- Git (any HTTPS provider) ------------------------------------------------
def git_test_and_store(repo_url: str, username: str, token: str) -> dict:
    """Validate git creds by ls-remote against the given repo, store by host."""
    import subprocess
    from urllib.parse import urlparse, urlunparse
    try:
        p = urlparse(repo_url)
        host = p.netloc
        authed = urlunparse(p._replace(netloc=f"{username}:{token}@{host}")) if username else repo_url
        r = subprocess.run(["git", "ls-remote", "--heads", authed],
                           capture_output=True, text=True, timeout=40,
                           env={"GIT_TERMINAL_PROMPT": "0"})
        if r.returncode != 0:
            return {"ok": False, "live": False,
                    "error": "ls-remote failed — check URL / username / token / network"}
        branches = len([l for l in r.stdout.splitlines() if l.strip()])
        _STORE.setdefault("git", {})[host] = {"username": username, "token": token}
        return {"ok": True, "live": True, "host": host, "branches": branches,
                "note": f"reachable — {branches} branches visible on {host}"}
    except Exception as e:
        return {"ok": False, "live": False, "error": str(e)}


def git_auth_for(repo_url: str) -> dict | None:
    """Stored git creds matching the repo's host, if any."""
    from urllib.parse import urlparse
    host = urlparse(repo_url).netloc
    return (_STORE.get("git") or {}).get(host)


def set_sast_team(team_id: int, team_name: str | None = None) -> dict:
    """Record the SAST team picked in the UI; SAST scans create the project under
    it (overrides config team_id). Requires an existing SAST connection."""
    s = _STORE.get("sast")
    if not s:
        return {"ok": False, "error": "connect to CxSAST first"}
    s["team_id"] = team_id
    s["team_name"] = team_name
    return {"ok": True, "team_id": team_id, "team_name": team_name}


def store_git_token(host: str, username: str, token: str) -> None:
    """Store git creds for a host (used by the GitHub OAuth device flow). Same
    in-memory store the manual git form writes to."""
    _STORE.setdefault("git", {})[host] = {"username": username, "token": token}


# ---- accessors used by the scan runners --------------------------------------
def get(name: str) -> dict | None:
    return _STORE.get(name)


def status() -> dict:
    """Non-secret view for the UI."""
    out = {}
    s = _STORE.get("sast")
    if s:
        out["sast"] = {"connected": True, "server_url": s["server_url"],
                       "username": s["username"], "team_id": s.get("team_id"),
                       "team_name": s.get("team_name")}
    c = _STORE.get("cxone")
    if c:
        out["cxone"] = {"connected": True, "tenant": c["tenant"],
                        "base_uri": c["base_uri"]}
    g = _STORE.get("git")
    if g:
        out["git"] = {"connected": True, "hosts": list(g.keys())}
    return out
