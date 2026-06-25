"""Optional HTTP Basic auth in front of the whole app.

WHY: 2ms findings carry the file + line of real leaked secrets, and the in-memory
run store has no per-user access control. Anyone who can reach the port can read
every run. This is the floor: a single shared credential, constant-time compared,
covering the dashboard and the API.

Enabled only when BOTH CXSCAN_AUTH_USER and CXSCAN_AUTH_PASSWORD are set, so local
dev stays frictionless. For multi-user / hosted use, replace this with real SSO.
"""
from __future__ import annotations
import base64
import os
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

_REALM = "cxscan"


def _credentials() -> tuple[str, str] | None:
    user = os.environ.get("CXSCAN_AUTH_USER")
    pwd = os.environ.get("CXSCAN_AUTH_PASSWORD")
    return (user, pwd) if user and pwd else None


def _unauthorized() -> Response:
    return Response("authentication required", status_code=401,
                    headers={"WWW-Authenticate": f'Basic realm="{_REALM}"'})


def _check(header: str | None, user: str, pwd: str) -> bool:
    if not header or not header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(header[6:]).decode("utf-8")
        got_user, _, got_pwd = decoded.partition(":")
    except Exception:
        return False
    # Compare both fields in constant time; & avoids short-circuit leaking which failed.
    return (secrets.compare_digest(got_user, user)
            & secrets.compare_digest(got_pwd, pwd))


class BasicAuthMiddleware(BaseHTTPMiddleware):
    """No-op unless credentials are configured in the environment."""

    async def dispatch(self, request, call_next):
        creds = _credentials()
        if creds is None:
            return await call_next(request)
        user, pwd = creds
        if not _check(request.headers.get("Authorization"), user, pwd):
            return _unauthorized()
        return await call_next(request)


def enabled() -> bool:
    return _credentials() is not None
