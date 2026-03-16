"""HTTP Basic Auth, in-memory rate limiting, and RBAC for the pyntrace dashboard.

Configuration via environment variables:
  PYNTRACE_USERNAME        — dashboard username (enables Basic Auth when set with PASSWORD)
  PYNTRACE_PASSWORD        — dashboard password
  PYNTRACE_ADMIN_USERS     — comma-separated usernames with admin access
  PYNTRACE_READONLY_USERS  — comma-separated usernames restricted to read-only access
  PYNTRACE_SECRET_KEY      — signing key for OAuth session cookies
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import time
from collections import defaultdict, deque
from typing import Literal

Role = Literal["admin", "viewer"]


# ---------------------------------------------------------------------------
# Credential helpers
# ---------------------------------------------------------------------------

def _creds() -> tuple[str, str] | None:
    """Return (username, password) from env if both are set, else None."""
    u = os.getenv("PYNTRACE_USERNAME")
    p = os.getenv("PYNTRACE_PASSWORD")
    return (u, p) if (u and p) else None


def _get_user_role(username: str) -> Role:
    """Determine role for *username* based on env-var lists.

    Rules (first match wins):
    1. If PYNTRACE_READONLY_USERS is set and username is in it → viewer
    2. If PYNTRACE_ADMIN_USERS is set and username is NOT in it → viewer
    3. Otherwise → admin
    """
    admins = {u.strip() for u in os.getenv("PYNTRACE_ADMIN_USERS", "").split(",") if u.strip()}
    viewers = {u.strip() for u in os.getenv("PYNTRACE_READONLY_USERS", "").split(",") if u.strip()}
    if viewers and username in viewers:
        return "viewer"
    if admins and username not in admins:
        return "viewer"
    return "admin"


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

def require_auth(request: object) -> str | None:
    """FastAPI dependency — authenticate via Basic Auth or session cookie.

    Returns the username, or None when auth is not configured (open dev mode).
    Raises HTTP 401 when credentials are wrong / missing and auth is configured.
    """
    creds = _creds()
    if creds is None:
        # No basic-auth configured — try OAuth session cookie
        return _verify_session_cookie(request)

    from fastapi import HTTPException
    from fastapi.security.utils import get_authorization_scheme_param

    auth = getattr(request, "headers", {}).get("Authorization", "")  # type: ignore[union-attr]
    scheme, param = get_authorization_scheme_param(auth)

    if scheme.lower() != "basic":
        raise HTTPException(
            401,
            "Unauthorized",
            headers={"WWW-Authenticate": 'Basic realm="pyntrace"'},
        )

    try:
        username, _, password = base64.b64decode(param).decode("utf-8").partition(":")
    except Exception:
        raise HTTPException(
            401,
            "Unauthorized",
            headers={"WWW-Authenticate": 'Basic realm="pyntrace"'},
        )

    if not (
        secrets.compare_digest(username, creds[0])
        and secrets.compare_digest(password, creds[1])
    ):
        raise HTTPException(
            401,
            "Unauthorized",
            headers={"WWW-Authenticate": 'Basic realm="pyntrace"'},
        )

    return username


def require_admin(request: object) -> str | None:
    """FastAPI dependency — like require_auth but additionally requires admin role.

    Raises HTTP 403 for viewer-role users.
    """
    username = require_auth(request)
    if username and _get_user_role(username) == "viewer":
        from fastapi import HTTPException

        raise HTTPException(403, "Admin role required")
    return username


# ---------------------------------------------------------------------------
# Session cookies (for OAuth flow)
# ---------------------------------------------------------------------------

def _verify_session_cookie(request: object) -> str | None:
    """Verify the HMAC-signed ``pyntrace_session`` cookie.

    Returns the username on success, or None if missing/invalid.
    """
    import hmac
    import hashlib

    cookies = getattr(request, "cookies", {})  # type: ignore[union-attr]
    cookie = cookies.get("pyntrace_session")
    if not cookie:
        return None

    secret = os.getenv("PYNTRACE_SECRET_KEY", "")
    if not secret:
        return None

    try:
        sig, _, payload = cookie.partition(".")
        expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not secrets.compare_digest(sig, expected):
            return None
        return json.loads(base64.b64decode(payload + "==")).get("username")
    except Exception:
        return None


def make_session_cookie(username: str) -> str:
    """Create an HMAC-SHA256-signed session cookie value.

    Uses ``PYNTRACE_SECRET_KEY`` from env.  Falls back to a random key per
    process if the env var is not set (sessions won't survive restarts).
    """
    import hmac
    import hashlib

    secret = os.getenv("PYNTRACE_SECRET_KEY") or _process_secret()
    payload = base64.b64encode(json.dumps({"username": username}).encode()).decode()
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{sig}.{payload}"


_PROCESS_SECRET: str | None = None


def _process_secret() -> str:
    global _PROCESS_SECRET
    if _PROCESS_SECRET is None:
        _PROCESS_SECRET = secrets.token_hex(32)
    return _PROCESS_SECRET


# ---------------------------------------------------------------------------
# In-memory sliding-window rate limiter
# ---------------------------------------------------------------------------

_windows: dict[str, deque] = defaultdict(deque)


def check_rate_limit(
    key: str,
    max_requests: int = 200,
    window_s: int = 60,
) -> None:
    """Raise HTTP 429 if *key* exceeds *max_requests* in *window_s* seconds.

    Uses an in-memory sliding window — no external dependencies.
    """
    now = time.time()
    dq = _windows[key]
    while dq and dq[0] < now - window_s:
        dq.popleft()
    if len(dq) >= max_requests:
        from fastapi import HTTPException

        raise HTTPException(429, "Too many requests — please slow down")
    dq.append(now)
