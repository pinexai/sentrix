"""Tests for pyntrace/server/auth.py"""
import base64
import os
import time
import pytest


class _MockRequest:
    """Minimal mock that matches what require_auth reads."""
    def __init__(self, auth_header: str = "", cookies: dict | None = None):
        self.headers = {"Authorization": auth_header} if auth_header else {}
        self.cookies = cookies or {}


def _basic(username: str, password: str) -> str:
    cred = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {cred}"


@pytest.fixture(autouse=True)
def clear_env(monkeypatch):
    for var in ("PYNTRACE_USERNAME", "PYNTRACE_PASSWORD", "PYNTRACE_ADMIN_USERS",
                "PYNTRACE_READONLY_USERS", "PYNTRACE_SECRET_KEY"):
        monkeypatch.delenv(var, raising=False)


# --- require_auth ---

def test_no_env_passes():
    from pyntrace.server.auth import require_auth
    result = require_auth(_MockRequest())
    assert result is None  # auth not configured


def test_correct_credentials_passes(monkeypatch):
    monkeypatch.setenv("PYNTRACE_USERNAME", "admin")
    monkeypatch.setenv("PYNTRACE_PASSWORD", "secret")
    from pyntrace.server.auth import require_auth
    req = _MockRequest(_basic("admin", "secret"))
    assert require_auth(req) == "admin"


def test_wrong_password_raises_401(monkeypatch):
    monkeypatch.setenv("PYNTRACE_USERNAME", "admin")
    monkeypatch.setenv("PYNTRACE_PASSWORD", "secret")
    from pyntrace.server.auth import require_auth
    from fastapi import HTTPException
    req = _MockRequest(_basic("admin", "wrong"))
    with pytest.raises(HTTPException) as exc_info:
        require_auth(req)
    assert exc_info.value.status_code == 401


def test_missing_auth_header_raises_401(monkeypatch):
    monkeypatch.setenv("PYNTRACE_USERNAME", "admin")
    monkeypatch.setenv("PYNTRACE_PASSWORD", "secret")
    from pyntrace.server.auth import require_auth
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        require_auth(_MockRequest())
    assert exc_info.value.status_code == 401
    assert "WWW-Authenticate" in exc_info.value.headers


def test_malformed_base64_raises_401(monkeypatch):
    monkeypatch.setenv("PYNTRACE_USERNAME", "admin")
    monkeypatch.setenv("PYNTRACE_PASSWORD", "secret")
    from pyntrace.server.auth import require_auth
    from fastapi import HTTPException
    req = _MockRequest("Basic not-valid-base64!!!")
    with pytest.raises(HTTPException) as exc_info:
        require_auth(req)
    assert exc_info.value.status_code == 401


# --- require_admin / RBAC ---

def test_admin_role_default(monkeypatch):
    monkeypatch.setenv("PYNTRACE_USERNAME", "admin")
    monkeypatch.setenv("PYNTRACE_PASSWORD", "secret")
    from pyntrace.server.auth import require_admin
    req = _MockRequest(_basic("admin", "secret"))
    assert require_admin(req) == "admin"


def test_viewer_role_blocked_by_require_admin(monkeypatch):
    monkeypatch.setenv("PYNTRACE_USERNAME", "bob")
    monkeypatch.setenv("PYNTRACE_PASSWORD", "pass")
    monkeypatch.setenv("PYNTRACE_READONLY_USERS", "bob")
    from pyntrace.server.auth import require_admin
    from fastapi import HTTPException
    req = _MockRequest(_basic("bob", "pass"))
    with pytest.raises(HTTPException) as exc_info:
        require_admin(req)
    assert exc_info.value.status_code == 403


def test_get_user_role_admin_list(monkeypatch):
    monkeypatch.setenv("PYNTRACE_ADMIN_USERS", "alice,charlie")
    from pyntrace.server.auth import _get_user_role
    assert _get_user_role("alice") == "admin"
    assert _get_user_role("charlie") == "admin"
    assert _get_user_role("bob") == "viewer"  # not in admin list


def test_get_user_role_readonly_overrides(monkeypatch):
    monkeypatch.setenv("PYNTRACE_READONLY_USERS", "alice")
    from pyntrace.server.auth import _get_user_role
    assert _get_user_role("alice") == "viewer"


# --- Session cookies ---

def test_session_cookie_round_trip(monkeypatch):
    monkeypatch.setenv("PYNTRACE_SECRET_KEY", "test-secret-key")
    from pyntrace.server.auth import make_session_cookie, _verify_session_cookie
    cookie = make_session_cookie("alice")
    req = _MockRequest(cookies={"pyntrace_session": cookie})
    assert _verify_session_cookie(req) == "alice"


def test_tampered_cookie_returns_none(monkeypatch):
    monkeypatch.setenv("PYNTRACE_SECRET_KEY", "test-secret-key")
    from pyntrace.server.auth import make_session_cookie, _verify_session_cookie
    cookie = make_session_cookie("alice")
    # Tamper with signature
    tampered = "badsig." + cookie.split(".", 1)[1]
    req = _MockRequest(cookies={"pyntrace_session": tampered})
    assert _verify_session_cookie(req) is None


def test_no_secret_key_returns_none(monkeypatch):
    monkeypatch.delenv("PYNTRACE_SECRET_KEY", raising=False)
    from pyntrace.server.auth import _verify_session_cookie
    req = _MockRequest(cookies={"pyntrace_session": "sig.payload"})
    assert _verify_session_cookie(req) is None


# --- Rate limiter ---

def test_rate_limit_allows_n(monkeypatch):
    from pyntrace.server import auth as _auth_mod
    _auth_mod._windows.clear()
    from pyntrace.server.auth import check_rate_limit
    for _ in range(5):
        check_rate_limit("test-key-rl", max_requests=5, window_s=60)


def test_rate_limit_raises_429_on_n_plus_1(monkeypatch):
    from pyntrace.server import auth as _auth_mod
    _auth_mod._windows.clear()
    from pyntrace.server.auth import check_rate_limit
    from fastapi import HTTPException
    for _ in range(5):
        check_rate_limit("test-key-429", max_requests=5, window_s=60)
    with pytest.raises(HTTPException) as exc_info:
        check_rate_limit("test-key-429", max_requests=5, window_s=60)
    assert exc_info.value.status_code == 429


def test_rate_limit_resets_after_window(monkeypatch):
    from pyntrace.server import auth as _auth_mod
    _auth_mod._windows.clear()
    from pyntrace.server.auth import check_rate_limit
    import pyntrace.server.auth as _auth

    # Fill up the window
    for _ in range(3):
        check_rate_limit("test-key-reset", max_requests=3, window_s=60)

    # Fake that the window has expired by backdating the timestamps
    dq = _auth._windows["test-key-reset"]
    old_time = time.time() - 61
    for i in range(len(dq)):
        dq[i] = old_time

    # Should succeed again now
    check_rate_limit("test-key-reset", max_requests=3, window_s=60)
