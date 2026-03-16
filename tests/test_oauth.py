"""Tests for pyntrace/server/oauth.py"""
import json
import os
import urllib.error
import pytest


@pytest.fixture(autouse=True)
def clear_oauth_env(monkeypatch):
    for var in ("PYNTRACE_OAUTH_PROVIDER", "PYNTRACE_OAUTH_CLIENT_ID",
                "PYNTRACE_OAUTH_CLIENT_SECRET", "PYNTRACE_OAUTH_REDIRECT_URI"):
        monkeypatch.delenv(var, raising=False)


def test_not_configured_returns_none():
    from pyntrace.server.oauth import get_login_url, is_configured
    assert not is_configured()
    assert get_login_url("state123") is None


def test_github_login_url(monkeypatch):
    monkeypatch.setenv("PYNTRACE_OAUTH_PROVIDER", "github")
    monkeypatch.setenv("PYNTRACE_OAUTH_CLIENT_ID", "my-client-id")
    from pyntrace.server.oauth import get_login_url, is_configured
    assert is_configured()
    url = get_login_url("abc")
    assert url is not None
    assert "github.com/login/oauth/authorize" in url
    assert "client_id=my-client-id" in url
    assert "state=abc" in url


def test_google_login_url(monkeypatch):
    monkeypatch.setenv("PYNTRACE_OAUTH_PROVIDER", "google")
    monkeypatch.setenv("PYNTRACE_OAUTH_CLIENT_ID", "google-id")
    from pyntrace.server.oauth import get_login_url
    url = get_login_url("xyz")
    assert url is not None
    assert "accounts.google.com" in url
    assert "google-id" in url
    assert "response_type=code" in url


def test_exchange_code_not_configured_returns_none():
    from pyntrace.server.oauth import exchange_code
    assert exchange_code("somecode") is None


def test_exchange_code_github(monkeypatch):
    monkeypatch.setenv("PYNTRACE_OAUTH_PROVIDER", "github")
    monkeypatch.setenv("PYNTRACE_OAUTH_CLIENT_ID", "cid")
    monkeypatch.setenv("PYNTRACE_OAUTH_CLIENT_SECRET", "csecret")

    token_resp = json.dumps({"access_token": "tok123"}).encode()
    user_resp = json.dumps({"login": "octocat", "id": 1}).encode()

    call_count = {"n": 0}

    class _MockResponse:
        def __init__(self, data):
            self._data = data
        def read(self):
            return self._data
        def __enter__(self):
            return self
        def __exit__(self, *a):
            pass

    def mock_urlopen(req, timeout=10):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _MockResponse(token_resp)
        return _MockResponse(user_resp)

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    from pyntrace.server.oauth import exchange_code
    username = exchange_code("code123")
    assert username == "octocat"
    assert call_count["n"] == 2


def test_exchange_code_network_error_returns_none(monkeypatch):
    monkeypatch.setenv("PYNTRACE_OAUTH_PROVIDER", "github")
    monkeypatch.setenv("PYNTRACE_OAUTH_CLIENT_ID", "cid")
    monkeypatch.setenv("PYNTRACE_OAUTH_CLIENT_SECRET", "csecret")

    def mock_urlopen(req, timeout=10):
        raise OSError("network error")

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    from pyntrace.server.oauth import exchange_code
    assert exchange_code("code") is None
