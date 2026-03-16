"""OAuth 2.0 authorization code flow — GitHub and Google.

Uses only Python stdlib (urllib) — no external OAuth libraries required.

Configuration via environment variables:
  PYNTRACE_OAUTH_PROVIDER      — "github" or "google"
  PYNTRACE_OAUTH_CLIENT_ID     — OAuth app client ID
  PYNTRACE_OAUTH_CLIENT_SECRET — OAuth app client secret
  PYNTRACE_OAUTH_REDIRECT_URI  — callback URL (default: http://localhost:7234/auth/callback)
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request

PROVIDERS: dict[str, dict] = {
    "github": {
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "user_url": "https://api.github.com/user",
        "scopes": "read:user",
        "username_field": "login",
        "extra_auth_params": {},
        "extra_token_params": {},
    },
    "google": {
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "user_url": "https://www.googleapis.com/oauth2/v2/userinfo",
        "scopes": "openid email profile",
        "username_field": "email",
        "extra_auth_params": {"response_type": "code", "access_type": "online"},
        "extra_token_params": {"grant_type": "authorization_code"},
    },
}


def _provider_cfg() -> tuple[str, dict, str, str, str] | None:
    """Return (provider_name, cfg, client_id, client_secret, redirect_uri) or None."""
    provider = os.getenv("PYNTRACE_OAUTH_PROVIDER", "").lower()
    client_id = os.getenv("PYNTRACE_OAUTH_CLIENT_ID", "")
    client_secret = os.getenv("PYNTRACE_OAUTH_CLIENT_SECRET", "")
    redirect_uri = os.getenv(
        "PYNTRACE_OAUTH_REDIRECT_URI", "http://localhost:7234/auth/callback"
    )
    if provider not in PROVIDERS or not client_id:
        return None
    return provider, PROVIDERS[provider], client_id, client_secret, redirect_uri


def is_configured() -> bool:
    """Return True when OAuth env vars are set."""
    return _provider_cfg() is not None


def get_login_url(state: str) -> str | None:
    """Return the OAuth authorization URL, or None when OAuth is not configured."""
    cfg_tuple = _provider_cfg()
    if cfg_tuple is None:
        return None
    _, cfg, client_id, _, redirect_uri = cfg_tuple
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": cfg["scopes"],
        "state": state,
        **cfg["extra_auth_params"],
    }
    return f"{cfg['auth_url']}?{urllib.parse.urlencode(params)}"


def exchange_code(code: str) -> str | None:
    """Exchange an authorization *code* for a username.

    Returns the username string on success, or None on any failure.
    """
    cfg_tuple = _provider_cfg()
    if cfg_tuple is None:
        return None
    _, cfg, client_id, client_secret, redirect_uri = cfg_tuple

    # Step 1: exchange code → access token
    token_body = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            **cfg["extra_token_params"],
        }
    ).encode()

    try:
        req = urllib.request.Request(
            cfg["token_url"],
            data=token_body,
            headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            token_data = json.loads(r.read())
    except Exception:
        return None

    access_token = token_data.get("access_token")
    if not access_token:
        return None

    # Step 2: fetch user profile
    try:
        req2 = urllib.request.Request(
            cfg["user_url"],
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req2, timeout=10) as r:
            user_data = json.loads(r.read())
    except Exception:
        return None

    return user_data.get(cfg["username_field"]) or None
