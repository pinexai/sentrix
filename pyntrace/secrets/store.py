"""Local encrypted secrets store at ~/.pyntrace/secrets.json.

- Without ``cryptography`` package: plaintext JSON, chmod 600 (warns).
- With ``cryptography`` package + ``PYNTRACE_SECRETS_KEY`` env var set:
  AES-256 Fernet encryption (pip install pyntrace[secure]).
"""
from __future__ import annotations

import json
import os
import stat
import warnings
from pathlib import Path

_DEFAULT_SECRETS_FILE = Path.home() / ".pyntrace" / "secrets.json"


def _get_fernet_key() -> bytes | None:
    """Derive a Fernet key from PYNTRACE_SECRETS_KEY, or return None."""
    raw = os.getenv("PYNTRACE_SECRETS_KEY")
    if not raw:
        return None
    import base64
    import hashlib

    derived = hashlib.sha256(raw.encode()).digest()
    return base64.urlsafe_b64encode(derived)


def load_secrets(path: Path | None = None) -> dict[str, str]:
    """Load secrets from file and inject missing keys into os.environ.

    Returns the loaded dict (empty if file doesn't exist or decryption fails).
    """
    p = path or _DEFAULT_SECRETS_FILE
    if not p.exists():
        return {}

    raw = p.read_bytes()
    key = _get_fernet_key()

    if key:
        try:
            from cryptography.fernet import Fernet

            data: dict = json.loads(Fernet(key).decrypt(raw))
        except ImportError:
            warnings.warn(
                "[pyntrace] PYNTRACE_SECRETS_KEY set but cryptography not installed. "
                "Run: pip install pyntrace[secure]"
            )
            return {}
        except Exception:
            warnings.warn(
                "[pyntrace] Failed to decrypt secrets file — wrong PYNTRACE_SECRETS_KEY?"
            )
            return {}
    else:
        try:
            data = json.loads(raw)
        except Exception:
            return {}
        warnings.warn(
            "[pyntrace] Secrets file loaded without encryption. "
            "Set PYNTRACE_SECRETS_KEY and run 'pip install pyntrace[secure]' to encrypt."
        )

    for k, v in data.items():
        if k not in os.environ:
            os.environ[k] = str(v)
    return {k: str(v) for k, v in data.items()}


def save_secrets(secrets: dict[str, str], path: Path | None = None) -> None:
    """Write secrets dict to file with chmod 600.

    Encrypts with Fernet AES-256 when PYNTRACE_SECRETS_KEY is set and
    ``cryptography`` is installed; otherwise saves as plaintext JSON.
    """
    p = path or _DEFAULT_SECRETS_FILE
    p.parent.mkdir(parents=True, exist_ok=True)

    payload = json.dumps(secrets, indent=2).encode()
    key = _get_fernet_key()

    if key:
        try:
            from cryptography.fernet import Fernet

            payload = Fernet(key).encrypt(payload)
        except ImportError:
            warnings.warn(
                "[pyntrace] cryptography not installed — saving secrets as plaintext. "
                "Run: pip install pyntrace[secure]"
            )

    p.write_bytes(payload)
    p.chmod(stat.S_IRUSR | stat.S_IWUSR)  # chmod 600


def get_secret(key: str, path: Path | None = None) -> str | None:
    """Return a single secret value, or None if not found."""
    data = load_secrets(path)
    return data.get(key)


def delete_secret(key: str, path: Path | None = None) -> bool:
    """Remove a key from the secrets file. Returns True if key existed."""
    p = path or _DEFAULT_SECRETS_FILE
    data = load_secrets(p)
    if key not in data:
        return False
    del data[key]
    save_secrets(data, p)
    return True


def list_secrets(path: Path | None = None) -> dict[str, str]:
    """Return all secrets with values masked (first 3 chars + ***)."""
    data = load_secrets(path)
    return {k: (v[:3] + "***" if len(v) > 3 else "***") for k, v in data.items()}
