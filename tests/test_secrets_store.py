"""Tests for pyntrace/secrets/store.py"""
import os
import stat
import json
import pytest
from pathlib import Path


@pytest.fixture(autouse=True)
def clear_secrets_env(monkeypatch):
    monkeypatch.delenv("PYNTRACE_SECRETS_KEY", raising=False)


def test_load_returns_empty_when_no_file(tmp_path):
    from pyntrace.secrets.store import load_secrets
    assert load_secrets(tmp_path / "secrets.json") == {}


def test_save_and_load_plaintext(tmp_path, monkeypatch):
    p = tmp_path / "secrets.json"
    from pyntrace.secrets.store import save_secrets, load_secrets
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        save_secrets({"MY_KEY": "hello"}, p)
        # Clear injected env before reload
        monkeypatch.delenv("MY_KEY", raising=False)
        result = load_secrets(p)
    assert result == {"MY_KEY": "hello"}


def test_save_chmod_600(tmp_path, monkeypatch):
    p = tmp_path / "secrets.json"
    from pyntrace.secrets.store import save_secrets
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        save_secrets({"KEY": "val"}, p)
    file_stat = p.stat()
    # Owner read+write, no group/other permissions
    assert file_stat.st_mode & stat.S_IRUSR
    assert file_stat.st_mode & stat.S_IWUSR
    assert not (file_stat.st_mode & stat.S_IRGRP)
    assert not (file_stat.st_mode & stat.S_IROTH)


def test_load_injects_into_environ(tmp_path, monkeypatch):
    p = tmp_path / "secrets.json"
    monkeypatch.delenv("INJECTED_KEY", raising=False)
    from pyntrace.secrets.store import save_secrets, load_secrets
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        save_secrets({"INJECTED_KEY": "injected_val"}, p)
    load_secrets(p)
    assert os.environ.get("INJECTED_KEY") == "injected_val"


def test_load_does_not_override_existing_env(tmp_path, monkeypatch):
    p = tmp_path / "secrets.json"
    monkeypatch.setenv("EXISTING_KEY", "original")
    from pyntrace.secrets.store import save_secrets, load_secrets
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        save_secrets({"EXISTING_KEY": "new_value"}, p)
        load_secrets(p)
    assert os.environ["EXISTING_KEY"] == "original"


def test_load_warns_without_encryption(tmp_path, monkeypatch):
    """load_secrets warns when reading plaintext file (no PYNTRACE_SECRETS_KEY)."""
    p = tmp_path / "secrets.json"
    import warnings
    from pyntrace.secrets.store import save_secrets, load_secrets
    save_secrets({"K": "v"}, p)
    monkeypatch.delenv("K", raising=False)
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        load_secrets(p)
    assert any("encrypt" in str(x.message).lower() for x in w)


def test_encrypted_round_trip(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    monkeypatch.setenv("PYNTRACE_SECRETS_KEY", "my-pass")
    p = tmp_path / "secrets.enc"
    from pyntrace.secrets.store import save_secrets, load_secrets
    save_secrets({"SECRET": "encrypted_value"}, p)
    monkeypatch.delenv("SECRET", raising=False)
    result = load_secrets(p)
    assert result == {"SECRET": "encrypted_value"}
    # File should NOT be readable as plain JSON
    raw = p.read_bytes()
    with pytest.raises(Exception):
        json.loads(raw)


def test_wrong_key_returns_empty(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    monkeypatch.setenv("PYNTRACE_SECRETS_KEY", "correct-key")
    p = tmp_path / "secrets.enc"
    from pyntrace.secrets.store import save_secrets
    save_secrets({"K": "v"}, p)
    monkeypatch.setenv("PYNTRACE_SECRETS_KEY", "wrong-key")
    from pyntrace.secrets.store import load_secrets
    import warnings
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        result = load_secrets(p)
    assert result == {}
    assert any("decrypt" in str(x.message).lower() for x in w)


def test_list_secrets_masked(tmp_path, monkeypatch):
    p = tmp_path / "secrets.json"
    import warnings
    from pyntrace.secrets.store import save_secrets, list_secrets
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        save_secrets({"API_KEY": "sk-abcdefghij"}, p)
        result = list_secrets(p)
    assert "API_KEY" in result
    assert result["API_KEY"].endswith("***")
    assert "sk-abcdefghij" not in result["API_KEY"]


def test_delete_secret(tmp_path, monkeypatch):
    p = tmp_path / "secrets.json"
    import warnings
    from pyntrace.secrets.store import save_secrets, delete_secret, load_secrets
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        save_secrets({"K1": "v1", "K2": "v2"}, p)
        removed = delete_secret("K1", p)
        assert removed is True
        monkeypatch.delenv("K1", raising=False)
        monkeypatch.delenv("K2", raising=False)
        data = load_secrets(p)
    assert "K1" not in data
    assert "K2" in data


def test_delete_nonexistent_returns_false(tmp_path, monkeypatch):
    p = tmp_path / "secrets.json"
    import warnings
    from pyntrace.secrets.store import save_secrets, delete_secret
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        save_secrets({}, p)
        assert delete_secret("NOPE", p) is False
