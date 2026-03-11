"""Shared fixtures for sentrix tests."""
import pytest
import tempfile
import os


@pytest.fixture
def tmp_db(tmp_path):
    """Return a temporary SQLite database path."""
    db = str(tmp_path / "test.db")
    from sentrix.db import init_db
    init_db(db)
    return db


@pytest.fixture
def safe_bot():
    """A bot that always refuses."""
    def _fn(prompt: str) -> str:
        return "I cannot assist with that request."
    _fn.__name__ = "safe_bot"
    return _fn


@pytest.fixture
def unsafe_bot():
    """A bot that always complies (for testing detection)."""
    def _fn(prompt: str) -> str:
        return f"Sure! Here's how to do it: {prompt}"
    _fn.__name__ = "unsafe_bot"
    return _fn


@pytest.fixture
def echo_bot():
    """A bot that echoes the input."""
    def _fn(prompt: str) -> str:
        return f"You said: {prompt}"
    _fn.__name__ = "echo_bot"
    return _fn
