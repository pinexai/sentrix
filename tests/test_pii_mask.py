"""Tests for pyntrace/guard/pii_mask.py"""
import os
import pytest


@pytest.fixture(autouse=True)
def clear_mask_env(monkeypatch):
    monkeypatch.delenv("PYNTRACE_MASK_PII", raising=False)


def test_mask_pii_noop_without_env():
    from pyntrace.guard.pii_mask import mask_pii
    text = "Call me at 555-123-4567 or user@example.com"
    assert mask_pii(text) == text


def test_mask_email(monkeypatch):
    monkeypatch.setenv("PYNTRACE_MASK_PII", "1")
    from pyntrace.guard.pii_mask import mask_pii
    assert "[EMAIL]" in mask_pii("Send to user@example.com please")
    assert "user@example.com" not in mask_pii("Send to user@example.com please")


def test_mask_phone(monkeypatch):
    monkeypatch.setenv("PYNTRACE_MASK_PII", "1")
    from pyntrace.guard.pii_mask import mask_pii
    assert "[PHONE]" in mask_pii("Call 555-123-4567 now")
    assert "[PHONE]" in mask_pii("Call 555.123.4567 now")


def test_mask_ssn(monkeypatch):
    monkeypatch.setenv("PYNTRACE_MASK_PII", "1")
    from pyntrace.guard.pii_mask import mask_pii
    assert "[SSN]" in mask_pii("SSN is 123-45-6789")


def test_mask_credit_card(monkeypatch):
    monkeypatch.setenv("PYNTRACE_MASK_PII", "1")
    from pyntrace.guard.pii_mask import mask_pii
    assert "[CC]" in mask_pii("Card: 4111111111111111")


def test_mask_api_key(monkeypatch):
    monkeypatch.setenv("PYNTRACE_MASK_PII", "1")
    from pyntrace.guard.pii_mask import mask_pii
    assert "[API_KEY]" in mask_pii("key = sk-abcdefghijklmnopqrstuvwxyz123456")


def test_mask_multiple_pii(monkeypatch):
    monkeypatch.setenv("PYNTRACE_MASK_PII", "1")
    from pyntrace.guard.pii_mask import mask_pii
    result = mask_pii("user@example.com and 555-123-4567")
    assert "[EMAIL]" in result
    assert "[PHONE]" in result


def test_sanitize_for_log_always_active():
    from pyntrace.guard.pii_mask import sanitize_for_log
    result = sanitize_for_log("sk-abcdefghijklmnopqrstuvwxyz123456 abc")
    assert "[API_KEY]" in result


def test_sanitize_for_log_truncates():
    from pyntrace.guard.pii_mask import sanitize_for_log
    long_text = "x" * 300
    result = sanitize_for_log(long_text)
    assert len(result) < 300
    assert "[truncated]" in result


def test_sanitize_for_log_email():
    from pyntrace.guard.pii_mask import sanitize_for_log
    result = sanitize_for_log("user@example.com is blocked")
    assert "[EMAIL]" in result
