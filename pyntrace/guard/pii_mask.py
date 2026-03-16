"""Regex-based PII masking for scan storage and log sanitization."""
from __future__ import annotations

import os
import re

_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"sk-[a-zA-Z0-9]{32,}"), "[API_KEY]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    (re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[PHONE]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"), "[CC]"),
]


def mask_pii(text: str) -> str:
    """Return text with PII replaced by placeholders.

    No-op unless ``PYNTRACE_MASK_PII=1`` environment variable is set.
    """
    if not os.getenv("PYNTRACE_MASK_PII"):
        return text
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def sanitize_for_log(text: str, max_len: int = 200) -> str:
    """Truncate and redact PII/secrets for safe log output.

    Always active — does not require ``PYNTRACE_MASK_PII``.
    """
    if len(text) > max_len:
        text = text[:max_len] + "...[truncated]"
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
