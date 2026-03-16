"""Structured JSON audit log → ~/.pyntrace/audit.log.

Rotating file handler (10 MB × 5 backups) using only stdlib.
Any log shipper (Filebeat, Fluentd, Vector, Splunk Universal Forwarder)
can tail this file without requiring a specific SIEM product.

Log format: one JSON object per line, e.g.
  {"timestamp": 1741996800.0, "event": "auth_failure", "ip": "10.0.0.1", ...}
"""
from __future__ import annotations

import json
import logging
import os
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

_DEFAULT_AUDIT_LOG = Path.home() / ".pyntrace" / "audit.log"

_logger: logging.Logger | None = None


def _get_logger() -> logging.Logger:
    global _logger
    if _logger is not None and _logger.handlers:
        return _logger

    log_path = Path(os.getenv("PYNTRACE_AUDIT_LOG", str(_DEFAULT_AUDIT_LOG)))
    log_path.parent.mkdir(parents=True, exist_ok=True)

    handler = RotatingFileHandler(
        str(log_path),
        maxBytes=10 * 1024 * 1024,  # 10 MB per file
        backupCount=5,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(message)s"))

    _logger = logging.getLogger("pyntrace.audit")
    # Clear any existing handlers to avoid duplicates on re-init
    _logger.handlers.clear()
    _logger.addHandler(handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False
    return _logger


def write_audit_event(event: str, **kwargs) -> None:
    """Write one structured JSON line to the audit log. Never raises."""
    try:
        record = {"timestamp": time.time(), "event": event, **kwargs}
        _get_logger().info(json.dumps(record, default=str))
    except Exception:
        pass
