"""Tests for pyntrace.guard.threats — threat intelligence catalog."""
from __future__ import annotations

import pytest

from pyntrace.guard.threats import get_threat_feed, _ALL_THREATS, _OWASP_CATALOG, _PYNTRACE_EXTRAS


class TestThreatCatalog:
    def test_owasp_catalog_has_ten_entries(self):
        assert len(_OWASP_CATALOG) == 10

    def test_pyntrace_extras_present(self):
        assert len(_PYNTRACE_EXTRAS) >= 1

    def test_all_threats_combined(self):
        assert len(_ALL_THREATS) == len(_OWASP_CATALOG) + len(_PYNTRACE_EXTRAS)

    def test_every_threat_has_required_keys(self):
        required = {"id", "name", "severity", "description", "category"}
        for threat in _ALL_THREATS:
            missing = required - threat.keys()
            assert not missing, f"Threat {threat.get('id')} missing keys: {missing}"

    def test_severity_values_are_valid(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for threat in _ALL_THREATS:
            assert threat["severity"] in valid, f"Invalid severity in {threat['id']}"

    def test_owasp_ids_start_with_llm(self):
        for threat in _OWASP_CATALOG:
            assert threat["id"].startswith("LLM"), f"Expected LLM prefix: {threat['id']}"

    def test_pyntrace_ids_start_with_pyn(self):
        for threat in _PYNTRACE_EXTRAS:
            assert threat["id"].startswith("PYN"), f"Expected PYN prefix: {threat['id']}"


class TestGetThreatFeed:
    def test_returns_list(self):
        feed = get_threat_feed()
        assert isinstance(feed, list)

    def test_default_limit_is_20(self):
        feed = get_threat_feed()
        assert len(feed) <= 20

    def test_custom_limit(self):
        feed = get_threat_feed(limit=5)
        assert len(feed) == 5

    def test_limit_zero_returns_empty(self):
        feed = get_threat_feed(limit=0)
        assert feed == []

    def test_sorted_most_severe_first(self):
        _SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        feed = get_threat_feed(limit=100)
        scores = [_SEV_ORDER.get(t["severity"], 0) for t in feed]
        assert scores == sorted(scores, reverse=True), "Feed must be sorted by severity desc"

    def test_critical_entries_before_high(self):
        feed = get_threat_feed(limit=100)
        severities = [t["severity"] for t in feed]
        if "CRITICAL" in severities and "HIGH" in severities:
            assert severities.index("CRITICAL") < severities.index("HIGH")

    def test_each_entry_has_all_required_fields(self):
        for entry in get_threat_feed(limit=100):
            assert "id" in entry
            assert "name" in entry
            assert "severity" in entry

    def test_limit_larger_than_catalog_returns_all(self):
        feed = get_threat_feed(limit=9999)
        assert len(feed) == len(_ALL_THREATS)
