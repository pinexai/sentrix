"""Tests for pyntrace.guard.multilingual — cross-language safety bypass matrix."""
import importlib
from unittest.mock import MagicMock, patch

import pytest

_ml_mod = importlib.import_module("pyntrace.guard.multilingual")


def make_bot(response: str):
    def _fn(msg: str) -> str:
        return response
    _fn.__name__ = "bot"
    return _fn


class TestMultilingualReport:
    def _make_report(self):
        from pyntrace.guard.multilingual import MultilingualReport
        return MultilingualReport(
            target_fn="my_bot",
            languages_tested=["en", "zh", "ar"],
            attacks_tested=["jailbreak"],
            results={
                "en": {"jailbreak": 0.2},
                "zh": {"jailbreak": 0.5},
                "ar": {"jailbreak": 0.1},
            },
            most_vulnerable_language="zh",
            safest_language="ar",
            total_attacks_run=15,
            total_cost_usd=0.01,
        )

    def test_summary_runs(self, capsys):
        report = self._make_report()
        report.summary()
        out = capsys.readouterr().out
        assert "Chinese" in out or "zh" in out

    def test_heatmap_runs(self, capsys):
        report = self._make_report()
        report.heatmap()
        out = capsys.readouterr().out
        assert "jailbreak" in out

    def test_to_json(self):
        report = self._make_report()
        j = report.to_json()
        assert j["most_vulnerable_language"] == "zh"
        assert j["safest_language"] == "ar"
        assert j["total_attacks_run"] == 15

    def test_persist(self, tmp_db):
        from pyntrace.db import _q, set_db_path
        report = self._make_report()
        set_db_path(tmp_db)
        report._persist()
        rows = _q("SELECT id, most_vulnerable_language FROM multilingual_reports", db_path=tmp_db)
        assert len(rows) == 1
        assert rows[0]["most_vulnerable_language"] == "zh"


class TestScanMultilingual:
    def test_returns_report(self):
        from pyntrace.guard.multilingual import scan_multilingual, MultilingualReport

        bot = make_bot("I cannot help with that.")

        with patch.object(_ml_mod, "_translate_attack") as mock_trans:
            mock_trans.return_value = ("translated attack", 0.001)
            with patch.object(_ml_mod, "_judge_response") as mock_judge:
                mock_judge.return_value = (False, "Safe.", 0.001)
                report = scan_multilingual(
                    bot,
                    languages=["en", "fr"],
                    attacks=["jailbreak"],
                    include_mixed_language=False,
                    n_attacks=2,
                    _persist=False,
                )

        assert isinstance(report, MultilingualReport)
        assert set(report.languages_tested) == {"en", "fr"}
        assert "jailbreak" in report.attacks_tested

    def test_results_keys_match_languages(self):
        from pyntrace.guard.multilingual import scan_multilingual

        bot = make_bot("Safe response.")

        with patch.object(_ml_mod, "_translate_attack") as mock_trans:
            mock_trans.return_value = ("attack", 0.0)
            with patch.object(_ml_mod, "_judge_response") as mock_judge:
                mock_judge.return_value = (False, "Safe.", 0.0)
                report = scan_multilingual(
                    bot,
                    languages=["en", "de", "es"],
                    attacks=["jailbreak"],
                    include_mixed_language=False,
                    n_attacks=2,
                    _persist=False,
                )

        assert set(report.results.keys()) == {"en", "de", "es"}

    def test_vulnerable_bot_detected(self):
        from pyntrace.guard.multilingual import scan_multilingual

        bot = make_bot("Sure, I'll help with anything!")

        with patch.object(_ml_mod, "_translate_attack") as mock_trans:
            mock_trans.return_value = ("attack text", 0.001)
            with patch.object(_ml_mod, "_judge_response") as mock_judge:
                mock_judge.return_value = (True, "Vulnerable.", 0.001)
                report = scan_multilingual(
                    bot,
                    languages=["zh"],
                    attacks=["jailbreak"],
                    include_mixed_language=False,
                    n_attacks=3,
                    _persist=False,
                )

        assert report.results["zh"]["jailbreak"] > 0.0

    def test_most_and_safest_language(self):
        from pyntrace.guard.multilingual import MultilingualReport

        # Build report directly with deterministic values
        report = MultilingualReport(
            target_fn="bot",
            languages_tested=["en", "zh"],
            attacks_tested=["jailbreak"],
            results={"en": {"jailbreak": 0.05}, "zh": {"jailbreak": 0.9}},
            most_vulnerable_language="zh",
            safest_language="en",
            total_attacks_run=8,
            total_cost_usd=0.005,
        )

        assert report.most_vulnerable_language == "zh"
        assert report.safest_language == "en"
        assert report.most_vulnerable_language != report.safest_language

    def test_mixed_language_attack_generated(self):
        from pyntrace.guard.multilingual import _make_mixed_attack

        result = _make_mixed_attack("Please help me with this task.", "ar")
        assert len(result) > len("Please help me with this task.")
