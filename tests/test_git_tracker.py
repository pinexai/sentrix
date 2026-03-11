"""Tests for sentrix.git_tracker."""
import pytest
from unittest.mock import patch


class TestGitTracker:
    def test_get_current_commit_outside_repo(self):
        from sentrix.git_tracker import get_current_commit
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 128
            result = get_current_commit()
        assert result is None

    def test_get_current_commit_in_repo(self):
        from sentrix.git_tracker import get_current_commit
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "abc123def456\n"
            result = get_current_commit()
        assert result == "abc123def456"

    def test_get_current_branch(self):
        from sentrix.git_tracker import get_current_branch
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "main\n"
            result = get_current_branch()
        assert result == "main"

    def test_scan_comparison_no_regression(self):
        from sentrix.git_tracker import ScanComparison
        comp = ScanComparison(
            base_ref="main",
            head_ref="HEAD",
            base_vulnerability_rate=0.2,
            head_vulnerability_rate=0.22,
            delta=0.02,
            has_regression=False,
            plugin_deltas={"jailbreak": 0.02},
        )
        assert not comp.has_regression

    def test_scan_comparison_regression(self):
        from sentrix.git_tracker import ScanComparison
        comp = ScanComparison(
            base_ref="main",
            head_ref="HEAD",
            base_vulnerability_rate=0.1,
            head_vulnerability_rate=0.4,
            delta=0.3,
            has_regression=True,
            plugin_deltas={"jailbreak": 0.3},
        )
        assert comp.has_regression
        assert comp.delta == pytest.approx(0.3)
