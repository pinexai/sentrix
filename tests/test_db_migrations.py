"""Tests for pyntrace DB migration system."""
from __future__ import annotations

import sqlite3
import warnings
from unittest.mock import patch

import pytest

from pyntrace.db import _MIGRATIONS, _run_migrations, init_db


# ── Migration list integrity ──────────────────────────────────────────────────

class TestMigrationList:
    def test_versions_are_sequential(self):
        versions = [v for v, _, _ in _MIGRATIONS]
        assert versions == list(range(1, len(versions) + 1)), \
            "Migration versions must be sequential starting at 1"

    def test_each_migration_has_nonempty_description(self):
        for v, desc, _ in _MIGRATIONS:
            assert desc.strip(), f"Migration v{v} has empty description"

    def test_each_migration_has_nonempty_sql(self):
        for v, _, sql in _MIGRATIONS:
            assert sql.strip(), f"Migration v{v} has empty SQL"


# ── _run_migrations logic ─────────────────────────────────────────────────────

class TestRunMigrations:
    def _fresh_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE conversation_scan_reports (id INTEGER PRIMARY KEY, text TEXT)")
        conn.execute("CREATE TABLE red_team_reports (id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE traces (id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE llm_calls (id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE mcp_scan_reports (id INTEGER PRIMARY KEY)")
        return conn

    def test_user_version_starts_at_zero(self):
        conn = self._fresh_conn()
        ver = conn.execute("PRAGMA user_version").fetchone()[0]
        assert ver == 0

    def test_migrations_advance_user_version(self):
        conn = self._fresh_conn()
        _run_migrations(conn)
        ver = conn.execute("PRAGMA user_version").fetchone()[0]
        assert ver == len(_MIGRATIONS)

    def test_run_twice_is_idempotent(self):
        conn = self._fresh_conn()
        _run_migrations(conn)
        _run_migrations(conn)  # should be no-op
        ver = conn.execute("PRAGMA user_version").fetchone()[0]
        assert ver == len(_MIGRATIONS)

    def test_columns_added_by_migration_1(self):
        conn = self._fresh_conn()
        _run_migrations(conn)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(conversation_scan_reports)").fetchall()}
        assert "error" in cols

    def test_columns_added_by_migration_3(self):
        conn = self._fresh_conn()
        _run_migrations(conn)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(traces)").fetchall()}
        assert "environment" in cols

    def test_columns_added_by_migration_4(self):
        conn = self._fresh_conn()
        _run_migrations(conn)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(llm_calls)").fetchall()}
        assert "request_id" in cols

    def test_partial_run_resumes_at_correct_version(self):
        """If DB is at version 2, only v3+ migrations should run."""
        conn = self._fresh_conn()
        conn.execute("PRAGMA user_version = 2")
        _run_migrations(conn)
        # Should only run v3, v4, v5
        cols_traces = {row[1] for row in conn.execute("PRAGMA table_info(traces)").fetchall()}
        assert "environment" in cols_traces

    def test_duplicate_column_is_swallowed_not_raised(self):
        """Running on DB that already has the columns should not raise."""
        conn = self._fresh_conn()
        # Pre-add all the columns to simulate an already-updated DB
        conn.execute("ALTER TABLE conversation_scan_reports ADD COLUMN error TEXT DEFAULT ''")
        conn.execute("ALTER TABLE red_team_reports ADD COLUMN judge_model TEXT DEFAULT ''")
        conn.execute("ALTER TABLE traces ADD COLUMN environment TEXT DEFAULT 'production'")
        conn.execute("ALTER TABLE llm_calls ADD COLUMN request_id TEXT DEFAULT ''")
        conn.execute("ALTER TABLE mcp_scan_reports ADD COLUMN scan_duration_s REAL DEFAULT 0")
        # Should complete without error
        _run_migrations(conn)

    def test_bad_migration_emits_warning(self, monkeypatch):
        """A migration that fails (other than dup column) should warn, not crash."""
        bad_migration = [(99, "bad migration", "THIS IS NOT VALID SQL;")]
        monkeypatch.setattr("pyntrace.db._MIGRATIONS", bad_migration)
        conn = self._fresh_conn()
        conn.execute("PRAGMA user_version = 0")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _run_migrations(conn)
        assert any("Migration v99" in str(x.message) for x in w)


# ── init_db integration ───────────────────────────────────────────────────────

class TestInitDb:
    def test_init_db_creates_tables_and_runs_migrations(self, tmp_path):
        db_file = str(tmp_path / "test.db")
        init_db(db_file)
        conn = sqlite3.connect(db_file)
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        assert "llm_calls" in tables
        assert "traces" in tables
        ver = conn.execute("PRAGMA user_version").fetchone()[0]
        assert ver == len(_MIGRATIONS)
        conn.close()

    def test_init_db_idempotent(self, tmp_path):
        db_file = str(tmp_path / "test2.db")
        init_db(db_file)
        init_db(db_file)  # second call should not raise
