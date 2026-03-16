"""Shared SQLite persistence layer for pyntrace."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

_DEFAULT_DB = Path.home() / ".pyntrace" / "data.db"
_CURRENT_DB: Path | None = None


def get_db_path(override: str | None = None) -> Path:
    if override:
        return Path(override)
    if _CURRENT_DB:
        return _CURRENT_DB
    return _DEFAULT_DB


def set_db_path(path: str | None) -> None:
    global _CURRENT_DB
    _CURRENT_DB = Path(path) if path else None


def get_conn(db_path: str | None = None) -> sqlite3.Connection:
    p = get_db_path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    key = os.environ.get("PYNTRACE_DB_KEY")
    if key:
        try:
            import sqlcipher3.dbapi2 as _sc  # type: ignore[import]

            conn = _sc.connect(str(p))
            conn.execute(f"PRAGMA key='{key}'")
            conn.row_factory = _sc.Row
            conn.execute("PRAGMA journal_mode=WAL")
            return conn  # type: ignore[return-value]
        except ImportError:
            import warnings

            warnings.warn(
                "[pyntrace] PYNTRACE_DB_KEY set but sqlcipher3 not installed. "
                "Database is NOT encrypted. "
                "Run: pip install sqlcipher3  (requires libsqlcipher)"
            )
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db(db_path: str | None = None) -> None:
    """Create all tables if they don't exist."""
    conn = get_conn(db_path)
    with conn:
        conn.executescript(_SCHEMA)
    conn.close()


def _q(sql: str, params: tuple = (), db_path: str | None = None) -> list:
    conn = get_conn(db_path)
    try:
        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        conn.commit()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def log_audit(
    event: str,
    *,
    ip: str = "",
    user_id: str = "",
    resource_type: str = "",
    resource_id: str = "",
    status: str = "success",
    details: dict | None = None,
    db_path: str | None = None,
) -> None:
    """Write one row to audit_log and a JSON line to the rotating audit log file.

    Never raises — failures are silently swallowed so the caller is never blocked.
    """
    import json as _json
    import time as _time

    try:
        _q(
            "INSERT INTO audit_log(timestamp,event,user_id,ip_address,"
            "resource_type,resource_id,status,details) VALUES(?,?,?,?,?,?,?,?)",
            (
                _time.time(),
                event,
                user_id,
                ip,
                resource_type,
                resource_id,
                status,
                _json.dumps(details or {}),
            ),
            db_path=db_path,
        )
    except Exception:
        pass

    try:
        from pyntrace.monitor.audit_log import write_audit_event

        write_audit_event(
            event,
            user_id=user_id,
            ip=ip,
            resource_type=resource_type,
            resource_id=resource_id,
            status=status,
        )
    except Exception:
        pass


_SCHEMA = """
-- LLM call capture
CREATE TABLE IF NOT EXISTS llm_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model TEXT,
    provider TEXT,
    function_name TEXT,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cost_usd REAL,
    duration_ms REAL,
    timestamp REAL,
    git_commit TEXT
);

-- Eval
CREATE TABLE IF NOT EXISTS datasets (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE,
    description TEXT,
    created_at REAL
);

CREATE TABLE IF NOT EXISTS dataset_items (
    id TEXT PRIMARY KEY,
    dataset_id TEXT,
    input TEXT,
    expected_output TEXT,
    metadata TEXT,
    created_at REAL,
    FOREIGN KEY (dataset_id) REFERENCES datasets(id)
);

CREATE TABLE IF NOT EXISTS experiments (
    id TEXT PRIMARY KEY,
    name TEXT,
    dataset_id TEXT,
    function_name TEXT,
    created_at REAL,
    git_commit TEXT
);

CREATE TABLE IF NOT EXISTS experiment_results (
    id TEXT PRIMARY KEY,
    experiment_id TEXT,
    dataset_item_id TEXT,
    output TEXT,
    scores TEXT,
    passed INTEGER,
    error TEXT,
    cost_usd REAL,
    duration_ms REAL
);

CREATE TABLE IF NOT EXISTS model_comparisons (
    id TEXT PRIMARY KEY,
    prompt TEXT,
    dataset_name TEXT,
    scorer_names TEXT,
    results_json TEXT,
    best_model TEXT,
    created_at REAL
);

-- Guard
CREATE TABLE IF NOT EXISTS red_team_reports (
    id TEXT PRIMARY KEY,
    target_fn TEXT,
    model TEXT,
    git_commit TEXT,
    total_attacks INTEGER,
    vulnerable_count INTEGER,
    vulnerability_rate REAL,
    total_cost_usd REAL,
    results_json TEXT,
    created_at REAL
);

CREATE TABLE IF NOT EXISTS fingerprints (
    id TEXT PRIMARY KEY,
    models_json TEXT,
    plugins_json TEXT,
    data_json TEXT,
    total_cost_usd REAL,
    created_at REAL
);

-- Monitor
CREATE TABLE IF NOT EXISTS traces (
    id TEXT PRIMARY KEY,
    name TEXT,
    start_time REAL,
    end_time REAL,
    input TEXT,
    output TEXT,
    metadata TEXT,
    tags TEXT,
    user_id TEXT,
    session_id TEXT,
    git_commit TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS spans (
    id TEXT PRIMARY KEY,
    trace_id TEXT,
    parent_span_id TEXT,
    name TEXT,
    span_type TEXT,
    start_time REAL,
    end_time REAL,
    input TEXT,
    output TEXT,
    metadata TEXT,
    model TEXT,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cost_usd REAL,
    duration_ms REAL,
    llm_call_id INTEGER,
    FOREIGN KEY (trace_id) REFERENCES traces(id)
);

CREATE TABLE IF NOT EXISTS scores (
    id TEXT PRIMARY KEY,
    trace_id TEXT,
    span_id TEXT,
    name TEXT,
    value REAL,
    comment TEXT,
    scorer TEXT,
    created_at REAL
);

CREATE TABLE IF NOT EXISTS drift_reports (
    id TEXT PRIMARY KEY,
    baseline_experiment TEXT,
    window_hours REAL,
    baseline_score REAL,
    current_score REAL,
    score_delta REAL,
    baseline_cost_per_call REAL,
    current_cost_per_call REAL,
    cost_delta_pct REAL,
    anomalous_trace_ids TEXT,
    sampled_trace_count INTEGER,
    created_at REAL
);

-- Agent security
CREATE TABLE IF NOT EXISTS agent_scan_reports (
    id TEXT PRIMARY KEY,
    target_fn TEXT,
    total_tests INTEGER,
    vulnerable_count INTEGER,
    results_json TEXT,
    created_at REAL
);

-- RAG scanning
CREATE TABLE IF NOT EXISTS rag_scan_reports (
    id TEXT PRIMARY KEY,
    documents_scanned INTEGER,
    poisoned_count INTEGER,
    system_prompt_hash TEXT,
    results_json TEXT,
    created_at REAL
);

-- Review annotations
CREATE TABLE IF NOT EXISTS review_annotations (
    id TEXT PRIMARY KEY,
    report_id TEXT,
    result_id TEXT,
    label TEXT,
    reviewer TEXT,
    comment TEXT,
    created_at REAL
);

-- Compliance reports
CREATE TABLE IF NOT EXISTS compliance_reports (
    id TEXT PRIMARY KEY,
    framework TEXT,
    overall_status TEXT,
    findings_json TEXT,
    scan_ids TEXT,
    created_at REAL
);

-- Monitoring events (daemon mode)
CREATE TABLE IF NOT EXISTS monitoring_events (
    id TEXT PRIMARY KEY,
    fn_name TEXT,
    vulnerability_rate REAL,
    cost_usd REAL,
    alert_sent INTEGER,
    created_at REAL
);

-- v0.2.0: Swarm trust exploitation
CREATE TABLE IF NOT EXISTS swarm_scan_reports (
    id TEXT PRIMARY KEY,
    agents_json TEXT,
    topology TEXT,
    rogue_position TEXT,
    attacks_json TEXT,
    propagation_results_json TEXT,
    overall_trust_exploit_rate REAL,
    per_agent_vulnerability_json TEXT,
    total_cost_usd REAL,
    created_at REAL
);

-- v0.2.0: Tool-chain privilege escalation
CREATE TABLE IF NOT EXISTS toolchain_reports (
    id TEXT PRIMARY KEY,
    tools_analyzed_json TEXT,
    find_json TEXT,
    escalation_chains_json TEXT,
    total_chains_tested INTEGER,
    high_severity_count INTEGER,
    medium_severity_count INTEGER,
    total_cost_usd REAL,
    created_at REAL
);

-- v0.2.0: System prompt leakage scoring
CREATE TABLE IF NOT EXISTS leakage_reports (
    id TEXT PRIMARY KEY,
    target_fn TEXT,
    system_prompt_length INTEGER,
    n_attempts INTEGER,
    overall_leakage_score REAL,
    phrases_leaked_json TEXT,
    technique_scores_json TEXT,
    recommendations_json TEXT,
    total_cost_usd REAL,
    created_at REAL
);

-- v0.2.0: Cross-language safety bypass
CREATE TABLE IF NOT EXISTS multilingual_reports (
    id TEXT PRIMARY KEY,
    target_fn TEXT,
    languages_json TEXT,
    attacks_json TEXT,
    results_json TEXT,
    most_vulnerable_language TEXT,
    safest_language TEXT,
    total_attacks_run INTEGER,
    total_cost_usd REAL,
    created_at REAL
);

-- v0.3.0: MCP security scanning
CREATE TABLE IF NOT EXISTS mcp_scan_reports (
    id TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    total_tests INTEGER,
    vulnerable_count INTEGER,
    results_json TEXT,
    created_at REAL
);

-- v0.4.0: Latency profiling
CREATE TABLE IF NOT EXISTS latency_reports (
    id TEXT PRIMARY KEY,
    fn_name TEXT,
    n_prompts INTEGER,
    n_runs INTEGER,
    p50_ms REAL,
    p95_ms REAL,
    p99_ms REAL,
    mean_ms REAL,
    min_ms REAL,
    max_ms REAL,
    results_json TEXT,
    created_at REAL
);

-- v0.4.0: Multi-turn conversation scanning
CREATE TABLE IF NOT EXISTS conversation_scan_reports (
    id TEXT PRIMARY KEY,
    fn_name TEXT,
    total_turns INTEGER,
    vulnerable_count INTEGER,
    vulnerability_rate REAL,
    results_json TEXT,
    created_at REAL
);

-- v0.5.0: Security audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    event TEXT NOT NULL,
    user_id TEXT DEFAULT '',
    ip_address TEXT DEFAULT '',
    resource_type TEXT DEFAULT '',
    resource_id TEXT DEFAULT '',
    status TEXT DEFAULT 'success',
    details TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event);
"""
