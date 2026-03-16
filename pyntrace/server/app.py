"""pyntrace FastAPI dashboard — 7-tab real-time monitoring UI."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from pyntrace import __version__ as _VERSION

try:
    from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False

STATIC_DIR = Path(__file__).parent / "static"


def create_app(db_path: str | None = None) -> "FastAPI":
    if not _HAS_FASTAPI:
        raise ImportError("pip install pyntrace[server]")

    from pyntrace.db import init_db, _q
    init_db(db_path)

    app = FastAPI(title="pyntrace Dashboard", version="0.1.0")

    from starlette.middleware.base import BaseHTTPMiddleware

    class _SecurityHeaders(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            response = await call_next(request)
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline'; "
                "connect-src 'self' ws: wss:; "
                "img-src 'self' data:;"
            )
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
            return response

    app.add_middleware(_SecurityHeaders)

    # Auth + rate-limit middleware — protects all /api/* routes
    from pyntrace.server.auth import require_auth, require_admin, check_rate_limit

    class _AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            path = request.url.path
            if path.startswith("/api/"):
                from fastapi.responses import JSONResponse as _J
                # Auth check
                try:
                    require_auth(request)
                except Exception as exc:
                    status = getattr(exc, "status_code", 401)
                    headers = getattr(exc, "headers", {"WWW-Authenticate": 'Basic realm="pyntrace"'})
                    return _J({"detail": "Unauthorized"}, status_code=status, headers=headers)
                # Rate limit (200 req/min per IP)
                try:
                    check_rate_limit(request.client.host or "unknown")
                except Exception:
                    return _J({"detail": "Too many requests"}, status_code=429)
            return await call_next(request)

    app.add_middleware(_AuthMiddleware)

    # CORS — default: localhost only; override with PYNTRACE_CORS_ORIGINS
    from fastapi.middleware.cors import CORSMiddleware
    _allowed_origins = [
        o.strip()
        for o in os.getenv(
            "PYNTRACE_CORS_ORIGINS", "http://localhost:7234,http://localhost:7235"
        ).split(",")
        if o.strip()
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # Serve static files
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # WebSocket connections manager
    class ConnectionManager:
        def __init__(self):
            self.active: list[WebSocket] = []

        async def connect(self, ws: WebSocket):
            await ws.accept()
            self.active.append(ws)

        def disconnect(self, ws: WebSocket):
            if ws in self.active:
                self.active.remove(ws)

        async def broadcast(self, msg: dict):
            for ws in list(self.active):
                try:
                    await ws.send_json(msg)
                except Exception:
                    self.disconnect(ws)

    manager = ConnectionManager()

    @app.get("/", response_class=HTMLResponse)
    async def index():
        html_path = STATIC_DIR / "index.html"
        if html_path.exists():
            return HTMLResponse(html_path.read_text())
        return HTMLResponse(_FALLBACK_HTML.replace("v0.4.0", f"v{_VERSION}"))

    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket):
        await manager.connect(ws)
        try:
            while True:
                data = await ws.receive_text()
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await ws.send_json({"type": "pong"})
        except WebSocketDisconnect:
            manager.disconnect(ws)

    def _clamp_limit(limit: int) -> int:
        return max(1, min(limit, 1000))

    def _clamp_days(days: int) -> int:
        return max(1, min(days, 365))

    # API: Security tab
    @app.get("/api/security/reports")
    async def get_security_reports(limit: int = 20):
        limit = _clamp_limit(limit)
        rows = _q(
            "SELECT id, target_fn, model, git_commit, total_attacks, vulnerable_count, vulnerability_rate, total_cost_usd, created_at FROM red_team_reports ORDER BY created_at DESC LIMIT ?",
            (limit,), db_path
        )
        return JSONResponse(rows)

    @app.get("/api/security/reports/{report_id}")
    async def get_report_detail(report_id: str):
        rows = _q("SELECT * FROM red_team_reports WHERE id = ?", (report_id,), db_path)
        if not rows:
            return JSONResponse({"error": "not found"}, status_code=404)
        row = rows[0]
        if row.get("results_json"):
            row["results"] = json.loads(row["results_json"])
        return JSONResponse(row)

    @app.get("/api/security/fingerprints")
    async def get_fingerprints(limit: int = 10):
        limit = _clamp_limit(limit)
        rows = _q("SELECT id, models_json, plugins_json, total_cost_usd, created_at FROM fingerprints ORDER BY created_at DESC LIMIT ?", (limit,), db_path)
        for r in rows:
            r["models"] = json.loads(r["models_json"]) if r.get("models_json") else []
            r["plugins"] = json.loads(r["plugins_json"]) if r.get("plugins_json") else []
        return JSONResponse(rows)

    # API: v0.2 Security features
    @app.get("/api/security/swarm")
    async def get_swarm_reports(limit: int = 10):
        limit = _clamp_limit(limit)
        rows = _q(
            "SELECT id, agents_json, topology, rogue_position, attacks_json, overall_trust_exploit_rate, total_cost_usd, created_at FROM swarm_scan_reports ORDER BY created_at DESC LIMIT ?",
            (limit,), db_path
        )
        for r in rows:
            r["agents"] = json.loads(r["agents_json"]) if r.get("agents_json") else []
            r["attacks"] = json.loads(r["attacks_json"]) if r.get("attacks_json") else []
        return JSONResponse(rows)

    @app.get("/api/security/toolchain")
    async def get_toolchain_reports(limit: int = 10):
        limit = _clamp_limit(limit)
        rows = _q(
            "SELECT id, tools_analyzed_json, find_json, total_chains_tested, high_severity_count, medium_severity_count, total_cost_usd, created_at FROM toolchain_reports ORDER BY created_at DESC LIMIT ?",
            (limit,), db_path
        )
        for r in rows:
            r["tools_analyzed"] = json.loads(r["tools_analyzed_json"]) if r.get("tools_analyzed_json") else []
        return JSONResponse(rows)

    @app.get("/api/security/leakage")
    async def get_leakage_reports(limit: int = 10):
        limit = _clamp_limit(limit)
        rows = _q(
            "SELECT id, target_fn, system_prompt_length, n_attempts, overall_leakage_score, technique_scores_json, total_cost_usd, created_at FROM leakage_reports ORDER BY created_at DESC LIMIT ?",
            (limit,), db_path
        )
        for r in rows:
            r["technique_scores"] = json.loads(r["technique_scores_json"]) if r.get("technique_scores_json") else {}
        return JSONResponse(rows)

    @app.get("/api/security/multilingual")
    async def get_multilingual_reports(limit: int = 10):
        limit = _clamp_limit(limit)
        rows = _q(
            "SELECT id, target_fn, languages_json, attacks_json, most_vulnerable_language, safest_language, total_attacks_run, total_cost_usd, created_at FROM multilingual_reports ORDER BY created_at DESC LIMIT ?",
            (limit,), db_path
        )
        for r in rows:
            r["languages"] = json.loads(r["languages_json"]) if r.get("languages_json") else []
        return JSONResponse(rows)

    # API: Eval tab
    @app.get("/api/eval/experiments")
    async def get_experiments(limit: int = 20):
        limit = _clamp_limit(limit)
        rows = _q("SELECT * FROM experiments ORDER BY created_at DESC LIMIT ?", (limit,), db_path)
        return JSONResponse(rows)

    @app.get("/api/eval/datasets")
    async def get_datasets():
        rows = _q("SELECT d.id, d.name, d.description, d.created_at, COUNT(di.id) as item_count FROM datasets d LEFT JOIN dataset_items di ON d.id = di.dataset_id GROUP BY d.id ORDER BY d.created_at DESC", db_path=db_path)
        return JSONResponse(rows)

    # API: Monitor tab
    @app.get("/api/monitor/traces")
    async def get_traces(limit: int = 50):
        limit = _clamp_limit(limit)
        rows = _q("SELECT id, name, start_time, end_time, user_id, tags, error FROM traces ORDER BY start_time DESC LIMIT ?", (limit,), db_path)
        return JSONResponse(rows)

    @app.get("/api/monitor/traces/{trace_id}/spans")
    async def get_spans(trace_id: str):
        rows = _q("SELECT * FROM spans WHERE trace_id = ? ORDER BY start_time", (trace_id,), db_path)
        return JSONResponse(rows)

    @app.get("/api/monitor/drift")
    async def get_drift(limit: int = 10):
        limit = _clamp_limit(limit)
        rows = _q("SELECT * FROM drift_reports ORDER BY created_at DESC LIMIT ?", (limit,), db_path)
        return JSONResponse(rows)

    # API: Costs tab
    @app.get("/api/costs/summary")
    async def get_costs_summary(days: int = 7):
        days = _clamp_days(days)
        cutoff = time.time() - days * 86400
        rows = _q(
            "SELECT model, SUM(cost_usd) as total_cost, COUNT(*) as calls, AVG(duration_ms) as avg_ms FROM llm_calls WHERE timestamp > ? GROUP BY model ORDER BY total_cost DESC",
            (cutoff,), db_path
        )
        return JSONResponse(rows)

    @app.get("/api/costs/daily")
    async def get_daily_costs(days: int = 30):
        days = _clamp_days(days)
        cutoff = time.time() - days * 86400
        rows = _q(
            "SELECT DATE(timestamp, 'unixepoch') as date, SUM(cost_usd) as cost, COUNT(*) as calls FROM llm_calls WHERE timestamp > ? GROUP BY date ORDER BY date",
            (cutoff,), db_path
        )
        return JSONResponse(rows)

    # API: Review tab
    @app.get("/api/review/pending")
    async def get_pending_reviews():
        from pyntrace.review.annotations import ReviewQueue
        q = ReviewQueue(db_path)
        return JSONResponse(q.pending())

    @app.post("/api/review/annotate")
    async def create_annotation(body: dict):
        from pyntrace.review.annotations import annotate
        ann = annotate(
            result_id=body["result_id"],
            label=body["label"],
            reviewer=body.get("reviewer"),
            comment=body.get("comment"),
        )
        return JSONResponse(ann.to_json())

    # API: Compliance tab
    @app.get("/api/compliance/reports")
    async def get_compliance_reports():
        rows = _q("SELECT * FROM compliance_reports ORDER BY created_at DESC LIMIT 20", db_path=db_path)
        return JSONResponse(rows)

    @app.post("/api/compliance/generate")
    async def generate_compliance(body: dict):
        from pyntrace.compliance import generate_report
        report = generate_report(framework=body.get("framework", "owasp_llm_top10"))
        return JSONResponse(report.to_json())

    # API: Git tab
    @app.get("/api/git/history")
    async def get_git_history():
        rows = _q("SELECT git_commit, COUNT(*) as scans, AVG(vulnerability_rate) as avg_vuln_rate, SUM(total_cost_usd) as total_cost FROM red_team_reports WHERE git_commit IS NOT NULL GROUP BY git_commit ORDER BY MAX(created_at) DESC LIMIT 20", db_path=db_path)
        return JSONResponse(rows)

    # API: MCP scan tab (v0.3.0)
    @app.get("/api/mcp-scans")
    async def get_mcp_scans(limit: int = 20):
        rows = _q(
            "SELECT id, endpoint, total_tests, vulnerable_count, created_at FROM mcp_scan_reports ORDER BY created_at DESC LIMIT ?",
            (limit,), db_path
        )
        return JSONResponse(rows)

    @app.get("/api/mcp-scans/{scan_id}")
    async def get_mcp_scan(scan_id: str):
        rows = _q(
            "SELECT * FROM mcp_scan_reports WHERE id = ?",
            (scan_id,), db_path
        )
        if not rows:
            return JSONResponse({"error": "Not found"}, status_code=404)
        row = rows[0]
        if row.get("results_json"):
            row["results"] = json.loads(row["results_json"])
            del row["results_json"]
        return JSONResponse(row)

    # API: Latency tab (v0.4.0)
    @app.get("/api/latency")
    async def get_latency_reports(limit: int = 20):
        limit = _clamp_limit(limit)
        rows = _q(
            "SELECT id, fn_name, n_prompts, n_runs, p50_ms, p95_ms, p99_ms, mean_ms, min_ms, max_ms, created_at FROM latency_reports ORDER BY created_at DESC LIMIT ?",
            (limit,), db_path
        )
        return JSONResponse(rows)

    @app.get("/api/latency/{report_id}")
    async def get_latency_report(report_id: str):
        rows = _q("SELECT * FROM latency_reports WHERE id = ?", (report_id,), db_path)
        if not rows:
            return JSONResponse({"error": "Not found"}, status_code=404)
        row = rows[0]
        if row.get("results_json"):
            row["per_prompt"] = json.loads(row["results_json"])
            del row["results_json"]
        return JSONResponse(row)

    # API: Conversation scans tab (v0.4.0)
    @app.get("/api/conversation-scans")
    async def get_conversation_scans(limit: int = 20):
        limit = _clamp_limit(limit)
        rows = _q(
            "SELECT id, fn_name, total_turns, vulnerable_count, vulnerability_rate, created_at FROM conversation_scan_reports ORDER BY created_at DESC LIMIT ?",
            (limit,), db_path
        )
        return JSONResponse(rows)

    @app.get("/api/conversation-scans/{scan_id}")
    async def get_conversation_scan(scan_id: str):
        rows = _q("SELECT * FROM conversation_scan_reports WHERE id = ?", (scan_id,), db_path)
        if not rows:
            return JSONResponse({"error": "Not found"}, status_code=404)
        row = rows[0]
        if row.get("results_json"):
            row["results"] = json.loads(row["results_json"])
            del row["results_json"]
        return JSONResponse(row)

    # Prometheus metrics endpoint (v0.4.0)
    from fastapi import Response as _FResponse

    @app.get("/metrics", include_in_schema=False)
    async def prometheus_metrics():
        from pyntrace.monitor.prometheus import PrometheusExporter
        exp = PrometheusExporter(db_path=db_path)
        return _FResponse(
            content=exp.get_metrics_text(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    # --- OAuth routes (v0.5.0) ---
    _oauth_states: set[str] = set()

    @app.get("/auth/login", include_in_schema=False)
    async def oauth_login():
        from pyntrace.server.oauth import get_login_url
        import secrets as _sec
        state = _sec.token_urlsafe(16)
        _oauth_states.add(state)
        url = get_login_url(state)
        if not url:
            return HTMLResponse(
                "<h1>OAuth not configured</h1>"
                "<p>Set PYNTRACE_OAUTH_PROVIDER, PYNTRACE_OAUTH_CLIENT_ID, "
                "PYNTRACE_OAUTH_CLIENT_SECRET to enable OAuth login.</p>"
            )
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url)

    @app.get("/auth/callback", include_in_schema=False)
    async def oauth_callback(code: str = "", state: str = ""):
        from pyntrace.server.oauth import exchange_code
        from pyntrace.server.auth import make_session_cookie
        from fastapi.responses import RedirectResponse, HTMLResponse as _H
        if state not in _oauth_states:
            return _H("<h1>Invalid or expired OAuth state</h1>", status_code=400)
        _oauth_states.discard(state)
        username = exchange_code(code)
        if not username:
            return _H("<h1>OAuth authentication failed</h1>", status_code=401)
        resp = RedirectResponse("/")
        resp.set_cookie(
            "pyntrace_session",
            make_session_cookie(username),
            httponly=True,
            samesite="lax",
        )
        return resp

    @app.get("/auth/logout", include_in_schema=False)
    async def oauth_logout():
        from fastapi.responses import RedirectResponse
        resp = RedirectResponse("/")
        resp.delete_cookie("pyntrace_session")
        return resp

    # --- GDPR endpoints (v0.5.0) ---
    from pyntrace.db import log_audit

    @app.get("/api/user/{user_id}/data")
    async def export_user_data(user_id: str, request: Request):
        """GDPR Art. 20 — data portability export."""
        check_rate_limit(request.client.host or "unknown", max_requests=10, window_s=60)
        data = {
            "user_id": user_id,
            "traces": _q(
                "SELECT id, name, start_time, end_time, output, error FROM traces WHERE user_id=?",
                (user_id,), db_path,
            ),
            "annotations": _q(
                "SELECT * FROM review_annotations WHERE reviewer=?",
                (user_id,), db_path,
            ),
        }
        log_audit(
            "data_export",
            ip=request.client.host or "",
            user_id=user_id,
            resource_type="user_data",
            resource_id=user_id,
        )
        return JSONResponse(data)

    @app.delete("/api/user/{user_id}/data", status_code=204)
    async def delete_user_data(user_id: str, request: Request):
        """GDPR Art. 17 — right to erasure (admin only)."""
        # Extra auth: require admin role
        try:
            require_admin(request)
        except Exception as exc:
            from fastapi.responses import JSONResponse as _J
            return _J({"detail": str(exc)}, status_code=getattr(exc, "status_code", 403))
        check_rate_limit(request.client.host or "unknown", max_requests=5, window_s=60)
        _q("DELETE FROM spans WHERE trace_id IN (SELECT id FROM traces WHERE user_id=?)",
           (user_id,), db_path)
        _q("DELETE FROM traces WHERE user_id=?", (user_id,), db_path)
        _q("DELETE FROM review_annotations WHERE reviewer=?", (user_id,), db_path)
        log_audit(
            "data_delete",
            ip=request.client.host or "",
            user_id=user_id,
            resource_type="user_data",
            resource_id=user_id,
        )

    return app


def run(
    port: int = 7234,
    db_path: str | None = None,
    no_open: bool = False,
    ssl_certfile: str | None = None,
    ssl_keyfile: str | None = None,
) -> None:
    """Start the pyntrace dashboard server."""
    try:
        import uvicorn
    except ImportError:
        raise ImportError("pip install pyntrace[server]")

    app = create_app(db_path)
    scheme = "https" if ssl_certfile else "http"

    if not no_open:
        import threading

        def _open_browser():
            import time
            import webbrowser
            time.sleep(1.5)
            webbrowser.open(f"{scheme}://localhost:{port}")

        threading.Thread(target=_open_browser, daemon=True).start()

    print(f"[pyntrace] Dashboard running at {scheme}://localhost:{port}")
    if ssl_certfile:
        print(f"[pyntrace] TLS enabled: {ssl_certfile}")

    ssl_kwargs: dict = {}
    if ssl_certfile:
        ssl_kwargs["ssl_certfile"] = ssl_certfile
    if ssl_keyfile:
        ssl_kwargs["ssl_keyfile"] = ssl_keyfile

    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning", **ssl_kwargs)


_FALLBACK_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>pyntrace Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
/* ── Design tokens ─────────────────────────────────────────────── */
:root {
  --bg-base:    #0a0a14;
  --bg-surface: #14142a;
  --bg-card:    #1a1a2e;
  --bg-hover:   #1e1e3e;
  --border:     #2a2a4e;
  --text-1:     #e2e8f0;
  --text-2:     #94a3b8;
  --text-3:     #64748b;
  --accent:     #c084fc;
  --accent-dim: #7c3aed;
  --success:    #10b981;
  --warning:    #f59e0b;
  --danger:     #ef4444;
  --info:       #3b82f6;
  --r-sm: 4px; --r: 8px; --r-lg: 12px;
  --font-mono: 'Fira Code', 'Courier New', monospace;
}
/* ── Reset & base ───────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
       background: var(--bg-base); color: var(--text-1); min-height: 100vh; }
/* ── Header ────────────────────────────────────────────────── */
.header { background: linear-gradient(135deg, #4a0080, #6a00c0);
          padding: 14px 24px; display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.header-left { display: flex; align-items: center; gap: 12px; }
.header h1 { font-size: 20px; font-weight: 700; letter-spacing: -.5px; }
.badge { background: rgba(255,255,255,.2); padding: 2px 8px; border-radius: 12px; font-size: 11px; }
/* ── Search box ─────────────────────────────────────────────── */
.search-wrap { position: relative; }
.search-input { background: rgba(0,0,0,.35); border: 1px solid rgba(255,255,255,.15);
                color: var(--text-1); border-radius: var(--r); padding: 6px 12px 6px 32px;
                font-size: 13px; width: 240px; outline: none; transition: border .2s; }
.search-input:focus { border-color: var(--accent); }
.search-input::placeholder { color: var(--text-3); }
.search-icon { position: absolute; left: 9px; top: 50%; transform: translateY(-50%);
               color: var(--text-3); font-size: 13px; pointer-events: none; }
.search-hint { position: absolute; right: 9px; top: 50%; transform: translateY(-50%);
               color: var(--text-3); font-size: 11px; pointer-events: none; }
@media(max-width:600px){ .search-wrap { display: none; } }
/* ── Tabs ───────────────────────────────────────────────────── */
.tabs { display: flex; background: var(--bg-surface); border-bottom: 1px solid var(--border);
        padding: 0 20px; overflow-x: auto; scrollbar-width: none; gap: 0; }
.tabs::-webkit-scrollbar { display: none; }
.tab { padding: 11px 18px; cursor: pointer; border-bottom: 2px solid transparent;
       color: var(--text-2); font-size: 13px; font-weight: 500;
       transition: color .15s, border-color .15s; white-space: nowrap; outline: none;
       display: flex; align-items: center; gap: 6px; user-select: none; }
.tab.active { color: var(--accent); border-bottom-color: var(--accent); }
.tab:hover:not(.active) { color: var(--text-1); }
.tab:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
.tab-count { background: var(--bg-hover); color: var(--text-3); border-radius: 10px;
             font-size: 10px; padding: 1px 6px; min-width: 18px; text-align: center; }
.tab.active .tab-count { background: rgba(192,132,252,.2); color: var(--accent); }
/* ── Content ────────────────────────────────────────────────── */
.content { padding: 20px 24px; max-width: 1400px; }
@media(max-width:768px){ .content { padding: 12px 14px; } }
/* ── Cards ──────────────────────────────────────────────────── */
.card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--r);
        padding: 18px 20px; margin-bottom: 14px; }
.card h3 { color: var(--accent); font-size: 12px; font-weight: 600; text-transform: uppercase;
           letter-spacing: .6px; margin-bottom: 14px; }
/* ── Stat cards ─────────────────────────────────────────────── */
.stats-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 12px; margin-bottom: 14px; }
.stat-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--r);
             padding: 14px 16px; }
.stat-card .sv { font-size: 28px; font-weight: 700; line-height: 1.1; }
.stat-card .sl { font-size: 11px; color: var(--text-2); margin-top: 3px; }
.sv-danger { color: var(--danger); }
.sv-warning { color: var(--warning); }
.sv-success { color: var(--success); }
.sv-info { color: var(--info); }
.sv-accent { color: var(--accent); }
/* ── Table ──────────────────────────────────────────────────── */
.table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; padding: 8px 12px; color: var(--text-2); font-weight: 500;
     border-bottom: 1px solid var(--border); cursor: pointer; user-select: none;
     white-space: nowrap; }
th:hover { color: var(--accent); }
th .sort-icon { font-size: 10px; margin-left: 4px; opacity: .5; }
th.sort-asc .sort-icon::after { content: ' ↑'; opacity: 1; }
th.sort-desc .sort-icon::after { content: ' ↓'; opacity: 1; }
td { padding: 10px 12px; border-bottom: 1px solid #1a1a2e; vertical-align: middle; }
tr:last-child td { border-bottom: none; }
tbody tr { transition: background .12s; cursor: pointer; }
tbody tr:hover td { background: var(--bg-hover); }
/* ── Mobile cards ─────────────────────────────────────────────── */
@media(max-width:640px){
  .mobile-hide { display: none; }
  .mobile-card-row { display: block; border-bottom: 1px solid var(--border); padding: 12px; }
  .mobile-card-row .mc-title { font-weight: 600; margin-bottom: 4px; }
  .mobile-card-row .mc-row { display: flex; justify-content: space-between; font-size: 12px; color: var(--text-2); margin-top: 3px; }
}
/* ── Badges ──────────────────────────────────────────────────── */
.badge-danger  { background: rgba(239,68,68,.15); color: #fca5a5; padding: 2px 8px; border-radius: var(--r-sm); font-size: 11px; white-space: nowrap; }
.badge-warning { background: rgba(245,158,11,.15); color: #fcd34d; padding: 2px 8px; border-radius: var(--r-sm); font-size: 11px; white-space: nowrap; }
.badge-success { background: rgba(16,185,129,.15); color: #6ee7b7; padding: 2px 8px; border-radius: var(--r-sm); font-size: 11px; white-space: nowrap; }
.badge-info    { background: rgba(59,130,246,.15); color: #93c5fd; padding: 2px 8px; border-radius: var(--r-sm); font-size: 11px; white-space: nowrap; }
.badge-neutral { background: var(--bg-hover); color: var(--text-2); padding: 2px 8px; border-radius: var(--r-sm); font-size: 11px; white-space: nowrap; }
/* ── Severity icon labels ─────────────────────────────────────────── */
.sev-label { display: inline-flex; align-items: center; gap: 4px; font-size: 12px; }
.sev-critical { color: var(--danger); }
.sev-high     { color: #f97316; }
.sev-medium   { color: var(--warning); }
.sev-low      { color: var(--success); }
/* ── Progress bar ─────────────────────────────────────────────── */
.progress-bar-wrap { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.progress-bar-label { width: 110px; font-size: 12px; color: var(--text-2); text-align: right; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex-shrink: 0; }
.progress-bar-track { flex: 1; height: 10px; background: var(--bg-hover); border-radius: 5px; overflow: hidden; }
.progress-bar-fill { height: 100%; border-radius: 5px; transition: width .4s ease; }
.progress-bar-val { width: 60px; font-size: 12px; color: var(--text-2); }
/* ── Loading skeleton ───────────────────────────────────────────── */
.skeleton-wrap { padding: 16px 0; }
.skel { background: linear-gradient(90deg, var(--bg-card) 25%, var(--bg-hover) 50%, var(--bg-card) 75%);
        background-size: 200% 100%; animation: shimmer 1.4s infinite; border-radius: var(--r-sm); }
@keyframes shimmer { 0%{background-position:200% 0} 100%{background-position:-200% 0} }
.skel-line { height: 14px; margin-bottom: 10px; }
.skel-line.w90 { width: 90%; }
.skel-line.w70 { width: 70%; }
.skel-line.w50 { width: 50%; }
.skel-head { height: 18px; margin-bottom: 16px; }
/* ── Empty states ─────────────────────────────────────────────── */
.empty-state { text-align: center; padding: 56px 24px; }
.empty-state .ei { font-size: 42px; margin-bottom: 12px; }
.empty-state h3 { color: var(--accent); font-size: 16px; font-weight: 600; margin-bottom: 6px; }
.empty-state p { color: var(--text-2); font-size: 13px; margin-bottom: 20px; max-width: 320px; margin-left: auto; margin-right: auto; }
.empty-cmd { background: var(--bg-base); border: 1px solid var(--border); border-radius: var(--r);
             padding: 9px 14px; display: inline-flex; align-items: center; gap: 10px;
             font-family: var(--font-mono); font-size: 12px; color: var(--accent); max-width: 100%; }
.copy-btn { background: var(--bg-hover); color: var(--text-2); border: none; padding: 3px 10px;
            border-radius: var(--r-sm); cursor: pointer; font-size: 11px; flex-shrink: 0; transition: all .15s; }
.copy-btn:hover { background: var(--accent); color: var(--bg-base); }
/* ── Error state ────────────────────────────────────────────── */
.error-state { text-align: center; padding: 56px 24px; }
.error-state .error-icon { font-size: 38px; margin-bottom: 10px; }
.error-state p { color: var(--text-2); font-size: 13px; margin-bottom: 18px; }
.retry-btn { background: transparent; color: var(--accent); border: 1px solid var(--accent);
             padding: 7px 22px; border-radius: var(--r); cursor: pointer; font-size: 13px;
             transition: all .2s; }
.retry-btn:hover { background: var(--accent); color: var(--bg-base); }
/* ── Chart ──────────────────────────────────────────────────── */
.chart-wrap { position: relative; height: 200px; margin-bottom: 4px; }
/* ── Detail panel ─────────────────────────────────────────────── */
.detail-panel { position: fixed; right: 0; top: 0; height: 100vh; width: min(480px, 100vw);
                background: var(--bg-surface); border-left: 1px solid var(--border);
                box-shadow: -8px 0 32px rgba(0,0,0,.5); z-index: 200;
                transform: translateX(100%); transition: transform .25s ease; overflow-y: auto; }
.detail-panel.open { transform: translateX(0); }
.detail-panel-header { padding: 16px 20px; border-bottom: 1px solid var(--border);
                       display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; background: var(--bg-surface); z-index: 1; }
.detail-panel-header h2 { font-size: 15px; font-weight: 600; color: var(--text-1); }
.close-btn { background: var(--bg-hover); border: none; color: var(--text-2); width: 28px; height: 28px;
             border-radius: 50%; cursor: pointer; font-size: 16px; display: flex; align-items: center; justify-content: center; transition: all .15s; }
.close-btn:hover { background: var(--border); color: var(--text-1); }
.detail-body { padding: 16px 20px; }
.detail-section { margin-bottom: 18px; }
.detail-section h4 { font-size: 11px; text-transform: uppercase; letter-spacing: .5px; color: var(--text-3); margin-bottom: 8px; font-weight: 600; }
.detail-kv { display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px solid var(--bg-hover); font-size: 13px; }
.detail-kv .dk { color: var(--text-2); }
.detail-kv .dv { color: var(--text-1); font-weight: 500; text-align: right; max-width: 60%; word-break: break-all; }
.overlay { position: fixed; inset: 0; background: rgba(0,0,0,.6); z-index: 199; display: none; }
.overlay.open { display: block; }
/* ── Toast notifications ────────────────────────────────────────── */
#toasts { position: fixed; top: 18px; right: 18px; z-index: 999; display: flex; flex-direction: column; gap: 8px; pointer-events: none; }
.toast { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--r);
         padding: 11px 16px; font-size: 13px; min-width: 220px; max-width: 340px;
         box-shadow: 0 4px 16px rgba(0,0,0,.5); transform: translateX(110%);
         transition: transform .25s ease; pointer-events: all; display: flex; align-items: center; gap: 10px; }
.toast.show { transform: translateX(0); }
.toast-success { border-left: 3px solid var(--success); }
.toast-error   { border-left: 3px solid var(--danger); }
.toast-info    { border-left: 3px solid var(--info); }
.toast-warning { border-left: 3px solid var(--warning); }
/* ── Search modal ─────────────────────────────────────────────── */
.search-modal { position: fixed; top: 80px; left: 50%; transform: translateX(-50%);
                background: var(--bg-surface); border: 1px solid var(--border);
                border-radius: var(--r-lg); width: min(560px, calc(100vw - 32px));
                box-shadow: 0 16px 48px rgba(0,0,0,.7); z-index: 300; overflow: hidden; display: none; }
.search-modal.open { display: block; }
.search-modal-input { width: 100%; background: transparent; border: none;
                      border-bottom: 1px solid var(--border); padding: 14px 18px;
                      font-size: 15px; color: var(--text-1); outline: none; }
.search-modal-input::placeholder { color: var(--text-3); }
.search-results-wrap { max-height: 360px; overflow-y: auto; padding: 8px 0; }
.search-result-item { padding: 9px 18px; cursor: pointer; display: flex; align-items: center; gap: 10px; transition: background .12s; }
.search-result-item:hover { background: var(--bg-hover); }
.search-result-item .sri-label { font-size: 13px; color: var(--text-1); }
.search-result-item .sri-meta { font-size: 11px; color: var(--text-3); margin-left: auto; }
.search-empty { padding: 24px 18px; text-align: center; color: var(--text-3); font-size: 13px; }
/* ── Detail result item ─────────────────────────────────────────── */
.result-item { border: 1px solid var(--border); border-radius: var(--r); padding: 10px 14px; margin-bottom: 8px; }
.result-item.vuln { border-left: 3px solid var(--danger); }
.result-item.safe { border-left: 3px solid var(--success); opacity: .7; }
.result-item .ri-header { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.result-item .ri-attack { font-size: 12px; color: var(--text-2); margin-top: 4px; font-family: var(--font-mono); word-break: break-all; }
.result-collapse { background: var(--bg-hover); border: 1px dashed var(--border); border-radius: var(--r); padding: 8px 14px; margin-top: 4px; cursor: pointer; font-size: 12px; color: var(--text-3); text-align: center; }
.result-collapse:hover { color: var(--accent); }
/* ── Vuln rate pill ─────────────────────────────────────────────── */
.rate-pill { display: inline-flex; align-items: center; gap: 5px; font-size: 13px; font-weight: 600; }
/* ── Scrollbar ────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-base); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
</style>
</head>
<body>
<div class="header">
  <div class="header-left">
    <h1>pyntrace <span class="badge">v0.4.0</span></h1>
  </div>
  <div class="search-wrap">
    <span class="search-icon">🔍</span>
    <input class="search-input" id="searchBar" placeholder="Filter current tab…" oninput="filterTable(this.value)" autocomplete="off">
    <span class="search-hint">⌘K</span>
  </div>
</div>

<div class="tabs" id="tabBar" role="tablist" aria-label="Dashboard sections">
  <div class="tab active" role="tab" tabindex="0" aria-selected="true"  onclick="showTab(this,'security')"   onkeydown="tabKey(event,this,'security')">Security   <span class="tab-count" id="cnt-security">—</span></div>
  <div class="tab"        role="tab" tabindex="0" aria-selected="false" onclick="showTab(this,'mcp')"        onkeydown="tabKey(event,this,'mcp')">MCP        <span class="tab-count" id="cnt-mcp">—</span></div>
  <div class="tab"        role="tab" tabindex="0" aria-selected="false" onclick="showTab(this,'eval')"       onkeydown="tabKey(event,this,'eval')">Eval       <span class="tab-count" id="cnt-eval">—</span></div>
  <div class="tab"        role="tab" tabindex="0" aria-selected="false" onclick="showTab(this,'monitor')"    onkeydown="tabKey(event,this,'monitor')">Monitor    <span class="tab-count" id="cnt-monitor">—</span></div>
  <div class="tab"        role="tab" tabindex="0" aria-selected="false" onclick="showTab(this,'costs')"      onkeydown="tabKey(event,this,'costs')">Costs      <span class="tab-count" id="cnt-costs">—</span></div>
  <div class="tab"        role="tab" tabindex="0" aria-selected="false" onclick="showTab(this,'review')"     onkeydown="tabKey(event,this,'review')">Review     <span class="tab-count" id="cnt-review">—</span></div>
  <div class="tab"        role="tab" tabindex="0" aria-selected="false" onclick="showTab(this,'compliance')" onkeydown="tabKey(event,this,'compliance')">Compliance <span class="tab-count" id="cnt-compliance">—</span></div>
  <div class="tab"        role="tab" tabindex="0" aria-selected="false" onclick="showTab(this,'git')"        onkeydown="tabKey(event,this,'git')">Git        <span class="tab-count" id="cnt-git">—</span></div>
</div>

<div class="content" id="content" role="tabpanel"></div>

<!-- Detail panel -->
<div class="overlay" id="overlay" onclick="closeDetail()"></div>
<div class="detail-panel" id="detailPanel" role="dialog" aria-label="Scan detail">
  <div class="detail-panel-header">
    <h2 id="detailTitle">Detail</h2>
    <button class="close-btn" onclick="closeDetail()" aria-label="Close">✕</button>
  </div>
  <div class="detail-body" id="detailBody"></div>
</div>

<!-- Toast container -->
<div id="toasts" aria-live="polite"></div>

<!-- Search modal (Cmd+K) -->
<div class="overlay" id="searchOverlay" onclick="closeSearchModal()"></div>
<div class="search-modal" id="searchModal" role="dialog" aria-label="Search">
  <input class="search-modal-input" id="searchModalInput" placeholder="Search scans, functions, models…"
         oninput="runSearchModal(this.value)" autocomplete="off">
  <div class="search-results-wrap" id="searchModalResults"></div>
</div>

<script>
'use strict';

/* ── Config ─────────────────────────────────────────────── */
const ENDPOINTS = {
  security:   '/api/security/reports',
  mcp:        '/api/mcp-scans',
  eval:       '/api/eval/experiments',
  monitor:    '/api/monitor/traces',
  costs:      '/api/costs/summary',
  review:     '/api/review/pending',
  compliance: '/api/compliance/reports',
  git:        '/api/git/history',
};

const EMPTY_STATES = {
  security:   { ei: '🔍', title: 'No scans yet',            desc: 'Run your first red team scan to see results here.',            cmd: 'pyntrace scan myapp:chatbot' },
  mcp:        { ei: '🔌', title: 'No MCP scans',            desc: 'Scan an MCP server for security vulnerabilities.',             cmd: 'pyntrace scan-mcp http://localhost:3000' },
  eval:       { ei: '📊', title: 'No experiments',          desc: 'Run an evaluation experiment to compare model outputs.',       cmd: 'pyntrace eval run experiment.py' },
  monitor:    { ei: '📡', title: 'No traces yet',           desc: 'Initialize pyntrace to start recording production traces.',     cmd: 'import pyntrace; pyntrace.init()' },
  costs:      { ei: '💰', title: 'No cost data',            desc: 'Initialize pyntrace to start tracking LLM API costs.',         cmd: 'import pyntrace; pyntrace.init()' },
  review:     { ei: '✅', title: 'Queue is empty',          desc: 'All annotations are up to date. Nothing to review.',          cmd: null },
  compliance: { ei: '📋', title: 'No compliance reports',   desc: 'Generate a compliance report for your framework.',            cmd: 'pyntrace compliance --framework owasp_llm_top10' },
  git:        { ei: '🔀', title: 'No regression history',   desc: 'Run scans across git commits to detect regressions.',         cmd: null },
};

/* ── State ─────────────────────────────────────────────── */
let _activeTab = 'security';
let _activeEl  = null;
let _chart     = null;
let _sortState = { col: null, dir: 1 };
let _tableData = [];
let _tableEl   = null;
let _allData   = {};   // cache per tab

/* ── Toast ─────────────────────────────────────────────── */
function toast(msg, type) {
  type = type || 'info';
  const icons = { success: '✓', error: '✗', info: 'ⓘ', warning: '⚠' };
  const d = document.createElement('div');
  d.className = 'toast toast-' + type;
  d.innerHTML = '<span>' + (icons[type] || 'ⓘ') + '</span><span>' + escH(msg) + '</span>';
  document.getElementById('toasts').appendChild(d);
  requestAnimationFrame(function() { d.classList.add('show'); });
  setTimeout(function() {
    d.classList.remove('show');
    setTimeout(function() { d.remove(); }, 300);
  }, 3200);
}

/* ── Helpers ────────────────────────────────────────────── */
function escH(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function copyCmd(cmd) {
  navigator.clipboard.writeText(cmd)
    .then(function() { toast('Copied to clipboard', 'success'); })
    .catch(function() { toast('Copy failed', 'error'); });
}

function escCmd(cmd) {
  return String(cmd).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function emptyState(name) {
  const s = EMPTY_STATES[name] || { ei: '📭', title: 'No data yet', desc: '', cmd: null };
  const cmdHtml = s.cmd
    ? '<div class="empty-cmd"><code>' + escH(s.cmd) + '</code>'
      + '<button class="copy-btn" onclick="copyCmd(\\\'' + escCmd(s.cmd) + '\\')">Copy</button></div>'
    : '';
  return '<div class="empty-state"><div class="ei">' + s.ei + '</div>'
    + '<h3>' + escH(s.title) + '</h3><p>' + escH(s.desc) + '</p>' + cmdHtml + '</div>';
}

function skeleton() {
  return '<div class="card skeleton-wrap">'
    + '<div class="skel skel-head w70"></div>'
    + '<div class="skel skel-line w90"></div><div class="skel skel-line w70"></div>'
    + '<div class="skel skel-line w50"></div><div class="skel skel-line w90"></div>'
    + '<div class="skel skel-line w70"></div></div>';
}

/* ── Format helpers ─────────────────────────────────────────── */
function fmt(col, v) {
  if (v === null || v === undefined) return '<span style="color:var(--text-3)">—</span>';
  const s = String(v);
  if (col === 'created_at') return escH(new Date(v * 1000).toLocaleString());
  if (col.includes('rate') && typeof v === 'number') {
    const pct = (v * 100).toFixed(1);
    const icon = v > .15 ? '⚠️' : v > .05 ? '⚡' : '✓';
    const cls  = v > .15 ? 'sev-critical' : v > .05 ? 'sev-high' : 'sev-low';
    return '<span class="sev-label ' + cls + '">' + icon + ' ' + pct + '%</span>';
  }
  if (col.includes('cost') && typeof v === 'number') return '$' + v.toFixed(4);
  if (col.includes('_ms') && typeof v === 'number')  return v.toFixed(0) + 'ms';
  if (col === 'vulnerable_count' && typeof v === 'number') {
    if (v === 0) return '<span class="badge-success">✓ 0</span>';
    if (v <= 2)  return '<span class="badge-warning">⚡ ' + v + ' vulns</span>';
    return '<span class="badge-danger">⚠️ ' + v + ' vulns</span>';
  }
  if (col === 'status') return v === 'pass'
    ? '<span class="badge-success">✓ PASS</span>'
    : '<span class="badge-danger">✗ FAIL</span>';
  return escH(s.length > 60 ? s.slice(0, 57) + '…' : s);
}

/* ── Sortable table ─────────────────────────────────────────── */
function buildTable(rows, cols, labels, onRowClick) {
  _tableData = rows.slice();
  const hdrs = labels || cols;
  let h = '<div class="table-wrap"><table id="mainTable"><thead><tr>';
  hdrs.forEach(function(label, i) {
    const col = cols[i];
    h += '<th onclick="sortBy(\\\'' + col + '\\')" aria-sort="none" data-col="' + col + '">' + escH(label) + '<span class="sort-icon"></span></th>';
  });
  h += '</tr></thead><tbody id="mainTbody">';
  h += rowsHtml(rows, cols, onRowClick);
  h += '</tbody></table></div>';
  return h;
}

function rowsHtml(rows, cols, onRowClick) {
  let h = '';
  rows.forEach(function(row, i) {
    const cb = onRowClick ? 'onclick="rowClick(' + i + ')" title="Click for details"' : '';
    h += '<tr ' + cb + '>' + cols.map(function(c) { return '<td>' + fmt(c, row[c]) + '</td>'; }).join('') + '</tr>';
  });
  return h || '<tr><td colspan="' + cols.length + '" style="text-align:center;color:var(--text-3);padding:24px">No results match your filter</td></tr>';
}

function sortBy(col) {
  if (_sortState.col === col) {
    _sortState.dir *= -1;
  } else {
    _sortState.col = col;
    _sortState.dir = 1;
  }
  const d = _sortState.dir;
  _tableData.sort(function(a, b) {
    const av = a[col], bv = b[col];
    if (av === null || av === undefined) return 1;
    if (bv === null || bv === undefined) return -1;
    if (typeof av === 'number') return (av - bv) * d;
    return String(av).localeCompare(String(bv)) * d;
  });
  // Update sort icons
  document.querySelectorAll('#mainTable th').forEach(function(th) {
    th.classList.remove('sort-asc', 'sort-desc');
    if (th.dataset.col === col) th.classList.add(d === 1 ? 'sort-asc' : 'sort-desc');
  });
  // Determine cols from current render context
  const tbody = document.getElementById('mainTbody');
  if (!tbody) return;
  const cols = Array.from(document.querySelectorAll('#mainTable th')).map(function(th) { return th.dataset.col; });
  tbody.innerHTML = rowsHtml(_tableData, cols, _tableRowClickFn);
}

let _tableRowClickFn = null;

/* ── Filter (search bar) ───────────────────────────────────────── */
function filterTable(q) {
  q = q.toLowerCase().trim();
  const tbody = document.getElementById('mainTbody');
  if (!tbody) return;
  const rows = Array.from(tbody.querySelectorAll('tr'));
  rows.forEach(function(row) {
    const text = row.textContent.toLowerCase();
    row.style.display = (!q || text.includes(q)) ? '' : 'none';
  });
}

/* ── Tab navigation ─────────────────────────────────────────── */
function tabKey(e, el, name) {
  const tabs = Array.from(document.querySelectorAll('.tab'));
  const idx  = tabs.indexOf(el);
  if (e.key === 'ArrowRight' && idx < tabs.length - 1) { e.preventDefault(); tabs[idx + 1].focus(); tabs[idx + 1].click(); }
  if (e.key === 'ArrowLeft'  && idx > 0)              { e.preventDefault(); tabs[idx - 1].focus(); tabs[idx - 1].click(); }
  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); el.click(); }
}

/* ── Tab switching ──────────────────────────────────────────── */
async function showTab(el, name) {
  document.querySelectorAll('.tab').forEach(function(t) {
    t.classList.remove('active');
    t.setAttribute('aria-selected', 'false');
  });
  el.classList.add('active');
  el.setAttribute('aria-selected', 'true');
  _activeTab = name;
  _activeEl  = el;
  _sortState = { col: null, dir: 1 };
  _tableRowClickFn = null;

  const c = document.getElementById('content');
  c.innerHTML = skeleton();
  if (_chart) { _chart.destroy(); _chart = null; }

  // Clear search bar
  const sb = document.getElementById('searchBar');
  if (sb) sb.value = '';

  try {
    const res = await fetch(ENDPOINTS[name]);
    if (!res.ok) throw new Error('HTTP ' + res.status + ' — ' + res.statusText);
    const data = await res.json();
    _allData[name] = data;
    renderTab(name, data);
  } catch(err) {
    c.innerHTML = '<div class="error-state"><div class="error-icon">⚠️</div>'
      + '<p>' + escH(err.message) + '</p>'
      + '<button class="retry-btn" onclick="showTab(_activeEl,_activeTab)">↺ Retry</button></div>';
  }
}

/* ── Detail panel ─────────────────────────────────────────── */
function openDetail(title, bodyHtml) {
  document.getElementById('detailTitle').textContent = title;
  document.getElementById('detailBody').innerHTML = bodyHtml;
  document.getElementById('detailPanel').classList.add('open');
  document.getElementById('overlay').classList.add('open');
}

function closeDetail() {
  document.getElementById('detailPanel').classList.remove('open');
  document.getElementById('overlay').classList.remove('open');
}

function rowClick(i) {
  const row = _tableData[i];
  if (!row) return;
  const title = row.target_fn || row.fn_name || row.name || row.endpoint || ('Item ' + i);
  let body = '<div class="detail-section"><h4>Details</h4>';
  Object.entries(row).forEach(function(kv) {
    const k = kv[0], v = kv[1];
    if (k === 'results_json' || k === 'results') return;
    const label = k.replace(/_/g,' ').replace(/\\b\\w/g, function(c){ return c.toUpperCase(); });
    body += '<div class="detail-kv"><span class="dk">' + escH(label) + '</span><span class="dv">' + fmt(k, v) + '</span></div>';
  });
  body += '</div>';
  // Results breakdown if present
  if (row.results && Array.isArray(row.results) && row.results.length) {
    const vulns  = row.results.filter(function(r) { return r.vulnerable; });
    const passed = row.results.filter(function(r) { return !r.vulnerable; });
    body += '<div class="detail-section"><h4>Results — ' + row.results.length + ' total</h4>';
    if (vulns.length) {
      body += '<div style="margin-bottom:8px;font-size:12px;color:var(--text-2)">⚠️ ' + vulns.length + ' vulnerable:</div>';
      vulns.forEach(function(r) {
        body += '<div class="result-item vuln">'
          + '<div class="ri-header"><span class="badge-danger">' + escH(r.plugin || r.template_name || 'attack') + '</span>'
          + (r.severity ? '<span class="badge-warning">' + escH(r.severity) + '</span>' : '') + '</div>'
          + '<div class="ri-attack">' + escH((r.attack_input || r.attack_payload || '').slice(0,120)) + '</div>'
          + (r.judge_reasoning ? '<div style="font-size:11px;color:var(--text-3);margin-top:4px">' + escH(r.judge_reasoning.slice(0,120)) + '</div>' : '')
          + '</div>';
      });
    }
    if (passed.length) {
      body += '<details style="margin-top:8px">'
        + '<summary class="result-collapse">✓ ' + passed.length + ' passed (click to expand)</summary>'
        + '<div style="margin-top:6px">';
      passed.forEach(function(r) {
        body += '<div class="result-item safe" style="font-size:12px">'
          + escH((r.plugin || '') + ' — ' + (r.attack_input || '').slice(0,80)) + '</div>';
      });
      body += '</div></details>';
    }
    body += '</div>';
  }
  openDetail(title, body);
}

/* ── Chart factory ─────────────────────────────────────────── */
function barChart(id, labels, values, colors, opts) {
  opts = opts || {};
  const ctx = document.getElementById(id);
  if (!ctx) return null;
  const isHoriz = opts.horizontal;
  return new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{ label: opts.label || '', data: values,
        backgroundColor: colors, borderRadius: 5, borderSkipped: false }]
    },
    options: {
      indexAxis: isHoriz ? 'y' : 'x',
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: function(ctx) {
              const v = ctx.parsed[isHoriz ? 'x' : 'y'];
              return opts.tooltipFmt ? opts.tooltipFmt(v) : (opts.label || '') + ' ' + v;
            }
          }
        }
      },
      scales: {
        x: { beginAtZero: true,
             ticks: { color: '#94a3b8', callback: opts.xFmt || undefined },
             grid: { color: '#1e1e3e' } },
        y: { beginAtZero: !isHoriz,
             ticks: { color: '#94a3b8', callback: opts.yFmt || undefined },
             grid: { color: '#1e1e3e' } }
      }
    }
  });
}

/* ── Renderers ────────────────────────────────────────────── */
function renderTab(name, data) {
  const c = document.getElementById('content');

  if (name === 'security') {
    const rows = Array.isArray(data) ? data : [];
    const cntEl = document.getElementById('cnt-security');
    if (cntEl) cntEl.textContent = rows.length;
    if (!rows.length) { c.innerHTML = emptyState(name); return; }

    // Summary stats
    const totalScans    = rows.length;
    const avgVuln       = rows.reduce(function(s, r) { return s + (r.vulnerability_rate || 0); }, 0) / rows.length;
    const totalCost     = rows.reduce(function(s, r) { return s + (r.total_cost_usd || 0); }, 0);
    const criticalScans = rows.filter(function(r) { return (r.vulnerability_rate || 0) > .15; }).length;

    c.innerHTML =
      '<div class="stats-grid">'
      + '<div class="stat-card"><div class="sv sv-accent">' + totalScans + '</div><div class="sl">Total scans</div></div>'
      + '<div class="stat-card"><div class="sv ' + (avgVuln > .15 ? 'sv-danger' : avgVuln > .05 ? 'sv-warning' : 'sv-success') + '">\'
        + (avgVuln * 100).toFixed(1) + '%</div><div class="sl">Avg vuln rate</div></div>'
      + '<div class="stat-card"><div class="sv ' + (criticalScans > 0 ? 'sv-danger' : 'sv-success') + '">' + criticalScans + '</div><div class="sl">⚠️ Critical scans</div></div>'
      + '<div class="stat-card"><div class="sv sv-info">$' + totalCost.toFixed(4) + '</div><div class="sl">Total cost</div></div>'
      + '</div>'
      + '<div class="card"><h3>Vulnerability Rate by Target</h3><div class="chart-wrap"><canvas id="ch"></canvas></div></div>'
      + '<div class="card"><h3>Red Team Reports</h3>'
      + buildTable(rows,
          ['target_fn','model','total_attacks','vulnerable_count','vulnerability_rate','total_cost_usd','created_at'],
          ['Target','Model','Attacks','Vulns','Vuln Rate','Cost','Date'],
          rowClick)
      + '</div>';
    _tableRowClickFn = rowClick;
    const rates = rows.map(function(r) { return +((r.vulnerability_rate || 0) * 100).toFixed(1); });
    _chart = barChart('ch',
      rows.map(function(r) { return r.target_fn || 'unknown'; }),
      rates,
      rates.map(function(r) { return r > 15 ? 'rgba(239,68,68,.85)' : r > 5 ? 'rgba(245,158,11,.85)' : 'rgba(16,185,129,.85)'; }),
      { label: 'Vuln %', yFmt: function(v) { return v + '%'; }, tooltipFmt: function(v) { return v + '%'; } }
    );

  } else if (name === 'mcp') {
    const rows = Array.isArray(data) ? data : [];
    const cntEl = document.getElementById('cnt-mcp');
    if (cntEl) cntEl.textContent = rows.length;
    if (!rows.length) { c.innerHTML = emptyState(name); return; }
    c.innerHTML = '<div class="card"><h3>MCP Security Scans</h3>'
      + buildTable(rows,
          ['endpoint','total_tests','vulnerable_count','created_at'],
          ['Endpoint','Tests','Vulns','Date'], rowClick)
      + '</div>';
    _tableRowClickFn = rowClick;

  } else if (name === 'eval') {
    const rows = Array.isArray(data) ? data : [];
    const cntEl = document.getElementById('cnt-eval');
    if (cntEl) cntEl.textContent = rows.length;
    if (!rows.length) { c.innerHTML = emptyState(name); return; }
    c.innerHTML = '<div class="card"><h3>Experiments</h3>'
      + buildTable(rows,
          ['name','function_name','git_commit','created_at'],
          ['Name','Function','Git Commit','Date'], rowClick)
      + '</div>';
    _tableRowClickFn = rowClick;

  } else if (name === 'monitor') {
    const rows = Array.isArray(data) ? data : [];
    const cntEl = document.getElementById('cnt-monitor');
    if (cntEl) cntEl.textContent = rows.length;
    if (!rows.length) { c.innerHTML = emptyState(name); return; }
    // Calculate duration from start/end time
    const enriched = rows.map(function(r) {
      const dur = (r.end_time && r.start_time) ? ((r.end_time - r.start_time) * 1000).toFixed(0) + 'ms' : '—';
      const err = r.error ? '⚠️ Error' : '✓ OK';
      return Object.assign({}, r, { _dur: dur, _status: err });
    });
    c.innerHTML = '<div class="card"><h3>Production Traces</h3>'
      + buildTable(enriched,
          ['name','_status','_dur','user_id','created_at'],
          ['Trace','Status','Duration','User','Date'], function(i) {
            const row = enriched[i];
            let body = '<div class="detail-section"><h4>Trace Info</h4>';
            ['id','name','user_id','session_id','error'].forEach(function(k) {
              if (row[k]) body += '<div class="detail-kv"><span class="dk">' + k + '</span><span class="dv">' + escH(String(row[k])) + '</span></div>';
            });
            body += '</div>';
            openDetail(row.name || 'Trace', body);
          })
      + '</div>';

  } else if (name === 'costs') {
    const rows = Array.isArray(data) ? data : [];
    const cntEl = document.getElementById('cnt-costs');
    if (cntEl) cntEl.textContent = rows.length + ' models';
    if (!rows.length) { c.innerHTML = emptyState(name); return; }
    const total = rows.reduce(function(s, r) { return s + (r.total_cost || 0); }, 0);
    const maxCost = Math.max.apply(null, rows.map(function(r) { return r.total_cost || 0; }));
    let barsHtml = '<div class="card"><h3>Cost by Model</h3>';
    rows.forEach(function(r) {
      const pct = maxCost > 0 ? ((r.total_cost || 0) / maxCost * 100) : 0;
      const share = total > 0 ? ((r.total_cost || 0) / total * 100).toFixed(0) : 0;
      barsHtml += '<div class="progress-bar-wrap">'
        + '<div class="progress-bar-label" title="' + escH(r.model) + '">' + escH((r.model || '?').slice(0,16)) + '</div>'
        + '<div class="progress-bar-track"><div class="progress-bar-fill" style="width:' + pct + '%;background:var(--accent-dim)"></div></div>'
        + '<div class="progress-bar-val">$' + (r.total_cost || 0).toFixed(4) + ' <span style="color:var(--text-3)">(' + share + '%)</span></div>'
        + '</div>';
    });
    barsHtml += '<div style="margin-top:12px;padding-top:10px;border-top:1px solid var(--border);display:flex;justify-content:space-between;font-size:13px">'
      + '<span style="color:var(--text-2)">Total LLM spend</span>'
      + '<span style="font-weight:700;color:var(--accent)">$' + total.toFixed(4) + '</span></div>';
    barsHtml += '</div>';
    c.innerHTML = barsHtml
      + '<div class="card"><h3>Breakdown</h3>'
      + buildTable(rows, ['model','calls','total_cost','avg_ms'], ['Model','Calls','Total Cost','Avg Latency'])
      + '</div>';

  } else if (name === 'review') {
    const items = Array.isArray(data) ? data : (data.pending || []);
    const cntEl = document.getElementById('cnt-review');
    if (cntEl) cntEl.textContent = items.length;
    if (!items.length) { c.innerHTML = emptyState(name); return; }
    c.innerHTML = '<div class="card"><h3>Annotation Queue</h3>'
      + buildTable(items,
          ['result_id','plugin','severity','label','reviewer','created_at'],
          ['Result ID','Plugin','Severity','Label','Reviewer','Date'])
      + '</div>';

  } else if (name === 'compliance') {
    const items = Array.isArray(data) ? data : [];
    const cntEl = document.getElementById('cnt-compliance');
    if (cntEl) cntEl.textContent = items.length;
    if (!items.length) { c.innerHTML = emptyState(name); return; }
    c.innerHTML = '<div class="card"><h3>Compliance Reports</h3>'
      + buildTable(items,
          ['framework','overall_status','created_at'],
          ['Framework','Status','Date'])
      + '</div>';

  } else if (name === 'git') {
    const rows = Array.isArray(data) ? data : [];
    const cntEl = document.getElementById('cnt-git');
    if (cntEl) cntEl.textContent = rows.length;
    if (!rows.length) { c.innerHTML = emptyState(name); return; }
    c.innerHTML = '<div class="card"><h3>Git Regression History</h3>'
      + buildTable(rows,
          ['git_commit','scans','avg_vuln_rate','total_cost'],
          ['Commit','Scans','Avg Vuln Rate','Total Cost'])
      + '</div>';

  } else {
    c.innerHTML = '<div class="card"><h3>' + escH(name) + '</h3><pre style="font-size:12px;overflow:auto">'
      + escH(JSON.stringify(data, null, 2)) + '</pre></div>';
  }
}

/* ── Global search / Cmd+K ─────────────────────────────────────── */
document.addEventListener('keydown', function(e) {
  if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
    e.preventDefault();
    openSearchModal();
  }
  if (e.key === 'Escape') {
    closeSearchModal();
    closeDetail();
  }
});

function openSearchModal() {
  document.getElementById('searchModal').classList.add('open');
  document.getElementById('searchOverlay').classList.add('open');
  setTimeout(function() { document.getElementById('searchModalInput').focus(); }, 50);
  runSearchModal('');
}

function closeSearchModal() {
  document.getElementById('searchModal').classList.remove('open');
  document.getElementById('searchOverlay').classList.remove('open');
}

function runSearchModal(q) {
  q = q.toLowerCase().trim();
  const wrap = document.getElementById('searchModalResults');
  let results = [];
  Object.entries(_allData).forEach(function(entry) {
    const tabName = entry[0], data = entry[1];
    const rows = Array.isArray(data) ? data : (data.pending || []);
    rows.forEach(function(r) {
      const text = JSON.stringify(r).toLowerCase();
      if (!q || text.includes(q)) {
        const label = r.target_fn || r.fn_name || r.name || r.endpoint || r.framework || r.git_commit || 'Item';
        results.push({ tab: tabName, label: label, meta: tabName, row: r });
      }
    });
  });
  results = results.slice(0, 24);
  if (!results.length) {
    wrap.innerHTML = '<div class="search-empty">' + (q ? 'No results for "' + escH(q) + '"' : 'Start typing to search…') + '</div>';
    return;
  }
  wrap.innerHTML = results.map(function(r) {
    return '<div class="search-result-item" onclick="jumpTo(\\\'' + escH(r.tab) + '\\')">'
      + '<span class="sri-label">' + escH(r.label.slice(0,60)) + '</span>'
      + '<span class="sri-meta">' + escH(r.meta) + '</span></div>';
  }).join('');
}

function jumpTo(tabName) {
  closeSearchModal();
  const tabEl = Array.from(document.querySelectorAll('.tab')).find(function(t) {
    return t.getAttribute('onclick') && t.getAttribute('onclick').includes("'" + tabName + "'");
  });
  if (tabEl) tabEl.click();
}

/* ── WebSocket ────────────────────────────────────────────── */
(function wsConnect() {
  try {
    const ws = new WebSocket('ws://' + location.host + '/ws');
    ws.onmessage = function(e) {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'scan_completed') {
          toast('Scan completed', 'success');
          showTab(_activeEl, _activeTab);
        } else if (msg.type === 'refresh') {
          showTab(_activeEl, _activeTab);
        }
      } catch(_) {}
    };
    ws.onclose = function() { setTimeout(wsConnect, 5000); };
    setInterval(function() { if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'ping' })); }, 30000);
  } catch(_) {}
})();

/* ── Init ──────────────────────────────────────────────── */
(function() {
  const el = document.querySelector('.tab.active');
  _activeEl = el;
  showTab(el, 'security');
})();
</script>
</body>
</html>"""
