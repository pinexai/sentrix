"""sentrix FastAPI dashboard — 7-tab real-time monitoring UI."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False

STATIC_DIR = Path(__file__).parent / "static"


def create_app(db_path: str | None = None) -> "FastAPI":
    if not _HAS_FASTAPI:
        raise ImportError("pip install sentrix[server]")

    from sentrix.db import init_db, _q
    init_db(db_path)

    app = FastAPI(title="sentrix Dashboard", version="0.1.0")

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
        return HTMLResponse(_FALLBACK_HTML)

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

    # API: Security tab
    @app.get("/api/security/reports")
    async def get_security_reports(limit: int = 20):
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
        rows = _q("SELECT id, models_json, plugins_json, total_cost_usd, created_at FROM fingerprints ORDER BY created_at DESC LIMIT ?", (limit,), db_path)
        for r in rows:
            r["models"] = json.loads(r["models_json"]) if r.get("models_json") else []
            r["plugins"] = json.loads(r["plugins_json"]) if r.get("plugins_json") else []
        return JSONResponse(rows)

    # API: Eval tab
    @app.get("/api/eval/experiments")
    async def get_experiments(limit: int = 20):
        rows = _q("SELECT * FROM experiments ORDER BY created_at DESC LIMIT ?", (limit,), db_path)
        return JSONResponse(rows)

    @app.get("/api/eval/datasets")
    async def get_datasets():
        rows = _q("SELECT d.id, d.name, d.description, d.created_at, COUNT(di.id) as item_count FROM datasets d LEFT JOIN dataset_items di ON d.id = di.dataset_id GROUP BY d.id ORDER BY d.created_at DESC", db_path=db_path)
        return JSONResponse(rows)

    # API: Monitor tab
    @app.get("/api/monitor/traces")
    async def get_traces(limit: int = 50):
        rows = _q("SELECT id, name, start_time, end_time, user_id, tags, error FROM traces ORDER BY start_time DESC LIMIT ?", (limit,), db_path)
        return JSONResponse(rows)

    @app.get("/api/monitor/traces/{trace_id}/spans")
    async def get_spans(trace_id: str):
        rows = _q("SELECT * FROM spans WHERE trace_id = ? ORDER BY start_time", (trace_id,), db_path)
        return JSONResponse(rows)

    @app.get("/api/monitor/drift")
    async def get_drift(limit: int = 10):
        rows = _q("SELECT * FROM drift_reports ORDER BY created_at DESC LIMIT ?", (limit,), db_path)
        return JSONResponse(rows)

    # API: Costs tab
    @app.get("/api/costs/summary")
    async def get_costs_summary(days: int = 7):
        cutoff = time.time() - days * 86400
        rows = _q(
            "SELECT model, SUM(cost_usd) as total_cost, COUNT(*) as calls, AVG(duration_ms) as avg_ms FROM llm_calls WHERE timestamp > ? GROUP BY model ORDER BY total_cost DESC",
            (cutoff,), db_path
        )
        return JSONResponse(rows)

    @app.get("/api/costs/daily")
    async def get_daily_costs(days: int = 30):
        cutoff = time.time() - days * 86400
        rows = _q(
            "SELECT DATE(timestamp, 'unixepoch') as date, SUM(cost_usd) as cost, COUNT(*) as calls FROM llm_calls WHERE timestamp > ? GROUP BY date ORDER BY date",
            (cutoff,), db_path
        )
        return JSONResponse(rows)

    # API: Review tab
    @app.get("/api/review/pending")
    async def get_pending_reviews():
        from sentrix.review.annotations import ReviewQueue
        q = ReviewQueue(db_path)
        return JSONResponse(q.pending())

    @app.post("/api/review/annotate")
    async def create_annotation(body: dict):
        from sentrix.review.annotations import annotate
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
        from sentrix.compliance import generate_report
        report = generate_report(framework=body.get("framework", "owasp_llm_top10"))
        return JSONResponse(report.to_json())

    # API: Git tab
    @app.get("/api/git/history")
    async def get_git_history():
        rows = _q("SELECT git_commit, COUNT(*) as scans, AVG(vulnerability_rate) as avg_vuln_rate, SUM(total_cost_usd) as total_cost FROM red_team_reports WHERE git_commit IS NOT NULL GROUP BY git_commit ORDER BY MAX(created_at) DESC LIMIT 20", db_path=db_path)
        return JSONResponse(rows)

    return app


def run(port: int = 7234, db_path: str | None = None, no_open: bool = False) -> None:
    """Start the sentrix dashboard server."""
    try:
        import uvicorn
    except ImportError:
        raise ImportError("pip install sentrix[server]")

    app = create_app(db_path)

    if not no_open:
        import threading
        def _open_browser():
            import time, webbrowser
            time.sleep(1.5)
            webbrowser.open(f"http://localhost:{port}")
        threading.Thread(target=_open_browser, daemon=True).start()

    print(f"[sentrix] Dashboard running at http://localhost:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")


_FALLBACK_HTML = """<!DOCTYPE html>
<html>
<head>
<title>sentrix Dashboard</title>
<meta charset="utf-8">
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f0f1a; color: #e0e0ff; min-height: 100vh; }
.header { background: linear-gradient(135deg, #4a0080, #6a00c0); padding: 16px 24px; display: flex; align-items: center; gap: 12px; }
.header h1 { font-size: 22px; font-weight: 700; letter-spacing: -0.5px; }
.header .badge { background: rgba(255,255,255,0.2); padding: 2px 8px; border-radius: 12px; font-size: 12px; }
.tabs { display: flex; background: #1a1a2e; border-bottom: 1px solid #2a2a4e; padding: 0 24px; }
.tab { padding: 12px 20px; cursor: pointer; border-bottom: 2px solid transparent; color: #8888aa; font-size: 14px; transition: all 0.2s; }
.tab.active { color: #c084fc; border-bottom-color: #c084fc; }
.content { padding: 24px; }
.card { background: #1a1a2e; border: 1px solid #2a2a4e; border-radius: 8px; padding: 20px; margin-bottom: 16px; }
.card h3 { color: #c084fc; margin-bottom: 12px; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px; }
.stat { display: inline-block; margin-right: 32px; }
.stat .value { font-size: 32px; font-weight: 700; color: #e0e0ff; }
.stat .label { font-size: 12px; color: #8888aa; margin-top: 4px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; padding: 8px 12px; color: #8888aa; font-weight: 500; border-bottom: 1px solid #2a2a4e; }
td { padding: 10px 12px; border-bottom: 1px solid #1e1e3e; }
tr:hover td { background: #1e1e3e; }
.badge-red { background: #3d0015; color: #ff6b9d; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
.badge-green { background: #003d1a; color: #4ade80; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
.badge-yellow { background: #3d2d00; color: #fbbf24; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
.empty { text-align: center; padding: 48px; color: #5555aa; }
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>sentrix <span class="badge">v0.1.0</span></h1>
  </div>
</div>
<div class="tabs">
  <div class="tab active" onclick="showTab('security')">Security</div>
  <div class="tab" onclick="showTab('eval')">Eval</div>
  <div class="tab" onclick="showTab('monitor')">Monitor</div>
  <div class="tab" onclick="showTab('costs')">Costs</div>
  <div class="tab" onclick="showTab('review')">Review</div>
  <div class="tab" onclick="showTab('compliance')">Compliance</div>
  <div class="tab" onclick="showTab('git')">Git</div>
</div>
<div class="content" id="content">Loading...</div>

<script>
const tabs = {
  security: '/api/security/reports',
  eval: '/api/eval/experiments',
  monitor: '/api/monitor/traces',
  costs: '/api/costs/summary',
  review: '/api/review/pending',
  compliance: '/api/compliance/reports',
  git: '/api/git/history',
};

async function showTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  event.target.classList.add('active');
  const res = await fetch(tabs[name]);
  const data = await res.json();
  renderTab(name, data);
}

function renderTab(name, data) {
  const c = document.getElementById('content');
  if (!data || data.length === 0) {
    c.innerHTML = '<div class="empty">No data yet. Run <code>sentrix scan</code> to get started.</div>';
    return;
  }
  if (name === 'security') {
    c.innerHTML = '<div class="card"><h3>Red Team Reports</h3>' + table(data, ['target_fn','model','total_attacks','vulnerable_count','vulnerability_rate','total_cost_usd','created_at']) + '</div>';
  } else if (name === 'costs') {
    c.innerHTML = '<div class="card"><h3>Cost by Model</h3>' + table(data, ['model','calls','total_cost','avg_ms']) + '</div>';
  } else {
    c.innerHTML = '<div class="card"><h3>' + name + '</h3><pre>' + JSON.stringify(data, null, 2) + '</pre></div>';
  }
}

function table(rows, cols) {
  if (!rows.length) return '<div class="empty">No data</div>';
  let h = '<table><tr>' + cols.map(c => '<th>' + c + '</th>').join('') + '</tr>';
  for (const row of rows) {
    h += '<tr>' + cols.map(c => {
      let v = row[c];
      if (typeof v === 'number' && c.includes('rate')) v = (v*100).toFixed(1)+'%';
      if (typeof v === 'number' && c.includes('cost')) v = '$'+v.toFixed(4);
      if (c === 'created_at' && v) v = new Date(v*1000).toLocaleDateString();
      return '<td>' + (v !== null && v !== undefined ? v : '-') + '</td>';
    }).join('') + '</tr>';
  }
  return h + '</table>';
}

showTab('security');
</script>
</body>
</html>"""
