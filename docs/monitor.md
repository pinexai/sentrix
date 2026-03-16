# Monitoring

## Tracing

```python
import pyntrace

with pyntrace.trace("user-request", input=user_message, user_id="u123") as t:
    with pyntrace.span("llm-call", span_type="llm") as s:
        response = my_chatbot(user_message)
        s.output = response
    t.output = response
```

## Drift detection

```python
detector = pyntrace.DriftDetector(on_drift="warn")
detector.baseline("my-experiment")
report = detector.check(window_hours=24)
report.summary()
```

## Continuous monitoring daemon

```bash
pyntrace monitor watch myapp:chatbot --interval 60 --plugins jailbreak,pii --webhook https://hooks.slack.com/...
```

```python
from pyntrace.monitor.daemon import watch
watch(my_chatbot, interval_seconds=300, plugins=["jailbreak"], alert_webhook="https://...")
```

---

## v0.4.0 — AlertManager

DSL-based webhook alerting with configurable severity thresholds.

```python
from pyntrace.monitor import AlertManager

alerts = AlertManager(webhook="https://hooks.slack.com/services/...")
alerts.on("vulnerability_rate > 0.10", severity="high")
alerts.on("vulnerability_rate > 0.05", severity="medium")
alerts.on("cost_usd > 1.00", severity="medium")
alerts.on("p99_latency_ms > 2000", severity="low")

# Start watching — fires webhook when any condition triggers
alerts.watch(my_chatbot, interval_seconds=300, plugins=["jailbreak", "pii"])
```

Webhook payload follows the standard pyntrace alert schema:

```json
{
  "severity": "high",
  "condition": "vulnerability_rate > 0.10",
  "value": 0.14,
  "scan_id": "scan_abc123",
  "timestamp": "2026-03-15T10:00:00Z"
}
```

---

## v0.4.0 — PrometheusExporter

Zero-dependency Prometheus text format export from the local SQLite store. No external backend required.

```python
from pyntrace.monitor import PrometheusExporter

# Standalone background HTTP server (default port 9090)
exporter = PrometheusExporter(port=9090)
exporter.start()  # serves /metrics in background thread

# Or integrate into an existing FastAPI app
from fastapi import FastAPI
app = FastAPI()
exporter = PrometheusExporter()
exporter.mount(app, path="/metrics")
```

Exported metrics:

| Metric | Type | Description |
|---|---|---|
| `pyntrace_vulnerability_rate` | Gauge | Latest vulnerability rate per plugin |
| `pyntrace_scan_total` | Counter | Total scans run |
| `pyntrace_cost_usd_total` | Counter | Total LLM spend |
| `pyntrace_p99_latency_ms` | Gauge | p99 response latency per function |
| `pyntrace_drift_score` | Gauge | Current drift score vs baseline |

---

## v0.4.0 — benchmark_latency

Profile your LLM function's response latency across a sample of real prompts.

```python
result = pyntrace.benchmark_latency(
    my_chatbot,
    n=100,                    # number of probe calls
    concurrency=5,            # parallel workers
    prompts=my_prompt_list,   # optional — uses built-in diverse prompts if omitted
)

print(f"p50  = {result.p50_ms:.0f}ms")
print(f"p95  = {result.p95_ms:.0f}ms")
print(f"p99  = {result.p99_ms:.0f}ms")
print(f"mean = {result.mean_ms:.0f}ms")
result.histogram()  # ASCII bar chart of latency distribution
```

CLI:

```bash
pyntrace benchmark myapp:chatbot --n 100 --concurrency 5
```

---

## v0.4.0 — scan_conversation

Multi-turn attack scanner. Tests whether safety guardrails hold across a full conversation, not just a single prompt.

```python
report = pyntrace.scan_conversation(
    my_chatbot,
    attacks=["jailbreak", "pii", "harmful"],
    turns=5,          # conversation depth
    n_attacks=10,
)
report.summary()
# jailbreak  multi-turn  8/10 vulnerable  (vs 2/10 single-turn)
```

CLI:

```bash
pyntrace scan-conversation myapp:chatbot --attacks jailbreak,pii --turns 5 --n 10
```
