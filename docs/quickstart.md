# Quick Start

## Installation

```bash
pip install pyntrace
```

## 1. Initialize pyntrace

```python
import pyntrace
pyntrace.init()  # Enables SQLite persistence and SDK cost tracking
```

## 2. Red team your chatbot

```python
def my_chatbot(prompt: str) -> str:
    """My AI assistant."""
    return call_your_llm(prompt)

report = pyntrace.red_team(
    my_chatbot,
    plugins=["jailbreak", "pii", "harmful"],
    n_attacks=10,
)
report.summary()
```

## 3. Attack heatmap across models

```python
fp = pyntrace.guard.fingerprint({
    "gpt-4o-mini": gpt_fn,
    "claude-haiku": claude_fn,
})
fp.heatmap()
```

## 4. Auto-generate test cases

```python
ds = pyntrace.auto_dataset(my_chatbot, n=20, focus="adversarial")
print(f"Generated {len(ds)} test cases")
```

## 5. Evaluate quality

```python
ds = pyntrace.dataset("qa")
ds.add(input="What is 2+2?", expected_output="4")

exp = pyntrace.experiment("math-test", dataset=ds, fn=my_chatbot,
                          scorers=[pyntrace.scorers.exact_match])
exp.run().summary()
```

## 6. Launch dashboard

```bash
pyntrace serve
# Opens http://localhost:7234
```

## v0.4.0 quick examples

### Benchmark latency (p50/p95/p99)

```python
result = pyntrace.benchmark_latency(my_chatbot, n=100)
print(f"p50={result.p50_ms}ms  p95={result.p95_ms}ms  p99={result.p99_ms}ms")
```

### Scan multi-turn conversations

```python
report = pyntrace.scan_conversation(
    my_chatbot,
    attacks=["jailbreak", "pii"],
    turns=5,
    n_attacks=10,
)
report.summary()
```

### DSL-based webhook alerting

```python
from pyntrace.monitor import AlertManager

alerts = AlertManager(webhook="https://hooks.slack.com/...")
alerts.on("vulnerability_rate > 0.10", severity="high")
alerts.on("cost_usd > 1.00", severity="medium")
alerts.watch(my_chatbot, interval_seconds=300)
```

## CLI quick reference

```bash
pyntrace scan myapp:chatbot                           # Red team
pyntrace scan myapp:chatbot --fast                    # Quick scan (5 attacks per plugin)
pyntrace scan myapp:chatbot --git-compare main        # With regression check
pyntrace fingerprint myapp:gpt_fn myapp:claude_fn     # Attack heatmap
pyntrace auto-dataset myapp:chatbot --n 50            # Generate test cases
pyntrace serve                                        # Dashboard
pyntrace history                                      # Past scans
pyntrace costs --days 7                               # Cost summary
```
