# Monitoring

## Tracing

```python
import sentrix

with sentrix.trace("user-request", input=user_message, user_id="u123") as t:
    with sentrix.span("llm-call", span_type="llm") as s:
        response = my_chatbot(user_message)
        s.output = response
    t.output = response
```

## Drift detection

```python
detector = sentrix.DriftDetector(on_drift="warn")
detector.baseline("my-experiment")
report = detector.check(window_hours=24)
report.summary()
```

## Continuous monitoring daemon

```bash
sentrix monitor watch myapp:chatbot --interval 60 --plugins jailbreak,pii --webhook https://hooks.slack.com/...
```

```python
from sentrix.monitor.daemon import watch
watch(my_chatbot, interval_seconds=300, plugins=["jailbreak"], alert_webhook="https://...")
```
