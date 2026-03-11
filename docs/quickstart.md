# Quick Start

## Installation

```bash
pip install sentrix
```

## 1. Initialize sentrix

```python
import sentrix
sentrix.init()  # Enables SQLite persistence and SDK cost tracking
```

## 2. Red team your chatbot

```python
def my_chatbot(prompt: str) -> str:
    """My AI assistant."""
    return call_your_llm(prompt)

report = sentrix.red_team(
    my_chatbot,
    plugins=["jailbreak", "pii", "harmful"],
    n_attacks=10,
)
report.summary()
```

## 3. Attack heatmap across models

```python
fp = sentrix.guard.fingerprint({
    "gpt-4o-mini": gpt_fn,
    "claude-haiku": claude_fn,
})
fp.heatmap()
```

## 4. Auto-generate test cases

```python
ds = sentrix.auto_dataset(my_chatbot, n=20, focus="adversarial")
print(f"Generated {len(ds)} test cases")
```

## 5. Evaluate quality

```python
ds = sentrix.dataset("qa")
ds.add(input="What is 2+2?", expected_output="4")

exp = sentrix.experiment("math-test", dataset=ds, fn=my_chatbot,
                          scorers=[sentrix.scorers.exact_match])
exp.run().summary()
```

## 6. Launch dashboard

```bash
sentrix serve
# Opens http://localhost:7234
```

## CLI quick reference

```bash
sentrix scan myapp:chatbot                           # Red team
sentrix scan myapp:chatbot --git-compare main        # With regression check
sentrix fingerprint myapp:gpt_fn myapp:claude_fn     # Attack heatmap
sentrix auto-dataset myapp:chatbot --n 50            # Generate test cases
sentrix serve                                        # Dashboard
sentrix history                                      # Past scans
sentrix costs --days 7                               # Cost summary
```
