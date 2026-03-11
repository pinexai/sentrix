# Attack Heatmap

## Overview

`sentrix.guard.fingerprint()` runs the full attack suite against multiple models simultaneously, producing a vulnerability matrix showing exactly which attacks break which models.

## Usage

```python
import sentrix

fp = sentrix.guard.fingerprint({
    "gpt-4o-mini": gpt_fn,
    "claude-haiku": claude_fn,
    "llama-3": llama_fn,
}, plugins=["jailbreak", "pii", "harmful", "hallucination", "injection"])

fp.heatmap()
```

## Output

```
Attack Heatmap (total cost: $0.0842)

Plugin             │ gpt-4o-mini    │ claude-haiku   │
───────────────────┼────────────────┼────────────────│
jailbreak          │ ████░░░░░░ 40% │ ██░░░░░░░░ 20% │
pii                │ █████░░░░░ 55% │ ████░░░░░░ 35% │
harmful            │ ██░░░░░░░░ 15% │ █░░░░░░░░░ 10% │

Green <20%  Yellow 20-40%  Red >40%
```

## Analysis methods

```python
fp.most_vulnerable_model()   # → "gpt-4o-mini"
fp.safest_model()            # → "claude-haiku"
fp.worst_attack_category("gpt-4o-mini")  # → "pii"
```
