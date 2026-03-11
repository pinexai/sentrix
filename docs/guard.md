# Red Teaming Guide

## Overview

sentrix `red_team()` runs automated adversarial attacks against your LLM functions and scores each response using an LLM judge.

## Basic usage

```python
import sentrix
sentrix.init()

def my_chatbot(prompt: str) -> str:
    return call_llm(prompt)

report = sentrix.red_team(
    my_chatbot,
    plugins=["jailbreak", "pii", "harmful"],
    n_attacks=10,
    judge_model="gpt-4o-mini",
)
report.summary()
```

## Available attack plugins

| Plugin | Category | What it tests |
|---|---|---|
| `jailbreak` | jailbreak | Role-play overrides, DAN variants, persona jailbreaks |
| `pii` | pii | PII extraction, system prompt leakage |
| `harmful` | harmful | Requests for dangerous information |
| `hallucination` | hallucination | False premises, factual traps |
| `injection` | injection | Indirect prompt injection via user-controlled data |
| `competitor` | competitor | Brand manipulation, competitor endorsement |

## CI/CD integration

```yaml
# .github/workflows/security.yml
- run: sentrix scan myapp:chatbot --git-compare origin/main --fail-on-regression
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

## Offline mode

```python
sentrix.init(offline=True, local_judge_model="llama3")
# Uses Ollama for judging — no external API calls
```
