# Evaluation

## Datasets

```python
ds = pyntrace.dataset("my-qa")
ds.add(input="What is 2+2?", expected_output="4")
ds.add(input="Capital of France?", expected_output="Paris")
```

## Scorers

```python
from pyntrace import scorers

scorers.exact_match           # 1.0 if exact match
scorers.contains              # 1.0 if expected in output
scorers.levenshtein_sim       # Normalized edit distance similarity
scorers.no_pii                # 1.0 if no PII detected
scorers.regex_match(r"\d+")   # Match regex pattern
scorers.llm_judge(criteria="accuracy and helpfulness")
scorers.json_schema_valid(schema)
```

## Experiments

```python
exp = pyntrace.experiment(
    "my-eval",
    dataset=ds,
    fn=my_chatbot,
    scorers=[scorers.exact_match, scorers.no_pii],
)
results = exp.run(pass_threshold=0.7)
results.summary()
```

## Model comparison

```python
comparison = pyntrace.compare_models(
    prompt="Explain quantum computing in one sentence.",
    models={
        "gpt-4o-mini": gpt_fn,
        "claude-haiku": claude_fn,
    },
    scorers=[scorers.llm_judge()],
)
comparison.summary()
# Shows Pareto frontier and best value model
```
