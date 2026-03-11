# CI/CD Integration

## GitHub Actions

```yaml
# .github/workflows/sentrix-scan.yml
name: sentrix Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install sentrix
      - run: sentrix scan myapp:chatbot --git-compare origin/main --fail-on-regression
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

## How it works

1. `sentrix scan` runs the attack suite against your function on the current branch
2. `--git-compare main` loads the stored scan from the `main` branch
3. If vulnerability rate increased by >5%, exit code 1 → PR fails
4. Results are written to `$GITHUB_STEP_SUMMARY` as a markdown table

## Pre-commit hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
sentrix scan myapp:chatbot --n 5 --plugins jailbreak
if [ $? -ne 0 ]; then
    echo "sentrix security check failed"
    exit 1
fi
```
