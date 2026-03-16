# CI/CD Integration

## GitHub Actions

```yaml
# .github/workflows/pyntrace-scan.yml
name: pyntrace Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install pyntrace
      - run: pyntrace scan myapp:chatbot --git-compare origin/main --fail-on-regression
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

### Fast scan for PR checks

Use `--fast` to run a reduced attack set (5 attacks per plugin) for quick feedback on every PR:

```yaml
# .github/workflows/pyntrace-scan.yml
name: pyntrace Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install pyntrace
      - run: pyntrace scan myapp:chatbot --fast --git-compare origin/main --fail-on-regression
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

Run a full scan on merge to main:

```yaml
  full-scan:
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install pyntrace
      - run: pyntrace scan myapp:chatbot --plugins all --n 50
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

## How it works

1. `pyntrace scan` runs the attack suite against your function on the current branch
2. `--git-compare main` loads the stored scan from the `main` branch
3. If vulnerability rate increased by >5%, exit code 1 → PR fails
4. Results are written to `$GITHUB_STEP_SUMMARY` as a markdown table

## Pre-commit hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
pyntrace scan myapp:chatbot --fast --plugins jailbreak
if [ $? -ne 0 ]; then
    echo "pyntrace security check failed"
    exit 1
fi
```
