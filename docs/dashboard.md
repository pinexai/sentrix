# Dashboard

## Launch

```bash
pyntrace serve
# Opens http://localhost:7234

pyntrace serve --port 8080 --no-open
```

## Screenshots

### Security tab — vulnerability rate bar chart and scan history

![pyntrace dashboard overview](images/dashboard-overview.png)

### Security tab — detailed findings

![pyntrace dashboard security](images/dashboard-security.png)

### MCP Security Scans tab

![pyntrace dashboard MCP](images/dashboard-mcp.png)

### Eval tab — experiment results and model comparison

![pyntrace dashboard eval](images/dashboard-eval.png)

### Monitor tab — production traces

![pyntrace dashboard monitor](images/dashboard-monitor.png)

### Costs tab — cost by model breakdown

![pyntrace dashboard costs](images/dashboard-costs.png)

### Review tab — annotation queue

![pyntrace dashboard review](images/dashboard-review.png)

### Compliance tab — OWASP/NIST/EU AI Act status

![pyntrace dashboard compliance](images/dashboard-compliance.png)

### Git tab — scan history across branches

![pyntrace dashboard git](images/dashboard-git.png)

---

## Tabs

| Tab | Contents |
|---|---|
| **Security** | Red team reports, vulnerability trends, fingerprint heatmap |
| **MCP** | MCP server scan results, tool chain analysis findings |
| **Eval** | Experiment results, dataset browser, model comparison |
| **Monitor** | Trace list, span tree, drift status |
| **Costs** | Cost per day, per model, cost per vulnerability |
| **Review** | Annotation queue, true/false positive labeling |
| **Compliance** | OWASP/NIST/EU AI Act status, download reports |
| **Git** | Scan history across git commits and branches |
