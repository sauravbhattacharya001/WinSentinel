# WinSentinel GitHub Action

Run automated Windows security audits in your CI/CD pipeline. Results upload to GitHub Code Scanning as SARIF.

## Quick Start

```yaml
name: Security Audit
on:
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6 AM UTC
  push:
    branches: [main]

jobs:
  audit:
    runs-on: windows-latest
    steps:
      - uses: sauravbhattacharya001/WinSentinel/action@main
        id: audit
        with:
          fail-on-critical: 'true'

      - name: Comment score
        if: always()
        run: |
          echo "Security Score: ${{ steps.audit.outputs.score }}/100"
          echo "Findings: ${{ steps.audit.outputs.findings-count }} (${{ steps.audit.outputs.critical-count }} critical)"
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `version` | `latest` | WinSentinel CLI version |
| `format` | `sarif` | Output format: sarif, json, csv, text |
| `severity` | `warning` | Minimum severity: info, warning, critical |
| `fail-on-critical` | `true` | Fail workflow on critical findings |
| `upload-sarif` | `true` | Upload to GitHub Code Scanning |
| `modules` | (all) | Comma-separated module list |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Security score 0-100 |
| `findings-count` | Total findings |
| `critical-count` | Critical findings |
| `sarif-file` | Path to SARIF file |
| `json-file` | Path to JSON file |

## Requirements

- **Windows runner** (`runs-on: windows-latest`)
- **.NET SDK** (pre-installed on GitHub-hosted Windows runners)
- **GitHub Advanced Security** (for Code Scanning SARIF upload on private repos)
