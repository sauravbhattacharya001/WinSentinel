# WinSentinel GitHub Action

Run automated Windows security audits in your CI/CD pipeline. Results upload directly to GitHub Code Scanning.

## Usage

```yaml
name: Security Audit
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 6 * * 1' # Weekly Monday 6am

jobs:
  winsentinel:
    runs-on: windows-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: sauravbhattacharya001/WinSentinel/action@main
        with:
          fail-on-score-below: 60
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `version` | WinSentinel CLI version | `latest` |
| `profile` | Audit profile (`all`, `cis-l1`, `essential8`, etc.) | `all` |
| `fail-on-score-below` | Fail if score < threshold (0 = never) | `0` |
| `upload-sarif` | Upload to Code Scanning | `true` |
| `output-format` | Output: `sarif`, `json`, `csv` | `sarif` |
| `additional-args` | Extra CLI arguments | |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Security score (0-100) |
| `grade` | Letter grade (A-F) |
| `findings-count` | Total findings |
| `sarif-file` | Path to SARIF file |

## Examples

### Fail PR if score drops below 70

```yaml
- uses: sauravbhattacharya001/WinSentinel/action@main
  with:
    fail-on-score-below: 70
```

### Run specific compliance profile

```yaml
- uses: sauravbhattacharya001/WinSentinel/action@main
  with:
    profile: cis-l1
```

### Use score in subsequent steps

```yaml
- uses: sauravbhattacharya001/WinSentinel/action@main
  id: audit
- run: echo "Score is ${{ steps.audit.outputs.score }}"
```

## Requirements

- **Windows runner** (`runs-on: windows-latest`)
- **.NET 8 SDK** (pre-installed on `windows-latest`)
- **`security-events: write`** permission (for SARIF upload)

## What gets audited

WinSentinel checks 30+ security categories on the runner including:
- Windows Defender configuration
- Firewall rules and network posture
- Account security and credential exposure
- Encryption (BitLocker, TPM)
- PowerShell security settings
- Browser security configuration
- Application update posture
- Event log analysis
- And more...

Results appear in your repository's **Security → Code scanning alerts** tab.
