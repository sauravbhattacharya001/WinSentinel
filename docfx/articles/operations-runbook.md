# Security Operations Runbook

Practical day-to-day procedures for security teams operating WinSentinel across fleets of Windows endpoints. This guide covers common operational scenarios, incident response workflows, scheduled maintenance, and escalation procedures.

---

## Daily Operations

### Morning Security Check

Run a quick posture assessment across managed endpoints:

```powershell
# Quick score check (exits 1 if below threshold)
winsentinel --score --threshold 70

# Vitals: key health indicators at a glance
winsentinel --vitals

# Check for overnight anomalies
winsentinel --watchdog --days 1
```

### Reviewing New Findings

After a scheduled or ad-hoc audit, triage new findings:

```powershell
# Show only new findings since last audit
winsentinel --age new

# Prioritize by risk: severity × age × exposure
winsentinel --rootcause priority

# Correlate findings to identify systemic patterns
winsentinel --correlate
```

### Score Monitoring

Track posture trends and detect regressions:

```powershell
# Trend analysis (last 7 days)
winsentinel --trend --trend-days 7

# Alert on score drops below threshold
winsentinel --trend --alert-below 75

# Per-module breakdown to pinpoint degradation source
winsentinel --trend --trend-modules
```

---

## Incident Response Procedures

### 1. Triage: Assess Scope

When a security event is detected or reported:

```powershell
# Full audit to establish current state
winsentinel --audit --json --output incident-baseline.json

# Attack path analysis: what's reachable?
winsentinel --attack-paths

# Attack surface enumeration
winsentinel --attack-surface

# Topology: visualize service relationships and exposure
winsentinel --topology
```

### 2. Investigation: Gather Evidence

```powershell
# Security autopsy: deep forensic analysis
winsentinel --autopsy

# Beacon detection: check for C2 indicators
winsentinel --beacon

# Threat hunt: look for indicators of compromise
winsentinel --hunt

# Flight recorder: replay recent security state changes
winsentinel --flight-recorder --days 7
```

### 3. Containment: Reduce Attack Surface

```powershell
# War-game simulation: model containment options
winsentinel --wargame

# What-if analysis: predict impact of mitigations
winsentinel --whatif all

# Harden aggressively (review each change)
winsentinel --harden

# Automated hardening (non-interactive for known-safe fixes)
winsentinel --fix-all --dry-run   # Preview first
winsentinel --fix-all             # Apply
```

### 4. Recovery: Verify and Document

```powershell
# Verify fixes took effect
winsentinel --audit --compare

# Generate incident report
winsentinel --audit --html --html-title "Post-Incident Report" --output report.html

# Save as new baseline
winsentinel --baseline save --force

# Update security changelog
winsentinel --changelog
```

---

## Scheduled Maintenance

### Weekly Tasks

| Task | Command | Purpose |
|------|---------|---------|
| Full audit | `winsentinel --audit` | Comprehensive posture assessment |
| Compliance check | `winsentinel --audit --profile cis` | CIS benchmark compliance |
| Noise analysis | `winsentinel --noise` | Identify false positives for ignore rules |
| Exemption review | `winsentinel --exemptions review` | Verify exemptions are still valid |
| Regression check | `winsentinel --regression` | Detect score regressions |

### Monthly Tasks

| Task | Command | Purpose |
|------|---------|---------|
| Maturity assessment | `winsentinel --maturity` | Track security program maturity |
| Coverage analysis | `winsentinel --coverage` | Identify blind spots |
| Forecast | `winsentinel --forecast` | Predict future posture based on trends |
| Burndown | `winsentinel --burndown` | Track finding remediation velocity |
| Report card | `winsentinel --report-card` | Executive summary for stakeholders |

### Quarterly Tasks

| Task | Command | Purpose |
|------|---------|---------|
| Full threat model | `winsentinel --threats` | Update threat landscape |
| War game exercise | `winsentinel --wargame` | Test detection and response |
| Policy review | `winsentinel --policy export` | Audit and update policies |
| Benchmark | `winsentinel --benchmark` | Compare against peer baselines |
| Schedule optimize | `winsentinel --schedule-optimize` | Tune audit frequency/timing |

---

## Compliance Workflows

### Pre-Audit Preparation (External Audit)

```powershell
# Run against the relevant compliance profile
winsentinel --audit --profile soc2 --json --output pre-audit.json

# Generate evidence package
winsentinel --audit --profile soc2 --sarif --output evidence.sarif
winsentinel --audit --profile soc2 --html --output evidence-report.html

# Export current policy and baseline
winsentinel --policy export --output current-policy.json
winsentinel --baseline save

# Document exemptions with justification
winsentinel --exemptions summary
```

### Continuous Compliance Monitoring

```powershell
# CI integration (fail build if compliance drops)
winsentinel --audit --profile pci-dss --threshold 85 --quiet

# Track compliance trend
winsentinel --compliance-trend --profile hipaa --days 90

# Drift detection: alert on policy/config changes
winsentinel --drift
```

---

## Fleet Management

### Multi-Endpoint Coordination

For environments with the WinSentinel Agent running on multiple endpoints:

```powershell
# Swarm intelligence: aggregate findings across fleet
winsentinel --swarm

# Radar: real-time fleet-wide security view
winsentinel --radar

# Nerve center: centralized alerting status
winsentinel --nerve
```

### Agent Health Monitoring

```powershell
# Check agent service status
winsentinel --pulse

# Verify IPC connectivity to agent
winsentinel --status

# Review agent audit schedule
winsentinel --calendar
```

---

## Alert Management

### Configuring Alert Rules

WinSentinel's alert rule engine triggers notifications when conditions are met:

```powershell
# View current alert configuration
winsentinel --vitals

# Threshold-based alerting (in CI/CD)
winsentinel --score --threshold 60
# Exit code 1 = score below threshold
```

### Responding to Alerts

| Alert Type | First Response | Investigation | Resolution |
|-----------|---------------|---------------|------------|
| Score drop | `--trend --days 3` | `--diff` | `--rootcause report` |
| New critical finding | `--age new` | `--attack-paths` | `--harden` |
| Anomaly detected | `--watchdog` | `--autopsy` | `--hunt` |
| Compliance drift | `--drift` | `--policy diff` | `--baseline check` |
| Regression | `--regression` | `--history` | `--replay` |

---

## Escalation Matrix

| Severity | Condition | Action | Timeframe |
|----------|-----------|--------|-----------|
| **Critical** | Score < 40 or active compromise indicators | Immediate incident response | < 1 hour |
| **High** | Score drop > 20 points in 24h | Investigate root cause, begin remediation | < 4 hours |
| **Medium** | New high-severity findings | Schedule remediation, assess risk | < 1 business day |
| **Low** | Minor findings, info-level alerts | Add to backlog, review in next cycle | Next scheduled review |

---

## Integration Patterns

### CI/CD Pipeline Integration

```yaml
# GitHub Actions example
- name: Security Gate
  run: |
    winsentinel --audit --profile enterprise --threshold 75 --quiet --json --output audit.json
    winsentinel --audit --sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Scheduled Automation (Windows Task Scheduler)

```powershell
# Register a daily audit at 6 AM
$action = New-ScheduledTaskAction -Execute "winsentinel" -Argument "--audit --json --output C:\Reports\daily-audit.json"
$trigger = New-ScheduledTaskTrigger -Daily -At 6:00AM
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "WinSentinel Daily Audit" -RunLevel Highest
```

### SIEM Integration

Export findings in SARIF or JSON for ingestion by SIEM tools:

```powershell
# SARIF for Azure Sentinel, Splunk, etc.
winsentinel --audit --sarif --output \\share\security\findings.sarif

# JSON for custom pipelines
winsentinel --audit --json --output \\share\security\audit.json
```

---

## Troubleshooting Operations Issues

| Symptom | Likely Cause | Resolution |
|---------|-------------|------------|
| Audit hangs on specific module | Module timeout or permission issue | Run with `--modules` to isolate; check admin privileges |
| Score fluctuates between runs | Transient findings (service states, network) | Use `--noise` to identify; add stable ignore rules |
| Agent not reporting | IPC pipe disconnection | Restart WinSentinel.Service; check `--pulse` |
| Compliance profile mismatch | Outdated profile definitions | Pull latest release; `--profile` auto-updates |
| Large finding count with low signal | Missing ignore/exemption rules | Run `--noise` and `--exemptions stale`; prune |

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│  WinSentinel Operations Quick Reference                     │
├─────────────────────────────────────────────────────────────┤
│  ASSESS    --score  --vitals  --status  --maturity          │
│  AUDIT     --audit  --modules  --profile  --threshold       │
│  RESPOND   --autopsy  --hunt  --beacon  --attack-paths      │
│  REMEDIATE --harden  --fix-all  --whatif  --wargame          │
│  MONITOR   --trend  --watchdog  --drift  --regression       │
│  REPORT    --html  --json  --sarif  --badge  --report-card  │
│  COMPLY    --profile  --baseline  --policy  --exemptions    │
│  FLEET     --swarm  --radar  --nerve  --pulse               │
└─────────────────────────────────────────────────────────────┘
```
