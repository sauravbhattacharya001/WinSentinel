# Enterprise Deployment Guide

This guide covers deploying WinSentinel across an enterprise fleet — from pilot rollout to centralized monitoring of thousands of endpoints.

## Deployment Architecture

```
┌─────────────────────────────────────────────┐
│            Central Dashboard                │
│   (Aggregated scores, fleet-wide alerts)    │
└────────────────┬────────────────────────────┘
                 │  JSON reports / file share
    ┌────────────┼────────────────┐
    │            │                │
┌───▼───┐   ┌───▼───┐       ┌───▼───┐
│ Win10 │   │ Win11 │  ...  │ Win11 │
│ Agent │   │ Agent │       │ Agent │
└───────┘   └───────┘       └───────┘
```

## Prerequisites

| Requirement | Details |
|-------------|---------|
| **OS** | Windows 10 1809+ or Windows 11 (x64) |
| **.NET Runtime** | .NET 8.0 Runtime (included in installer) |
| **Privileges** | Local Administrator for installation; SYSTEM for service operation |
| **Network** | Outbound HTTPS for update checks (optional); SMB/file share for report aggregation |
| **Disk** | ~50 MB installed; ~100 MB for logs and reports |

## Phase 1: Pilot Deployment

Start with 5–10 representative machines spanning different hardware profiles and user roles.

### Silent Installation

Use the installer script with the `-Silent` flag:

```powershell
# Download and install silently with Enterprise compliance profile
.\Install-WinSentinel.ps1 -Silent -ComplianceProfile enterprise
```

Or build an MSI/ZIP from source for distribution:

```powershell
dotnet publish src/WinSentinel.Agent -c Release -r win-x64 --self-contained -o .\dist\agent
dotnet publish src/WinSentinel.Cli -c Release -r win-x64 --self-contained -o .\dist\cli
```

### Verify Installation

```powershell
# Check service status
Get-Service WinSentinel

# Run a quick audit
winsentinel audit --profile enterprise --format json --output C:\ProgramData\WinSentinel\reports\
```

## Phase 2: Configuration Management

### Group Policy Distribution

Create a GPO to deploy WinSentinel configuration:

1. **Computer Configuration → Preferences → Files**
   - Source: `\\fileserver\WinSentinel\config\appsettings.json`
   - Destination: `C:\ProgramData\WinSentinel\appsettings.json`
   - Action: Replace

2. **Computer Configuration → Preferences → Scheduled Tasks**
   - Create a scheduled task to run `winsentinel audit --profile enterprise` daily

### Recommended Enterprise Configuration

```json
{
  "WinSentinel": {
    "ComplianceProfile": "enterprise",
    "Agent": {
      "Enabled": true,
      "MonitoringInterval": 300,
      "AutoRemediation": false,
      "RemediationRequiresApproval": true
    },
    "Reporting": {
      "OutputDirectory": "C:\\ProgramData\\WinSentinel\\reports",
      "Format": "json",
      "RetentionDays": 90,
      "NetworkShare": "\\\\fileserver\\WinSentinel\\reports\\%COMPUTERNAME%"
    },
    "Alerting": {
      "CriticalFindingsThreshold": 1,
      "ScoreDropThreshold": 15,
      "NotifyOnRemediation": true
    },
    "Modules": {
      "DisabledModules": [],
      "CustomWeights": {
        "Encryption": 1.5,
        "EventLog": 1.2,
        "Network": 1.3
      }
    }
  }
}
```

> **Security note:** Set `AutoRemediation` to `false` initially and require approval.  Enable auto-remediation only after validating behavior in your environment.

### Microsoft Intune / SCCM Deployment

**Intune (Win32 app):**

1. Package the installer as an `.intunewin` file using the [Win32 Content Prep Tool](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool)
2. Install command: `powershell.exe -ExecutionPolicy Bypass -File Install-WinSentinel.ps1 -Silent`
3. Uninstall command: `powershell.exe -ExecutionPolicy Bypass -File Install-WinSentinel.ps1 -Uninstall`
4. Detection rule: File exists `C:\Program Files\WinSentinel\WinSentinel.Agent.exe`

**SCCM:**

1. Create a package with the WinSentinel distribution files
2. Program command line: `powershell.exe -ExecutionPolicy Bypass -File Install-WinSentinel.ps1 -Silent`
3. Deploy to a device collection with required purpose

## Phase 3: Centralized Reporting

### Report Aggregation

Configure each endpoint to write JSON reports to a central file share:

```powershell
# On each endpoint (via GPO scheduled task)
winsentinel audit --profile enterprise --format json `
  --output "\\fileserver\WinSentinel\reports\$env:COMPUTERNAME\$(Get-Date -Format yyyy-MM-dd).json"
```

### Aggregation Script

Collect and summarize fleet-wide security posture:

```powershell
# aggregate-reports.ps1 — Run on the reporting server
$reportRoot = "\\fileserver\WinSentinel\reports"
$machines = Get-ChildItem $reportRoot -Directory

$summary = foreach ($machine in $machines) {
    $latest = Get-ChildItem $machine.FullName -Filter "*.json" |
              Sort-Object LastWriteTime -Descending |
              Select-Object -First 1

    if ($latest) {
        $report = Get-Content $latest.FullName | ConvertFrom-Json
        [PSCustomObject]@{
            Machine      = $machine.Name
            Score        = $report.Score
            Grade        = $report.Grade
            Critical     = ($report.Findings | Where-Object Severity -eq "Critical").Count
            High         = ($report.Findings | Where-Object Severity -eq "High").Count
            LastAudit    = $latest.LastWriteTime
            Compliant    = $report.Score -ge $report.ComplianceThreshold
        }
    }
}

# Output fleet summary
$summary | Sort-Object Score | Format-Table -AutoSize

# Highlight non-compliant machines
$nonCompliant = $summary | Where-Object { -not $_.Compliant }
if ($nonCompliant) {
    Write-Warning "$($nonCompliant.Count) machines are non-compliant:"
    $nonCompliant | Format-Table Machine, Score, Critical, High -AutoSize
}
```

### Dashboard Integration

Export aggregated data for SIEM or dashboard consumption:

- **Splunk:** Forward JSON reports via Splunk Universal Forwarder
- **Elastic/ELK:** Use Filebeat to ingest JSON reports
- **Power BI:** Point at the file share for fleet-wide compliance dashboards
- **Azure Sentinel:** Use Azure Monitor Agent to collect WinSentinel Event Log entries

## Phase 4: Ongoing Operations

### Compliance Monitoring Cadence

| Check | Frequency | Method |
|-------|-----------|--------|
| Full audit | Daily | Scheduled task |
| Agent health | Hourly | Service status check |
| Report aggregation | Daily | Aggregation script |
| Compliance review | Weekly | Dashboard review |
| Profile tuning | Monthly | Review findings trends |

### Handling Findings at Scale

**Prioritization matrix:**

1. **Critical findings on >10% of fleet** → Immediate GPO remediation
2. **Critical on individual machines** → Targeted fix within 24h
3. **High findings** → Address within 1 week
4. **Medium/Low** → Batch during maintenance windows

### Updating WinSentinel

```powershell
# Distribute update via GPO or SCCM
# 1. Stage new version on file share
# 2. Stop service, replace binaries, start service
Stop-Service WinSentinel
Copy-Item "\\fileserver\WinSentinel\dist\*" "C:\Program Files\WinSentinel\" -Recurse -Force
Start-Service WinSentinel
```

## Compliance Profile Selection

Choose the right profile for your regulatory environment:

| Profile | Use Case | Threshold |
|---------|----------|-----------|
| `enterprise` | General corporate endpoints | 75 |
| `hipaa` | Healthcare / PHI handling | 85 |
| `pci-dss` | Payment card processing | 90 |
| `cis-l1` | CIS Benchmark Level 1 compliance | 80 |

See [Compliance Profiles](compliance-profiles.md) for detailed weight and severity adjustments.

## Troubleshooting

- **Service won't start:** Check Event Log → Application for .NET runtime errors. Ensure .NET 8.0 is installed.
- **Reports not appearing on share:** Verify SMB permissions. The SYSTEM account needs write access.
- **High CPU during audit:** Normal for the first run. Subsequent runs use caching. Adjust `MonitoringInterval` if needed.
- **Score discrepancies between machines:** Verify all machines use the same compliance profile version.

See [Troubleshooting](troubleshooting.md) for more.
