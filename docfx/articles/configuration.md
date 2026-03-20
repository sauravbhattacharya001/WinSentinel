# Configuration Reference

WinSentinel uses `appsettings.json` for agent/service configuration and CLI flags for one-off runs. This guide covers all configuration options.

## Agent Configuration

The WinSentinel Agent reads `appsettings.json` from its installation directory. Here's a complete reference:

```json
{
  "WinSentinel": {
    "ScanIntervalMinutes": 60,
    "DefaultProfile": "developer",
    "AutoRemediate": false,
    "Modules": {
      "Enabled": ["defender", "firewall", "network", "updates", "account", "privacy", "encryption", "appsecurity", "browser", "system", "startup", "process", "eventlog"],
      "Disabled": []
    },
    "Monitoring": {
      "FileIntegrity": {
        "Enabled": true,
        "Paths": [
          "C:\\Windows\\System32",
          "C:\\Windows\\SysWOW64"
        ],
        "ExcludePatterns": ["*.log", "*.tmp"]
      },
      "EventLog": {
        "Enabled": true,
        "Channels": ["Security", "System", "Application"],
        "EventIds": [4625, 4648, 4672, 4720, 4732, 7045]
      }
    },
    "Reporting": {
      "OutputDirectory": "%ProgramData%\\WinSentinel\\reports",
      "Format": "json",
      "RetainDays": 90
    },
    "ThreatCorrelation": {
      "Enabled": true,
      "TimeWindowMinutes": 60,
      "MinEventsForCorrelation": 3
    }
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "WinSentinel": "Information",
      "Microsoft": "Warning"
    }
  }
}
```

## Configuration Options

### General

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `ScanIntervalMinutes` | int | 60 | How often the agent runs automatic audits |
| `DefaultProfile` | string | `null` | Compliance profile applied by default (home/developer/enterprise/server) |
| `AutoRemediate` | bool | `false` | Enable automatic remediation of findings. Creates restore points before changes. |

### Modules

| Setting | Type | Description |
|---------|------|-------------|
| `Modules.Enabled` | string[] | Explicit list of modules to run. If set, only these modules execute. |
| `Modules.Disabled` | string[] | Modules to skip. Applied after `Enabled` list. |

Available module names: `defender`, `firewall`, `network`, `updates`, `account`, `privacy`, `encryption`, `appsecurity`, `browser`, `system`, `startup`, `process`, `eventlog`.

### File Integrity Monitoring

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `Monitoring.FileIntegrity.Enabled` | bool | `true` | Watch critical directories for unauthorized changes |
| `Monitoring.FileIntegrity.Paths` | string[] | System dirs | Directories to monitor |
| `Monitoring.FileIntegrity.ExcludePatterns` | string[] | `[]` | Glob patterns to ignore |

### Event Log Monitoring

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `Monitoring.EventLog.Enabled` | bool | `true` | Monitor Windows Event Logs for security events |
| `Monitoring.EventLog.Channels` | string[] | Security, System, Application | Event log channels to watch |
| `Monitoring.EventLog.EventIds` | int[] | Security-relevant IDs | Specific event IDs to track |

Key event IDs monitored by default:

| Event ID | Description |
|----------|-------------|
| 4625 | Failed logon attempt |
| 4648 | Logon using explicit credentials |
| 4672 | Special privileges assigned |
| 4720 | User account created |
| 4732 | Member added to security group |
| 7045 | New service installed |

### Threat Correlation

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `ThreatCorrelation.Enabled` | bool | `true` | Enable AI-powered threat correlation |
| `ThreatCorrelation.TimeWindowMinutes` | int | 60 | Time window for correlating events |
| `ThreatCorrelation.MinEventsForCorrelation` | int | 3 | Minimum related events before generating a threat narrative |

### Reporting

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `Reporting.OutputDirectory` | string | `%ProgramData%\WinSentinel\reports` | Where to save audit reports |
| `Reporting.Format` | string | `json` | Output format: `json`, `html`, or `text` |
| `Reporting.RetainDays` | int | 90 | Days to keep old reports before cleanup |

### Logging

Standard .NET logging configuration using `Microsoft.Extensions.Logging`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "WinSentinel": "Debug",
      "Microsoft": "Warning"
    }
  }
}
```

Log files are written to `%ProgramData%\WinSentinel\logs\`.

## CLI Configuration

The CLI (`winsentinel`) accepts flags that override `appsettings.json`:

```powershell
# Run specific modules
winsentinel audit --modules defender,firewall,network

# Skip modules
winsentinel audit --skip browser,privacy

# Apply compliance profile
winsentinel audit --profile enterprise

# Output format
winsentinel audit --format json --output report.json
winsentinel audit --format html --output report.html

# Verbose logging
winsentinel audit --verbose

# Enable auto-remediation for this run
winsentinel audit --remediate

# Disable auto-remediation
winsentinel config set AutoRemediate false

# Set default profile
winsentinel config set DefaultProfile enterprise

# Diagnostic bundle
winsentinel diag --output diag-bundle.zip
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `WINSENTINEL_HOME` | Override installation directory |
| `WINSENTINEL_CONFIG` | Path to alternate `appsettings.json` |
| `WINSENTINEL_LOG_LEVEL` | Override log level (Trace/Debug/Information/Warning/Error) |
| `WINSENTINEL_NO_COLOR` | Disable colored console output |

## Service Installation

The WinSentinel Agent runs as a Windows Service for always-on monitoring:

```powershell
# Install the service (elevated)
.\Install-Agent.ps1

# Or manually
sc.exe create WinSentinel binPath="C:\Program Files\WinSentinel\WinSentinel.Agent.exe" start=auto
sc.exe description WinSentinel "WinSentinel Security Agent - Real-time Windows security monitoring"
sc.exe start WinSentinel

# Check status
Get-Service WinSentinel

# View logs
Get-Content "$env:ProgramData\WinSentinel\logs\agent.log" -Tail 50
```

## IPC Configuration

The agent and dashboard communicate via named pipes. See [IPC Protocol](ipc-protocol.md) for details on:

- Pipe name: `\\.\pipe\WinSentinel`
- Message format: JSON-RPC 2.0
- Authentication and access control
