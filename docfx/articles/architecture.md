# Architecture Guide

This document describes WinSentinel's internal architecture in depth. It's intended for contributors and anyone wanting to understand how the system works under the hood.

## Overview

WinSentinel uses a **two-process architecture**:

1. **Agent** — A .NET 8 Worker Service that runs as a Windows Service. Always on, even when the user isn't logged in. Handles real-time monitoring, threat detection, correlation, and auto-remediation.
2. **Dashboard** — A WPF desktop application that connects to the agent via named pipe IPC. Provides a visual interface for viewing threats, running audits, chatting with the agent, and configuring policies.

Additionally, there's a **CLI tool** that can run audits independently (no agent needed) for scripting and CI/CD use cases.

```
                                    ┌──────────────────────┐
                                    │   WinSentinel CLI    │
                                    │  (standalone audits)  │
                                    └──────────┬───────────┘
                                               │
                                               │ uses
                                               ▼
┌──────────────────────────┐         ┌──────────────────────┐
│  WinSentinel Dashboard   │ ◄─IPC─► │  WinSentinel Agent   │
│  (WPF, user-space)       │         │  (Windows Service)    │
└──────────┬───────────────┘         └──────────┬───────────┘
           │                                    │
           │ references                         │ references
           ▼                                    ▼
        ┌──────────────────────────────────────────┐
        │          WinSentinel.Core                 │
        │  (audit engine, models, helpers)          │
        └──────────────────────────────────────────┘
```

## Project Dependency Graph

```
WinSentinel.Tests ──► Core, Cli, Agent
WinSentinel.App   ──► Core
WinSentinel.Cli   ──► Core
WinSentinel.Agent ──► Core
WinSentinel.Service ──► Core (legacy)
```

`Core` is the shared library. It contains all audit modules, models, scoring logic, and helper utilities. Every other project depends on it.

## The Agent (WinSentinel.Agent)

The agent is the heart of WinSentinel. It runs four real-time monitors and a scheduled auditor, all coordinated by the `AgentService` host.

### Lifecycle

```
Program.cs → Host.CreateDefaultBuilder()
           → AddHostedService<AgentService>()
           → Run()

AgentService.StartAsync():
  1. Initialize AgentState
  2. Initialize ResponsePolicy (load from disk or create defaults)
  3. Start IPC Server (named pipe: "WinSentinel")
  4. Start all IAgentModule instances:
     - ProcessMonitorModule
     - FileSystemMonitorModule
     - EventLogMonitorModule
     - NetworkMonitorModule
     - ScheduledAuditModule
  5. Start ThreatCorrelator
  6. Start AgentJournal
  7. Ready for connections
```

### Module System

Every monitoring component implements `IAgentModule`:

```csharp
public interface IAgentModule
{
    string Name { get; }
    bool IsActive { get; }
    Task StartAsync(CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
}
```

Modules emit `ThreatEvent` objects when they detect something suspicious. These events flow through the pipeline:

```
Monitor Module
    │
    ▼ ThreatEvent
AgentBrain.ProcessThreat()
    │
    ├──► ThreatCorrelator.AddEvent()
    │        │
    │        └──► Correlated? → New ThreatEvent (severity elevated)
    │
    ├──► ResponsePolicy.Evaluate()
    │        │
    │        ├──► Log    → Journal only
    │        ├──► Alert  → Notification + IPC push
    │        ├──► Escalate → Urgent notification + IPC push
    │        └──► AutoFix → AutoRemediator.Execute()
    │
    └──► IPC broadcast to connected dashboards
```

### Real-Time Monitors

| Monitor | What It Watches | Key Signals |
|:---|:---|:---|
| **ProcessMonitor** | `Process.GetProcesses()` polling + WMI events | Suspicious process names, unsigned binaries, execution from `%TEMP%` or `Downloads`, known attack tools |
| **FileSystemMonitor** | `FileSystemWatcher` on critical paths | Changes to `C:\Windows\System32\drivers\etc\hosts`, new `.exe`/`.dll` in startup folders, `C:\Windows\System32` modifications |
| **EventLogMonitor** | `EventLog` class with entry-written events | Security Event IDs 4625 (failed logon), 4720 (account created), 4732 (admin group change), 1102 (audit log cleared) |
| **NetworkMonitor** | `netstat` equivalent via `GetTcpTable` | New listening ports, connections to known-bad IP ranges, unusual outbound ports (IRC, etc.) |

### Threat Correlation

The `ThreatCorrelator` maintains a sliding window of recent events and looks for multi-event patterns:

- **Brute force detection:** Multiple failed logons within a short window
- **Malware execution chain:** Suspicious file write → process launch from same path
- **Defense evasion:** Defender disabled → suspicious process → hosts file modified
- **Lateral movement:** New admin account → RDP connection → file system changes

When a correlation rule matches, it emits a new `ThreatEvent` with elevated severity and a description of the attack chain.

### Auto-Remediation

The `AutoRemediator` supports 7 actions, each with full undo support:

| Action | Trigger | Undo |
|:---|:---|:---|
| `KillProcess` | Malicious process detected | N/A (process was running) |
| `QuarantineFile` | Suspicious file created | Move back from quarantine dir |
| `BlockIp` | Connection to malicious IP | Delete firewall rule |
| `DisableUserAccount` | Brute force target account | Re-enable with `net user /active:yes` |
| `RestoreHostsFile` | Hosts file tampered | Restore hijacked file from backup |
| `ReEnableDefender` | Real-time protection disabled | N/A |
| `RevertRegistry` | Malicious registry change | Restore original value |

Every remediation is recorded as a `RemediationRecord` with metadata for undo. Records persist in memory during the agent's lifetime and are logged to the journal.

### Response Policy

The policy system has three evaluation layers (highest priority first):

1. **User Overrides** — Per-threat-title rules set by the user (e.g., "always ignore process X")
2. **Custom Rules** — Pattern-matching rules with category, severity, and title filters
3. **Default Policy** — Severity × RiskTolerance matrix

```
Threat → UserOverrides → Custom Rules → Default Policy → ResponseAction
```

Risk tolerance levels affect the default response:

| Severity | Low Tolerance | Medium Tolerance | High Tolerance |
|:---|:---|:---|:---|
| Critical | AutoFix | Alert | Alert |
| High | Alert | Alert | Log |
| Medium | Log | Log | Log |
| Low/Info | Log | Log | Log |

## The Audit Engine (WinSentinel.Core)

### Module Interface

Every audit module implements `IAuditModule`:

```csharp
public interface IAuditModule
{
    string Name { get; }
    string Category { get; }
    string Description { get; }
    Task<AuditResult> RunAuditAsync(CancellationToken cancellationToken = default);
}
```

### Scoring

Each module returns an `AuditResult` containing a list of `Finding` objects. The score is computed:

```
Module Score = 100 - (critical_count × 20) - (warning_count × 5)
Overall Score = average of all module scores
```

| Severity | Score Impact | Examples |
|:---|:---|:---|
| **Critical** | -20 points | Firewall disabled, no real-time protection |
| **Warning** | -5 points | LLMNR enabled, outdated definitions |
| **Info** | 0 points | Telemetry at default level |
| **Pass** | 0 points | Secure Boot enabled |

### Finding Model

```csharp
public class Finding
{
    string Title           // Short title: "Firewall Disabled"
    string Description     // Detailed explanation
    Severity Severity      // Pass | Info | Warning | Critical
    string? Remediation    // Human-readable fix instructions
    string? FixCommand     // PowerShell command to auto-fix
    string Category        // "Firewall", "Network", etc.
    DateTimeOffset Timestamp
}
```

If `FixCommand` is non-null, the finding is auto-fixable. The `FixEngine` executes these commands, handling elevation (UAC), timeouts, and output capture.

### Fix Engine

The `FixEngine` handles executing fix commands safely:

1. **Elevation detection:** Checks if the command pattern requires admin (registry writes, service changes, etc.)
2. **UAC integration:** If elevation is needed and the process isn't admin, launches `powershell.exe` with `-Verb RunAs`
3. **Timeout:** Default 60-second timeout per command
4. **Output capture:** Captures stdout/stderr for success/failure reporting
5. **Dry-run mode:** Returns what would be done without executing

### The 13 Audit Modules

| Module | Key Windows APIs Used |
|:---|:---|
| `FirewallAudit` | `netsh advfirewall`, WMI `Win32_Process` |
| `UpdateAudit` | `Get-WindowsUpdateLog`, COM `IUpdateSearcher` |
| `DefenderAudit` | `Get-MpPreference`, `Get-MpComputerStatus` |
| `AccountAudit` | `net user`, `Get-LocalUser`, `net accounts` |
| `NetworkAudit` | `netstat`, `Get-NetTCPConnection`, ARP table |
| `ProcessAudit` | `Process.GetProcesses()`, `Authenticode` verification |
| `StartupAudit` | Registry `Run`/`RunOnce` keys, `Get-ScheduledTask` |
| `SystemAudit` | `Confirm-SecureBootUEFI`, `manage-bde`, Registry for UAC/RDP/DEP |
| `PrivacyAudit` | Registry telemetry keys, location/clipboard/advertising settings |
| `BrowserAudit` | Chrome/Edge JSON preferences files, extension manifests |
| `AppSecurityAudit` | `Get-Package`, installed software version analysis |
| `EncryptionAudit` | `manage-bde -status`, TPM via WMI, certificate store |
| `EventLogAudit` | `Get-WinEvent`, Security log analysis |

## IPC Protocol

The agent and dashboard communicate over a named pipe (`WinSentinel`) using a JSON line protocol. Each message is an `IpcMessage`:

```json
{
  "type": "SendChat",
  "requestId": "a1b2c3d4",
  "payload": { "message": "run audit firewall" },
  "timestamp": "2026-02-19T00:00:00Z"
}
```

### Message Flow

```
Dashboard                          Agent
    │                                │
    │──── GetStatus ────────────────►│
    │◄─── StatusResponse ───────────│
    │                                │
    │──── SendChat { "audit" } ─────►│
    │◄─── AuditStarted ────────────│
    │◄─── ScanProgress (×13) ──────│
    │◄─── AuditCompleted ──────────│
    │                                │
    │◄─── ThreatDetected (push) ───│  (async, anytime)
    │                                │
```

### Message Types

**Requests (Dashboard → Agent):**
`GetStatus`, `RunAudit`, `RunFix`, `GetThreats`, `GetConfig`, `SetConfig`, `SendChat`, `Subscribe`, `Unsubscribe`, `Ping`, `GetPolicy`, `SetPolicy`

**Responses (Agent → Dashboard):**
`StatusResponse`, `AuditStarted`, `AuditCompleted`, `FixResult`, `ThreatsResponse`, `ConfigResponse`, `ChatResponse`, `Subscribed`, `Error`, `Pong`, `PolicyResponse`

**Events (Agent → Dashboard, pushed):**
`ThreatDetected`, `ScanProgress`, `AgentShutdown`

## Dashboard (WinSentinel.App)

The dashboard is a WPF application using **CommunityToolkit.Mvvm** for data binding.

### MVVM Structure

```
Views/                        ViewModels/
  DashboardPage.xaml     ◄──►  DashboardViewModel.cs
  ThreatFeedPage.xaml    ◄──►  ThreatFeedViewModel.cs
  ChatPage.xaml          ◄──►  ChatViewModel.cs
  AuditDetailPage.xaml   ◄──►  AuditDetailViewModel.cs
  PolicySettingsPage.xaml      (code-behind only)
  SettingsPage.xaml            (code-behind only)
```

ViewModels use `[ObservableProperty]` and `[RelayCommand]` source generators from CommunityToolkit.

### Service Layer

| Service | Purpose |
|:---|:---|
| `AgentConnectionService` | Manages the named pipe connection to the agent. Handles reconnection, message routing, event subscriptions. |
| `ChatAiService` | Formats chat messages and interprets agent chat responses for rich UI display (suggested actions, threat cards, score badges). |
| `TrayIconService` | System tray icon with context menu. Supports minimize-to-tray and balloon notifications. |

## CLI (WinSentinel.Cli)

The CLI is a standalone console application that uses `WinSentinel.Core` directly (no agent required).

### Command Flow

```
Program.cs → CliParser.Parse(args)
           → Match command:
               --audit     → AuditEngine.RunFullAuditAsync()
               --score     → AuditEngine → SecurityScorer
               --fix-all   → AuditEngine → FixEngine.ExecuteFixAsync()
               --history   → AuditHistoryService.GetHistory()
           → ConsoleFormatter.Format(output, format)
           → Write to stdout or --output file
```

### Output Formats

The `ConsoleFormatter` supports four output modes:

| Format | Flag | Use Case |
|:---|:---|:---|
| **Console** | (default) | Human-readable with ANSI colors and box-drawing characters |
| **JSON** | `--json` | Machine-parseable for scripting and pipelines |
| **HTML** | `--html` | Rich report for sharing and archiving |
| **Markdown** | `--markdown` | Documentation-friendly format |

### Exit Codes

| Code | Meaning |
|:---:|:---|
| 0 | All checks pass (or score ≥ threshold) |
| 1 | Warnings found (or score < threshold) |
| 2 | Critical findings found |
| 3 | Error during execution |

## Data Flow Summary

```
                    ┌─────────────┐
                    │ Windows OS  │
                    │ (Registry,  │
                    │  WMI, Event │
                    │  Log, etc.) │
                    └──────┬──────┘
                           │ queries
                           ▼
┌──────────────────────────────────────────┐
│            WinSentinel.Core              │
│                                          │
│  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│  │ 13 Audit │  │ Security │  │  Fix   │ │
│  │ Modules  │─►│  Scorer  │  │ Engine │ │
│  └──────────┘  └──────────┘  └────────┘ │
│       │                          ▲       │
│       ▼                          │       │
│  ┌──────────────────────────────┐│       │
│  │ AuditResult + Finding list   ││       │
│  │ (with optional FixCommand)  ─┘│       │
│  └───────────────────────────────┘       │
└──────────────────────────────────────────┘
           │                    │
    used by │                   │ used by
           ▼                    ▼
    ┌────────────┐      ┌────────────┐
    │   Agent    │      │    CLI     │
    │ (service)  │      │ (one-shot) │
    └────────────┘      └────────────┘
           │
    IPC    │
           ▼
    ┌────────────┐
    │ Dashboard  │
    │   (WPF)    │
    └────────────┘
```
