# API Reference

This section contains the auto-generated API documentation for all public types in WinSentinel.

## Namespaces

| Namespace | Description |
|-----------|-------------|
| `WinSentinel.Core` | Core models, interfaces, and services |
| `WinSentinel.Core.Audits` | Security audit module implementations |
| `WinSentinel.Core.Scoring` | Security score calculation engine |
| `WinSentinel.Core.Compliance` | Compliance profile definitions (CIS, HIPAA, etc.) |
| `WinSentinel.Core.Correlation` | AI-powered threat correlation engine |
| `WinSentinel.Core.Monitoring` | Real-time file and event monitoring |
| `WinSentinel.Core.Remediation` | Auto-remediation engine |
| `WinSentinel.Core.Security` | Input sanitization and security utilities |
| `WinSentinel.Cli` | Command-line interface components |
| `WinSentinel.Agent` | Background agent and scheduling |

## Key Types

### Audit Infrastructure
- `IAuditModule` — Interface for all audit modules
- `AuditResult` — Result from a single audit module run
- `AuditFinding` — Individual security finding with severity
- `SecurityScoreEngine` — Calculates overall security score

### Agent
- `AgentBrain` — Decision engine for the background agent
- `AgentJournal` — Structured logging for agent actions
- `FileWatcher` — Real-time file integrity monitoring
- `EventLogMonitor` — Windows Event Log monitoring

### Compliance
- `ComplianceProfile` — Defines a compliance standard's requirements
- `ComplianceResult` — Compliance check results with pass/fail
