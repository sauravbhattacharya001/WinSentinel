# Copilot Instructions — WinSentinel

## Project Overview

WinSentinel is a Windows security auditing and real-time monitoring agent built with .NET 8 and C# 12. It consists of a background agent (Windows Service), a WPF desktop dashboard, and a CLI tool.

## Architecture

The solution has **6 projects** in `WinSentinel.sln`:

| Project | Type | Description |
|---------|------|-------------|
| `WinSentinel.Core` | Class Library | Security audit engine — 13 audit modules, models, services, helpers |
| `WinSentinel.Agent` | Worker Service | Always-on Windows Service — real-time monitors, threat correlator, auto-remediator, IPC server, chat handler |
| `WinSentinel.App` | WPF Application | Desktop dashboard — MVVM with CommunityToolkit.Mvvm, live threat feed, chat UI, policy settings |
| `WinSentinel.Cli` | Console App | CLI tool (`winsentinel.exe`) — run audits, export reports, scripting/CI support |
| `WinSentinel.Service` | Worker Service | Legacy background monitoring service (pre-agent, kept for compatibility) |
| `WinSentinel.Installer` | MSIX Packaging | MSIX build/sign scripts and manifest |
| `WinSentinel.Tests` | xUnit Tests | 192+ tests covering Agent, Audits, CLI, Models, and Services |

### Dependency Graph

```
WinSentinel.Tests → Core, Cli, Agent
WinSentinel.App → Core
WinSentinel.Cli → Core
WinSentinel.Agent → Core
WinSentinel.Service → Core
```

### IPC Architecture

The Agent and App communicate via **named pipes** (`System.IO.Pipes`). The Agent runs an `IpcServer` and the App connects via `IpcClient` in Core. Messages use a simple JSON protocol defined in `Agent/Ipc/IpcMessage.cs`.

## Building & Testing

```powershell
# Full solution build
dotnet build WinSentinel.sln -p:Platform=x64

# Build specific project
dotnet build src/WinSentinel.Core

# Run all tests
dotnet test -p:Platform=x64

# Run tests with verbosity
dotnet test -p:Platform=x64 --verbosity normal
```

**Important:** The WPF App project (`WinSentinel.App`) requires `-p:Platform=x64` (or x86/ARM64). It does NOT build under `AnyCPU`. Core, Agent, and Cli build under `AnyCPU`.

## Conventions

### Code Style
- **C# 12** features: file-scoped namespaces, primary constructors, pattern matching, raw string literals
- **Nullable** reference types enabled everywhere (`<Nullable>enable</Nullable>`)
- **Implicit usings** enabled
- **Target framework:** `net8.0-windows` (all projects target Windows-specific APIs)

### Project Patterns
- **Audit modules** implement `IAuditModule` interface (in `Core/Interfaces/`). Each returns `AuditResult` with `Finding` items.
- **Agent modules** implement `IAgentModule` interface (in `Agent/`). Each has `StartAsync`/`StopAsync` lifecycle.
- **WPF Views** follow MVVM: Views in `Views/`, ViewModels in `ViewModels/`, using `[ObservableProperty]` and `[RelayCommand]` from CommunityToolkit.Mvvm.
- **Services** are registered via dependency injection in each project's `Program.cs`.

### Models
- `Finding` — individual security finding with `Severity` (Critical/Warning/Info/Pass), message, and optional fix action
- `AuditResult` — results from one audit module (module name, score, list of findings)
- `FullAuditReport` — aggregated report from all modules with overall score
- `ThreatEvent` — real-time threat detected by agent monitors

### Helpers
- `ShellHelper` — runs shell commands, wraps `Process.Start`
- `PowerShellHelper` — runs PowerShell commands via `System.Management.Automation`
- `RegistryHelper` — reads/writes Windows Registry
- `WmiHelper` — queries WMI via `System.Management`

## Testing

Tests are in `tests/WinSentinel.Tests/` organized by area:
- `Agent/` — AgentBrain, ThreatCorrelator, AutoRemediator, monitors, IPC, policies
- `Audits/` — Each of the 13 audit modules
- `Cli/` — CLI argument parsing and output formatting
- `Models/` — AuditResult, Finding, severity logic
- `Services/` — AuditEngine, SecurityScorer, ReportGenerator, FixEngine, etc.

Tests use **xUnit** with `[Fact]` and `[Theory]` attributes. Many audit tests mock Windows APIs since they access OS-level features.

## Key Files

- `RunAudit.ps1` — Quick one-shot audit script (no build needed)
- `Install-Agent.ps1` — Installs/uninstalls the Agent as a Windows Service
- `Install-WinSentinel.ps1` — MSIX installer script
- `Fix-Network.ps1` — Network security remediation script

## Tips for Coding Agents

1. **Always build with `-p:Platform=x64`** when building the full solution or WPF App.
2. **Core and Agent can use `AnyCPU`** for faster iteration when not touching the App.
3. **Tests reference Core, Cli, AND Agent** — changes to any of these may affect tests.
4. **Windows-only APIs** are used throughout (Registry, WMI, EventLog, etc.) — this is by design.
5. **The Agent's `InternalsVisibleTo` is set for `WinSentinel.Tests`** — internal members in Agent are testable.
6. When adding a new audit module, implement `IAuditModule` and register it in `AuditEngine`.
7. When adding a new agent monitor, implement `IAgentModule` and register it in `AgentService`.
