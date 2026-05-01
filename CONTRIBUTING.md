# Contributing to WinSentinel

Thank you for your interest in improving WinSentinel! Whether you're fixing a bug, adding an audit module, improving documentation, or suggesting ideas - contributions are welcome.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Adding an Audit Module](#adding-an-audit-module)
- [Testing](#testing)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Coding Conventions](#coding-conventions)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Getting Help](#getting-help)

## Code of Conduct

Be respectful, constructive, and professional. We're all here to make Windows security better.

## Architecture Overview

WinSentinel is structured as six projects that form a layered architecture:

```
┌─────────────────────────────────────────────────────────┐
│  User-Facing                                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
│  │   CLI    │  │  WPF App │  │  Windows Service      │  │
│  └────┬─────┘  └────┬─────┘  └──────────┬───────────┘  │
│       │              │                   │              │
│  ┌────┴──────────────┴───────────────────┴───────────┐  │
│  │                 Agent (IPC)                        │  │
│  │  AgentBrain → ThreatCorrelator → AutoRemediator   │  │
│  │  CommandRouter → IChatCommand pipeline             │  │
│  │  ScheduledAuditModule → Monitors                   │  │
│  │  IRemediationStrategy chain (6 built-in strategies) │  │
│  └──────────────────────┬────────────────────────────┘  │
│                         │                               │
│  ┌──────────────────────┴────────────────────────────┐  │
│  │                    Core                            │  │
│  │  AuditEngine → IAuditModule[] → Finding[]          │  │
│  │  98 Services (scoring, compliance, reporting...)    │  │
│  │  Helpers: InputSanitizer, RegistryHelper, WmiHelper │  │
│  └────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Scan path**: `AuditEngine` runs all `IAuditModule` implementations → each returns `AuditResult` containing `Finding[]` → aggregated into a `SecurityReport`
2. **Agent path**: `AgentBrain` receives `ThreatEvent` from monitors → evaluates against `ResponsePolicy` → correlates via `ThreatCorrelator` → optionally auto-remediates via `AutoRemediator` + strategy chain
3. **Chat path**: User input → `CommandRouter` iterates `IChatCommand[]` → first match returns `ChatResponsePayload` → falls back to `SecurityAdvisor` for natural language

### Service Categories (Core)

The 98 services in `WinSentinel.Core/Services/` group into functional areas:

| Area | Key Services | Purpose |
|------|-------------|----------|
| **Scan & Audit** | `AuditEngine`, `ScanScheduler`, `ScanProfileManager` | Orchestrate and schedule security scans |
| **Scoring & Risk** | `SecurityScorer`, `RiskAssessmentService`, `ScoreForecaster`, `AttackSurfaceAnalyzer` | Quantify and predict security posture |
| **Compliance** | `ComplianceProfileService`, `ComplianceMapper`, `ComplianceTrendTracker` | Map findings to CIS/HIPAA/PCI-DSS controls |
| **Remediation** | `FixEngine`, `RemediationPlanner`, `RemediationCostEstimator`, `RemediationBatchAnalyzer` | Prioritize and execute fixes |
| **Analysis** | `FindingCorrelator`, `HotspotAnalyzer`, `RootCauseAnalyzer`, `FindingDependencyAnalyzer` | Correlate and analyze findings across modules |
| **Reporting** | `ReportGenerator`, `HtmlDashboardGenerator`, `ExecutiveSummaryGenerator`, `SarifExporter` | Generate human and machine-readable reports |
| **Threat Intel** | `ThreatIntelFeed`, `ThreatModelService`, `MitreAttackMapper`, `AttackPathAnalyzer` | External threat data and MITRE ATT&CK mapping |
| **Monitoring** | `FileIntegrityMonitor`, `AnomalyWatchdogService`, `SecurityCanaryService`, `VitalSignsService` | Continuous security monitoring |
| **History & Trends** | `AuditHistoryService`, `AuditDiffService`, `SecurityTimeline`, `TrendAnalyzer`, `FindingAgeTracker` | Track changes over time |
| **Operational** | `MaintenanceWindowManager`, `SlaTracker`, `SecurityKpiService`, `PeerBenchmarkService` | Ops metrics and SLA tracking |
| **Gamification** | `GamificationService`, `SecurityQuizService`, `SecurityMentorService`, `SecurityHabitTracker` | User engagement and education |
| **Advanced** | `WhatIfSimulator`, `SecurityWarGameService`, `SecuritySwarmIntelligence`, `SecurityProphecyService` | Simulation and predictive analysis |

The service count (98) is based on files in `src/WinSentinel.Core/Services/`. When adding a new service, identify which area it belongs to — this helps reviewers understand scope and suggests which existing services your code should integrate with.

## Getting Started

1. **Fork** the repository
2. **Clone** your fork locally
3. **Create a branch** for your work (`git checkout -b feat/my-change`)
4. **Make changes**, add tests, verify the build
5. **Push** and open a Pull Request

## Development Setup

### Prerequisites

- **Windows 10/11** (WinSentinel is Windows-native)
- **.NET 8 SDK** - [download](https://dotnet.microsoft.com/download/dotnet/8.0)
- **Visual Studio 2022** (recommended) or **VS Code** with the C# Dev Kit
- **Git** - [download](https://git-scm.com/)

### Build

```powershell
# Clone your fork
git clone https://github.com/<your-username>/WinSentinel.git
cd WinSentinel

# Restore and build (x64)
dotnet build WinSentinel.sln -p:Platform=x64

# Run the CLI
dotnet run --project src/WinSentinel.Cli -p:Platform=x64 -- scan
```

### Run Tests

```powershell
# All tests
dotnet test tests/WinSentinel.Tests -p:Platform=x64

# Specific test class
dotnet test tests/WinSentinel.Tests -p:Platform=x64 --filter "FullyQualifiedName~FirewallAuditTests"

# With coverage
dotnet test tests/WinSentinel.Tests -p:Platform=x64 /p:CollectCoverage=true
```

## Project Structure

```
WinSentinel/
├── src/
│   ├── WinSentinel.Core/        # Audit engine, modules, models, services
│   │   ├── Audits/              # Audit module implementations
│   │   ├── Models/              # Data models (Finding, AuditResult, etc.)
│   │   ├── Services/            # SecurityAdvisor, compliance, agent brain
│   │   └── Data/                # SQLite history, encryption
│   ├── WinSentinel.App/         # WPF dashboard (XAML + code-behind)
│   ├── WinSentinel.Cli/         # Command-line interface
│   ├── WinSentinel.Agent/       # Background agent with IPC
│   ├── WinSentinel.Service/     # Windows Service host
│   └── WinSentinel.Installer/   # MSIX packaging
├── tests/
│   └── WinSentinel.Tests/       # xUnit test project
├── scripts/                     # PowerShell install/setup scripts
└── docs/                        # GitHub Pages site
```

### Key Concepts

- **AuditModule**: Base class for all security checks. Each module scans one security domain and returns `Finding` objects.
- **Finding**: A security observation with severity (`Critical`, `Warning`, `Info`, `Pass`), description, category, and optional remediation steps.
- **AuditEngine**: Orchestrates all modules, runs scans, aggregates results into a `SecurityReport`.
- **SecurityAdvisor**: Natural language chat interface that interprets user commands and invokes the engine.
- **ComplianceProfile**: Named policy configurations (e.g., CIS, HIPAA, PCI-DSS) that define required checks and thresholds.

## Making Changes

### Branch Naming

- `feat/description` - new features or audit modules
- `fix/description` - bug fixes
- `security/description` - security-related changes
- `docs/description` - documentation only
- `refactor/description` - code improvements without behavior change

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(audit): add USB device audit module
fix(firewall): handle disabled Windows Firewall service
security(input): sanitize PowerShell command arguments
docs(readme): add CLI usage examples
test(network): add IPv6 audit coverage
refactor(core): extract base class for registry audits
```

## Extension Points

WinSentinel has three primary extension points. Pick the one that matches your contribution:

| Extension | When to Use | Interface/Base |
|-----------|------------|----------------|
| **Audit Module** | New security check domain (e.g., USB devices, cloud config) | `AuditModuleBase` / `IAuditModule` |
| **Chat Command** | New agent command (e.g., `/export`, `/compare`) | `IChatCommand` |
| **Remediation Strategy** | New auto-fix type for the Agent | `IRemediationStrategy` |

## Adding an Audit Module

WinSentinel's architecture makes it straightforward to add new security checks.

### 1. Create the Module

Create a new file in `src/WinSentinel.Core/Audits/`:

```csharp
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits [describe what this checks].
/// </summary>
public class MyNewAudit : AuditModule
{
    public override string Name => "My New Audit";
    public override string Category => "Category Name";
    public override string Description => "What this module checks.";

    protected override Task<List<Finding>> RunChecksAsync(CancellationToken ct)
    {
        var findings = new List<Finding>();

        // Your security checks here
        // Use Finding.Critical(), Finding.Warning(), Finding.Pass(), Finding.Info()

        findings.Add(Finding.Pass(
            "Check Name",
            "Detailed description of what was checked.",
            Category));

        return Task.FromResult(findings);
    }
}
```

### 2. Register It

Add your module to the `AuditEngine` constructor in `src/WinSentinel.Core/Services/AuditEngine.cs`:

```csharp
_modules.Add(new MyNewAudit());
```

### 3. Add Tests

Create tests in `tests/WinSentinel.Tests/Audits/`:

```csharp
[Fact]
public async Task MyNewAudit_ReturnsFindings()
{
    var module = new MyNewAudit();
    var result = await module.RunAsync();

    Assert.NotNull(result);
    Assert.Equal("My New Audit", result.ModuleName);
    Assert.True(result.Findings.Count > 0);
}
```

> **Note**: The DI constructor `AuditEngine(IEnumerable<IAuditModule>)` is used in tests and by the Agent — no changes needed there.

### 4. Document It

Update the README's module table with your new audit.

## Adding a Remediation Strategy

The Agent auto-remediates threats using a strategy chain (`IRemediationStrategy` in `RemediationStrategies.cs`). The `AutoRemediator` evaluates each strategy in order; the first one that claims a threat handles it.

### Built-in Strategies (6)

| Strategy | Trigger | Action |
|----------|---------|--------|
| `DefenderRemediationStrategy` | "Defender" + "Disabled" in title | Re-enables Windows Defender |
| `HostsFileRemediationStrategy` | "Hosts File" in title | Restores hosts file to clean state |
| `ProcessKillRemediationStrategy` | Source is `ProcessMonitor` with PID | Kills the suspicious process |
| `FileQuarantineRemediationStrategy` | Source is `FileSystemMonitor` with path | Moves file to quarantine |
| `IpBlockRemediationStrategy` | IP address in description | Creates firewall block rule |
| `FixCommandRemediationStrategy` | Threat has a `FixCommand` | Executes the fix command (catch-all fallback) |

### Creating a New Strategy

Create a new class implementing `IRemediationStrategy` in `src/WinSentinel.Agent/Services/RemediationStrategies.cs`:

```csharp
namespace WinSentinel.Agent.Services;

/// <summary>
/// Disables a suspicious scheduled task when a TaskSchedulerMonitor threat is detected.
/// </summary>
public class TaskDisableRemediationStrategy : IRemediationStrategy
{
    private readonly AutoRemediator _remediator;

    public TaskDisableRemediationStrategy(AutoRemediator remediator)
        => _remediator = remediator;

    public bool CanHandle(ThreatEvent threat) =>
        threat.Source == "TaskSchedulerMonitor" &&
        !string.IsNullOrEmpty(threat.Description);

    public RemediationRecord Execute(ThreatEvent threat)
    {
        var taskName = ExtractTaskName(threat.Description);
        return _remediator.ExecuteFixCommand(threat with
        {
            FixCommand = $"schtasks /Change /TN \"{taskName}\" /Disable"
        });
    }

    private static string ExtractTaskName(string desc) { /* parse from description */ }
}
```

### Register the Strategy

Add it to the strategy chain in `AgentBrain`'s constructor. **Order matters** — more specific strategies should come before generic ones (`FixCommandRemediationStrategy` is always last as the catch-all):

```csharp
new TaskDisableRemediationStrategy(remediator),
// ... existing strategies ...
new FixCommandRemediationStrategy(remediator), // always last
```

### Test Both Paths

```csharp
[Fact]
public void TaskDisable_CanHandle_TaskSchedulerSource()
{
    var strategy = new TaskDisableRemediationStrategy(remediator);
    var threat = new ThreatEvent { Source = "TaskSchedulerMonitor", Description = "..." };
    Assert.True(strategy.CanHandle(threat));
}

[Fact]
public void TaskDisable_IgnoresUnrelatedSource()
{
    var strategy = new TaskDisableRemediationStrategy(remediator);
    var threat = new ThreatEvent { Source = "FileSystemMonitor", Description = "..." };
    Assert.False(strategy.CanHandle(threat));
}
```

## Adding a Chat Command

The WinSentinel Agent has a command pipeline (`CommandRouter`) that routes user input through `IChatCommand` implementations. First match wins.

### 1. Create the Command

Create a new file in `src/WinSentinel.Agent/Services/Commands/`:

```csharp
using WinSentinel.Agent.Ipc;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>
/// Handles the /mycommand chat command.
/// </summary>
public sealed class MyCommand : IChatCommand
{
    public Task<ChatResponsePayload?> TryExecuteAsync(
        string raw, string lower, ChatContext context)
    {
        if (!lower.StartsWith("/mycommand"))
            return Task.FromResult<ChatResponsePayload?>(null);

        // Parse arguments from raw, use context.Engine/context.History as needed
        var response = new ChatResponsePayload
        {
            Message = "Here are the results...",
            Category = "info"
        };

        return Task.FromResult<ChatResponsePayload?>(response);
    }
}
```

### 2. Register the Command

Add it to the command list in `AgentBrain`'s constructor (order matters - earlier commands have priority):

```csharp
// In AgentBrain constructor or DI registration
new MyCommand(),
```

### 3. Add Tests

Test both the match case and the non-match (returns null) case:

```csharp
[Fact]
public async Task MyCommand_MatchesPrefix()
{
    var cmd = new MyCommand();
    var result = await cmd.TryExecuteAsync("/mycommand foo", "/mycommand foo", context);
    Assert.NotNull(result);
}

[Fact]
public async Task MyCommand_IgnoresUnrelated()
{
    var cmd = new MyCommand();
    var result = await cmd.TryExecuteAsync("hello", "hello", context);
    Assert.Null(result);
}
```

### Existing Commands

Review these for patterns before writing your own:

| Command | File | Triggers |
|---------|------|----------|
| `ScanCommand` | Scan, check, audit keywords | Runs a security scan |
| `StatusCommand` | Status, score, report | Shows current security posture |
| `FixCommand` | Fix, remediate, repair | Executes auto-remediation |
| `MonitorsCommand` | Monitor, watch | Controls continuous monitors |
| `ThreatsCommand` | Threats, alerts | Shows threat log |
| `HelpCommand` | Help, commands, ? | Lists available commands |
| `InfoCommands` | What, explain, why | Explains findings/concepts |
| `SettingsCommands` | Settings, config | Agent configuration |
| `ActionCommands` | Export, compare, baseline | Data actions |
| `FallbackCommand` | *(catch-all)* | Routes to SecurityAdvisor NLP |

## Testing

- **All new code must have tests.** Aim for meaningful coverage of the logic, not just line count.
- **Tests must pass on x64 platform**: `dotnet test -p:Platform=x64`
- **Don't depend on specific machine state**: Mock or abstract OS-dependent calls where feasible. Some audit modules inherently test the current machine - that's fine, but test the logic paths, not just "it ran."
- **Sanitize inputs**: Any user-provided or external input must go through `InputSanitizer` before use in file paths, registry keys, or commands.

### Test Categories

| Directory | Coverage |
|-----------|----------|
| `Audits/` | Individual audit module behavior |
| `Services/` | SecurityAdvisor, AuditEngine, ComplianceEngine |
| `Models/` | Data model validation |
| `Data/` | SQLite history, encryption |
| Root | Integration and cross-cutting tests |

## Submitting a Pull Request

1. **Ensure the build passes**: `dotnet build WinSentinel.sln -p:Platform=x64`
2. **Ensure tests pass**: `dotnet test tests/WinSentinel.Tests -p:Platform=x64`
3. **Fill out the PR template** - it covers type of change, components affected, testing, and security considerations
4. **Keep PRs focused** - one feature or fix per PR
5. **Update documentation** if your change affects usage or architecture

### What We Look For in Reviews

- **Correctness**: Does it do what it claims?
- **Security**: No new attack surface, inputs validated, no sensitive data exposed
- **Tests**: Meaningful tests that verify behavior
- **Performance**: No unnecessary allocations, I/O, or blocking in hot paths
- **Style**: Consistent with the existing codebase

## Helpers & Utilities

The `WinSentinel.Core/Helpers/` directory contains shared utilities that **must** be used instead of rolling your own:

| Helper | Purpose | When to Use |
|--------|---------|-------------|
| `InputSanitizer` | Validates and sanitizes external input | **Always** - file paths, registry keys, user text, command arguments |
| `RegistryHelper` | Safe registry reads with error handling | Reading any registry key/value |
| `WmiHelper` | WMI/CIM query abstraction | Querying Win32_* classes |
| `ShellHelper` | Safe process execution with timeout | Running external commands (PowerShell, cmd, etc.) |
| `SignatureHelper` | Authenticode signature verification | Checking file/driver signatures |

> **Security rule**: Never call `Registry.GetValue()`, `Process.Start()`, or WMI directly in audit modules. Always go through the corresponding helper, which handles sanitization, error recovery, and timeout enforcement.

## Coding Conventions

- **C# 12 / .NET 8** - use modern language features (file-scoped namespaces, primary constructors, etc.)
- **Nullable reference types** - enabled project-wide; don't suppress warnings without good reason
- **`InputSanitizer`** - all external input (file paths, registry keys, user text) must be sanitized before use
- **Async all the way** - audit modules use `async Task`; don't block on async code
- **XML doc comments** - on all public types and methods
- **No `#pragma warning disable`** without a comment explaining why
- **Constants over magic numbers**
- **`CancellationToken`** - accept and respect cancellation in long-running operations

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.**

Instead, use the [Security Report](https://github.com/sauravbhattacharya001/WinSentinel/security/advisories/new) form, or email the maintainer directly. Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

We take security seriously - this is a security tool, after all.

## Debugging & Troubleshooting

### Common Build Issues

| Problem | Fix |
|---------|-----|
| `Platform 'x64' not found` | Ensure you pass `-p:Platform=x64` to all `dotnet` commands |
| `WPF targets not found` | Install the **.NET Desktop Development** workload in VS Installer |
| `SQLite native interop` | Run `dotnet restore` again - the native binary may not have been extracted |
| Tests fail with `Access Denied` | Some audits need **Administrator** - right-click VS/terminal → Run as Admin |

### Debugging Audit Modules

1. Set a breakpoint in your module's `RunChecksAsync`
2. Use the CLI as the debug target: `dotnet run --project src/WinSentinel.Cli -p:Platform=x64 -- scan --module "My New Audit"`
3. Attach to the WPF app or Agent process for UI/service debugging

### Logging

WinSentinel uses structured logging. When debugging, set the log level to `Debug` in `appsettings.json` or via environment variable:

```powershell
$env:LOGGING__LOGLEVEL__DEFAULT = "Debug"
dotnet run --project src/WinSentinel.Cli -p:Platform=x64 -- scan
```

## Docker Development

The repo includes a `Dockerfile` for CI and headless scan scenarios (no WPF/GUI). Useful for testing audit logic without a full Windows desktop.

```powershell
# Build the image
docker build -t winsentinel:dev .

# Run a scan
docker run --rm winsentinel:dev scan

# Run tests inside the container
docker run --rm winsentinel:dev dotnet test tests/WinSentinel.Tests -p:Platform=x64
```

> **Note**: Some audit modules that query live Windows APIs (firewall rules, registry, services) will produce limited or no findings inside a container. Test those on a real Windows machine.

## Adding a Compliance Profile

Compliance profiles define which checks must pass for a given standard (CIS, HIPAA, PCI-DSS, etc.).

1. Create a JSON profile in `src/WinSentinel.Core/Data/Profiles/`:

```json
{
  "name": "MyStandard",
  "description": "My compliance framework",
  "requiredModules": ["Firewall", "Encryption", "AccountPolicy"],
  "thresholds": {
    "maxCritical": 0,
    "maxWarning": 5
  }
}
```

2. The `ComplianceEngine` discovers profiles automatically at startup.
3. Add tests verifying the profile's module list covers all required controls.

## Getting Help

- **Issues**: Open an issue with the relevant template
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Code**: Browse the existing audit modules for patterns and examples

## Useful Development Commands

Quick reference for common development tasks:

```powershell
# Full build (all projects)
dotnet build WinSentinel.sln -p:Platform=x64

# Build just Core (fastest iteration)
dotnet build src/WinSentinel.Core -p:Platform=x64

# Run a specific audit from CLI
dotnet run --project src/WinSentinel.Cli -p:Platform=x64 -- scan --module "Firewall"

# Run tests matching a pattern
dotnet test tests/WinSentinel.Tests -p:Platform=x64 --filter "FullyQualifiedName~MyNewAudit"

# Generate a SARIF report (useful for testing SARIF exporter)
dotnet run --project src/WinSentinel.Cli -p:Platform=x64 -- scan --format sarif --output report.sarif

# Run the Agent in debug mode
$env:LOGGING__LOGLEVEL__DEFAULT = "Debug"
dotnet run --project src/WinSentinel.Agent -p:Platform=x64

# Check code formatting (if dotnet-format is installed)
dotnet format WinSentinel.sln --verify-no-changes
```

## Release Process

Releases follow semantic versioning. The CI pipeline handles most of it:

1. Tag with `v<major>.<minor>.<patch>` (e.g., `v1.12.0`)
2. The `release.yml` workflow builds, tests, and creates a GitHub Release
3. The `nuget.yml` workflow publishes updated packages
4. The `docker.yml` workflow builds and pushes the container image

Changelog entries are auto-generated from conventional commit messages since the last tag.

Thank you for helping make Windows more secure! 🛡️
