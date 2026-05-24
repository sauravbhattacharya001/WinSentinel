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
- [PR Lifecycle & Review Process](#pr-lifecycle--review-process)
- [Labels Glossary](#labels-glossary)
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

## PR Lifecycle & Review Process

Knowing what happens to a PR after you click "Create pull request" helps set expectations and avoid back-and-forth.

### Stage 1 — Automated Checks (minutes)

When you open a PR, several GitHub Actions run automatically:

| Workflow | What It Does | Required to Pass |
|----------|-------------|------------------|
| `ci.yml` | Restores, builds (x64), and runs tests | ✅ Yes |
| `codeql.yml` | Static security analysis (C#) | ✅ Yes (no new alerts) |
| `coverage-gate.yml` | Enforces coverage threshold via Codecov | ✅ Yes |
| `labeler.yml` | Auto-applies area labels based on changed files | Informational |
| `docker.yml` | Builds the container image (PRs touching Docker) | ✅ When triggered |

If any required check fails, the PR is blocked from merge. Look at the workflow logs, fix the issue, and push again — checks re-run automatically.

### Stage 2 — Auto-Labeling (seconds)

The `actions/labeler@v6` workflow inspects your changed files and applies area labels (`core`, `audits`, `agent`, `cli`, etc.) — see the [Labels Glossary](#labels-glossary) for the full list. You don't need to label your PR manually; the bot handles it. If a label seems wrong, mention it in a comment and a maintainer can update `.github/labeler.yml`.

### Stage 3 — Maintainer Review (1–7 days)

A maintainer will review your PR for the criteria in [What We Look For in Reviews](#what-we-look-for-in-reviews). Possible outcomes:

- **Approved** ✅ — your PR will be merged (usually squash-merge to keep history clean)
- **Changes requested** 📝 — address the comments and push more commits to the same branch; the review will be re-requested automatically
- **Closed** ❌ — rare, only if the change conflicts with project direction; a maintainer will explain why

Review turnaround is typically 1–3 business days for small PRs and up to a week for larger architectural changes. If a week has passed with no response, leave a polite ping comment.

### Stage 4 — Merge & Release

Once merged to `master`:

- The `version-sync.yml` workflow keeps version numbers consistent across projects.
- If your change warrants a release, a maintainer will tag a new version (`v<major>.<minor>.<patch>`), which triggers `release.yml` (GitHub Release), `nuget.yml` (NuGet packages), and `docker.yml` (container image push). See the [Release Process](#release-process) section.

### Tips for a Smooth Review

- **Keep PRs small and focused.** One feature or fix per PR. If you have multiple unrelated changes, split them.
- **Write a clear description.** Explain *why* the change is needed, not just *what* it does.
- **Link the issue** it closes (`Closes #123`) so the issue auto-closes on merge.
- **Self-review first.** Re-read the diff in the GitHub PR view — you'll often spot leftover debug code or missed edge cases.
- **Don't force-push after review.** Push additional commits so reviewers can see exactly what you changed in response to feedback. A maintainer will squash on merge.
- **Be responsive but don't rush.** It's fine to take a day or two to address feedback thoughtfully.

## Labels Glossary

Labels are auto-applied by `.github/labeler.yml` based on the files a PR touches. They make it easy to filter issues and PRs by area. Don't apply labels manually unless a maintainer asks — the bot keeps them in sync.

### Component Labels

| Label | Applied When PR Touches |
|-------|------------------------|
| `core` | Anything in `src/WinSentinel.Core/` |
| `audits` | `src/WinSentinel.Core/Audits/` (security audit modules) |
| `services` | `src/WinSentinel.Core/Services/` (the 98+ service classes) |
| `helpers` | `src/WinSentinel.Core/Helpers/` (InputSanitizer, RegistryHelper, etc.) |
| `models` | `src/WinSentinel.Core/Models/` (data models) |
| `data` | `src/WinSentinel.Core/Data/` (SQLite history, encryption) |
| `agent` | `src/WinSentinel.Agent/` (real-time monitoring agent) |
| `cli` | `src/WinSentinel.Cli/` (command-line interface) |
| `app` | `src/WinSentinel.App/` (WPF dashboard) |
| `service` | `src/WinSentinel.Service/` (Windows Service host) |
| `installer` | `src/WinSentinel.Installer/` (MSIX installer project only) |
| `ui` | XAML files, views, view-models, controls |

### Cross-cutting Labels

| Label | Applied When PR Touches |
|-------|------------------------|
| `ipc` | Agent IPC layer or `IpcClient` |
| `threat-detection` | Agent monitors, `ThreatCorrelator`, `AgentBrain`, threat models |
| `remediation` | Auto-remediation strategies, `FixEngine`, `RemediationPlanner` |
| `tests` | Anything in `tests/` |
| `build` | Solution file, `.csproj`, `Directory.Build.props`, `global.json` |
| `ci` | Files in `.github/workflows/` or labeler/stale config |
| `docker` | `Dockerfile`, `docker-compose.yml`, `.dockerignore`, Docker workflows |
| `documentation` | `README.md`, `docs/`, `docfx/`, `SECURITY.md`, `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, copilot instructions |
| `scripts` | Root-level `*.ps1` files (Install-Agent, Fix-Network, RunAudit, etc.) and `scripts/` |
| `dependencies` | `.github/dependabot.yml`, `*.csproj`, lockfiles, `Directory.Packages.props` |

### Triage Labels (manual)

These are applied by maintainers during triage, not by the labeler:

| Label | Meaning |
|-------|---------|
| `bug` | Confirmed defect |
| `enhancement` | New feature or improvement |
| `documentation` | Docs-only issue or PR |
| `good first issue` | Approachable for new contributors |
| `help wanted` | Maintainers welcome external contribution |
| `question` | Discussion or clarification needed |
| `duplicate` | Already tracked elsewhere |
| `invalid` | Not actionable as filed |
| `wontfix` | Out of scope or intentional |

### Adding a New Label

If a meaningful area of the codebase isn't covered by an existing label:

1. Add a new entry to `.github/labeler.yml` with appropriate file globs.
2. Create the label in GitHub: `gh label create <name> --color <hex> --description "<description>" --repo sauravbhattacharya001/WinSentinel`.
3. Update this glossary table.
4. Open a small PR with just those three changes so it's easy to review.

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

## Audit Module Catalog

WinSentinel ships 32 audit modules across 8 security domains. Refer to this catalog to understand coverage, avoid duplication, and identify integration points when adding new modules.

### System & OS Hardening
| Module | What It Checks |
|--------|---------------|
| `AccountAudit` | User accounts, password policies, guest/admin state |
| `GroupPolicyAudit` | Applied GPOs, security-relevant policy settings |
| `EnvironmentAudit` | PATH hijack risks, environment variable hygiene |
| `UpdateAudit` | Windows Update status, pending patches, WSUS config |
| `VirtualizationAudit` | Hyper-V, VBS, Credential Guard, hypervisor state |

### Network & Connectivity
| Module | What It Checks |
|--------|---------------|
| `FirewallAudit` | Windows Firewall profiles, inbound/outbound rules |
| `NetworkAudit` | Open ports, listening services, network adapters |
| `DnsAudit` | DNS client config, DNSSEC, DNS-over-HTTPS, cache poisoning risk |
| `WifiAudit` | Wireless profiles, encryption strength, open network exposure |
| `BluetoothAudit` | Bluetooth discoverability, paired devices, service state |
| `RemoteAccessAudit` | RDP, SSH, WinRM, remote desktop configuration |
| `SmbShareAudit` | SMB shares, permissions, guest access, SMBv1 status |

### Endpoint Protection
| Module | What It Checks |
|--------|---------------|
| `DefenderAudit` | Windows Defender status, real-time protection, definitions |
| `EncryptionAudit` | BitLocker, EFS, TLS settings, certificate strength |
| `CertificateAudit` | Certificate store health, expiry, revocation, weak algorithms |
| `DriverAudit` | Unsigned drivers, vulnerable driver blocklist, kernel integrity |

### Application Security
| Module | What It Checks |
|--------|---------------|
| `AppSecurityAudit` | App execution policies, SmartScreen, ASLR, DEP |
| `BrowserAudit` | Browser security settings, extensions, autofill exposure |
| `PowerShellAudit` | Execution policy, constrained language mode, logging |
| `SoftwareInventoryAudit` | Installed software, EOL products, known-vulnerable versions |

### Process & Service Integrity
| Module | What It Checks |
|--------|---------------|
| `ProcessAudit` | Running processes, unsigned executables, parent-child anomalies |
| `ProcessLineageAudit` | Process tree analysis, injection detection, LOLBin usage |
| `ServiceAudit` | Windows services, unquoted paths, writable service binaries |
| `StartupAudit` | Startup programs, Run/RunOnce keys, scheduled auto-start |
| `ScheduledTaskAudit` | Scheduled tasks, suspicious triggers, non-system task owners |

### Data & Privacy
| Module | What It Checks |
|--------|---------------|
| `PrivacyAudit` | Telemetry settings, location, camera/mic access, advertising ID |
| `CredentialExposureAudit` | Cached credentials, credential manager entries, plaintext secrets |
| `BackupAudit` | Backup configuration, recovery options, shadow copies |

### Monitoring & Logging
| Module | What It Checks |
|--------|---------------|
| `EventLogAudit` | Event log configuration, retention, cleared log detection |
| `RegistryAudit` | Critical registry key permissions, modification detection |
| `SystemAudit` | Secure boot, UEFI, TPM, kernel DMA protection |

> When creating a new module, check this catalog first. If your check overlaps with an existing module, consider extending it rather than creating a new one.

## Service Integration Patterns

WinSentinel's 99 services in `Core/Services/` follow consistent patterns. Understanding these helps you integrate new code correctly.

### Cross-Service Dependencies

Services reference each other through constructor injection. Common dependency chains:

```
AuditEngine → SecurityScorer → ComplianceProfileService
                             → TrendAnalyzer → AuditHistoryService

SecurityAdvisor → AuditEngine → IAuditModule[]
                → SecurityScorer
                → SecurityKnowledgeBase

FixEngine → RemediationPlanner → RemediationCostEstimator
                               → FindingDependencyAnalyzer
```

When adding a new service, identify which existing services it needs and which services should consume it. Draw the dependency chain before writing code — circular dependencies will break DI resolution.

### Threat Detection Services

The advanced threat detection services (`DataExfiltrationDetector`, `LateralMovementDetector`, `PrivilegeEscalationDetector`, `DefenseEvasionDetector`, `PersistenceScanner`, `InsiderThreatProfiler`) share a common pattern:

1. Consume findings from multiple audit modules
2. Correlate across finding categories to detect multi-stage attack patterns
3. Produce enriched `Finding` objects with MITRE ATT&CK technique IDs
4. Feed into `KillChainReconstructorService` for attack narrative generation

If adding a new detector, implement the same pattern and register it with the kill chain reconstructor.

### Predictive & Analytics Services

Services like `ScoreForecaster`, `SecurityDecayPredictor`, `RegressionPredictorService`, and `PostureMomentumAnalyzer` depend on `AuditHistoryService` for historical data. They expect at least 3 historical scans to produce meaningful predictions. When testing, seed history with representative scan data.

### Report Pipeline

Reports flow through a chain:

```
AuditEngine.RunAsync()
  → SecurityReport
    → ReportGenerator (text/JSON)
    → HtmlDashboardGenerator (interactive HTML)
    → ExecutiveSummaryGenerator (management-level)
    → SarifExporter (SARIF for IDE integration)
    → SecurityDigestGenerator (email digest)
    → CalendarHeatmapService (temporal visualization)
```

If adding a new output format, implement it as a new generator service and wire it into the CLI's `--format` switch and the Agent's `/export` command.

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

## Plugins are out-of-tree

WinSentinel uses a multi-publisher plugin architecture. **No plugin
implementations may be added to this repo** — not the official `winsentinel-pro`
plugin, not 3rd-party plugins, not internal plugins, none. `winsentinel-pro` is
just one such external plugin and lives in its own private repo. Every other
plugin lives in its own repo too.

Concretely:

- The MIT core (this repo) ships ONLY plugin **interfaces**
  (`src/WinSentinel.Core/Plugins/`), the **trust + signature loader**
  (`PluginHost`), and the **trust store** (`TrustedPublisherStore`).
- Concrete plugin implementations (PDF/DOCX exporters, monitor daemons, fleet
  clients, compliance mappers, schedulers, etc.) belong in their own repos,
  signed with their publisher's Ed25519 key, and discovered at runtime under
  `%LOCALAPPDATA%\WinSentinel\plugins\`.
- `scripts/check-no-pro-code.ps1` enforces this in CI: PRs that add concrete
  plugin impls under `src/`, smuggle inline `LicenseManager.IsPro` /
  `TryRequirePro` / `GetStatus` branches into feature code, or embed a
  `plugin.json` resource into a core csproj will be rejected automatically.
- See [`docs/CREATING-PLUGINS.md`](docs/CREATING-PLUGINS.md) for the plugin
  author guide, and [`docs/plugin-key-setup.md`](docs/plugin-key-setup.md) for
  the WinSentinel-project signing-key runbook (founder-only).
