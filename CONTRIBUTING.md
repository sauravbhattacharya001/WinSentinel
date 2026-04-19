# Contributing to WinSentinel

Thank you for your interest in improving WinSentinel! Whether you're fixing a bug, adding an audit module, improving documentation, or suggesting ideas — contributions are welcome.

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

## Getting Started

1. **Fork** the repository
2. **Clone** your fork locally
3. **Create a branch** for your work (`git checkout -b feat/my-change`)
4. **Make changes**, add tests, verify the build
5. **Push** and open a Pull Request

## Development Setup

### Prerequisites

- **Windows 10/11** (WinSentinel is Windows-native)
- **.NET 8 SDK** — [download](https://dotnet.microsoft.com/download/dotnet/8.0)
- **Visual Studio 2022** (recommended) or **VS Code** with the C# Dev Kit
- **Git** — [download](https://git-scm.com/)

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

- `feat/description` — new features or audit modules
- `fix/description` — bug fixes
- `security/description` — security-related changes
- `docs/description` — documentation only
- `refactor/description` — code improvements without behavior change

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

### 4. Document It

Update the README's module table with your new audit.

## Testing

- **All new code must have tests.** Aim for meaningful coverage of the logic, not just line count.
- **Tests must pass on x64 platform**: `dotnet test -p:Platform=x64`
- **Don't depend on specific machine state**: Mock or abstract OS-dependent calls where feasible. Some audit modules inherently test the current machine — that's fine, but test the logic paths, not just "it ran."
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
3. **Fill out the PR template** — it covers type of change, components affected, testing, and security considerations
4. **Keep PRs focused** — one feature or fix per PR
5. **Update documentation** if your change affects usage or architecture

### What We Look For in Reviews

- **Correctness**: Does it do what it claims?
- **Security**: No new attack surface, inputs validated, no sensitive data exposed
- **Tests**: Meaningful tests that verify behavior
- **Performance**: No unnecessary allocations, I/O, or blocking in hot paths
- **Style**: Consistent with the existing codebase

## Coding Conventions

- **C# 12 / .NET 8** — use modern language features (file-scoped namespaces, primary constructors, etc.)
- **Nullable reference types** — enabled project-wide; don't suppress warnings without good reason
- **`InputSanitizer`** — all external input (file paths, registry keys, user text) must be sanitized before use
- **Async all the way** — audit modules use `async Task`; don't block on async code
- **XML doc comments** — on all public types and methods
- **No `#pragma warning disable`** without a comment explaining why
- **Constants over magic numbers**
- **`CancellationToken`** — accept and respect cancellation in long-running operations

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.**

Instead, use the [Security Report](https://github.com/sauravbhattacharya001/WinSentinel/security/advisories/new) form, or email the maintainer directly. Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

We take security seriously — this is a security tool, after all.

## Debugging & Troubleshooting

### Common Build Issues

| Problem | Fix |
|---------|-----|
| `Platform 'x64' not found` | Ensure you pass `-p:Platform=x64` to all `dotnet` commands |
| `WPF targets not found` | Install the **.NET Desktop Development** workload in VS Installer |
| `SQLite native interop` | Run `dotnet restore` again — the native binary may not have been extracted |
| Tests fail with `Access Denied` | Some audits need **Administrator** — right-click VS/terminal → Run as Admin |

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

Thank you for helping make Windows more secure! 🛡️
