# Getting Started

This guide walks you through installing WinSentinel and running your first security audit.

## Prerequisites

- **Windows 10 or 11** (x64)
- **.NET 8.0 Runtime** — [Download](https://dotnet.microsoft.com/download/dotnet/8.0)
- **Administrator access** — Required for full audit capabilities

## Installation

### Option 1: Quick Install (Recommended)

Download and run the installer script in an **elevated PowerShell**:

```powershell
# Download the latest release
Invoke-WebRequest -Uri "https://github.com/sauravbhattacharya001/WinSentinel/releases/latest" -OutFile install.ps1

# Or clone and install directly
git clone https://github.com/sauravbhattacharya001/WinSentinel.git
cd WinSentinel
.\Install-WinSentinel.ps1
```

### Option 2: Build from Source

```powershell
git clone https://github.com/sauravbhattacharya001/WinSentinel.git
cd WinSentinel
dotnet restore
dotnet build --configuration Release -p:Platform=x64
```

## Running Your First Audit

### CLI

```powershell
# Run a full security audit
winsentinel audit

# Run specific modules
winsentinel audit --modules defender,firewall,network

# Run with a compliance profile
winsentinel audit --profile cis

# Export results as JSON
winsentinel audit --format json --output report.json
```

### Desktop App

Launch `WinSentinel.App.exe` for the WPF interface with:
- Interactive chat control plane
- Real-time score visualization
- Module-by-module breakdown
- One-click remediation

## Understanding Results

WinSentinel produces a security score from **0-100** with letter grades:

| Score | Grade | Meaning |
|-------|-------|---------|
| 90-100 | A | Excellent — minimal issues |
| 80-89 | B | Good — minor improvements needed |
| 70-79 | C | Fair — several issues to address |
| 60-69 | D | Poor — significant vulnerabilities |
| 0-59 | F | Critical — immediate action needed |

Each audit finding includes:
- **Severity** (Critical, High, Medium, Low, Info)
- **Description** of the issue
- **Impact** assessment
- **Remediation steps** with PowerShell commands

## Next Steps

- [Architecture Guide](architecture.md) — Understand how WinSentinel works
- [CLI Reference](cli-reference.md) — Full CLI command reference
- [Extending WinSentinel](extending.md) — Create custom audit modules
- [Audit Modules](audit-modules.md) — Detailed module documentation
