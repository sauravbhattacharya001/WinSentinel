# Example WinSentinel Plugin

This is a minimal example showing how to write a community plugin for WinSentinel.

## Structure

- `ExampleAuditPlugin.cs` — implements `IWinSentinelPlugin` (the minimum contract)
- `plugin.json` — embedded manifest declaring the plugin's identity
- `ExamplePlugin.csproj` — standard .NET 8 class library referencing WinSentinel.Core

## Build

```pwsh
dotnet build
```

## Install

1. Build the DLL
2. Copy it to `%LOCALAPPDATA%\WinSentinel\plugins\`
3. Run `winsentinel plugin list` to verify

For signed distribution, see [docs/CREATING-PLUGINS.md](../../docs/CREATING-PLUGINS.md).

## Extend

Implement additional interfaces for more capabilities:
- `IReportExporter` — custom report formats (HTML, PDF, etc.)
- `IMonitorDaemon` — real-time monitoring
- `IComplianceMapper` — custom compliance frameworks
- `IScheduledScan` — scheduled audit logic
