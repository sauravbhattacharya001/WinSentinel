# Extending WinSentinel

This guide walks through adding custom audit modules and agent monitors. WinSentinel is designed to be extensible — both the audit engine and the agent use a simple interface-based plugin system.

## Adding a Custom Audit Module

Audit modules live in `src/WinSentinel.Core/Audits/` and implement `IAuditModule`. Each module scans one aspect of Windows security and returns findings.

### Step 1: Create the Module Class

Create a new file in `src/WinSentinel.Core/Audits/`:

```csharp
// src/WinSentinel.Core/Audits/DnsAudit.cs

using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits DNS configuration for security issues.
/// </summary>
public class DnsAudit : IAuditModule
{
    public string Name => "DNS Security";
    public string Category => "DNS";
    public string Description => "Checks DNS configuration for security issues like DNS-over-HTTPS status, "
                               + "suspicious DNS servers, and DNS cache poisoning vectors.";

    public async Task<AuditResult> RunAuditAsync(CancellationToken cancellationToken = default)
    {
        var result = new AuditResult
        {
            ModuleName = Name,
            Category = Category,
            StartTime = DateTimeOffset.UtcNow
        };

        try
        {
            await CheckDnsServers(result, cancellationToken);
            await CheckDnsOverHttps(result, cancellationToken);
            await CheckDnsCachePoisoning(result, cancellationToken);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    private async Task CheckDnsServers(AuditResult result, CancellationToken ct)
    {
        // Use ShellHelper or WmiHelper to query DNS configuration
        var output = await Helpers.ShellHelper.RunAsync(
            "powershell",
            "-NoProfile -Command \"Get-DnsClientServerAddress | ConvertTo-Json\"",
            ct);

        // Parse and analyze...

        // Report findings using the static factory methods:
        result.Findings.Add(Finding.Pass(
            title: "DNS servers configured",
            description: "System is using well-known DNS servers (8.8.8.8, 1.1.1.1)",
            category: Category));

        // Or report issues:
        result.Findings.Add(Finding.Warning(
            title: "DNS-over-HTTPS not enabled",
            description: "DNS queries are sent in plaintext, allowing network eavesdropping.",
            category: Category,
            remediation: "Enable DNS-over-HTTPS in Windows Settings > Network & Internet > DNS",
            fixCommand: "Set-DnsClientDohServerAddress -ServerAddress '8.8.8.8' -DohTemplate 'https://dns.google/dns-query' -AllowFallbackToUdp $true"));
    }

    // ... more check methods
}
```

### Step 2: Register the Module

Add it to the `AuditEngine` constructor in `src/WinSentinel.Core/Services/AuditEngine.cs`:

```csharp
_modules = new List<IAuditModule>
{
    new FirewallAudit(),
    new UpdateAudit(),
    // ... existing modules ...
    new EventLogAudit(),
    new DnsAudit(),  // ← Add your module here
};
```

### Step 3: Write Tests

Create a test file in `tests/WinSentinel.Tests/Audits/`:

```csharp
// tests/WinSentinel.Tests/Audits/DnsAuditTests.cs

using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

public class DnsAuditTests
{
    [Fact]
    public async Task RunAudit_ReturnsResult()
    {
        var audit = new DnsAudit();
        var result = await audit.RunAuditAsync();

        Assert.Equal("DNS", result.Category);
        Assert.True(result.Success);
        Assert.NotEmpty(result.Findings);
    }

    [Fact]
    public void Module_HasCorrectMetadata()
    {
        var audit = new DnsAudit();

        Assert.Equal("DNS Security", audit.Name);
        Assert.Equal("DNS", audit.Category);
        Assert.False(string.IsNullOrWhiteSpace(audit.Description));
    }

    [Fact]
    public async Task Score_IsWithinValidRange()
    {
        var audit = new DnsAudit();
        var result = await audit.RunAuditAsync();

        Assert.InRange(result.Score, 0, 100);
    }
}
```

### Key Conventions for Audit Modules

1. **Use `Finding` factory methods** — `Finding.Pass()`, `Finding.Warning()`, `Finding.Critical()`, `Finding.Info()`. They ensure consistent structure.

2. **Always include `category`** — Match your module's `Category` property.

3. **Provide `remediation` text** — Human-readable instructions for manual fixing.

4. **Provide `fixCommand` when possible** — A PowerShell command that resolves the finding. This enables the CLI `--fix-all` feature and the dashboard's one-click fix.

5. **Handle errors gracefully** — Wrap risky operations in try/catch. Set `result.Success = false` and `result.Error` for unrecoverable failures. Individual check failures should add an Info finding rather than crashing the whole module.

6. **Use helpers** — `ShellHelper.RunAsync()` for shell commands, `PowerShellHelper` for PowerShell, `RegistryHelper` for registry reads, `WmiHelper` for WMI queries. These handle error cases and timeouts.

7. **Respect cancellation** — Pass `CancellationToken` through to async operations.

### Scoring Impact

Your findings affect the module's score automatically:

| Severity | Score Deduction |
|:---:|:---:|
| Critical | -20 points |
| Warning | -5 points |
| Info | 0 (informational only) |
| Pass | 0 (positive signal) |

The module score starts at 100 and deductions are subtracted. The overall system score is the average of all module scores.

---

## Adding a Custom Agent Monitor

Agent monitors live in `src/WinSentinel.Agent/Modules/` and implement `IAgentModule`. They run continuously in the background and emit `ThreatEvent` objects when they detect suspicious activity.

### Step 1: Create the Monitor

```csharp
// src/WinSentinel.Agent/Modules/UsbMonitorModule.cs

using Microsoft.Extensions.Logging;

namespace WinSentinel.Agent.Modules;

/// <summary>
/// Monitors USB device connections for suspicious activity.
/// </summary>
public class UsbMonitorModule : IAgentModule
{
    private readonly ILogger<UsbMonitorModule> _logger;
    private readonly Action<ThreatEvent> _onThreat;
    private CancellationTokenSource? _cts;
    private Task? _monitorTask;

    public string Name => "USB Monitor";
    public bool IsActive { get; private set; }

    public UsbMonitorModule(ILogger<UsbMonitorModule> logger, Action<ThreatEvent> onThreat)
    {
        _logger = logger;
        _onThreat = onThreat;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _monitorTask = MonitorLoop(_cts.Token);
        IsActive = true;
        _logger.LogInformation("USB Monitor started");
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _cts?.Cancel();
        if (_monitorTask != null)
            await _monitorTask;
        IsActive = false;
        _logger.LogInformation("USB Monitor stopped");
    }

    private async Task MonitorLoop(CancellationToken ct)
    {
        var knownDevices = new HashSet<string>();

        while (!ct.IsCancellationRequested)
        {
            try
            {
                // Query connected USB devices (WMI or SetupAPI)
                var currentDevices = GetConnectedUsbDevices();

                foreach (var device in currentDevices)
                {
                    if (knownDevices.Add(device.Id))
                    {
                        // New device detected
                        _onThreat(new ThreatEvent
                        {
                            Source = "UsbMonitor",
                            Severity = ClassifyDevice(device),
                            Title = $"USB device connected: {device.Name}",
                            Description = $"New USB device '{device.Name}' (VID:{device.VendorId} PID:{device.ProductId}) "
                                        + $"connected at {DateTimeOffset.UtcNow:HH:mm:ss}",
                            AutoFixable = false
                        });
                    }
                }

                await Task.Delay(TimeSpan.FromSeconds(5), ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "USB monitor error");
                await Task.Delay(TimeSpan.FromSeconds(30), ct);
            }
        }
    }

    // ... device query and classification methods
}
```

### Step 2: Register the Monitor

Add it to `AgentService` where modules are initialized. The pattern varies, but typically:

```csharp
// In AgentService.cs or wherever modules are registered
var usbMonitor = new UsbMonitorModule(
    loggerFactory.CreateLogger<UsbMonitorModule>(),
    threat => agentBrain.ProcessThreat(threat));

_modules.Add(usbMonitor);
```

### Step 3: Write Tests

```csharp
// tests/WinSentinel.Tests/Agent/UsbMonitorModuleTests.cs

public class UsbMonitorModuleTests
{
    [Fact]
    public async Task StartStop_SetsIsActive()
    {
        var threats = new List<ThreatEvent>();
        var logger = new NullLogger<UsbMonitorModule>();
        var monitor = new UsbMonitorModule(logger, t => threats.Add(t));

        await monitor.StartAsync(CancellationToken.None);
        Assert.True(monitor.IsActive);

        await monitor.StopAsync(CancellationToken.None);
        Assert.False(monitor.IsActive);
    }

    [Fact]
    public void Name_IsSet()
    {
        var monitor = new UsbMonitorModule(
            new NullLogger<UsbMonitorModule>(), _ => { });
        Assert.Equal("USB Monitor", monitor.Name);
    }
}
```

### Key Conventions for Agent Monitors

1. **Emit `ThreatEvent` via the callback** — Don't try to handle threats yourself. The `AgentBrain` handles correlation, policy evaluation, and response.

2. **Use appropriate severity levels:**
   - `ThreatSeverity.Info` — Normal but notable activity
   - `ThreatSeverity.Low` — Unusual but probably benign
   - `ThreatSeverity.Medium` — Suspicious, worth investigating
   - `ThreatSeverity.High` — Likely malicious
   - `ThreatSeverity.Critical` — Confirmed threat requiring immediate action

3. **Set `AutoFixable`** — If your monitor can describe a fix command, set `AutoFixable = true` and populate `FixCommand`.

4. **Handle graceful shutdown** — Always respect the `CancellationToken`. Clean up resources in `StopAsync`.

5. **Use polling intervals wisely** — High-frequency polling (< 1s) can impact system performance. Most monitors use 3-10 second intervals.

6. **Log at appropriate levels** — Use `LogInformation` for lifecycle events, `LogWarning` for recoverable issues, `LogError` for failures that affect monitoring.

---

## Adding CLI Support for Your Module

If you add a new audit module, the CLI automatically picks it up (it uses `AuditEngine.Modules`). However, to support `--modules yourmodule`:

The `CliParser` matches module names case-insensitively against `IAuditModule.Category`. Ensure your module's `Category` is a single lowercase-friendly word (e.g., "dns", "usb") for easy CLI use:

```bash
winsentinel --audit --modules firewall,dns,network
```

---

## Adding a New Chat Command

Chat commands are handled in `src/WinSentinel.Agent/Services/ChatHandler.cs`. To add a new command:

1. Add a pattern match in the command router
2. Implement the handler method
3. Return a `ChatResponsePayload` with appropriate `Category`, `Text`, `SuggestedActions`, etc.

The chat handler supports both exact commands and natural language intent matching.

---

## Helper Utilities Reference

### ShellHelper

```csharp
// Run a command and get output
string output = await ShellHelper.RunAsync("cmd.exe", "/c ipconfig /all", ct);

// Run and get exit code
(string output, int exitCode) = await ShellHelper.RunWithExitCodeAsync("netsh", "advfirewall show allprofiles", ct);
```

### RegistryHelper

```csharp
// Read a registry value
object? value = RegistryHelper.GetValue(
    @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    "EnableLUA");

// Check if key exists
bool exists = RegistryHelper.KeyExists(@"HKLM\SOFTWARE\WinSentinel");
```

### PowerShellHelper

```csharp
// Run PowerShell command
string output = await PowerShellHelper.RunAsync(
    "Get-MpPreference | Select-Object DisableRealtimeMonitoring | ConvertTo-Json",
    ct);
```

### WmiHelper

```csharp
// Query WMI
var results = WmiHelper.Query("SELECT * FROM Win32_OperatingSystem");
string osVersion = results.FirstOrDefault()?["Version"]?.ToString() ?? "";
```

---

## Build & Test

```powershell
# Build the full solution
dotnet build WinSentinel.sln -p:Platform=x64

# Build just Core (fast iteration for audit modules)
dotnet build src/WinSentinel.Core

# Run all tests
dotnet test -p:Platform=x64

# Run specific test class
dotnet test -p:Platform=x64 --filter "FullyQualifiedName~DnsAuditTests"

# Run tests with detailed output
dotnet test -p:Platform=x64 --verbosity normal
```

**Note:** The WPF App project requires `-p:Platform=x64` (or x86/ARM64). Core, Agent, and CLI build under AnyCPU, so you can iterate faster by building just those.

---

## Checklist for New Modules

- [ ] Implements `IAuditModule` (audit) or `IAgentModule` (monitor)
- [ ] Registered in `AuditEngine` or `AgentService`
- [ ] Has xUnit tests covering basic functionality
- [ ] Uses `Finding` factory methods with proper severity, remediation, and fixCommand
- [ ] Handles errors gracefully (no unhandled exceptions)
- [ ] Respects `CancellationToken`
- [ ] XML doc comments on public API
- [ ] Module name and category are descriptive and unique
