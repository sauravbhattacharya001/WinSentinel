using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;
using Microsoft.Win32;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits PowerShell security configuration for risks including:
/// - Unrestricted execution policy allowing arbitrary script execution
/// - PowerShell v2 engine enabled (downgrade attack vector)
/// - Script block logging disabled (lack of command visibility)
/// - Module logging disabled (can't track loaded modules)
/// - Transcription logging disabled (no session transcripts)
/// - Constrained Language Mode not enforced
/// - AMSI provider registration issues
/// - PowerShell remoting (WinRM) exposure
/// </summary>
public class PowerShellAudit : IAuditModule
{
    public string Name => "PowerShell Security Audit";
    public string Category => "PowerShell";
    public string Description =>
        "Checks PowerShell execution policy, logging configuration, " +
        "language mode, AMSI status, and remoting exposure.";

    /// <summary>
    /// Execution policies considered insecure.
    /// </summary>
    public static readonly HashSet<string> InsecurePolicies =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "Unrestricted", "Bypass"
        };

    /// <summary>
    /// Execution policies considered acceptable.
    /// </summary>
    public static readonly HashSet<string> SecurePolicies =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "AllSigned", "RemoteSigned", "Restricted"
        };

    /// <summary>
    /// Data transfer object for PowerShell environment state.
    /// All checks operate on this record so they can be unit-tested
    /// without running real PowerShell commands.
    /// </summary>
    public sealed class PowerShellState
    {
        // Execution policy
        public string MachinePolicy { get; set; } = "Undefined";
        public string UserPolicy { get; set; } = "Undefined";
        public string ProcessPolicy { get; set; } = "Undefined";
        public string CurrentUserPolicy { get; set; } = "Undefined";
        public string LocalMachinePolicy { get; set; } = "Undefined";
        public string EffectivePolicy { get; set; } = "Undefined";

        // Logging
        public bool ScriptBlockLoggingEnabled { get; set; }
        public bool ModuleLoggingEnabled { get; set; }
        public bool TranscriptionEnabled { get; set; }
        public string? TranscriptionOutputDir { get; set; }

        // Language mode
        public string LanguageMode { get; set; } = "FullLanguage";

        // PowerShell v2
        public bool V2EngineInstalled { get; set; }

        // AMSI
        public bool AmsiProviderRegistered { get; set; } = true;

        // Remoting
        public bool WinRmRunning { get; set; }
        public bool WinRmPublicAccess { get; set; }
        public List<string> WinRmTrustedHosts { get; set; } = new();

        // PowerShell versions found
        public List<string> InstalledVersions { get; set; } = new();
    }

    // ── Public entry point ─────────────────────────────────────

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
            var state = await CollectStateAsync(cancellationToken);
            AnalyzeState(state, result);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    // ── Data collection (calls real system) ─────────────────────

    /// <summary>
    /// Collects the current PowerShell security state from the system.
    /// </summary>
    public async Task<PowerShellState> CollectStateAsync(CancellationToken ct = default)
    {
        var state = new PowerShellState();

        await CollectExecutionPolicy(state, ct);
        CollectLoggingConfig(state);
        await CollectLanguageMode(state, ct);
        CollectV2EngineState(state);
        CollectAmsiState(state);
        await CollectRemotingState(state, ct);
        CollectInstalledVersions(state);

        return state;
    }

    // ── Analysis (pure logic, testable) ─────────────────────────

    /// <summary>
    /// Analyzes a <see cref="PowerShellState"/> and populates findings.
    /// This method is pure logic—no I/O—so it can be called directly
    /// from tests with synthetic state objects.
    /// </summary>
    public void AnalyzeState(PowerShellState state, AuditResult result)
    {
        CheckExecutionPolicy(state, result);
        CheckScriptBlockLogging(state, result);
        CheckModuleLogging(state, result);
        CheckTranscription(state, result);
        CheckLanguageMode(state, result);
        CheckV2Engine(state, result);
        CheckAmsi(state, result);
        CheckRemoting(state, result);
        CheckVersions(state, result);
    }

    // ── Execution policy ────────────────────────────────────────

    private void CheckExecutionPolicy(PowerShellState state, AuditResult result)
    {
        var effective = state.EffectivePolicy;

        if (InsecurePolicies.Contains(effective))
        {
            result.Findings.Add(Finding.Critical(
                $"Execution Policy: {effective}",
                $"The effective PowerShell execution policy is '{effective}', " +
                "which allows running any script without restriction. " +
                "Attackers commonly use unrestricted policies to execute malicious scripts.",
                Category,
                "Set execution policy to RemoteSigned or AllSigned.",
                "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"));
        }
        else if (string.Equals(effective, "Undefined", StringComparison.OrdinalIgnoreCase))
        {
            // Check scopes — if machine/user are both Undefined, 
            // Windows defaults to Restricted (safe on client) but it's
            // better to be explicit
            if (string.Equals(state.LocalMachinePolicy, "Undefined", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(state.CurrentUserPolicy, "Undefined", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add(Finding.Info(
                    "Execution Policy: Not Explicitly Set",
                    "No execution policy is explicitly configured. " +
                    "Windows defaults to Restricted on client SKUs, but " +
                    "setting it explicitly prevents ambiguity.",
                    Category,
                    "Set an explicit execution policy.",
                    "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"));
            }
        }
        else if (SecurePolicies.Contains(effective))
        {
            result.Findings.Add(Finding.Pass(
                $"Execution Policy: {effective}",
                $"The effective execution policy '{effective}' restricts script execution appropriately.",
                Category));
        }

        // Check for Bypass at any scope (even if not effective)
        if (InsecurePolicies.Contains(state.MachinePolicy))
        {
            result.Findings.Add(Finding.Warning(
                $"GPO Machine Policy: {state.MachinePolicy}",
                $"Group Policy sets the machine-level execution policy to '{state.MachinePolicy}'. " +
                "This overrides all other scopes.",
                Category,
                "Review the Group Policy setting: Computer Configuration > Administrative Templates > " +
                "Windows Components > Windows PowerShell > Turn on Script Execution."));
        }
    }

    // ── Script block logging ────────────────────────────────────

    private void CheckScriptBlockLogging(PowerShellState state, AuditResult result)
    {
        if (!state.ScriptBlockLoggingEnabled)
        {
            result.Findings.Add(Finding.Warning(
                "Script Block Logging Disabled",
                "PowerShell script block logging is not enabled. " +
                "Without it, obfuscated commands and dynamic code cannot be " +
                "captured in the event log for forensic analysis.",
                Category,
                "Enable via Group Policy or registry: " +
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1",
                @"New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' " +
                "-Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Script Block Logging Enabled",
                "PowerShell script block logging is enabled. " +
                "Obfuscated and dynamically generated commands are captured in event logs.",
                Category));
        }
    }

    // ── Module logging ──────────────────────────────────────────

    private void CheckModuleLogging(PowerShellState state, AuditResult result)
    {
        if (!state.ModuleLoggingEnabled)
        {
            result.Findings.Add(Finding.Warning(
                "Module Logging Disabled",
                "PowerShell module logging is not enabled. " +
                "Module logging records pipeline execution details for all " +
                "modules, aiding in detection of malicious module usage.",
                Category,
                "Enable via Group Policy or registry: " +
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\EnableModuleLogging = 1",
                @"New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' " +
                "-Name EnableModuleLogging -Value 1 -PropertyType DWord -Force"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Module Logging Enabled",
                "PowerShell module logging is enabled, providing pipeline execution visibility.",
                Category));
        }
    }

    // ── Transcription ───────────────────────────────────────────

    private void CheckTranscription(PowerShellState state, AuditResult result)
    {
        if (!state.TranscriptionEnabled)
        {
            result.Findings.Add(Finding.Info(
                "PowerShell Transcription Disabled",
                "Automatic transcription is not enabled. " +
                "Transcription records full session input/output to text files, " +
                "providing a complete audit trail.",
                Category,
                "Enable via Group Policy or registry: " +
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting = 1",
                @"New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' " +
                "-Name EnableTranscripting -Value 1 -PropertyType DWord -Force"));
        }
        else
        {
            var dirNote = string.IsNullOrEmpty(state.TranscriptionOutputDir)
                ? " (output directory not configured — defaults to user's Documents)"
                : $" (output directory: {state.TranscriptionOutputDir})";

            result.Findings.Add(Finding.Pass(
                "PowerShell Transcription Enabled",
                "Automatic transcription is enabled" + dirNote + ".",
                Category));
        }
    }

    // ── Language mode ───────────────────────────────────────────

    private void CheckLanguageMode(PowerShellState state, AuditResult result)
    {
        if (string.Equals(state.LanguageMode, "FullLanguage", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Info(
                "Language Mode: FullLanguage",
                "PowerShell is running in FullLanguage mode, which allows " +
                "unrestricted access to .NET types and COM objects. " +
                "Constrained Language Mode limits the attack surface.",
                Category,
                "Consider enforcing Constrained Language Mode via AppLocker or WDAC policies."));
        }
        else if (string.Equals(state.LanguageMode, "ConstrainedLanguage", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Pass(
                "Language Mode: ConstrainedLanguage",
                "PowerShell is running in Constrained Language Mode, " +
                "limiting access to sensitive .NET types and reducing attack surface.",
                Category));
        }
        else
        {
            result.Findings.Add(Finding.Info(
                $"Language Mode: {state.LanguageMode}",
                $"PowerShell language mode is set to '{state.LanguageMode}'.",
                Category));
        }
    }

    // ── PowerShell v2 engine ────────────────────────────────────

    private void CheckV2Engine(PowerShellState state, AuditResult result)
    {
        if (state.V2EngineInstalled)
        {
            result.Findings.Add(Finding.Warning(
                "PowerShell v2 Engine Installed",
                "The legacy PowerShell v2 engine is installed. " +
                "Attackers use 'powershell -Version 2' to downgrade to v2, " +
                "which bypasses AMSI, script block logging, and Constrained " +
                "Language Mode protections.",
                Category,
                "Disable the PowerShell v2 engine via Windows Features.",
                "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "PowerShell v2 Engine Disabled",
                "The legacy PowerShell v2 engine is not installed, " +
                "preventing downgrade attacks that bypass modern security controls.",
                Category));
        }
    }

    // ── AMSI ────────────────────────────────────────────────────

    private void CheckAmsi(PowerShellState state, AuditResult result)
    {
        if (!state.AmsiProviderRegistered)
        {
            result.Findings.Add(Finding.Critical(
                "AMSI Provider Not Registered",
                "The Anti-Malware Scan Interface (AMSI) provider is not " +
                "registered in the system. AMSI enables real-time scanning " +
                "of PowerShell scripts, VBScript, JScript, and other scripting " +
                "engines. A missing AMSI provider may indicate tampering.",
                Category,
                "Ensure Windows Defender or another AMSI-compatible antivirus is installed and running.",
                "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "AMSI Provider Registered",
                "An AMSI provider is registered, enabling real-time script " +
                "content scanning for malicious patterns.",
                Category));
        }
    }

    // ── Remoting ────────────────────────────────────────────────

    private void CheckRemoting(PowerShellState state, AuditResult result)
    {
        if (!state.WinRmRunning)
        {
            result.Findings.Add(Finding.Pass(
                "WinRM Service Not Running",
                "The Windows Remote Management (WinRM) service is not running, " +
                "reducing the attack surface for remote PowerShell sessions.",
                Category));
            return;
        }

        result.Findings.Add(Finding.Info(
            "WinRM Service Running",
            "The WinRM service is running, enabling PowerShell remoting.",
            Category));

        // Check trusted hosts — wildcard is dangerous
        if (state.WinRmTrustedHosts.Any(h =>
                h == "*" || string.Equals(h, "any", StringComparison.OrdinalIgnoreCase)))
        {
            result.Findings.Add(Finding.Critical(
                "WinRM TrustedHosts: Wildcard (*)",
                "WinRM TrustedHosts is set to '*', allowing connections " +
                "to any remote host without certificate validation. " +
                "This enables man-in-the-middle attacks.",
                Category,
                "Restrict TrustedHosts to specific hosts or use HTTPS transport.",
                "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value '' -Force"));
        }
        else if (state.WinRmTrustedHosts.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                $"WinRM TrustedHosts: {state.WinRmTrustedHosts.Count} entries",
                $"TrustedHosts configured: {string.Join(", ", state.WinRmTrustedHosts.Take(5))}",
                Category,
                "Review trusted hosts list and ensure all entries are expected."));
        }

        if (state.WinRmPublicAccess)
        {
            result.Findings.Add(Finding.Warning(
                "WinRM May Be Accessible on Public Networks",
                "WinRM firewall rules allow connections on Public network profiles. " +
                "This could expose PowerShell remoting on untrusted networks.",
                Category,
                "Restrict WinRM firewall rules to Domain and Private profiles only.",
                @"Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-PUBLIC' -Enabled False"));
        }
    }

    // ── Installed versions ──────────────────────────────────────

    private void CheckVersions(PowerShellState state, AuditResult result)
    {
        if (state.InstalledVersions.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                $"PowerShell Versions Installed: {state.InstalledVersions.Count}",
                $"Detected PowerShell versions: {string.Join(", ", state.InstalledVersions)}",
                Category));
        }
    }

    // ── Collection helpers (I/O) ────────────────────────────────

    private async Task CollectExecutionPolicy(PowerShellState state, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"Get-ExecutionPolicy -List | ForEach-Object { 
                '{0}|{1}' -f $_.Scope, $_.ExecutionPolicy 
            }", ct);

        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = line.Split('|', 2);
            if (parts.Length != 2) continue;

            var scope = parts[0].Trim();
            var policy = parts[1].Trim();

            switch (scope)
            {
                case "MachinePolicy": state.MachinePolicy = policy; break;
                case "UserPolicy": state.UserPolicy = policy; break;
                case "Process": state.ProcessPolicy = policy; break;
                case "CurrentUser": state.CurrentUserPolicy = policy; break;
                case "LocalMachine": state.LocalMachinePolicy = policy; break;
            }
        }

        // Effective = first non-Undefined scope (highest precedence)
        var scopes = new[] { state.MachinePolicy, state.UserPolicy, state.ProcessPolicy,
                             state.CurrentUserPolicy, state.LocalMachinePolicy };
        state.EffectivePolicy = scopes.FirstOrDefault(p =>
            !string.Equals(p, "Undefined", StringComparison.OrdinalIgnoreCase)) ?? "Undefined";
    }

    private void CollectLoggingConfig(PowerShellState state)
    {
        // Script block logging
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging");
            if (key != null)
            {
                var val = key.GetValue("EnableScriptBlockLogging");
                state.ScriptBlockLoggingEnabled = val is int i && i == 1;
            }
        }
        catch { /* Access denied */ }

        // Module logging
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging");
            if (key != null)
            {
                var val = key.GetValue("EnableModuleLogging");
                state.ModuleLoggingEnabled = val is int i && i == 1;
            }
        }
        catch { /* Access denied */ }

        // Transcription
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription");
            if (key != null)
            {
                var val = key.GetValue("EnableTranscripting");
                state.TranscriptionEnabled = val is int i && i == 1;
                state.TranscriptionOutputDir = key.GetValue("OutputDirectory")?.ToString();
            }
        }
        catch { /* Access denied */ }
    }

    private async Task CollectLanguageMode(PowerShellState state, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            "$ExecutionContext.SessionState.LanguageMode", ct);
        if (!string.IsNullOrWhiteSpace(output))
            state.LanguageMode = output.Trim();
    }

    private void CollectV2EngineState(PowerShellState state)
    {
        try
        {
            // Check if PowerShell v2 Windows Feature is enabled
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine");
            if (key != null)
            {
                var version = key.GetValue("PowerShellVersion")?.ToString();
                if (version != null && version.StartsWith("2"))
                    state.V2EngineInstalled = true;
            }
        }
        catch { /* Access denied */ }

        // Also check via DISM feature state registry
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages");
            if (key != null)
            {
                var v2Package = key.GetSubKeyNames()
                    .FirstOrDefault(n => n.Contains("MicrosoftWindowsPowerShellV2",
                        StringComparison.OrdinalIgnoreCase));
                if (v2Package != null)
                {
                    using var pkgKey = key.OpenSubKey(v2Package);
                    var visibility = pkgKey?.GetValue("Visibility")?.ToString();
                    // Visibility=1 means installed; 2 means removed
                    if (visibility == "1")
                        state.V2EngineInstalled = true;
                }
            }
        }
        catch { /* Access denied */ }
    }

    private void CollectAmsiState(PowerShellState state)
    {
        try
        {
            // AMSI providers register under this CLSID
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\AMSI\Providers");
            state.AmsiProviderRegistered = key != null && key.GetSubKeyNames().Length > 0;
        }
        catch
        {
            // Can't read — assume present (don't false-alarm)
            state.AmsiProviderRegistered = true;
        }
    }

    private async Task CollectRemotingState(PowerShellState state, CancellationToken ct)
    {
        // Check WinRM service status
        var svcOutput = await ShellHelper.RunPowerShellAsync(
            "(Get-Service WinRM -ErrorAction SilentlyContinue).Status", ct);
        state.WinRmRunning = string.Equals(svcOutput.Trim(), "Running",
            StringComparison.OrdinalIgnoreCase);

        if (!state.WinRmRunning) return;

        // Check TrustedHosts
        var hostsOutput = await ShellHelper.RunPowerShellAsync(
            "(Get-Item WSMan:\\localhost\\Client\\TrustedHosts -ErrorAction SilentlyContinue).Value", ct);
        if (!string.IsNullOrWhiteSpace(hostsOutput))
        {
            state.WinRmTrustedHosts = hostsOutput.Trim()
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();
        }

        // Check for public profile firewall rules
        var fwOutput = await ShellHelper.RunPowerShellAsync(
            @"Get-NetFirewallRule -Name '*WinRM*' -ErrorAction SilentlyContinue | 
              Where-Object { $_.Enabled -eq 'True' -and $_.Profile -match 'Public' } | 
              Measure-Object | Select-Object -ExpandProperty Count", ct);
        state.WinRmPublicAccess = int.TryParse(fwOutput.Trim(), out int count) && count > 0;
    }

    private void CollectInstalledVersions(PowerShellState state)
    {
        var versions = new List<string>();

        // Windows PowerShell (5.x)
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine");
            var ver = key?.GetValue("PowerShellVersion")?.ToString();
            if (ver != null) versions.Add($"Windows PowerShell {ver}");
        }
        catch { /* ignored */ }

        // PowerShell 7+ (pwsh)
        try
        {
            var pwshPaths = new[]
            {
                @"C:\Program Files\PowerShell",
                @"C:\Program Files (x86)\PowerShell"
            };

            foreach (var basePath in pwshPaths)
            {
                if (!System.IO.Directory.Exists(basePath)) continue;
                foreach (var dir in System.IO.Directory.GetDirectories(basePath))
                {
                    var dirName = System.IO.Path.GetFileName(dir);
                    if (dirName != null && char.IsDigit(dirName[0]))
                        versions.Add($"PowerShell {dirName}");
                }
            }
        }
        catch { /* ignored */ }

        state.InstalledVersions = versions;
    }
}
