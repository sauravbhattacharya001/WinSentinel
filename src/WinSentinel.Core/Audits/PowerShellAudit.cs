using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;
using Microsoft.Win32;
using PowerShellState = WinSentinel.Core.Audits.PowerShellSecurityAnalyzer.PowerShellState;

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
/// - Tampered PowerShell profile scripts (profile.ps1 persistence, T1546.013)
///
/// This module owns only data collection from the live system. Every security
/// decision (the thresholds that turn collected state into findings) lives in the
/// pure, unit-tested <see cref="PowerShellSecurityAnalyzer"/>. Mirrors the
/// BrowserAudit / BrowserSecurityAnalyzer split.
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
    /// Kept for backwards compatibility; the source of truth is
    /// <see cref="PowerShellSecurityAnalyzer.InsecurePolicies"/>.
    /// </summary>
    public static IReadOnlySet<string> InsecurePolicies => PowerShellSecurityAnalyzer.InsecurePolicies;

    /// <summary>
    /// Execution policies considered acceptable.
    /// Kept for backwards compatibility; the source of truth is
    /// <see cref="PowerShellSecurityAnalyzer.SecurePolicies"/>.
    /// </summary>
    public static IReadOnlySet<string> SecurePolicies => PowerShellSecurityAnalyzer.SecurePolicies;

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
        CollectProfilesState(state);

        return state;
    }

    // ── Analysis (delegates to the pure analyzer) ───────────────

    /// <summary>
    /// Analyzes a <see cref="PowerShellState"/> and populates findings by delegating
    /// to <see cref="PowerShellSecurityAnalyzer.Analyze"/>. Kept as a thin wrapper so
    /// existing callers/tests keep working; the analyzer holds the pure logic.
    /// </summary>
    public void AnalyzeState(PowerShellState state, AuditResult result)
    {
        result.Findings.AddRange(PowerShellSecurityAnalyzer.Analyze(state));
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

        // Effective = first non-Undefined scope (highest precedence).
        state.EffectivePolicy = PowerShellSecurityAnalyzer.ResolveEffectivePolicy(state);
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
                // Distinguish an explicit 0 (someone turned it OFF = tamper signal)
                // from an absent value (never configured = hygiene gap).
                state.ScriptBlockLoggingExplicitlyDisabled = val is int d && d == 0;
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
                state.ModuleLoggingExplicitlyDisabled = val is int d && d == 0;

                // ModuleNames subkey holds the per-module logging scope. CIS L1
                // requires a single "*" wildcard entry so every module is logged;
                // the analyzer flags an enabled-but-scoped config as incomplete
                // coverage. Values are stored as name=value pairs (typically "*"="*").
                try
                {
                    using var namesKey = key.OpenSubKey("ModuleNames");
                    if (namesKey != null)
                    {
                        foreach (var name in namesKey.GetValueNames())
                        {
                            if (!string.IsNullOrWhiteSpace(name))
                                state.ModuleLoggingNames.Add(name);
                        }
                    }
                }
                catch { /* Access denied */ }
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
                var hdr = key.GetValue("EnableInvocationHeader");
                state.TranscriptionInvocationHeaderEnabled = hdr is int h && h == 1;
            }
        }
        catch { /* Access denied */ }

        // Protected Event Logging (encrypts sensitive event-log content via CMS).
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging");
            if (key != null)
            {
                var val = key.GetValue("EnableProtectedEventLogging");
                state.ProtectedEventLoggingEnabled = val is int p && p == 1;
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

        // AMSI kill switch: SOFTWARE\Microsoft\Windows Script\Settings\AmsiEnable = 0
        // disables AMSI content scanning for the Windows Script Host / PowerShell
        // console host while leaving the provider registered. Check both HKLM (all
        // users) and HKCU (current user); either being an explicit 0 is the bypass.
        var disabledHives = new List<string>();
        CheckAmsiEnableHive(Registry.LocalMachine, "HKLM", disabledHives);
        CheckAmsiEnableHive(Registry.CurrentUser, "HKCU", disabledHives);
        if (disabledHives.Count > 0)
        {
            state.AmsiDisabledViaRegistry = true;
            state.AmsiDisableRegistryScope = string.Join(", ", disabledHives);
        }
    }

    /// <summary>
    /// Reads <c>SOFTWARE\Microsoft\Windows Script\Settings\AmsiEnable</c> under the
    /// given root hive and, when the value is present and explicitly 0, records the
    /// hive label. An absent value (the default) or any non-zero value is treated as
    /// "not disabled" so a machine that never touched the setting does not false-alarm.
    /// </summary>
    private static void CheckAmsiEnableHive(RegistryKey root, string label, List<string> disabledHives)
    {
        try
        {
            using var key = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows Script\Settings");
            if (key == null) return;
            var val = key.GetValue("AmsiEnable");
            if (val is int i && i == 0)
                disabledHives.Add(label);
        }
        catch { /* Access denied — treat as not-disabled to avoid false alarms */ }
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

        // Check AllowUnencrypted on the service (server) and client sides. WinRM
        // exposes these under the WSMan: PSDrive; 'true'/'false' string values.
        var svcUnenc = await ShellHelper.RunPowerShellAsync(
            "(Get-Item WSMan:\\localhost\\Service\\AllowUnencrypted -ErrorAction SilentlyContinue).Value", ct);
        state.WinRmServiceAllowUnencrypted =
            string.Equals(svcUnenc.Trim(), "true", StringComparison.OrdinalIgnoreCase);

        var cliUnenc = await ShellHelper.RunPowerShellAsync(
            "(Get-Item WSMan:\\localhost\\Client\\AllowUnencrypted -ErrorAction SilentlyContinue).Value", ct);
        state.WinRmClientAllowUnencrypted =
            string.Equals(cliUnenc.Trim(), "true", StringComparison.OrdinalIgnoreCase);
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

    /// <summary>
    /// Collects the PowerShell profile scripts (profile.ps1) that exist on disk so the
    /// analyzer can inspect them for tampering. Covers all four well-known profile
    /// scopes for both Windows PowerShell (5.x) and PowerShell 7+ (pwsh):
    /// AllUsersAllHosts, AllUsersCurrentHost, CurrentUserAllHosts, CurrentUserCurrentHost.
    /// Only reads files that exist; unreadable files are recorded with null content so
    /// the analyzer can still note a machine-wide profile's presence.
    /// </summary>
    private void CollectProfilesState(PowerShellState state)
    {
        var profiles = new List<PowerShellSecurityAnalyzer.PowerShellProfileInfo>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string? path, string scope, bool machineWide)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            if (!seen.Add(path)) return;               // de-dupe (WinPS + pwsh share $PSHOME rarely, but be safe)
            try
            {
                if (!System.IO.File.Exists(path)) return;
            }
            catch { return; }

            string? content = null;
            try { content = System.IO.File.ReadAllText(path); }
            catch { /* locked / access denied - still record presence with null content */ }

            profiles.Add(new PowerShellSecurityAnalyzer.PowerShellProfileInfo
            {
                Path = path,
                Scope = scope,
                IsMachineWide = machineWide,
                Content = content
            });
        }

        // Machine-wide ($PSHOME) profiles - run for EVERY user.
        try
        {
            var winPsHome = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), // ...\System32
                "WindowsPowerShell", "v1.0");
            Add(System.IO.Path.Combine(winPsHome, "profile.ps1"),
                "AllUsersAllHosts (Windows PowerShell)", machineWide: true);
            Add(System.IO.Path.Combine(winPsHome, "Microsoft.PowerShell_profile.ps1"),
                "AllUsersCurrentHost (Windows PowerShell)", machineWide: true);
        }
        catch { /* ignored */ }

        try
        {
            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (!string.IsNullOrEmpty(pf))
            {
                var pwshHome = System.IO.Path.Combine(pf, "PowerShell", "7");
                Add(System.IO.Path.Combine(pwshHome, "profile.ps1"),
                    "AllUsersAllHosts (PowerShell 7)", machineWide: true);
                Add(System.IO.Path.Combine(pwshHome, "Microsoft.PowerShell_profile.ps1"),
                    "AllUsersCurrentHost (PowerShell 7)", machineWide: true);
            }
        }
        catch { /* ignored */ }

        // Per-user (Documents) profiles.
        try
        {
            var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            if (!string.IsNullOrEmpty(docs))
            {
                var winPsUser = System.IO.Path.Combine(docs, "WindowsPowerShell");
                Add(System.IO.Path.Combine(winPsUser, "profile.ps1"),
                    "CurrentUserAllHosts (Windows PowerShell)", machineWide: false);
                Add(System.IO.Path.Combine(winPsUser, "Microsoft.PowerShell_profile.ps1"),
                    "CurrentUserCurrentHost (Windows PowerShell)", machineWide: false);

                var pwshUser = System.IO.Path.Combine(docs, "PowerShell");
                Add(System.IO.Path.Combine(pwshUser, "profile.ps1"),
                    "CurrentUserAllHosts (PowerShell 7)", machineWide: false);
                Add(System.IO.Path.Combine(pwshUser, "Microsoft.PowerShell_profile.ps1"),
                    "CurrentUserCurrentHost (PowerShell 7)", machineWide: false);
            }
        }
        catch { /* ignored */ }

        state.Profiles = profiles;
    }
}
