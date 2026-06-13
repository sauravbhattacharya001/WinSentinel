using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for the <see cref="PowerShellAudit"/> module.
///
/// All PowerShell security decisions live here - the rules that turn collected raw
/// state (execution-policy scopes, logging/transcription registry flags, language
/// mode, the legacy v2 engine, AMSI provider registration, WinRM remoting exposure
/// and installed engine versions) into <see cref="Finding"/> objects.
///
/// Nothing here touches the registry, the filesystem, WMI, WinRM, the clock or the
/// console, so every security-relevant threshold can be unit tested directly with
/// synthetic <see cref="PowerShellState"/> instances. <see cref="PowerShellAudit"/>
/// owns only the collection of raw data and delegates every decision to this class.
///
/// Mirrors the established <see cref="BrowserSecurityAnalyzer"/> /
/// <see cref="EncryptionAnalyzer"/> / <see cref="IdentityCredentialAnalyzer"/> /
/// <see cref="EventLogAnalyzer"/> pattern.
/// </summary>
public static class PowerShellSecurityAnalyzer
{
    /// <summary>Category label shared with <see cref="PowerShellAudit"/>.</summary>
    public const string Category = "PowerShell";

    /// <summary>
    /// Execution policies considered insecure - they allow running any script
    /// without restriction (the classic attacker downgrade target).
    /// </summary>
    public static readonly IReadOnlySet<string> InsecurePolicies =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Unrestricted", "Bypass"
        };

    /// <summary>
    /// Execution policies considered acceptable on a client machine.
    /// </summary>
    public static readonly IReadOnlySet<string> SecurePolicies =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "AllSigned", "RemoteSigned", "Restricted"
        };

    private const string UndefinedPolicy = "Undefined";

    /// <summary>
    /// Data transfer object for PowerShell environment state. All checks operate on
    /// this record so they can be unit-tested without running real PowerShell
    /// commands or reading the registry.
    /// </summary>
    public sealed class PowerShellState
    {
        // Execution policy (per scope, plus the resolved effective policy)
        public string MachinePolicy { get; set; } = UndefinedPolicy;
        public string UserPolicy { get; set; } = UndefinedPolicy;
        public string ProcessPolicy { get; set; } = UndefinedPolicy;
        public string CurrentUserPolicy { get; set; } = UndefinedPolicy;
        public string LocalMachinePolicy { get; set; } = UndefinedPolicy;
        public string EffectivePolicy { get; set; } = UndefinedPolicy;

        // Logging
        public bool ScriptBlockLoggingEnabled { get; set; }
        public bool ModuleLoggingEnabled { get; set; }
        public bool TranscriptionEnabled { get; set; }
        public string? TranscriptionOutputDir { get; set; }

        // Language mode
        public string LanguageMode { get; set; } = "FullLanguage";

        // PowerShell v2 (downgrade attack vector)
        public bool V2EngineInstalled { get; set; }

        // AMSI
        public bool AmsiProviderRegistered { get; set; } = true;

        // Remoting (WinRM)
        public bool WinRmRunning { get; set; }
        public bool WinRmPublicAccess { get; set; }
        public List<string> WinRmTrustedHosts { get; set; } = new();

        // PowerShell versions found on disk / in the registry
        public List<string> InstalledVersions { get; set; } = new();
    }

    // ──────────────────────────────────────────────────────────────────────
    // Aggregate entry point
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Runs every PowerShell security check against <paramref name="state"/> and
    /// returns the findings in a stable order. Pure - no I/O.
    /// </summary>
    public static List<Finding> Analyze(PowerShellState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        var findings = new List<Finding>();
        findings.AddRange(CheckExecutionPolicy(state));
        findings.Add(CheckScriptBlockLogging(state));
        findings.Add(CheckModuleLogging(state));
        findings.Add(CheckTranscription(state));
        findings.Add(CheckLanguageMode(state));
        findings.Add(CheckV2Engine(state));
        findings.Add(CheckAmsi(state));
        findings.AddRange(CheckRemoting(state));
        var versions = CheckVersions(state);
        if (versions != null) findings.Add(versions);
        return findings;
    }

    private static bool IsUndefined(string? policy) =>
        string.IsNullOrWhiteSpace(policy) ||
        string.Equals(policy, UndefinedPolicy, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Resolves the effective execution policy from the per-scope values, honouring
    /// Windows precedence: MachinePolicy &gt; UserPolicy &gt; Process &gt;
    /// CurrentUser &gt; LocalMachine. Returns "Undefined" when every scope is unset.
    /// </summary>
    public static string ResolveEffectivePolicy(PowerShellState state)
    {
        var scopes = new[]
        {
            state.MachinePolicy, state.UserPolicy, state.ProcessPolicy,
            state.CurrentUserPolicy, state.LocalMachinePolicy
        };
        return scopes.FirstOrDefault(p => !IsUndefined(p)) ?? UndefinedPolicy;
    }

    // ── Execution policy ───────────────────────────────────────────────────

    /// <summary>
    /// Evaluates execution-policy posture. May emit up to two findings: one for the
    /// effective policy and a separate warning when GPO forces an insecure machine
    /// policy.
    /// </summary>
    public static List<Finding> CheckExecutionPolicy(PowerShellState state)
    {
        var findings = new List<Finding>();
        var effective = state.EffectivePolicy;

        if (InsecurePolicies.Contains(effective))
        {
            findings.Add(Finding.Critical(
                $"Execution Policy: {effective}",
                $"The effective PowerShell execution policy is '{effective}', " +
                "which allows running any script without restriction. " +
                "Attackers commonly use unrestricted policies to execute malicious scripts.",
                Category,
                "Set execution policy to RemoteSigned or AllSigned.",
                "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"));
        }
        else if (IsUndefined(effective))
        {
            // If machine/user are both Undefined, Windows defaults to Restricted on
            // client SKUs (safe) but it's better to be explicit.
            if (IsUndefined(state.LocalMachinePolicy) && IsUndefined(state.CurrentUserPolicy))
            {
                findings.Add(Finding.Info(
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
            findings.Add(Finding.Pass(
                $"Execution Policy: {effective}",
                $"The effective execution policy '{effective}' restricts script execution appropriately.",
                Category));
        }

        // Flag Bypass/Unrestricted forced by GPO at the machine scope (it overrides
        // all other scopes) even when it is already the effective policy.
        if (InsecurePolicies.Contains(state.MachinePolicy))
        {
            findings.Add(Finding.Warning(
                $"GPO Machine Policy: {state.MachinePolicy}",
                $"Group Policy sets the machine-level execution policy to '{state.MachinePolicy}'. " +
                "This overrides all other scopes.",
                Category,
                "Review the Group Policy setting: Computer Configuration > Administrative Templates > " +
                "Windows Components > Windows PowerShell > Turn on Script Execution."));
        }

        return findings;
    }

    // ── Script block logging ───────────────────────────────────────────────

    public static Finding CheckScriptBlockLogging(PowerShellState state)
    {
        if (!state.ScriptBlockLoggingEnabled)
        {
            return Finding.Warning(
                "Script Block Logging Disabled",
                "PowerShell script block logging is not enabled. " +
                "Without it, obfuscated commands and dynamic code cannot be " +
                "captured in the event log for forensic analysis.",
                Category,
                "Enable via Group Policy or registry: " +
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1",
                @"New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' " +
                "-Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force");
        }

        return Finding.Pass(
            "Script Block Logging Enabled",
            "PowerShell script block logging is enabled. " +
            "Obfuscated and dynamically generated commands are captured in event logs.",
            Category);
    }

    // ── Module logging ─────────────────────────────────────────────────────

    public static Finding CheckModuleLogging(PowerShellState state)
    {
        if (!state.ModuleLoggingEnabled)
        {
            return Finding.Warning(
                "Module Logging Disabled",
                "PowerShell module logging is not enabled. " +
                "Module logging records pipeline execution details for all " +
                "modules, aiding in detection of malicious module usage.",
                Category,
                "Enable via Group Policy or registry: " +
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\EnableModuleLogging = 1",
                @"New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' " +
                "-Name EnableModuleLogging -Value 1 -PropertyType DWord -Force");
        }

        return Finding.Pass(
            "Module Logging Enabled",
            "PowerShell module logging is enabled, providing pipeline execution visibility.",
            Category);
    }

    // ── Transcription ──────────────────────────────────────────────────────

    public static Finding CheckTranscription(PowerShellState state)
    {
        if (!state.TranscriptionEnabled)
        {
            return Finding.Info(
                "PowerShell Transcription Disabled",
                "Automatic transcription is not enabled. " +
                "Transcription records full session input/output to text files, " +
                "providing a complete audit trail.",
                Category,
                "Enable via Group Policy or registry: " +
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting = 1",
                @"New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' " +
                "-Name EnableTranscripting -Value 1 -PropertyType DWord -Force");
        }

        var dirNote = string.IsNullOrEmpty(state.TranscriptionOutputDir)
            ? " (output directory not configured - defaults to user's Documents)"
            : $" (output directory: {state.TranscriptionOutputDir})";

        return Finding.Pass(
            "PowerShell Transcription Enabled",
            "Automatic transcription is enabled" + dirNote + ".",
            Category);
    }

    // ── Language mode ──────────────────────────────────────────────────────

    public static Finding CheckLanguageMode(PowerShellState state)
    {
        if (string.Equals(state.LanguageMode, "FullLanguage", StringComparison.OrdinalIgnoreCase))
        {
            return Finding.Info(
                "Language Mode: FullLanguage",
                "PowerShell is running in FullLanguage mode, which allows " +
                "unrestricted access to .NET types and COM objects. " +
                "Constrained Language Mode limits the attack surface.",
                Category,
                "Consider enforcing Constrained Language Mode via AppLocker or WDAC policies.");
        }

        if (string.Equals(state.LanguageMode, "ConstrainedLanguage", StringComparison.OrdinalIgnoreCase))
        {
            return Finding.Pass(
                "Language Mode: ConstrainedLanguage",
                "PowerShell is running in Constrained Language Mode, " +
                "limiting access to sensitive .NET types and reducing attack surface.",
                Category);
        }

        return Finding.Info(
            $"Language Mode: {state.LanguageMode}",
            $"PowerShell language mode is set to '{state.LanguageMode}'.",
            Category);
    }

    // ── PowerShell v2 engine ───────────────────────────────────────────────

    public static Finding CheckV2Engine(PowerShellState state)
    {
        if (state.V2EngineInstalled)
        {
            return Finding.Warning(
                "PowerShell v2 Engine Installed",
                "The legacy PowerShell v2 engine is installed. " +
                "Attackers use 'powershell -Version 2' to downgrade to v2, " +
                "which bypasses AMSI, script block logging, and Constrained " +
                "Language Mode protections.",
                Category,
                "Disable the PowerShell v2 engine via Windows Features.",
                "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart");
        }

        return Finding.Pass(
            "PowerShell v2 Engine Disabled",
            "The legacy PowerShell v2 engine is not installed, " +
            "preventing downgrade attacks that bypass modern security controls.",
            Category);
    }

    // ── AMSI ───────────────────────────────────────────────────────────────

    public static Finding CheckAmsi(PowerShellState state)
    {
        if (!state.AmsiProviderRegistered)
        {
            return Finding.Critical(
                "AMSI Provider Not Registered",
                "The Anti-Malware Scan Interface (AMSI) provider is not " +
                "registered in the system. AMSI enables real-time scanning " +
                "of PowerShell scripts, VBScript, JScript, and other scripting " +
                "engines. A missing AMSI provider may indicate tampering.",
                Category,
                "Ensure Windows Defender or another AMSI-compatible antivirus is installed and running.",
                "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled");
        }

        return Finding.Pass(
            "AMSI Provider Registered",
            "An AMSI provider is registered, enabling real-time script " +
            "content scanning for malicious patterns.",
            Category);
    }

    // ── Remoting ───────────────────────────────────────────────────────────

    /// <summary>
    /// Evaluates WinRM remoting posture. Emits a single Pass when WinRM is stopped;
    /// otherwise an Info that it is running plus any TrustedHosts / public-profile
    /// warnings.
    /// </summary>
    public static List<Finding> CheckRemoting(PowerShellState state)
    {
        var findings = new List<Finding>();

        if (!state.WinRmRunning)
        {
            findings.Add(Finding.Pass(
                "WinRM Service Not Running",
                "The Windows Remote Management (WinRM) service is not running, " +
                "reducing the attack surface for remote PowerShell sessions.",
                Category));
            return findings;
        }

        findings.Add(Finding.Info(
            "WinRM Service Running",
            "The WinRM service is running, enabling PowerShell remoting.",
            Category));

        // Wildcard TrustedHosts disables certificate validation entirely.
        if (state.WinRmTrustedHosts.Any(h =>
                h == "*" || string.Equals(h, "any", StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add(Finding.Critical(
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
            findings.Add(Finding.Info(
                $"WinRM TrustedHosts: {state.WinRmTrustedHosts.Count} entries",
                $"TrustedHosts configured: {string.Join(", ", state.WinRmTrustedHosts.Take(5))}",
                Category,
                "Review trusted hosts list and ensure all entries are expected."));
        }

        if (state.WinRmPublicAccess)
        {
            findings.Add(Finding.Warning(
                "WinRM May Be Accessible on Public Networks",
                "WinRM firewall rules allow connections on Public network profiles. " +
                "This could expose PowerShell remoting on untrusted networks.",
                Category,
                "Restrict WinRM firewall rules to Domain and Private profiles only.",
                @"Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-PUBLIC' -Enabled False"));
        }

        return findings;
    }

    // ── Installed versions ─────────────────────────────────────────────────

    /// <summary>
    /// Returns an informational finding listing detected PowerShell engine versions,
    /// or <c>null</c> when none were detected.
    /// </summary>
    public static Finding? CheckVersions(PowerShellState state)
    {
        if (state.InstalledVersions.Count == 0) return null;

        return Finding.Info(
            $"PowerShell Versions Installed: {state.InstalledVersions.Count}",
            $"Detected PowerShell versions: {string.Join(", ", state.InstalledVersions)}",
            Category);
    }
}
