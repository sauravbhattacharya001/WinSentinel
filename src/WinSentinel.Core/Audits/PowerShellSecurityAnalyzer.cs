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
    /// Regex-free substrings that, when present in a PowerShell profile script, are
    /// strong indicators of malicious content: download cradles (WebClient / Invoke-
    /// WebRequest / Invoke-RestMethod and their iwr/irm aliases), LOLBin fetch/decode
    /// (certutil -urlcache/-decode, bitsadmin /transfer, BITS), reverse/bind-shell
    /// primitives (Net.Sockets.TcpClient), in-memory execution, inline execution-
    /// policy downgrade (-ExecutionPolicy Bypass), AMSI/logging/Defender tampering,
    /// Defender real-time-monitoring kill, profile-skipping relaunch wrappers
    /// (-NoProfile / -nop), named offensive tooling (Invoke-Mimikatz, Invoke-Shellcode,
    /// named offensive tooling (Invoke-Mimikatz, Invoke-Shellcode, Nishang,
    /// PowerSploit), AMSI reflection bypasses ([Ref].Assembly.GetType / setValue),
    /// native-API injection primitives (DllImport / GetDelegateForType), and obfuscation. Each entry pairs the token that is matched (case-insensitively)
    /// with a short human explanation shown in the finding. Order is the reporting order.
    /// </summary>
    public static readonly IReadOnlyList<(string Token, string Reason)> SuspiciousProfilePatterns =
        new List<(string, string)>
        {
            ("iex",                        "Invoke-Expression (iex) runs arbitrary strings as code"),
            ("invoke-expression",          "Invoke-Expression runs arbitrary strings as code"),
            ("downloadstring",             "Net.WebClient.DownloadString download cradle"),
            ("downloadfile",               "Net.WebClient.DownloadFile download cradle"),
            ("invoke-webrequest",          "remote payload fetch (Invoke-WebRequest)"),
            ("invoke-restmethod",          "remote payload fetch (Invoke-RestMethod)"),
            ("iwr http",                   "remote payload fetch (iwr = Invoke-WebRequest alias) of a URL"),
            ("irm http",                   "remote payload fetch (irm = Invoke-RestMethod alias) of a URL"),
            ("start-bitstransfer",         "remote payload fetch via BITS"),
            ("bitsadmin /transfer",        "remote payload fetch via the bitsadmin LOLBin"),
            ("certutil -urlcache",         "remote payload fetch via the certutil LOLBin (-urlcache)"),
            ("certutil.exe -urlcache",     "remote payload fetch via the certutil LOLBin (-urlcache)"),
            ("certutil -decode",           "base64 payload decode via the certutil LOLBin (-decode)"),
            ("certutil.exe -decode",       "base64 payload decode via the certutil LOLBin (-decode)"),
            ("system.net.webclient",       "Net.WebClient download-cradle object"),
            (".downloaddata",              "Net.WebClient.DownloadData download cradle"),
            ("frombase64string",           "base64-encoded payload decode"),
            ("-encodedcommand",            "launches a hidden base64-encoded command"),
            ("-enc ",                      "launches a hidden base64-encoded command (-enc)"),
            ("-windowstyle hidden",        "spawns a hidden PowerShell window"),
            ("-w hidden",                  "spawns a hidden PowerShell window (-w hidden)"),
            ("amsiutils",                  "AMSI-bypass tampering (System.Management.Automation.AmsiUtils)"),
            ("amsiinitfailed",             "AMSI-bypass tampering (amsiInitFailed)"),
            ("reflection.assembly",        "in-memory .NET assembly loading"),
            ("[reflection.assembly]",      "in-memory .NET assembly loading"),
            ("virtualalloc",               "shellcode injection primitive (VirtualAlloc)"),
            ("createthread",               "shellcode injection primitive (CreateThread)"),
            ("getdelegatefortype",          "dynamic native-API invocation primitive (GetDelegateForType) used for in-memory injection"),
            ("dllimport",                   "P/Invoke of a native API (DllImport) - common shellcode/injection primitive in a profile"),
            ("setvalue($null,$true)",       "AMSI-bypass reflection tamper (setValue($null,$true) on amsiInitFailed)"),
            ("[ref].assembly.gettype",      "AMSI-bypass reflection tamper ([Ref].Assembly.GetType(...) to flip amsiInitFailed)"),
            ("net.sockets.tcpclient",      "raw TCP socket - reverse/bind-shell primitive (Net.Sockets.TcpClient)"),
            ("-executionpolicy bypass",    "inline execution-policy downgrade (-ExecutionPolicy Bypass)"),
            ("-ep bypass",                 "inline execution-policy downgrade (-ep Bypass)"),
            ("add-mppreference",           "tampers with Windows Defender exclusions"),
            ("set-mppreference",           "disables/relaxes Windows Defender settings"),
            ("disablerealtimemonitoring",  "disables Windows Defender real-time protection"),
            ("-noprofile",                 "relaunches PowerShell ignoring profiles (-NoProfile), a common evasion wrapper"),
            ("-nop ",                      "relaunches PowerShell ignoring profiles (-nop), a common evasion wrapper"),
            ("invoke-mimikatz",            "in-memory credential theft (Invoke-Mimikatz)"),
            ("invoke-shellcode",           "in-memory shellcode execution (Invoke-Shellcode)"),
            ("invoke-obfuscation",         "payload obfuscation via Invoke-Obfuscation"),
            ("nishang",                    "references the Nishang offensive PowerShell toolkit"),
            ("-noninteractive",            "relaunches PowerShell non-interactively (-NonInteractive), a common automation/evasion wrapper"),
            ("-noni ",                     "relaunches PowerShell non-interactively (-noni), a common automation/evasion wrapper"),
            ("powersploit",                "references the PowerSploit offensive toolkit"),
            ("hidden powershell",          "references a hidden PowerShell launch"),
        };

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

        // CIS L1 recommends transcription include a per-command invocation header
        // (EnableInvocationHeader = 1). Without it, transcripts run the input/output
        // together with no timestamped command boundaries, which makes forensic
        // reconstruction of "what ran when" unreliable. Only meaningful when
        // TranscriptionEnabled is true.
        public bool TranscriptionInvocationHeaderEnabled { get; set; }

        // Tamper signal: the logging policy value is present in the registry but set
        // to 0 (explicitly OFF), as opposed to simply never configured. Attackers
        // disable script-block/module logging to blind forensic capture (MITRE
        // T1562.002 - Impair Defenses: Disable Windows Event Logging), so an
        // explicit 0 is graded far more seriously than an absent key. Defaults false
        // so a machine that never configured logging reads as a hygiene gap, not
        // tampering.
        public bool ScriptBlockLoggingExplicitlyDisabled { get; set; }
        public bool ModuleLoggingExplicitlyDisabled { get; set; }

        // The module names configured under the ModuleLogging\ModuleNames subkey.
        // CIS L1 requires this to contain the single wildcard entry "*" so that
        // pipeline execution is logged for EVERY module. A common misconfiguration
        // is to set EnableModuleLogging = 1 (so the top-level flag reads "enabled")
        // while leaving ModuleNames empty or scoped to a handful of named modules -
        // in that state almost nothing is actually logged, giving a false sense of
        // coverage. When this list is non-empty and does not contain "*", coverage
        // is incomplete. An EMPTY list means the collector could not read the subkey
        // (access denied / not present) and is treated as "unknown", not a finding,
        // to avoid false positives. Matching is case-insensitive.
        public List<string> ModuleLoggingNames { get; set; } = new();

        // Language mode
        public string LanguageMode { get; set; } = "FullLanguage";

        // PowerShell v2 (downgrade attack vector)
        public bool V2EngineInstalled { get; set; }

        // AMSI
        public bool AmsiProviderRegistered { get; set; } = true;

        // AMSI kill switch: the well-known registry bypass that turns AMSI OFF for
        // the Windows Script Host / PowerShell console host - HKLM or HKCU
        // SOFTWARE\Microsoft\Windows Script\Settings\AmsiEnable = 0. Setting this to
        // 0 disables real-time script scanning without unregistering the provider,
        // so the provider-registered check above still passes while AMSI is in fact
        // neutered. Attackers flip it to evade content inspection (MITRE T1562.001 -
        // Impair Defenses: Disable or Modify Tools). Defaults false (not disabled).
        public bool AmsiDisabledViaRegistry { get; set; }

        // Which hive the AmsiEnable=0 value was found in ("HKLM", "HKCU", or
        // "HKLM, HKCU" when both) - purely for the finding text. Null/empty when the
        // kill switch was not found.
        public string? AmsiDisableRegistryScope { get; set; }

        // Remoting (WinRM)
        public bool WinRmRunning { get; set; }
        public bool WinRmPublicAccess { get; set; }
        public List<string> WinRmTrustedHosts { get; set; } = new();

        // WinRM plaintext transport: WSMan:\localhost\Service\AllowUnencrypted (server
        // side) and \Client\AllowUnencrypted (client side). When true, WinRM will
        // negotiate HTTP without message-level encryption, so credentials and command
        // output can traverse the network in cleartext (MITRE T1040 - Network Sniffing).
        // Both default false (the secure Windows default requires encryption); either
        // being true is a real posture gap once WinRM is running.
        public bool WinRmServiceAllowUnencrypted { get; set; }
        public bool WinRmClientAllowUnencrypted { get; set; }

        // WinRM Basic authentication: WSMan:\localhost\Service\Auth\Basic (server
        // side) and \Client\Auth\Basic (client side). Basic auth transmits the
        // username and password as a base64-encoded (NOT encrypted) blob, so unless
        // the transport itself is HTTPS/encrypted the credentials are effectively
        // cleartext on the wire (MITRE T1040 - Network Sniffing). It also cannot do
        // mutual authentication, so it invites credential relay. CIS Windows L1
        // requires Basic auth to be disabled on both the WinRM service and client;
        // Kerberos/Negotiate should be used instead. Both default false (Basic is not
        // enabled by default), so either being true is a real posture gap once WinRM
        // is running - and it compounds the AllowUnencrypted finding above.
        public bool WinRmServiceBasicAuth { get; set; }
        public bool WinRmClientBasicAuth { get; set; }

        // WinRM CredSSP authentication: WSMan:\localhost\Service\Auth\CredSSP
        // (server side) and \Client\Auth\CredSSP (client side). CredSSP delegates
        // the user's FULL plaintext-equivalent credentials to the remote host so that
        // host can act as the user (the classic "second hop" enabler). A compromised
        // or malicious target then holds usable credentials, and CredSSP has a long
        // history of relay/downgrade weaknesses (e.g. CVE-2018-0886). Attackers abuse
        // delegated credentials for lateral movement (MITRE T1550 - Use Alternate
        // Authentication Material). CIS Windows L1 requires CredSSP to be disabled on
        // both the WinRM service and client; use Kerberos constrained delegation or
        // resource-based delegation instead when a second hop is genuinely needed.
        // Both default false (CredSSP is not enabled by default), so either being
        // true is a real credential-exposure gap once WinRM is running.
        public bool WinRmServiceCredSsp { get; set; }
        public bool WinRmClientCredSsp { get; set; }

        // PowerShell versions found on disk / in the registry
        public List<string> InstalledVersions { get; set; } = new();

        // PowerShell profile scripts (profile.ps1) present on disk. Each profile
        // auto-runs when a shell of the matching host opens, so a tampered profile
        // is a classic persistence + defense-evasion vector (MITRE T1546.013).
        public List<PowerShellProfileInfo> Profiles { get; set; } = new();

        // Protected Event Logging (a.k.a. Protected CIM/Event Logging). When enabled
        // via Group Policy with an encryption certificate, PowerShell (and other
        // participating providers) encrypt sensitive event-log content with CMS so
        // credentials/secrets that land in Script Block / Module logs are not stored
        // in plaintext where a local reader could harvest them. Registry:
        // HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging\
        // EnableProtectedEventLogging = 1 (+ an EncryptionCertificate). Defaults
        // false (not configured) - a defense-in-depth gap once logging is on.
        public bool ProtectedEventLoggingEnabled { get; set; }
    }

    /// <summary>
    /// One PowerShell profile script found on disk. The collector fills these in
    /// (path + whether it is machine-wide + the file's text); the analyzer decides
    /// whether the content is suspicious. Kept as a plain record so profile checks
    /// are unit-testable with synthetic content and never touch the filesystem.
    /// </summary>
    public sealed class PowerShellProfileInfo
    {
        /// <summary>Full path to the profile script (e.g. the CurrentUserCurrentHost profile).</summary>
        public string Path { get; set; } = string.Empty;

        /// <summary>Human label for the profile scope (e.g. "AllUsersAllHosts").</summary>
        public string Scope { get; set; } = string.Empty;

        /// <summary>
        /// True for the AllUsers* profiles under $PSHOME - they execute for EVERY user
        /// on the machine, so malicious content there is a machine-wide backdoor and is
        /// graded one step higher than a per-user profile.
        /// </summary>
        public bool IsMachineWide { get; set; }

        /// <summary>Raw text of the profile script (null when the file could not be read).</summary>
        public string? Content { get; set; }
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
        findings.AddRange(CheckProfiles(state));
        findings.Add(CheckProtectedEventLogging(state));
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

    /// <summary>
    /// Single source of truth for "what policy is actually in force" used by every
    /// execution-policy check. Honours an explicitly-supplied <see
    /// cref="PowerShellState.EffectivePolicy"/> (what <see cref="PowerShellAudit"/>
    /// sets after collection) when it is defined, otherwise derives it from the
    /// per-scope values via <see cref="ResolveEffectivePolicy"/>.
    ///
    /// This closes a false-negative on the analyzer's documented synthetic-state
    /// contract: a caller that sets per-scope policies but leaves the denormalized
    /// <c>EffectivePolicy</c> at its "Undefined" default previously had its real
    /// effective policy (e.g. a CurrentUser-scope <c>Bypass</c>) silently ignored.
    /// </summary>
    public static string EffectiveExecutionPolicy(PowerShellState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return IsUndefined(state.EffectivePolicy)
            ? ResolveEffectivePolicy(state)
            : state.EffectivePolicy;
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
        var effective = EffectiveExecutionPolicy(state);

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
            // A genuinely Undefined effective policy means every scope
            // (Machine/User/Process/CurrentUser/LocalMachine) is unset, so Windows
            // falls back to Restricted on client SKUs (safe) - but it is better to
            // be explicit. Gate on the full resolved value (not a hand-picked
            // subset of scopes) so this stays consistent with the precedence model.
            findings.Add(Finding.Info(
                "Execution Policy: Not Explicitly Set",
                "No execution policy is explicitly configured. " +
                "Windows defaults to Restricted on client SKUs, but " +
                "setting it explicitly prevents ambiguity.",
                Category,
                "Set an explicit execution policy.",
                "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"));
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
        // Explicitly disabled (value present and 0) is a tamper signal, not a mere
        // hygiene gap: someone actively turned OFF forensic script capture. Grade it
        // Critical (MITRE T1562.002) and keep it distinct from "never configured".
        if (state.ScriptBlockLoggingExplicitlyDisabled)
        {
            return Finding.Critical(
                "Script Block Logging Explicitly Disabled",
                "PowerShell script block logging is explicitly turned OFF " +
                "(EnableScriptBlockLogging = 0 in the registry), not merely unset. " +
                "Disabling it blinds forensic capture of obfuscated and dynamically " +
                "generated commands and is a common defense-evasion step " +
                "(MITRE T1562.002 - Impair Defenses: Disable Windows Event Logging).",
                Category,
                "Re-enable script block logging and investigate why it was disabled: " +
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1",
                @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' " +
                "-Name EnableScriptBlockLogging -Value 1");
        }

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
        // Explicitly disabled (value present and 0) => tamper signal, graded Critical
        // and kept distinct from "never configured" (the Warning below).
        if (state.ModuleLoggingExplicitlyDisabled)
        {
            return Finding.Critical(
                "Module Logging Explicitly Disabled",
                "PowerShell module logging is explicitly turned OFF " +
                "(EnableModuleLogging = 0 in the registry), not merely unset. " +
                "Disabling it removes pipeline-execution visibility across all " +
                "modules and is a common defense-evasion step " +
                "(MITRE T1562.002 - Impair Defenses: Disable Windows Event Logging).",
                Category,
                "Re-enable module logging and investigate why it was disabled: " +
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\EnableModuleLogging = 1",
                @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' " +
                "-Name EnableModuleLogging -Value 1");
        }

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

        // Enabled at the top level, but coverage is only complete when ModuleNames
        // contains the "*" wildcard. If the collected name list is non-empty and does
        // NOT include "*", logging is scoped to a subset of modules and most pipeline
        // activity goes unrecorded despite the flag reading "enabled" - a false sense
        // of coverage that CIS L1 explicitly calls out. An empty list is "unknown"
        // (collector could not read the subkey) and is not graded.
        if (state.ModuleLoggingNames.Count > 0 &&
            !state.ModuleLoggingNames.Any(n => n.Trim() == "*"))
        {
            var configured = string.Join(", ", state.ModuleLoggingNames.Select(n => n.Trim())
                .Where(n => n.Length > 0));
            return Finding.Warning(
                "Module Logging Coverage Incomplete",
                "PowerShell module logging is enabled (EnableModuleLogging = 1) but the " +
                "ModuleNames list does not include the '*' wildcard, so pipeline " +
                "execution is only recorded for a scoped subset of modules " +
                (configured.Length > 0 ? $"({configured}) " : "") +
                "rather than every module. This leaves most PowerShell activity " +
                "unlogged while the top-level flag reads 'enabled', giving a false " +
                "sense of forensic coverage (CIS L1 requires ModuleNames = '*').",
                Category,
                "Set the ModuleNames wildcard so all modules are logged: " +
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames\* = '*'",
                @"New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' " +
                "-Force | Out-Null; New-ItemProperty -Path " +
                @"'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' " +
                "-Name '*' -Value '*' -PropertyType String -Force");
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

        // Transcription is on but the per-command invocation header is off. Per CIS
        // L1, the header stamps each command with a timestamp/user/command line so
        // the transcript has real command boundaries; without it the log is far less
        // useful for forensic reconstruction. Surface as its own Info so the fix
        // (EnableInvocationHeader = 1) is unambiguous and not conflated with the
        // "transcription entirely off" case above.
        if (!state.TranscriptionInvocationHeaderEnabled)
        {
            return Finding.Info(
                "PowerShell Transcription: Invocation Header Disabled",
                "Automatic transcription is enabled" + dirNote + ", but the per-command " +
                "invocation header (EnableInvocationHeader) is not turned on. Without it, " +
                "transcripts lack the timestamped command boundaries that make forensic " +
                "reconstruction of what ran, and when, reliable (CIS L1).",
                Category,
                "Enable the invocation header via Group Policy or registry: " +
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableInvocationHeader = 1",
                @"New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' " +
                "-Name EnableInvocationHeader -Value 1 -PropertyType DWord -Force");
        }

        return Finding.Pass(
            "PowerShell Transcription Enabled",
            "Automatic transcription is enabled" + dirNote +
            ", with per-command invocation headers for reliable forensic reconstruction.",
            Category);
    }

    // ── Language mode ──────────────────────────────────────────────────────

    // Protected Event Logging encrypts sensitive event-log content (CMS) using an
    // encryption certificate, so secrets that leak into Script Block / Module logs
    // are not readable at rest by anyone who can read the event log. It is a
    // defense-in-depth control that only matters once logging is on; we report it
    // as Info (a recommendation) rather than a failure.
    public static Finding CheckProtectedEventLogging(PowerShellState state)
    {
        if (state.ProtectedEventLoggingEnabled)
        {
            return Finding.Pass(
                "Protected Event Logging Enabled",
                "Protected Event Logging is enabled, so sensitive PowerShell event-log " +
                "content is encrypted (CMS) at rest and cannot be read by a local user " +
                "who can merely read the event log.",
                Category);
        }

        return Finding.Info(
            "Protected Event Logging Disabled",
            "Protected Event Logging is not enabled. Script Block and Module logging " +
            "can capture credentials, tokens, and other secrets that flow through the " +
            "shell; without Protected Event Logging that content is stored in the event " +
            "log in plaintext, readable by anyone with log-read access. Enabling it " +
            "encrypts the content with a certificate so only the holder of the private " +
            "key can decrypt it (defense-in-depth for PowerShell logging).",
            Category,
            "Deploy an encryption certificate, then enable via Group Policy or registry: " +
            @"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging\EnableProtectedEventLogging = 1",
            @"New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' " +
            "-Name EnableProtectedEventLogging -Value 1 -PropertyType DWord -Force");
    }

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
        // The AmsiEnable=0 registry kill switch is graded FIRST and separately from
        // provider registration: it disables AMSI content scanning while leaving the
        // provider registered, so a machine can look fine to the provider check yet
        // have AMSI fully neutered. This is a very common, cheap defense-evasion step
        // (MITRE T1562.001) - surface it as its own Critical so the remediation is
        // unambiguous (delete/reset the value), not conflated with "install an AV".
        if (state.AmsiDisabledViaRegistry)
        {
            var scope = string.IsNullOrWhiteSpace(state.AmsiDisableRegistryScope)
                ? "the registry"
                : state.AmsiDisableRegistryScope;
            return Finding.Critical(
                "AMSI Disabled via Registry (AmsiEnable = 0)",
                "The Anti-Malware Scan Interface (AMSI) is turned OFF by the " +
                $"'AmsiEnable' registry value under {scope} " +
                @"SOFTWARE\Microsoft\Windows Script\Settings. " +
                "With AmsiEnable = 0, PowerShell / Windows Script Host script content " +
                "is no longer submitted to AMSI for real-time malware scanning, even " +
                "though an AMSI provider is still registered. Attackers set this value " +
                "to evade content inspection of obfuscated and in-memory payloads " +
                "(MITRE T1562.001 - Impair Defenses: Disable or Modify Tools).",
                Category,
                "Remove the AmsiEnable override (or set it to 1) and investigate why it " +
                "was disabled: " +
                @"HKLM\SOFTWARE\Microsoft\Windows Script\Settings\AmsiEnable (and the HKCU hive).",
                @"Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script\Settings' " +
                "-Name AmsiEnable -ErrorAction SilentlyContinue; " +
                @"Remove-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows Script\Settings' " +
                "-Name AmsiEnable -ErrorAction SilentlyContinue");
        }

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
            "An AMSI provider is registered and no AmsiEnable=0 kill switch is set, " +
            "enabling real-time script content scanning for malicious patterns.",
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

        // Plaintext transport: AllowUnencrypted on either the service or client side
        // lets WinRM negotiate HTTP with no message-level encryption, exposing
        // credentials and command output to network sniffing (MITRE T1040).
        if (state.WinRmServiceAllowUnencrypted || state.WinRmClientAllowUnencrypted)
        {
            var sides = new List<string>();
            if (state.WinRmServiceAllowUnencrypted) sides.Add("service (server)");
            if (state.WinRmClientAllowUnencrypted) sides.Add("client");
            var sideText = string.Join(" and ", sides);
            findings.Add(Finding.Critical(
                "WinRM Allows Unencrypted Traffic",
                $"WinRM AllowUnencrypted is enabled on the {sideText} side, so remote " +
                "PowerShell sessions can be negotiated over plain HTTP with no " +
                "message-level encryption. Credentials and command output then cross " +
                "the network in cleartext and can be captured by anyone on-path " +
                "(MITRE T1040 - Network Sniffing).",
                Category,
                "Disable unencrypted WinRM transport and require HTTPS/Kerberos-encrypted " +
                "traffic on both the service and client.",
                "Set-Item WSMan:\\localhost\\Service\\AllowUnencrypted -Value $false; " +
                "Set-Item WSMan:\\localhost\\Client\\AllowUnencrypted -Value $false"));
        }

        // Basic authentication: sends credentials as a base64 blob (not encrypted)
        // and cannot mutually authenticate, so on any non-HTTPS transport it hands
        // creds to an on-path attacker (MITRE T1040) and invites relay. CIS L1
        // requires it disabled on both the service and client.
        if (state.WinRmServiceBasicAuth || state.WinRmClientBasicAuth)
        {
            var sides = new List<string>();
            if (state.WinRmServiceBasicAuth) sides.Add("service (server)");
            if (state.WinRmClientBasicAuth) sides.Add("client");
            var sideText = string.Join(" and ", sides);
            findings.Add(Finding.Warning(
                "WinRM Basic Authentication Enabled",
                $"WinRM Basic authentication is enabled on the {sideText} side. Basic " +
                "auth transmits the username and password as a base64-encoded (not " +
                "encrypted) value and cannot perform mutual authentication, so on any " +
                "transport that is not HTTPS/message-encrypted the credentials are " +
                "effectively cleartext and can be captured or relayed by an on-path " +
                "attacker (MITRE T1040 - Network Sniffing). CIS Windows L1 requires " +
                "Basic authentication to be disabled.",
                Category,
                "Disable WinRM Basic authentication on both the service and client and " +
                "use Kerberos/Negotiate instead.",
                "Set-Item WSMan:\\localhost\\Service\\Auth\\Basic -Value $false; " +
                "Set-Item WSMan:\\localhost\\Client\\Auth\\Basic -Value $false"));
        }

        // CredSSP authentication: delegates the user's full plaintext-equivalent
        // credentials to the remote host (the "second hop" enabler), so a compromised
        // target then holds usable creds for lateral movement (MITRE T1550). CredSSP
        // also has a history of relay/downgrade CVEs (e.g. CVE-2018-0886). CIS L1
        // requires it disabled on both the service and client.
        if (state.WinRmServiceCredSsp || state.WinRmClientCredSsp)
        {
            var sides = new List<string>();
            if (state.WinRmServiceCredSsp) sides.Add("service (server)");
            if (state.WinRmClientCredSsp) sides.Add("client");
            var sideText = string.Join(" and ", sides);
            findings.Add(Finding.Warning(
                "WinRM CredSSP Authentication Enabled",
                $"WinRM CredSSP authentication is enabled on the {sideText} side. CredSSP " +
                "delegates the user's full (plaintext-equivalent) credentials to the " +
                "remote host so it can act as the user - the classic 'second hop' " +
                "mechanism. A compromised or malicious target then holds usable " +
                "credentials for lateral movement (MITRE T1550 - Use Alternate " +
                "Authentication Material), and CredSSP has a history of relay/downgrade " +
                "weaknesses (e.g. CVE-2018-0886). CIS Windows L1 requires CredSSP to be " +
                "disabled.",
                Category,
                "Disable WinRM CredSSP on both the service and client; use Kerberos " +
                "constrained or resource-based delegation when a second hop is required.",
                "Set-Item WSMan:\\localhost\\Service\\Auth\\CredSSP -Value $false; " +
                "Set-Item WSMan:\\localhost\\Client\\Auth\\CredSSP -Value $false"));
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

    // ── Profile scripts (profile.ps1 persistence) ──────────────────────────

    /// <summary>
    /// Scans a single profile's content for the <see cref="SuspiciousProfilePatterns"/>
    /// tokens (case-insensitive substring match) and returns the human reasons for
    /// every distinct pattern that matched, in declaration order. Empty when the
    /// content is null/blank or nothing matched. Pure - no I/O.
    /// </summary>
    public static IReadOnlyList<string> ScanProfileContent(string? content)
    {
        if (string.IsNullOrWhiteSpace(content)) return Array.Empty<string>();

        var lower = content.ToLowerInvariant();
        var reasons = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (token, reason) in SuspiciousProfilePatterns)
        {
            if (lower.Contains(token, StringComparison.Ordinal) && seen.Add(reason))
                reasons.Add(reason);
        }
        return reasons;
    }

    /// <summary>
    /// Evaluates PowerShell profile scripts for tampering. A PowerShell profile
    /// (<c>profile.ps1</c> / <c>Microsoft.PowerShell_profile.ps1</c>) auto-executes
    /// every time a shell of the matching host starts, so attackers plant code there
    /// for persistence and to re-arm defense-evasion (AMSI bypass, logging off) on
    /// each launch - MITRE ATT&amp;CK T1546.013 (Event Triggered Execution: PowerShell
    /// Profile).
    ///
    /// Grading:
    /// <list type="bullet">
    /// <item>profile with a suspicious pattern → Critical (machine-wide AllUsers) or
    /// Warning (per-user), since a benign profile rarely downloads+executes code.</item>
    /// <item>machine-wide profile that exists but looks clean → Info (it runs for
    /// every user, so its existence is worth surfacing).</item>
    /// <item>no profiles present → a single Pass.</item>
    /// </list>
    /// Pure - operates only on the collected <see cref="PowerShellProfileInfo"/> list.
    /// </summary>
    public static List<Finding> CheckProfiles(PowerShellState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var findings = new List<Finding>();

        var profiles = state.Profiles ?? new List<PowerShellProfileInfo>();
        if (profiles.Count == 0)
        {
            findings.Add(Finding.Pass(
                "No PowerShell Profile Scripts Found",
                "No PowerShell profile scripts (profile.ps1) are present. Profiles " +
                "auto-run on every shell start, so an absent profile removes a common " +
                "persistence and AMSI-bypass foothold.",
                Category));
            return findings;
        }

        foreach (var profile in profiles)
        {
            var where = string.IsNullOrWhiteSpace(profile.Scope) ? "profile" : profile.Scope;
            var pathNote = string.IsNullOrWhiteSpace(profile.Path) ? "" : $" ({profile.Path})";
            var reasons = ScanProfileContent(profile.Content);

            if (reasons.Count > 0)
            {
                var reasonList = string.Join("; ", reasons);
                var scopeWord = profile.IsMachineWide ? "machine-wide (all users)" : "per-user";
                var description =
                    $"The {scopeWord} PowerShell profile{pathNote} contains " +
                    $"pattern(s) commonly seen in malicious profiles: {reasonList}. " +
                    "PowerShell profiles execute automatically on every shell start, making " +
                    "them a persistence and defense-evasion vector (MITRE T1546.013). " +
                    "Review the script - this is expected only if you intentionally added it.";
                var remediation =
                    $"Inspect '{profile.Path}'. If unexpected, remove or restore it and rotate " +
                    "any credentials the shell may have exposed.";

                findings.Add(profile.IsMachineWide
                    ? Finding.Critical($"Suspicious PowerShell Profile: {where}", description, Category, remediation)
                    : Finding.Warning($"Suspicious PowerShell Profile: {where}", description, Category, remediation));
            }
            else if (profile.IsMachineWide)
            {
                findings.Add(Finding.Info(
                    $"Machine-Wide PowerShell Profile Present: {where}",
                    $"A machine-wide PowerShell profile{pathNote} exists and runs for every " +
                    "user on this system. No suspicious patterns were detected, but confirm " +
                    "its contents are intended - machine-wide profiles are a high-value " +
                    "persistence target.",
                    Category,
                    $"Review '{profile.Path}' and confirm every line is expected."));
            }
        }

        // If profiles exist but none were machine-wide or suspicious, note the clean state.
        if (findings.Count == 0)
        {
            findings.Add(Finding.Pass(
                "PowerShell Profile Scripts Clean",
                $"{profiles.Count} per-user PowerShell profile script(s) present; no suspicious " +
                "patterns (download cradles, AMSI-bypass, hidden execution) detected.",
                Category));
        }

        return findings;
    }
}
