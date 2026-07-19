using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;
using Microsoft.Win32;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits Windows Registry for security risks including:
/// - UAC disabled or weakened (ConsentPromptBehaviorAdmin, EnableLUA)
/// - Remote Desktop enabled without NLA
/// - AutoPlay/AutoRun not disabled (infection vector)
/// - Credential caching (CachedLogonsCount)
/// - WDigest plain-text credential storage
/// - Windows Script Host enabled (malware execution vector)
/// - LSASS protection disabled (credential dumping risk)
/// - Additional auto-run persistence beyond startup Run keys
/// - Windows Remote Management (WinRM) exposure
/// - Safe DLL search order disabled (DLL hijacking risk)
/// </summary>
public class RegistryAudit : IAuditModule
{
    /// <inheritdoc />
    public string Name => "Registry Security Audit";

    /// <inheritdoc />
    public string Category => "Registry";

    /// <inheritdoc />
    public string Description =>
        "Checks registry-based security policies including UAC, Remote Desktop, " +
        "credential storage, LSASS protection, scripting hosts, and persistence mechanisms.";

    /// <summary>
    /// Immutable snapshot of every registry value sampled by <see cref="GatherStateAsync"/>.
    /// </summary>
    /// <remarks>
    /// All numeric fields are nullable: <see langword="null"/> means the value was not present
    /// (or the key could not be opened). The downstream analyzers treat "missing" and "explicitly
    /// set to a safe value" differently, so do not collapse <see langword="null"/> to a default.
    /// </remarks>
    public sealed class RegistryState
    {
        // ---- UAC (User Account Control) ----

        /// <summary><c>HKLM\...\Policies\System\EnableLUA</c>. <c>0</c> disables UAC entirely.</summary>
        public int? EnableLua { get; set; }

        /// <summary>
        /// <c>HKLM\...\Policies\System\ConsentPromptBehaviorAdmin</c>. Controls whether admin
        /// elevation prompts appear and on which desktop. <c>0</c> = silent auto-elevate (insecure),
        /// <c>1</c> = regular desktop prompt, <c>2</c>/<c>5</c> = secure desktop prompt.
        /// </summary>
        public int? ConsentPromptBehaviorAdmin { get; set; }

        /// <summary>
        /// <c>HKLM\...\Policies\System\FilterAdministratorToken</c>. When <c>0</c> or unset, the
        /// built-in Administrator (RID 500) runs with a full, unfiltered admin token and is NOT
        /// subject to UAC prompts even while UAC is otherwise enabled. Set to <c>1</c> to put the
        /// built-in Administrator into Admin Approval Mode (CIS L1 2.3.17.1).
        /// </summary>
        public int? FilterAdministratorToken { get; set; }

        /// <summary>
        /// <c>HKLM\...\Policies\System\EnableVirtualization</c>. <c>1</c> enables file/registry
        /// virtualization for legacy apps writing to protected areas.
        /// </summary>
        public int? EnableVirtualization { get; set; }

        // ---- Remote Desktop ----

        /// <summary>
        /// <c>HKLM\SYSTEM\...\Terminal Server\fDenyTSConnections</c>. <c>0</c> means RDP is enabled.
        /// </summary>
        public int? DenyTsConnections { get; set; }

        /// <summary>
        /// <c>UserAuthentication</c> on <c>RDP-Tcp</c>. <c>1</c> requires Network Level Authentication
        /// before the RDP login screen is reachable.
        /// </summary>
        public int? NlaRequired { get; set; }

        /// <summary>
        /// <c>SecurityLayer</c> on <c>RDP-Tcp</c>. <c>0</c> = legacy RDP security, <c>1</c> = negotiate,
        /// <c>2</c> = TLS (preferred).
        /// </summary>
        public int? RdpSecurityLayer { get; set; }

        // ---- AutoPlay / AutoRun ----

        /// <summary>
        /// <c>HKLM\...\Policies\Explorer\NoDriveTypeAutoRun</c>. <c>0xFF</c> (255) disables AutoRun on
        /// all drive types — the recommended hardening value.
        /// </summary>
        public int? NoDriveTypeAutoRun { get; set; }

        /// <summary>
        /// <c>DisableAutoplay</c>. <c>1</c> disables AutoPlay for all media.
        /// </summary>
        public int? DisableAutoplay { get; set; }

        // ---- Credentials ----

        /// <summary>
        /// <c>HKLM\...\Winlogon\CachedLogonsCount</c> (REG_SZ). Number of domain logon password hashes
        /// cached locally for offline logon. Recommended: <c>0</c>–<c>4</c>.
        /// </summary>
        public string? CachedLogonsCount { get; set; }

        /// <summary>
        /// <c>...\SecurityProviders\WDigest\UseLogonCredential</c>. <c>1</c> stores credentials in
        /// plain text in LSASS memory — must be <c>0</c>.
        /// </summary>
        public int? WDigestUseLogonCredential { get; set; }

        // ---- LSASS protection ----

        /// <summary>
        /// <c>HKLM\SYSTEM\...\Lsa\RunAsPPL</c>. <c>1</c>/<c>2</c> enables Protected Process Light for
        /// LSASS, blocking credential-dumping tools.
        /// </summary>
        public int? LsassRunAsPpl { get; set; }

        // ---- Windows Script Host ----

        /// <summary>
        /// <c>HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings\Enabled</c> (REG_SZ).
        /// <c>"0"</c> disables wscript/cscript execution of <c>.vbs</c>/<c>.js</c> files.
        /// </summary>
        public string? ScriptHostEnabled { get; set; }

        // ---- WinRM (Windows Remote Management) ----

        /// <summary>
        /// <c>WinRM\Service\AllowAutoConfig</c>. <c>1</c> indicates WinRM is auto-configured by policy.
        /// </summary>
        public int? WinRmAllowAutoConfig { get; set; }

        /// <summary>
        /// <c>WinRM\Service\AllowUnencryptedTraffic</c>. <c>1</c> permits plain-text HTTP — must be <c>0</c>.
        /// </summary>
        public int? WinRmAllowUnencrypted { get; set; }

        /// <summary>
        /// <c>WinRM\Client\AllowBasic</c>. <c>1</c> permits HTTP Basic auth (Base64 credentials).
        /// </summary>
        public int? WinRmAllowBasic { get; set; }

        // ---- DLL search order ----

        /// <summary>
        /// <c>Session Manager\SafeDllSearchMode</c>. <c>1</c> searches system directories before the
        /// current working directory when loading DLLs, mitigating DLL hijacking.
        /// </summary>
        public int? SafeDllSearchMode { get; set; }

        // ---- Persistence mechanisms ----

        /// <summary>
        /// Parsed list of DLLs from <c>...\Windows NT\CurrentVersion\Windows\AppInit_DLLs</c>. Each
        /// listed DLL is injected into every user-mode process when <see cref="LoadAppInitDlls"/> is
        /// <c>1</c>.
        /// </summary>
        public List<string> AppInitDlls { get; set; } = new();

        /// <summary>
        /// <c>LoadAppInit_DLLs</c>. <c>1</c> activates the <see cref="AppInitDlls"/> list.
        /// </summary>
        public int? LoadAppInitDlls { get; set; }

        /// <summary>
        /// Entries under <c>Image File Execution Options</c> that have a <c>Debugger</c> value set.
        /// Used both for legitimate debugging hooks and the well-known accessibility-binary hijack
        /// persistence technique (MITRE T1546.008).
        /// </summary>
        public List<IfeoEntry> IfeoDebuggers { get; set; } = new();

        /// <summary>
        /// Reserved for shell-extension enumeration. Currently unused by the analyzer.
        /// </summary>
        public List<string> ShellExtensions { get; set; } = new();

        /// <summary>
        /// <c>Winlogon\Shell</c>. Expected value <c>explorer.exe</c>; anything else indicates a
        /// shell-hijacking persistence implant.
        /// </summary>
        public string? WinlogonShell { get; set; }

        /// <summary>
        /// <c>Winlogon\Userinit</c>. Expected value contains <c>userinit.exe</c>; replaced values
        /// execute custom code at every interactive logon.
        /// </summary>
        public string? WinlogonUserinit { get; set; }
    }

    /// <summary>
    /// A single <c>Image File Execution Options</c> entry where a <c>Debugger</c> value has been set.
    /// When Windows launches <see cref="TargetExecutable"/>, it instead launches
    /// <see cref="DebuggerValue"/> passing the original as an argument.
    /// </summary>
    public sealed class IfeoEntry
    {
        /// <summary>Name of the executable the IFEO key applies to (e.g. <c>sethc.exe</c>).</summary>
        public string TargetExecutable { get; set; } = string.Empty;

        /// <summary>The command line stored in the <c>Debugger</c> value of the IFEO subkey.</summary>
        public string DebuggerValue { get; set; } = string.Empty;
    }

    /// <summary>
    /// Run the full audit: gather registry state, analyze it, and return the aggregated
    /// <see cref="AuditResult"/>. Any exception is captured into the result rather than thrown.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token forwarded to <see cref="GatherStateAsync"/>.</param>
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
            var state = await GatherStateAsync(cancellationToken);
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

    /// <summary>
    /// Read every monitored registry value into a <see cref="RegistryState"/> snapshot.
    /// </summary>
    /// <remarks>
    /// Each read is best-effort via <see cref="RegistryHelper"/>; missing keys/values yield
    /// <see langword="null"/> in the snapshot rather than throwing. This is synchronous I/O
    /// wrapped in <see cref="Task.FromResult{TResult}"/> for API uniformity with other audit modules.
    /// </remarks>
    /// <param name="cancellationToken">Currently unused; reserved for future async I/O.</param>
    public Task<RegistryState> GatherStateAsync(CancellationToken cancellationToken = default)
    {
        var state = new RegistryState();
        state.EnableLua = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA");
        state.ConsentPromptBehaviorAdmin = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin");
        state.FilterAdministratorToken = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "FilterAdministratorToken");
        state.EnableVirtualization = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableVirtualization");
        state.DenyTsConnections = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");
        state.NlaRequired = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication");
        state.RdpSecurityLayer = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "SecurityLayer");
        state.NoDriveTypeAutoRun = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun");
        state.DisableAutoplay = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "DisableAutoplay");
        state.CachedLogonsCount = RegistryHelper.GetValue<string>(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount");
        state.WDigestUseLogonCredential = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential");
        state.LsassRunAsPpl = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL");
        state.ScriptHostEnabled = RegistryHelper.GetValue<string>(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows Script Host\Settings", "Enabled");
        state.WinRmAllowAutoConfig = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "AllowAutoConfig");
        state.WinRmAllowUnencrypted = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "AllowUnencryptedTraffic");
        state.WinRmAllowBasic = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client", "AllowBasic");
        state.SafeDllSearchMode = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager", "SafeDllSearchMode");
        state.LoadAppInitDlls = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "LoadAppInit_DLLs");
        var appInitValue = RegistryHelper.GetValue<string>(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs");
        if (!string.IsNullOrWhiteSpace(appInitValue))
            state.AppInitDlls = appInitValue.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).Where(s => s.Length > 0).ToList();
        GatherIfeoDebuggers(state);
        state.WinlogonShell = RegistryHelper.GetValue<string>(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell");
        state.WinlogonUserinit = RegistryHelper.GetValue<string>(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit");
        return Task.FromResult(state);
    }

    private static void GatherIfeoDebuggers(RegistryState state)
    {
        const string ifeoPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        var subKeys = RegistryHelper.GetSubKeyNames(RegistryHive.LocalMachine, ifeoPath);
        foreach (var exe in subKeys)
        {
            var debugger = RegistryHelper.GetValue<string>(RegistryHive.LocalMachine, $@"{ifeoPath}\{exe}", "Debugger");
            if (!string.IsNullOrWhiteSpace(debugger))
                state.IfeoDebuggers.Add(new IfeoEntry { TargetExecutable = exe, DebuggerValue = debugger });
        }
    }

    /// <summary>
    /// Apply every security check against the supplied <paramref name="state"/>, appending
    /// <see cref="Finding"/>s to <paramref name="result"/>. This method is pure and side-effect
    /// free w.r.t. the registry, so it can be unit-tested with synthetic states.
    /// </summary>
    /// <param name="state">A registry snapshot — typically from <see cref="GatherStateAsync"/>.</param>
    /// <param name="result">Audit result the findings are appended to.</param>
    public void AnalyzeState(RegistryState state, AuditResult result)
    {
        CheckUac(state, result);
        CheckRemoteDesktop(state, result);
        CheckAutoPlay(state, result);
        CheckCredentials(state, result);
        CheckLsass(state, result);
        CheckScriptHost(state, result);
        CheckWinRm(state, result);
        CheckDllSafety(state, result);
        CheckPersistence(state, result);
    }

    private static void CheckUac(RegistryState state, AuditResult result)
    {
        const string cat = "Registry - UAC";
        if (state.EnableLua.HasValue && state.EnableLua.Value == 0)
            result.Findings.Add(Finding.Critical("UAC Disabled", "User Account Control is completely disabled (EnableLUA=0). All processes run with full admin privileges without prompting.", cat, "Enable UAC: Set EnableLUA to 1 and reboot.", "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f"));
        else
            result.Findings.Add(Finding.Pass("UAC Enabled", "User Account Control is enabled.", cat));

        if (state.ConsentPromptBehaviorAdmin.HasValue)
        {
            var val = state.ConsentPromptBehaviorAdmin.Value;
            if (val == 0)
                result.Findings.Add(Finding.Critical("UAC Auto-Elevate Without Prompt", "ConsentPromptBehaviorAdmin=0: admin operations elevate silently without any consent prompt. Malware can elevate undetected.", cat, "Set ConsentPromptBehaviorAdmin to 2 (prompt on secure desktop) or 5 (default).", "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f"));
            else if (val == 1)
                result.Findings.Add(Finding.Warning("UAC Prompts on Regular Desktop", "ConsentPromptBehaviorAdmin=1: prompts appear on the regular desktop, not the secure desktop. Malware can spoof or auto-click the prompt.", cat, "Set ConsentPromptBehaviorAdmin to 2 for secure desktop prompts."));
            else
                result.Findings.Add(Finding.Pass("UAC Prompt Behavior Secure", $"ConsentPromptBehaviorAdmin={val}: admin elevation requires consent.", cat));
        }

        if (state.EnableVirtualization.HasValue && state.EnableVirtualization.Value == 0)
            result.Findings.Add(Finding.Warning("UAC Virtualization Disabled", "File and registry virtualization is disabled. Legacy applications writing to protected areas will fail rather than being redirected.", cat, "Enable virtualization: Set EnableVirtualization to 1."));

        // Admin Approval Mode for the built-in Administrator (CIS L1 2.3.17.1).
        // Only meaningful when UAC is on: with EnableLUA=0 the "UAC Disabled" finding
        // above already dominates, so we don't double-report here. When UAC is on but
        // FilterAdministratorToken is 0/unset, the RID-500 Administrator gets a full
        // token and bypasses every elevation prompt.
        bool uacOn = !state.EnableLua.HasValue || state.EnableLua.Value != 0;
        if (uacOn)
        {
            if (state.FilterAdministratorToken.HasValue && state.FilterAdministratorToken.Value == 1)
                result.Findings.Add(Finding.Pass("Built-in Administrator in Admin Approval Mode", "FilterAdministratorToken=1: the built-in Administrator account is subject to UAC elevation prompts like any other admin.", cat));
            else
                result.Findings.Add(Finding.Warning("Built-in Administrator Bypasses UAC", "FilterAdministratorToken is not set to 1: the built-in Administrator (RID 500) runs with a full, unfiltered token and is NOT prompted by UAC, even though UAC is enabled. Malware running in that account elevates silently.", cat, "Enable Admin Approval Mode for the built-in Administrator: Set FilterAdministratorToken to 1 (CIS L1 2.3.17.1).", "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v FilterAdministratorToken /t REG_DWORD /d 1 /f"));
        }
    }

    private static void CheckRemoteDesktop(RegistryState state, AuditResult result)
    {
        const string cat = "Registry - Remote Desktop";
        bool rdpEnabled = state.DenyTsConnections.HasValue && state.DenyTsConnections.Value == 0;
        if (!rdpEnabled)
        {
            result.Findings.Add(Finding.Pass("Remote Desktop Disabled", "RDP is not enabled (fDenyTSConnections is not 0).", cat));
            return;
        }
        result.Findings.Add(Finding.Info("Remote Desktop Enabled", "RDP is enabled. Ensure it is required and properly secured.", cat));
        if (!state.NlaRequired.HasValue || state.NlaRequired.Value != 1)
            result.Findings.Add(Finding.Critical("Network Level Authentication Not Required", "RDP is enabled without NLA. Attackers can reach the login screen without first authenticating, exposing the system to brute-force and DoS.", cat, "Enable NLA: Set UserAuthentication to 1.", "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication /t REG_DWORD /d 1 /f"));
        else
            result.Findings.Add(Finding.Pass("Network Level Authentication Required", "NLA is enabled - clients must authenticate before establishing a session.", cat));
        if (state.RdpSecurityLayer.HasValue && state.RdpSecurityLayer.Value == 0)
            result.Findings.Add(Finding.Warning("RDP Using Legacy Security Layer", "SecurityLayer=0 (RDP Security). Traffic uses weaker RDP-native encryption rather than TLS.", cat, "Set SecurityLayer to 2 (TLS) for stronger encryption."));
    }

    private static void CheckAutoPlay(RegistryState state, AuditResult result)
    {
        const string cat = "Registry - AutoPlay";
        bool autoRunDisabled = state.NoDriveTypeAutoRun.HasValue && state.NoDriveTypeAutoRun.Value == 0xFF;
        bool autoPlayDisabled = state.DisableAutoplay.HasValue && state.DisableAutoplay.Value == 1;
        if (autoRunDisabled || autoPlayDisabled)
            result.Findings.Add(Finding.Pass("AutoPlay/AutoRun Disabled", "AutoRun is disabled, preventing automatic execution from removable media.", cat));
        else
            result.Findings.Add(Finding.Warning("AutoPlay/AutoRun Not Fully Disabled", "AutoRun is not fully disabled. Malware on USB drives or CDs can execute automatically when inserted.", cat, "Set NoDriveTypeAutoRun to 0xFF to disable AutoRun on all drive types.", "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f"));
    }

    private static void CheckCredentials(RegistryState state, AuditResult result)
    {
        const string cat = "Registry - Credentials";
        if (!string.IsNullOrWhiteSpace(state.CachedLogonsCount) && int.TryParse(state.CachedLogonsCount, out var count))
        {
            if (count > 4)
                result.Findings.Add(Finding.Warning($"High Cached Logon Count ({count})", $"CachedLogonsCount={count}: {count} domain password hashes cached locally. Attackers with disk access can extract and crack these hashes.", cat, "Reduce CachedLogonsCount to 1-2 for workstations, 0 for servers."));
            else
                result.Findings.Add(Finding.Pass("Cached Logon Count Acceptable", $"CachedLogonsCount={count}: within acceptable limits.", cat));
        }
        if (state.WDigestUseLogonCredential.HasValue && state.WDigestUseLogonCredential.Value == 1)
            result.Findings.Add(Finding.Critical("WDigest Plain-Text Credential Storage Enabled", "UseLogonCredential=1: WDigest stores credentials in plain text in LSASS memory. Tools like Mimikatz can extract them directly.", cat, "Disable WDigest: Set UseLogonCredential to 0.", "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" /v UseLogonCredential /t REG_DWORD /d 0 /f"));
        else
            result.Findings.Add(Finding.Pass("WDigest Plain-Text Storage Disabled", "WDigest is not storing credentials in plain text.", cat));
    }

    private static void CheckLsass(RegistryState state, AuditResult result)
    {
        const string cat = "Registry - LSASS";
        if (state.LsassRunAsPpl.HasValue && state.LsassRunAsPpl.Value >= 1)
            result.Findings.Add(Finding.Pass("LSASS Protected Process Light Enabled", "RunAsPPL is enabled - LSASS runs as a protected process, preventing credential-dumping tools from accessing its memory.", cat));
        else
            result.Findings.Add(Finding.Warning("LSASS Not Running as Protected Process", "RunAsPPL is not enabled. Credential-dumping tools like Mimikatz can directly access LSASS memory to extract passwords and hashes.", cat, "Enable LSASS protection: Set RunAsPPL to 1.", "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RunAsPPL /t REG_DWORD /d 1 /f"));
    }

    private static void CheckScriptHost(RegistryState state, AuditResult result)
    {
        const string cat = "Registry - Scripting";
        if (state.ScriptHostEnabled != null && state.ScriptHostEnabled == "0")
            result.Findings.Add(Finding.Pass("Windows Script Host Disabled", "WSH is disabled - .vbs and .js scripts cannot execute via wscript/cscript.", cat));
        else
            result.Findings.Add(Finding.Info("Windows Script Host Enabled", "WSH is enabled. Malicious .vbs/.js scripts can execute via wscript.exe or cscript.exe. Consider disabling if not needed.", cat, "Disable WSH: Set Enabled to 0 under Windows Script Host\\Settings."));
    }

    private static void CheckWinRm(RegistryState state, AuditResult result)
    {
        const string cat = "Registry - WinRM";
        bool winRmActive = state.WinRmAllowAutoConfig.HasValue && state.WinRmAllowAutoConfig.Value == 1;
        if (!winRmActive)
        {
            result.Findings.Add(Finding.Pass("WinRM Not Auto-Configured", "WinRM auto-configuration is not enabled via policy.", cat));
            return;
        }
        result.Findings.Add(Finding.Info("WinRM Auto-Configuration Enabled", "WinRM is auto-configured via policy. Ensure it is secured with HTTPS and proper auth.", cat));
        if (state.WinRmAllowUnencrypted.HasValue && state.WinRmAllowUnencrypted.Value == 1)
            result.Findings.Add(Finding.Critical("WinRM Allows Unencrypted Traffic", "AllowUnencryptedTraffic=1: WinRM accepts plain HTTP connections. Credentials and commands transmitted in clear text.", cat, "Set AllowUnencryptedTraffic to 0.", "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f"));
        if (state.WinRmAllowBasic.HasValue && state.WinRmAllowBasic.Value == 1)
            result.Findings.Add(Finding.Warning("WinRM Basic Authentication Enabled", "AllowBasic=1: WinRM client allows Basic authentication, which sends credentials in Base64 (effectively plain text).", cat, "Disable Basic auth: Set AllowBasic to 0 under WinRM\\Client."));
    }

    private static void CheckDllSafety(RegistryState state, AuditResult result)
    {
        const string cat = "Registry - DLL Safety";
        if (state.SafeDllSearchMode.HasValue && state.SafeDllSearchMode.Value == 0)
            result.Findings.Add(Finding.Warning("Safe DLL Search Mode Disabled", "SafeDllSearchMode=0: current working directory is searched before system directories when loading DLLs, enabling DLL hijacking attacks.", cat, "Enable safe search: Set SafeDllSearchMode to 1.", "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\" /v SafeDllSearchMode /t REG_DWORD /d 1 /f"));
        else
            result.Findings.Add(Finding.Pass("Safe DLL Search Mode Enabled", "DLL search order is secure - system directories are searched before the current directory.", cat));
    }

    private static void CheckPersistence(RegistryState state, AuditResult result)
    {
        const string cat = "Registry - Persistence";
        if (state.LoadAppInitDlls.HasValue && state.LoadAppInitDlls.Value == 1 && state.AppInitDlls.Count > 0)
            result.Findings.Add(Finding.Critical("AppInit_DLLs Active", $"LoadAppInit_DLLs=1 with {state.AppInitDlls.Count} DLL(s): {string.Join(", ", state.AppInitDlls)}. These DLLs are loaded into every user-mode process - a common malware persistence technique.", cat, "Remove AppInit_DLLs entries and set LoadAppInit_DLLs to 0.", "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f"));
        else if (state.AppInitDlls.Count > 0)
            result.Findings.Add(Finding.Info("AppInit_DLLs Configured but Not Loaded", $"{state.AppInitDlls.Count} DLL(s) in AppInit_DLLs but LoadAppInit_DLLs is off.", cat));
        else
            result.Findings.Add(Finding.Pass("No AppInit_DLLs", "AppInit_DLLs is empty - no DLLs injected into user-mode processes.", cat));

        var legitimateIfeo = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe", "atbroker.exe" };
        var suspiciousIfeo = state.IfeoDebuggers.Where(e => !string.IsNullOrWhiteSpace(e.DebuggerValue)).ToList();
        if (suspiciousIfeo.Count > 0)
        {
            var accessibilityHijacks = suspiciousIfeo.Where(e => legitimateIfeo.Contains(e.TargetExecutable)).ToList();
            if (accessibilityHijacks.Count > 0)
            {
                var targets = string.Join(", ", accessibilityHijacks.Select(e => $"{e.TargetExecutable} -> {e.DebuggerValue}"));
                result.Findings.Add(Finding.Critical("Accessibility Binary Hijacking Detected", $"IFEO debugger set on accessibility executables: {targets}. This is a well-known persistence technique (T1546.008) allowing unauthenticated code execution from the login screen.", cat, "Remove the Debugger values from Image File Execution Options for these executables."));
            }
            var otherIfeo = suspiciousIfeo.Where(e => !legitimateIfeo.Contains(e.TargetExecutable)).ToList();
            if (otherIfeo.Count > 0)
            {
                var entries = string.Join("; ", otherIfeo.Select(e => $"{e.TargetExecutable} -> {e.DebuggerValue}"));
                result.Findings.Add(Finding.Warning($"IFEO Debuggers Found ({otherIfeo.Count})", $"Image File Execution Options debugger entries: {entries}. While sometimes legitimate, IFEO debugger entries can redirect execution of targeted programs.", cat, "Verify each IFEO debugger entry is intentional and legitimate."));
            }
        }
        else
            result.Findings.Add(Finding.Pass("No IFEO Debugger Entries", "No Image File Execution Options debugger entries found.", cat));

        if (!string.IsNullOrWhiteSpace(state.WinlogonShell))
        {
            var shell = state.WinlogonShell.Trim();
            if (!shell.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase) && !shell.Equals("Explorer.exe", StringComparison.OrdinalIgnoreCase))
                result.Findings.Add(Finding.Critical("Non-Standard Winlogon Shell", $"Winlogon Shell is set to \"{shell}\" instead of explorer.exe. Malware replaces the shell to gain control of the desktop session.", cat, "Restore Shell to explorer.exe.", "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Shell /t REG_SZ /d explorer.exe /f"));
        }

        if (!string.IsNullOrWhiteSpace(state.WinlogonUserinit))
        {
            var userinit = state.WinlogonUserinit.Trim().TrimEnd(',');
            var expected = new[] { "userinit.exe", @"C:\Windows\system32\userinit.exe" };
            if (!expected.Any(e => userinit.Equals(e, StringComparison.OrdinalIgnoreCase)))
                result.Findings.Add(Finding.Critical("Non-Standard Winlogon Userinit", $"Winlogon Userinit is set to \"{state.WinlogonUserinit}\" instead of the default userinit.exe. This executes before the shell and is a high-value persistence target.", cat, "Restore Userinit to C:\\Windows\\system32\\userinit.exe,."));
        }
    }
}
