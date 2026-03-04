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
    public string Name => "Registry Security Audit";
    public string Category => "Registry";
    public string Description =>
        "Checks registry-based security policies including UAC, Remote Desktop, " +
        "credential storage, LSASS protection, scripting hosts, and persistence mechanisms.";

    // Data Transfer Object
    public sealed class RegistryState
    {
        // UAC
        public int? EnableLua { get; set; }
        public int? ConsentPromptBehaviorAdmin { get; set; }
        public int? EnableVirtualization { get; set; }
        // Remote Desktop
        public int? DenyTsConnections { get; set; }
        public int? NlaRequired { get; set; }
        public int? RdpSecurityLayer { get; set; }
        // AutoPlay
        public int? NoDriveTypeAutoRun { get; set; }
        public int? DisableAutoplay { get; set; }
        // Credentials
        public string? CachedLogonsCount { get; set; }
        public int? WDigestUseLogonCredential { get; set; }
        // LSASS
        public int? LsassRunAsPpl { get; set; }
        // Script Host
        public string? ScriptHostEnabled { get; set; }
        // WinRM
        public int? WinRmAllowAutoConfig { get; set; }
        public int? WinRmAllowUnencrypted { get; set; }
        public int? WinRmAllowBasic { get; set; }
        // DLL
        public int? SafeDllSearchMode { get; set; }
        // Persistence
        public List<string> AppInitDlls { get; set; } = new();
        public int? LoadAppInitDlls { get; set; }
        public List<IfeoEntry> IfeoDebuggers { get; set; } = new();
        public List<string> ShellExtensions { get; set; } = new();
        public string? WinlogonShell { get; set; }
        public string? WinlogonUserinit { get; set; }
    }

    public sealed class IfeoEntry
    {
        public string TargetExecutable { get; set; } = string.Empty;
        public string DebuggerValue { get; set; } = string.Empty;
    }

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

    public Task<RegistryState> GatherStateAsync(CancellationToken cancellationToken = default)
    {
        var state = new RegistryState();
        state.EnableLua = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA");
        state.ConsentPromptBehaviorAdmin = RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin");
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
