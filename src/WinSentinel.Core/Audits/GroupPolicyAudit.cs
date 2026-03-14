using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;
using Microsoft.Win32;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits security-relevant Group Policy settings by reading the registry
/// keys that GPO writes.
/// </summary>
public class GroupPolicyAudit : IAuditModule
{
    public string Name => "Group Policy Security Audit";
    public string Category => "GroupPolicy";
    public string Description =>
        "Checks security-relevant Group Policy settings including account lockout, " +
        "NTLM restrictions, audit policy, credential protection, SMB signing, " +
        "and application whitelisting configuration.";

    public sealed class GpoState
    {
        public int? LockoutThreshold { get; set; }
        public int? LockoutDuration { get; set; }
        public int? LockoutObservationWindow { get; set; }
        public int? LmCompatibilityLevel { get; set; }
        public int? RestrictNtlmOutgoing { get; set; }
        public int? RestrictAnonymousSam { get; set; }
        public int? RestrictAnonymous { get; set; }
        public int? EveryoneIncludesAnonymous { get; set; }
        public int? SmbServerRequireSigning { get; set; }
        public int? SmbClientRequireSigning { get; set; }
        public int? CredentialGuardConfig { get; set; }
        public bool? VbsEnabled { get; set; }
        public bool? VbsRunning { get; set; }
        public int? AuditProcessCommandLine { get; set; }
        public int? AuditProcessCreation { get; set; }
        public int? AuditLogonEvents { get; set; }
        public int? AuditPrivilegeUse { get; set; }
        public int? RestrictedAdminMode { get; set; }
        public int? AllowEncryptionOracle { get; set; }
        public int? NlaRequired { get; set; }
        public int? RdpEncryptionLevel { get; set; }
        public int? AuEnabled { get; set; }
        public bool WuManaged { get; set; }
        public bool AppLockerConfigured { get; set; }
        public int AppLockerExeRuleCount { get; set; }
        public bool SrpConfigured { get; set; }
        public int? SrpDefaultLevel { get; set; }
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

    internal async Task<GpoState> GatherStateAsync(CancellationToken ct)
    {
        var state = new GpoState();

        state.LockoutThreshold = await ReadNetAccountsValueAsync("lockout threshold", ct);
        state.LockoutDuration = await ReadNetAccountsValueAsync("lockout duration", ct);
        state.LockoutObservationWindow = await ReadNetAccountsValueAsync("lockout observation window", ct);

        state.LmCompatibilityLevel = ReadRegistryDword(
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel");
        state.RestrictNtlmOutgoing = ReadRegistryDword(
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "RestrictSendingNTLMTraffic");

        state.RestrictAnonymousSam = ReadRegistryDword(
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM");
        state.RestrictAnonymous = ReadRegistryDword(
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymous");
        state.EveryoneIncludesAnonymous = ReadRegistryDword(
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "EveryoneIncludesAnonymous");

        state.SmbServerRequireSigning = ReadRegistryDword(
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature");
        state.SmbClientRequireSigning = ReadRegistryDword(
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature");

        state.CredentialGuardConfig = ReadRegistryDword(
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "LsaCfgFlags");
        try
        {
            var vbsOutput = await ShellHelper.RunPowerShellAsync(
                "(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard " +
                "-ErrorAction SilentlyContinue).VirtualizationBasedSecurityStatus", ct);
            if (int.TryParse(vbsOutput.Trim(), out var vbsVal))
            {
                state.VbsRunning = vbsVal == 2;
                state.VbsEnabled = vbsVal >= 1;
            }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        state.AuditProcessCommandLine = ReadRegistryDword(
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
            "ProcessCreationIncludeCmdLine_Enabled");

        try
        {
            var auditOutput = await ShellHelper.RunPowerShellAsync(
                "auditpol /get /subcategory:\"Process Creation\" /r 2>$null | " +
                "Select-Object -Skip 1 | ConvertFrom-Csv | Select-Object -ExpandProperty 'Inclusion Setting'", ct);
            state.AuditProcessCreation = ParseAuditSetting(auditOutput.Trim());
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        try
        {
            var logonOutput = await ShellHelper.RunPowerShellAsync(
                "auditpol /get /subcategory:\"Logon\" /r 2>$null | " +
                "Select-Object -Skip 1 | ConvertFrom-Csv | Select-Object -ExpandProperty 'Inclusion Setting'", ct);
            state.AuditLogonEvents = ParseAuditSetting(logonOutput.Trim());
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        try
        {
            var privOutput = await ShellHelper.RunPowerShellAsync(
                "auditpol /get /subcategory:\"Sensitive Privilege Use\" /r 2>$null | " +
                "Select-Object -Skip 1 | ConvertFrom-Csv | Select-Object -ExpandProperty 'Inclusion Setting'", ct);
            state.AuditPrivilegeUse = ParseAuditSetting(privOutput.Trim());
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        state.RestrictedAdminMode = ReadRegistryDword(
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "DisableRestrictedAdmin");
        state.AllowEncryptionOracle = ReadRegistryDword(
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters",
            "AllowEncryptionOracle");

        state.NlaRequired = ReadRegistryDword(
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "UserAuthentication");
        state.RdpEncryptionLevel = ReadRegistryDword(
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "MinEncryptionLevel");

        state.AuEnabled = ReadRegistryDword(
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "AUOptions");
        var wuServer = Registry.GetValue(
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "WUServer", null);
        state.WuManaged = wuServer != null;

        try
        {
            var alOutput = await ShellHelper.RunPowerShellAsync(
                "(Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue).RuleCollections.Count", ct);
            if (int.TryParse(alOutput.Trim(), out var alCount) && alCount > 0)
            {
                state.AppLockerConfigured = true;
                var exeOutput = await ShellHelper.RunPowerShellAsync(
                    "((Get-AppLockerPolicy -Effective).RuleCollections | " +
                    "Where-Object { $_.RuleCollectionType -eq 'Exe' }).Count", ct);
                if (int.TryParse(exeOutput.Trim(), out var exeCount))
                    state.AppLockerExeRuleCount = exeCount;
            }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        state.SrpDefaultLevel = ReadRegistryDword(
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers", "DefaultLevel");
        state.SrpConfigured = state.SrpDefaultLevel.HasValue;

        return state;
    }

    public void AnalyzeState(GpoState state, AuditResult result)
    {
        CheckAccountLockout(state, result);
        CheckNtlm(state, result);
        CheckAnonymousAccess(state, result);
        CheckSmbSigning(state, result);
        CheckCredentialGuard(state, result);
        CheckAuditPolicy(state, result);
        CheckCredentialDelegation(state, result);
        CheckRemoteDesktop(state, result);
        CheckWindowsUpdate(state, result);
        CheckApplicationControl(state, result);
    }

    private void CheckAccountLockout(GpoState state, AuditResult result)
    {
        if (!state.LockoutThreshold.HasValue || state.LockoutThreshold.Value == 0)
        {
            result.Findings.Add(Finding.Critical(
                "Account Lockout Not Configured",
                "No account lockout threshold is set. Attackers can attempt unlimited password guesses.",
                Category, "Set account lockout threshold to 5-10 failed attempts.",
                "net accounts /lockoutthreshold:5"));
        }
        else if (state.LockoutThreshold.Value > 10)
        {
            result.Findings.Add(Finding.Warning(
                "Weak Account Lockout Threshold",
                $"Account lockout triggers after {state.LockoutThreshold.Value} failed attempts.",
                Category, "Consider lowering the lockout threshold to 5-10 attempts."));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Account Lockout Configured",
                $"Account lockout is set to {state.LockoutThreshold.Value} failed attempts.",
                Category));
        }

        if (state.LockoutDuration.HasValue && state.LockoutDuration.Value > 0
            && state.LockoutDuration.Value < 15)
        {
            result.Findings.Add(Finding.Warning(
                "Short Lockout Duration",
                $"Lockout duration is only {state.LockoutDuration.Value} minute(s).",
                Category, "Set lockout duration to at least 15-30 minutes.",
                "net accounts /lockoutduration:30"));
        }
    }

    private void CheckNtlm(GpoState state, AuditResult result)
    {
        if (!state.LmCompatibilityLevel.HasValue)
        {
            result.Findings.Add(Finding.Warning(
                "NTLM Authentication Level Not Configured",
                "LAN Manager authentication level is not explicitly set via policy.",
                Category,
                "Set LmCompatibilityLevel to 5 (Send NTLMv2 response only, refuse LM & NTLM)."));
        }
        else if (state.LmCompatibilityLevel.Value < 3)
        {
            result.Findings.Add(Finding.Critical(
                "Weak NTLM Authentication Allowed",
                $"LmCompatibilityLevel is {state.LmCompatibilityLevel.Value}, allowing LM or NTLMv1.",
                Category, "Set LmCompatibilityLevel to 5 (NTLMv2 only, refuse LM & NTLM)."));
        }
        else if (state.LmCompatibilityLevel.Value < 5)
        {
            result.Findings.Add(Finding.Info(
                "NTLM Partially Restricted",
                $"LmCompatibilityLevel is {state.LmCompatibilityLevel.Value}. NTLMv2 is used but older protocols are not fully refused.",
                Category, "Consider raising to 5 for maximum protection."));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "NTLMv2 Only Authentication",
                "LmCompatibilityLevel is 5 — only NTLMv2 responses are sent.",
                Category));
        }
    }

    private void CheckAnonymousAccess(GpoState state, AuditResult result)
    {
        if (state.RestrictAnonymousSam.HasValue && state.RestrictAnonymousSam.Value == 1)
        {
            result.Findings.Add(Finding.Pass(
                "Anonymous SAM Enumeration Restricted",
                "Anonymous users cannot enumerate SAM accounts and shares.",
                Category));
        }
        else
        {
            result.Findings.Add(Finding.Warning(
                "Anonymous SAM Enumeration Allowed",
                "Anonymous users may be able to enumerate local accounts and shares.",
                Category, "Set RestrictAnonymousSAM to 1."));
        }

        if (state.EveryoneIncludesAnonymous.HasValue && state.EveryoneIncludesAnonymous.Value == 1)
        {
            result.Findings.Add(Finding.Critical(
                "Everyone Includes Anonymous",
                "The Everyone security group includes anonymous users.",
                Category, "Set EveryoneIncludesAnonymous to 0."));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Everyone Excludes Anonymous",
                "Anonymous users are not included in the Everyone security group.",
                Category));
        }
    }

    private void CheckSmbSigning(GpoState state, AuditResult result)
    {
        if (state.SmbServerRequireSigning.HasValue && state.SmbServerRequireSigning.Value == 1)
        {
            result.Findings.Add(Finding.Pass("SMB Server Signing Required",
                "SMB server requires packet signing.", Category));
        }
        else
        {
            result.Findings.Add(Finding.Warning("SMB Server Signing Not Required",
                "SMB server does not require packet signing. This allows SMB relay attacks.",
                Category, "Enable mandatory SMB server signing."));
        }

        if (state.SmbClientRequireSigning.HasValue && state.SmbClientRequireSigning.Value == 1)
        {
            result.Findings.Add(Finding.Pass("SMB Client Signing Required",
                "SMB client requires packet signing for outbound connections.", Category));
        }
        else
        {
            result.Findings.Add(Finding.Warning("SMB Client Signing Not Required",
                "SMB client does not require packet signing for outbound connections.",
                Category, "Enable mandatory SMB client signing."));
        }
    }

    private void CheckCredentialGuard(GpoState state, AuditResult result)
    {
        if (state.VbsRunning == true)
        {
            result.Findings.Add(Finding.Pass("Virtualization-Based Security Running",
                "VBS is active, providing hardware-backed isolation.", Category));
        }
        else if (state.VbsEnabled == true)
        {
            result.Findings.Add(Finding.Info("VBS Enabled But Not Running",
                "VBS is enabled but not currently running. A reboot may be required.",
                Category));
        }
        else
        {
            result.Findings.Add(Finding.Warning("Virtualization-Based Security Not Enabled",
                "VBS is not enabled. Credential Guard and HVCI cannot protect against credential theft.",
                Category, "Enable VBS via Group Policy."));
        }

        if (state.CredentialGuardConfig.HasValue && state.CredentialGuardConfig.Value >= 1)
        {
            var lockType = state.CredentialGuardConfig.Value == 1 ? "with UEFI lock" : "without UEFI lock";
            result.Findings.Add(Finding.Pass("Credential Guard Configured",
                $"Credential Guard is enabled ({lockType}).", Category));
        }
        else if (state.VbsEnabled == true || state.VbsRunning == true)
        {
            result.Findings.Add(Finding.Info("Credential Guard Not Configured",
                "VBS is available but Credential Guard is not enabled.",
                Category, "Set LsaCfgFlags to 1 (UEFI lock) or 2 (no lock)."));
        }
    }

    private void CheckAuditPolicy(GpoState state, AuditResult result)
    {
        if (state.AuditProcessCreation.HasValue && (state.AuditProcessCreation.Value & 1) != 0)
        {
            result.Findings.Add(Finding.Pass("Process Creation Auditing Enabled",
                "Successful process creation events are being logged (Event ID 4688).", Category));
        }
        else
        {
            result.Findings.Add(Finding.Warning("Process Creation Auditing Not Enabled",
                "Process creation events are not being audited.", Category,
                "Enable process creation auditing.",
                "auditpol /set /subcategory:\"Process Creation\" /success:enable /failure:enable"));
        }

        if (state.AuditProcessCommandLine.HasValue && state.AuditProcessCommandLine.Value == 1)
        {
            result.Findings.Add(Finding.Pass("Command-Line Process Auditing Enabled",
                "Command-line arguments are included in process creation events.", Category));
        }
        else
        {
            result.Findings.Add(Finding.Warning("Command-Line Process Auditing Not Enabled",
                "Process creation events do not include command-line arguments.", Category,
                "Enable command-line process auditing."));
        }

        if (state.AuditLogonEvents.HasValue && state.AuditLogonEvents.Value >= 1)
        {
            result.Findings.Add(Finding.Pass("Logon Auditing Enabled",
                "Logon events are being audited.", Category));
        }
        else
        {
            result.Findings.Add(Finding.Warning("Logon Auditing Not Enabled",
                "Logon events are not audited.", Category, "Enable logon auditing.",
                "auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable"));
        }

        if (state.AuditPrivilegeUse.HasValue && (state.AuditPrivilegeUse.Value & 1) != 0)
        {
            result.Findings.Add(Finding.Pass("Privilege Use Auditing Enabled",
                "Sensitive privilege use is being audited.", Category));
        }
        else
        {
            result.Findings.Add(Finding.Info("Privilege Use Auditing Not Enabled",
                "Sensitive privilege use is not audited.", Category, "Enable privilege use auditing.",
                "auditpol /set /subcategory:\"Sensitive Privilege Use\" /success:enable"));
        }
    }

    private void CheckCredentialDelegation(GpoState state, AuditResult result)
    {
        if (state.AllowEncryptionOracle.HasValue)
        {
            if (state.AllowEncryptionOracle.Value == 0)
            {
                result.Findings.Add(Finding.Critical("CredSSP Vulnerable Configuration",
                    "AllowEncryptionOracle is 0 (Vulnerable). RDP connections susceptible to CVE-2018-0886.",
                    Category, "Set AllowEncryptionOracle to 2 (Force Updated Clients)."));
            }
            else if (state.AllowEncryptionOracle.Value == 1)
            {
                result.Findings.Add(Finding.Warning("CredSSP Mitigated But Not Enforced",
                    "AllowEncryptionOracle is 1 (Mitigated). Unpatched clients can still connect.",
                    Category, "Set to 2 (Force Updated Clients) for full protection."));
            }
            else
            {
                result.Findings.Add(Finding.Pass("CredSSP Fully Patched",
                    "AllowEncryptionOracle is 2 (Force Updated Clients).", Category));
            }
        }

        if (state.RestrictedAdminMode.HasValue && state.RestrictedAdminMode.Value == 0)
        {
            result.Findings.Add(Finding.Pass("Restricted Admin Mode Available",
                "Restricted Admin mode for RDP is not disabled.", Category));
        }
    }

    private void CheckRemoteDesktop(GpoState state, AuditResult result)
    {
        if (state.NlaRequired.HasValue && state.NlaRequired.Value == 1)
        {
            result.Findings.Add(Finding.Pass("NLA Required for Remote Desktop",
                "Network Level Authentication is required.", Category));
        }
        else if (state.NlaRequired.HasValue)
        {
            result.Findings.Add(Finding.Warning("NLA Not Required for Remote Desktop",
                "Network Level Authentication is not enforced.", Category,
                "Enable NLA for Remote Desktop connections."));
        }

        if (state.RdpEncryptionLevel.HasValue && state.RdpEncryptionLevel.Value < 3)
        {
            result.Findings.Add(Finding.Warning("Low RDP Encryption Level",
                $"RDP encryption level is {state.RdpEncryptionLevel.Value} (1=Low, 2=Client Compatible).",
                Category, "Set minimum encryption level to High (3) or FIPS (4)."));
        }
        else if (state.RdpEncryptionLevel.HasValue)
        {
            var levelName = state.RdpEncryptionLevel.Value == 4 ? "FIPS" : "High";
            result.Findings.Add(Finding.Pass($"RDP Encryption Level: {levelName}",
                $"Remote Desktop encryption level is set to {levelName}.", Category));
        }
    }

    private void CheckWindowsUpdate(GpoState state, AuditResult result)
    {
        if (state.WuManaged)
        {
            result.Findings.Add(Finding.Pass("Windows Update Managed by Policy",
                "Windows Update is managed via WSUS or Windows Update for Business.", Category));
        }
        else if (state.AuEnabled.HasValue && state.AuEnabled.Value >= 3)
        {
            result.Findings.Add(Finding.Pass("Automatic Windows Updates Enabled",
                "Windows Updates are configured to download and install automatically.", Category));
        }
        else if (state.AuEnabled.HasValue && state.AuEnabled.Value >= 2)
        {
            result.Findings.Add(Finding.Info("Windows Update: Download Only",
                "Updates are downloaded automatically but not installed.",
                Category, "Consider enabling automatic installation (AUOptions = 4)."));
        }
        else
        {
            result.Findings.Add(Finding.Warning("Windows Update Policy Not Configured",
                "No Group Policy controls Windows Update behavior.",
                Category, "Configure Windows Update via Group Policy."));
        }
    }

    private void CheckApplicationControl(GpoState state, AuditResult result)
    {
        if (state.AppLockerConfigured)
        {
            result.Findings.Add(Finding.Pass("AppLocker Policies Configured",
                $"AppLocker is active with {state.AppLockerExeRuleCount} executable rules.", Category));
        }
        else if (state.SrpConfigured)
        {
            if (state.SrpDefaultLevel == 0)
            {
                result.Findings.Add(Finding.Pass("Software Restriction Policies: Whitelist Mode",
                    "SRP is configured in Disallowed-by-default mode.", Category));
            }
            else
            {
                result.Findings.Add(Finding.Info("Software Restriction Policies: Unrestricted",
                    "SRP is configured but in Unrestricted mode.", Category));
            }
        }
        else
        {
            result.Findings.Add(Finding.Info("No Application Control Policies",
                "Neither AppLocker nor Software Restriction Policies are configured.",
                Category, "Consider configuring AppLocker for application whitelisting."));
        }
    }

    private static int? ReadRegistryDword(string keyPath, string valueName)
    {
        var val = Registry.GetValue(keyPath, valueName, null);
        if (val is int i) return i;
        return null;
    }

    private static async Task<int?> ReadNetAccountsValueAsync(string field, CancellationToken ct)
    {
        try
        {
            var output = await ShellHelper.RunPowerShellAsync("net accounts", ct);
            foreach (var line in output.Split('\n'))
            {
                if (line.IndexOf(field, StringComparison.OrdinalIgnoreCase) < 0) continue;
                var parts = line.Split(':');
                if (parts.Length < 2) continue;
                var val = parts[^1].Trim();
                if (val.Equals("Never", StringComparison.OrdinalIgnoreCase)) return 0;
                if (int.TryParse(val, out var n)) return n;
            }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
        return null;
    }

    public static int? ParseAuditSetting(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var lower = text.ToLowerInvariant().Trim();
        if (lower.Contains("success") && lower.Contains("failure")) return 3;
        if (lower.Contains("success")) return 1;
        if (lower.Contains("failure")) return 2;
        if (lower.Contains("no auditing") || lower == "none") return 0;
        return null;
    }
}
