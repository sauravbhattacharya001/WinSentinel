using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;
using Microsoft.Win32;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Identity &amp; Credential audit module — local admin sprawl, stale accounts,
/// password-never-expires, LAPS posture, and cached credentials count.
/// Complements AccountAudit with deeper credential hygiene checks.
///
/// This module owns only the <em>collection</em> of raw system state into an
/// <see cref="IdentityCredentialAnalyzer.IdentityState"/>; every pass/warn/info
/// decision is made by the pure, unit-tested <see cref="IdentityCredentialAnalyzer"/>.
/// </summary>
public class IdentityCredentialAudit : AuditModuleBase
{
    public override string Name => "Identity & Credential Audit";
    public override string Category => "Identity";
    public override string Description =>
        "Audits local admin sprawl, stale accounts, password-never-expires flags, " +
        "LAPS deployment status, cached credential exposure, LSA Protection (RunAsPPL), " +
        "WDigest cleartext credential caching, LM/NTLM authentication level, and Credential Guard.";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = await CollectStateAsync(cancellationToken);
        foreach (var finding in IdentityCredentialAnalyzer.BuildFindings(state))
            result.Findings.Add(finding);
    }

    // ── Data collection (calls real system) ─────────────────────

    /// <summary>
    /// Collects the current identity / credential posture from the system into a
    /// plain state object. No findings are produced here — that is the analyzer's
    /// job — so this method can fail a single probe without affecting the others.
    /// </summary>
    public async Task<IdentityCredentialAnalyzer.IdentityState> CollectStateAsync(CancellationToken ct = default)
    {
        var state = new IdentityCredentialAnalyzer.IdentityState();

        await CollectPasswordNeverExpires(state, ct);
        await CollectStaleAccounts(state, ct);
        await CollectLocalAdminSprawl(state, ct);
        await CollectLapsPosture(state, ct);
        CollectCachedCredentials(state);
        CollectLsaProtection(state);
        CollectCredentialGuard(state);
        CollectWDigest(state);
        CollectNtlmLevel(state);

        return state;
    }

    /// <summary>
    /// Collects enabled local accounts with the "password never expires" flag set.
    /// CIS L1: 1.1.5 — Ensure 'Password never expires' is not set for service accounts.
    /// </summary>
    private async Task CollectPasswordNeverExpires(IdentityCredentialAnalyzer.IdentityState state, CancellationToken ct)
    {
        try
        {
            var output = await ShellHelper.RunPowerShellAsync(
                "Get-LocalUser | Where-Object { $_.Enabled -and $_.PasswordExpires -eq $null } | " +
                "Select-Object Name, LastLogon | ConvertTo-Json -Compress", ct);

            state.NeverExpireAccountNames = IdentityCredentialAnalyzer.ExtractJsonNames(output).ToList();
        }
        catch
        {
            state.PasswordExpiryCheckFailed = true;
        }
    }

    /// <summary>
    /// Collects stale local accounts (enabled but not logged in for 90+ days).
    /// </summary>
    private async Task CollectStaleAccounts(IdentityCredentialAnalyzer.IdentityState state, CancellationToken ct)
    {
        try
        {
            var output = await ShellHelper.RunPowerShellAsync(
                "$cutoff = (Get-Date).AddDays(-90); " +
                "Get-LocalUser | Where-Object { $_.Enabled -and $_.LastLogon -and $_.LastLogon -lt $cutoff } | " +
                "Select-Object -ExpandProperty Name", ct);

            state.StaleAccountNames = output
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(n => !string.IsNullOrWhiteSpace(n))
                .ToList();
        }
        catch
        {
            state.StaleAccountCheckFailed = true;
        }
    }

    /// <summary>
    /// Collects local admin sprawl signal — member count and whether any nested
    /// groups exist in the Administrators group.
    /// </summary>
    private async Task CollectLocalAdminSprawl(IdentityCredentialAnalyzer.IdentityState state, CancellationToken ct)
    {
        try
        {
            var output = await ShellHelper.RunPowerShellAsync(
                "Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | " +
                "Select-Object Name, ObjectClass, PrincipalSource | ConvertTo-Json -Compress", ct);

            if (string.IsNullOrWhiteSpace(output) || output.Trim() == "null")
                return;

            state.AdminGroupReadable = true;

            // Count members by number of "Name": occurrences.
            var lines = output.Split("\"Name\":", StringSplitOptions.RemoveEmptyEntries);
            state.AdminMemberCount = Math.Max(1, lines.Length - 1);

            state.AdminGroupHasNestedGroups =
                output.Contains("\"ObjectClass\":\"Group\"", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            // Already covered in AccountAudit at a basic level; leave AdminGroupReadable=false.
        }
    }

    /// <summary>
    /// Collects whether LAPS (Local Administrator Password Solution) is deployed.
    /// LAPS randomizes local admin passwords — critical for domain-joined machines.
    /// </summary>
    private async Task CollectLapsPosture(IdentityCredentialAnalyzer.IdentityState state, CancellationToken ct)
    {
        try
        {
            var domainOutput = await ShellHelper.RunPowerShellAsync(
                "(Get-CimInstance Win32_ComputerSystem).PartOfDomain", ct);

            state.IsDomainJoined = domainOutput.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);

            if (!state.IsDomainJoined) return;

            // Windows LAPS (built into Windows 11 23H2+ / Server 2025)
            var windowsLaps = await ShellHelper.RunPowerShellAsync(
                "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS\\State' " +
                "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty PasswordExpirationTime -ErrorAction SilentlyContinue", ct);

            if (!string.IsNullOrWhiteSpace(windowsLaps) && !windowsLaps.Contains("Error"))
            {
                state.WindowsLapsActive = true;
                return;
            }

            // Legacy LAPS (Microsoft LAPS CSE)
            var legacyLaps = await ShellHelper.RunPowerShellAsync(
                "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions\\{D76B9641-3288-4f75-942D-087DE603E3EA}' " +
                "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty DllName -ErrorAction SilentlyContinue", ct);

            if (!string.IsNullOrWhiteSpace(legacyLaps) && legacyLaps.Contains("AdmPwd", StringComparison.OrdinalIgnoreCase))
            {
                state.LegacyLapsInstalled = true;
            }
        }
        catch
        {
            state.LapsCheckFailed = true;
        }
    }

    /// <summary>
    /// Collects the cached logon credentials count from the registry.
    /// Default is 10; reducing to 1-2 limits credential theft on stolen laptops.
    /// </summary>
    private void CollectCachedCredentials(IdentityCredentialAnalyzer.IdentityState state)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");

            if (key == null) return;

            var cachedStr = key.GetValue("CachedLogonsCount")?.ToString();
            if (int.TryParse(cachedStr, out int cached))
            {
                state.CachedLogonsConfigured = true;
                state.CachedLogonsCount = cached;
            }
        }
        catch
        {
            // Registry access restricted — leave CachedLogonsConfigured=false.
        }
    }

    /// <summary>
    /// Collects the WDigest <c>UseLogonCredential</c> setting. When 1, WDigest stores the
    /// user's plaintext password in LSASS memory, where credential-dumping tools (Mimikatz
    /// <c>sekurlsa::wdigest</c>) can read it directly. Windows 8.1 / Server 2012 R2 and later
    /// (via KB2871997 on older OSes) default to 0 / unset, so an explicit 1 is a real
    /// regression that reintroduces cleartext credential exposure (MITRE ATT&amp;CK T1003.001).
    /// </summary>
    private void CollectWDigest(IdentityCredentialAnalyzer.IdentityState state)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest");

            if (key == null) return;

            state.WDigestKeyReadable = true;
            var useLogonCred = key.GetValue("UseLogonCredential");
            if (useLogonCred != null)
            {
                state.WDigestValueSet = true;
                state.WDigestUseLogonCredential = Convert.ToInt32(useLogonCred);
            }
        }
        catch
        {
            // Registry access restricted — leave WDigestKeyReadable=false (audit stays quiet).
        }
    }

    /// <summary>
    /// Collects LSA Protection (RunAsPPL) status — protects lsass.exe from dumping.
    /// </summary>
    /// <summary>
    /// Collects LmCompatibilityLevel from HKLM\SYSTEM\CurrentControlSet\Control\Lsa (CIS Windows L1 2.3.11.7).
    /// Level 5 sends NTLMv2 only and refuses LM/NTLMv1; lower levels still produce/accept crackable legacy responses.
    /// </summary>
    private void CollectNtlmLevel(IdentityCredentialAnalyzer.IdentityState state)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Lsa");

            if (key == null) return;

            state.LmCompatibilityKeyReadable = true;
            var level = key.GetValue("LmCompatibilityLevel");
            if (level != null)
            {
                state.LmCompatibilityLevelSet = true;
                state.LmCompatibilityLevel = Convert.ToInt32(level);
            }
        }
        catch
        {
            // Registry access restricted - leave LmCompatibilityKeyReadable=false (audit stays quiet).
        }
    }

    private void CollectLsaProtection(IdentityCredentialAnalyzer.IdentityState state)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Lsa");

            if (key == null) return;

            state.LsaKeyReadable = true;
            var runAsPpl = key.GetValue("RunAsPPL");
            // RunAsPPL: 1 = enabled WITH a UEFI lock (tamper-resistant; stored in a UEFI
            // variable so deleting the registry value after reboot has no effect),
            // 2 = enabled WITHOUT the UEFI lock (registry only, easier to roll back).
            // Both values enable PPL; only 1 is locked into firmware. Treating 2 as
            // "not enabled" (the old `== 1` check) was a false-negative that flagged
            // machines running LSA Protection without the UEFI lock.
            int runAsPplValue = runAsPpl != null ? Convert.ToInt32(runAsPpl) : 0;
            state.RunAsPplEnabled = runAsPplValue == 1 || runAsPplValue == 2;
            state.RunAsPplUefiLocked = runAsPplValue == 1;
        }
        catch
        {
            // Registry access restricted — leave LsaKeyReadable=false.
        }
    }

    /// <summary>
    /// Collects Windows Credential Guard status (virtualization-based credential isolation).
    /// </summary>
    private void CollectCredentialGuard(IdentityCredentialAnalyzer.IdentityState state)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard");

            if (key == null) return;

            state.DeviceGuardKeyPresent = true;

            var enableVbs = key.GetValue("EnableVirtualizationBasedSecurity");
            state.VbsEnabled = enableVbs != null && Convert.ToInt32(enableVbs) == 1;

            using var lsaCfgKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Lsa");
            var lsaCfg = lsaCfgKey?.GetValue("LsaCfgFlags");
            if (lsaCfg != null) state.LsaCfgFlags = Convert.ToInt32(lsaCfg);
        }
        catch
        {
            // Registry access restricted — leave DeviceGuardKeyPresent=false.
        }
    }
}
