using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;
using Microsoft.Win32;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Identity &amp; Credential audit module — local admin sprawl, stale accounts,
/// password-never-expires, LAPS posture, and cached credentials count.
/// Complements AccountAudit with deeper credential hygiene checks.
/// </summary>
public class IdentityCredentialAudit : AuditModuleBase
{
    public override string Name => "Identity & Credential Audit";
    public override string Category => "Identity";
    public override string Description =>
        "Audits local admin sprawl, stale accounts, password-never-expires flags, " +
        "LAPS deployment status, and cached credential exposure.";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        await CheckPasswordNeverExpires(result, cancellationToken);
        await CheckStaleAccounts(result, cancellationToken);
        await CheckLocalAdminSprawl(result, cancellationToken);
        await CheckLapsPosture(result, cancellationToken);
        CheckCachedCredentials(result);
        CheckLsaProtection(result);
        CheckCredentialGuard(result);
    }

    /// <summary>
    /// Identifies local accounts with the "password never expires" flag set.
    /// CIS L1: 1.1.5 — Ensure 'Password never expires' is not set for service accounts
    /// </summary>
    private async Task CheckPasswordNeverExpires(AuditResult result, CancellationToken ct)
    {
        try
        {
            var output = await ShellHelper.RunPowerShellAsync(
                "Get-LocalUser | Where-Object { $_.Enabled -and $_.PasswordExpires -eq $null } | " +
                "Select-Object Name, LastLogon | ConvertTo-Json -Compress", ct);

            if (string.IsNullOrWhiteSpace(output) || output.Trim() == "null")
            {
                result.Findings.Add(Finding.Pass(
                    "No Password-Never-Expires Accounts",
                    "All enabled local accounts have password expiration configured.",
                    Category));
                return;
            }

            // Parse JSON array or single object
            var trimmed = output.Trim();
            int count = 0;
            var names = new List<string>();

            if (trimmed.StartsWith('['))
            {
                // Multiple results
                foreach (var line in trimmed.Split(new[] { "\"Name\":" }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var nameMatch = ExtractJsonString(line);
                    if (nameMatch != null)
                    {
                        names.Add(nameMatch);
                        count++;
                    }
                }
            }
            else if (trimmed.StartsWith('{'))
            {
                var nameMatch = ExtractNameFromJson(trimmed);
                if (nameMatch != null) names.Add(nameMatch);
                count = 1;
            }

            // Filter out well-known service accounts that legitimately don't expire
            var wellKnown = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "DefaultAccount", "WDAGUtilityAccount", "Guest"
            };
            var flagged = names.Where(n => !wellKnown.Contains(n)).ToList();

            if (flagged.Count > 0)
            {
                result.Findings.Add(Finding.Warning(
                    $"Password Never Expires ({flagged.Count} account{(flagged.Count > 1 ? "s" : "")})",
                    $"Accounts with password-never-expires: {string.Join(", ", flagged)}. " +
                    "Passwords that never expire increase risk of credential compromise over time.",
                    Category,
                    "Configure password expiration for these accounts or move to managed service accounts.",
                    $"Set-LocalUser -Name '{flagged[0]}' -PasswordNeverExpires $false"));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "No Risky Password-Never-Expires Accounts",
                    "Only well-known system accounts have password-never-expires set.",
                    Category));
            }
        }
        catch
        {
            result.Findings.Add(Finding.Info(
                "Password Expiry Check Skipped",
                "Unable to query local user password expiration status.",
                Category));
        }
    }

    /// <summary>
    /// Detects stale local accounts (enabled but not logged in for 90+ days).
    /// </summary>
    private async Task CheckStaleAccounts(AuditResult result, CancellationToken ct)
    {
        try
        {
            var output = await ShellHelper.RunPowerShellAsync(
                "$cutoff = (Get-Date).AddDays(-90); " +
                "Get-LocalUser | Where-Object { $_.Enabled -and $_.LastLogon -and $_.LastLogon -lt $cutoff } | " +
                "Select-Object -ExpandProperty Name", ct);

            if (string.IsNullOrWhiteSpace(output))
            {
                result.Findings.Add(Finding.Pass(
                    "No Stale Local Accounts",
                    "All enabled accounts have logged in within the last 90 days.",
                    Category));
                return;
            }

            var stale = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(n => !string.IsNullOrWhiteSpace(n))
                .ToList();

            if (stale.Count > 0)
            {
                result.Findings.Add(Finding.Warning(
                    $"Stale Local Accounts ({stale.Count})",
                    $"Accounts not used in 90+ days: {string.Join(", ", stale)}. " +
                    "Stale accounts are attractive targets for attackers.",
                    Category,
                    "Disable or remove accounts that are no longer needed.",
                    $"Disable-LocalUser -Name '{stale[0]}'"));
            }
        }
        catch
        {
            result.Findings.Add(Finding.Info(
                "Stale Account Check Skipped",
                "Unable to query last logon dates for local accounts.",
                Category));
        }
    }

    /// <summary>
    /// Checks for local admin sprawl — non-built-in accounts/groups in Administrators.
    /// More granular than AccountAudit: flags domain users, service accounts with admin rights.
    /// </summary>
    private async Task CheckLocalAdminSprawl(AuditResult result, CancellationToken ct)
    {
        try
        {
            var output = await ShellHelper.RunPowerShellAsync(
                "Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | " +
                "Select-Object Name, ObjectClass, PrincipalSource | ConvertTo-Json -Compress", ct);

            if (string.IsNullOrWhiteSpace(output) || output.Trim() == "null")
                return;

            // Count non-built-in admins
            var lines = output.Split("\"Name\":", StringSplitOptions.RemoveEmptyEntries);
            int totalMembers = Math.Max(1, lines.Length - 1);

            // Check for groups in admin (nested admin is dangerous)
            bool hasGroupMembers = output.Contains("\"ObjectClass\":\"Group\"", StringComparison.OrdinalIgnoreCase);

            if (totalMembers > 3)
            {
                result.Findings.Add(Finding.Warning(
                    $"Local Admin Sprawl ({totalMembers} members)",
                    $"The Administrators group has {totalMembers} members. " +
                    "Excessive admin accounts increase the attack surface. " +
                    "Apply principle of least privilege.",
                    Category,
                    "Remove unnecessary members from the local Administrators group. Use JIT/JEA where possible.",
                    "Get-LocalGroupMember -Group 'Administrators' | Format-Table Name, ObjectClass"));
            }

            if (hasGroupMembers)
            {
                result.Findings.Add(Finding.Info(
                    "Nested Groups in Administrators",
                    "One or more groups are members of the local Administrators group. " +
                    "This creates indirect admin access that may be hard to audit.",
                    Category));
            }
        }
        catch
        {
            // Already covered in AccountAudit at a basic level
        }
    }

    /// <summary>
    /// Checks whether LAPS (Local Administrator Password Solution) is deployed.
    /// LAPS randomizes local admin passwords and stores them in AD — critical for domain-joined machines.
    /// </summary>
    private async Task CheckLapsPosture(AuditResult result, CancellationToken ct)
    {
        try
        {
            // Check if machine is domain-joined first
            var domainOutput = await ShellHelper.RunPowerShellAsync(
                "(Get-CimInstance Win32_ComputerSystem).PartOfDomain", ct);

            bool isDomainJoined = domainOutput.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);

            if (!isDomainJoined)
            {
                result.Findings.Add(Finding.Info(
                    "LAPS Not Applicable (Standalone)",
                    "This machine is not domain-joined. LAPS is an Active Directory feature.",
                    Category));
                return;
            }

            // Check for Windows LAPS (new, built into Windows 11 23H2+ / Server 2025)
            var windowsLaps = await ShellHelper.RunPowerShellAsync(
                "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS\\State' " +
                "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty PasswordExpirationTime -ErrorAction SilentlyContinue", ct);

            if (!string.IsNullOrWhiteSpace(windowsLaps) && !windowsLaps.Contains("Error"))
            {
                result.Findings.Add(Finding.Pass(
                    "Windows LAPS Active",
                    "Windows LAPS is managing the local administrator password on this domain-joined machine.",
                    Category));
                return;
            }

            // Check for legacy LAPS (Microsoft LAPS CSE)
            var legacyLaps = await ShellHelper.RunPowerShellAsync(
                "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions\\{D76B9641-3288-4f75-942D-087DE603E3EA}' " +
                "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty DllName -ErrorAction SilentlyContinue", ct);

            if (!string.IsNullOrWhiteSpace(legacyLaps) && legacyLaps.Contains("AdmPwd", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add(Finding.Pass(
                    "Legacy LAPS Installed",
                    "Microsoft LAPS client-side extension is installed on this domain-joined machine.",
                    Category));
                return;
            }

            result.Findings.Add(Finding.Warning(
                "LAPS Not Deployed",
                "This domain-joined machine does not have LAPS (Local Administrator Password Solution) " +
                "installed. Without LAPS, the local admin password is likely static across the environment, " +
                "enabling lateral movement after a single credential compromise.",
                Category,
                "Deploy Windows LAPS (preferred) or legacy Microsoft LAPS to randomize local admin passwords.",
                "Get-WindowsCapability -Online | Where-Object Name -like '*LAPS*'"));
        }
        catch
        {
            result.Findings.Add(Finding.Info(
                "LAPS Check Skipped",
                "Unable to determine LAPS deployment status.",
                Category));
        }
    }

    /// <summary>
    /// Checks the cached logon credentials count in the registry.
    /// Default is 10; reducing to 1-2 limits credential theft on stolen laptops.
    /// </summary>
    private void CheckCachedCredentials(AuditResult result)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");

            if (key == null) return;

            var cachedStr = key.GetValue("CachedLogonsCount")?.ToString();
            if (int.TryParse(cachedStr, out int cached))
            {
                if (cached > 4)
                {
                    result.Findings.Add(Finding.Warning(
                        $"High Cached Credentials Count ({cached})",
                        $"Windows caches {cached} domain logon credentials. " +
                        "Cached credentials can be extracted by tools like Mimikatz on compromised machines. " +
                        "CIS recommends ≤4 for workstations, 1-2 for high-security environments.",
                        Category,
                        "Reduce CachedLogonsCount to 2 (or 0 for always-connected machines).",
                        @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -Value '2'"));
                }
                else
                {
                    result.Findings.Add(Finding.Pass(
                        $"Cached Credentials: {cached}",
                        $"Cached logon count is {cached} (≤4 is acceptable).",
                        Category));
                }
            }
            else
            {
                // Default is 10 if not set
                result.Findings.Add(Finding.Info(
                    "Cached Credentials at Default (10)",
                    "CachedLogonsCount is not explicitly configured; Windows defaults to 10. " +
                    "Consider reducing to limit credential exposure.",
                    Category));
            }
        }
        catch
        {
            // Registry access restricted
        }
    }

    /// <summary>
    /// Checks if LSA Protection (RunAsPPL) is enabled to protect lsass.exe from credential dumping.
    /// </summary>
    private void CheckLsaProtection(AuditResult result)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Lsa");

            if (key == null) return;

            var runAsPpl = key.GetValue("RunAsPPL");
            if (runAsPpl != null && Convert.ToInt32(runAsPpl) == 1)
            {
                result.Findings.Add(Finding.Pass(
                    "LSA Protection Enabled",
                    "LSASS is running as a Protected Process Light (PPL), protecting against credential dumping tools.",
                    Category));
            }
            else
            {
                result.Findings.Add(Finding.Warning(
                    "LSA Protection Not Enabled",
                    "LSASS is not running as a Protected Process. Credential dumping tools like Mimikatz " +
                    "can extract passwords and hashes from memory.",
                    Category,
                    "Enable LSA Protection (RunAsPPL) to harden against credential theft.",
                    @"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1"));
            }
        }
        catch
        {
            // Registry access restricted
        }
    }

    /// <summary>
    /// Checks Windows Credential Guard status (virtualization-based security for credentials).
    /// </summary>
    private void CheckCredentialGuard(AuditResult result)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard");

            if (key == null)
            {
                result.Findings.Add(Finding.Info(
                    "Credential Guard Not Configured",
                    "Device Guard / Credential Guard is not configured on this system. " +
                    "Credential Guard uses virtualization to isolate secrets from the OS.",
                    Category));
                return;
            }

            var enableVbs = key.GetValue("EnableVirtualizationBasedSecurity");
            var requiredFeatures = key.GetValue("RequirePlatformSecurityFeatures");

            using var lsaCfgKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Lsa");
            var lsaCfg = lsaCfgKey?.GetValue("LsaCfgFlags");

            if (enableVbs != null && Convert.ToInt32(enableVbs) == 1 &&
                lsaCfg != null && Convert.ToInt32(lsaCfg) >= 1)
            {
                result.Findings.Add(Finding.Pass(
                    "Credential Guard Enabled",
                    "Windows Credential Guard is enabled, providing virtualization-based isolation of credentials.",
                    Category));
            }
            else if (enableVbs != null && Convert.ToInt32(enableVbs) == 1)
            {
                result.Findings.Add(Finding.Info(
                    "VBS Enabled, Credential Guard Not Fully Configured",
                    "Virtualization-Based Security is enabled but Credential Guard (LsaCfgFlags) is not configured.",
                    Category));
            }
            else
            {
                result.Findings.Add(Finding.Info(
                    "Credential Guard Not Enabled",
                    "Credential Guard is not enabled. On supported hardware, it provides strong protection against credential theft.",
                    Category));
            }
        }
        catch
        {
            // Registry access restricted
        }
    }

    private static string? ExtractJsonString(string fragment)
    {
        var start = fragment.IndexOf('"');
        if (start < 0) return null;
        var end = fragment.IndexOf('"', start + 1);
        if (end < 0) return null;
        return fragment.Substring(start + 1, end - start - 1);
    }

    private static string? ExtractNameFromJson(string json)
    {
        var marker = "\"Name\":\"";
        var idx = json.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;
        var start = idx + marker.Length;
        var end = json.IndexOf('"', start);
        if (end < 0) return null;
        return json.Substring(start, end - start);
    }
}
