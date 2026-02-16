using System.Management;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;
using Microsoft.Win32;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits local user accounts, admin accounts, password policies, and guest account status.
/// </summary>
public class AccountAudit : IAuditModule
{
    public string Name => "Account Audit";
    public string Category => "Accounts";
    public string Description => "Checks local user accounts, admin membership, password policies, and guest account status.";

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
            await CheckGuestAccount(result, cancellationToken);
            await CheckAdminAccounts(result, cancellationToken);
            await CheckPasswordPolicy(result, cancellationToken);
            await CheckLockedOutAccounts(result, cancellationToken);
            CheckAutoLogon(result);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    private async Task CheckGuestAccount(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            "(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled", ct);

        if (output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Critical(
                "Guest Account Enabled",
                "The built-in Guest account is enabled. This allows unauthenticated access to the system.",
                Category,
                "Disable the Guest account.",
                "Disable-LocalUser -Name 'Guest'"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Guest Account Disabled",
                "The built-in Guest account is disabled.",
                Category));
        }
    }

    private async Task CheckAdminAccounts(AuditResult result, CancellationToken ct)
    {
        // Get all members of the Administrators group
        var output = await ShellHelper.RunPowerShellAsync(
            @"Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name", ct);

        var adminAccounts = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(a => !string.IsNullOrWhiteSpace(a))
            .ToList();

        if (adminAccounts.Count > 2)
        {
            result.Findings.Add(Finding.Warning(
                $"Multiple Admin Accounts ({adminAccounts.Count})",
                $"There are {adminAccounts.Count} accounts in the Administrators group: {string.Join(", ", adminAccounts)}. Minimize admin access.",
                Category,
                "Review admin accounts and remove unnecessary administrative privileges.",
                "Get-LocalGroupMember -Group 'Administrators'"));
        }
        else if (adminAccounts.Count > 0)
        {
            result.Findings.Add(Finding.Pass(
                $"Admin Accounts: {adminAccounts.Count}",
                $"Administrators group members: {string.Join(", ", adminAccounts)}",
                Category));
        }

        // Check if default Administrator account is enabled
        var adminEnabled = await ShellHelper.RunPowerShellAsync(
            "(Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue).Enabled", ct);

        if (adminEnabled.Trim().Equals("True", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Warning(
                "Built-in Administrator Account Enabled",
                "The built-in Administrator account is enabled. This is a well-known target for attacks.",
                Category,
                "Disable the built-in Administrator account and use a named admin account instead.",
                "Disable-LocalUser -Name 'Administrator'"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Built-in Administrator Account Disabled",
                "The built-in Administrator account is disabled.",
                Category));
        }
    }

    private async Task CheckPasswordPolicy(AuditResult result, CancellationToken ct)
    {
        // Check minimum password length via net accounts
        var output = await ShellHelper.RunCmdAsync("net accounts", ct);

        var lines = output.Split('\n');
        foreach (var line in lines)
        {
            if (line.Contains("Minimum password length", StringComparison.OrdinalIgnoreCase))
            {
                var parts = line.Split(':');
                if (parts.Length > 1 && int.TryParse(parts[1].Trim(), out int minLength))
                {
                    if (minLength < 8)
                    {
                        result.Findings.Add(Finding.Warning(
                            $"Weak Minimum Password Length ({minLength})",
                            $"Minimum password length is set to {minLength} characters. Recommend at least 8.",
                            Category,
                            "Increase minimum password length to at least 8 characters.",
                            "net accounts /minpwlen:8"));
                    }
                    else
                    {
                        result.Findings.Add(Finding.Pass(
                            $"Adequate Password Length ({minLength})",
                            $"Minimum password length is set to {minLength} characters.",
                            Category));
                    }
                }
            }

            if (line.Contains("Lockout threshold", StringComparison.OrdinalIgnoreCase))
            {
                var parts = line.Split(':');
                if (parts.Length > 1)
                {
                    var thresholdStr = parts[1].Trim();
                    if (thresholdStr.Equals("Never", StringComparison.OrdinalIgnoreCase) ||
                        thresholdStr == "0")
                    {
                        result.Findings.Add(Finding.Warning(
                            "No Account Lockout Policy",
                            "Account lockout threshold is not set. Brute force attacks can try unlimited passwords.",
                            Category,
                            "Set an account lockout threshold (e.g., 5 failed attempts).",
                            "net accounts /lockoutthreshold:5"));
                    }
                    else if (int.TryParse(thresholdStr, out int threshold) && threshold > 0)
                    {
                        result.Findings.Add(Finding.Pass(
                            $"Account Lockout Configured ({threshold} attempts)",
                            $"Account lockout threshold is set to {threshold} failed attempts.",
                            Category));
                    }
                }
            }
        }
    }

    private async Task CheckLockedOutAccounts(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            "Get-LocalUser | Where-Object { $_.Enabled -and $_.AccountExpires -and $_.AccountExpires -lt (Get-Date) } | Select-Object -ExpandProperty Name", ct);

        if (!string.IsNullOrWhiteSpace(output))
        {
            var expired = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            result.Findings.Add(Finding.Info(
                $"Expired Accounts Found ({expired.Length})",
                $"Expired user accounts: {string.Join(", ", expired)}. Consider removing or disabling them.",
                Category));
        }
    }

    private void CheckAutoLogon(AuditResult result)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
            if (key != null)
            {
                var autoLogon = key.GetValue("AutoAdminLogon")?.ToString();
                var defaultPassword = key.GetValue("DefaultPassword")?.ToString();

                if (autoLogon == "1")
                {
                    if (!string.IsNullOrEmpty(defaultPassword))
                    {
                        result.Findings.Add(Finding.Critical(
                            "Auto-Logon with Stored Password",
                            "Auto-logon is enabled with a password stored in plaintext in the registry.",
                            Category,
                            "Disable auto-logon and remove the stored password.",
                            @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -Value '0'; Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultPassword' -ErrorAction SilentlyContinue"));
                    }
                    else
                    {
                        result.Findings.Add(Finding.Warning(
                            "Auto-Logon Enabled",
                            "Auto-logon is enabled. Anyone with physical access can log in.",
                            Category,
                            "Disable auto-logon for better physical security.",
                            @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -Value '0'"));
                    }
                }
            }
        }
        catch
        {
            // Registry access may be restricted
        }
    }
}
