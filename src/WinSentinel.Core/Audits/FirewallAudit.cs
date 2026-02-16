using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits Windows Firewall status, profile states, and rules.
/// </summary>
public class FirewallAudit : IAuditModule
{
    public string Name => "Firewall Audit";
    public string Category => "Firewall";
    public string Description => "Checks Windows Firewall status, profile states, and rule analysis.";

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
            await CheckFirewallProfiles(result, cancellationToken);
            await CheckFirewallRules(result, cancellationToken);
            await CheckInboundDefaults(result, cancellationToken);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    private async Task CheckFirewallProfiles(AuditResult result, CancellationToken ct)
    {
        // Check each firewall profile (Domain, Private, Public)
        var profiles = new[] { "domainprofile", "privateprofile", "publicprofile" };
        var profileNames = new[] { "Domain", "Private", "Public" };

        for (int i = 0; i < profiles.Length; i++)
        {
            var output = await ShellHelper.RunNetshAsync($"advfirewall show {profiles[i]} state", ct);

            if (output.Contains("ON", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add(Finding.Pass(
                    $"{profileNames[i]} Firewall Enabled",
                    $"Windows Firewall {profileNames[i]} profile is enabled.",
                    Category));
            }
            else
            {
                result.Findings.Add(Finding.Critical(
                    $"{profileNames[i]} Firewall Disabled",
                    $"Windows Firewall {profileNames[i]} profile is DISABLED. Your system is exposed to network attacks.",
                    Category,
                    $"Enable the {profileNames[i]} firewall profile immediately.",
                    $"netsh advfirewall set {profiles[i]} state on"));
            }
        }
    }

    private async Task CheckFirewallRules(AuditResult result, CancellationToken ct)
    {
        // Count enabled inbound allow rules (can be slow with many rules)
        var output = await ShellHelper.RunPowerShellAsync(
            "Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Measure-Object | Select-Object -ExpandProperty Count",
            TimeSpan.FromSeconds(45), ct);

        if (int.TryParse(output.Trim(), out int ruleCount))
        {
            if (ruleCount > 100)
            {
                result.Findings.Add(Finding.Warning(
                    "High Number of Inbound Allow Rules",
                    $"There are {ruleCount} enabled inbound allow rules. Consider reviewing and removing unnecessary rules.",
                    Category,
                    "Review inbound firewall rules and disable any that are no longer needed.",
                    "Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Format-Table Name, DisplayName, Profile"));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "Inbound Rules Count Acceptable",
                    $"There are {ruleCount} enabled inbound allow rules.",
                    Category));
            }
        }

        // Check for any rules allowing all ports (can be slow)
        var anyPortRules = await ShellHelper.RunPowerShellAsync(
            @"Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Get-NetFirewallPortFilter | Where-Object { $_.LocalPort -eq 'Any' -and $_.Protocol -eq 'TCP' } | Measure-Object | Select-Object -ExpandProperty Count",
            TimeSpan.FromSeconds(60), ct);

        if (int.TryParse(anyPortRules.Trim(), out int anyCount) && anyCount > 5)
        {
            result.Findings.Add(Finding.Warning(
                "Rules Allowing All TCP Ports",
                $"{anyCount} inbound rules allow connections on any TCP port. This increases attack surface.",
                Category,
                "Review rules that allow all ports and restrict to specific ports where possible."));
        }
    }

    private async Task CheckInboundDefaults(AuditResult result, CancellationToken ct)
    {
        // Check default inbound action
        var output = await ShellHelper.RunNetshAsync("advfirewall show currentprofile firewallpolicy", ct);

        if (output.Contains("BlockInbound", StringComparison.OrdinalIgnoreCase) ||
            output.Contains("Block", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Pass(
                "Default Inbound Policy: Block",
                "The default inbound firewall policy is set to block, which is the recommended configuration.",
                Category));
        }
        else if (output.Contains("AllowInbound", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Critical(
                "Default Inbound Policy: Allow",
                "The default inbound firewall policy is set to ALLOW. All incoming connections are permitted by default.",
                Category,
                "Change the default inbound policy to Block.",
                "netsh advfirewall set currentprofile firewallpolicy blockinbound,allowoutbound"));
        }
    }
}
