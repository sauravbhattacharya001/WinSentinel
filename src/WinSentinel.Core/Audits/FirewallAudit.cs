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
        // Use netsh instead of Get-NetFirewallRule — netsh runs in <1s vs 60-90s for the cmdlets.
        var output = await ShellHelper.RunNetshAsync(
            "advfirewall firewall show rule name=all dir=in verbose", ct);

        if (string.IsNullOrWhiteSpace(output))
        {
            result.Findings.Add(Finding.Info(
                "Firewall Rules Check Skipped",
                "Could not retrieve firewall rules via netsh.",
                Category));
            return;
        }

        // Parse netsh output — rules are separated by blank lines, fields are "Key: Value"
        var rules = output.Split(new[] { "\r\n\r\n", "\n\n" }, StringSplitOptions.RemoveEmptyEntries);
        int allowCount = 0;
        int anyPortTcpCount = 0;

        foreach (var ruleBlock in rules)
        {
            var fields = ParseNetshRuleBlock(ruleBlock);

            // Only count enabled allow rules
            if (!fields.TryGetValue("Enabled", out var enabled) ||
                !enabled.Equals("Yes", StringComparison.OrdinalIgnoreCase))
                continue;
            if (!fields.TryGetValue("Action", out var action) ||
                !action.Equals("Allow", StringComparison.OrdinalIgnoreCase))
                continue;

            allowCount++;

            // Check for rules allowing any TCP port
            fields.TryGetValue("Protocol", out var protocol);
            fields.TryGetValue("LocalPort", out var localPort);
            if (protocol != null && protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase) &&
                localPort != null && localPort.Equals("Any", StringComparison.OrdinalIgnoreCase))
            {
                anyPortTcpCount++;
            }
        }

        if (allowCount > 100)
        {
            result.Findings.Add(Finding.Warning(
                "High Number of Inbound Allow Rules",
                $"There are {allowCount} enabled inbound allow rules. Consider reviewing and removing unnecessary rules.",
                Category,
                "Review inbound firewall rules and disable any that are no longer needed.",
                "netsh advfirewall firewall show rule name=all dir=in"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Inbound Rules Count Acceptable",
                $"There are {allowCount} enabled inbound allow rules.",
                Category));
        }

        if (anyPortTcpCount > 5)
        {
            result.Findings.Add(Finding.Warning(
                "Rules Allowing All TCP Ports",
                $"{anyPortTcpCount} inbound rules allow connections on any TCP port. This increases attack surface.",
                Category,
                "Review rules that allow all ports and restrict to specific ports where possible."));
        }
    }

    /// <summary>
    /// Parse a netsh rule block into key-value pairs.
    /// Each line is "Key:                Value".
    /// </summary>
    private static Dictionary<string, string> ParseNetshRuleBlock(string block)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var lines = block.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            // Skip separator lines
            if (line.StartsWith("---")) continue;

            var colonIdx = line.IndexOf(':');
            if (colonIdx <= 0) continue;

            var key = line.Substring(0, colonIdx).Trim();
            var value = line.Substring(colonIdx + 1).Trim();
            fields[key] = value;
        }
        return fields;
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
