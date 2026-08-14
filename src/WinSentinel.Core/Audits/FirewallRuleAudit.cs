using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Deep per-rule firewall analysis: dangerous exposed ports, overly-permissive
/// wide-open rules, duplicate rules, and shadowed (redundant) rules, rolled up
/// into a firewall risk score.
///
/// This complements <see cref="FirewallAudit"/> (which reports profile states,
/// dropped-packet logging, and the overall inbound allow-rule surface) by drilling
/// into individual inbound Allow rules. It is a thin I/O shell: it collects the raw
/// <c>netsh advfirewall firewall show rule</c> dump and delegates every security
/// decision to the pure, unit-tested <see cref="FirewallRuleAnalyzer"/>. Mirrors the
/// established BrowserAudit / BrowserSecurityAnalyzer and PowerShellAudit /
/// PowerShellSecurityAnalyzer collector/analyzer split.
///
/// Single-machine, local-only: firewall rule inspection is free-tier (see the
/// OSS/Pro boundary — fleet-wide rollups are the Pro layer, per-machine analysis
/// stays free).
/// </summary>
public class FirewallRuleAudit : AuditModuleBase
{
    public override string Name => "Firewall Rule Analysis";
    public override string Category => "Firewall";
    public override string Description =>
        "Deep analysis of individual inbound firewall Allow rules: flags rules " +
        "exposing dangerous ports (RDP, SMB, WinRM, SQL, Redis, MongoDB, …), " +
        "overly-permissive wide-open rules, Public-profile exposure, duplicate " +
        "rules, and shadowed/redundant rules, with an overall firewall risk score.";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = await CollectAsync(cancellationToken);
        var analyzer = new FirewallRuleAnalyzer();
        result.Findings.AddRange(analyzer.Analyze(state));
    }

    /// <summary>
    /// Collects the live inbound firewall rules via netsh (fast: &lt;1s vs 60-90s for
    /// the Get-NetFirewallRule cmdlets) and maps each rule block onto the analyzer's
    /// <see cref="FirewallRuleAnalyzer.FirewallRule"/> DTO. All classification then
    /// happens in the pure analyzer.
    /// </summary>
    private static async Task<FirewallRuleAnalyzer.FirewallRuleState> CollectAsync(CancellationToken ct)
    {
        var state = new FirewallRuleAnalyzer.FirewallRuleState();

        var ruleDump = await ShellHelper.RunNetshAsync(
            "advfirewall firewall show rule name=all dir=in verbose", ct);
        if (string.IsNullOrWhiteSpace(ruleDump))
            return state;

        var blocks = ruleDump.Split(
            new[] { "\r\n\r\n", "\n\n" }, StringSplitOptions.RemoveEmptyEntries);

        foreach (var block in blocks)
        {
            var fields = FirewallAnalyzer.ParseNetshRuleBlock(block);
            if (!fields.ContainsKey("Rule Name")) continue; // skip the banner block

            state.Rules.Add(new FirewallRuleAnalyzer.FirewallRule
            {
                Name = fields.GetValueOrDefault("Rule Name", ""),
                Enabled = fields.GetValueOrDefault("Enabled", "")
                    .Equals("Yes", StringComparison.OrdinalIgnoreCase),
                Direction = NormalizeDirection(fields.GetValueOrDefault("Direction", "In")),
                Action = string.IsNullOrWhiteSpace(fields.GetValueOrDefault("Action", ""))
                    ? "Allow" : fields["Action"],
                Protocol = Blank(fields.GetValueOrDefault("Protocol", "Any")),
                LocalPort = Blank(fields.GetValueOrDefault("LocalPort", "Any")),
                RemotePort = Blank(fields.GetValueOrDefault("RemotePort", "Any")),
                RemoteAddress = Blank(fields.GetValueOrDefault("RemoteIP", "Any")),
                LocalAddress = Blank(fields.GetValueOrDefault("LocalIP", "Any")),
                Program = Blank(fields.GetValueOrDefault("Program", "Any")),
                Profile = Blank(fields.GetValueOrDefault("Profiles", "Any")),
                Grouping = fields.GetValueOrDefault("Grouping", ""),
                Description = fields.GetValueOrDefault("Description", ""),
            });
        }

        return state;
    }

    /// <summary>netsh emits an empty scope when unset; the analyzer expects "Any".</summary>
    private static string Blank(string value) =>
        string.IsNullOrWhiteSpace(value) ? "Any" : value.Trim();

    /// <summary>Map netsh "In"/"Out" (occasionally "Inbound") onto the analyzer's "In"/"Out".</summary>
    private static string NormalizeDirection(string value)
    {
        var v = (value ?? "").Trim();
        if (v.StartsWith("Out", StringComparison.OrdinalIgnoreCase)) return "Out";
        return "In";
    }
}
