using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.FirewallAnalyzer;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits Windows Firewall status, profile states, and rules.
///
/// This module is a thin I/O shell: it collects raw <c>netsh advfirewall</c> output,
/// builds a <see cref="FirewallState"/>, and delegates every decision (including the
/// fiddly rule-block parsing) to the pure <see cref="FirewallAnalyzer"/>. All
/// thresholds are unit-tested there against synthetic state; see
/// <c>FirewallAnalyzerTests</c>.
/// </summary>
public class FirewallAudit : AuditModuleBase
{
    public override string Name => "Firewall Audit";
    public override string Category => FirewallAnalyzer.Category;
    public override string Description => "Checks Windows Firewall profile states (Domain/Private/Public), per-profile dropped-packet logging, the default inbound and outbound policies, the inbound allow-rule surface, and over-permissive wide-open inbound rules that let any program accept connections from any address on any port.";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = await CollectAsync(cancellationToken);
        result.Findings.AddRange(Analyze(state));
    }

    /// <summary>
    /// Collects raw firewall state via netsh (fast: netsh runs in &lt;1s vs 60-90s for
    /// the Get-NetFirewallRule cmdlets) and hands the parsing/classification to
    /// <see cref="FirewallAnalyzer"/>.
    /// </summary>
    private static async Task<FirewallState> CollectAsync(CancellationToken ct)
    {
        var state = new FirewallState();

        // ── Profiles (state + dropped-packet logging posture) ──────────────────
        var profiles = new[] { "domainprofile", "privateprofile", "publicprofile" };
        var profileNames = new[] { "Domain", "Private", "Public" };
        for (int i = 0; i < profiles.Length; i++)
        {
            var stateOutput = await ShellHelper.RunNetshAsync($"advfirewall show {profiles[i]} state", ct);
            var loggingOutput = await ShellHelper.RunNetshAsync($"advfirewall show {profiles[i]} logging", ct);
            state.Profiles.Add(new FirewallProfile(
                profileNames[i],
                ParseProfileState(stateOutput),
                ParseLogDroppedConnections(loggingOutput)));
        }

        // ── Inbound rules ─────────────────────────────────────────────────────
        var ruleDump = await ShellHelper.RunNetshAsync(
            "advfirewall firewall show rule name=all dir=in verbose", ct);
        if (string.IsNullOrWhiteSpace(ruleDump))
        {
            state.RulesQueried = false;
        }
        else
        {
            state.InboundRules = ParseRules(ruleDump);
        }

        // ── Default inbound policy (current profile) ───────────────────────────
        var policy = await ShellHelper.RunNetshAsync(
            "advfirewall show currentprofile firewallpolicy", ct);
        state.DefaultInboundBlock = ParseDefaultInbound(policy);
        state.DefaultOutboundBlock = ParseDefaultOutbound(policy);

        return state;
    }
}
