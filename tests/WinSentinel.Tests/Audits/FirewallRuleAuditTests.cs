using WinSentinel.Core.Audits;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Tests for the <see cref="FirewallRuleAudit"/> collector — that it is registered
/// in the default engine and that it is wired to the pure
/// <see cref="FirewallRuleAnalyzer"/> (which owns all the classification logic and
/// is covered exhaustively by FirewallRuleAnalyzerTests). These tests guard the
/// wiring so the deep per-rule firewall analysis actually reaches a live --audit.
/// </summary>
public class FirewallRuleAuditTests
{
    [Fact]
    public void DefaultEngine_RegistersFirewallRuleAudit()
    {
        var engine = new AuditEngine();
        Assert.Contains(engine.Modules, m => m is FirewallRuleAudit);
    }

    [Fact]
    public void FirewallRuleAudit_ExposesFirewallCategory()
    {
        var module = new FirewallRuleAudit();
        Assert.Equal("Firewall", module.Category);
        Assert.False(string.IsNullOrWhiteSpace(module.Name));
        Assert.False(string.IsNullOrWhiteSpace(module.Description));
    }

    [Fact]
    public async Task FirewallRuleAudit_RunOnAnyHost_DoesNotThrow_AndReportsSuccess()
    {
        // The collector shells out to netsh (read-only) and delegates every decision
        // to the pure analyzer. On a host with no rules / no netsh access it must
        // still complete cleanly rather than throw — the base class captures any
        // failure into result.Error, so a green run means Success stayed true.
        var module = new FirewallRuleAudit();
        var result = await module.RunAuditAsync();

        Assert.NotNull(result);
        Assert.Equal("Firewall", result.Category);
        Assert.True(result.Success, result.Error);
    }

    [Fact]
    public void FirewallRuleAnalyzer_EmptyState_EmitsSummaryFinding()
    {
        // The collector hands the analyzer a FirewallRuleState; even an empty rule set
        // yields the "Firewall Rule Summary" info finding (0 rules, risk 0/100).
        var analyzer = new FirewallRuleAnalyzer();
        var findings = analyzer.Analyze(new FirewallRuleAnalyzer.FirewallRuleState());

        Assert.Contains(findings, f => f.Title == "Firewall Rule Summary");
    }
}
