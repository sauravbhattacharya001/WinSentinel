using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.PostureRegressionExplainer;

namespace WinSentinel.Tests.Services;

public class PostureRegressionExplainerTests
{
    private static readonly DateTime T0 = new DateTime(2026, 5, 17, 12, 0, 0, DateTimeKind.Utc);

    private static PostureSnapshot Snap(int score, Dictionary<string, int>? cats = null,
        IEnumerable<FindingSummary>? findings = null, DateTime? at = null)
    {
        return new PostureSnapshot(
            at ?? T0,
            score,
            cats ?? new Dictionary<string, int>
            {
                ["Firewall"] = 80, ["PatchHygiene"] = 80, ["Credentials"] = 80,
                ["AttackSurface"] = 80, ["ConfigDrift"] = 80, ["Monitoring"] = 80,
            },
            (findings ?? Array.Empty<FindingSummary>()).ToList());
    }

    [Fact]
    public void Improving_snapshot_yields_grade_A()
    {
        var prev = Snap(70);
        var cur = Snap(82, at: T0.AddHours(1),
            findings: Enumerable.Range(0, 5).Select(i => new FindingSummary(
                $"f{i}", "Firewall", FindingSeverity.Medium, $"old issue {i}", IsResolved: true)));
        var rep = new PostureRegressionExplainer().Explain(prev, cur);
        Assert.Equal(RegressionVerdict.Improving, rep.Verdict);
        Assert.Equal("A", rep.Grade);
        // Only RESOLVED_PROGRESS (or nothing) — never NEW_CRITICAL_FINDING.
        Assert.DoesNotContain(rep.Signals, s => s.Code == "NEW_CRITICAL_FINDING");
    }

    [Fact]
    public void Score_drop_10_is_regressing()
    {
        var prev = Snap(80);
        var cur = Snap(70, at: T0.AddHours(1));
        var rep = new PostureRegressionExplainer().Explain(prev, cur);
        Assert.Equal(RegressionVerdict.Regressing, rep.Verdict);
        Assert.Equal("C", rep.Grade);
    }

    [Fact]
    public void Three_new_attack_surface_findings_emit_signal_and_action()
    {
        var prev = Snap(80);
        var cur = Snap(72, at: T0.AddHours(1), findings: new[]
        {
            new FindingSummary("a1", "AttackSurface", FindingSeverity.Medium, "Port 3389 open", IsNew: true),
            new FindingSummary("a2", "AttackSurface", FindingSeverity.Medium, "Port 445 open", IsNew: true),
            new FindingSummary("a3", "AttackSurface", FindingSeverity.Medium, "Anonymous SMB share", IsNew: true),
        });
        var rep = new PostureRegressionExplainer().Explain(prev, cur);
        Assert.Contains(rep.Signals, s => s.Code == "NEW_ATTACK_SURFACE");
        Assert.Contains(rep.Playbook, a => a.Id == "ATTACK_SURFACE_REVIEW");
    }

    [Fact]
    public void Config_drift_drop_20_emits_signal_and_audit_action()
    {
        var prev = Snap(80);
        var cur = Snap(72, cats: new Dictionary<string, int>
        {
            ["Firewall"] = 80, ["PatchHygiene"] = 80, ["Credentials"] = 80,
            ["AttackSurface"] = 80, ["ConfigDrift"] = 60, ["Monitoring"] = 80,
        }, at: T0.AddHours(1));
        var rep = new PostureRegressionExplainer().Explain(prev, cur);
        Assert.Contains(rep.Signals, s => s.Code == "CONFIG_DRIFT_SPIKE");
        Assert.Contains(rep.Playbook, a => a.Id == "AUDIT_CONFIG_CHANGES");
    }

    [Fact]
    public void Fix_rollback_within_5_days_emits_root_cause_hint()
    {
        var prev = Snap(80, findings: new[]
        {
            new FindingSummary("f1", "Credentials", FindingSeverity.High, "Weak SMB signing",
                IsResolved: true),
        });
        var cur = Snap(68, at: T0.AddDays(1), findings: new[]
        {
            new FindingSummary("f99", "Credentials", FindingSeverity.High,
                "Weak SMB signing reintroduced by FIX-SMB-001", IsNew: true),
        });
        var ctx = new RegressionContext
        {
            NowOverride = T0.AddDays(1),
            RecentFixRollbacks =
            {
                new FixRollback(T0.AddDays(1).AddDays(-5), "FIX-SMB-001",
                    "Reverted SMB-signing GPO due to user complaints")
            },
        };
        var rep = new PostureRegressionExplainer().Explain(prev, cur, ctx);
        var sig = rep.Signals.FirstOrDefault(s => s.Code == "FIX_ROLLBACK_SUSPECTED");
        Assert.NotNull(sig);
        Assert.Equal(ActionPriority.P0, sig!.Priority);
        Assert.NotNull(sig.RootCauseHint);
        Assert.Contains(rep.Playbook, a => a.Id == "INVESTIGATE_ROLLBACK");
        Assert.Contains("ROOT_CAUSE_LIKELY", string.Join("|", rep.Insights));
    }

    [Fact]
    public void Two_P0_signals_force_grade_F()
    {
        var prev = Snap(80);
        var cur = Snap(70, cats: new Dictionary<string, int>
        {
            ["Firewall"] = 50, ["PatchHygiene"] = 80, ["Credentials"] = 80,
            ["AttackSurface"] = 80, ["ConfigDrift"] = 80, ["Monitoring"] = 80,
        }, at: T0.AddHours(1), findings: new[]
        {
            new FindingSummary("c1", "Firewall", FindingSeverity.Critical, "Rule allows ANY ANY ANY", IsNew: true),
            new FindingSummary("c2", "Firewall", FindingSeverity.Critical, "Public RDP open", IsNew: true),
        });
        var ctx = new RegressionContext
        {
            NowOverride = T0.AddHours(1),
            RecentFixRollbacks = { new FixRollback(T0, "FIX-FW-002", "Reverted firewall lockdown") },
        };
        var rep = new PostureRegressionExplainer().Explain(prev, cur, ctx);
        int p0 = rep.Signals.Count(s => s.Priority == ActionPriority.P0);
        Assert.True(p0 >= 2, $"expected >=2 P0, got {p0}");
        Assert.Equal("F", rep.Grade);
    }

    [Fact]
    public void Cautious_appetite_promotes_monitoring_to_P0()
    {
        var prev = Snap(80);
        var cur = Snap(72, cats: new Dictionary<string, int>
        {
            ["Firewall"] = 80, ["PatchHygiene"] = 80, ["Credentials"] = 80,
            ["AttackSurface"] = 80, ["ConfigDrift"] = 80, ["Monitoring"] = 65,
        }, at: T0.AddHours(1));
        var balanced = new PostureRegressionExplainer().Explain(prev, cur,
            new RegressionContext { Risk = RiskAppetite.Balanced });
        var cautious = new PostureRegressionExplainer().Explain(prev, cur,
            new RegressionContext { Risk = RiskAppetite.Cautious });
        var bSig = balanced.Signals.First(s => s.Code == "MONITORING_BLINDSPOT");
        var cSig = cautious.Signals.First(s => s.Code == "MONITORING_BLINDSPOT");
        Assert.NotEqual(ActionPriority.P0, bSig.Priority);
        Assert.Equal(ActionPriority.P0, cSig.Priority);
    }

    [Fact]
    public void Aggressive_appetite_trims_low_priority_actions()
    {
        var prev = Snap(80);
        var cur = Snap(75, at: T0.AddHours(1), findings: Enumerable.Range(0, 4).Select(i =>
            new FindingSummary($"p{i}", "Patch", FindingSeverity.High, $"stale patch {i}", IsPersistent: true)));
        var balanced = new PostureRegressionExplainer().Explain(prev, cur,
            new RegressionContext { Risk = RiskAppetite.Balanced });
        var aggressive = new PostureRegressionExplainer().Explain(prev, cur,
            new RegressionContext { Risk = RiskAppetite.Aggressive });
        Assert.True(balanced.Playbook.Count >= aggressive.Playbook.Count);
        Assert.DoesNotContain(aggressive.Playbook,
            a => a.Priority == ActionPriority.P2 || a.Priority == ActionPriority.P3);
    }

    [Fact]
    public void Json_renderer_is_deterministic_with_now_override()
    {
        var prev = Snap(80);
        var cur = Snap(70, at: T0.AddHours(1));
        var ctx = new RegressionContext { NowOverride = T0.AddHours(1) };
        var e = new PostureRegressionExplainer();
        var j1 = PostureRegressionExplainer.RenderJson(e.Explain(prev, cur, ctx));
        var j2 = PostureRegressionExplainer.RenderJson(e.Explain(prev, cur, ctx));
        Assert.Equal(j1, j2);
    }

    [Fact]
    public void Markdown_renderer_contains_all_section_headers()
    {
        var prev = Snap(80);
        var cur = Snap(70, at: T0.AddHours(1));
        var rep = new PostureRegressionExplainer().Explain(prev, cur);
        var md = PostureRegressionExplainer.RenderMarkdown(rep);
        Assert.Contains("## Summary", md);
        Assert.Contains("## Signals", md);
        Assert.Contains("## Playbook", md);
        Assert.Contains("## Insights", md);
    }

    [Fact]
    public void Identical_snapshots_are_stable_with_no_signals()
    {
        var prev = Snap(80);
        var cur = Snap(80, at: T0.AddHours(1));
        var rep = new PostureRegressionExplainer().Explain(prev, cur);
        Assert.Equal(RegressionVerdict.Stable, rep.Verdict);
        Assert.Equal("B", rep.Grade);
        Assert.Empty(rep.Signals);
    }

    [Fact]
    public void Resolved_progress_only_signal_triggers_celebrate_action()
    {
        var prev = Snap(80);
        var cur = Snap(82, at: T0.AddHours(1),
            findings: Enumerable.Range(0, 6).Select(i => new FindingSummary(
                $"r{i}", "Firewall", FindingSeverity.Medium, $"closed {i}", IsResolved: true)));
        var rep = new PostureRegressionExplainer().Explain(prev, cur);
        Assert.Contains(rep.Signals, s => s.Code == "RESOLVED_PROGRESS");
        Assert.Contains(rep.Playbook, a => a.Id == "CELEBRATE_PROGRESS");
    }

    [Fact]
    public void Never_mutates_input_findings_list()
    {
        var findings = new List<FindingSummary>
        {
            new("x1", "Firewall", FindingSeverity.High, "stuff", IsPersistent: true),
        };
        var prev = Snap(80, findings: findings);
        var cur = Snap(70, at: T0.AddHours(1), findings: findings);
        int before = findings.Count;
        _ = new PostureRegressionExplainer().Explain(prev, cur);
        Assert.Equal(before, findings.Count);
    }
}
