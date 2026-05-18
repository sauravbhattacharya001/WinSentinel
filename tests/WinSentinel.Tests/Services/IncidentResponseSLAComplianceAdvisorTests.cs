using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.IncidentResponseSLAComplianceAdvisor;

namespace WinSentinel.Tests.Services;

public class IncidentResponseSLAComplianceAdvisorTests
{
    private static readonly DateTime T0 = new DateTime(2026, 5, 18, 12, 0, 0, DateTimeKind.Utc);

    private static IncidentRecord Make(
        string id,
        IncidentSeverity sev,
        double? ackMin = null,
        double? containMin = null,
        double? resolveMin = null,
        DateTime? detectedAt = null,
        bool vendor = false,
        bool manual = false,
        int reopen = 0,
        bool postmortem = false,
        string? title = null)
    {
        var det = detectedAt ?? T0;
        return new IncidentRecord(
            id,
            title ?? $"Incident {id}",
            sev,
            det,
            ackMin.HasValue ? det.AddMinutes(ackMin.Value) : null,
            containMin.HasValue ? det.AddMinutes(containMin.Value) : null,
            resolveMin.HasValue ? det.AddMinutes(resolveMin.Value) : null,
            RequiredVendorEscalation: vendor,
            RequiredManualRunbook: manual,
            ReopenCount: reopen,
            PostmortemCompleted: postmortem);
    }

    private static SlaContext Ctx(
        RiskAppetite risk = RiskAppetite.Balanced,
        bool regulated = false,
        int? roster = null,
        DateTime? now = null)
        => new SlaContext(
            Budgets: null,
            NowOverride: now ?? T0.AddDays(10),
            RiskAppetite: risk,
            RegulatedDomain: regulated,
            OnCallRosterSize: roster);

    [Fact]
    public void Empty_list_is_Excellent_grade_A_with_healthy_action_and_insight()
    {
        var rep = new IncidentResponseSLAComplianceAdvisor().Analyze(Array.Empty<IncidentRecord>(), Ctx());
        Assert.Equal(PortfolioVerdict.Excellent, rep.Verdict);
        Assert.Equal("A", rep.Grade);
        Assert.Contains(rep.Playbook, a => a.Id == "SLA_COMPLIANCE_HEALTHY");
        Assert.Contains(rep.Insights, s => s.StartsWith("HEALTHY_IR_PROGRAM"));
    }

    [Fact]
    public void Three_sev3_within_50pct_budget_are_grade_A_and_OnTrack()
    {
        // Sev3 budgets: ack 120m, contain 720m, resolve 4320m. 50% = 60/360/2160.
        var incs = new[]
        {
            Make("i1", IncidentSeverity.Sev3, ackMin: 30, containMin: 300, resolveMin: 2000),
            Make("i2", IncidentSeverity.Sev3, ackMin: 30, containMin: 300, resolveMin: 2000),
            Make("i3", IncidentSeverity.Sev3, ackMin: 30, containMin: 300, resolveMin: 2000),
        };
        var rep = new IncidentResponseSLAComplianceAdvisor().Analyze(incs, Ctx());
        Assert.Equal("A", rep.Grade);
        Assert.Equal(3, rep.Summary.OnTrackCount);
    }

    [Fact]
    public void Sev1_resolve_blown_more_than_3x_is_Crisis_with_EMERGENCY_action_and_P0()
    {
        // Sev1 resolve budget = 240m. 3x = 720m. Use 900m -> CriticalBreach.
        var inc = Make("i1", IncidentSeverity.Sev1, ackMin: 5, containMin: 30, resolveMin: 900);
        var rep = new IncidentResponseSLAComplianceAdvisor().Analyze(new[] { inc }, Ctx());
        Assert.Equal("F", rep.Grade);
        Assert.Contains(rep.Playbook, a => a.Id == "EMERGENCY_IR_REVIEW");
        var a = Assert.Single(rep.Incidents);
        Assert.Equal(IncidentVerdict.CriticalMiss, a.Verdict);
        Assert.Equal("P0", a.Priority);
    }

    [Fact]
    public void Two_repeat_reopen_incidents_trigger_P0_root_cause_and_chronic_insight()
    {
        var incs = new[]
        {
            Make("i1", IncidentSeverity.Sev3, ackMin: 10, containMin: 100, resolveMin: 500, reopen: 2),
            Make("i2", IncidentSeverity.Sev3, ackMin: 10, containMin: 100, resolveMin: 500, reopen: 2),
        };
        var rep = new IncidentResponseSLAComplianceAdvisor().Analyze(incs, Ctx());
        Assert.Contains(rep.Playbook, a => a.Id == "ROOT_CAUSE_REPEAT_INCIDENTS" && a.Priority == "P0");
        Assert.Contains(rep.Insights, s => s.StartsWith("CHRONIC_REOPEN_PATTERN"));
        Assert.All(rep.Incidents, i =>
            Assert.Contains(i.Reasons, r => r.Code == "REPEAT_REOPEN"));
    }

    [Fact]
    public void Two_vendor_minor_breaches_trigger_escalate_vendor_and_bottleneck_insight()
    {
        // Sev3 contain budget 720m; 800m -> MinorBreach.
        var incs = new[]
        {
            Make("i1", IncidentSeverity.Sev3, ackMin: 10, containMin: 800, resolveMin: 2000, vendor: true),
            Make("i2", IncidentSeverity.Sev3, ackMin: 10, containMin: 800, resolveMin: 2000, vendor: true),
        };
        var rep = new IncidentResponseSLAComplianceAdvisor().Analyze(incs, Ctx());
        Assert.Contains(rep.Playbook, a => a.Id == "ESCALATE_VENDOR_SLA" && a.Priority == "P1");
        Assert.Contains(rep.Insights, s => s.StartsWith("VENDOR_BOTTLENECK"));
    }

    [Fact]
    public void Two_manual_runbook_breaches_trigger_automate_and_manual_insight()
    {
        var incs = new[]
        {
            Make("i1", IncidentSeverity.Sev3, ackMin: 10, containMin: 800, resolveMin: 2000, manual: true),
            Make("i2", IncidentSeverity.Sev3, ackMin: 10, containMin: 800, resolveMin: 2000, manual: true),
        };
        var rep = new IncidentResponseSLAComplianceAdvisor().Analyze(incs, Ctx());
        Assert.Contains(rep.Playbook, a => a.Id == "AUTOMATE_RUNBOOK" && a.Priority == "P1");
        Assert.Contains(rep.Insights, s => s.StartsWith("MANUAL_PROCESS_DRAG"));
    }

    [Fact]
    public void Regulated_sev1_ack_at_12m_breaches_tightened_budget()
    {
        // Tightened Sev1 ack = 15m * 0.70 = 10.5m. 12m -> MinorBreach.
        // Use contain=30m (under regulated 42m), resolve=200m (under 240m).
        var inc = Make("i1", IncidentSeverity.Sev1, ackMin: 12, containMin: 30, resolveMin: 200);
        var rep = new IncidentResponseSLAComplianceAdvisor().Analyze(new[] { inc }, Ctx(regulated: true));
        var a = Assert.Single(rep.Incidents);
        Assert.Contains(a.Reasons, r => r.Code == "ACK_LATE");
    }

    [Fact]
    public void RiskAppetite_score_is_monotonic_Cautious_le_Balanced_le_Aggressive()
    {
        // Two Sev2 minor breaches: contain budget 240m -> 300m (1.25x = MinorBreach).
        var incs = new[]
        {
            Make("i1", IncidentSeverity.Sev2, ackMin: 10, containMin: 300, resolveMin: 1000),
            Make("i2", IncidentSeverity.Sev2, ackMin: 10, containMin: 300, resolveMin: 1000),
        };
        var adv = new IncidentResponseSLAComplianceAdvisor();
        var c = adv.Analyze(incs, Ctx(risk: RiskAppetite.Cautious)).ComplianceScore;
        var b = adv.Analyze(incs, Ctx(risk: RiskAppetite.Balanced)).ComplianceScore;
        var a = adv.Analyze(incs, Ctx(risk: RiskAppetite.Aggressive)).ComplianceScore;
        Assert.True(c <= b, $"expected Cautious({c}) <= Balanced({b})");
        Assert.True(b <= a, $"expected Balanced({b}) <= Aggressive({a})");
    }

    [Fact]
    public void Json_renderer_is_deterministic_with_now_override()
    {
        var incs = new[]
        {
            Make("i1", IncidentSeverity.Sev2, ackMin: 10, containMin: 100, resolveMin: 500),
            Make("i2", IncidentSeverity.Sev3, ackMin: 10, containMin: 800, resolveMin: 2000, vendor: true),
        };
        var ctx = Ctx();
        var adv = new IncidentResponseSLAComplianceAdvisor();
        var j1 = IncidentResponseSLAComplianceAdvisor.RenderJson(adv.Analyze(incs, ctx));
        var j2 = IncidentResponseSLAComplianceAdvisor.RenderJson(adv.Analyze(incs, ctx));
        Assert.Equal(j1, j2);
    }

    [Fact]
    public void Headline_starts_with_VERDICT()
    {
        var rep = new IncidentResponseSLAComplianceAdvisor().Analyze(Array.Empty<IncidentRecord>(), Ctx());
        Assert.StartsWith("VERDICT", rep.Headline);
    }

    [Fact]
    public void Markdown_contains_all_section_headers()
    {
        var rep = new IncidentResponseSLAComplianceAdvisor().Analyze(Array.Empty<IncidentRecord>(), Ctx());
        var md = IncidentResponseSLAComplianceAdvisor.RenderMarkdown(rep);
        Assert.Contains("## Summary", md);
        Assert.Contains("## Incidents", md);
        Assert.Contains("## Playbook", md);
        Assert.Contains("## Insights", md);
    }

    [Fact]
    public void Sev2_off_hours_detection_with_major_breach_emits_off_hours_reason()
    {
        // Detected at 03:00 UTC. Sev2 contain budget 240m. 500m -> ratio 2.08 -> MajorBreach.
        var det = new DateTime(2026, 5, 18, 3, 0, 0, DateTimeKind.Utc);
        var inc = Make("i1", IncidentSeverity.Sev2,
            ackMin: 5, containMin: 500, resolveMin: 1000, detectedAt: det);
        var rep = new IncidentResponseSLAComplianceAdvisor().Analyze(new[] { inc }, Ctx());
        var a = Assert.Single(rep.Incidents);
        Assert.Contains(a.Reasons, r => r.Code == "OFF_HOURS_DETECTION");
    }

    [Fact]
    public void Open_sev3_at_85pct_resolve_budget_is_AtRisk_and_P2()
    {
        // Sev3 resolve budget = 4320m. NowOverride at DetectedAt + 0.85*4320 = +3672m.
        var det = T0;
        var now = det.AddMinutes(0.85 * 4320);
        var inc = Make("i1", IncidentSeverity.Sev3, detectedAt: det); // open, no ack/contain/resolve
        var rep = new IncidentResponseSLAComplianceAdvisor().Analyze(new[] { inc }, Ctx(now: now));
        var a = Assert.Single(rep.Incidents);
        Assert.Equal(IncidentVerdict.AtRisk, a.Verdict);
        Assert.Equal("P2", a.Priority);
    }

    [Fact]
    public void Aggressive_trims_all_P3_actions_when_P0_present()
    {
        // Sev1 critical miss -> forced F + P0 EMERGENCY_IR_REVIEW. With Aggressive, no P3 action should remain.
        var incs = new[]
        {
            Make("crit", IncidentSeverity.Sev1, ackMin: 5, containMin: 30, resolveMin: 900),
            Make("healthy", IncidentSeverity.Sev3, ackMin: 10, containMin: 100, resolveMin: 500),
        };
        var rep = new IncidentResponseSLAComplianceAdvisor()
            .Analyze(incs, Ctx(risk: RiskAppetite.Aggressive));
        Assert.Contains(rep.Playbook, a => a.Priority == "P0");
        Assert.DoesNotContain(rep.Playbook, a => a.Priority == "P3");
    }

    [Fact]
    public void Cautious_grade_D_appends_quarterly_audit_action()
    {
        // 2 Sev2 majors + 2 Sev3 minors. Score = 100 - (2*15 + 2*5) = 60. Cautious -8 = 52 -> D.
        // No Sev1 anywhere -> no forced F.
        // Sev2 contain budget 240m; 600m = 2.5x -> MajorBreach.
        // Sev3 contain budget 720m; 800m -> MinorBreach.
        var incs = new[]
        {
            Make("m1", IncidentSeverity.Sev2, ackMin: 5, containMin: 600, resolveMin: 1000),
            Make("m2", IncidentSeverity.Sev2, ackMin: 5, containMin: 600, resolveMin: 1000),
            Make("n1", IncidentSeverity.Sev3, ackMin: 5, containMin: 800, resolveMin: 2000),
            Make("n2", IncidentSeverity.Sev3, ackMin: 5, containMin: 800, resolveMin: 2000),
        };
        var rep = new IncidentResponseSLAComplianceAdvisor()
            .Analyze(incs, Ctx(risk: RiskAppetite.Cautious));
        Assert.Equal("D", rep.Grade);
        Assert.Contains(rep.Playbook, a => a.Id == "SCHEDULE_QUARTERLY_IR_AUDIT");
    }

    [Fact]
    public void Incidents_sorted_by_priority_then_id()
    {
        var incs = new[]
        {
            // P3 OnTrack, id "a-onTrack"
            Make("a-onTrack", IncidentSeverity.Sev3, ackMin: 5, containMin: 100, resolveMin: 500),
            // P1 Sev2 MinorMiss (contain 300m vs 240m budget = 1.25x), id "z-p1"
            Make("z-p1", IncidentSeverity.Sev2, ackMin: 5, containMin: 300, resolveMin: 1000),
            // P1 Sev2 MinorMiss, id "b-p1"
            Make("b-p1", IncidentSeverity.Sev2, ackMin: 5, containMin: 300, resolveMin: 1000),
            // P0 Sev2 with reopen=2
            Make("c-p0", IncidentSeverity.Sev2, ackMin: 5, containMin: 100, resolveMin: 500, reopen: 2),
        };
        var rep = new IncidentResponseSLAComplianceAdvisor().Analyze(incs, Ctx());
        var ids = rep.Incidents.Select(i => i.Id).ToArray();
        Assert.Equal(new[] { "c-p0", "b-p1", "z-p1", "a-onTrack" }, ids);
    }

    [Fact]
    public void Sev1_major_miss_is_priority_P0()
    {
        // Sev1 contain budget = 60m. 120m -> ratio 2.0 -> MajorBreach.
        // Resolve 200m under 240m budget. Ack 5m under 15m.
        var inc = Make("i1", IncidentSeverity.Sev1, ackMin: 5, containMin: 120, resolveMin: 200);
        var rep = new IncidentResponseSLAComplianceAdvisor().Analyze(new[] { inc }, Ctx());
        var a = Assert.Single(rep.Incidents);
        Assert.Equal(IncidentVerdict.MajorMiss, a.Verdict);
        Assert.Equal("P0", a.Priority);
    }

    [Fact]
    public void Analyze_never_mutates_input_list()
    {
        var list = new List<IncidentRecord>
        {
            Make("i1", IncidentSeverity.Sev2, ackMin: 10, containMin: 100, resolveMin: 500),
            Make("i2", IncidentSeverity.Sev3, ackMin: 10, containMin: 800, resolveMin: 2000),
        };
        int before = list.Count;
        _ = new IncidentResponseSLAComplianceAdvisor().Analyze(list, Ctx());
        Assert.Equal(before, list.Count);
    }
}
