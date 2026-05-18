using System.Text.Json;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.PolicyExceptionRiskAdvisor;

namespace WinSentinel.Tests;

public class PolicyExceptionRiskAdvisorTests
{
    private static readonly DateTime Now = new DateTime(2026, 5, 18, 22, 0, 0, DateTimeKind.Utc);

    private static AdvisorContext Ctx(
        RiskAppetite risk = RiskAppetite.Balanced,
        int cadence = 90) =>
        new AdvisorContext { Risk = risk, NowOverride = Now, ReviewCadenceDays = cadence };

    private static PolicyException Make(
        string id,
        FindingSeverity sev = FindingSeverity.Medium,
        int ageDays = 30,
        DateTime? expiresAt = null,
        string? owner = "alice",
        DateTime? lastReviewedAt = null,
        string justification = "Documented business justification approved by CISO with full mitigations.",
        IReadOnlyList<string>? related = null,
        string category = "Firewall")
    {
        return new PolicyException(
            Id: id,
            PolicyId: $"POL-{id}",
            Category: category,
            GrantedAt: Now.AddDays(-ageDays),
            ExpiresAt: expiresAt,
            SeverityAtGrant: sev,
            Justification: justification,
            GrantedBy: "ciso",
            Owner: owner,
            LastReviewedAt: lastReviewedAt ?? Now.AddDays(-10),
            RelatedFindingIds: related ?? Array.Empty<string>());
    }

    [Fact]
    public void Empty_list_returns_healthy_posture_grade_A()
    {
        var advisor = new PolicyExceptionRiskAdvisor();
        var r = advisor.Analyze(Array.Empty<PolicyException>(), Ctx());

        Assert.Equal(0, r.TotalExceptions);
        Assert.Equal("A", r.Grade);
        Assert.Equal("HEALTHY", r.Verdict);
        Assert.Single(r.Playbook);
        Assert.Equal("HEALTHY_POSTURE", r.Playbook[0].Id);
        Assert.Equal(ActionPriority.P3, r.Playbook[0].Priority);
    }

    [Fact]
    public void Expired_high_severity_forces_F_and_revoke_now_playbook()
    {
        var advisor = new PolicyExceptionRiskAdvisor();
        var ex = Make("e1", sev: FindingSeverity.High,
            expiresAt: Now.AddDays(-5),
            ageDays: 200);

        var r = advisor.Analyze(new[] { ex }, Ctx());

        Assert.Equal("F", r.Grade);
        Assert.Equal(1, r.RevokeNowCount);
        var a = r.Assessments.Single();
        Assert.Equal(ExceptionVerdict.RevokeNow, a.Verdict);
        Assert.Contains("EXPIRED", a.Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "REVOKE_EXPIRED_BATCH" && p.Priority == ActionPriority.P0);
    }

    [Fact]
    public void Missing_owner_yields_missing_owner_and_assign_owners_when_two_or_more()
    {
        var advisor = new PolicyExceptionRiskAdvisor();
        var ex1 = Make("e1", owner: null);
        var ex2 = Make("e2", owner: "   ");

        var r = advisor.Analyze(new[] { ex1, ex2 }, Ctx());

        Assert.All(r.Assessments, a => Assert.Equal(ExceptionVerdict.MissingOwner, a.Verdict));
        Assert.All(r.Assessments, a => Assert.Contains("OWNER_MISSING", a.Reasons));
        Assert.Contains(r.Playbook, p => p.Id == "ASSIGN_OWNERS_BATCH" && p.Priority == ActionPriority.P0);
    }

    [Fact]
    public void Stale_review_triggers_requires_review_and_reason()
    {
        var advisor = new PolicyExceptionRiskAdvisor();
        var ex = Make("e1",
            sev: FindingSeverity.High,
            ageDays: 200,
            lastReviewedAt: Now.AddDays(-200));

        var r = advisor.Analyze(new[] { ex }, Ctx(cadence: 90));

        var a = r.Assessments.Single();
        Assert.Contains("STALE_REVIEW", a.Reasons);
        Assert.True(a.Verdict == ExceptionVerdict.RequiresReview ||
                    a.Verdict == ExceptionVerdict.ExtendWithReview,
            $"Expected RequiresReview or ExtendWithReview, got {a.Verdict}");
    }

    [Fact]
    public void Expiring_soon_low_severity_is_expire_as_scheduled_P2()
    {
        var advisor = new PolicyExceptionRiskAdvisor();
        var ex = Make("e1", sev: FindingSeverity.Low,
            expiresAt: Now.AddDays(7),
            ageDays: 10);

        var r = advisor.Analyze(new[] { ex }, Ctx());
        var a = r.Assessments.Single();

        Assert.Equal(ExceptionVerdict.ExpireAsScheduled, a.Verdict);
        Assert.Contains("EXPIRING_SOON", a.Reasons);
        Assert.Equal(ActionPriority.P2, a.Priority);
    }

    [Fact]
    public void Indefinite_critical_yields_extend_with_review_and_reason()
    {
        var advisor = new PolicyExceptionRiskAdvisor();
        var ex = Make("e1", sev: FindingSeverity.Critical,
            expiresAt: null, ageDays: 10);

        var r = advisor.Analyze(new[] { ex }, Ctx());
        var a = r.Assessments.Single();

        Assert.Equal(ExceptionVerdict.ExtendWithReview, a.Verdict);
        Assert.Contains("INDEFINITE_WAIVER_HIGH_SEV", a.Reasons);
    }

    [Fact]
    public void Drift_count_elevated_reason_appears_when_three_related_findings()
    {
        var advisor = new PolicyExceptionRiskAdvisor();
        var ex = Make("e1", related: new[] { "f1", "f2", "f3", "f4" });

        var r = advisor.Analyze(new[] { ex }, Ctx());
        var a = r.Assessments.Single();
        Assert.Contains("DRIFT_COUNT_ELEVATED", a.Reasons);
    }

    [Fact]
    public void Thin_justification_under_40_chars_adds_reason()
    {
        var advisor = new PolicyExceptionRiskAdvisor();
        var ex = Make("e1", justification: "short");

        var r = advisor.Analyze(new[] { ex }, Ctx());
        var a = r.Assessments.Single();
        Assert.Contains("THIN_JUSTIFICATION", a.Reasons);
    }

    [Fact]
    public void Aggressive_appetite_trims_P3_healthy_posture_when_P0_present()
    {
        var advisor = new PolicyExceptionRiskAdvisor();
        var expired = Make("e1", sev: FindingSeverity.High,
            expiresAt: Now.AddDays(-3));

        var r = advisor.Analyze(new[] { expired }, Ctx(risk: RiskAppetite.Aggressive));

        Assert.DoesNotContain(r.Playbook, p => p.Id == "HEALTHY_POSTURE");
        Assert.Contains(r.Playbook, p => p.Priority == ActionPriority.P0);
    }

    [Fact]
    public void Cautious_appetite_adds_quarterly_review_even_with_one_stale()
    {
        var advisor = new PolicyExceptionRiskAdvisor();
        // One exception, stale-review (no LastReviewedAt = stale), low severity, owned.
        var ex = Make("e1",
            sev: FindingSeverity.Low,
            ageDays: 10,
            lastReviewedAt: Now.AddDays(-200));

        var r = advisor.Analyze(new[] { ex }, Ctx(risk: RiskAppetite.Cautious));

        Assert.Contains(r.Playbook, p => p.Id == "SCHEDULE_QUARTERLY_REVIEW_BATCH");
    }

    [Fact]
    public void Risk_score_monotonic_stale_higher_than_recent()
    {
        var advisor = new PolicyExceptionRiskAdvisor();
        var stale = Make("e1", lastReviewedAt: Now.AddDays(-200));
        var recent = Make("e1", lastReviewedAt: Now.AddDays(-1));

        var rs = advisor.Analyze(new[] { stale }, Ctx());
        var rr = advisor.Analyze(new[] { recent }, Ctx());

        Assert.True(rs.Assessments[0].RiskScore > rr.Assessments[0].RiskScore,
            $"stale={rs.Assessments[0].RiskScore} recent={rr.Assessments[0].RiskScore}");
    }

    [Fact]
    public void NowOverride_drives_age_and_expiry_deterministically()
    {
        var advisor = new PolicyExceptionRiskAdvisor();
        var pinned = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var ex = new PolicyException(
            Id: "e1",
            PolicyId: "POL-1",
            Category: "Firewall",
            GrantedAt: pinned.AddDays(-100),
            ExpiresAt: pinned.AddDays(10),
            SeverityAtGrant: FindingSeverity.Medium,
            Justification: "Documented business justification approved by CISO with full mitigations.",
            GrantedBy: "ciso",
            Owner: "alice",
            LastReviewedAt: pinned.AddDays(-1),
            RelatedFindingIds: Array.Empty<string>());

        var r = advisor.Analyze(new[] { ex },
            new AdvisorContext { NowOverride = pinned, ReviewCadenceDays = 90 });

        var a = r.Assessments.Single();
        Assert.Equal(100, a.AgeDays);
        Assert.Equal(10, a.DaysToExpiry);
        Assert.Equal(pinned, r.GeneratedAt);
    }

    [Fact]
    public void RenderJson_round_trips_as_valid_json()
    {
        var advisor = new PolicyExceptionRiskAdvisor();
        var ex = Make("e1", sev: FindingSeverity.High);
        var r = advisor.Analyze(new[] { ex }, Ctx());

        string json = PolicyExceptionRiskAdvisor.RenderJson(r);
        using var doc = JsonDocument.Parse(json);

        Assert.True(doc.RootElement.TryGetProperty("Verdict", out _));
        Assert.True(doc.RootElement.TryGetProperty("Assessments", out var assess));
        Assert.Equal(JsonValueKind.Array, assess.ValueKind);
    }

    [Fact]
    public void RenderMarkdown_contains_expected_sections()
    {
        var advisor = new PolicyExceptionRiskAdvisor();
        var ex = Make("e1", sev: FindingSeverity.High,
            expiresAt: Now.AddDays(-2));
        var r = advisor.Analyze(new[] { ex }, Ctx());

        string md = PolicyExceptionRiskAdvisor.RenderMarkdown(r);

        Assert.Contains("## Summary", md);
        Assert.Contains("## Assessments", md);
        Assert.Contains("## Playbook", md);
        Assert.Contains("## Insights", md);
    }
}
