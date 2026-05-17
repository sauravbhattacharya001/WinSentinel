using System.Text.Json;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.AlertRoutingAdvisor;
using AP = WinSentinel.Core.Services.AlertRuleEngine.AlertPriority;
using AlertResult = WinSentinel.Core.Services.AlertRuleEngine.AlertResult;

namespace WinSentinel.Tests.Services;

public class AlertRoutingAdvisorTests
{
    private readonly AlertRoutingAdvisor _sut = new();

    // ── Helpers ──────────────────────────────────────────────────

    // Fixed "now" so windowing is deterministic. Wednesday, 14:00 local.
    private static readonly DateTimeOffset Now =
        new(2026, 5, 13, 14, 0, 0, TimeSpan.Zero);

    private static AlertResult MakeAlert(string id, AP priority, string? name = null) => new()
    {
        RuleId = id,
        RuleName = name ?? $"Rule {id}",
        Message = $"alert {id}",
        Priority = priority,
        Timestamp = Now,
    };

    private static RoutingContext BasicCtx(AP _) => new()
    {
        OnCall = new()
        {
            new OnCallEntry(
                "Alice", "alice@pager", new[]
                {
                    DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday,
                    DayOfWeek.Thursday, DayOfWeek.Friday,
                },
                new TimeOnly(0, 0), new TimeOnly(0, 0), PrimaryPager: true),
            new OnCallEntry(
                "Bob", "bob@pager", new[]
                {
                    DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday,
                    DayOfWeek.Thursday, DayOfWeek.Friday,
                },
                new TimeOnly(0, 0), new TimeOnly(0, 0), PrimaryPager: false),
        },
        NowOverride = Now,
    };

    // ── Default-priority routing ─────────────────────────────────

    [Theory]
    [InlineData(AP.Critical, RoutingAction.Page)]
    [InlineData(AP.High, RoutingAction.Email)]
    [InlineData(AP.Medium, RoutingAction.Chat)]
    [InlineData(AP.Low, RoutingAction.Batch)]
    public void DefaultPriority_MapsToExpectedAction(AP priority, RoutingAction expected)
    {
        var plan = _sut.Plan(new[] { MakeAlert("r1", priority) }, BasicCtx(priority));
        Assert.Single(plan.Decisions);
        Assert.Equal(expected, plan.Decisions[0].Action);
    }

    // ── Dedup ────────────────────────────────────────────────────

    [Fact]
    public void RecentDuplicate_Suppresses()
    {
        var ctx = BasicCtx(AP.High);
        ctx.RecentFirings.Add(new RecentFiring("r1", Now.AddMinutes(-5)));
        var plan = _sut.Plan(new[] { MakeAlert("r1", AP.High) }, ctx);
        Assert.Equal(RoutingAction.Suppress, plan.Decisions[0].Action);
        Assert.Contains("RECENT_DUPLICATE", plan.Decisions[0].Signals);
    }

    // ── Fatigue ──────────────────────────────────────────────────

    [Fact]
    public void Fatigue_DemotesPageToEmail()
    {
        var ctx = BasicCtx(AP.Critical);
        for (int i = 0; i < 13; i++)
            ctx.RecentFirings.Add(new RecentFiring($"x{i}", Now.AddHours(-1).AddMinutes(-i)));
        var plan = _sut.Plan(new[] { MakeAlert("r1", AP.Critical) }, ctx);
        var d = plan.Decisions[0];
        Assert.Contains("ALERT_FATIGUE", d.Signals);
        // Critical default = Page; fatigue demotes to Email.
        Assert.Equal(RoutingAction.Email, d.Action);
    }

    // ── Quiet hours ──────────────────────────────────────────────

    [Fact]
    public void QuietHours_DemotePageToEmail_WhenBatchInsteadOfPaging()
    {
        var ctx = BasicCtx(AP.Critical);
        // Window covers 14:00.
        ctx.Quiet = new QuietHours(new TimeOnly(13, 0), new TimeOnly(17, 0), true);
        var plan = _sut.Plan(new[] { MakeAlert("r1", AP.Critical) }, ctx);
        var d = plan.Decisions[0];
        Assert.Equal(RoutingAction.Email, d.Action);
        Assert.Contains("QUIET_HOURS", d.Signals);
    }

    [Fact]
    public void Cautious_KeepsCriticalAtPage_DuringQuietHours()
    {
        var ctx = BasicCtx(AP.Critical);
        ctx.Risk = RiskAppetite.Cautious;
        ctx.Quiet = new QuietHours(new TimeOnly(13, 0), new TimeOnly(17, 0), true);
        var plan = _sut.Plan(new[] { MakeAlert("r1", AP.Critical) }, ctx);
        Assert.Equal(RoutingAction.Page, plan.Decisions[0].Action);
    }

    [Fact]
    public void Aggressive_DemotesPageOnFatigue()
    {
        var ctx = BasicCtx(AP.Critical);
        ctx.Risk = RiskAppetite.Aggressive;
        for (int i = 0; i < 13; i++)
            ctx.RecentFirings.Add(new RecentFiring($"x{i}", Now.AddHours(-1).AddMinutes(-i)));
        var plan = _sut.Plan(new[] { MakeAlert("r1", AP.Critical) }, ctx);
        // Fatigue demotes Page -> Email, aggressive keeps it at Email (page already gone).
        // Verify aggressive demote signal does NOT add another demote since we already are at Email.
        Assert.Equal(RoutingAction.Email, plan.Decisions[0].Action);
        Assert.Contains("ALERT_FATIGUE", plan.Decisions[0].Signals);
    }

    // ── Channel availability ─────────────────────────────────────

    [Fact]
    public void ChannelUnavailable_DowngradesPagerToEmail()
    {
        var ctx = BasicCtx(AP.Critical);
        ctx.PagerAvailable = false;
        var plan = _sut.Plan(new[] { MakeAlert("r1", AP.Critical) }, ctx);
        var d = plan.Decisions[0];
        Assert.Equal(RoutingAction.Email, d.Action);
        Assert.Contains("CHANNEL_UNAVAILABLE", d.Signals);
    }

    // ── Rate limit ───────────────────────────────────────────────

    [Fact]
    public void RateLimit_BatchesWithDeliverAtSet()
    {
        var ctx = BasicCtx(AP.High);
        ctx.MaxAlertsPerHourPerChannel = 2;
        // Pre-populate 2 recent deliveries within the last hour.
        ctx.RecentFirings.Add(new RecentFiring("prev1", Now.AddMinutes(-30)));
        ctx.RecentFirings.Add(new RecentFiring("prev2", Now.AddMinutes(-20)));

        var plan = _sut.Plan(new[] { MakeAlert("r1", AP.High) }, ctx);
        var d = plan.Decisions[0];
        Assert.Equal(RoutingAction.Batch, d.Action);
        Assert.NotNull(d.DeliverAt);
        Assert.Contains("RATE_LIMITED", d.Signals);
    }

    // ── Escalation ───────────────────────────────────────────────

    [Fact]
    public void NoPrimaryOnCall_CriticalEscalates()
    {
        var ctx = BasicCtx(AP.Critical);
        // Remove primary.
        ctx.OnCall = ctx.OnCall.Where(e => !e.PrimaryPager).ToList();
        var plan = _sut.Plan(new[] { MakeAlert("r1", AP.Critical) }, ctx);
        var d = plan.Decisions[0];
        Assert.Equal(RoutingAction.Escalate, d.Action);
        Assert.Contains("NO_PRIMARY_ONCALL", d.Signals);
    }

    // ── Recipient resolution ─────────────────────────────────────

    [Fact]
    public void PageRecipient_PrefersPrimaryPager()
    {
        var ctx = BasicCtx(AP.Critical);
        var plan = _sut.Plan(new[] { MakeAlert("r1", AP.Critical) }, ctx);
        Assert.Equal("Alice", plan.Decisions[0].Recipient);
    }

    // ── Confidence ───────────────────────────────────────────────

    [Fact]
    public void ConfidenceScore_ClampedToValidRange()
    {
        var ctx = BasicCtx(AP.Critical);
        // Force many signals: fatigue + quiet + aggressive demote + channel down.
        ctx.Quiet = new QuietHours(new TimeOnly(13, 0), new TimeOnly(17, 0), true);
        ctx.Risk = RiskAppetite.Aggressive;
        ctx.PagerAvailable = false;
        for (int i = 0; i < 13; i++)
            ctx.RecentFirings.Add(new RecentFiring($"x{i}", Now.AddHours(-1).AddMinutes(-i)));
        var plan = _sut.Plan(new[] { MakeAlert("r1", AP.Critical) }, ctx);
        Assert.InRange(plan.Decisions[0].ConfidenceScore, 25, 100);
    }

    // ── Portfolio insights ───────────────────────────────────────

    [Fact]
    public void Storm_Insight_FiresAtMoreThanEight()
    {
        var ctx = BasicCtx(AP.Medium);
        var alerts = Enumerable.Range(0, 9).Select(i => MakeAlert($"r{i}", AP.Medium)).ToList();
        var plan = _sut.Plan(alerts, ctx);
        Assert.Contains(plan.Insights, i => i.Code == "STORM");
    }

    [Fact]
    public void CriticalBacklog_FiresAtThreeOrMore()
    {
        var ctx = BasicCtx(AP.Critical);
        var alerts = Enumerable.Range(0, 3).Select(i => MakeAlert($"r{i}", AP.Critical)).ToList();
        var plan = _sut.Plan(alerts, ctx);
        Assert.Contains(plan.Insights, i => i.Code == "CRITICAL_BACKLOG");
    }

    // ── Formatters ───────────────────────────────────────────────

    [Fact]
    public void FormatText_ContainsGrade()
    {
        var ctx = BasicCtx(AP.High);
        var plan = _sut.Plan(new[] { MakeAlert("r1", AP.High) }, ctx);
        var text = _sut.FormatText(plan);
        Assert.False(string.IsNullOrWhiteSpace(text));
        Assert.Contains($"Grade {plan.Grade}", text);
    }

    [Fact]
    public void FormatMarkdown_ContainsTableHeader()
    {
        var ctx = BasicCtx(AP.High);
        var plan = _sut.Plan(new[] { MakeAlert("r1", AP.High) }, ctx);
        var md = _sut.FormatMarkdown(plan);
        Assert.Contains("| Rule |", md);
        Assert.Contains("# Alert Routing Plan", md);
    }

    [Fact]
    public void FormatJson_RoundTripsToDecisionsArray()
    {
        var ctx = BasicCtx(AP.High);
        var plan = _sut.Plan(new[] { MakeAlert("r1", AP.High) }, ctx);
        var json = _sut.FormatJson(plan);
        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("Decisions", out var arr));
        Assert.Equal(JsonValueKind.Array, arr.ValueKind);
        Assert.Equal(1, arr.GetArrayLength());
    }

    [Fact]
    public void FormatJson_IsDeterministicForSameInputs()
    {
        var ctx1 = BasicCtx(AP.High);
        var ctx2 = BasicCtx(AP.High);
        var plan1 = _sut.Plan(new[] { MakeAlert("r1", AP.High), MakeAlert("r2", AP.Medium) }, ctx1);
        var plan2 = _sut.Plan(new[] { MakeAlert("r1", AP.High), MakeAlert("r2", AP.Medium) }, ctx2);
        Assert.Equal(_sut.FormatJson(plan1), _sut.FormatJson(plan2));
    }
}
