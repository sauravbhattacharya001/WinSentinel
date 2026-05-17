using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Core.Services;

/// <summary>
/// Agentic alert routing and fatigue-protection policy advisor.
/// <para>
/// Complements <see cref="AlertRuleEngine"/>: takes a batch of triggered
/// <see cref="AlertRuleEngine.AlertResult"/> objects plus a
/// <see cref="RoutingContext"/> (on-call config, channels, quiet hours,
/// recent firing history) and emits per-alert routing decisions
/// (Suppress / Batch / Chat / Email / Page / Escalate) with structured
/// reasons, plus portfolio-level insights and a single-letter grade.
/// </para>
/// <para>
/// Pure / deterministic — no I/O, no network. Time can be pinned via
/// <see cref="RoutingContext.NowOverride"/> for reproducible tests.
/// </para>
/// </summary>
public class AlertRoutingAdvisor
{
    // ── Public model ─────────────────────────────────────────────

    /// <summary>Concrete delivery action chosen for an alert.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum RoutingAction
    {
        /// <summary>Drop entirely (duplicate, noise).</summary>
        Suppress,
        /// <summary>Hold for the next digest window.</summary>
        Batch,
        /// <summary>Chat channel (low-noise).</summary>
        Chat,
        /// <summary>Email channel.</summary>
        Email,
        /// <summary>Pager / push to on-call.</summary>
        Page,
        /// <summary>Escalate up the chain (no primary available).</summary>
        Escalate,
    }

    /// <summary>How aggressively the advisor protects the channel.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum RiskAppetite
    {
        /// <summary>Prefer over-alerting; do not demote Critical below Email.</summary>
        Cautious,
        /// <summary>Default behaviour.</summary>
        Balanced,
        /// <summary>Aggressively demote on fatigue/quiet hours.</summary>
        Aggressive,
    }

    /// <summary>On-call rotation entry.</summary>
    public record OnCallEntry(
        string Name,
        string Channel,
        DayOfWeek[] Days,
        TimeOnly Start,
        TimeOnly End,
        bool PrimaryPager);

    /// <summary>Quiet-hours window. Inclusive of start, exclusive of end. Crosses midnight if Start &gt; End.</summary>
    public record QuietHours(TimeOnly Start, TimeOnly End, bool BatchInsteadOfPaging);

    /// <summary>Record of a rule already firing recently — used for dedup and fatigue.</summary>
    public record RecentFiring(string RuleId, DateTimeOffset At);

    /// <summary>Caller-supplied context for routing decisions.</summary>
    public class RoutingContext
    {
        /// <summary>On-call rotation.</summary>
        public List<OnCallEntry> OnCall { get; set; } = new();

        /// <summary>Quiet-hours policy (optional).</summary>
        public QuietHours? Quiet { get; set; }

        /// <summary>History of recent firings (used for dedup + fatigue).</summary>
        public List<RecentFiring> RecentFirings { get; set; } = new();

        /// <summary>Maximum alerts per hour per channel before rate-limiting kicks in.</summary>
        public int MaxAlertsPerHourPerChannel { get; set; } = 6;

        /// <summary>Total firings in last 24h above which fatigue is declared.</summary>
        public int FatigueThresholdPer24h { get; set; } = 12;

        /// <summary>Whether chat channel is available right now.</summary>
        public bool ChatAvailable { get; set; } = true;

        /// <summary>Whether email channel is available right now.</summary>
        public bool EmailAvailable { get; set; } = true;

        /// <summary>Whether pager is available right now.</summary>
        public bool PagerAvailable { get; set; } = true;

        /// <summary>How aggressively to protect the channel.</summary>
        public RiskAppetite Risk { get; set; } = RiskAppetite.Balanced;

        /// <summary>Pin "now" for deterministic testing.</summary>
        public DateTimeOffset? NowOverride { get; set; }
    }

    /// <summary>Routing decision for a single alert.</summary>
    public record RoutingDecision(
        string RuleId,
        string RuleName,
        AlertRuleEngine.AlertPriority Priority,
        RoutingAction Action,
        string Channel,
        string Recipient,
        string Reason,
        List<string> Signals,
        int ConfidenceScore,
        DateTimeOffset DecidedAt,
        DateTimeOffset? DeliverAt);

    /// <summary>Portfolio-level observation across the whole batch.</summary>
    public record PortfolioInsight(
        string Code,
        string Headline,
        AlertRuleEngine.AlertPriority Severity,
        string Recommendation);

    /// <summary>Full routing plan emitted by <see cref="Plan"/>.</summary>
    public class RoutingPlan
    {
        public List<RoutingDecision> Decisions { get; set; } = new();
        public List<PortfolioInsight> Insights { get; set; } = new();
        public Dictionary<RoutingAction, int> ActionHistogram { get; set; } = new();
        public string Headline { get; set; } = "";
        public string Grade { get; set; } = "C";
        public DateTimeOffset GeneratedAt { get; set; }
    }

    // ── Public API ───────────────────────────────────────────────

    /// <summary>
    /// Build a routing plan for a batch of triggered alerts.
    /// </summary>
    public RoutingPlan Plan(
        IEnumerable<AlertRuleEngine.AlertResult> alerts,
        RoutingContext context)
    {
        ArgumentNullException.ThrowIfNull(alerts);
        ArgumentNullException.ThrowIfNull(context);

        var now = context.NowOverride ?? DateTimeOffset.UtcNow;
        var batch = alerts.ToList();

        // Mutable channel-firings projection so within-batch rate-limit works.
        var projected = new List<RecentFiring>(context.RecentFirings);

        var decisions = new List<RoutingDecision>(batch.Count);
        foreach (var alert in batch)
        {
            var decision = DecideOne(alert, context, now, projected);
            decisions.Add(decision);

            // Only count actually-delivered actions toward future rate limits.
            if (decision.Action is RoutingAction.Chat or RoutingAction.Email or RoutingAction.Page)
            {
                projected.Add(new RecentFiring(alert.RuleId, now));
            }
        }

        var histogram = decisions
            .GroupBy(d => d.Action)
            .ToDictionary(g => g.Key, g => g.Count());

        var insights = BuildInsights(batch, decisions, context);
        var grade = ComputeGrade(batch, decisions, insights);
        var headline = BuildHeadline(batch.Count, histogram, grade);

        return new RoutingPlan
        {
            Decisions = decisions,
            Insights = insights,
            ActionHistogram = histogram,
            Headline = headline,
            Grade = grade,
            GeneratedAt = now,
        };
    }

    // ── Core per-alert logic ─────────────────────────────────────

    private static RoutingDecision DecideOne(
        AlertRuleEngine.AlertResult alert,
        RoutingContext ctx,
        DateTimeOffset now,
        List<RecentFiring> projected)
    {
        var signals = new List<string>();
        var basePriority = alert.Priority;
        var defaultAction = DefaultActionFor(basePriority);
        var action = defaultAction;
        DateTimeOffset? deliverAt = null;

        // 1. Dedup — same rule fired within last 10 minutes.
        var dedupWindow = TimeSpan.FromMinutes(10);
        if (projected.Any(f => f.RuleId == alert.RuleId && (now - f.At) <= dedupWindow))
        {
            signals.Add("RECENT_DUPLICATE");
            return Finalize(alert, RoutingAction.Suppress, "(suppressed)", "n/a",
                "Same rule fired within the last 10 minutes; suppressing duplicate.",
                signals, defaultAction, now, null);
        }

        // 2. Fatigue check — total firings in last 24h.
        var fatigueWindow = TimeSpan.FromHours(24);
        int firingsLast24h = projected.Count(f => (now - f.At) <= fatigueWindow);
        bool fatigueActive = firingsLast24h > ctx.FatigueThresholdPer24h;
        if (fatigueActive)
        {
            signals.Add("ALERT_FATIGUE");
            action = DemoteOneNotch(action);
        }

        // 3. Base action already chosen via DefaultActionFor above; possibly demoted.

        // 4. Quiet-hours adjustment.
        if (ctx.Quiet is not null && InWindow(now, ctx.Quiet.Start, ctx.Quiet.End)
            && ctx.Quiet.BatchInsteadOfPaging)
        {
            bool skipForCriticalCautious =
                basePriority == AlertRuleEngine.AlertPriority.Critical
                && ctx.Risk == RiskAppetite.Cautious;

            if (!skipForCriticalCautious)
            {
                if (action == RoutingAction.Page)
                {
                    action = RoutingAction.Email;
                    signals.Add("QUIET_HOURS");
                }
                else if (action == RoutingAction.Email)
                {
                    action = RoutingAction.Chat;
                    signals.Add("QUIET_HOURS");
                }
            }
        }

        // 5. Channel availability — downgrade if chosen channel down.
        var adjusted = EnforceAvailability(action, ctx, signals);
        action = adjusted;

        // 6. Per-channel rate limit (count delivered actions only).
        var hourWindow = TimeSpan.FromHours(1);
        string channelForAction = ChannelFor(action);
        int onChannel = projected
            .Count(f => (now - f.At) <= hourWindow);
        // Note: projected entries don't track which channel they used. We
        // approximate by capping total deliveries per channel using the same
        // hour-bucket counter — conservative but deterministic.
        if (action is RoutingAction.Chat or RoutingAction.Email or RoutingAction.Page
            && onChannel >= ctx.MaxAlertsPerHourPerChannel)
        {
            signals.Add("RATE_LIMITED");
            action = RoutingAction.Batch;
            deliverAt = NextHourBucket(now);
        }

        // 7. Escalation — Critical with no primary on-call right now.
        if (basePriority == AlertRuleEngine.AlertPriority.Critical
            && !HasPrimaryOnCall(ctx.OnCall, now))
        {
            signals.Add("NO_PRIMARY_ONCALL");
            action = RoutingAction.Escalate;
        }

        // 8. Risk modulation.
        if (ctx.Risk == RiskAppetite.Cautious)
        {
            // Never demote Critical below Email.
            if (basePriority == AlertRuleEngine.AlertPriority.Critical
                && (action == RoutingAction.Chat || action == RoutingAction.Batch))
            {
                action = RoutingAction.Email;
                signals.Add("CAUTIOUS_FLOOR");
            }
        }
        else if (ctx.Risk == RiskAppetite.Aggressive)
        {
            // Demote Page → Email when fatigue OR quiet hours hit.
            if (action == RoutingAction.Page
                && (signals.Contains("ALERT_FATIGUE") || signals.Contains("QUIET_HOURS")))
            {
                action = RoutingAction.Email;
                signals.Add("AGGRESSIVE_DEMOTE");
            }
        }

        // 9. Recipient resolution.
        var (recipient, channel) = ResolveRecipient(action, ctx.OnCall, now);

        // 10. Build reason.
        var reason = BuildReason(basePriority, action, signals);

        return Finalize(alert, action, channel, recipient, reason, signals, defaultAction, now, deliverAt);
    }

    private static RoutingDecision Finalize(
        AlertRuleEngine.AlertResult alert,
        RoutingAction action,
        string channel,
        string recipient,
        string reason,
        List<string> signals,
        RoutingAction defaultAction,
        DateTimeOffset now,
        DateTimeOffset? deliverAt)
    {
        int confidence = 80;
        if (action == defaultAction) confidence += 5;
        confidence -= 10 * signals.Count;
        if (confidence < 25) confidence = 25;
        if (confidence > 100) confidence = 100;

        return new RoutingDecision(
            alert.RuleId,
            alert.RuleName,
            alert.Priority,
            action,
            channel,
            recipient,
            reason,
            signals,
            confidence,
            now,
            deliverAt);
    }

    // ── Helpers ──────────────────────────────────────────────────

    private static RoutingAction DefaultActionFor(AlertRuleEngine.AlertPriority priority) =>
        priority switch
        {
            AlertRuleEngine.AlertPriority.Critical => RoutingAction.Page,
            AlertRuleEngine.AlertPriority.High => RoutingAction.Email,
            AlertRuleEngine.AlertPriority.Medium => RoutingAction.Chat,
            _ => RoutingAction.Batch,
        };

    private static RoutingAction DemoteOneNotch(RoutingAction action) =>
        action switch
        {
            RoutingAction.Page => RoutingAction.Email,
            RoutingAction.Email => RoutingAction.Chat,
            RoutingAction.Chat => RoutingAction.Batch,
            _ => action,
        };

    private static RoutingAction EnforceAvailability(
        RoutingAction desired,
        RoutingContext ctx,
        List<string> signals)
    {
        bool changed = false;
        var action = desired;

        if (action == RoutingAction.Page && !ctx.PagerAvailable)
        {
            action = RoutingAction.Email;
            changed = true;
        }
        if (action == RoutingAction.Email && !ctx.EmailAvailable)
        {
            action = RoutingAction.Chat;
            changed = true;
        }
        if (action == RoutingAction.Chat && !ctx.ChatAvailable)
        {
            action = RoutingAction.Batch;
            changed = true;
        }

        if (changed) signals.Add("CHANNEL_UNAVAILABLE");
        return action;
    }

    private static bool InWindow(DateTimeOffset now, TimeOnly start, TimeOnly end)
    {
        var t = TimeOnly.FromDateTime(now.DateTime);
        if (start == end) return false;
        if (start < end)
        {
            return t >= start && t < end;
        }
        // Crosses midnight: window is [start, 24:00) ∪ [00:00, end)
        return t >= start || t < end;
    }

    private static bool HasPrimaryOnCall(IEnumerable<OnCallEntry> roster, DateTimeOffset now)
    {
        var day = now.DateTime.DayOfWeek;
        var t = TimeOnly.FromDateTime(now.DateTime);
        foreach (var entry in roster)
        {
            if (!entry.PrimaryPager) continue;
            if (!entry.Days.Contains(day)) continue;
            if (InEntryWindow(entry, t)) return true;
        }
        return false;
    }

    private static bool InEntryWindow(OnCallEntry entry, TimeOnly t)
    {
        if (entry.Start == entry.End) return true; // all-day
        if (entry.Start < entry.End)
        {
            return t >= entry.Start && t < entry.End;
        }
        return t >= entry.Start || t < entry.End;
    }

    private static (string recipient, string channel) ResolveRecipient(
        RoutingAction action,
        List<OnCallEntry> roster,
        DateTimeOffset now)
    {
        if (action == RoutingAction.Suppress)
            return ("(suppressed)", "n/a");
        if (action == RoutingAction.Batch)
            return ("(digest)", "digest");

        var day = now.DateTime.DayOfWeek;
        var t = TimeOnly.FromDateTime(now.DateTime);
        var candidates = roster
            .Where(e => e.Days.Contains(day) && InEntryWindow(e, t))
            .ToList();

        if (candidates.Count == 0)
            return ("unassigned", ChannelFor(action));

        if (action == RoutingAction.Page)
        {
            var primary = candidates.FirstOrDefault(c => c.PrimaryPager);
            if (primary is not null)
                return (primary.Name, primary.Channel);
        }
        if (action == RoutingAction.Escalate)
        {
            // Pick the first non-primary as the escalation target if any.
            var escalate = candidates.FirstOrDefault(c => !c.PrimaryPager) ?? candidates[0];
            return (escalate.Name, escalate.Channel);
        }

        var match = candidates[0];
        return (match.Name, match.Channel);
    }

    private static string ChannelFor(RoutingAction action) => action switch
    {
        RoutingAction.Page => "pager",
        RoutingAction.Email => "email",
        RoutingAction.Chat => "chat",
        RoutingAction.Batch => "digest",
        RoutingAction.Escalate => "escalation",
        _ => "n/a",
    };

    private static DateTimeOffset NextHourBucket(DateTimeOffset now)
    {
        var rounded = new DateTimeOffset(
            now.Year, now.Month, now.Day, now.Hour, 0, 0, now.Offset);
        return rounded.AddHours(1);
    }

    private static string BuildReason(
        AlertRuleEngine.AlertPriority priority,
        RoutingAction action,
        List<string> signals)
    {
        var sb = new StringBuilder();
        sb.Append($"Priority {priority} → {action}");
        if (signals.Count > 0)
            sb.Append(" (").Append(string.Join(", ", signals)).Append(')');
        sb.Append('.');
        return sb.ToString();
    }

    // ── Portfolio insights + grade ───────────────────────────────

    private static List<PortfolioInsight> BuildInsights(
        List<AlertRuleEngine.AlertResult> batch,
        List<RoutingDecision> decisions,
        RoutingContext ctx)
    {
        var insights = new List<PortfolioInsight>();

        if (batch.Count > 8)
        {
            insights.Add(new PortfolioInsight(
                "STORM",
                $"Alert storm in progress: {batch.Count} alerts in one batch.",
                AlertRuleEngine.AlertPriority.High,
                "Consider raising rule thresholds or pausing noisy modules."));
        }

        if (decisions.Any(d => d.Signals.Contains("ALERT_FATIGUE")))
        {
            insights.Add(new PortfolioInsight(
                "FATIGUE_ACTIVE",
                "On-call fatigue threshold exceeded; demotions applied.",
                AlertRuleEngine.AlertPriority.High,
                "Review the noisiest rules over the last 24h and tighten."));
        }

        if (decisions.Any(d => d.Signals.Contains("NO_PRIMARY_ONCALL")))
        {
            insights.Add(new PortfolioInsight(
                "NO_ONCALL",
                "Critical alert(s) had no primary on-call to page.",
                AlertRuleEngine.AlertPriority.Critical,
                "Fix the on-call rotation or assign a fallback pager."));
        }

        if (decisions.Any(d => d.Signals.Contains("QUIET_HOURS")))
        {
            insights.Add(new PortfolioInsight(
                "QUIET_BATCHING",
                "Quiet-hours policy demoted some pages to lower channels.",
                AlertRuleEngine.AlertPriority.Medium,
                "Confirm the demoted alerts are not silently dangerous."));
        }

        int criticalCount = batch.Count(a => a.Priority == AlertRuleEngine.AlertPriority.Critical);
        if (criticalCount >= 3)
        {
            insights.Add(new PortfolioInsight(
                "CRITICAL_BACKLOG",
                $"{criticalCount} Critical alerts open simultaneously.",
                AlertRuleEngine.AlertPriority.Critical,
                "Treat as multi-incident; consider incident commander rotation."));
        }

        return insights;
    }

    private static string ComputeGrade(
        List<AlertRuleEngine.AlertResult> batch,
        List<RoutingDecision> decisions,
        List<PortfolioInsight> insights)
    {
        bool fatigue = insights.Any(i => i.Code == "FATIGUE_ACTIVE");
        bool storm = insights.Any(i => i.Code == "STORM");
        bool noOncall = insights.Any(i => i.Code == "NO_ONCALL");
        int criticalCount = batch.Count(a => a.Priority == AlertRuleEngine.AlertPriority.Critical);

        if (noOncall && criticalCount > 0) return "F";
        if (storm || fatigue) return "D";
        if (batch.Count <= 2 && criticalCount == 0 && !fatigue) return "A";
        if (batch.Count <= 5 && criticalCount <= 1) return "B";
        if (batch.Count <= 10) return "C";
        return "D";
    }

    private static string BuildHeadline(
        int total,
        Dictionary<RoutingAction, int> histogram,
        string grade)
    {
        if (total == 0) return $"No alerts to route. Grade {grade}.";

        var parts = new List<string>();
        foreach (RoutingAction a in Enum.GetValues<RoutingAction>())
        {
            if (histogram.TryGetValue(a, out var n) && n > 0)
                parts.Add($"{n} {a}");
        }
        return $"Routed {total} alerts: {string.Join(", ", parts)}. Grade {grade}.";
    }

    // ── Formatters ───────────────────────────────────────────────

    /// <summary>Plain-text rendering of the plan.</summary>
    public string FormatText(RoutingPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var sb = new StringBuilder();
        sb.AppendLine($"ALERT ROUTING PLAN — Grade {plan.Grade}");
        sb.AppendLine(plan.Headline);
        sb.AppendLine($"Generated: {plan.GeneratedAt:u}");
        sb.AppendLine(new string('-', 60));
        foreach (var d in plan.Decisions)
        {
            sb.AppendLine(
                $"[{d.Priority,-8}] {d.RuleName,-32} -> {d.Action,-8} via {d.Channel,-9} to {d.Recipient}");
            sb.AppendLine($"           reason: {d.Reason}");
            if (d.DeliverAt is not null)
                sb.AppendLine($"           deliver at: {d.DeliverAt:u}");
            sb.AppendLine($"           confidence: {d.ConfidenceScore}");
        }
        if (plan.Insights.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("PORTFOLIO INSIGHTS");
            foreach (var i in plan.Insights)
            {
                sb.AppendLine($" * [{i.Severity}] {i.Code}: {i.Headline}");
                sb.AppendLine($"     -> {i.Recommendation}");
            }
        }
        return sb.ToString();
    }

    /// <summary>Markdown rendering of the plan.</summary>
    public string FormatMarkdown(RoutingPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var sb = new StringBuilder();
        sb.AppendLine("# Alert Routing Plan");
        sb.AppendLine();
        sb.AppendLine($"**Grade:** {plan.Grade}  ");
        sb.AppendLine($"**Headline:** {plan.Headline}  ");
        sb.AppendLine($"**Generated:** {plan.GeneratedAt:u}");
        sb.AppendLine();
        sb.AppendLine("| Rule | Priority | Action | Channel | Recipient | Reason |");
        sb.AppendLine("|------|----------|--------|---------|-----------|--------|");
        foreach (var d in plan.Decisions)
        {
            var reason = d.Reason.Replace("|", "\\|");
            sb.AppendLine($"| {d.RuleName} | {d.Priority} | {d.Action} | {d.Channel} | {d.Recipient} | {reason} |");
        }
        if (plan.Insights.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("## Portfolio Insights");
            sb.AppendLine();
            foreach (var i in plan.Insights)
            {
                sb.AppendLine($"- **[{i.Severity}] {i.Code}** — {i.Headline} _Recommendation:_ {i.Recommendation}");
            }
        }
        return sb.ToString();
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>JSON rendering of the plan (deterministic with same inputs).</summary>
    public string FormatJson(RoutingPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        return JsonSerializer.Serialize(plan, JsonOpts);
    }
}
