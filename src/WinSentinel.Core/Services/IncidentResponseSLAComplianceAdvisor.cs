using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Core.Services;

/// <summary>
/// Agentic incident-response SLA compliance + process-improvement advisor.
/// <para>
/// Given a portfolio of <see cref="IncidentRecord"/> entries and an optional
/// <see cref="SlaContext"/> (per-severity SLA budgets, risk appetite, regulated
/// flag, on-call roster size), grades MTTA/MTTC/MTTR per incident against the
/// SLA catalogue and emits a structured <see cref="IncidentSlaReport"/>:
/// per-incident verdict / priority / reason codes, a deduped P0-first
/// process-improvement playbook (EMERGENCY_IR_REVIEW, EXPAND_ONCALL_ROSTER,
/// ROOT_CAUSE_REPEAT_INCIDENTS, AUTOMATE_RUNBOOK, ESCALATE_VENDOR_SLA,
/// TIGHTEN_ACK_PAGER_ROTATION, BACKFILL_POSTMORTEMS, ADD_OFF_HOURS_COVERAGE,
/// RENEGOTIATE_SEV_BUDGETS, SLA_COMPLIANCE_HEALTHY), cross-incident insights
/// and an overall A-F grade with Sev1-breach gating.
/// </para>
/// <para>
/// Sibling to <see cref="FixOrchestrationPlanner"/> (sequences fixes),
/// <see cref="AlertRoutingAdvisor"/> (routes alerts),
/// <see cref="AttackerProfileSynthesizer"/> (identifies attackers) and
/// <see cref="PostureRegressionExplainer"/> (explains posture drift). This
/// advisor answers <em>did we meet our IR SLAs and what should our IR
/// program improve next?</em>
/// </para>
/// <para>Pure / deterministic - no I/O. Time can be pinned via
/// <see cref="SlaContext.NowOverride"/> for reproducible tests. Never mutates
/// the input incident list.</para>
/// </summary>
public class IncidentResponseSLAComplianceAdvisor
{
    // -- Public model ------------------------------------------------

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum IncidentSeverity { Sev1, Sev2, Sev3, Sev4 }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum RiskAppetite { Cautious, Balanced, Aggressive }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum StageBand { MetWithBuffer, MetOnTime, MinorBreach, MajorBreach, CriticalBreach, NotApplicable }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum IncidentVerdict { OnTrack, AtRisk, MinorMiss, MajorMiss, CriticalMiss, Unresolved }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum PortfolioVerdict { Excellent, Healthy, Strained, Failing, Crisis }

    public record IncidentRecord(
        string Id,
        string Title,
        IncidentSeverity Severity,
        DateTime DetectedAt,
        DateTime? AcknowledgedAt,
        DateTime? ContainedAt,
        DateTime? ResolvedAt,
        string? Category = null,
        string? AssignedTeam = null,
        bool RequiredVendorEscalation = false,
        bool RequiredManualRunbook = false,
        int ReopenCount = 0,
        bool PostmortemCompleted = false,
        IReadOnlyList<string>? Tags = null);

    public record SlaBudget(
        IncidentSeverity Severity,
        TimeSpan AckWithin,
        TimeSpan ContainWithin,
        TimeSpan ResolveWithin);

    public record SlaContext(
        IReadOnlyList<SlaBudget>? Budgets = null,
        DateTime? NowOverride = null,
        RiskAppetite RiskAppetite = RiskAppetite.Balanced,
        bool RegulatedDomain = false,
        int? OnCallRosterSize = null);

    public record StageAssessment(
        string Stage,
        double? Minutes,
        double? BudgetMinutes,
        StageBand Band);

    public record IncidentReason(string Code, int Weight, string Detail);

    public record IncidentAssessment(
        string Id,
        string Title,
        IncidentSeverity Severity,
        IncidentVerdict Verdict,
        string Priority,
        double? AckMinutes,
        double? ContainMinutes,
        double? ResolveMinutes,
        IReadOnlyList<StageAssessment> Stages,
        IReadOnlyList<IncidentReason> Reasons);

    public record PlaybookAction(
        string Id,
        string Priority,
        string Label,
        string Owner,
        int BlastRadius,
        string Reversibility,
        string Reason,
        IReadOnlyList<string> TargetIncidentIds,
        double? SuggestedValue);

    public record PortfolioSummary(
        int TotalIncidents,
        double? MeanAckMinutes,
        double? MeanContainMinutes,
        double? MeanResolveMinutes,
        double BreachRate,
        double Sev1BreachRate,
        int OnTrackCount,
        int MinorMissCount,
        int MajorMissCount,
        int CriticalMissCount,
        int AtRiskCount);

    public record IncidentSlaReport(
        DateTime GeneratedAt,
        PortfolioVerdict Verdict,
        string Grade,
        int ComplianceScore,
        PortfolioSummary Summary,
        IReadOnlyList<IncidentAssessment> Incidents,
        IReadOnlyList<PlaybookAction> Playbook,
        IReadOnlyList<string> Insights,
        string Headline);

    // -- Public API --------------------------------------------------

    public IncidentSlaReport Analyze(IEnumerable<IncidentRecord> incidents, SlaContext? ctx = null)
    {
        if (incidents is null) throw new ArgumentNullException(nameof(incidents));
        ctx ??= new SlaContext();
        var now = ctx.NowOverride ?? DateTime.UtcNow;

        // Snapshot inputs (never mutate caller's collection).
        var input = incidents.ToList();

        // Build budget lookup.
        var budgets = BuildBudgets(ctx);

        // Per-incident pass.
        var assessments = new List<IncidentAssessment>(input.Count);
        // Track at-risk state per assessment (cannot stash inside record without leaking).
        var atRiskOnly = new Dictionary<string, bool>();

        foreach (var inc in input)
        {
            var (assess, isAtRiskOnly) = AssessIncident(inc, budgets, ctx, now);
            assessments.Add(assess);
            atRiskOnly[inc.Id] = isAtRiskOnly;
        }

        // Portfolio summary.
        var summary = BuildSummary(assessments);

        // Compliance score / grade / verdict.
        var (score, grade, pVerdict) = BuildGrade(summary, assessments, ctx);

        // Playbook.
        var playbook = BuildPlaybook(assessments, summary, ctx, grade, pVerdict, budgets);

        // Insights.
        var insights = BuildInsights(assessments, summary, ctx, grade, playbook, input);

        // Stable sort: priority asc then id asc.
        var orderedIncidents = assessments
            .OrderBy(a => PriorityRank(a.Priority))
            .ThenBy(a => a.Id, StringComparer.Ordinal)
            .ToList();

        // Headline.
        double breachPct = summary.BreachRate * 100.0;
        int p0Count = playbook.Count(p => p.Priority == "P0");
        string meanResolveDisplay = summary.MeanResolveMinutes.HasValue
            ? $"{summary.MeanResolveMinutes.Value:F0}m"
            : "-";
        string headline = $"VERDICT: grade={grade} {summary.TotalIncidents} incidents, breach={breachPct:F0}%, P0={p0Count}, mean MTTR={meanResolveDisplay}";

        return new IncidentSlaReport(
            now,
            pVerdict,
            grade,
            score,
            summary,
            orderedIncidents,
            playbook,
            insights,
            headline);
    }

    // -- Renderers ---------------------------------------------------

    public static string Render(IncidentSlaReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"IR SLA compliance report  generated {r.GeneratedAt:O}");
        sb.AppendLine($"Verdict: {r.Verdict}  Grade: {r.Grade}  Score: {r.ComplianceScore}");
        sb.AppendLine($"Headline: {r.Headline}");
        sb.AppendLine();
        sb.AppendLine($"Incidents ({r.Incidents.Count}):");
        foreach (var i in r.Incidents)
        {
            sb.AppendLine($"  [{i.Priority}] {i.Id} sev={i.Severity} verdict={i.Verdict}  ack={Fmt(i.AckMinutes)} contain={Fmt(i.ContainMinutes)} resolve={Fmt(i.ResolveMinutes)}");
            foreach (var rsn in i.Reasons)
                sb.AppendLine($"      - {rsn.Code} (w={rsn.Weight}): {rsn.Detail}");
        }
        sb.AppendLine();
        sb.AppendLine($"Playbook ({r.Playbook.Count}):");
        foreach (var a in r.Playbook)
            sb.AppendLine($"  [{a.Priority}] {a.Id} -> {a.Label} (owner={a.Owner}, blast={a.BlastRadius}, rev={a.Reversibility})");
        sb.AppendLine();
        sb.AppendLine($"Insights ({r.Insights.Count}):");
        foreach (var s in r.Insights) sb.AppendLine($"  - {s}");
        return sb.ToString();
    }

    public static string RenderMarkdown(IncidentSlaReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine("## Summary");
        sb.AppendLine("| Metric | Value |");
        sb.AppendLine("| --- | --- |");
        sb.AppendLine($"| Verdict | {r.Verdict} |");
        sb.AppendLine($"| Grade | {r.Grade} |");
        sb.AppendLine($"| ComplianceScore | {r.ComplianceScore} |");
        sb.AppendLine($"| TotalIncidents | {r.Summary.TotalIncidents} |");
        sb.AppendLine($"| BreachRate | {r.Summary.BreachRate:F2} |");
        sb.AppendLine($"| Sev1BreachRate | {r.Summary.Sev1BreachRate:F2} |");
        sb.AppendLine($"| MeanAckMinutes | {Fmt(r.Summary.MeanAckMinutes)} |");
        sb.AppendLine($"| MeanContainMinutes | {Fmt(r.Summary.MeanContainMinutes)} |");
        sb.AppendLine($"| MeanResolveMinutes | {Fmt(r.Summary.MeanResolveMinutes)} |");
        sb.AppendLine($"| OnTrack | {r.Summary.OnTrackCount} |");
        sb.AppendLine($"| AtRisk | {r.Summary.AtRiskCount} |");
        sb.AppendLine($"| MinorMiss | {r.Summary.MinorMissCount} |");
        sb.AppendLine($"| MajorMiss | {r.Summary.MajorMissCount} |");
        sb.AppendLine($"| CriticalMiss | {r.Summary.CriticalMissCount} |");
        sb.AppendLine($"| GeneratedAt | {r.GeneratedAt:O} |");
        sb.AppendLine($"| Headline | {r.Headline} |");
        sb.AppendLine();
        sb.AppendLine("## Incidents");
        sb.AppendLine("| Id | Sev | Verdict | Priority | Ack (min) | Contain (min) | Resolve (min) | Reasons |");
        sb.AppendLine("| --- | --- | --- | --- | --- | --- | --- | --- |");
        foreach (var i in r.Incidents)
        {
            string reasons = string.Join(",", i.Reasons.Select(x => x.Code));
            sb.AppendLine($"| {i.Id} | {i.Severity} | {i.Verdict} | {i.Priority} | {Fmt(i.AckMinutes)} | {Fmt(i.ContainMinutes)} | {Fmt(i.ResolveMinutes)} | {reasons} |");
        }
        sb.AppendLine();
        sb.AppendLine("## Playbook");
        sb.AppendLine("| Priority | Id | Label | Owner | Blast | Reversibility | Targets |");
        sb.AppendLine("| --- | --- | --- | --- | --- | --- | --- |");
        foreach (var a in r.Playbook)
            sb.AppendLine($"| {a.Priority} | {a.Id} | {a.Label} | {a.Owner} | {a.BlastRadius} | {a.Reversibility} | {string.Join(",", a.TargetIncidentIds)} |");
        sb.AppendLine();
        sb.AppendLine("## Insights");
        if (r.Insights.Count == 0) sb.AppendLine("- (none)");
        else foreach (var s in r.Insights) sb.AppendLine($"- {s}");
        return sb.ToString();
    }

    public static string RenderJson(IncidentSlaReport r)
    {
        var opts = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() },
        };
        return JsonSerializer.Serialize(r, opts);
    }

    // -- Internals ---------------------------------------------------

    private static string Fmt(double? v) => v.HasValue ? v.Value.ToString("F1") : "-";

    private static int PriorityRank(string p) => p switch
    {
        "P0" => 0, "P1" => 1, "P2" => 2, "P3" => 3, _ => 9,
    };

    private static Dictionary<IncidentSeverity, SlaBudget> BuildBudgets(SlaContext ctx)
    {
        var defaults = new[]
        {
            new SlaBudget(IncidentSeverity.Sev1, TimeSpan.FromMinutes(15), TimeSpan.FromHours(1),  TimeSpan.FromHours(4)),
            new SlaBudget(IncidentSeverity.Sev2, TimeSpan.FromMinutes(30), TimeSpan.FromHours(4),  TimeSpan.FromHours(24)),
            new SlaBudget(IncidentSeverity.Sev3, TimeSpan.FromHours(2),    TimeSpan.FromHours(12), TimeSpan.FromHours(72)),
            new SlaBudget(IncidentSeverity.Sev4, TimeSpan.FromHours(8),    TimeSpan.FromHours(48), TimeSpan.FromHours(168)),
        };
        var src = ctx.Budgets ?? defaults;
        var map = new Dictionary<IncidentSeverity, SlaBudget>();
        foreach (var b in src) map[b.Severity] = b;
        // Ensure all severities present.
        foreach (var d in defaults)
            if (!map.ContainsKey(d.Severity)) map[d.Severity] = d;

        if (ctx.RegulatedDomain && map.TryGetValue(IncidentSeverity.Sev1, out var s1))
        {
            map[IncidentSeverity.Sev1] = new SlaBudget(
                IncidentSeverity.Sev1,
                TimeSpan.FromTicks((long)(s1.AckWithin.Ticks * 0.70)),
                TimeSpan.FromTicks((long)(s1.ContainWithin.Ticks * 0.70)),
                s1.ResolveWithin);
        }
        return map;
    }

    private static (IncidentAssessment, bool atRiskOnly) AssessIncident(
        IncidentRecord inc,
        Dictionary<IncidentSeverity, SlaBudget> budgets,
        SlaContext ctx,
        DateTime now)
    {
        var budget = budgets[inc.Severity];
        bool open = inc.ResolvedAt is null;

        // Data error: resolved before detected.
        if (inc.ResolvedAt.HasValue && inc.ResolvedAt.Value < inc.DetectedAt)
        {
            var na = new[]
            {
                new StageAssessment("Ack", null, budget.AckWithin.TotalMinutes, StageBand.NotApplicable),
                new StageAssessment("Contain", null, budget.ContainWithin.TotalMinutes, StageBand.NotApplicable),
                new StageAssessment("Resolve", null, budget.ResolveWithin.TotalMinutes, StageBand.NotApplicable),
            };
            var dataErrReasons = new List<IncidentReason>
            {
                new("DATA_ERROR", 90, "ResolvedAt precedes DetectedAt; treating as data error."),
            };
            var priority = ComputePriority(inc, IncidentVerdict.CriticalMiss);
            return (new IncidentAssessment(
                inc.Id, inc.Title, inc.Severity, IncidentVerdict.CriticalMiss, priority,
                null, null, null, na, dataErrReasons), false);
        }

        // Compute each stage.
        var (ackStage, ackMin, ackAtRisk, ackRealBreach) =
            ScoreStage("Ack", inc.AcknowledgedAt, inc.DetectedAt, budget.AckWithin, open, now);
        var (conStage, conMin, conAtRisk, conRealBreach) =
            ScoreStage("Contain", inc.ContainedAt, inc.DetectedAt, budget.ContainWithin, open, now);
        var (resStage, resMin, resAtRisk, resRealBreach) =
            ScoreStage("Resolve", inc.ResolvedAt, inc.DetectedAt, budget.ResolveWithin, open, now);

        var stages = new List<StageAssessment> { ackStage, conStage, resStage };

        // Verdict.
        bool anyCritical = stages.Any(s => s.Band == StageBand.CriticalBreach);
        bool anyMajor = stages.Any(s => s.Band == StageBand.MajorBreach);
        bool anyMinorReal = ackRealBreach || conRealBreach || resRealBreach;
        bool anyAtRisk = ackAtRisk || conAtRisk || resAtRisk;

        IncidentVerdict verdict;
        if (anyCritical) verdict = IncidentVerdict.CriticalMiss;
        else if (anyMajor) verdict = IncidentVerdict.MajorMiss;
        else if (anyMinorReal) verdict = IncidentVerdict.MinorMiss;
        else if (anyAtRisk) verdict = IncidentVerdict.AtRisk;
        else if (open) verdict = IncidentVerdict.Unresolved;
        else verdict = IncidentVerdict.OnTrack;

        bool atRiskOnly = verdict == IncidentVerdict.AtRisk;

        // Reasons.
        var reasons = BuildReasons(inc, stages, verdict, ctx);

        var priorityStr = ComputePriority(inc, verdict);

        return (new IncidentAssessment(
            inc.Id, inc.Title, inc.Severity, verdict, priorityStr,
            ackMin, conMin, resMin, stages, reasons), atRiskOnly);
    }

    private static (StageAssessment stage, double? minutes, bool atRisk, bool realBreach)
        ScoreStage(string name, DateTime? stageTime, DateTime detected, TimeSpan budget, bool incidentOpen, DateTime now)
    {
        double budgetMin = budget.TotalMinutes;
        if (stageTime.HasValue)
        {
            double m = (stageTime.Value - detected).TotalMinutes;
            if (m < 0) m = 0;
            double r = budgetMin > 0 ? m / budgetMin : 0;
            StageBand band = r <= 0.50 ? StageBand.MetWithBuffer
                            : r <= 1.00 ? StageBand.MetOnTime
                            : r <= 1.50 ? StageBand.MinorBreach
                            : r <= 3.00 ? StageBand.MajorBreach
                            : StageBand.CriticalBreach;
            bool realB = band == StageBand.MinorBreach;
            return (new StageAssessment(name, m, budgetMin, band), m, false, realB);
        }

        // Not reached.
        if (!incidentOpen)
        {
            // Closed but stage missing -> skipped stage.
            return (new StageAssessment(name, null, budgetMin, StageBand.CriticalBreach), null, false, false);
        }

        // Still open: compute in-progress elapsed.
        double elapsed = (now - detected).TotalMinutes;
        if (elapsed < 0) elapsed = 0;
        double ratio = budgetMin > 0 ? elapsed / budgetMin : 0;
        // Open incidents with unreached stages never escalate past MinorBreach;
        // they only feed AtRisk tracking (per spec: "don't double-count").
        if (ratio < 0.80)
            return (new StageAssessment(name, elapsed, budgetMin, StageBand.MetOnTime), elapsed, false, false);
        return (new StageAssessment(name, elapsed, budgetMin, StageBand.MinorBreach), elapsed, true, false);
    }

    private static string ComputePriority(IncidentRecord inc, IncidentVerdict v)
    {
        bool isSev1 = inc.Severity == IncidentSeverity.Sev1;
        bool isSev2 = inc.Severity == IncidentSeverity.Sev2;
        if (v == IncidentVerdict.CriticalMiss) return "P0";
        if (isSev1 && v == IncidentVerdict.MajorMiss) return "P0";
        if (inc.ReopenCount >= 2) return "P0";
        if (v == IncidentVerdict.MajorMiss) return "P1";
        if ((isSev1 || isSev2) && v == IncidentVerdict.MinorMiss) return "P1";
        bool anyBreach = v == IncidentVerdict.MinorMiss || v == IncidentVerdict.MajorMiss || v == IncidentVerdict.CriticalMiss;
        if (inc.RequiredVendorEscalation && anyBreach) return "P1";
        if (v == IncidentVerdict.MinorMiss || v == IncidentVerdict.AtRisk) return "P2";
        return "P3";
    }

    private static List<IncidentReason> BuildReasons(
        IncidentRecord inc,
        List<StageAssessment> stages,
        IncidentVerdict verdict,
        SlaContext ctx)
    {
        var reasons = new List<IncidentReason>();
        bool anyBreach = stages.Any(s => s.Band == StageBand.MinorBreach || s.Band == StageBand.MajorBreach || s.Band == StageBand.CriticalBreach);

        bool BreachOf(string name)
        {
            var s = stages.First(x => x.Stage == name);
            return s.Band == StageBand.MinorBreach || s.Band == StageBand.MajorBreach || s.Band == StageBand.CriticalBreach;
        }

        if (inc.Severity == IncidentSeverity.Sev1 && anyBreach)
            reasons.Add(new IncidentReason("SEV1_BLAST", 80, "Sev1 incident missed at least one SLA stage."));
        if (ctx.RegulatedDomain && inc.Severity == IncidentSeverity.Sev1)
            reasons.Add(new IncidentReason("REGULATED_BUDGET_TIGHT", 40, "Regulated-domain Sev1 budget tightened by 30%."));
        if (BreachOf("Ack"))
            reasons.Add(new IncidentReason("ACK_LATE", 60, "Acknowledgement stage exceeded SLA budget."));
        if (BreachOf("Contain"))
            reasons.Add(new IncidentReason("CONTAINMENT_LATE", 70, "Containment stage exceeded SLA budget."));
        if (BreachOf("Resolve"))
            reasons.Add(new IncidentReason("RESOLUTION_LATE", 70, "Resolution stage exceeded SLA budget."));
        if (inc.RequiredVendorEscalation && anyBreach)
            reasons.Add(new IncidentReason("VENDOR_DELAY", 50, "Vendor escalation coincided with SLA breach."));
        if (inc.RequiredManualRunbook && anyBreach)
            reasons.Add(new IncidentReason("MANUAL_RUNBOOK_DRAG", 45, "Manual runbook execution coincided with SLA breach."));
        if (inc.ReopenCount >= 2)
            reasons.Add(new IncidentReason("REPEAT_REOPEN", 75, $"Incident reopened {inc.ReopenCount} times."));
        if ((verdict == IncidentVerdict.MajorMiss || verdict == IncidentVerdict.CriticalMiss) && !inc.PostmortemCompleted)
            reasons.Add(new IncidentReason("MISSING_POSTMORTEM", 30, "Major/critical miss without completed postmortem."));
        int h = inc.DetectedAt.ToUniversalTime().Hour;
        if ((h >= 22 || h < 6) && anyBreach)
            reasons.Add(new IncidentReason("OFF_HOURS_DETECTION", 20, "Detected outside business hours and breached SLA."));
        var dow = inc.DetectedAt.ToUniversalTime().DayOfWeek;
        if ((dow == DayOfWeek.Saturday || dow == DayOfWeek.Sunday) && anyBreach)
            reasons.Add(new IncidentReason("WEEKEND_DETECTION", 20, "Detected on a weekend and breached SLA."));

        return reasons
            .GroupBy(r => r.Code).Select(g => g.First())
            .OrderByDescending(r => r.Weight)
            .ThenBy(r => r.Code, StringComparer.Ordinal)
            .ToList();
    }

    private static PortfolioSummary BuildSummary(List<IncidentAssessment> assessments)
    {
        int total = assessments.Count;
        double? Mean(Func<IncidentAssessment, double?> sel)
        {
            var vals = assessments.Select(sel).Where(v => v.HasValue).Select(v => v!.Value).ToList();
            return vals.Count == 0 ? (double?)null : vals.Average();
        }
        int onTrack = assessments.Count(a => a.Verdict == IncidentVerdict.OnTrack);
        int atRisk = assessments.Count(a => a.Verdict == IncidentVerdict.AtRisk);
        int minor = assessments.Count(a => a.Verdict == IncidentVerdict.MinorMiss);
        int major = assessments.Count(a => a.Verdict == IncidentVerdict.MajorMiss);
        int critical = assessments.Count(a => a.Verdict == IncidentVerdict.CriticalMiss);

        double breachRate = total == 0 ? 0.0 : (double)(minor + major + critical) / total;
        var sev1 = assessments.Where(a => a.Severity == IncidentSeverity.Sev1).ToList();
        int sev1Breach = sev1.Count(a => a.Verdict == IncidentVerdict.MinorMiss || a.Verdict == IncidentVerdict.MajorMiss || a.Verdict == IncidentVerdict.CriticalMiss);
        double sev1Rate = sev1.Count == 0 ? 0.0 : (double)sev1Breach / sev1.Count;

        return new PortfolioSummary(
            total,
            Mean(a => a.AckMinutes),
            Mean(a => a.ContainMinutes),
            Mean(a => a.ResolveMinutes),
            breachRate,
            sev1Rate,
            onTrack, minor, major, critical, atRisk);
    }

    private static (int score, string grade, PortfolioVerdict verdict) BuildGrade(
        PortfolioSummary s, List<IncidentAssessment> assessments, SlaContext ctx)
    {
        int score = 100 - (s.CriticalMissCount * 25 + s.MajorMissCount * 15 + s.MinorMissCount * 5 + s.AtRiskCount * 3);
        score = Math.Max(0, Math.Min(100, score));
        if (ctx.RiskAppetite == RiskAppetite.Cautious) score -= 8;
        else if (ctx.RiskAppetite == RiskAppetite.Aggressive) score += 8;
        if (ctx.RegulatedDomain) score -= 5;
        score = Math.Max(0, Math.Min(100, score));

        string grade = score >= 85 ? "A" : score >= 70 ? "B" : score >= 55 ? "C" : score >= 40 ? "D" : "F";

        bool forceF = s.Sev1BreachRate >= 0.25 ||
            assessments.Any(a => a.Severity == IncidentSeverity.Sev1 && a.Verdict == IncidentVerdict.CriticalMiss);
        if (forceF) grade = "F";

        PortfolioVerdict v = grade switch
        {
            "A" => PortfolioVerdict.Excellent,
            "B" => PortfolioVerdict.Healthy,
            "C" => PortfolioVerdict.Strained,
            "D" => PortfolioVerdict.Failing,
            _ => PortfolioVerdict.Crisis,
        };
        return (score, grade, v);
    }

    private static List<PlaybookAction> BuildPlaybook(
        List<IncidentAssessment> assessments,
        PortfolioSummary summary,
        SlaContext ctx,
        string grade,
        PortfolioVerdict pVerdict,
        Dictionary<IncidentSeverity, SlaBudget> budgets)
    {
        var actions = new List<PlaybookAction>();
        void Add(string id, string priority, string label, string owner, int blast, string rev, string reason, IEnumerable<string> targets, double? sv = null)
        {
            if (actions.Any(a => a.Id == id)) return;
            actions.Add(new PlaybookAction(id, priority, label, owner, blast, rev, reason,
                targets.OrderBy(x => x, StringComparer.Ordinal).ToList(), sv));
        }

        // Helpers
        IEnumerable<string> WithReason(string code) =>
            assessments.Where(a => a.Reasons.Any(r => r.Code == code)).Select(a => a.Id);

        var sev1Critical = assessments.Where(a =>
            a.Severity == IncidentSeverity.Sev1 && a.Verdict == IncidentVerdict.CriticalMiss).Select(a => a.Id).ToList();
        var anyMajorOrCritical = assessments.Where(a =>
            a.Verdict == IncidentVerdict.MajorMiss || a.Verdict == IncidentVerdict.CriticalMiss).Select(a => a.Id).ToList();

        // P0 EMERGENCY_IR_REVIEW
        if (pVerdict == PortfolioVerdict.Crisis || sev1Critical.Count >= 2)
        {
            var targets = pVerdict == PortfolioVerdict.Crisis
                ? assessments.Select(a => a.Id)
                : sev1Critical;
            Add("EMERGENCY_IR_REVIEW", "P0",
                "Open emergency IR program review",
                "incident_commander", 5, "low",
                pVerdict == PortfolioVerdict.Crisis
                    ? "Portfolio is in crisis (grade F)."
                    : $"{sev1Critical.Count} Sev1 critical misses observed.",
                targets);
        }

        // P0 EXPAND_ONCALL_ROSTER
        if (ctx.OnCallRosterSize.HasValue && ctx.OnCallRosterSize.Value <= 2 && anyMajorOrCritical.Count > 0)
        {
            Add("EXPAND_ONCALL_ROSTER", "P0",
                "Expand on-call roster",
                "ops", 4, "high",
                $"Roster size {ctx.OnCallRosterSize.Value} with major/critical misses present.",
                anyMajorOrCritical,
                ctx.OnCallRosterSize.Value + 1);
        }

        // P0 ROOT_CAUSE_REPEAT_INCIDENTS
        var reopens = WithReason("REPEAT_REOPEN").ToList();
        if (reopens.Count > 0)
        {
            Add("ROOT_CAUSE_REPEAT_INCIDENTS", "P0",
                "Root-cause repeatedly reopened incidents",
                "engineering", 3, "medium",
                $"{reopens.Count} incident(s) reopened >=2 times.",
                reopens);
        }

        // P1 AUTOMATE_RUNBOOK
        var manualDrag = WithReason("MANUAL_RUNBOOK_DRAG").ToList();
        if (manualDrag.Count >= 2)
        {
            Add("AUTOMATE_RUNBOOK", "P1",
                "Automate manual runbook steps",
                "automation", 3, "high",
                $"{manualDrag.Count} incidents tagged with manual-runbook drag.",
                manualDrag);
        }

        // P1 ESCALATE_VENDOR_SLA
        var vendor = WithReason("VENDOR_DELAY").ToList();
        if (vendor.Count >= 2)
        {
            Add("ESCALATE_VENDOR_SLA", "P1",
                "Escalate vendor SLA terms",
                "procurement", 2, "medium",
                $"{vendor.Count} incidents delayed by vendor escalation.",
                vendor);
        }

        // P1 TIGHTEN_ACK_PAGER_ROTATION
        double sev2AckBudget = budgets[IncidentSeverity.Sev2].AckWithin.TotalMinutes;
        if (summary.MeanAckMinutes.HasValue && summary.MeanAckMinutes.Value > 0.6 * sev2AckBudget)
        {
            Add("TIGHTEN_ACK_PAGER_ROTATION", "P1",
                "Tighten ack pager rotation",
                "soc_lead", 2, "high",
                $"Mean ack {summary.MeanAckMinutes.Value:F1}m exceeds 60% of Sev2 ack budget ({sev2AckBudget:F0}m).",
                assessments.Where(a => a.AckMinutes.HasValue).Select(a => a.Id));
        }

        // P2 BACKFILL_POSTMORTEMS
        var p0p1Missing = assessments
            .Where(a => (a.Priority == "P0" || a.Priority == "P1") &&
                        a.Reasons.Any(r => r.Code == "MISSING_POSTMORTEM"))
            .Select(a => a.Id).ToList();
        if (p0p1Missing.Count >= 2)
        {
            Add("BACKFILL_POSTMORTEMS", "P2",
                "Backfill missing postmortems",
                "team_lead", 1, "high",
                $"{p0p1Missing.Count} P0/P1 incidents missing postmortems.",
                p0p1Missing);
        }

        // P2 ADD_OFF_HOURS_COVERAGE
        var offTargets = assessments
            .Where(a => a.Reasons.Any(r => r.Code == "OFF_HOURS_DETECTION" || r.Code == "WEEKEND_DETECTION"))
            .Select(a => a.Id).ToList();
        int offHoursCount = assessments.Sum(a => a.Reasons.Count(r => r.Code == "OFF_HOURS_DETECTION" || r.Code == "WEEKEND_DETECTION"));
        if (offHoursCount >= 2)
        {
            Add("ADD_OFF_HOURS_COVERAGE", "P2",
                "Add off-hours / weekend coverage",
                "ops", 3, "medium",
                $"{offHoursCount} off-hours/weekend detections coincided with breaches.",
                offTargets);
        }

        // P2 RENEGOTIATE_SEV_BUDGETS
        var breached = assessments.Where(a => a.Verdict == IncidentVerdict.MinorMiss || a.Verdict == IncidentVerdict.MajorMiss || a.Verdict == IncidentVerdict.CriticalMiss).ToList();
        if (!ctx.RegulatedDomain && breached.Count > 0)
        {
            var minorOnly = breached.Where(b => b.Verdict == IncidentVerdict.MinorMiss).ToList();
            if ((double)minorOnly.Count / breached.Count >= 0.50)
            {
                Add("RENEGOTIATE_SEV_BUDGETS", "P2",
                    "Renegotiate per-severity SLA budgets",
                    "leadership", 2, "medium",
                    $"{minorOnly.Count}/{breached.Count} breaches were minor-only.",
                    minorOnly.Select(a => a.Id));
            }
        }

        // P3 SLA_COMPLIANCE_HEALTHY - fallback
        if (actions.Count == 0 && (grade == "A" || grade == "B"))
        {
            Add("SLA_COMPLIANCE_HEALTHY", "P3",
                "IR SLA compliance is healthy",
                "team_lead", 1, "high",
                "No corrective actions needed; portfolio is healthy.",
                Array.Empty<string>());
        }

        // Cautious extra
        if (ctx.RiskAppetite == RiskAppetite.Cautious &&
            (grade == "C" || grade == "D" || grade == "F") &&
            !actions.Any(a => a.Id == "SCHEDULE_QUARTERLY_IR_AUDIT"))
        {
            Add("SCHEDULE_QUARTERLY_IR_AUDIT", "P2",
                "Schedule quarterly IR program audit",
                "leadership", 1, "high",
                $"Cautious appetite with grade {grade}; schedule audit cadence.",
                Array.Empty<string>());
        }

        // Aggressive trimming
        if (ctx.RiskAppetite == RiskAppetite.Aggressive)
        {
            bool anyP0P1 = actions.Any(a => a.Priority == "P0" || a.Priority == "P1");
            if (anyP0P1)
            {
                actions.RemoveAll(a => a.Priority == "P3");
                int p2 = actions.Count(a => a.Priority == "P2");
                if (p2 == 1) actions.RemoveAll(a => a.Priority == "P2");
            }
        }

        // Dedupe + sort.
        return actions
            .GroupBy(a => a.Id).Select(g => g.First())
            .OrderBy(a => PriorityRank(a.Priority))
            .ThenBy(a => a.Id, StringComparer.Ordinal)
            .ToList();
    }

    private static List<string> BuildInsights(
        List<IncidentAssessment> assessments,
        PortfolioSummary summary,
        SlaContext ctx,
        string grade,
        List<PlaybookAction> playbook,
        List<IncidentRecord> rawIncidents)
    {
        var rawById = rawIncidents.ToDictionary(r => r.Id, r => r);
        var insights = new List<string>();
        var breached = assessments.Where(a => a.Verdict == IncidentVerdict.MinorMiss || a.Verdict == IncidentVerdict.MajorMiss || a.Verdict == IncidentVerdict.CriticalMiss).ToList();
        int breachCount = breached.Count;

        int sev1Breach = assessments.Count(a => a.Severity == IncidentSeverity.Sev1 &&
            (a.Verdict == IncidentVerdict.MinorMiss || a.Verdict == IncidentVerdict.MajorMiss || a.Verdict == IncidentVerdict.CriticalMiss));
        if (sev1Breach >= 2)
            insights.Add($"SEV1_BREACH_CLUSTER: {sev1Breach} Sev1 incidents breached SLA");

        int reopenCount = rawIncidents.Count(r => r.ReopenCount >= 1);
        if (reopenCount >= 2)
            insights.Add($"CHRONIC_REOPEN_PATTERN: {reopenCount} incidents reopened repeatedly");

        if (breachCount >= 1)
        {
            int vendor = breached.Count(b => b.Reasons.Any(r => r.Code == "VENDOR_DELAY"));
            if ((double)vendor / breachCount >= 0.50)
                insights.Add($"VENDOR_BOTTLENECK: {vendor}/{breachCount} breaches involved vendor delay");

            int manual = breached.Count(b => b.Reasons.Any(r => r.Code == "MANUAL_RUNBOOK_DRAG"));
            if ((double)manual / breachCount >= 0.50)
                insights.Add($"MANUAL_PROCESS_DRAG: {manual}/{breachCount} breaches involved manual runbook drag");

            int offHours = breached.Count(b => b.Reasons.Any(r => r.Code == "OFF_HOURS_DETECTION" || r.Code == "WEEKEND_DETECTION"));
            if ((double)offHours / breachCount >= 0.50)
                insights.Add($"OFF_HOURS_GAP: {offHours}/{breachCount} breaches detected off-hours/weekend");
        }

        var p0p1 = assessments.Where(a => a.Priority == "P0" || a.Priority == "P1").ToList();
        if (p0p1.Count >= 2)
        {
            int completed = p0p1.Count(a => rawById.TryGetValue(a.Id, out var raw) && raw.PostmortemCompleted);
            if ((double)completed / p0p1.Count < 0.50)
                insights.Add($"POSTMORTEM_DEBT: only {completed}/{p0p1.Count} P0/P1 incidents have completed postmortems");
        }

        if (ctx.RegulatedDomain && (grade == "C" || grade == "D" || grade == "F"))
            insights.Add($"REGULATED_AT_RISK: regulated domain operating at grade {grade}");

        if (insights.Count == 0 && (grade == "A" || grade == "B"))
            insights.Add($"HEALTHY_IR_PROGRAM: IR portfolio operating at grade {grade}");

        return insights;
    }
}
