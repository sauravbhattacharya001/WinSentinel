using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Core.Services;

/// <summary>
/// Agentic policy-exception risk advisor.
/// <para>
/// Scores currently-granted security policy exceptions (a.k.a. risk acceptances /
/// waivers) for staleness, ownership gaps, drift, and accumulated exposure, then
/// emits a P0-first remediation playbook.
/// </para>
/// <para>
/// Fifth sibling in the agentic services suite alongside
/// <see cref="FixOrchestrationPlanner"/>, <see cref="AlertRoutingAdvisor"/>,
/// <see cref="AttackerProfileSynthesizer"/> and
/// <see cref="PostureRegressionExplainer"/>. It answers
/// <em>which active risk acceptances should we revoke or re-review first?</em>
/// </para>
/// <para>
/// Pure / deterministic — no I/O. Inject time via
/// <see cref="AdvisorContext.NowOverride"/> for reproducible tests.
/// Never mutates inputs.
/// </para>
/// </summary>
public class PolicyExceptionRiskAdvisor
{
    // ── Public model ─────────────────────────────────────────────

    /// <summary>Severity of an underlying finding when the exception was granted.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum FindingSeverity { Low, Medium, High, Critical }

    /// <summary>How aggressively the advisor recommends action.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum RiskAppetite { Cautious, Balanced, Aggressive }

    /// <summary>Action / assessment priority bucket.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ActionPriority { P0, P1, P2, P3 }

    /// <summary>Per-exception advisor verdict.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ExceptionVerdict
    {
        RevokeNow,
        ExpireAsScheduled,
        ExtendWithReview,
        RequiresReview,
        MissingOwner,
        Keep,
    }

    /// <summary>A granted policy exception / risk acceptance.</summary>
    public record PolicyException(
        string Id,
        string PolicyId,
        string Category,
        DateTime GrantedAt,
        DateTime? ExpiresAt,
        FindingSeverity SeverityAtGrant,
        string Justification,
        string GrantedBy,
        string? Owner,
        DateTime? LastReviewedAt,
        IReadOnlyList<string> RelatedFindingIds);

    /// <summary>Caller-supplied context.</summary>
    public class AdvisorContext
    {
        public RiskAppetite Risk { get; set; } = RiskAppetite.Balanced;
        public DateTime? NowOverride { get; set; }
        /// <summary>Review cadence used to detect stale reviews (default 90 days).</summary>
        public int ReviewCadenceDays { get; set; } = 90;
    }

    /// <summary>Per-exception assessment.</summary>
    public record ExceptionAssessment(
        string Id,
        string PolicyId,
        string Category,
        int RiskScore,
        ExceptionVerdict Verdict,
        ActionPriority Priority,
        IReadOnlyList<string> Reasons,
        string Owner,
        int AgeDays,
        int? DaysToExpiry);

    /// <summary>Cross-portfolio playbook action.</summary>
    public record PlaybookAction(
        string Id,
        ActionPriority Priority,
        string Label,
        string Owner,
        int BlastRadius,
        string Reversibility,
        string Reason,
        IReadOnlyList<string> RelatedExceptionIds);

    /// <summary>Full report returned to the caller.</summary>
    public record PolicyExceptionRiskReport(
        DateTime GeneratedAt,
        int TotalExceptions,
        int RevokeNowCount,
        int RequiresReviewCount,
        double MeanRiskScore,
        double MaxRiskScore,
        string Verdict,
        string Grade,
        IReadOnlyList<ExceptionAssessment> Assessments,
        IReadOnlyList<PlaybookAction> Playbook,
        IReadOnlyList<string> Insights);

    // ── Public API ───────────────────────────────────────────────

    public PolicyExceptionRiskReport Analyze(
        IEnumerable<PolicyException> exceptions,
        AdvisorContext? ctx = null)
    {
        if (exceptions is null) throw new ArgumentNullException(nameof(exceptions));
        ctx ??= new AdvisorContext();
        var list = exceptions.ToList();
        var now = ctx.NowOverride ?? DateTime.UtcNow;
        int cadence = Math.Max(1, ctx.ReviewCadenceDays);
        int sevShift = ctx.Risk switch
        {
            RiskAppetite.Cautious => +5,
            RiskAppetite.Aggressive => -5,
            _ => 0,
        };

        var assessments = new List<ExceptionAssessment>();
        int expiredCount = 0;
        int unownedCount = 0;
        int staleCount = 0;
        int indefiniteHighSevCount = 0;
        int thinJustificationCount = 0;
        int driftElevatedCount = 0;
        bool anyExpiredHighSev = false;

        foreach (var ex in list)
        {
            var reasons = new List<string>();
            int score = 0;

            // Base severity
            int sevBase = ex.SeverityAtGrant switch
            {
                FindingSeverity.Low => 10,
                FindingSeverity.Medium => 25,
                FindingSeverity.High => 50,
                FindingSeverity.Critical => 75,
                _ => 10,
            };
            score += sevBase;

            // Age
            int ageDays = Math.Max(0, (int)Math.Floor((now - ex.GrantedAt).TotalDays));
            int ageBoost = Math.Min(25, ageDays / 30);
            score += ageBoost;
            if (ageDays >= 180) reasons.Add("AGED_GRANT");

            // Stale review
            bool ownerMissing = string.IsNullOrWhiteSpace(ex.Owner);
            bool staleReview = !ex.LastReviewedAt.HasValue ||
                (now - ex.LastReviewedAt.Value).TotalDays > cadence;
            if (staleReview)
            {
                score += 20;
                reasons.Add("STALE_REVIEW");
                staleCount++;
            }

            // Expiry signals
            bool expired = ex.ExpiresAt.HasValue && ex.ExpiresAt.Value < now;
            bool expiringSoon = ex.ExpiresAt.HasValue && !expired &&
                (ex.ExpiresAt.Value - now).TotalDays <= 14;
            int? daysToExpiry = ex.ExpiresAt.HasValue
                ? (int)Math.Ceiling((ex.ExpiresAt.Value - now).TotalDays)
                : (int?)null;

            if (expired)
            {
                score += 30;
                reasons.Add("EXPIRED");
                expiredCount++;
                if (ex.SeverityAtGrant >= FindingSeverity.High)
                    anyExpiredHighSev = true;
            }
            else if (expiringSoon)
            {
                score += 10;
                reasons.Add("EXPIRING_SOON");
            }

            // Indefinite waiver penalty
            bool indefiniteHigh = !ex.ExpiresAt.HasValue &&
                ex.SeverityAtGrant >= FindingSeverity.High;
            if (indefiniteHigh)
            {
                score += 15;
                reasons.Add("INDEFINITE_WAIVER_HIGH_SEV");
                indefiniteHighSevCount++;
            }

            // Drift penalty
            int relatedCount = ex.RelatedFindingIds?.Count ?? 0;
            if (relatedCount >= 3)
            {
                score += 10;
                reasons.Add("DRIFT_COUNT_ELEVATED");
                driftElevatedCount++;
            }

            // Unowned
            if (ownerMissing)
            {
                score += 15;
                reasons.Add("OWNER_MISSING");
                unownedCount++;
            }

            // Thin justification
            var justification = ex.Justification ?? string.Empty;
            if (justification.Length < 40)
            {
                score += 10;
                reasons.Add("THIN_JUSTIFICATION");
                thinJustificationCount++;
            }

            // Risk-appetite shift
            score += sevShift;
            score = Math.Max(0, Math.Min(100, score));

            // Verdict mapping (order matters)
            ExceptionVerdict verdict;
            if (expired)
            {
                verdict = ExceptionVerdict.RevokeNow;
            }
            else if (ex.SeverityAtGrant >= FindingSeverity.High && expiringSoon && score >= 70)
            {
                verdict = ExceptionVerdict.RevokeNow;
            }
            else if (ownerMissing)
            {
                verdict = ExceptionVerdict.MissingOwner;
            }
            else if (staleReview && score >= 50)
            {
                verdict = ExceptionVerdict.RequiresReview;
            }
            else if (expiringSoon)
            {
                verdict = ExceptionVerdict.ExpireAsScheduled;
            }
            else if (ex.SeverityAtGrant >= FindingSeverity.High && !ex.ExpiresAt.HasValue)
            {
                verdict = ExceptionVerdict.ExtendWithReview;
            }
            else
            {
                verdict = ExceptionVerdict.Keep;
            }

            // Priority
            ActionPriority priority = verdict switch
            {
                ExceptionVerdict.RevokeNow => ActionPriority.P0,
                ExceptionVerdict.MissingOwner =>
                    score >= 75 ? ActionPriority.P0 :
                    score >= 55 ? ActionPriority.P1 : ActionPriority.P1,
                ExceptionVerdict.RequiresReview =>
                    score >= 75 ? ActionPriority.P0 : ActionPriority.P1,
                ExceptionVerdict.ExtendWithReview =>
                    score >= 75 ? ActionPriority.P0 : ActionPriority.P1,
                ExceptionVerdict.ExpireAsScheduled =>
                    score >= 55 ? ActionPriority.P1 : ActionPriority.P2,
                ExceptionVerdict.Keep =>
                    score >= 75 ? ActionPriority.P0 :
                    score >= 55 ? ActionPriority.P1 :
                    score >= 30 ? ActionPriority.P2 : ActionPriority.P3,
                _ => ActionPriority.P3,
            };

            assessments.Add(new ExceptionAssessment(
                ex.Id,
                ex.PolicyId,
                ex.Category,
                score,
                verdict,
                priority,
                reasons,
                ownerMissing ? "(unowned)" : ex.Owner!,
                ageDays,
                daysToExpiry));
        }

        // Aggregates
        int total = assessments.Count;
        int revokeNow = assessments.Count(a => a.Verdict == ExceptionVerdict.RevokeNow);
        int requiresReview = assessments.Count(a => a.Verdict == ExceptionVerdict.RequiresReview);
        double mean = total == 0 ? 0.0 : assessments.Average(a => (double)a.RiskScore);
        double max = total == 0 ? 0.0 : assessments.Max(a => (double)a.RiskScore);

        // Verdict band
        string portfolioVerdict =
            mean < 20 ? "HEALTHY" :
            mean < 35 ? "WATCH" :
            mean < 55 ? "ELEVATED_EXCEPTION_RISK" :
            mean < 75 ? "HIGH_EXCEPTION_DEBT" :
            "CRITICAL_EXCEPTION_DEBT";

        // Grade
        string grade =
            mean < 20 ? "A" :
            mean < 35 ? "B" :
            mean < 55 ? "C" :
            mean < 75 ? "D" :
            "F";
        if (anyExpiredHighSev) grade = "F";

        // Insights
        var insights = new List<string>();
        if (expiredCount >= 2) insights.Add($"MANY_EXPIRED: {expiredCount} expired exceptions");
        if (total > 0 && (double)unownedCount / total >= 0.20)
            insights.Add($"OWNERSHIP_GAP: {unownedCount}/{total} unowned");
        if (total > 0 && (double)indefiniteHighSevCount / total >= 0.30)
            insights.Add($"INDEFINITE_HEAVY: {indefiniteHighSevCount}/{total} indefinite high-severity");
        if (total > 0 && (double)staleCount / total >= 0.50)
            insights.Add($"REVIEW_DEBT: {staleCount}/{total} stale reviews");
        if (total > 0 && mean < 20) insights.Add("LOW_RISK_PORTFOLIO");

        // Playbook
        var playbook = new List<PlaybookAction>();
        void Add(string id, ActionPriority p, string label, string owner, int blast, string rev, string reason, IEnumerable<string> ids)
        {
            if (playbook.Any(a => a.Id == id)) return;
            playbook.Add(new PlaybookAction(id, p, label, owner, blast, rev, reason, ids.Distinct().ToList()));
        }

        var expiredIds = assessments.Where(a => a.Reasons.Contains("EXPIRED")).Select(a => a.Id).ToList();
        if (expiredIds.Count > 0)
            Add("REVOKE_EXPIRED_BATCH", ActionPriority.P0,
                "Revoke expired exceptions",
                "security_eng", 4, "low",
                $"{expiredIds.Count} exception(s) past their expiration date — revoke and re-triage underlying findings.",
                expiredIds);

        var unownedIds = assessments.Where(a => a.Reasons.Contains("OWNER_MISSING")).Select(a => a.Id).ToList();
        if (unownedIds.Count >= 2)
            Add("ASSIGN_OWNERS_BATCH", ActionPriority.P0,
                "Assign accountable owners to unowned exceptions",
                "security_governance", 3, "high",
                $"{unownedIds.Count} unowned exceptions — assign accountable owners.",
                unownedIds);

        var highRiskIds = assessments.Where(a => a.RiskScore >= 80).Select(a => a.Id).ToList();
        if (highRiskIds.Count > 0)
            Add("EMERGENCY_REVIEW_HIGH_RISK", ActionPriority.P0,
                "Emergency review of highest-risk exceptions",
                "ciso_office", 5, "medium",
                $"{highRiskIds.Count} exception(s) scored >=80; review and decide revoke / mitigate.",
                highRiskIds);

        var staleIds = assessments.Where(a => a.Reasons.Contains("STALE_REVIEW")).Select(a => a.Id).ToList();
        bool addQuarterlyByCount = staleIds.Count >= 3;
        bool addQuarterlyByCautious = ctx.Risk == RiskAppetite.Cautious && staleIds.Count >= 1;
        if (addQuarterlyByCount || addQuarterlyByCautious)
            Add("SCHEDULE_QUARTERLY_REVIEW_BATCH", ActionPriority.P1,
                "Schedule quarterly review of stale exceptions",
                "security_governance", 2, "high",
                $"{staleIds.Count} exception(s) overdue for review — schedule a quarterly batch review.",
                staleIds);

        var indefIds = assessments.Where(a => a.Reasons.Contains("INDEFINITE_WAIVER_HIGH_SEV")).Select(a => a.Id).ToList();
        if (indefIds.Count >= 2)
            Add("REVISIT_INDEFINITE_WAIVERS", ActionPriority.P1,
                "Revisit indefinite high-severity waivers",
                "security_eng", 3, "medium",
                $"{indefIds.Count} indefinite waivers on high/critical findings — add expiration or revoke.",
                indefIds);

        var thinIds = assessments.Where(a => a.Reasons.Contains("THIN_JUSTIFICATION")).Select(a => a.Id).ToList();
        if (thinIds.Count >= 3)
            Add("TIGHTEN_JUSTIFICATION_TEMPLATE", ActionPriority.P2,
                "Tighten exception-request justification template",
                "security_governance", 2, "high",
                $"{thinIds.Count} exceptions have thin justifications (<40 chars) — improve request template.",
                thinIds);

        var driftIds = assessments.Where(a => a.Reasons.Contains("DRIFT_COUNT_ELEVATED")).Select(a => a.Id).ToList();
        if (driftIds.Count >= 2)
            Add("CLEAN_DRIFTED_EXCEPTIONS", ActionPriority.P2,
                "Clean up drifted exceptions",
                "security_eng", 2, "high",
                $"{driftIds.Count} exception(s) now cover 3+ related findings — split or revoke.",
                driftIds);

        if (playbook.Count == 0)
            Add("HEALTHY_POSTURE", ActionPriority.P3,
                "Exception portfolio is healthy — maintain rhythm",
                "security_governance", 1, "high",
                "No P0/P1/P2 conditions detected.",
                Array.Empty<string>());

        // Aggressive: drop P3 + standalone P2 when P0/P1 present.
        if (ctx.Risk == RiskAppetite.Aggressive)
        {
            bool hasP0OrP1 = playbook.Any(a => a.Priority == ActionPriority.P0 || a.Priority == ActionPriority.P1);
            if (hasP0OrP1)
            {
                playbook.RemoveAll(a => a.Priority == ActionPriority.P3);
                playbook.RemoveAll(a => a.Priority == ActionPriority.P2);
            }
        }

        playbook = playbook
            .OrderBy(a => (int)a.Priority)
            .ThenBy(a => a.Id, StringComparer.Ordinal)
            .ToList();

        var assessmentsOut = assessments
            .OrderBy(a => (int)a.Priority)
            .ThenByDescending(a => a.RiskScore)
            .ThenBy(a => a.Id, StringComparer.Ordinal)
            .ToList();

        return new PolicyExceptionRiskReport(
            now,
            total,
            revokeNow,
            requiresReview,
            Math.Round(mean, 2),
            Math.Round(max, 2),
            portfolioVerdict,
            grade,
            assessmentsOut,
            playbook,
            insights);
    }

    // ── Renderers ─────────────────────────────────────────────────

    public static string Render(PolicyExceptionRiskReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Policy exception risk report  generated {r.GeneratedAt:O}");
        sb.AppendLine($"Verdict: {r.Verdict}  Grade: {r.Grade}");
        sb.AppendLine($"Exceptions: {r.TotalExceptions}  (revoke-now {r.RevokeNowCount}, requires-review {r.RequiresReviewCount})");
        sb.AppendLine($"Risk score: mean {r.MeanRiskScore:0.##}  max {r.MaxRiskScore:0.##}");
        sb.AppendLine();
        sb.AppendLine($"Assessments ({r.Assessments.Count}):");
        foreach (var a in r.Assessments)
        {
            var exp = a.DaysToExpiry.HasValue
                ? (a.DaysToExpiry.Value < 0
                    ? $"expired {-a.DaysToExpiry.Value}d ago"
                    : $"expires in {a.DaysToExpiry.Value}d")
                : "indefinite";
            sb.AppendLine($"  [{a.Priority}] {a.Id} ({a.Category}) score={a.RiskScore} verdict={a.Verdict} owner={a.Owner} age={a.AgeDays}d {exp}");
            if (a.Reasons.Count > 0)
                sb.AppendLine($"      reasons: {string.Join(", ", a.Reasons)}");
        }
        sb.AppendLine();
        sb.AppendLine($"Playbook ({r.Playbook.Count}):");
        foreach (var p in r.Playbook)
            sb.AppendLine($"  [{p.Priority}] {p.Id} -> {p.Label} (owner={p.Owner}, blast={p.BlastRadius}, rev={p.Reversibility})");
        sb.AppendLine();
        sb.AppendLine($"Insights ({r.Insights.Count}):");
        foreach (var i in r.Insights) sb.AppendLine($"  - {i}");
        return sb.ToString();
    }

    public static string RenderMarkdown(PolicyExceptionRiskReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine("## Summary");
        sb.AppendLine();
        sb.AppendLine($"- Verdict: **{r.Verdict}**  (grade **{r.Grade}**)");
        sb.AppendLine($"- Exceptions: {r.TotalExceptions} (revoke-now {r.RevokeNowCount}, requires-review {r.RequiresReviewCount})");
        sb.AppendLine($"- Mean risk: {r.MeanRiskScore:0.##}  /  Max risk: {r.MaxRiskScore:0.##}");
        sb.AppendLine($"- Generated: {r.GeneratedAt:O}");
        sb.AppendLine();
        sb.AppendLine("## Assessments");
        sb.AppendLine();
        sb.AppendLine("| Priority | Id | Category | Score | Verdict | Owner |");
        sb.AppendLine("|----------|----|----------|-------|---------|-------|");
        foreach (var a in r.Assessments)
            sb.AppendLine($"| {a.Priority} | {a.Id} | {a.Category} | {a.RiskScore} | {a.Verdict} | {a.Owner} |");
        sb.AppendLine();
        sb.AppendLine("## Playbook");
        sb.AppendLine();
        if (r.Playbook.Count == 0) sb.AppendLine("- _none_");
        else foreach (var p in r.Playbook)
            sb.AppendLine($"- **[{p.Priority}] {p.Id}** — {p.Label} _(owner {p.Owner}, blast {p.BlastRadius}, reversibility {p.Reversibility})_  ");
        sb.AppendLine();
        sb.AppendLine("## Insights");
        sb.AppendLine();
        if (r.Insights.Count == 0) sb.AppendLine("- _none_");
        else foreach (var i in r.Insights) sb.AppendLine($"- {i}");
        return sb.ToString();
    }

    public static string RenderJson(PolicyExceptionRiskReport r)
    {
        var opts = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() },
        };
        return JsonSerializer.Serialize(r, opts);
    }
}
