using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Reviews ignore/exemption rules for staleness, upcoming expiration,
/// recent expiration, and utilization against current findings.
///
/// Helps security operators maintain rule hygiene by answering:
/// - Which exemptions are about to expire and need renewal decisions?
/// - Which exemptions recently expired and may need re-evaluation?
/// - Which exemptions are stale (old, never-expiring) and should be reviewed?
/// - Which exemptions never match any current findings (dead rules)?
/// </summary>
public class ExemptionReviewService
{
    // ── Result types ─────────────────────────────────────────────────

    /// <summary>Classification of an exemption's review status.</summary>
    public enum ReviewStatus
    {
        /// <summary>Rule is active and not due for review.</summary>
        Current,

        /// <summary>Rule expires within the review window.</summary>
        ExpiringSoon,

        /// <summary>Rule has already expired.</summary>
        RecentlyExpired,

        /// <summary>Rule is old with no expiration — needs periodic review.</summary>
        Stale,

        /// <summary>Rule doesn't match any current findings.</summary>
        Unused,

        /// <summary>Rule is disabled.</summary>
        Disabled
    }

    /// <summary>An ignore rule annotated with review metadata.</summary>
    public class ReviewedRule
    {
        /// <summary>The underlying ignore rule.</summary>
        public required IgnoreRule Rule { get; init; }

        /// <summary>Review classification.</summary>
        public ReviewStatus Status { get; init; }

        /// <summary>Days until expiration (negative = already expired).</summary>
        public int? DaysUntilExpiry { get; init; }

        /// <summary>Age of the rule in days since creation.</summary>
        public int AgeDays { get; init; }

        /// <summary>Number of current findings this rule matches.</summary>
        public int MatchCount { get; init; }

        /// <summary>Human-readable recommendation.</summary>
        public string Recommendation { get; init; } = string.Empty;
    }

    /// <summary>Summary statistics for the exemption review.</summary>
    public class ReviewSummary
    {
        /// <summary>Total number of ignore rules.</summary>
        public int TotalRules { get; init; }

        /// <summary>Number of active (enabled + not expired) rules.</summary>
        public int ActiveRules { get; init; }

        /// <summary>Number of rules expiring within the review window.</summary>
        public int ExpiringSoon { get; init; }

        /// <summary>Number of recently expired rules.</summary>
        public int RecentlyExpired { get; init; }

        /// <summary>Number of stale rules needing review.</summary>
        public int StaleRules { get; init; }

        /// <summary>Number of unused rules (no current matches).</summary>
        public int UnusedRules { get; init; }

        /// <summary>Number of disabled rules.</summary>
        public int DisabledRules { get; init; }

        /// <summary>Overall health: percentage of rules that are current and used.</summary>
        public double HealthScore { get; init; }

        /// <summary>Overall health grade (A-F).</summary>
        public string HealthGrade { get; init; } = "N/A";
    }

    /// <summary>Full exemption review result.</summary>
    public class ReviewResult
    {
        /// <summary>All reviewed rules.</summary>
        public List<ReviewedRule> Rules { get; init; } = new();

        /// <summary>Rules expiring soon (sorted by days until expiry).</summary>
        public List<ReviewedRule> ExpiringSoon { get; init; } = new();

        /// <summary>Recently expired rules (sorted by most recently expired first).</summary>
        public List<ReviewedRule> RecentlyExpired { get; init; } = new();

        /// <summary>Stale rules (sorted by age, oldest first).</summary>
        public List<ReviewedRule> Stale { get; init; } = new();

        /// <summary>Unused rules that don't match any current findings.</summary>
        public List<ReviewedRule> Unused { get; init; } = new();

        /// <summary>Disabled rules.</summary>
        public List<ReviewedRule> Disabled { get; init; } = new();

        /// <summary>Summary statistics.</summary>
        public ReviewSummary Summary { get; init; } = new();
    }

    // ── Configuration ────────────────────────────────────────────────

    /// <summary>Days before expiration to flag as "expiring soon". Default: 7.</summary>
    public int ExpiryWarningDays { get; set; } = 7;

    /// <summary>Days after expiration to show as "recently expired". Default: 30.</summary>
    public int RecentExpiryDays { get; set; } = 30;

    /// <summary>Days without expiration before a rule is considered "stale". Default: 90.</summary>
    public int StaleDays { get; set; } = 90;

    // ── Core logic ───────────────────────────────────────────────────

    private readonly IgnoreRuleService _ignoreService;

    /// <summary>
    /// Create an ExemptionReviewService.
    /// </summary>
    public ExemptionReviewService(IgnoreRuleService ignoreService)
    {
        _ignoreService = ignoreService ?? throw new ArgumentNullException(nameof(ignoreService));
    }

    /// <summary>
    /// Run a full exemption review against the current findings.
    /// </summary>
    /// <param name="report">Current security report (for utilization analysis). May be null.</param>
    /// <param name="asOf">Reference time for expiry calculations. Defaults to UtcNow.</param>
    public ReviewResult Review(SecurityReport? report = null, DateTimeOffset? asOf = null)
    {
        var now = asOf ?? DateTimeOffset.UtcNow;
        var allRules = _ignoreService.GetAllRules();

        // Build match counts if we have a report
        Dictionary<string, int>? matchCounts = null;
        if (report != null)
        {
            matchCounts = _ignoreService.GetRuleMatchCounts(report);
        }

        var reviewed = new List<ReviewedRule>();
        var expiringSoon = new List<ReviewedRule>();
        var recentlyExpired = new List<ReviewedRule>();
        var stale = new List<ReviewedRule>();
        var unused = new List<ReviewedRule>();
        var disabled = new List<ReviewedRule>();

        foreach (var rule in allRules)
        {
            var ageDays = (int)(now - rule.CreatedAt).TotalDays;
            int? daysUntilExpiry = null;
            if (rule.ExpiresAt.HasValue)
            {
                daysUntilExpiry = (int)(rule.ExpiresAt.Value - now).TotalDays;
            }

            var matchCount = matchCounts != null && matchCounts.TryGetValue(rule.Id, out var mc)
                ? mc : 0;

            var status = ClassifyRule(rule, ageDays, daysUntilExpiry, matchCount, now, report != null);
            var recommendation = GenerateRecommendation(status, rule, ageDays, daysUntilExpiry, matchCount);

            var reviewedRule = new ReviewedRule
            {
                Rule = rule,
                Status = status,
                DaysUntilExpiry = daysUntilExpiry,
                AgeDays = ageDays,
                MatchCount = matchCount,
                Recommendation = recommendation
            };

            reviewed.Add(reviewedRule);

            switch (status)
            {
                case ReviewStatus.ExpiringSoon:
                    expiringSoon.Add(reviewedRule);
                    break;
                case ReviewStatus.RecentlyExpired:
                    recentlyExpired.Add(reviewedRule);
                    break;
                case ReviewStatus.Stale:
                    stale.Add(reviewedRule);
                    break;
                case ReviewStatus.Unused:
                    unused.Add(reviewedRule);
                    break;
                case ReviewStatus.Disabled:
                    disabled.Add(reviewedRule);
                    break;
            }
        }

        // Sort each category
        expiringSoon.Sort((a, b) => (a.DaysUntilExpiry ?? 0).CompareTo(b.DaysUntilExpiry ?? 0));
        recentlyExpired.Sort((a, b) => (b.DaysUntilExpiry ?? 0).CompareTo(a.DaysUntilExpiry ?? 0));
        stale.Sort((a, b) => b.AgeDays.CompareTo(a.AgeDays));
        unused.Sort((a, b) => b.AgeDays.CompareTo(a.AgeDays));

        var summary = BuildSummary(reviewed, expiringSoon.Count, recentlyExpired.Count,
            stale.Count, unused.Count, disabled.Count);

        return new ReviewResult
        {
            Rules = reviewed,
            ExpiringSoon = expiringSoon,
            RecentlyExpired = recentlyExpired,
            Stale = stale,
            Unused = unused,
            Disabled = disabled,
            Summary = summary
        };
    }

    // ── Classification ───────────────────────────────────────────────

    private ReviewStatus ClassifyRule(IgnoreRule rule, int ageDays,
        int? daysUntilExpiry, int matchCount, DateTimeOffset now, bool hasReport)
    {
        // Disabled rules are always classified as Disabled
        if (!rule.Enabled)
            return ReviewStatus.Disabled;

        // Expired rules within the recent window
        if (rule.ExpiresAt.HasValue && now > rule.ExpiresAt.Value)
        {
            var daysSinceExpiry = (int)(now - rule.ExpiresAt.Value).TotalDays;
            if (daysSinceExpiry <= RecentExpiryDays)
                return ReviewStatus.RecentlyExpired;
            // Very old expired rules are also "recently expired" for reporting
            return ReviewStatus.RecentlyExpired;
        }

        // Expiring soon
        if (daysUntilExpiry.HasValue && daysUntilExpiry.Value <= ExpiryWarningDays)
            return ReviewStatus.ExpiringSoon;

        // Unused (only if we have a report to check against)
        if (hasReport && matchCount == 0 && rule.IsActive)
            return ReviewStatus.Unused;

        // Stale: old rule with no expiration
        if (!rule.ExpiresAt.HasValue && ageDays >= StaleDays)
            return ReviewStatus.Stale;

        return ReviewStatus.Current;
    }

    private static string GenerateRecommendation(ReviewStatus status, IgnoreRule rule,
        int ageDays, int? daysUntilExpiry, int matchCount)
    {
        switch (status)
        {
            case ReviewStatus.ExpiringSoon:
                var daysLeft = daysUntilExpiry ?? 0;
                if (daysLeft <= 0)
                    return "Expires today. Decide whether to renew or let it expire.";
                if (daysLeft == 1)
                    return "Expires tomorrow. Review and renew if still needed.";
                return $"Expires in {daysLeft} days. Review and decide on renewal.";

            case ReviewStatus.RecentlyExpired:
                var daysAgo = -(daysUntilExpiry ?? 0);
                if (matchCount > 0)
                    return $"Expired {daysAgo} day(s) ago but still matches {matchCount} finding(s). Consider renewing or fixing the underlying issue.";
                return $"Expired {daysAgo} day(s) ago. Remove with --ignore remove {rule.Id} or renew if still needed.";

            case ReviewStatus.Stale:
                if (matchCount > 0)
                    return $"Active for {ageDays} days with no expiration, matches {matchCount} finding(s). Consider adding an expiration date.";
                return $"Active for {ageDays} days with no expiration and no current matches. Consider removing.";

            case ReviewStatus.Unused:
                return $"No current findings match this rule (age: {ageDays} days). The underlying issue may be fixed. Consider removing.";

            case ReviewStatus.Disabled:
                return "Rule is disabled. Remove if no longer needed.";

            default:
                if (matchCount > 0)
                    return $"Active and matching {matchCount} finding(s). No action needed.";
                return "Active. No action needed.";
        }
    }

    // ── Summary ──────────────────────────────────────────────────────

    private static ReviewSummary BuildSummary(List<ReviewedRule> rules,
        int expiringSoon, int recentlyExpired, int staleRules, int unusedRules, int disabledRules)
    {
        var total = rules.Count;
        var active = rules.Count(r => r.Status == ReviewStatus.Current);

        // Health score: percentage of rules that are Current
        // Penalize for problematic rules
        double health;
        if (total == 0)
        {
            health = 100.0;
        }
        else
        {
            var problemCount = expiringSoon + recentlyExpired + staleRules + unusedRules + disabledRules;
            health = ((double)(total - problemCount) / total) * 100;
            health = Math.Max(0, Math.Min(100, health));
        }

        var grade = health switch
        {
            >= 90 => "A",
            >= 80 => "B",
            >= 70 => "C",
            >= 60 => "D",
            _ => "F"
        };

        return new ReviewSummary
        {
            TotalRules = total,
            ActiveRules = active,
            ExpiringSoon = expiringSoon,
            RecentlyExpired = recentlyExpired,
            StaleRules = staleRules,
            UnusedRules = unusedRules,
            DisabledRules = disabledRules,
            HealthScore = Math.Round(health, 1),
            HealthGrade = grade
        };
    }
}
