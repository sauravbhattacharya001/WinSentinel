using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Ranks security findings into a prioritized remediation queue using a
/// composite scoring model based on severity, exploitability, blast radius,
/// and finding age. Outputs an actionable "fix this first" list with effort
/// estimates and quick-win identification.
/// </summary>
public class RemediationPrioritizer
{
    // ── Scoring weights (configurable) ───────────────────────────

    /// <summary>Configuration for priority scoring weights.</summary>
    public class PriorityWeights
    {
        /// <summary>Weight for severity score (0-1).</summary>
        public double SeverityWeight { get; set; } = 0.35;

        /// <summary>Weight for exploitability score (0-1).</summary>
        public double ExploitabilityWeight { get; set; } = 0.25;

        /// <summary>Weight for blast radius score (0-1).</summary>
        public double BlastRadiusWeight { get; set; } = 0.20;

        /// <summary>Weight for age-based urgency score (0-1).</summary>
        public double AgeWeight { get; set; } = 0.10;

        /// <summary>Weight for fix availability bonus (0-1).</summary>
        public double FixAvailabilityWeight { get; set; } = 0.10;

        /// <summary>Standard balanced weights.</summary>
        public static PriorityWeights Balanced => new();

        /// <summary>Severity-first: emphasizes critical findings.</summary>
        public static PriorityWeights SeverityFirst => new()
        {
            SeverityWeight = 0.50,
            ExploitabilityWeight = 0.20,
            BlastRadiusWeight = 0.15,
            AgeWeight = 0.05,
            FixAvailabilityWeight = 0.10,
        };

        /// <summary>Quick-win: emphasizes easy fixes with high impact.</summary>
        public static PriorityWeights QuickWin => new()
        {
            SeverityWeight = 0.25,
            ExploitabilityWeight = 0.15,
            BlastRadiusWeight = 0.15,
            AgeWeight = 0.05,
            FixAvailabilityWeight = 0.40,
        };
    }

    /// <summary>Effort level estimate for remediation.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum EffortLevel
    {
        /// <summary>Automated fix available, minimal effort.</summary>
        Trivial,
        /// <summary>Simple config change or setting toggle.</summary>
        Low,
        /// <summary>Requires investigation and manual steps.</summary>
        Medium,
        /// <summary>Significant work, potential downtime.</summary>
        High,
        /// <summary>Major infrastructure or policy change.</summary>
        VeryHigh
    }

    /// <summary>Priority tier for remediation scheduling.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum PriorityTier
    {
        /// <summary>Fix immediately (score >= 80).</summary>
        Immediate,
        /// <summary>Fix within 24 hours (score >= 60).</summary>
        Urgent,
        /// <summary>Fix within 1 week (score >= 40).</summary>
        Soon,
        /// <summary>Fix within 1 month (score >= 20).</summary>
        Planned,
        /// <summary>Fix when convenient (score &lt; 20).</summary>
        Backlog
    }

    // ── Prioritized finding ──────────────────────────────────────

    /// <summary>A finding with computed priority score and metadata.</summary>
    public class PrioritizedFinding
    {
        /// <summary>Rank position (1 = highest priority).</summary>
        public int Rank { get; set; }

        /// <summary>The original finding.</summary>
        public required Finding Finding { get; init; }

        /// <summary>Composite priority score (0-100).</summary>
        public double PriorityScore { get; init; }

        /// <summary>Priority tier based on score.</summary>
        public PriorityTier Tier { get; init; }

        /// <summary>Estimated remediation effort.</summary>
        public EffortLevel Effort { get; init; }

        /// <summary>Whether this is a quick win (high impact, low effort).</summary>
        public bool IsQuickWin { get; init; }

        /// <summary>Individual score components for transparency.</summary>
        public ScoreBreakdown Breakdown { get; init; } = new();

        /// <summary>Suggested remediation timeframe.</summary>
        public string TimeframeLabel => Tier switch
        {
            PriorityTier.Immediate => "Fix now",
            PriorityTier.Urgent => "Within 24 hours",
            PriorityTier.Soon => "Within 1 week",
            PriorityTier.Planned => "Within 1 month",
            PriorityTier.Backlog => "When convenient",
            _ => "Unknown"
        };

        /// <summary>Effort estimate description.</summary>
        public string EffortLabel => Effort switch
        {
            EffortLevel.Trivial => "< 5 min (auto-fix)",
            EffortLevel.Low => "5-15 min",
            EffortLevel.Medium => "15-60 min",
            EffortLevel.High => "1-4 hours",
            EffortLevel.VeryHigh => "4+ hours",
            _ => "Unknown"
        };
    }

    /// <summary>Breakdown of individual score components.</summary>
    public class ScoreBreakdown
    {
        /// <summary>Severity component (0-100).</summary>
        public double SeverityScore { get; init; }

        /// <summary>Exploitability component (0-100).</summary>
        public double ExploitabilityScore { get; init; }

        /// <summary>Blast radius component (0-100).</summary>
        public double BlastRadiusScore { get; init; }

        /// <summary>Age urgency component (0-100).</summary>
        public double AgeScore { get; init; }

        /// <summary>Fix availability component (0-100).</summary>
        public double FixAvailabilityScore { get; init; }
    }

    // ── Prioritization report ────────────────────────────────────

    /// <summary>Complete prioritization report.</summary>
    public class PrioritizationReport
    {
        /// <summary>Report generation timestamp.</summary>
        public DateTimeOffset GeneratedAt { get; init; }

        /// <summary>Weights used for scoring.</summary>
        public string WeightsProfile { get; init; } = "";

        /// <summary>Total findings analyzed.</summary>
        public int TotalFindings { get; init; }

        /// <summary>Quick wins identified.</summary>
        public int QuickWinCount { get; init; }

        /// <summary>Ranked findings (highest priority first).</summary>
        public List<PrioritizedFinding> Rankings { get; init; } = [];

        /// <summary>Summary by priority tier.</summary>
        public Dictionary<PriorityTier, int> TierSummary { get; init; } = new();

        /// <summary>Summary by effort level.</summary>
        public Dictionary<EffortLevel, int> EffortSummary { get; init; } = new();

        /// <summary>Top quick wins for immediate impact.</summary>
        public List<PrioritizedFinding> QuickWins { get; init; } = [];

        /// <summary>Estimated total remediation effort.</summary>
        public string TotalEffortEstimate { get; init; } = "";

        /// <summary>Category breakdown showing which areas need most attention.</summary>
        public Dictionary<string, CategoryStats> CategoryBreakdown { get; init; } = new();
    }

    /// <summary>Stats for a single category.</summary>
    public class CategoryStats
    {
        /// <summary>Number of findings in this category.</summary>
        public int Count { get; init; }

        /// <summary>Average priority score.</summary>
        public double AvgPriority { get; init; }

        /// <summary>Number of quick wins.</summary>
        public int QuickWins { get; init; }

        /// <summary>Highest severity in this category.</summary>
        public Severity MaxSeverity { get; init; }
    }

    // ── Category → exploitability / blast radius mappings ────────

    private static readonly Dictionary<string, double> ExploitabilityMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Firewall"] = 90,
        ["Network"] = 85,
        ["RemoteAccess"] = 95,
        ["Accounts"] = 80,
        ["CredentialExposure"] = 95,
        ["WiFi"] = 75,
        ["SMB"] = 85,
        ["Browser"] = 70,
        ["PowerShell"] = 80,
        ["Defender"] = 60,
        ["Encryption"] = 50,
        ["Updates"] = 65,
        ["Services"] = 60,
        ["Process"] = 55,
        ["Startup"] = 65,
        ["ScheduledTasks"] = 70,
        ["Registry"] = 50,
        ["GroupPolicy"] = 45,
        ["Privacy"] = 40,
        ["Certificates"] = 55,
        ["DNS"] = 70,
        ["Drivers"] = 50,
        ["EventLog"] = 35,
        ["Backup"] = 30,
        ["Bluetooth"] = 60,
        ["Environment"] = 40,
        ["AppSecurity"] = 65,
        ["SoftwareInventory"] = 45,
        ["Virtualization"] = 50,
        ["System"] = 55,
    };

    private static readonly Dictionary<string, double> BlastRadiusMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Firewall"] = 95,
        ["Network"] = 90,
        ["RemoteAccess"] = 95,
        ["Accounts"] = 85,
        ["CredentialExposure"] = 90,
        ["Encryption"] = 80,
        ["Defender"] = 85,
        ["Updates"] = 75,
        ["GroupPolicy"] = 70,
        ["PowerShell"] = 75,
        ["DNS"] = 70,
        ["Services"] = 65,
        ["SMB"] = 80,
        ["WiFi"] = 60,
        ["Browser"] = 55,
        ["Certificates"] = 60,
        ["Backup"] = 50,
        ["Startup"] = 55,
        ["ScheduledTasks"] = 55,
        ["Process"] = 50,
        ["Registry"] = 50,
        ["Privacy"] = 45,
        ["Drivers"] = 55,
        ["EventLog"] = 40,
        ["Bluetooth"] = 35,
        ["Environment"] = 40,
        ["AppSecurity"] = 60,
        ["SoftwareInventory"] = 45,
        ["Virtualization"] = 55,
        ["System"] = 65,
    };

    // ── State ────────────────────────────────────────────────────

    private readonly PriorityWeights _weights;

    /// <summary>
    /// Create a new prioritizer with the specified scoring weights.
    /// </summary>
    public RemediationPrioritizer(PriorityWeights? weights = null)
    {
        _weights = weights ?? PriorityWeights.Balanced;
    }

    // ── Core prioritization ──────────────────────────────────────

    /// <summary>
    /// Prioritize findings from a security report.
    /// </summary>
    /// <param name="report">The security report to analyze.</param>
    /// <param name="top">Maximum number of findings to return (0 = all).</param>
    /// <param name="minSeverity">Minimum severity to include.</param>
    /// <returns>Prioritization report with ranked findings.</returns>
    public PrioritizationReport Prioritize(SecurityReport report, int top = 0, Severity minSeverity = Severity.Info)
    {
        ArgumentNullException.ThrowIfNull(report);

        var allFindings = report.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity >= minSeverity && f.Severity != Severity.Pass)
            .ToList();

        return PrioritizeFindings(allFindings, top);
    }

    /// <summary>
    /// Prioritize a list of findings directly.
    /// </summary>
    public PrioritizationReport PrioritizeFindings(IReadOnlyList<Finding> findings, int top = 0)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var scored = findings.Select(f => ScoreFinding(f)).ToList();

        // Sort by priority score descending
        scored.Sort((a, b) => b.PriorityScore.CompareTo(a.PriorityScore));

        // Assign ranks
        for (int i = 0; i < scored.Count; i++)
            scored[i].Rank = i + 1;

        var results = top > 0 ? scored.Take(top).ToList() : scored;
        var quickWins = scored.Where(f => f.IsQuickWin).ToList();

        // Tier summary
        var tierSummary = new Dictionary<PriorityTier, int>();
        foreach (PriorityTier tier in Enum.GetValues<PriorityTier>())
            tierSummary[tier] = scored.Count(f => f.Tier == tier);

        // Effort summary
        var effortSummary = new Dictionary<EffortLevel, int>();
        foreach (EffortLevel effort in Enum.GetValues<EffortLevel>())
            effortSummary[effort] = scored.Count(f => f.Effort == effort);

        // Category breakdown
        var catBreakdown = scored
            .GroupBy(f => f.Finding.Category)
            .ToDictionary(
                g => g.Key,
                g => new CategoryStats
                {
                    Count = g.Count(),
                    AvgPriority = Math.Round(g.Average(f => f.PriorityScore), 1),
                    QuickWins = g.Count(f => f.IsQuickWin),
                    MaxSeverity = g.Max(f => f.Finding.Severity),
                });

        // Total effort estimate
        var totalMinutes = scored.Sum(f => EstimateMinutes(f.Effort));
        var totalEffort = totalMinutes switch
        {
            < 60 => $"{totalMinutes} minutes",
            < 480 => $"{totalMinutes / 60}h {totalMinutes % 60}m",
            _ => $"{totalMinutes / 60 / 8} days {totalMinutes / 60 % 8}h"
        };

        var weightsName = _weights == PriorityWeights.Balanced ? "Balanced" :
                          _weights == PriorityWeights.SeverityFirst ? "SeverityFirst" :
                          _weights == PriorityWeights.QuickWin ? "QuickWin" : "Custom";

        return new PrioritizationReport
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            WeightsProfile = weightsName,
            TotalFindings = scored.Count,
            QuickWinCount = quickWins.Count,
            Rankings = results,
            TierSummary = tierSummary,
            EffortSummary = effortSummary,
            QuickWins = quickWins.Take(10).ToList(),
            TotalEffortEstimate = totalEffort,
            CategoryBreakdown = catBreakdown,
        };
    }

    /// <summary>
    /// Score a single finding.
    /// </summary>
    public PrioritizedFinding ScoreFinding(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        var severityScore = SeverityToScore(finding.Severity);
        var exploitScore = GetExploitabilityScore(finding);
        var blastScore = GetBlastRadiusScore(finding);
        var ageScore = GetAgeScore(finding);
        var fixScore = GetFixAvailabilityScore(finding);

        var composite = Math.Round(
            severityScore * _weights.SeverityWeight +
            exploitScore * _weights.ExploitabilityWeight +
            blastScore * _weights.BlastRadiusWeight +
            ageScore * _weights.AgeWeight +
            fixScore * _weights.FixAvailabilityWeight,
            1);

        // Clamp to 0-100
        composite = Math.Max(0, Math.Min(100, composite));

        var effort = EstimateEffort(finding);
        var tier = ScoreToTier(composite);
        var isQuickWin = effort <= EffortLevel.Low && composite >= 40;

        return new PrioritizedFinding
        {
            Finding = finding,
            PriorityScore = composite,
            Tier = tier,
            Effort = effort,
            IsQuickWin = isQuickWin,
            Breakdown = new ScoreBreakdown
            {
                SeverityScore = severityScore,
                ExploitabilityScore = exploitScore,
                BlastRadiusScore = blastScore,
                AgeScore = ageScore,
                FixAvailabilityScore = fixScore,
            },
        };
    }

    // ── Scoring helpers ──────────────────────────────────────────

    private static double SeverityToScore(Severity severity) => severity switch
    {
        Severity.Critical => 100,
        Severity.Warning => 60,
        Severity.Info => 25,
        _ => 0,
    };

    private static double GetExploitabilityScore(Finding finding)
    {
        if (ExploitabilityMap.TryGetValue(finding.Category, out var score))
        {
            // Boost if severity is critical (more likely to be actively exploited)
            return finding.Severity == Severity.Critical ? Math.Min(100, score * 1.1) : score;
        }
        return 50; // default for unknown categories
    }

    private static double GetBlastRadiusScore(Finding finding)
    {
        if (BlastRadiusMap.TryGetValue(finding.Category, out var score))
            return score;
        return 50;
    }

    private static double GetAgeScore(Finding finding)
    {
        var age = DateTimeOffset.UtcNow - finding.Timestamp;
        // Older findings get higher urgency (they've been unresolved longer)
        return age.TotalDays switch
        {
            >= 90 => 100,
            >= 30 => 80,
            >= 7 => 60,
            >= 1 => 40,
            _ => 20,
        };
    }

    private static double GetFixAvailabilityScore(Finding finding)
    {
        // Auto-fix available = highest score (easiest to remediate)
        if (!string.IsNullOrEmpty(finding.FixCommand))
            return 100;
        // Has remediation guidance
        if (!string.IsNullOrEmpty(finding.Remediation))
            return 60;
        // No guidance at all
        return 20;
    }

    private static EffortLevel EstimateEffort(Finding finding)
    {
        // Auto-fix = trivial
        if (!string.IsNullOrEmpty(finding.FixCommand))
            return EffortLevel.Trivial;

        // Category-based estimation
        return finding.Category.ToLowerInvariant() switch
        {
            "firewall" or "defender" or "privacy" or "bluetooth" => EffortLevel.Low,
            "accounts" or "updates" or "browser" or "dns" or "wifi" => EffortLevel.Medium,
            "encryption" or "network" or "remoteaccess" or "smb" => EffortLevel.High,
            "grouppolicy" or "virtualization" or "system" => EffortLevel.VeryHigh,
            _ => string.IsNullOrEmpty(finding.Remediation) ? EffortLevel.High : EffortLevel.Medium,
        };
    }

    private static PriorityTier ScoreToTier(double score) => score switch
    {
        >= 80 => PriorityTier.Immediate,
        >= 60 => PriorityTier.Urgent,
        >= 40 => PriorityTier.Soon,
        >= 20 => PriorityTier.Planned,
        _ => PriorityTier.Backlog,
    };

    private static int EstimateMinutes(EffortLevel effort) => effort switch
    {
        EffortLevel.Trivial => 3,
        EffortLevel.Low => 10,
        EffortLevel.Medium => 30,
        EffortLevel.High => 120,
        EffortLevel.VeryHigh => 360,
        _ => 30,
    };

    // ── Text report ──────────────────────────────────────────────

    /// <summary>
    /// Generate a plain-text prioritization report.
    /// </summary>
    public string GenerateTextReport(SecurityReport report, int top = 20, Severity minSeverity = Severity.Info)
    {
        var result = Prioritize(report, top, minSeverity);
        return FormatTextReport(result);
    }

    /// <summary>
    /// Format a prioritization report as plain text.
    /// </summary>
    public static string FormatTextReport(PrioritizationReport report)
    {
        var sb = new StringBuilder();

        sb.AppendLine("═══ Remediation Priority Queue ═══");
        sb.AppendLine($"Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Profile: {report.WeightsProfile}");
        sb.AppendLine();

        // Summary
        sb.AppendLine($"Total Findings:     {report.TotalFindings}");
        sb.AppendLine($"Quick Wins:         {report.QuickWinCount}");
        sb.AppendLine($"Est. Total Effort:  {report.TotalEffortEstimate}");
        sb.AppendLine();

        // Tier breakdown
        sb.AppendLine("── Priority Tiers ──");
        foreach (var (tier, count) in report.TierSummary.Where(kv => kv.Value > 0))
            sb.AppendLine($"  {tier,-12} {count}");
        sb.AppendLine();

        // Quick wins
        if (report.QuickWins.Count > 0)
        {
            sb.AppendLine("── Quick Wins (high impact, low effort) ──");
            foreach (var qw in report.QuickWins)
            {
                sb.AppendLine($"  #{qw.Rank} [{qw.Finding.Severity}] {qw.Finding.Title}");
                sb.AppendLine($"      Category: {qw.Finding.Category} | Score: {qw.PriorityScore} | {qw.EffortLabel}");
                if (!string.IsNullOrEmpty(qw.Finding.FixCommand))
                    sb.AppendLine($"      Auto-fix: {qw.Finding.FixCommand}");
            }
            sb.AppendLine();
        }

        // Category hotspots
        sb.AppendLine("── Category Hotspots ──");
        foreach (var (cat, stats) in report.CategoryBreakdown
            .OrderByDescending(kv => kv.Value.AvgPriority)
            .Take(10))
        {
            sb.AppendLine($"  {cat,-20} {stats.Count} findings | avg priority: {stats.AvgPriority} | max: {stats.MaxSeverity}");
        }
        sb.AppendLine();

        // Full rankings
        sb.AppendLine("── Ranked Remediation Queue ──");
        foreach (var item in report.Rankings)
        {
            var qwTag = item.IsQuickWin ? " ★" : "";
            sb.AppendLine($"  #{item.Rank} [{item.Tier}] {item.Finding.Title}{qwTag}");
            sb.AppendLine($"      Severity: {item.Finding.Severity} | Category: {item.Finding.Category}");
            sb.AppendLine($"      Score: {item.PriorityScore} | Effort: {item.EffortLabel} | {item.TimeframeLabel}");
            if (!string.IsNullOrEmpty(item.Finding.Remediation))
                sb.AppendLine($"      Fix: {item.Finding.Remediation}");
        }

        return sb.ToString();
    }

    /// <summary>
    /// Generate a JSON report.
    /// </summary>
    public string GenerateJsonReport(SecurityReport report, int top = 0, Severity minSeverity = Severity.Info)
    {
        var result = Prioritize(report, top, minSeverity);
        return JsonSerializer.Serialize(result, new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() },
        });
    }

    /// <summary>
    /// Generate a CSV report.
    /// </summary>
    public string GenerateCsvReport(SecurityReport report, int top = 0, Severity minSeverity = Severity.Info)
    {
        var result = Prioritize(report, top, minSeverity);
        var sb = new StringBuilder();

        sb.AppendLine("Rank,Title,Category,Severity,Score,Tier,Effort,QuickWin,Timeframe,HasAutoFix");
        foreach (var item in result.Rankings)
        {
            var title = item.Finding.Title.Contains(',')
                ? $"\"{item.Finding.Title}\""
                : item.Finding.Title;
            sb.AppendLine($"{item.Rank},{title},{item.Finding.Category},{item.Finding.Severity}," +
                          $"{item.PriorityScore},{item.Tier},{item.Effort},{item.IsQuickWin}," +
                          $"{item.TimeframeLabel},{!string.IsNullOrEmpty(item.Finding.FixCommand)}");
        }

        return sb.ToString();
    }
}
