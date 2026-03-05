using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Multi-factor risk assessment that prioritizes findings based on
/// exploitability, impact, environmental exposure, and persistence.
/// Produces a prioritized finding list and a risk matrix summary.
/// </summary>
public class RiskAssessmentService
{
    /// <summary>
    /// Risk level classification based on composite risk score.
    /// </summary>
    public enum RiskLevel
    {
        Low = 0,
        Medium = 1,
        High = 2,
        Critical = 3
    }

    /// <summary>
    /// A finding enriched with multi-factor risk scoring.
    /// </summary>
    public class RiskAssessedFinding
    {
        public required Finding Finding { get; init; }
        public required string Module { get; init; }

        /// <summary>Base severity score (0–10) derived from finding severity.</summary>
        public double SeverityScore { get; init; }

        /// <summary>Exploitability factor (0–10): how easily this can be exploited.</summary>
        public double ExploitabilityScore { get; init; }

        /// <summary>Impact factor (0–10): damage if exploited.</summary>
        public double ImpactScore { get; init; }

        /// <summary>Environmental factor (0–10): exposure of the affected surface.</summary>
        public double EnvironmentalScore { get; init; }

        /// <summary>Persistence factor (0–10): how long the finding has been present.</summary>
        public double PersistenceScore { get; init; }

        /// <summary>
        /// Composite risk score (0–100). Weighted combination of all factors.
        /// Formula: Severity×0.30 + Exploitability×0.25 + Impact×0.25 + Environment×0.10 + Persistence×0.10
        /// Normalized to 0–100 scale.
        /// </summary>
        public double CompositeScore { get; init; }

        /// <summary>Risk level classification.</summary>
        public RiskLevel Level { get; init; }

        /// <summary>Priority rank (1 = highest priority).</summary>
        public int PriorityRank { get; set; }

        /// <summary>Human-readable risk justification.</summary>
        public string Justification { get; init; } = string.Empty;
    }

    /// <summary>
    /// Summary of risk distribution across a report.
    /// </summary>
    public class RiskMatrix
    {
        public int TotalFindings { get; init; }
        public int CriticalRisk { get; init; }
        public int HighRisk { get; init; }
        public int MediumRisk { get; init; }
        public int LowRisk { get; init; }

        /// <summary>Average composite score across all findings.</summary>
        public double AverageRiskScore { get; init; }

        /// <summary>Highest risk categories, sorted by average score descending.</summary>
        public List<CategoryRisk> CategoryBreakdown { get; init; } = new();

        /// <summary>Overall risk level of the system.</summary>
        public RiskLevel OverallRisk { get; init; }

        /// <summary>Top priority findings (up to 5) that should be addressed first.</summary>
        public List<RiskAssessedFinding> TopPriorities { get; init; } = new();
    }

    /// <summary>
    /// Risk summary for a single audit category.
    /// </summary>
    public class CategoryRisk
    {
        public required string Category { get; init; }
        public double AverageScore { get; init; }
        public int FindingCount { get; init; }
        public RiskLevel HighestRisk { get; init; }
    }

    // ── Category Risk Factors ──
    // Consolidated risk profile per audit category.  Each category gets a
    // single record with exploitability, impact, and environmental exposure
    // ratings (0–10 scale).  Keeping them in one structure ensures a new
    // category always has all three dimensions defined.

    /// <summary>
    /// Risk factor profile for a single audit category.
    /// </summary>
    /// <param name="Exploitability">How easily findings in this category can be exploited (0–10).</param>
    /// <param name="Impact">How much damage exploitation would cause (0–10).</param>
    /// <param name="Environment">How exposed the affected surface is to external threats (0–10).</param>
    public readonly record struct CategoryRiskProfile(
        double Exploitability,
        double Impact,
        double Environment);

    /// <summary>Default risk factors used when a category is not in the lookup table.</summary>
    internal static readonly CategoryRiskProfile DefaultProfile = new(5.0, 5.0, 5.0);

    internal static readonly Dictionary<string, CategoryRiskProfile> CategoryRiskFactors =
        new(StringComparer.OrdinalIgnoreCase)
    {
        //                                        Exploit  Impact  Environ
        ["Network"]     = new CategoryRiskProfile( 9.0,     8.5,    9.0),  // Remote, lateral movement
        ["Firewall"]    = new CategoryRiskProfile( 8.5,     8.0,    9.0),  // Direct network exposure
        ["Update"]      = new CategoryRiskProfile( 8.0,     7.5,    7.0),  // Known CVEs, public exploits
        ["Browser"]     = new CategoryRiskProfile( 7.5,     6.0,    8.0),  // Large user-facing surface
        ["Account"]     = new CategoryRiskProfile( 7.0,     9.0,    6.0),  // Credential attacks
        ["Encryption"]  = new CategoryRiskProfile( 6.5,     9.5,    5.0),  // Data exposure if breached
        ["Privacy"]     = new CategoryRiskProfile( 6.0,     6.5,    5.0),  // Data leakage
        ["Defender"]    = new CategoryRiskProfile( 5.5,     7.0,    4.0),  // AV/EDR blind spots
        ["EventLog"]    = new CategoryRiskProfile( 5.0,     5.0,    3.0),  // Evidence tampering
        ["Process"]     = new CategoryRiskProfile( 4.5,     5.5,    3.0),  // Local exploitation
        ["AppSecurity"] = new CategoryRiskProfile( 4.0,     3.5,    3.0),  // Application-level
        ["Startup"]     = new CategoryRiskProfile( 3.5,     4.5,    2.0),  // Persistence, local access
        ["System"]      = new CategoryRiskProfile( 3.0,     4.0,    2.0),  // Misconfiguration, local
    };

    /// <summary>
    /// Assess risk for all findings in a security report.
    /// Returns findings sorted by composite risk score (highest first).
    /// </summary>
    public List<RiskAssessedFinding> AssessFindings(SecurityReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var assessed = new List<RiskAssessedFinding>();

        foreach (var result in report.Results)
        {
            foreach (var finding in result.Findings)
            {
                if (finding.Severity == Severity.Pass)
                    continue; // Skip passing checks

                var entry = AssessSingleFinding(finding, result.Category, result.ModuleName);
                assessed.Add(entry);
            }
        }

        // Sort by composite score descending
        assessed.Sort((a, b) => b.CompositeScore.CompareTo(a.CompositeScore));

        // Assign priority ranks
        for (int i = 0; i < assessed.Count; i++)
            assessed[i].PriorityRank = i + 1;

        return assessed;
    }

    /// <summary>
    /// Assess a single finding with multi-factor scoring.
    /// </summary>
    public RiskAssessedFinding AssessSingleFinding(Finding finding, string category, string module)
    {
        ArgumentNullException.ThrowIfNull(finding);

        double severityScore = SeverityToScore(finding.Severity);
        var profile = GetCategoryProfile(category);
        double exploitability = profile.Exploitability;
        double impact = profile.Impact;
        double environmental = profile.Environment;
        double persistence = CalculatePersistence(finding);

        // Composite score: weighted average, scaled to 0-100
        double composite = (
            severityScore * 0.30 +
            exploitability * 0.25 +
            impact * 0.25 +
            environmental * 0.10 +
            persistence * 0.10
        ) * 10.0; // Scale from 0-10 to 0-100

        var level = ClassifyRiskLevel(composite);
        var justification = BuildJustification(finding, category, severityScore,
            exploitability, impact, environmental, persistence, composite);

        return new RiskAssessedFinding
        {
            Finding = finding,
            Module = module,
            SeverityScore = severityScore,
            ExploitabilityScore = exploitability,
            ImpactScore = impact,
            EnvironmentalScore = environmental,
            PersistenceScore = persistence,
            CompositeScore = Math.Round(composite, 1),
            Level = level,
            Justification = justification
        };
    }

    /// <summary>
    /// Generate a risk matrix summary from assessed findings.
    /// </summary>
    public RiskMatrix GenerateMatrix(List<RiskAssessedFinding> assessedFindings)
    {
        ArgumentNullException.ThrowIfNull(assessedFindings);

        if (assessedFindings.Count == 0)
        {
            return new RiskMatrix
            {
                TotalFindings = 0,
                CriticalRisk = 0,
                HighRisk = 0,
                MediumRisk = 0,
                LowRisk = 0,
                AverageRiskScore = 0,
                OverallRisk = RiskLevel.Low,
                CategoryBreakdown = new(),
                TopPriorities = new()
            };
        }

        var categoryGroups = assessedFindings
            .GroupBy(f => f.Finding.Category)
            .Select(g => new CategoryRisk
            {
                Category = g.Key,
                AverageScore = Math.Round(g.Average(f => f.CompositeScore), 1),
                FindingCount = g.Count(),
                HighestRisk = g.Max(f => f.Level)
            })
            .OrderByDescending(c => c.AverageScore)
            .ToList();

        double avgScore = Math.Round(assessedFindings.Average(f => f.CompositeScore), 1);

        return new RiskMatrix
        {
            TotalFindings = assessedFindings.Count,
            CriticalRisk = assessedFindings.Count(f => f.Level == RiskLevel.Critical),
            HighRisk = assessedFindings.Count(f => f.Level == RiskLevel.High),
            MediumRisk = assessedFindings.Count(f => f.Level == RiskLevel.Medium),
            LowRisk = assessedFindings.Count(f => f.Level == RiskLevel.Low),
            AverageRiskScore = avgScore,
            OverallRisk = ClassifyRiskLevel(avgScore),
            CategoryBreakdown = categoryGroups,
            TopPriorities = assessedFindings.Take(5).ToList()
        };
    }

    /// <summary>
    /// Generate a risk matrix directly from a security report.
    /// </summary>
    public RiskMatrix Analyze(SecurityReport report)
    {
        var assessed = AssessFindings(report);
        return GenerateMatrix(assessed);
    }

    /// <summary>
    /// Format risk assessment as a text summary.
    /// </summary>
    public static string FormatSummary(RiskMatrix matrix)
    {
        ArgumentNullException.ThrowIfNull(matrix);

        var lines = new List<string>
        {
            "═══ Risk Assessment Summary ═══",
            "",
            $"Overall Risk Level: {matrix.OverallRisk}",
            $"Average Risk Score: {matrix.AverageRiskScore:F1}/100",
            $"Total Findings: {matrix.TotalFindings}",
            "",
            "Risk Distribution:",
            $"  Critical: {matrix.CriticalRisk}",
            $"  High:     {matrix.HighRisk}",
            $"  Medium:   {matrix.MediumRisk}",
            $"  Low:      {matrix.LowRisk}",
        };

        if (matrix.CategoryBreakdown.Count > 0)
        {
            lines.Add("");
            lines.Add("Category Risk Ranking:");
            foreach (var cat in matrix.CategoryBreakdown)
            {
                lines.Add($"  {cat.Category,-15} avg={cat.AverageScore,5:F1}  count={cat.FindingCount}  highest={cat.HighestRisk}");
            }
        }

        if (matrix.TopPriorities.Count > 0)
        {
            lines.Add("");
            lines.Add("Top Priority Findings:");
            foreach (var p in matrix.TopPriorities)
            {
                lines.Add($"  #{p.PriorityRank} [{p.Level}] {p.Finding.Title} (score={p.CompositeScore:F1})");
                lines.Add($"     {p.Justification}");
            }
        }

        return string.Join(Environment.NewLine, lines);
    }

    // ── Private Helpers ──

    private static double SeverityToScore(Severity severity) => severity switch
    {
        Severity.Critical => 10.0,
        Severity.Warning => 6.0,
        Severity.Info => 3.0,
        Severity.Pass => 0.0,
        _ => 0.0
    };

    internal static CategoryRiskProfile GetCategoryProfile(string category)
    {
        if (string.IsNullOrEmpty(category))
            return DefaultProfile;
        return CategoryRiskFactors.GetValueOrDefault(category, DefaultProfile);
    }

    private static double CalculatePersistence(Finding finding)
    {
        // Score based on how old the finding is
        var age = DateTimeOffset.UtcNow - finding.Timestamp;

        if (age.TotalDays > 90) return 10.0;  // 3+ months old
        if (age.TotalDays > 30) return 7.0;   // 1-3 months
        if (age.TotalDays > 7)  return 4.0;   // 1-4 weeks
        if (age.TotalDays > 1)  return 2.0;   // 1-7 days
        return 1.0;                            // Fresh
    }

    public static RiskLevel ClassifyRiskLevel(double compositeScore) => compositeScore switch
    {
        >= 75.0 => RiskLevel.Critical,
        >= 50.0 => RiskLevel.High,
        >= 25.0 => RiskLevel.Medium,
        _ => RiskLevel.Low
    };

    private static string BuildJustification(Finding finding, string category,
        double severity, double exploitability, double impact,
        double environmental, double persistence, double composite)
    {
        var parts = new List<string>();

        if (severity >= 8.0)
            parts.Add("critical severity");
        else if (severity >= 5.0)
            parts.Add("moderate severity");

        if (exploitability >= 7.0)
            parts.Add($"high exploitability in {category}");

        if (impact >= 7.0)
            parts.Add($"high potential impact");

        if (environmental >= 7.0)
            parts.Add("externally exposed surface");

        if (persistence >= 7.0)
            parts.Add("long-standing issue");

        if (finding.Remediation != null)
            parts.Add("remediation available");
        else
            parts.Add("no known remediation");

        return parts.Count > 0
            ? string.Join("; ", parts)
            : "standard risk profile";
    }
}
