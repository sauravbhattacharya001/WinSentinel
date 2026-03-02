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

    // ── Category Exploitability Ratings ──
    // Categories with higher attack surface or remote exploitability score higher.
    private static readonly Dictionary<string, double> CategoryExploitability = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Network"]     = 9.0,  // Remote, often automated
        ["Firewall"]    = 8.5,  // Direct network exposure
        ["Update"]      = 8.0,  // Known CVEs, public exploits
        ["Browser"]     = 7.5,  // Large attack surface, user-facing
        ["Account"]     = 7.0,  // Credential attacks
        ["Encryption"]  = 6.5,  // Data exposure if breached
        ["Privacy"]     = 6.0,  // Data leakage
        ["Defender"]    = 5.5,  // Disabling AV lowers defenses
        ["EventLog"]    = 5.0,  // Evidence tampering
        ["Process"]     = 4.5,  // Local exploitation
        ["AppSecurity"] = 4.0,  // Application-level
        ["Startup"]     = 3.5,  // Persistence, local access needed
        ["System"]      = 3.0,  // Misconfiguration, local
    };

    // ── Category Impact Ratings ──
    // How much damage exploitation in this category causes.
    private static readonly Dictionary<string, double> CategoryImpact = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Encryption"]  = 9.5,  // Complete data exposure
        ["Account"]     = 9.0,  // Full system compromise
        ["Network"]     = 8.5,  // Lateral movement
        ["Firewall"]    = 8.0,  // Defense bypass
        ["Update"]      = 7.5,  // Known vulnerability exploitation
        ["Defender"]    = 7.0,  // AV/EDR blind spots
        ["Privacy"]     = 6.5,  // Data breach
        ["Browser"]     = 6.0,  // Session/credential theft
        ["Process"]     = 5.5,  // Code execution
        ["EventLog"]    = 5.0,  // Forensic evidence loss
        ["Startup"]     = 4.5,  // Persistence
        ["System"]      = 4.0,  // Stability/config issues
        ["AppSecurity"] = 3.5,  // Limited scope
    };

    // ── Environmental Exposure ──
    // How exposed the affected surface is to external threats.
    private static readonly Dictionary<string, double> CategoryEnvironment = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Network"]     = 9.0,
        ["Firewall"]    = 9.0,
        ["Browser"]     = 8.0,
        ["Update"]      = 7.0,
        ["Account"]     = 6.0,
        ["Encryption"]  = 5.0,
        ["Privacy"]     = 5.0,
        ["Defender"]    = 4.0,
        ["EventLog"]    = 3.0,
        ["Process"]     = 3.0,
        ["AppSecurity"] = 3.0,
        ["Startup"]     = 2.0,
        ["System"]      = 2.0,
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
        double exploitability = GetCategoryFactor(CategoryExploitability, category);
        double impact = GetCategoryFactor(CategoryImpact, category);
        double environmental = GetCategoryFactor(CategoryEnvironment, category);
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

    private static double GetCategoryFactor(Dictionary<string, double> factors, string category)
    {
        if (string.IsNullOrEmpty(category))
            return 5.0; // Default mid-range

        return factors.GetValueOrDefault(category, 5.0);
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
