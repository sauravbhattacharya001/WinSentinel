using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates a comprehensive security posture report that synthesizes data
/// from multiple analysis services into an executive-level briefing.
///
/// Combines: security score, risk assessment, finding age, persistence,
/// trend direction, compliance status, and remediation priorities into
/// a single actionable document.
/// </summary>
public class SecurityPostureService
{
    // ── Score thresholds ──────────────────────────────────────────────
    private const int ScoreExcellent = 90;
    private const int ScoreGood = 70;
    private const int ScoreFair = 50;

    // ── Posture report generation ────────────────────────────────────

    /// <summary>
    /// Generate a full security posture report from audit results and history.
    /// </summary>
    /// <param name="report">Current audit report.</param>
    /// <param name="previousScore">Score from the previous audit (null if first run).</param>
    /// <param name="runs">Historical audit runs for trend/persistence analysis.</param>
    /// <param name="complianceProfile">Optional compliance profile name to evaluate.</param>
    public PostureReport Generate(
        SecurityReport report,
        int? previousScore = null,
        List<AuditRunRecord>? runs = null,
        string? complianceProfile = null)
    {
        var posture = new PostureReport
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            OverallScore = report.SecurityScore,
            Grade = SecurityScorer.GetGrade(report.SecurityScore),
            PostureLevel = ClassifyPosture(report.SecurityScore),
        };

        // ── Score delta ──
        if (previousScore.HasValue)
        {
            posture.ScoreDelta = report.SecurityScore - previousScore.Value;
            posture.TrendDirection = posture.ScoreDelta switch
            {
                > 2 => TrendDirection.Improving,
                < -2 => TrendDirection.Declining,
                _ => TrendDirection.Stable
            };
        }

        // ── Finding summary (single pass instead of 5 separate iterations) ──
        var allFindings = report.Results.SelectMany(r => r.Findings).ToList();
        int criticalCount = 0, warningCount = 0, infoCount = 0, passCount = 0, autoFixableCount = 0;
        foreach (var f in allFindings)
        {
            switch (f.Severity)
            {
                case Severity.Critical: criticalCount++; break;
                case Severity.Warning: warningCount++; break;
                case Severity.Info: infoCount++; break;
                case Severity.Pass: passCount++; break;
            }
            if (!string.IsNullOrWhiteSpace(f.FixCommand)) autoFixableCount++;
        }
        posture.TotalFindings = allFindings.Count;
        posture.CriticalCount = criticalCount;
        posture.WarningCount = warningCount;
        posture.InfoCount = infoCount;
        posture.PassCount = passCount;
        posture.AutoFixableCount = autoFixableCount;

        // ── Module breakdown ──
        // Pre-build a finding→category lookup so TopRisks/QuickWins avoid
        // O(findings × results) scans via FirstOrDefault + Contains.
        var findingToCategory = new Dictionary<Finding, string>(allFindings.Count);
        posture.ModuleBreakdown = report.Results
            .Select(r =>
            {
                int modCritical = 0, modWarning = 0;
                foreach (var f in r.Findings)
                {
                    findingToCategory[f] = r.Category;
                    if (f.Severity == Severity.Critical) modCritical++;
                    else if (f.Severity == Severity.Warning) modWarning++;
                }
                return new ModulePosture
                {
                    ModuleName = r.Category,
                    Score = r.Score,
                    FindingCount = r.Findings.Count,
                    CriticalCount = modCritical,
                    WarningCount = modWarning,
                    Health = ClassifyModuleHealth(r.Score, r.Findings)
                };
            })
            .OrderBy(m => m.Score)
            .ToList();

        // ── Top risks ──
        posture.TopRisks = allFindings
            .Where(f => f.Severity is Severity.Critical or Severity.Warning)
            .OrderByDescending(f => f.Severity == Severity.Critical ? 2 : 1)
            .ThenBy(f => f.Title)
            .Take(10)
            .Select(f => new RiskItem
            {
                Title = f.Title,
                Severity = f.Severity,
                Module = findingToCategory.GetValueOrDefault(f, "Unknown"),
                HasAutoFix = !string.IsNullOrWhiteSpace(f.FixCommand),
                Remediation = f.Remediation ?? ""
            })
            .ToList();

        // ── Quick wins (auto-fixable criticals/warnings) ──
        posture.QuickWins = allFindings
            .Where(f => !string.IsNullOrWhiteSpace(f.FixCommand)
                     && f.Severity is Severity.Critical or Severity.Warning)
            .Select(f => new QuickWinItem
            {
                Title = f.Title,
                Severity = f.Severity,
                FixCommand = f.FixCommand!,
                Module = findingToCategory.GetValueOrDefault(f, "Unknown"),
                EstimatedImpact = f.Severity == Severity.Critical ? "High" : "Medium"
            })
            .OrderByDescending(q => q.Severity == Severity.Critical ? 2 : 1)
            .ToList();

        // ── Persistence analysis (if history available) ──
        if (runs is { Count: > 1 })
        {
            var analyzer = new FindingPersistenceAnalyzer();
            var persistence = analyzer.Analyze(runs);
            posture.PersistentCount = persistence.Entries
                .Count(e => e.Classification == PersistenceClass.Chronic);
            posture.NewCount = persistence.Entries
                .Count(e => e.Classification == PersistenceClass.Transient && e.AppearanceCount == 1);
            posture.ResolvedCount = persistence.Entries
                .Count(e => e.Classification == PersistenceClass.Resolved);
            posture.HasPersistenceData = true;
        }

        // ── Compliance evaluation ──
        if (!string.IsNullOrWhiteSpace(complianceProfile))
        {
            var compliance = new ComplianceProfileService();
            var compResult = compliance.ApplyProfile(complianceProfile, report);
            if (compResult != null)
            {
                posture.ComplianceProfile = complianceProfile;
                posture.ComplianceScore = compResult.AdjustedScore;
                posture.ComplianceStatus = compResult.AdjustedScore >= 80
                    ? "Compliant"
                    : compResult.AdjustedScore >= 60
                        ? "Partially Compliant"
                        : "Non-Compliant";
            }
        }

        // ── Executive summary ──
        posture.ExecutiveSummary = GenerateExecutiveSummary(posture);

        // ── Recommendations ──
        posture.Recommendations = GenerateRecommendations(posture);

        return posture;
    }

    // ── Classification helpers ───────────────────────────────────────

    /// <summary>Classify overall security posture based on score.</summary>
    public static PostureLevel ClassifyPosture(int score) => score switch
    {
        >= ScoreExcellent => PostureLevel.Excellent,
        >= ScoreGood => PostureLevel.Good,
        >= ScoreFair => PostureLevel.Fair,
        >= 30 => PostureLevel.Poor,
        _ => PostureLevel.Critical
    };

    /// <summary>Classify individual module health.</summary>
    public static ModuleHealth ClassifyModuleHealth(int score, List<Finding> findings)
    {
        var hasCritical = findings.Any(f => f.Severity == Severity.Critical);
        if (hasCritical && score < 50) return ModuleHealth.Critical;
        if (hasCritical) return ModuleHealth.AtRisk;
        if (score >= 90) return ModuleHealth.Healthy;
        if (score >= 70) return ModuleHealth.Moderate;
        return ModuleHealth.NeedsAttention;
    }

    // ── Executive summary generation ─────────────────────────────────

    internal static string GenerateExecutiveSummary(PostureReport posture)
    {
        var parts = new List<string>();

        // Overall posture
        parts.Add($"Security posture is {posture.PostureLevel.ToString().ToUpperInvariant()} " +
                   $"with a score of {posture.OverallScore}/100 (Grade {posture.Grade}).");

        // Trend
        if (posture.ScoreDelta.HasValue)
        {
            var direction = posture.ScoreDelta.Value > 0 ? "up" : posture.ScoreDelta.Value < 0 ? "down" : "unchanged";
            var abs = Math.Abs(posture.ScoreDelta.Value);
            if (abs > 0)
                parts.Add($"Score moved {direction} {abs} point{(abs != 1 ? "s" : "")} since last audit.");
            else
                parts.Add("Score is unchanged since last audit.");
        }

        // Critical findings
        if (posture.CriticalCount > 0)
        {
            parts.Add($"{posture.CriticalCount} critical finding{(posture.CriticalCount != 1 ? "s" : "")} " +
                       $"require immediate attention.");
        }

        // Quick wins
        if (posture.QuickWins.Count > 0)
        {
            parts.Add($"{posture.QuickWins.Count} issue{(posture.QuickWins.Count != 1 ? "s" : "")} " +
                       $"can be resolved with automated fixes.");
        }

        // Persistent issues
        if (posture.HasPersistenceData && posture.PersistentCount > 0)
        {
            parts.Add($"{posture.PersistentCount} chronic issue{(posture.PersistentCount != 1 ? "s" : "")} " +
                       $"persist across multiple audits and should be prioritized.");
        }

        // Compliance
        if (!string.IsNullOrWhiteSpace(posture.ComplianceStatus))
        {
            parts.Add($"Compliance status against {posture.ComplianceProfile}: {posture.ComplianceStatus} " +
                       $"({posture.ComplianceScore}/100).");
        }

        return string.Join(" ", parts);
    }

    // ── Recommendation generation ────────────────────────────────────

    internal static List<PostureRecommendation> GenerateRecommendations(PostureReport posture)
    {
        var recs = new List<PostureRecommendation>();
        int priority = 0;

        // Critical findings — always #1
        if (posture.CriticalCount > 0)
        {
            recs.Add(new PostureRecommendation
            {
                Priority = ++priority,
                Category = "Critical Findings",
                Action = $"Address {posture.CriticalCount} critical finding{(posture.CriticalCount != 1 ? "s" : "")} immediately.",
                Impact = "High",
                Effort = posture.QuickWins.Any(q => q.Severity == Severity.Critical) ? "Low-Medium" : "Medium-High",
                Rationale = "Critical findings represent active security vulnerabilities that could be exploited."
            });
        }

        // Quick wins
        if (posture.QuickWins.Count > 0)
        {
            var criticalQuickWins = posture.QuickWins.Count(q => q.Severity == Severity.Critical);
            recs.Add(new PostureRecommendation
            {
                Priority = ++priority,
                Category = "Quick Wins",
                Action = $"Run {posture.QuickWins.Count} auto-fix command{(posture.QuickWins.Count != 1 ? "s" : "")} " +
                         $"to resolve issues with minimal effort.",
                Impact = criticalQuickWins > 0 ? "High" : "Medium",
                Effort = "Low",
                Rationale = "Automated fixes provide the best return on time invested."
            });
        }

        // Weakest module
        var weakest = posture.ModuleBreakdown.FirstOrDefault();
        if (weakest is { Score: < 70 })
        {
            recs.Add(new PostureRecommendation
            {
                Priority = ++priority,
                Category = "Module Focus",
                Action = $"Focus on {weakest.ModuleName} module (score: {weakest.Score}/100, " +
                         $"{weakest.CriticalCount} critical, {weakest.WarningCount} warning).",
                Impact = "Medium-High",
                Effort = "Medium",
                Rationale = "Improving the weakest module has the highest marginal impact on overall score."
            });
        }

        // Persistent issues
        if (posture.HasPersistenceData && posture.PersistentCount > 0)
        {
            recs.Add(new PostureRecommendation
            {
                Priority = ++priority,
                Category = "Chronic Issues",
                Action = $"Investigate {posture.PersistentCount} chronic finding{(posture.PersistentCount != 1 ? "s" : "")} " +
                         $"that persist across audits.",
                Impact = "Medium",
                Effort = "Medium-High",
                Rationale = "Persistent findings indicate systemic issues that won't resolve without targeted intervention."
            });
        }

        // Declining trend
        if (posture.TrendDirection == TrendDirection.Declining)
        {
            recs.Add(new PostureRecommendation
            {
                Priority = ++priority,
                Category = "Trend Alert",
                Action = "Investigate the declining security trend — score dropped " +
                         $"{Math.Abs(posture.ScoreDelta!.Value)} points since last audit.",
                Impact = "Medium",
                Effort = "Low",
                Rationale = "A declining trend may indicate new vulnerabilities, configuration drift, or disabled protections."
            });
        }

        // Compliance gap
        if (posture.ComplianceScore.HasValue && posture.ComplianceScore < 80)
        {
            recs.Add(new PostureRecommendation
            {
                Priority = ++priority,
                Category = "Compliance",
                Action = $"Close compliance gap for {posture.ComplianceProfile} " +
                         $"(current: {posture.ComplianceScore}/100, target: 80+).",
                Impact = "Medium-High",
                Effort = "Medium",
                Rationale = "Compliance failures may have regulatory or audit implications."
            });
        }

        // No issues — congratulations
        if (recs.Count == 0 && posture.OverallScore >= ScoreExcellent)
        {
            recs.Add(new PostureRecommendation
            {
                Priority = 1,
                Category = "Maintenance",
                Action = "Maintain current security posture with regular audits.",
                Impact = "Low",
                Effort = "Low",
                Rationale = "Excellent security posture — continue monitoring for regression."
            });
        }

        return recs;
    }

    // ── Formatting ───────────────────────────────────────────────────

    /// <summary>
    /// Format the posture report as a human-readable text summary.
    /// </summary>
    public static string FormatReport(PostureReport posture)
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine("═══════════════════════════════════════════════════════════════");
        sb.AppendLine("                  SECURITY POSTURE REPORT                     ");
        sb.AppendLine("═══════════════════════════════════════════════════════════════");
        sb.AppendLine();

        // Executive summary
        sb.AppendLine("── Executive Summary ──");
        sb.AppendLine(posture.ExecutiveSummary);
        sb.AppendLine();

        // Score card
        sb.AppendLine("── Score Card ──");
        sb.AppendLine($"  Overall Score:   {posture.OverallScore}/100 (Grade {posture.Grade})");
        sb.AppendLine($"  Posture Level:   {posture.PostureLevel}");
        if (posture.ScoreDelta.HasValue)
        {
            var arrow = posture.ScoreDelta.Value > 0 ? "↑" : posture.ScoreDelta.Value < 0 ? "↓" : "→";
            sb.AppendLine($"  Trend:           {arrow} {Math.Abs(posture.ScoreDelta.Value)} ({posture.TrendDirection})");
        }
        sb.AppendLine();

        // Finding summary
        sb.AppendLine("── Findings ──");
        sb.AppendLine($"  Total:           {posture.TotalFindings}");
        sb.AppendLine($"  Critical:        {posture.CriticalCount}");
        sb.AppendLine($"  Warning:         {posture.WarningCount}");
        sb.AppendLine($"  Info:            {posture.InfoCount}");
        sb.AppendLine($"  Auto-fixable:    {posture.AutoFixableCount}");
        if (posture.HasPersistenceData)
        {
            sb.AppendLine($"  New:             {posture.NewCount}");
            sb.AppendLine($"  Chronic:         {posture.PersistentCount}");
            sb.AppendLine($"  Resolved:        {posture.ResolvedCount}");
        }
        sb.AppendLine();

        // Module breakdown
        if (posture.ModuleBreakdown.Count > 0)
        {
            sb.AppendLine("── Module Health ──");
            foreach (var m in posture.ModuleBreakdown)
            {
                var bar = new string('█', m.Score / 5) + new string('░', 20 - m.Score / 5);
                sb.AppendLine($"  {m.ModuleName,-20} [{bar}] {m.Score,3}/100  {m.Health}");
            }
            sb.AppendLine();
        }

        // Top risks
        if (posture.TopRisks.Count > 0)
        {
            sb.AppendLine("── Top Risks ──");
            foreach (var (risk, i) in posture.TopRisks.Select((r, i) => (r, i)))
            {
                var icon = risk.Severity == Severity.Critical ? "🔴" : "🟡";
                var fix = risk.HasAutoFix ? " [auto-fix]" : "";
                sb.AppendLine($"  {i + 1}. {icon} [{risk.Module}] {risk.Title}{fix}");
            }
            sb.AppendLine();
        }

        // Quick wins
        if (posture.QuickWins.Count > 0)
        {
            sb.AppendLine("── Quick Wins ──");
            foreach (var qw in posture.QuickWins)
            {
                sb.AppendLine($"  • {qw.Title}");
                sb.AppendLine($"    Fix: {qw.FixCommand}");
            }
            sb.AppendLine();
        }

        // Recommendations
        if (posture.Recommendations.Count > 0)
        {
            sb.AppendLine("── Recommendations ──");
            foreach (var rec in posture.Recommendations)
            {
                sb.AppendLine($"  #{rec.Priority} [{rec.Category}] {rec.Action}");
                sb.AppendLine($"     Impact: {rec.Impact}  |  Effort: {rec.Effort}");
                sb.AppendLine($"     {rec.Rationale}");
            }
            sb.AppendLine();
        }

        // Compliance
        if (!string.IsNullOrWhiteSpace(posture.ComplianceStatus))
        {
            sb.AppendLine("── Compliance ──");
            sb.AppendLine($"  Profile:  {posture.ComplianceProfile}");
            sb.AppendLine($"  Score:    {posture.ComplianceScore}/100");
            sb.AppendLine($"  Status:   {posture.ComplianceStatus}");
            sb.AppendLine();
        }

        sb.AppendLine($"Generated: {posture.GeneratedAt:yyyy-MM-dd HH:mm:ss UTC}");
        sb.AppendLine("═══════════════════════════════════════════════════════════════");

        return sb.ToString();
    }
}

// ── Enums ────────────────────────────────────────────────────────────

/// <summary>Overall security posture classification.</summary>
public enum PostureLevel
{
    /// <summary>Score 90+: excellent security posture.</summary>
    Excellent,
    /// <summary>Score 70-89: good security posture.</summary>
    Good,
    /// <summary>Score 50-69: fair, needs improvement.</summary>
    Fair,
    /// <summary>Score 30-49: poor, significant risks.</summary>
    Poor,
    /// <summary>Score below 30: critical, immediate action needed.</summary>
    Critical
}

/// <summary>Individual module health status.</summary>
public enum ModuleHealth
{
    /// <summary>Score 90+ and no criticals.</summary>
    Healthy,
    /// <summary>Score 70-89, no criticals.</summary>
    Moderate,
    /// <summary>Score below 70, no criticals.</summary>
    NeedsAttention,
    /// <summary>Has critical findings but score >= 50.</summary>
    AtRisk,
    /// <summary>Has critical findings and score below 50.</summary>
    Critical
}

// ── Models ───────────────────────────────────────────────────────────

/// <summary>Complete security posture report.</summary>
public class PostureReport
{
    public DateTimeOffset GeneratedAt { get; set; }

    // ── Score ──
    public int OverallScore { get; set; }
    public string Grade { get; set; } = "";
    public PostureLevel PostureLevel { get; set; }
    public int? ScoreDelta { get; set; }
    public TrendDirection? TrendDirection { get; set; }

    // ── Finding summary ──
    public int TotalFindings { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    public int InfoCount { get; set; }
    public int PassCount { get; set; }
    public int AutoFixableCount { get; set; }

    // ── Persistence ──
    public bool HasPersistenceData { get; set; }
    public int PersistentCount { get; set; }
    public int NewCount { get; set; }
    public int ResolvedCount { get; set; }

    // ── Compliance ──
    public string? ComplianceProfile { get; set; }
    public int? ComplianceScore { get; set; }
    public string? ComplianceStatus { get; set; }

    // ── Details ──
    public List<ModulePosture> ModuleBreakdown { get; set; } = [];
    public List<RiskItem> TopRisks { get; set; } = [];
    public List<QuickWinItem> QuickWins { get; set; } = [];
    public List<PostureRecommendation> Recommendations { get; set; } = [];

    // ── Summary ──
    public string ExecutiveSummary { get; set; } = "";
}

/// <summary>Per-module posture detail.</summary>
public class ModulePosture
{
    public string ModuleName { get; set; } = "";
    public int Score { get; set; }
    public int FindingCount { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    public ModuleHealth Health { get; set; }
}

/// <summary>A top-risk finding.</summary>
public class RiskItem
{
    public string Title { get; set; } = "";
    public Severity Severity { get; set; }
    public string Module { get; set; } = "";
    public bool HasAutoFix { get; set; }
    public string Remediation { get; set; } = "";
}

/// <summary>An auto-fixable finding.</summary>
public class QuickWinItem
{
    public string Title { get; set; } = "";
    public Severity Severity { get; set; }
    public string FixCommand { get; set; } = "";
    public string Module { get; set; } = "";
    public string EstimatedImpact { get; set; } = "";
}

/// <summary>A prioritized recommendation.</summary>
public class PostureRecommendation
{
    public int Priority { get; set; }
    public string Category { get; set; } = "";
    public string Action { get; set; } = "";
    public string Impact { get; set; } = "";
    public string Effort { get; set; } = "";
    public string Rationale { get; set; } = "";
}
