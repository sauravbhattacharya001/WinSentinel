using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates a concise executive security digest combining current audit results,
/// trend data, top risks, and prioritized next steps into a single report.
/// </summary>
public class SecurityDigestService
{
    /// <summary>
    /// Generate a digest from current audit results and optional historical data.
    /// </summary>
    public SecurityDigest Generate(SecurityReport report, List<AuditRunRecord>? history = null)
    {
        var digest = new SecurityDigest
        {
            GeneratedAt = DateTimeOffset.Now,
            MachineName = Environment.MachineName,
            Score = report.SecurityScore,
            Grade = SecurityScorer.GetGrade(report.SecurityScore),
            TotalFindings = report.TotalFindings,
            CriticalCount = report.TotalCritical,
            WarningCount = report.TotalWarnings,
            InfoCount = report.TotalInfo,
            PassCount = report.TotalPass,
        };

        // Top risks: critical first, then warnings, limited to 5
        var topFindings = report.Results
            .SelectMany(r => r.Findings.Select(f => new DigestFinding
            {
                Title = f.Title,
                Severity = f.Severity,
                Category = f.Category,
                Remediation = f.Remediation,
                HasAutoFix = !string.IsNullOrWhiteSpace(f.FixCommand)
            }))
            .Where(f => f.Severity is Severity.Critical or Severity.Warning)
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Title)
            .Take(5)
            .ToList();

        digest.TopRisks = topFindings;

        // Module breakdown: worst-scoring modules first
        digest.ModuleBreakdown = report.Results
            .Select(r => new DigestModule
            {
                Name = r.Category,
                Score = SecurityScorer.CalculateCategoryScore(r),
                Critical = r.CriticalCount,
                Warnings = r.WarningCount,
                Status = r.CriticalCount > 0 ? "Critical"
                       : r.WarningCount > 0 ? "Warning"
                       : "Good"
            })
            .OrderBy(m => m.Score)
            .ToList();

        // Trend data if history available
        if (history != null && history.Count >= 2)
        {
            var chronological = history.OrderBy(r => r.Timestamp).ToList();
            var latest = chronological.Last();
            var previous = chronological[^2];

            digest.Trend = new DigestTrend
            {
                PreviousScore = previous.OverallScore,
                ScoreChange = latest.OverallScore - previous.OverallScore,
                Direction = latest.OverallScore > previous.OverallScore ? "Improving"
                          : latest.OverallScore < previous.OverallScore ? "Declining"
                          : "Stable",
                TotalScans = chronological.Count,
                BestScore = chronological.Max(r => r.OverallScore),
                WorstScore = chronological.Min(r => r.OverallScore),
                AverageScore = (int)Math.Round(chronological.Average(r => (double)r.OverallScore)),
                FirstScanDate = chronological.First().Timestamp,
                LastScanDate = latest.Timestamp,
            };

            // Calculate streak
            int streak = 0;
            for (int i = chronological.Count - 1; i >= 1; i--)
            {
                var diff = chronological[i].OverallScore - chronological[i - 1].OverallScore;
                if (digest.Trend.ScoreChange > 0 && diff > 0) streak++;
                else if (digest.Trend.ScoreChange < 0 && diff < 0) streak++;
                else if (digest.Trend.ScoreChange == 0 && diff == 0) streak++;
                else break;
            }
            digest.Trend.Streak = streak;
        }

        // Generate actionable next steps
        digest.NextSteps = GenerateNextSteps(report, digest);

        // Overall assessment
        digest.Assessment = GenerateAssessment(digest);

        return digest;
    }

    private List<string> GenerateNextSteps(SecurityReport report, SecurityDigest digest)
    {
        var steps = new List<string>();

        // Count auto-fixable
        var autoFixable = report.Results
            .SelectMany(r => r.Findings)
            .Count(f => f.Severity is Severity.Critical or Severity.Warning
                     && !string.IsNullOrWhiteSpace(f.FixCommand));

        if (digest.CriticalCount > 0)
        {
            steps.Add($"Address {digest.CriticalCount} critical finding(s) immediately — run `winsentinel --fix-all` to auto-fix {autoFixable} issue(s)");
        }
        else if (autoFixable > 0)
        {
            steps.Add($"Run `winsentinel --fix-all` to auto-fix {autoFixable} warning(s)");
        }

        // Worst module suggestion
        var worstModule = digest.ModuleBreakdown.FirstOrDefault(m => m.Score < 80);
        if (worstModule != null)
        {
            steps.Add($"Focus on {worstModule.Name} (score: {worstModule.Score}/100) — run `winsentinel --audit -m {worstModule.Name.ToLowerInvariant().Replace(" ", "")}` for details");
        }

        if (digest.Trend != null && digest.Trend.Direction == "Declining")
        {
            steps.Add($"Score has dropped {Math.Abs(digest.Trend.ScoreChange)} points — review recent changes with `winsentinel --history --diff`");
        }

        if (digest.Score >= 90 && digest.CriticalCount == 0)
        {
            steps.Add("Strong posture! Consider saving a baseline: `winsentinel --baseline save good-state`");
        }

        if (steps.Count == 0)
        {
            steps.Add("System is in good shape — no immediate action required");
        }

        return steps;
    }

    private string GenerateAssessment(SecurityDigest digest)
    {
        if (digest.CriticalCount > 0)
        {
            return $"ATTENTION REQUIRED: {digest.CriticalCount} critical security issue(s) detected. Immediate remediation recommended.";
        }

        if (digest.Score >= 90)
        {
            var trendNote = digest.Trend?.Direction == "Improving" ? " and improving" : "";
            return $"Excellent security posture{trendNote}. {digest.WarningCount} minor warning(s) remain.";
        }

        if (digest.Score >= 70)
        {
            return $"Good security posture with room for improvement. {digest.WarningCount} warning(s) should be reviewed.";
        }

        if (digest.Score >= 50)
        {
            return $"Fair security posture — several issues need attention. Review the {digest.WarningCount} warning(s) and apply recommended fixes.";
        }

        return $"Poor security posture — significant remediation needed. {digest.CriticalCount} critical and {digest.WarningCount} warning findings require action.";
    }
}

/// <summary>
/// Executive security digest — a concise summary of system security state.
/// </summary>
public class SecurityDigest
{
    public DateTimeOffset GeneratedAt { get; set; }
    public string MachineName { get; set; } = "";
    public int Score { get; set; }
    public string Grade { get; set; } = "";
    public int TotalFindings { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    public int InfoCount { get; set; }
    public int PassCount { get; set; }
    public string Assessment { get; set; } = "";
    public List<DigestFinding> TopRisks { get; set; } = new();
    public List<DigestModule> ModuleBreakdown { get; set; } = new();
    public DigestTrend? Trend { get; set; }
    public List<string> NextSteps { get; set; } = new();
}

public class DigestFinding
{
    public string Title { get; set; } = "";
    public Severity Severity { get; set; }
    public string Category { get; set; } = "";
    public string? Remediation { get; set; }
    public bool HasAutoFix { get; set; }
}

public class DigestModule
{
    public string Name { get; set; } = "";
    public int Score { get; set; }
    public int Critical { get; set; }
    public int Warnings { get; set; }
    public string Status { get; set; } = "";
}

public class DigestTrend
{
    public int PreviousScore { get; set; }
    public int ScoreChange { get; set; }
    public string Direction { get; set; } = "";
    public int TotalScans { get; set; }
    public int BestScore { get; set; }
    public int WorstScore { get; set; }
    public int AverageScore { get; set; }
    public int Streak { get; set; }
    public DateTimeOffset FirstScanDate { get; set; }
    public DateTimeOffset LastScanDate { get; set; }
}
