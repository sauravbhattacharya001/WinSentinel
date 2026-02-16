using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Calculates security score from audit results.
/// </summary>
public static class SecurityScorer
{
    private const int MaxScore = 100;
    private const int CriticalPenalty = 15;
    private const int WarningPenalty = 5;
    private const int InfoPenalty = 1;

    /// <summary>
    /// Calculate security score (0-100) from a security report.
    /// </summary>
    public static int CalculateScore(SecurityReport report)
    {
        if (report.Results.Count == 0) return MaxScore;

        int totalDeductions = 0;

        foreach (var result in report.Results)
        {
            foreach (var finding in result.Findings)
            {
                totalDeductions += finding.Severity switch
                {
                    Severity.Critical => CriticalPenalty,
                    Severity.Warning => WarningPenalty,
                    Severity.Info => InfoPenalty,
                    _ => 0
                };
            }
        }

        return Math.Max(0, MaxScore - totalDeductions);
    }

    /// <summary>
    /// Calculate score for a single category.
    /// </summary>
    public static int CalculateCategoryScore(AuditResult result)
    {
        int deductions = 0;

        foreach (var finding in result.Findings)
        {
            deductions += finding.Severity switch
            {
                Severity.Critical => CriticalPenalty,
                Severity.Warning => WarningPenalty,
                Severity.Info => InfoPenalty,
                _ => 0
            };
        }

        return Math.Max(0, MaxScore - deductions);
    }

    /// <summary>
    /// Get a grade letter from a score.
    /// </summary>
    public static string GetGrade(int score) => score switch
    {
        >= 90 => "A",
        >= 80 => "B",
        >= 70 => "C",
        >= 60 => "D",
        _ => "F"
    };

    /// <summary>
    /// Get a color string for the score.
    /// </summary>
    public static string GetScoreColor(int score) => score switch
    {
        >= 80 => "#4CAF50", // Green
        >= 60 => "#FFC107", // Yellow
        >= 40 => "#FF9800", // Orange
        _ => "#F44336"      // Red
    };
}
