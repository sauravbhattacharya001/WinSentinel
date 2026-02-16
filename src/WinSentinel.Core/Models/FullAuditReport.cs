namespace WinSentinel.Core.Models;

/// <summary>
/// Aggregated results from all audit modules.
/// </summary>
public class FullAuditReport
{
    public List<AuditResult> Results { get; init; } = [];
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;

    /// <summary>
    /// Overall security score (0-100), weighted average of all module scores.
    /// </summary>
    public int OverallScore
    {
        get
        {
            if (Results.Count == 0) return 0;
            return (int)Results.Average(r => r.Score);
        }
    }

    public string Grade => OverallScore switch
    {
        >= 90 => "A",
        >= 80 => "B",
        >= 70 => "C",
        >= 60 => "D",
        _ => "F"
    };

    public int TotalCritical => Results.Sum(r => r.CriticalCount);
    public int TotalWarnings => Results.Sum(r => r.WarningCount);
    public int TotalFindings => Results.Sum(r => r.Findings.Count);
}
