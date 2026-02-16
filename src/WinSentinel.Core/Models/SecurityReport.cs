namespace WinSentinel.Core.Models;

/// <summary>
/// Aggregated result from running all audit modules.
/// </summary>
public class SecurityReport
{
    public List<AuditResult> Results { get; set; } = new();
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;
    public int SecurityScore { get; set; }

    public int TotalFindings => Results.Sum(r => r.Findings.Count);
    public int TotalCritical => Results.Sum(r => r.CriticalCount);
    public int TotalWarnings => Results.Sum(r => r.WarningCount);
    public int TotalInfo => Results.Sum(r => r.InfoCount);
    public int TotalPass => Results.Sum(r => r.PassCount);
}
