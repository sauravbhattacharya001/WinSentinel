namespace WinSentinel.Core.Models;

/// <summary>
/// Aggregated result from running all audit modules.
/// </summary>
public class SecurityReport
{
    /// <summary>Results from each individual audit module.</summary>
    public List<AuditResult> Results { get; set; } = new();

    /// <summary>When this report was generated.</summary>
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Overall security score (0-100).</summary>
    public int SecurityScore { get; set; }

    /// <summary>Total number of findings across all modules.</summary>
    public int TotalFindings => Results.Sum(r => r.Findings.Count);

    /// <summary>Total critical-severity findings across all modules.</summary>
    public int TotalCritical => Results.Sum(r => r.CriticalCount);

    /// <summary>Total warning-severity findings across all modules.</summary>
    public int TotalWarnings => Results.Sum(r => r.WarningCount);

    /// <summary>Total informational findings across all modules.</summary>
    public int TotalInfo => Results.Sum(r => r.InfoCount);

    /// <summary>Total passing findings across all modules.</summary>
    public int TotalPass => Results.Sum(r => r.PassCount);
}
