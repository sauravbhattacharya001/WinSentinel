namespace WinSentinel.Core.Models;

/// <summary>
/// Result from a single audit module run.
/// </summary>
public class AuditResult
{
    public required string ModuleName { get; set; }
    public required string Category { get; set; }
    public List<Finding> Findings { get; set; } = new();
    public DateTimeOffset StartTime { get; set; }
    public DateTimeOffset EndTime { get; set; }
    public TimeSpan Duration => EndTime - StartTime;
    public bool Success { get; set; } = true;
    public string? Error { get; set; }

    public int CriticalCount => Findings.Count(f => f.Severity == Severity.Critical);
    public int WarningCount => Findings.Count(f => f.Severity == Severity.Warning);
    public int InfoCount => Findings.Count(f => f.Severity == Severity.Info);
    public int PassCount => Findings.Count(f => f.Severity == Severity.Pass);

    public Severity OverallSeverity
    {
        get
        {
            if (CriticalCount > 0) return Severity.Critical;
            if (WarningCount > 0) return Severity.Warning;
            if (InfoCount > 0) return Severity.Info;
            return Severity.Pass;
        }
    }
}
