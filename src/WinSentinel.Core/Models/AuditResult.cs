namespace WinSentinel.Core.Models;

/// <summary>
/// Result from a single audit module run.
/// </summary>
public class AuditResult
{
    /// <summary>Name of the audit module that produced this result.</summary>
    public required string ModuleName { get; set; }

    /// <summary>Category grouping for this audit (e.g. "Network", "System").</summary>
    public required string Category { get; set; }

    /// <summary>Individual security findings discovered during the audit.</summary>
    public List<Finding> Findings { get; set; } = new();

    /// <summary>When the audit module started running.</summary>
    public DateTimeOffset StartTime { get; set; }

    /// <summary>When the audit module finished.</summary>
    public DateTimeOffset EndTime { get; set; }

    /// <summary>Wall-clock duration of the audit run.</summary>
    public TimeSpan Duration => EndTime - StartTime;

    /// <summary>Whether the audit completed without errors.</summary>
    public bool Success { get; set; } = true;

    /// <summary>Error message if the audit failed.</summary>
    public string? Error { get; set; }

    /// <summary>Number of critical-severity findings.</summary>
    public int CriticalCount => Findings.Count(f => f.Severity == Severity.Critical);

    /// <summary>Number of warning-severity findings.</summary>
    public int WarningCount => Findings.Count(f => f.Severity == Severity.Warning);

    /// <summary>Number of informational findings.</summary>
    public int InfoCount => Findings.Count(f => f.Severity == Severity.Info);

    /// <summary>Number of passing (no-issue) findings.</summary>
    public int PassCount => Findings.Count(f => f.Severity == Severity.Pass);

    /// <summary>
    /// Computed score (0-100) based on finding severities.
    /// Delegates to <see cref="Services.SecurityScorer.CalculateCategoryScore"/>
    /// to keep the scoring formula in a single place.
    /// </summary>
    public int Score => Services.SecurityScorer.CalculateCategoryScore(this);

    /// <summary>
    /// The highest severity across all findings, or <see cref="Severity.Pass"/> if none.
    /// </summary>
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
