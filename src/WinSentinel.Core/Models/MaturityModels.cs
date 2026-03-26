namespace WinSentinel.Core.Models;

/// <summary>
/// Security maturity level (1-5) following CMMI-style grading.
/// </summary>
public enum MaturityLevel
{
    /// <summary>Level 1 – Ad-hoc / Initial: security is reactive and unstructured.</summary>
    Initial = 1,

    /// <summary>Level 2 – Repeatable: basic controls exist but inconsistently applied.</summary>
    Repeatable = 2,

    /// <summary>Level 3 – Defined: security practices are documented and followed.</summary>
    Defined = 3,

    /// <summary>Level 4 – Managed: security is measured and monitored.</summary>
    Managed = 4,

    /// <summary>Level 5 – Optimizing: continuous improvement with proactive measures.</summary>
    Optimizing = 5
}

/// <summary>
/// A single security domain with its maturity assessment.
/// </summary>
public sealed class MaturityDomain
{
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public MaturityLevel Level { get; init; } = MaturityLevel.Initial;
    public int Score { get; init; }
    public int MaxScore { get; init; }
    public double Percentage => MaxScore > 0 ? Math.Round(Score * 100.0 / MaxScore, 1) : 0;
    public string[] Strengths { get; init; } = [];
    public string[] Gaps { get; init; } = [];
    public string[] Recommendations { get; init; } = [];
}

/// <summary>
/// Overall maturity assessment result.
/// </summary>
public sealed class MaturityAssessment
{
    public MaturityLevel OverallLevel { get; init; } = MaturityLevel.Initial;
    public double OverallScore { get; init; }
    public string Grade { get; init; } = "F";
    public List<MaturityDomain> Domains { get; init; } = [];
    public string[] TopPriorities { get; init; } = [];
    public DateTime AssessedAt { get; init; } = DateTime.UtcNow;
    public int TotalFindings { get; init; }
    public int CriticalFindings { get; init; }
    public int WarningFindings { get; init; }
}
