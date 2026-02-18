namespace WinSentinel.Core.Models;

/// <summary>
/// A saved security baseline snapshot that captures the expected security state.
/// Users can compare current audits against a baseline to detect deviations.
/// </summary>
public class SecurityBaseline
{
    /// <summary>Unique name for this baseline (e.g., "production", "post-hardening").</summary>
    public string Name { get; set; } = "";

    /// <summary>Optional description of what this baseline represents.</summary>
    public string? Description { get; set; }

    /// <summary>When this baseline was created.</summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Machine name where the baseline was captured.</summary>
    public string MachineName { get; set; } = Environment.MachineName;

    /// <summary>Overall security score at baseline time.</summary>
    public int OverallScore { get; set; }

    /// <summary>Grade at baseline time.</summary>
    public string Grade { get; set; } = "";

    /// <summary>Per-module scores at baseline time.</summary>
    public List<BaselineModuleScore> ModuleScores { get; set; } = [];

    /// <summary>All findings present at baseline time (the "known state").</summary>
    public List<BaselineFinding> Findings { get; set; } = [];

    /// <summary>Total finding counts at baseline time.</summary>
    public int TotalFindings { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    public int InfoCount { get; set; }
    public int PassCount { get; set; }
}

/// <summary>
/// Module score snapshot within a baseline.
/// </summary>
public class BaselineModuleScore
{
    public string ModuleName { get; set; } = "";
    public string Category { get; set; } = "";
    public int Score { get; set; }
    public int FindingCount { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
}

/// <summary>
/// A finding snapshot within a baseline.
/// </summary>
public class BaselineFinding
{
    public string ModuleName { get; set; } = "";
    public string Title { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Description { get; set; } = "";
    public string? Remediation { get; set; }
}

/// <summary>
/// Result of checking the current audit against a saved baseline.
/// </summary>
public class BaselineCheckResult
{
    /// <summary>The baseline being checked against.</summary>
    public SecurityBaseline Baseline { get; set; } = new();

    /// <summary>Current audit score.</summary>
    public int CurrentScore { get; set; }

    /// <summary>Score change from baseline.</summary>
    public int ScoreChange => CurrentScore - Baseline.OverallScore;

    /// <summary>Whether the current state meets or exceeds the baseline score.</summary>
    public bool ScorePassed => CurrentScore >= Baseline.OverallScore;

    /// <summary>New findings not present in the baseline (regressions).</summary>
    public List<BaselineFinding> Regressions { get; set; } = [];

    /// <summary>Findings that were in the baseline but are now resolved (improvements).</summary>
    public List<BaselineFinding> Resolved { get; set; } = [];

    /// <summary>Findings present in both baseline and current (unchanged).</summary>
    public List<BaselineFinding> Unchanged { get; set; } = [];

    /// <summary>Per-module score deviations from baseline.</summary>
    public List<BaselineModuleDeviation> ModuleDeviations { get; set; } = [];

    /// <summary>Overall pass/fail: no regressions in Critical/Warning and score not decreased.</summary>
    public bool Passed => ScorePassed && Regressions.All(r =>
        r.Severity != "Critical" && r.Severity != "Warning");

    /// <summary>Number of critical regressions.</summary>
    public int CriticalRegressions => Regressions.Count(r => r.Severity == "Critical");

    /// <summary>Number of warning regressions.</summary>
    public int WarningRegressions => Regressions.Count(r => r.Severity == "Warning");
}

/// <summary>
/// Per-module deviation from baseline.
/// </summary>
public class BaselineModuleDeviation
{
    public string ModuleName { get; set; } = "";
    public string Category { get; set; } = "";
    public int BaselineScore { get; set; }
    public int CurrentScore { get; set; }
    public int ScoreChange => CurrentScore - BaselineScore;
    public string Status => ScoreChange > 0 ? "Improved" : ScoreChange < 0 ? "Regressed" : "Unchanged";
}

/// <summary>
/// Summary entry for listing saved baselines.
/// </summary>
public class BaselineSummary
{
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public string MachineName { get; set; } = "";
    public int OverallScore { get; set; }
    public string Grade { get; set; } = "";
    public int TotalFindings { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
}
