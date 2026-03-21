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
    /// <summary>Display name of the audit module.</summary>
    public string ModuleName { get; set; } = "";

    /// <summary>Category grouping (e.g. "Firewall", "Network").</summary>
    public string Category { get; set; } = "";

    /// <summary>Module security score (0-100) at baseline capture time.</summary>
    public int Score { get; set; }

    /// <summary>Total findings in this module at baseline time.</summary>
    public int FindingCount { get; set; }

    /// <summary>Critical-severity findings at baseline time.</summary>
    public int CriticalCount { get; set; }

    /// <summary>Warning-severity findings at baseline time.</summary>
    public int WarningCount { get; set; }
}

/// <summary>
/// A finding snapshot within a baseline, used for regression detection.
/// </summary>
public class BaselineFinding
{
    /// <summary>Audit module that produced this finding.</summary>
    public string ModuleName { get; set; } = "";

    /// <summary>Short title describing the finding.</summary>
    public string Title { get; set; } = "";

    /// <summary>Severity level as a string (e.g. "Critical", "Warning").</summary>
    public string Severity { get; set; } = "";

    /// <summary>Detailed description of the finding.</summary>
    public string Description { get; set; } = "";

    /// <summary>Suggested remediation steps, if available.</summary>
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
/// Per-module score deviation from baseline, showing improvement or regression.
/// </summary>
public class BaselineModuleDeviation
{
    /// <summary>Audit module name.</summary>
    public string ModuleName { get; set; } = "";

    /// <summary>Module category.</summary>
    public string Category { get; set; } = "";

    /// <summary>Score recorded in the baseline.</summary>
    public int BaselineScore { get; set; }

    /// <summary>Current scan score for this module.</summary>
    public int CurrentScore { get; set; }

    /// <summary>Score delta (positive = improved, negative = regressed).</summary>
    public int ScoreChange => CurrentScore - BaselineScore;

    /// <summary>Human-readable status: "Improved", "Regressed", or "Unchanged".</summary>
    public string Status => ScoreChange > 0 ? "Improved" : ScoreChange < 0 ? "Regressed" : "Unchanged";
}

/// <summary>
/// Lightweight summary for listing saved baselines without loading full finding data.
/// </summary>
public class BaselineSummary
{
    /// <summary>Baseline name identifier.</summary>
    public string Name { get; set; } = "";

    /// <summary>Optional description.</summary>
    public string? Description { get; set; }

    /// <summary>When the baseline was captured.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Machine where the baseline was taken.</summary>
    public string MachineName { get; set; } = "";

    /// <summary>Overall security score at baseline time.</summary>
    public int OverallScore { get; set; }

    /// <summary>Letter grade at baseline time.</summary>
    public string Grade { get; set; } = "";

    /// <summary>Total finding count.</summary>
    public int TotalFindings { get; set; }

    /// <summary>Critical finding count.</summary>
    public int CriticalCount { get; set; }

    /// <summary>Warning finding count.</summary>
    public int WarningCount { get; set; }
}
