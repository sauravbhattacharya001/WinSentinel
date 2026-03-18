namespace WinSentinel.Core.Models;

/// <summary>
/// Tracks a finding that alternates between present and absent across audit runs.
/// </summary>
public class FlappingFinding
{
    /// <summary>Finding title (identity key).</summary>
    public string Title { get; set; } = "";

    /// <summary>Module that reports this finding.</summary>
    public string ModuleName { get; set; } = "";

    /// <summary>Current severity level.</summary>
    public string Severity { get; set; } = "";

    /// <summary>Number of state transitions (present→absent or absent→present).</summary>
    public int Transitions { get; set; }

    /// <summary>Total audit runs where this finding appeared.</summary>
    public int PresentCount { get; set; }

    /// <summary>Total audit runs where this finding was absent.</summary>
    public int AbsentCount { get; set; }

    /// <summary>Total audit runs analyzed.</summary>
    public int TotalRuns { get; set; }

    /// <summary>Whether the finding is present in the most recent run.</summary>
    public bool CurrentlyPresent { get; set; }

    /// <summary>First seen timestamp.</summary>
    public DateTimeOffset FirstSeen { get; set; }

    /// <summary>Last seen timestamp.</summary>
    public DateTimeOffset LastSeen { get; set; }

    /// <summary>
    /// Flap rate: transitions / (totalRuns - 1). Range 0.0 (stable) to 1.0 (every run flips).
    /// </summary>
    public double FlapRate => TotalRuns > 1
        ? (double)Transitions / (TotalRuns - 1)
        : 0;

    /// <summary>
    /// Stability score: 0 = wildly unstable, 100 = perfectly stable.
    /// </summary>
    public int StabilityScore => Math.Max(0, (int)((1.0 - FlapRate) * 100));

    /// <summary>
    /// Classification based on flap rate.
    /// </summary>
    public string Classification => FlapRate switch
    {
        >= 0.7 => "Highly Unstable",
        >= 0.4 => "Unstable",
        >= 0.2 => "Intermittent",
        _ => "Mostly Stable"
    };

    /// <summary>
    /// Pattern string showing presence (█) / absence (░) across recent runs.
    /// </summary>
    public string Pattern { get; set; } = "";
}

/// <summary>
/// Summary statistics from flapping analysis.
/// </summary>
public class FlappingSummary
{
    /// <summary>Total unique findings that appeared at least once.</summary>
    public int TotalFindings { get; set; }

    /// <summary>Number of findings classified as flapping (flapRate >= 0.2).</summary>
    public int FlappingCount { get; set; }

    /// <summary>Number of highly unstable findings (flapRate >= 0.7).</summary>
    public int HighlyUnstableCount { get; set; }

    /// <summary>Number of unstable findings (flapRate >= 0.4).</summary>
    public int UnstableCount { get; set; }

    /// <summary>Number of intermittent findings (flapRate >= 0.2).</summary>
    public int IntermittentCount { get; set; }

    /// <summary>Average flap rate across all flapping findings.</summary>
    public double AverageFlapRate { get; set; }

    /// <summary>Module with the most flapping findings.</summary>
    public string? MostUnstableModule { get; set; }

    /// <summary>Number of flapping findings in the most unstable module.</summary>
    public int MostUnstableModuleCount { get; set; }

    /// <summary>Number of audit runs analyzed.</summary>
    public int RunsAnalyzed { get; set; }

    /// <summary>
    /// Overall stability grade. A = very stable, F = chaotic.
    /// </summary>
    public string StabilityGrade { get; set; } = "N/A";

    /// <summary>Breakdown of flapping findings by module.</summary>
    public Dictionary<string, int> FlappingByModule { get; set; } = new();

    /// <summary>Breakdown of flapping findings by severity.</summary>
    public Dictionary<string, int> FlappingBySeverity { get; set; } = new();
}

/// <summary>
/// Full flapping analysis report.
/// </summary>
public class FlappingReport
{
    /// <summary>All findings that show flapping behavior (flapRate >= 0.2).</summary>
    public List<FlappingFinding> Findings { get; set; } = [];

    /// <summary>Summary statistics.</summary>
    public FlappingSummary Summary { get; set; } = new();

    /// <summary>Whether there is enough data to analyze.</summary>
    public bool HasData { get; set; }
}
