namespace WinSentinel.Core.Models;

/// <summary>
/// Tracks a single finding's lifecycle across multiple audit runs.
/// </summary>
public class FindingLifecycle
{
    /// <summary>Finding title (used as the identity key).</summary>
    public string Title { get; set; } = "";

    /// <summary>Module that reports this finding.</summary>
    public string ModuleName { get; set; } = "";

    /// <summary>Current severity level.</summary>
    public string Severity { get; set; } = "";

    /// <summary>Timestamp of the first audit run where this finding appeared.</summary>
    public DateTimeOffset FirstSeen { get; set; }

    /// <summary>Timestamp of the most recent audit run where this finding appeared.</summary>
    public DateTimeOffset LastSeen { get; set; }

    /// <summary>
    /// Timestamp when this finding was resolved (no longer appeared in a
    /// subsequent run), or null if it is still active.
    /// </summary>
    public DateTimeOffset? ResolvedAt { get; set; }

    /// <summary>Number of consecutive audit runs where this finding has appeared.</summary>
    public int ConsecutiveRuns { get; set; }

    /// <summary>Total number of audit runs where this finding appeared.</summary>
    public int TotalOccurrences { get; set; }

    /// <summary>Total number of audit runs in the analysis window.</summary>
    public int TotalRunsAnalyzed { get; set; }

    /// <summary>Whether the finding is still present in the latest audit run.</summary>
    public bool IsActive { get; set; }

    /// <summary>
    /// Age of the finding (time between first seen and resolved/now).
    /// </summary>
    public TimeSpan Age => IsActive
        ? DateTimeOffset.UtcNow - FirstSeen
        : (ResolvedAt ?? LastSeen) - FirstSeen;

    /// <summary>
    /// Human-readable age string (e.g. "3d 2h", "45m", "1.2h").
    /// </summary>
    public string AgeText
    {
        get
        {
            var age = Age;
            if (age.TotalDays >= 1) return $"{age.TotalDays:F0}d {age.Hours}h";
            if (age.TotalHours >= 1) return $"{age.TotalHours:F1}h";
            return $"{age.TotalMinutes:F0}m";
        }
    }

    /// <summary>
    /// Frequency ratio: how often this finding appears relative to total runs.
    /// </summary>
    public double Frequency => TotalRunsAnalyzed > 0
        ? (double)TotalOccurrences / TotalRunsAnalyzed
        : 0;

    /// <summary>
    /// Priority score combining severity weight and age in hours.
    /// Higher means more urgent to fix.
    /// </summary>
    public double PriorityScore
    {
        get
        {
            var severityWeight = Severity.ToUpperInvariant() switch
            {
                "CRITICAL" => 4.0,
                "WARNING" => 2.0,
                "INFO" => 1.0,
                _ => 0.5
            };
            // Score = severity × log2(ageHours + 1) × frequency
            var ageHours = Math.Max(Age.TotalHours, 0.01);
            return severityWeight * Math.Log2(ageHours + 1) * Math.Max(Frequency, 0.1);
        }
    }

    /// <summary>
    /// Classification based on persistence pattern.
    /// </summary>
    public string Classification
    {
        get
        {
            if (!IsActive) return "Resolved";
            if (TotalOccurrences == 1) return "New";
            if (Frequency >= 0.9) return "Chronic";
            if (Frequency >= 0.5) return "Recurring";
            return "Intermittent";
        }
    }
}

/// <summary>
/// Summary statistics from finding age analysis.
/// </summary>
public class FindingAgeSummary
{
    /// <summary>Total number of unique findings tracked.</summary>
    public int TotalFindings { get; set; }

    /// <summary>Number of currently active (unresolved) findings.</summary>
    public int ActiveFindings { get; set; }

    /// <summary>Number of findings resolved during the analysis window.</summary>
    public int ResolvedFindings { get; set; }

    /// <summary>Number of chronic findings (frequency >= 90%).</summary>
    public int ChronicFindings { get; set; }

    /// <summary>Number of new findings (seen only in the latest run).</summary>
    public int NewFindings { get; set; }

    /// <summary>Mean time to resolve in hours (null if no findings were resolved).</summary>
    public double? MeanTimeToResolveHours { get; set; }

    /// <summary>Median time to resolve in hours (null if no findings were resolved).</summary>
    public double? MedianTimeToResolveHours { get; set; }

    /// <summary>Age of the oldest active finding in hours.</summary>
    public double? OldestActiveFindingHours { get; set; }

    /// <summary>Title of the oldest active finding.</summary>
    public string? OldestActiveFindingTitle { get; set; }

    /// <summary>Average age of all active findings in hours.</summary>
    public double? AverageActiveAgeHours { get; set; }

    /// <summary>Number of audit runs analyzed.</summary>
    public int RunsAnalyzed { get; set; }

    /// <summary>Breakdown of active findings by severity.</summary>
    public Dictionary<string, int> ActiveBySeverity { get; set; } = new();

    /// <summary>Breakdown of active findings by classification.</summary>
    public Dictionary<string, int> ActiveByClassification { get; set; } = new();

    /// <summary>Breakdown of active findings by module.</summary>
    public Dictionary<string, int> ActiveByModule { get; set; } = new();

    /// <summary>
    /// "Health" grade based on chronic finding ratio and MTTR.
    /// A = excellent, F = needs attention.
    /// </summary>
    public string HealthGrade { get; set; } = "N/A";

    /// <summary>Human-readable summary text.</summary>
    public string SummaryText { get; set; } = "";
}

/// <summary>
/// Full age analysis report.
/// </summary>
public class FindingAgeReport
{
    /// <summary>All tracked finding lifecycles.</summary>
    public List<FindingLifecycle> Findings { get; set; } = [];

    /// <summary>Summary statistics.</summary>
    public FindingAgeSummary Summary { get; set; } = new();

    /// <summary>Active findings sorted by priority score (highest first).</summary>
    public List<FindingLifecycle> PriorityQueue =>
        Findings.Where(f => f.IsActive)
                .OrderByDescending(f => f.PriorityScore)
                .ToList();

    /// <summary>Chronic findings (frequency >= 90%).</summary>
    public List<FindingLifecycle> ChronicFindings =>
        Findings.Where(f => f.IsActive && f.Classification == "Chronic")
                .OrderByDescending(f => f.PriorityScore)
                .ToList();

    /// <summary>Newly appeared findings.</summary>
    public List<FindingLifecycle> NewFindings =>
        Findings.Where(f => f.IsActive && f.Classification == "New")
                .OrderByDescending(f => f.PriorityScore)
                .ToList();

    /// <summary>Recently resolved findings.</summary>
    public List<FindingLifecycle> ResolvedFindings =>
        Findings.Where(f => !f.IsActive)
                .OrderByDescending(f => f.ResolvedAt)
                .ToList();

    /// <summary>Get findings for a specific module.</summary>
    public List<FindingLifecycle> GetByModule(string moduleName) =>
        Findings.Where(f => f.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(f => f.PriorityScore)
                .ToList();

    /// <summary>Get findings by severity.</summary>
    public List<FindingLifecycle> GetBySeverity(string severity) =>
        Findings.Where(f => f.Severity.Equals(severity, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(f => f.PriorityScore)
                .ToList();
}
