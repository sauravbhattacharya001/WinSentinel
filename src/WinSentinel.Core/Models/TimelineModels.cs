namespace WinSentinel.Core.Models;

/// <summary>
/// A single event in the security timeline.
/// </summary>
public class TimelineEvent
{
    /// <summary>When this event occurred (from the audit run timestamp).</summary>
    public DateTimeOffset Timestamp { get; set; }

    /// <summary>The audit run ID this event came from.</summary>
    public long RunId { get; set; }

    /// <summary>Type of timeline event.</summary>
    public TimelineEventType EventType { get; set; }

    /// <summary>Severity level of the event itself (how important is this change).</summary>
    public TimelineSeverity Severity { get; set; }

    /// <summary>Short title for the event.</summary>
    public string Title { get; set; } = "";

    /// <summary>Detailed description of what happened.</summary>
    public string Description { get; set; } = "";

    /// <summary>Module/category this event relates to (null for global events).</summary>
    public string? Module { get; set; }

    /// <summary>Finding title this event relates to (null for score/module events).</summary>
    public string? FindingTitle { get; set; }

    /// <summary>Score at the time of this event (overall or module score).</summary>
    public int? Score { get; set; }

    /// <summary>Previous score (for change events).</summary>
    public int? PreviousScore { get; set; }

    /// <summary>Score delta (positive = improvement, negative = regression).</summary>
    public int? ScoreDelta { get; set; }
}

/// <summary>
/// Types of security timeline events.
/// </summary>
public enum TimelineEventType
{
    /// <summary>A new finding appeared for the first time.</summary>
    FindingAppeared,

    /// <summary>A previously seen finding was resolved.</summary>
    FindingResolved,

    /// <summary>A finding's severity changed between runs.</summary>
    SeverityChanged,

    /// <summary>Overall security score improved.</summary>
    ScoreImproved,

    /// <summary>Overall security score regressed.</summary>
    ScoreRegressed,

    /// <summary>A module's score changed significantly.</summary>
    ModuleScoreChanged,

    /// <summary>First ever audit scan was recorded.</summary>
    InitialScan,

    /// <summary>Score reached a new all-time high.</summary>
    NewHighScore,

    /// <summary>Score dropped to a new all-time low.</summary>
    NewLowScore,

    /// <summary>A critical finding appeared.</summary>
    CriticalAlert,

    /// <summary>All critical findings were resolved.</summary>
    CriticalsClear
}

/// <summary>
/// How important/urgent the timeline event is.
/// </summary>
public enum TimelineSeverity
{
    Info,
    Notice,
    Warning,
    Critical
}

/// <summary>
/// Complete security timeline report.
/// </summary>
public class TimelineReport
{
    /// <summary>All timeline events in chronological order.</summary>
    public List<TimelineEvent> Events { get; set; } = [];

    /// <summary>Timeline summary statistics.</summary>
    public TimelineSummary Summary { get; set; } = new();

    /// <summary>Time range covered by this timeline.</summary>
    public DateTimeOffset? StartDate { get; set; }
    public DateTimeOffset? EndDate { get; set; }

    /// <summary>Number of audit runs analyzed.</summary>
    public int RunsAnalyzed { get; set; }

    /// <summary>Filter to specific severity or above (null = all).</summary>
    public TimelineSeverity? MinSeverity { get; set; }

    /// <summary>Filter to specific module (null = all).</summary>
    public string? ModuleFilter { get; set; }

    /// <summary>Filter to specific event types (null = all).</summary>
    public List<TimelineEventType>? EventTypeFilter { get; set; }
}

/// <summary>
/// Summary statistics for a timeline.
/// </summary>
public class TimelineSummary
{
    /// <summary>Total events in the timeline.</summary>
    public int TotalEvents { get; set; }

    /// <summary>Findings that appeared and were later resolved.</summary>
    public int FindingsResolved { get; set; }

    /// <summary>Findings that appeared and are still present.</summary>
    public int FindingsStillOpen { get; set; }

    /// <summary>Number of score improvements.</summary>
    public int ScoreImprovements { get; set; }

    /// <summary>Number of score regressions.</summary>
    public int ScoreRegressions { get; set; }

    /// <summary>Total score change from first to last run.</summary>
    public int NetScoreChange { get; set; }

    /// <summary>Number of critical alerts raised.</summary>
    public int CriticalAlerts { get; set; }

    /// <summary>Average time to resolve a finding (from appeared to resolved).</summary>
    public TimeSpan? AverageTimeToResolve { get; set; }

    /// <summary>Fastest resolution time.</summary>
    public TimeSpan? FastestResolution { get; set; }

    /// <summary>Slowest resolution time.</summary>
    public TimeSpan? SlowestResolution { get; set; }

    /// <summary>Breakdown of events by type.</summary>
    public Dictionary<TimelineEventType, int> EventsByType { get; set; } = new();
}
