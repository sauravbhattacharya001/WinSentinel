namespace WinSentinel.Core.Models;

/// <summary>Predicted decay trajectory for a finding.</summary>
public enum DecayTrajectory
{
    /// <summary>Finding is stable — low escalation risk.</summary>
    Stable,
    /// <summary>Finding is slowly degrading — may escalate in weeks/months.</summary>
    SlowDecay,
    /// <summary>Finding is actively decaying — escalation likely within days.</summary>
    ActiveDecay,
    /// <summary>Finding is in rapid decay — imminent escalation.</summary>
    RapidDecay,
    /// <summary>Finding has already exceeded expected escalation time.</summary>
    Overdue
}

/// <summary>Risk tier for prioritization based on decay urgency.</summary>
public enum DecayUrgency
{
    /// <summary>No action needed soon.</summary>
    Low,
    /// <summary>Should be addressed within weeks.</summary>
    Medium,
    /// <summary>Should be addressed within days.</summary>
    High,
    /// <summary>Immediate attention required.</summary>
    Critical
}

/// <summary>A single finding's decay prediction.</summary>
public class FindingDecayPrediction
{
    /// <summary>The finding being analyzed.</summary>
    public required string FindingTitle { get; set; }

    /// <summary>Current severity.</summary>
    public Severity CurrentSeverity { get; set; }

    /// <summary>Predicted next severity level.</summary>
    public Severity PredictedNextSeverity { get; set; }

    /// <summary>Category of the finding.</summary>
    public string Category { get; set; } = string.Empty;

    /// <summary>Age of the finding in days.</summary>
    public double AgeDays { get; set; }

    /// <summary>Predicted days until severity escalation.</summary>
    public double DaysToEscalation { get; set; }

    /// <summary>Decay trajectory classification.</summary>
    public DecayTrajectory Trajectory { get; set; }

    /// <summary>Urgency tier for prioritization.</summary>
    public DecayUrgency Urgency { get; set; }

    /// <summary>Decay velocity: rate of risk accumulation (0-1 per day).</summary>
    public double DecayVelocity { get; set; }

    /// <summary>Exposure multiplier based on category risk profile.</summary>
    public double ExposureMultiplier { get; set; }

    /// <summary>Confidence in the prediction (0-100).</summary>
    public int Confidence { get; set; }

    /// <summary>Recommended intervention window description.</summary>
    public string InterventionWindow { get; set; } = string.Empty;
}

/// <summary>Category-level decay summary.</summary>
public class CategoryDecaySummary
{
    /// <summary>Category name.</summary>
    public required string Category { get; set; }

    /// <summary>Number of findings in this category.</summary>
    public int FindingCount { get; set; }

    /// <summary>Average days to escalation across findings.</summary>
    public double AvgDaysToEscalation { get; set; }

    /// <summary>Number of findings with critical urgency.</summary>
    public int CriticalUrgencyCount { get; set; }

    /// <summary>Number of findings with high urgency.</summary>
    public int HighUrgencyCount { get; set; }

    /// <summary>Overall category decay health (0-100, higher is healthier).</summary>
    public int HealthScore { get; set; }
}

/// <summary>Full decay prediction report.</summary>
public class DecayPredictionReport
{
    /// <summary>When the analysis was performed.</summary>
    public DateTimeOffset AnalyzedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Total findings analyzed.</summary>
    public int TotalFindings { get; set; }

    /// <summary>Findings predicted to escalate within 7 days.</summary>
    public int EscalatingWithin7Days { get; set; }

    /// <summary>Findings predicted to escalate within 30 days.</summary>
    public int EscalatingWithin30Days { get; set; }

    /// <summary>Findings already overdue for escalation.</summary>
    public int OverdueCount { get; set; }

    /// <summary>Overall decay health score (0-100, higher means less decay pressure).</summary>
    public int HealthScore { get; set; }

    /// <summary>Individual finding predictions, sorted by urgency.</summary>
    public List<FindingDecayPrediction> Predictions { get; set; } = [];

    /// <summary>Per-category summaries.</summary>
    public List<CategoryDecaySummary> CategorySummaries { get; set; } = [];

    /// <summary>Autonomous recommendations for addressing decay.</summary>
    public List<string> Recommendations { get; set; } = [];

    /// <summary>Summary text.</summary>
    public string Summary { get; set; } = string.Empty;
}
