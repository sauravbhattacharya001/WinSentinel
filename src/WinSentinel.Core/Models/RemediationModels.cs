using System.Text.Json.Serialization;

namespace WinSentinel.Core.Models;

/// <summary>
/// A prioritized remediation plan generated from audit findings.
/// Groups findings into Quick Wins, Medium Effort, and Major Changes
/// with impact scores and effort estimates.
/// </summary>
public class RemediationPlan
{
    /// <summary>When the plan was generated.</summary>
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Current security score before remediation.</summary>
    public int CurrentScore { get; set; }

    /// <summary>Current grade before remediation.</summary>
    public string CurrentGrade { get; set; } = "";

    /// <summary>Estimated score after all remediations are applied.</summary>
    public int ProjectedScore { get; set; }

    /// <summary>Estimated grade after all remediations.</summary>
    public string ProjectedGrade { get; set; } = "";

    /// <summary>Total estimated score improvement.</summary>
    public int TotalImpact => ProjectedScore - CurrentScore;

    /// <summary>Quick wins: automated fixes or simple config changes (&lt;5 min each).</summary>
    public List<RemediationItem> QuickWins { get; set; } = [];

    /// <summary>Medium effort: manual steps requiring some research (5-30 min each).</summary>
    public List<RemediationItem> MediumEffort { get; set; } = [];

    /// <summary>Major changes: significant work requiring planning (&gt;30 min each).</summary>
    public List<RemediationItem> MajorChanges { get; set; } = [];

    /// <summary>Total actionable items across all categories.</summary>
    public int TotalItems => QuickWins.Count + MediumEffort.Count + MajorChanges.Count;

    /// <summary>Total items that have automated fixes.</summary>
    public int AutoFixableCount => QuickWins.Count(i => i.HasAutoFix) +
                                    MediumEffort.Count(i => i.HasAutoFix) +
                                    MajorChanges.Count(i => i.HasAutoFix);
}

/// <summary>
/// A single remediation action item with priority, effort, and impact data.
/// </summary>
public class RemediationItem
{
    /// <summary>Step number in the overall plan.</summary>
    public int StepNumber { get; set; }

    /// <summary>Finding title.</summary>
    public string Title { get; set; } = "";

    /// <summary>Finding description.</summary>
    public string Description { get; set; } = "";

    /// <summary>Severity of the original finding.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public Severity Severity { get; set; }

    /// <summary>Module/category this finding belongs to.</summary>
    public string Category { get; set; } = "";

    /// <summary>Estimated score impact if resolved (points gained).</summary>
    public int Impact { get; set; }

    /// <summary>Effort category: QuickWin, Medium, Major.</summary>
    public string Effort { get; set; } = "";

    /// <summary>Estimated time to complete (human-readable).</summary>
    public string EstimatedTime { get; set; } = "";

    /// <summary>Remediation instructions.</summary>
    public string? Remediation { get; set; }

    /// <summary>Automated fix command, if available.</summary>
    public string? FixCommand { get; set; }

    /// <summary>Whether an automated fix is available.</summary>
    public bool HasAutoFix => !string.IsNullOrWhiteSpace(FixCommand);

    /// <summary>Priority score for ordering (higher = more urgent). Internal use.</summary>
    [JsonIgnore]
    public double PriorityScore { get; set; }
}
