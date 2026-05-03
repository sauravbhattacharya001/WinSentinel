namespace WinSentinel.Core.Models;

/// <summary>
/// Full collection activity detection report.
/// MITRE ATT&amp;CK: TA0009 (Collection)
/// </summary>
public class CollectionReport
{
    /// <summary>When this analysis was generated.</summary>
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Days of history analyzed.</summary>
    public int DaysAnalyzed { get; set; }

    /// <summary>Total events processed.</summary>
    public int EventsProcessed { get; set; }

    /// <summary>Total collection activities detected.</summary>
    public int CollectionActivitiesDetected { get; set; }

    /// <summary>High severity count.</summary>
    public int HighSeverityCount { get; set; }

    /// <summary>Medium severity count.</summary>
    public int MediumSeverityCount { get; set; }

    /// <summary>Low severity count.</summary>
    public int LowSeverityCount { get; set; }

    /// <summary>Overall threat score (0-100, higher = worse).</summary>
    public double ThreatScore { get; set; }

    /// <summary>Threat level classification.</summary>
    public string ThreatLevel { get; set; } = "Minimal";

    /// <summary>Detected collection events.</summary>
    public List<CollectionEvent> Events { get; set; } = new();

    /// <summary>Aggregated technique breakdown.</summary>
    public List<CollectionTechnique> Techniques { get; set; } = new();

    /// <summary>Recommendations.</summary>
    public List<CollectionRecommendation> Recommendations { get; set; } = new();

    /// <summary>Summary statistics.</summary>
    public CollectionStats Stats { get; set; } = new();

    /// <summary>Detected collection campaigns.</summary>
    public List<CollectionCampaign> Campaigns { get; set; } = new();
}

/// <summary>
/// Individual collection activity event.
/// </summary>
public class CollectionEvent
{
    /// <summary>When the event occurred.</summary>
    public DateTimeOffset Timestamp { get; set; }

    /// <summary>Technique name.</summary>
    public string Technique { get; set; } = string.Empty;

    /// <summary>MITRE ATT&amp;CK technique ID.</summary>
    public string TechniqueId { get; set; } = string.Empty;

    /// <summary>Description of the collection indicator.</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>Source process or module.</summary>
    public string SourceProcess { get; set; } = string.Empty;

    /// <summary>Target data being collected.</summary>
    public string TargetData { get; set; } = string.Empty;

    /// <summary>Severity level.</summary>
    public string Severity { get; set; } = "Medium";

    /// <summary>Detection confidence (0.0-1.0).</summary>
    public double Confidence { get; set; }

    /// <summary>Context indicators that triggered detection.</summary>
    public List<string> ContextIndicators { get; set; } = new();

    /// <summary>Risk factors that boosted severity.</summary>
    public List<string> RiskFactors { get; set; } = new();
}

/// <summary>
/// Aggregated collection technique information.
/// </summary>
public class CollectionTechnique
{
    /// <summary>Technique name.</summary>
    public string TechniqueName { get; set; } = string.Empty;

    /// <summary>MITRE technique ID.</summary>
    public string TechniqueId { get; set; } = string.Empty;

    /// <summary>Number of events using this technique.</summary>
    public int EventCount { get; set; }

    /// <summary>First seen timestamp.</summary>
    public DateTimeOffset FirstSeen { get; set; }

    /// <summary>Last seen timestamp.</summary>
    public DateTimeOffset LastSeen { get; set; }

    /// <summary>Technique severity.</summary>
    public string Severity { get; set; } = "Medium";
}

/// <summary>
/// Recommendation for mitigating collection activity risk.
/// </summary>
public class CollectionRecommendation
{
    /// <summary>Priority (1=highest).</summary>
    public int Priority { get; set; }

    /// <summary>Category of recommendation.</summary>
    public string Category { get; set; } = string.Empty;

    /// <summary>Short title.</summary>
    public string Title { get; set; } = string.Empty;

    /// <summary>Detailed description.</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>Related MITRE technique.</summary>
    public string MitreTechnique { get; set; } = string.Empty;
}

/// <summary>
/// Summary statistics for collection analysis.
/// </summary>
public class CollectionStats
{
    /// <summary>Total distinct techniques detected.</summary>
    public int TotalTechniquesDetected { get; set; }

    /// <summary>Unique source processes.</summary>
    public int UniqueProcesses { get; set; }

    /// <summary>Collection activities during off-hours.</summary>
    public int OffHoursActivities { get; set; }

    /// <summary>High volume collection events.</summary>
    public int HighVolumeCollections { get; set; }

    /// <summary>Automated collection events.</summary>
    public int AutomatedCollectionCount { get; set; }

    /// <summary>Events targeting sensitive data.</summary>
    public int SensitiveDataTargets { get; set; }
}

/// <summary>
/// Detected collection campaign (multiple techniques from same source).
/// </summary>
public class CollectionCampaign
{
    /// <summary>Campaign identifier.</summary>
    public string CampaignId { get; set; } = string.Empty;

    /// <summary>Source process driving the campaign.</summary>
    public string SourceProcess { get; set; } = string.Empty;

    /// <summary>Techniques used in this campaign.</summary>
    public List<string> TechniquesUsed { get; set; } = new();

    /// <summary>Total events in this campaign.</summary>
    public int EventCount { get; set; }

    /// <summary>Campaign severity.</summary>
    public string Severity { get; set; } = "High";

    /// <summary>Campaign confidence.</summary>
    public double Confidence { get; set; }
}
