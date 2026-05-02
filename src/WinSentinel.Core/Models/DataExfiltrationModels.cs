namespace WinSentinel.Core.Models;

/// <summary>
/// Full data exfiltration detection report.
/// </summary>
public class DataExfiltrationReport
{
    /// <summary>When this analysis was generated.</summary>
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Days of history analyzed.</summary>
    public int DaysAnalyzed { get; set; }

    /// <summary>Total events processed.</summary>
    public int EventsProcessed { get; set; }

    /// <summary>Total exfiltration events detected.</summary>
    public int ExfiltrationsDetected { get; set; }

    /// <summary>High severity count.</summary>
    public int HighSeverityCount { get; set; }

    /// <summary>Medium severity count.</summary>
    public int MediumSeverityCount { get; set; }

    /// <summary>Low severity count.</summary>
    public int LowSeverityCount { get; set; }

    /// <summary>Overall threat score (0-100, higher = worse).</summary>
    public double ThreatScore { get; set; }

    /// <summary>Threat level classification.</summary>
    public string ThreatLevel { get; set; } = "Low";

    /// <summary>Detected exfiltration events.</summary>
    public List<ExfiltrationEvent> Events { get; set; } = new();

    /// <summary>Aggregated exfiltration channels.</summary>
    public List<ExfiltrationChannel> Channels { get; set; } = new();

    /// <summary>Recommendations.</summary>
    public List<DataExfiltrationRecommendation> Recommendations { get; set; } = new();

    /// <summary>Summary statistics.</summary>
    public DataExfiltrationStats Stats { get; set; } = new();

    /// <summary>Exfiltration graph visualization data.</summary>
    public ExfiltrationGraph Graph { get; set; } = new();
}

/// <summary>
/// Individual exfiltration event detection.
/// </summary>
public class ExfiltrationEvent
{
    /// <summary>When the event occurred.</summary>
    public DateTimeOffset Timestamp { get; set; }

    /// <summary>Technique name.</summary>
    public string Technique { get; set; } = string.Empty;

    /// <summary>MITRE ATT&CK technique ID.</summary>
    public string TechniqueId { get; set; } = string.Empty;

    /// <summary>Description of the exfiltration indicator.</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>Source process or module.</summary>
    public string SourceProcess { get; set; } = string.Empty;

    /// <summary>Destination address or service.</summary>
    public string DestinationAddress { get; set; } = string.Empty;

    /// <summary>Estimated data volume in bytes.</summary>
    public long DataVolume { get; set; }

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
/// Aggregated exfiltration channel information.
/// </summary>
public class ExfiltrationChannel
{
    /// <summary>Channel type (e.g., "Cloud Storage", "USB", "C2").</summary>
    public string ChannelType { get; set; } = string.Empty;

    /// <summary>MITRE technique ID.</summary>
    public string TechniqueId { get; set; } = string.Empty;

    /// <summary>Number of events using this channel.</summary>
    public int EventCount { get; set; }

    /// <summary>Total estimated data volume.</summary>
    public long TotalVolumeEstimate { get; set; }

    /// <summary>First seen timestamp.</summary>
    public DateTimeOffset FirstSeen { get; set; }

    /// <summary>Last seen timestamp.</summary>
    public DateTimeOffset LastSeen { get; set; }

    /// <summary>Channel severity.</summary>
    public string Severity { get; set; } = "Medium";
}

/// <summary>
/// Recommendation for mitigating exfiltration risk.
/// </summary>
public class DataExfiltrationRecommendation
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
/// Summary statistics for exfiltration analysis.
/// </summary>
public class DataExfiltrationStats
{
    /// <summary>Total distinct channels detected.</summary>
    public int TotalChannelsDetected { get; set; }

    /// <summary>Unique destination addresses/services.</summary>
    public int UniqueDestinations { get; set; }

    /// <summary>Exfiltrations during off-hours.</summary>
    public int OffHoursExfiltrations { get; set; }

    /// <summary>High volume transfer events.</summary>
    public int HighVolumeTransfers { get; set; }

    /// <summary>Events using encrypted channels.</summary>
    public int EncryptedChannelCount { get; set; }

    /// <summary>Events using unusual protocols.</summary>
    public int UnusualProtocolCount { get; set; }
}

/// <summary>
/// Graph representation of exfiltration paths.
/// </summary>
public class ExfiltrationGraph
{
    /// <summary>Graph nodes.</summary>
    public List<ExfilNode> Nodes { get; set; } = new();

    /// <summary>Graph edges.</summary>
    public List<ExfilEdge> Edges { get; set; } = new();
}

/// <summary>
/// Node in the exfiltration graph.
/// </summary>
public class ExfilNode
{
    /// <summary>Unique node ID.</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>Display label.</summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>Node type (process, destination, channel).</summary>
    public string Type { get; set; } = string.Empty;
}

/// <summary>
/// Edge in the exfiltration graph.
/// </summary>
public class ExfilEdge
{
    /// <summary>Source node ID.</summary>
    public string Source { get; set; } = string.Empty;

    /// <summary>Target node ID.</summary>
    public string Target { get; set; } = string.Empty;

    /// <summary>Edge label.</summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>Edge weight.</summary>
    public double Weight { get; set; }
}
