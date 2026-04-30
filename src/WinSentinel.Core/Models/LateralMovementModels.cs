namespace WinSentinel.Core.Models;

/// <summary>
/// Full lateral movement detection report.
/// </summary>
public class LateralMovementReport
{
    /// <summary>When this analysis was generated.</summary>
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Days of history analyzed.</summary>
    public int DaysAnalyzed { get; set; }

    /// <summary>Total events processed.</summary>
    public int EventsProcessed { get; set; }

    /// <summary>Total lateral movements detected.</summary>
    public int MovementsDetected { get; set; }

    /// <summary>High severity movement count.</summary>
    public int HighSeverityMovements { get; set; }

    /// <summary>Medium severity movement count.</summary>
    public int MediumSeverityMovements { get; set; }

    /// <summary>Low severity movement count.</summary>
    public int LowSeverityMovements { get; set; }

    /// <summary>Overall threat score (0-100, higher = worse).</summary>
    public double ThreatScore { get; set; }

    /// <summary>Threat level classification.</summary>
    public string ThreatLevel { get; set; } = "Low";

    /// <summary>Detected lateral movements.</summary>
    public List<LateralMovement> Movements { get; set; } = new();

    /// <summary>Multi-hop movement paths.</summary>
    public List<MovementPath> Paths { get; set; } = new();

    /// <summary>Containment recommendations.</summary>
    public List<LateralMovementRecommendation> Recommendations { get; set; } = new();

    /// <summary>Summary statistics.</summary>
    public LateralMovementStats Stats { get; set; } = new();

    /// <summary>Movement graph visualization data.</summary>
    public MovementGraph Graph { get; set; } = new();
}

/// <summary>
/// A single detected lateral movement event.
/// </summary>
public class LateralMovement
{
    /// <summary>Source host originating the movement.</summary>
    public string SourceHost { get; set; } = "";

    /// <summary>Target host being accessed.</summary>
    public string TargetHost { get; set; } = "";

    /// <summary>Movement technique (RDP, SMB/PsExec, WMI, PSRemoting, DCOM, WinRM, SSH, ScheduledTask, ToolTransfer).</summary>
    public string Technique { get; set; } = "";

    /// <summary>MITRE ATT&CK technique ID.</summary>
    public string MitreTechnique { get; set; } = "";

    /// <summary>Account used for the movement.</summary>
    public string? AccountUsed { get; set; }

    /// <summary>When the movement was detected.</summary>
    public DateTimeOffset DetectedAt { get; set; }

    /// <summary>Detection confidence (0.0-1.0).</summary>
    public double Confidence { get; set; }

    /// <summary>Severity classification.</summary>
    public LateralMovementSeverity Severity { get; set; }

    /// <summary>Evidence description.</summary>
    public string Evidence { get; set; } = "";

    /// <summary>Process name involved.</summary>
    public string? ProcessName { get; set; }

    /// <summary>Whether the account is a service account.</summary>
    public bool IsServiceAccount { get; set; }

    /// <summary>Supporting indicators.</summary>
    public List<string> Indicators { get; set; } = new();
}

/// <summary>Severity levels for lateral movement events.</summary>
public enum LateralMovementSeverity { Low, Medium, High, Critical }

/// <summary>
/// A multi-hop lateral movement path (chain of movements).
/// </summary>
public class MovementPath
{
    /// <summary>Ordered list of hosts in the path.</summary>
    public List<string> Hops { get; set; } = new();

    /// <summary>Techniques used at each hop.</summary>
    public List<string> Techniques { get; set; } = new();

    /// <summary>Number of hops.</summary>
    public int HopCount { get; set; }

    /// <summary>Cumulative risk score for the path.</summary>
    public double PathRisk { get; set; }

    /// <summary>Originating host.</summary>
    public string? OriginHost { get; set; }

    /// <summary>Terminal/final host.</summary>
    public string? TerminalHost { get; set; }

    /// <summary>Whether the path reaches a critical asset.</summary>
    public bool ReachesCriticalAsset { get; set; }

    /// <summary>Total duration of the movement chain.</summary>
    public TimeSpan Duration { get; set; }
}

/// <summary>
/// Movement graph representing host-to-host connections.
/// </summary>
public class MovementGraph
{
    /// <summary>Number of unique hosts.</summary>
    public int NodeCount { get; set; }

    /// <summary>Number of unique connections.</summary>
    public int EdgeCount { get; set; }

    /// <summary>Host nodes.</summary>
    public List<GraphNode> Nodes { get; set; } = new();

    /// <summary>Movement edges.</summary>
    public List<GraphEdge> Edges { get; set; } = new();

    /// <summary>Most connected host (highest degree).</summary>
    public string? MostConnectedNode { get; set; }

    /// <summary>Longest path length in the graph.</summary>
    public int MaxPathLength { get; set; }
}

/// <summary>A host node in the movement graph.</summary>
public class GraphNode
{
    /// <summary>Host name or IP.</summary>
    public string HostName { get; set; } = "";

    /// <summary>Number of incoming movements.</summary>
    public int InDegree { get; set; }

    /// <summary>Number of outgoing movements.</summary>
    public int OutDegree { get; set; }

    /// <summary>Whether this is a critical asset (DC, server, etc.).</summary>
    public bool IsCriticalAsset { get; set; }

    /// <summary>Classified role (workstation, server, dc, jump-box).</summary>
    public string Role { get; set; } = "workstation";
}

/// <summary>A movement edge in the graph.</summary>
public class GraphEdge
{
    /// <summary>Source host.</summary>
    public string Source { get; set; } = "";

    /// <summary>Target host.</summary>
    public string Target { get; set; } = "";

    /// <summary>Technique used.</summary>
    public string Technique { get; set; } = "";

    /// <summary>Number of times this movement occurred.</summary>
    public int Count { get; set; }

    /// <summary>Most recent occurrence.</summary>
    public DateTimeOffset LastSeen { get; set; }
}

/// <summary>Containment recommendation.</summary>
public class LateralMovementRecommendation
{
    /// <summary>Priority: Critical, High, Medium, Low.</summary>
    public string Priority { get; set; } = "Medium";

    /// <summary>Category of recommendation.</summary>
    public string Category { get; set; } = "";

    /// <summary>Short title.</summary>
    public string Title { get; set; } = "";

    /// <summary>Detailed description.</summary>
    public string Description { get; set; } = "";

    /// <summary>MITRE mitigation ID if applicable.</summary>
    public string? MitreMitigation { get; set; }
}

/// <summary>Summary statistics for lateral movement analysis.</summary>
public class LateralMovementStats
{
    /// <summary>Unique source hosts.</summary>
    public int UniqueSourceHosts { get; set; }

    /// <summary>Unique target hosts.</summary>
    public int UniqueTargetHosts { get; set; }

    /// <summary>Unique techniques observed.</summary>
    public int UniqueTechniques { get; set; }

    /// <summary>Unique accounts involved.</summary>
    public int UniqueAccounts { get; set; }

    /// <summary>Movements using service accounts.</summary>
    public int ServiceAccountMovements { get; set; }

    /// <summary>Movements during off-hours (22:00-06:00).</summary>
    public int OffHoursMovements { get; set; }

    /// <summary>Most frequently used technique.</summary>
    public string MostUsedTechnique { get; set; } = "";

    /// <summary>Most targeted host.</summary>
    public string MostTargetedHost { get; set; } = "";

    /// <summary>Most active account.</summary>
    public string MostActiveAccount { get; set; } = "";

    /// <summary>Average hops per detected path.</summary>
    public double AverageHopsPerPath { get; set; }
}
