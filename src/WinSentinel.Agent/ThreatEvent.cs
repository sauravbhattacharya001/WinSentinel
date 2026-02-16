namespace WinSentinel.Agent;

/// <summary>
/// Represents a real-time threat detection event.
/// </summary>
public class ThreatEvent
{
    /// <summary>Unique ID for this event.</summary>
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];

    /// <summary>When the threat was detected.</summary>
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Source module that detected the threat.</summary>
    public string Source { get; set; } = "";

    /// <summary>Threat severity.</summary>
    public ThreatSeverity Severity { get; set; }

    /// <summary>Human-readable title.</summary>
    public string Title { get; set; } = "";

    /// <summary>Detailed description.</summary>
    public string Description { get; set; } = "";

    /// <summary>Whether this threat can be auto-fixed.</summary>
    public bool AutoFixable { get; set; }

    /// <summary>What action was taken (if any).</summary>
    public string? ResponseTaken { get; set; }

    /// <summary>Associated fix command, if available.</summary>
    public string? FixCommand { get; set; }
}

/// <summary>Threat severity levels.</summary>
public enum ThreatSeverity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}
