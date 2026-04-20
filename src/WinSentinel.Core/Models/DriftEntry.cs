namespace WinSentinel.Core.Models;

public class DriftEntry
{
    public string Title { get; set; } = "";
    public string Module { get; set; } = "";
    public DriftType Type { get; set; }
    public Severity? OldSeverity { get; set; }
    public Severity? NewSeverity { get; set; }
    public string Category { get; set; } = "";
    public DateTime DetectedAt { get; set; }
    public string? FixCommand { get; set; }
    public string Recommendation { get; set; } = "";
}

public enum DriftType
{
    New,
    Resolved,
    Escalated,
    Deescalated,
    Recurring
}
