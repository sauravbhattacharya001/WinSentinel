namespace WinSentinel.Core.Models;

/// <summary>
/// Represents a single finding from a security audit.
/// </summary>
public class AuditFinding
{
    public required string Title { get; init; }
    public required string Description { get; init; }
    public Severity Severity { get; init; } = Severity.Info;
    public string? Remediation { get; init; }
    public string? FixCommand { get; init; }
    public string Category { get; init; } = "General";
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;

    public override string ToString() =>
        $"[{Severity}] {Title}: {Description}";
}
