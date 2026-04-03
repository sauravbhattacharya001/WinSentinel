namespace WinSentinel.Cli;

/// <summary>
/// Represents a scheduled event on the security calendar (audit, SLA deadline, review, etc.).
/// </summary>
public record CalendarEvent
{
    /// <summary>Short title for the calendar event.</summary>
    public required string Title { get; init; }

    /// <summary>When the event is scheduled to occur.</summary>
    public required DateTimeOffset Start { get; init; }

    /// <summary>Expected duration of the event.</summary>
    public required TimeSpan Duration { get; init; }

    /// <summary>Human-readable description of the event.</summary>
    public required string Description { get; init; }

    /// <summary>Event category (e.g., "Audit", "SLA", "Review").</summary>
    public required string Category { get; init; }

    /// <summary>Priority level (e.g., "High", "Medium", "Low").</summary>
    public required string Priority { get; init; }
}
