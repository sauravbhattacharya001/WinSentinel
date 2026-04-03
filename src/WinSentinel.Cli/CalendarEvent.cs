namespace WinSentinel.Cli;

public record CalendarEvent
{
    public required string Title { get; init; }
    public required DateTimeOffset Start { get; init; }
    public required TimeSpan Duration { get; init; }
    public required string Description { get; init; }
    public required string Category { get; init; }
    public required string Priority { get; init; }
}
