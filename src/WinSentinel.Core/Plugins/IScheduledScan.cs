namespace WinSentinel.Core.Plugins;

/// <summary>
/// Plugin contract for background / scheduled scans (Pro tier).
/// </summary>
public interface IScheduledScan
{
    /// <summary>
    /// Register a recurring scan according to <paramref name="schedule"/>.
    /// Returns a handle the caller can use to cancel/inspect the schedule.
    /// </summary>
    Task<ScheduleHandle> ScheduleAsync(ScanSchedule schedule, CancellationToken ct);
}

/// <summary>Opaque handle returned by an <see cref="IScheduledScan"/> plugin.</summary>
public sealed class ScheduleHandle
{
    /// <summary>Unique identifier the plugin assigns to this schedule.</summary>
    public required string Id { get; init; }

    /// <summary>Human-readable description for diagnostics / status output.</summary>
    public string? Description { get; init; }
}

/// <summary>Cron-style or interval-based schedule description.</summary>
public sealed class ScanSchedule
{
    /// <summary>Optional cron expression (5-field). Mutually exclusive with <see cref="Interval"/>.</summary>
    public string? Cron { get; init; }

    /// <summary>Fixed interval between scans. Used when <see cref="Cron"/> is null.</summary>
    public TimeSpan? Interval { get; init; }

    /// <summary>Optional module filter forwarded to the audit engine.</summary>
    public string? ModulesFilter { get; init; }

    /// <summary>Optional output directory for the produced report.</summary>
    public string? OutputDir { get; init; }
}
