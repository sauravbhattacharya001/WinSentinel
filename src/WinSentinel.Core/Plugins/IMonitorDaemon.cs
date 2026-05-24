namespace WinSentinel.Core.Plugins;

/// <summary>
/// Long-running monitor that emits real-time alerts (e.g. Windows toast).
/// </summary>
public interface IMonitorDaemon
{
    /// <summary>Start monitoring. Returns once the daemon is running.</summary>
    Task StartAsync(MonitorOptions opts, CancellationToken ct);

    /// <summary>Stop monitoring gracefully.</summary>
    Task StopAsync(CancellationToken ct);
}

/// <summary>User-tunable options for an <see cref="IMonitorDaemon"/>.</summary>
public sealed class MonitorOptions
{
    /// <summary>Comma-separated severity filter, e.g. "critical,warning".</summary>
    public string SeverityFilter { get; init; } = "critical,warning";

    /// <summary>Minimum interval between toast notifications for the same finding.</summary>
    public TimeSpan QuietWindow { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>Optional module filter.</summary>
    public string? ModulesFilter { get; init; }
}
