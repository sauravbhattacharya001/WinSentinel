using System;
using System.Threading;
using System.Threading.Tasks;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// Options describing how a continuous monitor should behave.
/// </summary>
/// <param name="Interval">How often the monitor performs an inline check.</param>
/// <param name="EmitOnlyOnChange">If true, the monitor only emits when state has changed since the last tick.</param>
/// <param name="ProfileName">Optional audit profile name to constrain monitored modules.</param>
public sealed record MonitorOptions(TimeSpan Interval, bool EmitOnlyOnChange, string? ProfileName);

/// <summary>
/// A long-running monitor plugin (background service, event subscriber, …).
/// Lifecycle is fully controlled by the host: <see cref="StartAsync"/> must
/// return promptly after handing control to a background loop;
/// <see cref="StopAsync"/> must drain cleanly.
/// </summary>
public interface IMonitorDaemon
{
    Task StartAsync(MonitorOptions options, CancellationToken ct);
    Task StopAsync(CancellationToken ct);
}
