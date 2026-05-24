using System;
using System.Threading;
using System.Threading.Tasks;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// Schedule definition handed to <see cref="IScheduledScan.ScheduleAsync"/>.
/// </summary>
/// <param name="Cron">CRON expression (5- or 6-field) interpreted in local time by the plugin.</param>
/// <param name="ProfileName">Optional audit profile to run; <c>null</c> = default profile.</param>
/// <param name="MaxRuntime">Hard ceiling for a single scheduled run.</param>
public sealed record ScanSchedule(string Cron, string? ProfileName, TimeSpan MaxRuntime);

/// <summary>
/// Opaque handle returned by the scheduler — useful for later cancellation
/// once the host grows a <c>scan unschedule</c> command.
/// </summary>
/// <param name="Id">Plugin-defined identifier for the registered schedule.</param>
/// <param name="NextRunUtc">Best estimate of next fire time. Informational only.</param>
public sealed record ScheduleHandle(string Id, DateTimeOffset NextRunUtc);

/// <summary>
/// A plugin that registers WinSentinel scans with a host scheduler (Task
/// Scheduler, systemd timer, cron, …). The Core itself never schedules.
/// </summary>
public interface IScheduledScan
{
    Task<ScheduleHandle> ScheduleAsync(ScanSchedule schedule, CancellationToken ct);
}
