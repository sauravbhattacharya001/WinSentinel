using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Cli.ScheduledScans;

/// <summary>
/// Configuration for scheduled security scans via Windows Task Scheduler.
/// </summary>
public class ScheduleConfig
{
    [JsonPropertyName("cadence")]
    public string Cadence { get; set; } = "daily";

    [JsonPropertyName("time")]
    public string Time { get; set; } = "03:00";

    [JsonPropertyName("dayOfWeek")]
    public string? DayOfWeek { get; set; }

    [JsonPropertyName("autoFix")]
    public bool AutoFix { get; set; }

    [JsonPropertyName("quiet")]
    public bool Quiet { get; set; }

    [JsonPropertyName("modules")]
    public string? Modules { get; set; }

    [JsonPropertyName("taskName")]
    public string TaskName { get; set; } = "WinSentinel_ScheduledAudit";

    [JsonPropertyName("createdAt")]
    public string? CreatedAt { get; set; }
}
