using System.Collections.Concurrent;

namespace WinSentinel.Agent;

/// <summary>
/// Tracks the runtime state of the agent service.
/// Thread-safe — updated by multiple modules concurrently.
/// </summary>
public class AgentState
{
    private readonly object _lock = new();
    private DateTimeOffset _startTime = DateTimeOffset.UtcNow;

    /// <summary>When the agent was started.</summary>
    public DateTimeOffset StartTime
    {
        get { lock (_lock) return _startTime; }
        set { lock (_lock) _startTime = value; }
    }

    /// <summary>Current uptime.</summary>
    public TimeSpan Uptime => DateTimeOffset.UtcNow - StartTime;

    /// <summary>Number of threats detected since startup.</summary>
    public int ThreatsDetectedToday => ThreatLog?.GetTodayCount() ?? 0;

    /// <summary>Last time a full audit completed.</summary>
    public DateTimeOffset? LastScanTime { get; set; }

    /// <summary>Last audit security score.</summary>
    public int? LastScanScore { get; set; }

    /// <summary>Whether a scan is currently running.</summary>
    public bool IsScanRunning { get; set; }

    /// <summary>Currently active module names.</summary>
    public ConcurrentDictionary<string, bool> ActiveModules { get; } = new();

    /// <summary>Reference to the threat log for counting.</summary>
    public ThreatLog? ThreatLog { get; set; }

    /// <summary>Agent version.</summary>
    public string Version { get; } = typeof(AgentState).Assembly.GetName().Version?.ToString() ?? "1.0.0";

    /// <summary>Create a snapshot for IPC transmission.</summary>
    public AgentStatusSnapshot ToSnapshot() => new()
    {
        StartTime = StartTime,
        UptimeSeconds = (long)Uptime.TotalSeconds,
        ThreatsDetectedToday = ThreatsDetectedToday,
        LastScanTime = LastScanTime,
        LastScanScore = LastScanScore,
        IsScanRunning = IsScanRunning,
        ActiveModules = ActiveModules.Where(kv => kv.Value).Select(kv => kv.Key).ToList(),
        Version = Version
    };
}

/// <summary>
/// Serializable snapshot of agent state for IPC.
/// </summary>
public class AgentStatusSnapshot
{
    public DateTimeOffset StartTime { get; set; }
    public long UptimeSeconds { get; set; }
    public int ThreatsDetectedToday { get; set; }
    public DateTimeOffset? LastScanTime { get; set; }
    public int? LastScanScore { get; set; }
    public bool IsScanRunning { get; set; }
    public List<string> ActiveModules { get; set; } = [];
    public string Version { get; set; } = "";
}
