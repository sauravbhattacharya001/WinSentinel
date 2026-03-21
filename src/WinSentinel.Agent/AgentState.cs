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
    private DateTimeOffset? _lastScanTime;
    private int? _lastScanScore;
    private int _isScanRunning; // 0 = false, 1 = true; int for Interlocked

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
    public DateTimeOffset? LastScanTime
    {
        get { lock (_lock) return _lastScanTime; }
        set { lock (_lock) _lastScanTime = value; }
    }

    /// <summary>Last audit security score.</summary>
    public int? LastScanScore
    {
        get { lock (_lock) return _lastScanScore; }
        set { lock (_lock) _lastScanScore = value; }
    }

    /// <summary>
    /// Whether a scan is currently running.
    /// Uses Interlocked for lock-free thread safety since this is used as
    /// a concurrency guard in ScheduledAuditModule to prevent overlapping audits.
    /// </summary>
    public bool IsScanRunning
    {
        get => Interlocked.CompareExchange(ref _isScanRunning, 0, 0) != 0;
        set => Interlocked.Exchange(ref _isScanRunning, value ? 1 : 0);
    }

    /// <summary>
    /// Atomically try to set IsScanRunning from false to true.
    /// Returns true if this call acquired the scan lock, false if a scan is already running.
    /// Prevents the TOCTOU race in the read-then-set pattern.
    /// </summary>
    public bool TryStartScan() => Interlocked.CompareExchange(ref _isScanRunning, 1, 0) == 0;

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
/// Serializable snapshot of agent state for IPC transmission to the UI app.
/// </summary>
public class AgentStatusSnapshot
{
    /// <summary>When the agent process was started.</summary>
    public DateTimeOffset StartTime { get; set; }

    /// <summary>Total uptime in seconds since agent start.</summary>
    public long UptimeSeconds { get; set; }

    /// <summary>Number of threats detected since midnight UTC.</summary>
    public int ThreatsDetectedToday { get; set; }

    /// <summary>When the last full audit scan completed (null if none yet).</summary>
    public DateTimeOffset? LastScanTime { get; set; }

    /// <summary>Security score (0-100) from the last completed scan.</summary>
    public int? LastScanScore { get; set; }

    /// <summary>Whether an audit scan is currently in progress.</summary>
    public bool IsScanRunning { get; set; }

    /// <summary>Names of currently active monitoring modules.</summary>
    public List<string> ActiveModules { get; set; } = [];

    /// <summary>Agent assembly version string.</summary>
    public string Version { get; set; } = "";
}
