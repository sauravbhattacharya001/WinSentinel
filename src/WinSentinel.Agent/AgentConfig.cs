using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Agent;

/// <summary>
/// Persisted agent configuration. Stored as JSON in %LocalAppData%/WinSentinel/agent-config.json.
/// Controls scan schedules, auto-fix policies, monitoring toggles, and risk tolerance.
/// </summary>
public class AgentConfig
{
    /// <summary>How often to run a full audit (in hours).</summary>
    public double ScanIntervalHours { get; set; } = 4.0;

    /// <summary>Whether to auto-fix critical findings after detection.</summary>
    public bool AutoFixCritical { get; set; } = false;

    /// <summary>Whether to auto-fix warning findings after detection.</summary>
    public bool AutoFixWarnings { get; set; } = false;

    /// <summary>Risk tolerance: Low = aggressive scanning, High = relaxed.</summary>
    public RiskTolerance RiskTolerance { get; set; } = RiskTolerance.Medium;

    /// <summary>Enable/disable specific monitoring modules by name.</summary>
    public Dictionary<string, bool> ModuleToggles { get; set; } = new();

    /// <summary>Maximum number of threat events to keep in memory.</summary>
    public int MaxThreatLogSize { get; set; } = 1000;

    /// <summary>Whether to send Windows toast notifications for critical threats.</summary>
    public bool NotifyOnCriticalThreats { get; set; } = true;

    /// <summary>Whether to send Windows toast notifications when scan completes.</summary>
    public bool NotifyOnScanComplete { get; set; } = true;

    // ── Persistence ──

    private static readonly string ConfigDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinSentinel");

    private static readonly string ConfigPath =
        Path.Combine(ConfigDir, "agent-config.json");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>Load config from disk, or create defaults.</summary>
    public void Load()
    {
        try
        {
            if (File.Exists(ConfigPath))
            {
                var json = File.ReadAllText(ConfigPath);
                var loaded = JsonSerializer.Deserialize<AgentConfig>(json, JsonOptions);
                if (loaded != null)
                {
                    ScanIntervalHours = loaded.ScanIntervalHours;
                    AutoFixCritical = loaded.AutoFixCritical;
                    AutoFixWarnings = loaded.AutoFixWarnings;
                    RiskTolerance = loaded.RiskTolerance;
                    ModuleToggles = loaded.ModuleToggles;
                    MaxThreatLogSize = loaded.MaxThreatLogSize;
                    NotifyOnCriticalThreats = loaded.NotifyOnCriticalThreats;
                    NotifyOnScanComplete = loaded.NotifyOnScanComplete;
                }
            }
        }
        catch
        {
            // Use defaults on failure
        }
    }

    /// <summary>Save current config to disk.</summary>
    public void Save()
    {
        try
        {
            Directory.CreateDirectory(ConfigDir);
            var json = JsonSerializer.Serialize(this, JsonOptions);
            File.WriteAllText(ConfigPath, json);
        }
        catch
        {
            // Best-effort save
        }
    }

    /// <summary>Create a serializable snapshot.</summary>
    public AgentConfigSnapshot ToSnapshot() => new()
    {
        ScanIntervalHours = ScanIntervalHours,
        AutoFixCritical = AutoFixCritical,
        AutoFixWarnings = AutoFixWarnings,
        RiskTolerance = RiskTolerance.ToString(),
        ModuleToggles = new Dictionary<string, bool>(ModuleToggles),
        MaxThreatLogSize = MaxThreatLogSize,
        NotifyOnCriticalThreats = NotifyOnCriticalThreats,
        NotifyOnScanComplete = NotifyOnScanComplete
    };

    /// <summary>Apply settings from a snapshot (received via IPC).</summary>
    public void ApplySnapshot(AgentConfigSnapshot snapshot)
    {
        ScanIntervalHours = snapshot.ScanIntervalHours;
        AutoFixCritical = snapshot.AutoFixCritical;
        AutoFixWarnings = snapshot.AutoFixWarnings;
        if (Enum.TryParse<RiskTolerance>(snapshot.RiskTolerance, out var rt))
            RiskTolerance = rt;
        ModuleToggles = new Dictionary<string, bool>(snapshot.ModuleToggles);
        MaxThreatLogSize = snapshot.MaxThreatLogSize;
        NotifyOnCriticalThreats = snapshot.NotifyOnCriticalThreats;
        NotifyOnScanComplete = snapshot.NotifyOnScanComplete;
        Save();
    }

    /// <summary>Check if a module is enabled (defaults to true if not in toggles).</summary>
    public bool IsModuleEnabled(string moduleName) =>
        !ModuleToggles.TryGetValue(moduleName, out var enabled) || enabled;
}

/// <summary>Risk tolerance levels.</summary>
public enum RiskTolerance
{
    Low,    // Aggressive: scan frequently, alert on everything
    Medium, // Balanced: standard intervals
    High    // Relaxed: scan less often, only alert on critical
}

/// <summary>Serializable config snapshot for IPC.</summary>
public class AgentConfigSnapshot
{
    public double ScanIntervalHours { get; set; }
    public bool AutoFixCritical { get; set; }
    public bool AutoFixWarnings { get; set; }
    public string RiskTolerance { get; set; } = "Medium";
    public Dictionary<string, bool> ModuleToggles { get; set; } = new();
    public int MaxThreatLogSize { get; set; }
    public bool NotifyOnCriticalThreats { get; set; }
    public bool NotifyOnScanComplete { get; set; }
}
