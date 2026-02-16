using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Core.Models;

/// <summary>
/// Configurable schedule settings for automated scanning.
/// Persisted to JSON in AppData.
/// </summary>
public class ScheduleSettings
{
    /// <summary>Whether scheduled scanning is enabled.</summary>
    public bool Enabled { get; set; }

    /// <summary>Scan interval type.</summary>
    public ScanInterval Interval { get; set; } = ScanInterval.Daily;

    /// <summary>Custom interval in minutes (used when Interval == Custom).</summary>
    public int CustomIntervalMinutes { get; set; } = 120;

    /// <summary>Which audit module categories to include. Empty = all modules.</summary>
    public List<string> IncludedModules { get; set; } = new();

    /// <summary>Whether to show toast notification on scan complete.</summary>
    public bool NotifyOnComplete { get; set; } = true;

    /// <summary>Whether to show toast notification when score drops.</summary>
    public bool NotifyOnScoreDrop { get; set; } = true;

    /// <summary>Whether to show toast notification on new critical/warning findings.</summary>
    public bool NotifyOnNewFindings { get; set; } = true;

    /// <summary>Whether to auto-export reports after scheduled scans.</summary>
    public bool AutoExportEnabled { get; set; }

    /// <summary>Folder to save auto-exported reports. Uses Documents/WinSentinel/Reports if empty.</summary>
    public string? AutoExportFolder { get; set; }

    /// <summary>Format for auto-exported reports (Html, Json, or Text).</summary>
    public string AutoExportFormat { get; set; } = "Html";

    /// <summary>Last scan timestamp (UTC).</summary>
    public DateTimeOffset? LastScanTime { get; set; }

    /// <summary>Last known security score (for comparison).</summary>
    public int? LastScore { get; set; }

    /// <summary>Get the effective interval as a TimeSpan.</summary>
    [JsonIgnore]
    public TimeSpan EffectiveInterval => Interval switch
    {
        ScanInterval.Hourly => TimeSpan.FromHours(1),
        ScanInterval.Daily => TimeSpan.FromHours(24),
        ScanInterval.Custom => TimeSpan.FromMinutes(Math.Max(5, CustomIntervalMinutes)),
        _ => TimeSpan.FromHours(24)
    };

    private static readonly string SettingsDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinSentinel");

    private static readonly string SettingsPath =
        Path.Combine(SettingsDir, "schedule-settings.json");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>Load settings from AppData JSON file, or return defaults.</summary>
    public static ScheduleSettings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var json = File.ReadAllText(SettingsPath);
                return JsonSerializer.Deserialize<ScheduleSettings>(json, JsonOptions) ?? new();
            }
        }
        catch
        {
            // Corrupted file — return defaults
        }
        return new();
    }

    /// <summary>Get the effective auto-export folder, creating it if needed.</summary>
    [JsonIgnore]
    public string EffectiveAutoExportFolder
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(AutoExportFolder) && Directory.Exists(AutoExportFolder))
                return AutoExportFolder;

            var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            var folder = Path.Combine(docs, "WinSentinel", "Reports");
            Directory.CreateDirectory(folder);
            return folder;
        }
    }

    /// <summary>Save settings to AppData JSON file.</summary>
    public void Save()
    {
        try
        {
            Directory.CreateDirectory(SettingsDir);
            var json = JsonSerializer.Serialize(this, JsonOptions);
            File.WriteAllText(SettingsPath, json);
        }
        catch
        {
            // Best-effort save
        }
    }
}

/// <summary>Scan interval presets.</summary>
public enum ScanInterval
{
    Hourly,
    Daily,
    Custom
}
