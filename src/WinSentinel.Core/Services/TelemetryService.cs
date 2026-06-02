using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Core.Services;

/// <summary>
/// Opt-in anonymous telemetry service for crash/error reporting.
/// Disabled by default. Users opt in via `winsentinel telemetry enable`.
/// Configuration stored in %APPDATA%\WinSentinel\telemetry.json.
/// 
/// Data sent:
///   - CLI version
///   - OS version (Windows build)
///   - Command that failed
///   - Exception type + message (no stack frames with user paths)
///   - Unique install ID (random GUID, not tied to user identity)
/// 
/// Data NOT sent:
///   - Machine name, username, IP, file paths, audit findings,
///     license keys, environment variables, or any PII.
/// </summary>
public sealed class TelemetryService
{
    private const string ConfigFileName = "telemetry.json";
    private const string DefaultEndpoint = "https://api.winsentinel.ai/telemetry";
    private static readonly TimeSpan SendTimeout = TimeSpan.FromSeconds(5);

    private readonly string _configPath;
    private TelemetryConfig? _config;
    private static TelemetryService? _instance;
    private static readonly object Lock = new();

    /// <summary>
    /// Singleton instance.
    /// </summary>
    public static TelemetryService Instance
    {
        get
        {
            if (_instance != null) return _instance;
            lock (Lock)
            {
                _instance ??= new TelemetryService();
            }
            return _instance;
        }
    }

    public TelemetryService() : this(GetDefaultConfigPath()) { }

    public TelemetryService(string configPath)
    {
        _configPath = configPath;
    }

    /// <summary>
    /// Whether telemetry is currently enabled.
    /// </summary>
    public bool IsEnabled => LoadConfig().Enabled;

    /// <summary>
    /// The anonymous install ID for this machine.
    /// </summary>
    public string InstallId => LoadConfig().InstallId;

    /// <summary>
    /// Enable telemetry collection.
    /// </summary>
    public void Enable()
    {
        var config = LoadConfig();
        config.Enabled = true;
        SaveConfig(config);
    }

    /// <summary>
    /// Disable telemetry collection and optionally clear the install ID.
    /// </summary>
    public void Disable(bool clearId = false)
    {
        var config = LoadConfig();
        config.Enabled = false;
        if (clearId)
        {
            config.InstallId = Guid.NewGuid().ToString("N");
        }
        SaveConfig(config);
    }

    /// <summary>
    /// Report a crash/error event. Fire-and-forget; never throws.
    /// </summary>
    public async Task ReportErrorAsync(string command, Exception ex, string? cliVersion = null)
    {
        try
        {
            var config = LoadConfig();
            if (!config.Enabled) return;

            var payload = new TelemetryEvent
            {
                InstallId = config.InstallId,
                CliVersion = cliVersion ?? GetCliVersion(),
                OsVersion = Environment.OSVersion.VersionString,
                OsBuild = Environment.OSVersion.Version.Build,
                EventType = "crash",
                Command = SanitizeCommand(command),
                ExceptionType = ex.GetType().FullName ?? ex.GetType().Name,
                ExceptionMessage = SanitizeMessage(ex.Message),
                Timestamp = DateTimeOffset.UtcNow
            };

            using var client = new HttpClient { Timeout = SendTimeout };
            var endpoint = config.Endpoint ?? DefaultEndpoint;
            await client.PostAsJsonAsync(endpoint, payload);
        }
        catch
        {
            // Telemetry must never interfere with CLI operation
        }
    }

    /// <summary>
    /// Report a generic telemetry event (e.g., command usage). Fire-and-forget.
    /// </summary>
    public async Task ReportEventAsync(string eventType, string command, string? detail = null, string? cliVersion = null)
    {
        try
        {
            var config = LoadConfig();
            if (!config.Enabled) return;

            var payload = new TelemetryEvent
            {
                InstallId = config.InstallId,
                CliVersion = cliVersion ?? GetCliVersion(),
                OsVersion = Environment.OSVersion.VersionString,
                OsBuild = Environment.OSVersion.Version.Build,
                EventType = eventType,
                Command = SanitizeCommand(command),
                Timestamp = DateTimeOffset.UtcNow,
                Detail = detail
            };

            using var client = new HttpClient { Timeout = SendTimeout };
            var endpoint = config.Endpoint ?? DefaultEndpoint;
            await client.PostAsJsonAsync(endpoint, payload);
        }
        catch
        {
            // Telemetry must never interfere with CLI operation
        }
    }

    /// <summary>
    /// Get current telemetry status for display.
    /// </summary>
    public TelemetryStatus GetStatus()
    {
        var config = LoadConfig();
        return new TelemetryStatus
        {
            Enabled = config.Enabled,
            InstallId = config.InstallId,
            Endpoint = config.Endpoint ?? DefaultEndpoint,
            ConfigPath = _configPath
        };
    }

    private TelemetryConfig LoadConfig()
    {
        if (_config != null) return _config;

        try
        {
            if (File.Exists(_configPath))
            {
                var json = File.ReadAllText(_configPath);
                _config = JsonSerializer.Deserialize<TelemetryConfig>(json) ?? new TelemetryConfig();
            }
            else
            {
                _config = new TelemetryConfig();
            }
        }
        catch
        {
            _config = new TelemetryConfig();
        }

        return _config;
    }

    private void SaveConfig(TelemetryConfig config)
    {
        try
        {
            var dir = Path.GetDirectoryName(_configPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_configPath, json);
            _config = config;
        }
        catch
        {
            // Config write failure is non-fatal
        }
    }

    private static string GetDefaultConfigPath()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        return Path.Combine(appData, "WinSentinel", ConfigFileName);
    }

    private static string GetCliVersion()
    {
        var asm = typeof(TelemetryService).Assembly;
        return asm.GetName().Version?.ToString() ?? "unknown";
    }

    /// <summary>
    /// Strip anything that might contain user paths from command strings.
    /// </summary>
    private static string SanitizeCommand(string command)
    {
        // Only keep the first token (the subcommand name)
        var parts = command.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length > 0 ? parts[0] : "unknown";
    }

    /// <summary>
    /// Strip file paths from exception messages to avoid leaking PII.
    /// </summary>
    private static string SanitizeMessage(string message)
    {
        if (string.IsNullOrEmpty(message)) return message;
        // Truncate to 500 chars and strip Windows paths
        var truncated = message.Length > 500 ? message[..500] : message;
        return System.Text.RegularExpressions.Regex.Replace(
            truncated,
            @"[A-Za-z]:\\[^\s""']+",
            "[path]");
    }
}

/// <summary>
/// Telemetry configuration stored on disk.
/// </summary>
public sealed class TelemetryConfig
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    [JsonPropertyName("installId")]
    public string InstallId { get; set; } = Guid.NewGuid().ToString("N");

    [JsonPropertyName("endpoint")]
    public string? Endpoint { get; set; }
}

/// <summary>
/// A single telemetry event payload.
/// </summary>
public sealed class TelemetryEvent
{
    [JsonPropertyName("installId")]
    public string InstallId { get; set; } = "";

    [JsonPropertyName("cliVersion")]
    public string CliVersion { get; set; } = "";

    [JsonPropertyName("osVersion")]
    public string OsVersion { get; set; } = "";

    [JsonPropertyName("osBuild")]
    public int OsBuild { get; set; }

    [JsonPropertyName("eventType")]
    public string EventType { get; set; } = "";

    [JsonPropertyName("command")]
    public string Command { get; set; } = "";

    [JsonPropertyName("exceptionType")]
    public string? ExceptionType { get; set; }

    [JsonPropertyName("exceptionMessage")]
    public string? ExceptionMessage { get; set; }

    [JsonPropertyName("detail")]
    public string? Detail { get; set; }

    [JsonPropertyName("timestamp")]
    public DateTimeOffset Timestamp { get; set; }
}

/// <summary>
/// Status display model for `winsentinel telemetry status`.
/// </summary>
public sealed class TelemetryStatus
{
    public bool Enabled { get; set; }
    public string InstallId { get; set; } = "";
    public string Endpoint { get; set; } = "";
    public string ConfigPath { get; set; } = "";
}
