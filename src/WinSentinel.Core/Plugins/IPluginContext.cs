namespace WinSentinel.Core.Plugins;

/// <summary>
/// Narrow callback surface exposed by the core to loaded plugins.
/// Plugins must not reach into core types directly — they get only what is
/// here. Keep this interface tight: every member is a long-term public
/// contract that ships in the free MIT core.
/// </summary>
public interface IPluginContext
{
    /// <summary>
    /// Log a diagnostic line. Implementation typically writes to the same sink
    /// the CLI uses (stderr / log file). Plugins should not log secrets.
    /// </summary>
    void Log(string message);

    /// <summary>
    /// Read-only configuration values for the host process (e.g. CLI flags
    /// the user opted into). Keys are case-insensitive. Plugins must treat
    /// values as untrusted user input.
    /// </summary>
    IReadOnlyDictionary<string, string> Config { get; }

    /// <summary>
    /// Version string of the core that loaded this plugin
    /// (compare against <see cref="PluginManifest.MinCoreVersion"/>).
    /// </summary>
    string CoreVersion { get; }
}

/// <summary>
/// Default minimal <see cref="IPluginContext"/> the host hands to plugins.
/// </summary>
internal sealed class PluginContext : IPluginContext
{
    private readonly Action<string> _log;

    public PluginContext(
        Action<string> log,
        IReadOnlyDictionary<string, string>? config,
        string coreVersion)
    {
        _log = log;
        Config = config ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        CoreVersion = coreVersion;
    }

    public void Log(string message) => _log(message);
    public IReadOnlyDictionary<string, string> Config { get; }
    public string CoreVersion { get; }
}
