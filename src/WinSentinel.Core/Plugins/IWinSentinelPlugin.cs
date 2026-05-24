namespace WinSentinel.Core.Plugins;

/// <summary>
/// Root contract every WinSentinel plugin must implement. The host discovers
/// implementations via reflection inside a signed, manifest-bearing DLL.
/// </summary>
public interface IWinSentinelPlugin
{
    /// <summary>
    /// Stable identifier for the feature this plugin provides. Must match the
    /// <c>featureId</c> field in the embedded <c>plugin.json</c> manifest and
    /// the entitlement name checked against <see cref="Licensing.LicenseManager"/>.
    /// Examples: <c>pdf-report</c>, <c>monitor-daemon</c>, <c>fleet-sink</c>.
    /// </summary>
    string FeatureId { get; }

    /// <summary>Plugin version (semver). Used for diagnostics + future compatibility checks.</summary>
    string Version { get; }

    /// <summary>
    /// Called exactly once by the host after instantiation. Plugins should
    /// stash <paramref name="ctx"/> for later use (logging, report access).
    /// Throwing here is fatal for this plugin only; the host catches and skips.
    /// </summary>
    void Initialize(IPluginContext ctx);
}
