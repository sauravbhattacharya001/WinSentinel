namespace WinSentinel.Core.Plugins;

/// <summary>
/// Base marker interface that every WinSentinel plugin must implement.
/// Discovered and instantiated by <see cref="PluginHost"/> after the plugin
/// passes signature + entitlement checks.
/// </summary>
/// <remarks>
/// This repo intentionally contains <b>no implementations</b> of this interface
/// or any of the feature interfaces in this namespace. All Pro features ship
/// as signed plugin DLLs from a separate commercial repository.
/// </remarks>
public interface IWinSentinelPlugin
{
    /// <summary>
    /// Stable identifier for this plugin / feature, e.g. <c>"winsentinel.pro.pdf"</c>.
    /// Must match <see cref="PluginManifest.FeatureId"/>.
    /// </summary>
    string FeatureId { get; }

    /// <summary>Plugin semantic version, e.g. <c>"1.0.0"</c>.</summary>
    string Version { get; }

    /// <summary>
    /// Called once after load. Plugins should capture the supplied
    /// <paramref name="ctx"/> for later use; this is their only allowed
    /// callback surface into the core.
    /// </summary>
    void Initialize(IPluginContext ctx);
}
