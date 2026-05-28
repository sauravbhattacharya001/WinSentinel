// TEST-ONLY misbehaving plugin. Exercises host resilience against badly-written
// plugins. See issue #205.

using WinSentinel.Core.Plugins;

namespace WinSentinel.NaughtyTestPlugin;

/// <summary>Throws in Initialize — host must catch and skip gracefully.</summary>
public sealed class ThrowingPlugin : IWinSentinelPlugin
{
    public string FeatureId => "naughty-thrower";
    public string Version => "0.0.1";
    public void Initialize(IPluginContext ctx)
    {
        throw new InvalidOperationException("Intentional explosion in Initialize");
    }
}
