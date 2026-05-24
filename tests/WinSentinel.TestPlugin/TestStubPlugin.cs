// TEST-ONLY synthetic stub. NOT a real plugin. NOT shipped. Used by PluginHostTests
// to exercise signature/entitlement/load paths. Do NOT use as a template — see
// docs/CREATING-PLUGINS.md for the real plugin author guide.

using WinSentinel.Core.Plugins;

namespace WinSentinel.TestPlugin;

public sealed class TestStubPlugin : IWinSentinelPlugin
{
    public string FeatureId => "test-stub";
    public string Version => "0.0.1";
    public void Initialize(IPluginContext ctx)
    {
        ctx.Log("TestStubPlugin initialized", PluginLogLevel.Debug);
    }
}
