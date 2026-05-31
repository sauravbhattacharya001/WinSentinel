using WinSentinel.Core.Plugins;

namespace ExamplePlugin;

/// <summary>
/// Example community plugin demonstrating how to write a custom audit module.
/// This plugin logs a greeting on initialization — replace with your own
/// security checks, compliance rules, or reporting logic.
/// </summary>
public sealed class ExampleAuditPlugin : IWinSentinelPlugin
{
    public string FeatureId => "example-audit";
    public string Version => "1.0.0";

    public void Initialize(IPluginContext ctx)
    {
        ctx.Log("ExampleAuditPlugin loaded! Replace this with your custom security checks.", PluginLogLevel.Info);
    }
}
