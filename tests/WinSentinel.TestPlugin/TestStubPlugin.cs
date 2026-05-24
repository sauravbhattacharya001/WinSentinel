// Synthetic plugin used ONLY by PluginHostTests. It implements
// IWinSentinelPlugin + IReportExporter with no-op bodies so the test
// can prove that a valid signature + matching entitlement results in a
// loaded plugin. Nothing in here is a real Pro feature.

using WinSentinel.Core.Models;
using WinSentinel.Core.Plugins;

namespace WinSentinel.TestPlugin;

public sealed class TestStubPlugin : IWinSentinelPlugin, IReportExporter
{
    public string FeatureId => "winsentinel.test.stub";
    public string Version => "0.0.1";
    public string Format => "test-noop";

    public static int InitializeCallCount;

    public void Initialize(IPluginContext ctx)
    {
        System.Threading.Interlocked.Increment(ref InitializeCallCount);
        ctx.Log($"TestStubPlugin initialized on core {ctx.CoreVersion}");
    }

    public Task ExportAsync(SecurityReport report, Stream output, CancellationToken ct)
    {
        // No-op: the host already proved it could find the implementation.
        return Task.CompletedTask;
    }
}
