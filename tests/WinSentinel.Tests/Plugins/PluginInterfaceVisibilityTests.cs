using System.Reflection;
using WinSentinel.Core.Audits;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;
using WinSentinel.Core.Plugins;

namespace WinSentinel.Tests.Plugins;

/// <summary>
/// Verifies all plugin-facing interfaces and types remain public in the Core assembly.
/// Prevents accidental visibility regressions that would break third-party plugins.
/// Issue: #215
/// </summary>
[Trait("Category", "BVT")]
public class PluginInterfaceVisibilityTests
{
    private static readonly Type[] RequiredPublicTypes =
    [
        typeof(IWinSentinelPlugin),
        typeof(IPluginContext),
        typeof(IAuditModule),
        typeof(IComplianceMapper),
        typeof(IReportExporter),
        typeof(IMonitorDaemon),
        typeof(IFleetSink),
        typeof(IScheduledScan),
        typeof(PluginLogLevel),
        typeof(PluginLoadStatus),
    ];

    [Fact]
    public void AllPluginInterfaces_ArePublic()
    {
        foreach (var type in RequiredPublicTypes)
        {
            Assert.True(type.IsPublic, $"{type.FullName} must be public for plugin authors");
        }
    }

    [Fact]
    public void CoreModels_UsedByPlugins_ArePublic()
    {
        // Models that plugin authors need to construct/return
        var modelTypes = new[]
        {
            typeof(Finding),
            typeof(Severity),
            typeof(AuditResult),
            typeof(SecurityReport),
            typeof(FixResult),
        };

        foreach (var type in modelTypes)
        {
            Assert.True(type.IsPublic, $"{type.FullName} must be public for plugin authors");
        }
    }

    [Fact]
    public void AuditModuleBase_IsPublic()
    {
        var type = typeof(AuditModuleBase);
        Assert.True(type.IsPublic, "AuditModuleBase must be public so plugins can extend it");
        Assert.True(type.IsAbstract, "AuditModuleBase must remain abstract");
    }

    [Fact]
    public void IPluginContext_ExposesRequiredMembers()
    {
        var contextType = typeof(IPluginContext);
        var members = contextType.GetMembers(BindingFlags.Public | BindingFlags.Instance);

        // Must have Log property
        Assert.Contains(members, m => m.Name == "Log");
        // Must have Config property
        Assert.Contains(members, m => m.Name == "Config");
    }
}
