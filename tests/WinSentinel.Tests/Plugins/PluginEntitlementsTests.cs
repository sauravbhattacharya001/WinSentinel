using WinSentinel.Core.Plugins;

namespace WinSentinel.Tests.Plugins;

/// <summary>
/// Tests for the PluginEntitlements vocabulary.
/// Issue: #198
/// </summary>
[Trait("Category", "BVT")]
public class PluginEntitlementsTests
{
    [Fact]
    public void All_ContainsExpectedEntitlements()
    {
        Assert.Contains(PluginEntitlements.AuditModule, PluginEntitlements.All);
        Assert.Contains(PluginEntitlements.MonitorDaemon, PluginEntitlements.All);
        Assert.Contains(PluginEntitlements.ReportExporter, PluginEntitlements.All);
        Assert.Contains(PluginEntitlements.SystemExec, PluginEntitlements.All);
        Assert.Contains(PluginEntitlements.SystemNetwork, PluginEntitlements.All);
        Assert.Contains(PluginEntitlements.StorageDb, PluginEntitlements.All);
    }

    [Fact]
    public void IsKnown_RecognizesAllDefined()
    {
        foreach (var e in PluginEntitlements.All)
        {
            Assert.True(PluginEntitlements.IsKnown(e), $"{e} should be known");
        }
    }

    [Fact]
    public void IsKnown_RejectsUnknown()
    {
        Assert.False(PluginEntitlements.IsKnown("winsentinel.fake.thing"));
        Assert.False(PluginEntitlements.IsKnown(null));
        Assert.False(PluginEntitlements.IsKnown(""));
        Assert.False(PluginEntitlements.IsKnown("  "));
    }

    [Fact]
    public void IsElevated_IdentifiesDangerousEntitlements()
    {
        Assert.True(PluginEntitlements.IsElevated(PluginEntitlements.SystemExec));
        Assert.True(PluginEntitlements.IsElevated(PluginEntitlements.SystemRegistryWrite));
        Assert.True(PluginEntitlements.IsElevated(PluginEntitlements.SystemFileAccess));
        Assert.True(PluginEntitlements.IsElevated(PluginEntitlements.SystemNetwork));
    }

    [Fact]
    public void IsElevated_SafeEntitlementsReturnFalse()
    {
        Assert.False(PluginEntitlements.IsElevated(PluginEntitlements.AuditModule));
        Assert.False(PluginEntitlements.IsElevated(PluginEntitlements.ReportExporter));
        Assert.False(PluginEntitlements.IsElevated(PluginEntitlements.Notify));
        Assert.False(PluginEntitlements.IsElevated(null));
    }

    [Theory]
    [InlineData(PluginEntitlements.AuditModule)]
    [InlineData(PluginEntitlements.MonitorDaemon)]
    [InlineData(PluginEntitlements.SystemExec)]
    public void Entitlements_FollowNamingConvention(string entitlement)
    {
        // Must be dot-separated lowercase: winsentinel.{category}.{action}
        Assert.StartsWith("winsentinel.", entitlement);
        Assert.Equal(entitlement, entitlement.ToLowerInvariant());
        Assert.True(entitlement.Split('.').Length >= 3, "Must have at least 3 segments");
    }

    [Fact]
    public void All_NoDuplicates()
    {
        var unique = new HashSet<string>(PluginEntitlements.All);
        Assert.Equal(PluginEntitlements.All.Length, unique.Count);
    }
}
