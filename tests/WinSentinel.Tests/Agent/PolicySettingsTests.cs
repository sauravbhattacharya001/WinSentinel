using WinSentinel.Agent;
using WinSentinel.Agent.Services;

namespace WinSentinel.Tests.Agent;

public class PolicySettingsTests
{
    // ── AgentConfig Extended Fields ──

    [Fact]
    public void AgentConfig_DefaultValues_AreCorrect()
    {
        var config = new AgentConfig();

        Assert.True(config.NotificationSound);
        Assert.False(config.NotifyCriticalOnly);
        Assert.False(config.AutoExportAfterScan);
        Assert.Equal("HTML", config.AutoExportFormat);
        Assert.False(config.StartWithWindows);
        Assert.True(config.MinimizeToTray);
        Assert.Empty(config.CategoryAutoFix);
        Assert.Empty(config.CategoryDefaultResponse);
    }

    [Fact]
    public void AgentConfig_Snapshot_IncludesNewFields()
    {
        var config = new AgentConfig
        {
            NotificationSound = false,
            NotifyCriticalOnly = true,
            AutoExportAfterScan = true,
            AutoExportFormat = "JSON",
            StartWithWindows = true,
            MinimizeToTray = false,
            CategoryAutoFix = new Dictionary<string, bool> { ["Process"] = true, ["Network"] = false },
            CategoryDefaultResponse = new Dictionary<string, string> { ["Process"] = "AutoFix", ["Network"] = "Log" }
        };

        var snapshot = config.ToSnapshot();

        Assert.False(snapshot.NotificationSound);
        Assert.True(snapshot.NotifyCriticalOnly);
        Assert.True(snapshot.AutoExportAfterScan);
        Assert.Equal("JSON", snapshot.AutoExportFormat);
        Assert.True(snapshot.StartWithWindows);
        Assert.False(snapshot.MinimizeToTray);
        Assert.True(snapshot.CategoryAutoFix["Process"]);
        Assert.False(snapshot.CategoryAutoFix["Network"]);
        Assert.Equal("AutoFix", snapshot.CategoryDefaultResponse["Process"]);
        Assert.Equal("Log", snapshot.CategoryDefaultResponse["Network"]);
    }

    [Fact]
    public void AgentConfig_ApplySnapshot_SetsNewFields()
    {
        var config = new AgentConfig();
        var snapshot = new AgentConfigSnapshot
        {
            ScanIntervalHours = 8,
            AutoFixCritical = true,
            RiskTolerance = "Low",
            ModuleToggles = new Dictionary<string, bool> { ["NetworkMonitor"] = true },
            NotificationSound = false,
            NotifyCriticalOnly = true,
            AutoExportAfterScan = true,
            AutoExportFormat = "JSON",
            StartWithWindows = true,
            MinimizeToTray = false,
            CategoryAutoFix = new Dictionary<string, bool> { ["Process"] = true },
            CategoryDefaultResponse = new Dictionary<string, string> { ["Process"] = "Alert" }
        };

        config.ApplySnapshot(snapshot);

        Assert.Equal(8, config.ScanIntervalHours);
        Assert.True(config.AutoFixCritical);
        Assert.Equal(RiskTolerance.Low, config.RiskTolerance);
        Assert.False(config.NotificationSound);
        Assert.True(config.NotifyCriticalOnly);
        Assert.True(config.AutoExportAfterScan);
        Assert.Equal("JSON", config.AutoExportFormat);
        Assert.True(config.StartWithWindows);
        Assert.False(config.MinimizeToTray);
        Assert.True(config.CategoryAutoFix["Process"]);
        Assert.Equal("Alert", config.CategoryDefaultResponse["Process"]);
    }

    [Fact]
    public void AgentConfig_SnapshotRoundTrip_PreservesAllFields()
    {
        var original = new AgentConfig
        {
            ScanIntervalHours = 12,
            AutoFixCritical = true,
            AutoFixWarnings = true,
            RiskTolerance = RiskTolerance.Low,
            ModuleToggles = new Dictionary<string, bool>
            {
                ["ProcessMonitor"] = true,
                ["NetworkMonitor"] = false,
                ["EventLogMonitor"] = true
            },
            MaxThreatLogSize = 500,
            NotifyOnCriticalThreats = false,
            NotifyOnScanComplete = false,
            NotificationSound = false,
            NotifyCriticalOnly = true,
            AutoExportAfterScan = true,
            AutoExportFormat = "JSON",
            StartWithWindows = true,
            MinimizeToTray = false,
            CategoryAutoFix = new Dictionary<string, bool> { ["Process"] = true, ["FileSystem"] = false },
            CategoryDefaultResponse = new Dictionary<string, string> { ["Process"] = "AutoFix", ["EventLog"] = "Alert" }
        };

        var snapshot = original.ToSnapshot();
        var restored = new AgentConfig();
        restored.ApplySnapshot(snapshot);

        Assert.Equal(original.ScanIntervalHours, restored.ScanIntervalHours);
        Assert.Equal(original.AutoFixCritical, restored.AutoFixCritical);
        Assert.Equal(original.AutoFixWarnings, restored.AutoFixWarnings);
        Assert.Equal(original.RiskTolerance, restored.RiskTolerance);
        Assert.Equal(original.NotificationSound, restored.NotificationSound);
        Assert.Equal(original.NotifyCriticalOnly, restored.NotifyCriticalOnly);
        Assert.Equal(original.AutoExportAfterScan, restored.AutoExportAfterScan);
        Assert.Equal(original.AutoExportFormat, restored.AutoExportFormat);
        Assert.Equal(original.StartWithWindows, restored.StartWithWindows);
        Assert.Equal(original.MinimizeToTray, restored.MinimizeToTray);
        Assert.Equal(original.CategoryAutoFix.Count, restored.CategoryAutoFix.Count);
        Assert.Equal(original.CategoryDefaultResponse.Count, restored.CategoryDefaultResponse.Count);
    }

    // ── ResponsePolicy NetworkMonitor Classification ──

    [Fact]
    public void ResponsePolicy_ClassifiesNetworkMonitor()
    {
        var category = ResponsePolicy.ClassifyCategory("NetworkMonitor");
        Assert.Equal(ThreatCategory.Network, category);
    }

    [Fact]
    public void ResponsePolicy_ClassifiesNetworkMonitor_CaseInsensitive()
    {
        var category = ResponsePolicy.ClassifyCategory("networkmonitor");
        Assert.Equal(ThreatCategory.Network, category);
    }

    // ── User Override Management ──

    [Fact]
    public void ResponsePolicy_AddUserOverride_Works()
    {
        var policy = new ResponsePolicy();
        policy.AddUserOverride("Test Threat", UserOverrideAction.AlwaysIgnore);

        Assert.Single(policy.UserOverrides);
        Assert.Equal("Test Threat", policy.UserOverrides[0].ThreatTitle);
        Assert.Equal(UserOverrideAction.AlwaysIgnore, policy.UserOverrides[0].OverrideAction);
    }

    [Fact]
    public void ResponsePolicy_RemoveUserOverride_Works()
    {
        var policy = new ResponsePolicy();
        policy.AddUserOverride("Test Threat", UserOverrideAction.AlwaysAutoFix);
        Assert.Single(policy.UserOverrides);

        var removed = policy.RemoveUserOverride("Test Threat");
        Assert.True(removed);
        Assert.Empty(policy.UserOverrides);
    }

    [Fact]
    public void ResponsePolicy_RemoveUserOverride_NonexistentReturnsFalse()
    {
        var policy = new ResponsePolicy();
        var removed = policy.RemoveUserOverride("Nonexistent");
        Assert.False(removed);
    }

    [Fact]
    public void ResponsePolicy_AddUserOverride_ReplacesDuplicate()
    {
        var policy = new ResponsePolicy();
        policy.AddUserOverride("Test Threat", UserOverrideAction.AlwaysIgnore);
        policy.AddUserOverride("Test Threat", UserOverrideAction.AlwaysAutoFix);

        Assert.Single(policy.UserOverrides);
        Assert.Equal(UserOverrideAction.AlwaysAutoFix, policy.UserOverrides[0].OverrideAction);
    }

    // ── Module Toggles with NetworkMonitor ──

    [Fact]
    public void AgentConfig_IsModuleEnabled_NetworkMonitor_DefaultTrue()
    {
        var config = new AgentConfig();
        Assert.True(config.IsModuleEnabled("NetworkMonitor"));
    }

    [Fact]
    public void AgentConfig_IsModuleEnabled_NetworkMonitor_CanBeDisabled()
    {
        var config = new AgentConfig();
        config.ModuleToggles["NetworkMonitor"] = false;
        Assert.False(config.IsModuleEnabled("NetworkMonitor"));
    }
}
