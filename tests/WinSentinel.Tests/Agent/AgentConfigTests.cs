using WinSentinel.Agent;

namespace WinSentinel.Tests.Agent;

/// <summary>
/// Tests for AgentConfig persistence and behavior.
/// </summary>
public class AgentConfigTests
{
    [Fact]
    public void New_Config_Has_Sensible_Defaults()
    {
        var config = new AgentConfig();

        Assert.Equal(4.0, config.ScanIntervalHours);
        Assert.False(config.AutoFixCritical);
        Assert.False(config.AutoFixWarnings);
        Assert.Equal(RiskTolerance.Medium, config.RiskTolerance);
        Assert.Empty(config.ModuleToggles);
        Assert.Equal(1000, config.MaxThreatLogSize);
        Assert.True(config.NotifyOnCriticalThreats);
        Assert.True(config.NotifyOnScanComplete);
    }

    [Fact]
    public void IsModuleEnabled_Returns_True_For_Unknown_Module()
    {
        var config = new AgentConfig();
        Assert.True(config.IsModuleEnabled("SomeNewModule"));
    }

    [Fact]
    public void IsModuleEnabled_Returns_False_When_Disabled()
    {
        var config = new AgentConfig();
        config.ModuleToggles["ProcessMonitor"] = false;

        Assert.False(config.IsModuleEnabled("ProcessMonitor"));
    }

    [Fact]
    public void IsModuleEnabled_Returns_True_When_Enabled()
    {
        var config = new AgentConfig();
        config.ModuleToggles["ProcessMonitor"] = true;

        Assert.True(config.IsModuleEnabled("ProcessMonitor"));
    }

    [Fact]
    public void ToSnapshot_And_ApplySnapshot_Roundtrip()
    {
        var config = new AgentConfig
        {
            ScanIntervalHours = 2.5,
            AutoFixCritical = true,
            AutoFixWarnings = false,
            RiskTolerance = RiskTolerance.Low,
            MaxThreatLogSize = 500,
            NotifyOnCriticalThreats = false,
            NotifyOnScanComplete = true
        };
        config.ModuleToggles["TestModule"] = false;

        var snapshot = config.ToSnapshot();

        // Apply to a new config instance
        var newConfig = new AgentConfig();
        newConfig.ApplySnapshot(snapshot);

        Assert.Equal(2.5, newConfig.ScanIntervalHours);
        Assert.True(newConfig.AutoFixCritical);
        Assert.False(newConfig.AutoFixWarnings);
        Assert.Equal(RiskTolerance.Low, newConfig.RiskTolerance);
        Assert.Equal(500, newConfig.MaxThreatLogSize);
        Assert.False(newConfig.NotifyOnCriticalThreats);
        Assert.True(newConfig.NotifyOnScanComplete);
        Assert.False(newConfig.IsModuleEnabled("TestModule"));
    }

    [Fact]
    public void Snapshot_RiskTolerance_Is_String()
    {
        var config = new AgentConfig { RiskTolerance = RiskTolerance.High };
        var snapshot = config.ToSnapshot();

        Assert.Equal("High", snapshot.RiskTolerance);
    }

    [Fact]
    public void ApplySnapshot_Handles_Invalid_RiskTolerance()
    {
        var config = new AgentConfig();
        var snapshot = new AgentConfigSnapshot { RiskTolerance = "InvalidValue" };

        // Should not throw, should keep the existing value
        config.ApplySnapshot(snapshot);
        Assert.Equal(RiskTolerance.Medium, config.RiskTolerance);
    }

    [Fact]
    public void Save_And_Load_Persistence()
    {
        // Use a temp path for testing
        var tempDir = Path.Combine(Path.GetTempPath(), "WinSentinel_Test_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);
        var configPath = Path.Combine(tempDir, "test-agent-config.json");

        try
        {
            var config = new AgentConfig
            {
                ScanIntervalHours = 6.0,
                AutoFixCritical = true,
                RiskTolerance = RiskTolerance.High,
                MaxThreatLogSize = 2000
            };
            config.ModuleToggles["TestModule"] = false;

            // Write manually to test path
            var json = System.Text.Json.JsonSerializer.Serialize(config, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true,
                Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
            });
            File.WriteAllText(configPath, json);

            // Read back
            var loaded = System.Text.Json.JsonSerializer.Deserialize<AgentConfig>(
                File.ReadAllText(configPath),
                new System.Text.Json.JsonSerializerOptions
                {
                    Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
                });

            Assert.NotNull(loaded);
            Assert.Equal(6.0, loaded.ScanIntervalHours);
            Assert.True(loaded.AutoFixCritical);
            Assert.Equal(RiskTolerance.High, loaded.RiskTolerance);
            Assert.Equal(2000, loaded.MaxThreatLogSize);
            Assert.False(loaded.IsModuleEnabled("TestModule"));
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }
}
