using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class ConfigBackupServiceTests : IDisposable
{
    private readonly string _tempDir;

    public ConfigBackupServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"ws-config-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void Export_CreatesValidBundle()
    {
        var service = new ConfigBackupService();
        var bundle = service.Export("test backup");

        Assert.Equal(1, bundle.Version);
        Assert.Equal("test backup", bundle.Description);
        Assert.Equal(Environment.MachineName, bundle.MachineName);
        Assert.Equal(Environment.UserName, bundle.ExportedBy);
        Assert.NotNull(bundle.Summary);
        Assert.Equal(bundle.IgnoreRules.Count, bundle.Summary.IgnoreRuleCount);
        Assert.Equal(bundle.Baselines.Count, bundle.Summary.BaselineCount);
    }

    [Fact]
    public void RoundTrip_JsonSerializationWorks()
    {
        var bundle = new ConfigBundle
        {
            Description = "round-trip test",
            IgnoreRules = [new IgnoreRule
            {
                Pattern = "test-pattern",
                MatchMode = IgnoreMatchMode.Contains,
                Reason = "testing"
            }],
            Baselines = [new SecurityBaseline
            {
                Name = "test-baseline",
                OverallScore = 85,
                Grade = "B+"
            }],
            Summary = new ConfigBundleSummary
            {
                IgnoreRuleCount = 1,
                BaselineCount = 1,
                HasPolicy = false
            }
        };

        var json = ConfigBackupService.ToJson(bundle);
        Assert.NotNull(json);
        Assert.Contains("round-trip test", json);

        var restored = ConfigBackupService.FromJson(json);
        Assert.NotNull(restored);
        Assert.Equal("round-trip test", restored!.Description);
        Assert.Single(restored.IgnoreRules);
        Assert.Equal("test-pattern", restored.IgnoreRules[0].Pattern);
        Assert.Single(restored.Baselines);
        Assert.Equal("test-baseline", restored.Baselines[0].Name);
        Assert.Equal(85, restored.Baselines[0].OverallScore);
    }

    [Fact]
    public void Inspect_ReturnsNullForMissingFile()
    {
        var result = ConfigBackupService.Inspect(Path.Combine(_tempDir, "nonexistent.json"));
        Assert.Null(result);
    }

    [Fact]
    public void Inspect_ParsesValidFile()
    {
        var bundle = new ConfigBundle { Description = "inspect test" };
        var json = ConfigBackupService.ToJson(bundle);
        var filePath = Path.Combine(_tempDir, "test-bundle.json");
        File.WriteAllText(filePath, json);

        var result = ConfigBackupService.Inspect(filePath);
        Assert.NotNull(result);
        Assert.Equal("inspect test", result!.Description);
    }

    [Fact]
    public void BundleSummary_TotalItemsCalculation()
    {
        var summary = new ConfigBundleSummary
        {
            IgnoreRuleCount = 5,
            BaselineCount = 3,
            HasPolicy = true
        };

        Assert.Equal(9, summary.TotalItems);
    }

    [Fact]
    public void RestoreResult_TotalCalculations()
    {
        var result = new ConfigRestoreResult
        {
            IgnoreRulesImported = 3,
            BaselinesImported = 2,
            PolicyImported = true,
            IgnoreRulesSkipped = 1,
            BaselinesSkipped = 0
        };

        Assert.Equal(6, result.TotalImported);
        Assert.Equal(1, result.TotalSkipped);
    }
}
