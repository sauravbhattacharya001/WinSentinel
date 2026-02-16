using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Models;

public class ScheduleSettingsTests
{
    [Fact]
    public void Defaults_AreCorrect()
    {
        var settings = new ScheduleSettings();

        Assert.False(settings.Enabled);
        Assert.Equal(ScanInterval.Daily, settings.Interval);
        Assert.Equal(120, settings.CustomIntervalMinutes);
        Assert.Empty(settings.IncludedModules);
        Assert.True(settings.NotifyOnComplete);
        Assert.True(settings.NotifyOnScoreDrop);
        Assert.True(settings.NotifyOnNewFindings);
        Assert.Null(settings.LastScanTime);
        Assert.Null(settings.LastScore);
    }

    [Theory]
    [InlineData(ScanInterval.Hourly, 60)]
    [InlineData(ScanInterval.Daily, 1440)]
    public void EffectiveInterval_ReturnsCorrectMinutes(ScanInterval interval, int expectedMinutes)
    {
        var settings = new ScheduleSettings { Interval = interval };

        Assert.Equal(TimeSpan.FromMinutes(expectedMinutes), settings.EffectiveInterval);
    }

    [Fact]
    public void EffectiveInterval_Custom_UsesCustomMinutes()
    {
        var settings = new ScheduleSettings
        {
            Interval = ScanInterval.Custom,
            CustomIntervalMinutes = 30
        };

        Assert.Equal(TimeSpan.FromMinutes(30), settings.EffectiveInterval);
    }

    [Fact]
    public void EffectiveInterval_Custom_EnforcesMinimum5Minutes()
    {
        var settings = new ScheduleSettings
        {
            Interval = ScanInterval.Custom,
            CustomIntervalMinutes = 1
        };

        Assert.Equal(TimeSpan.FromMinutes(5), settings.EffectiveInterval);
    }

    [Fact]
    public void SaveAndLoad_RoundTrips()
    {
        var settings = new ScheduleSettings
        {
            Enabled = true,
            Interval = ScanInterval.Hourly,
            CustomIntervalMinutes = 45,
            NotifyOnComplete = false,
            NotifyOnScoreDrop = true,
            NotifyOnNewFindings = false,
            LastScanTime = new DateTimeOffset(2026, 2, 15, 12, 0, 0, TimeSpan.Zero),
            LastScore = 78,
            IncludedModules = new List<string> { "Firewall", "Network" }
        };

        settings.Save();

        var loaded = ScheduleSettings.Load();
        Assert.True(loaded.Enabled);
        Assert.Equal(ScanInterval.Hourly, loaded.Interval);
        Assert.Equal(45, loaded.CustomIntervalMinutes);
        Assert.False(loaded.NotifyOnComplete);
        Assert.True(loaded.NotifyOnScoreDrop);
        Assert.False(loaded.NotifyOnNewFindings);
        Assert.NotNull(loaded.LastScanTime);
        Assert.Equal(78, loaded.LastScore);
        Assert.Contains("Firewall", loaded.IncludedModules);
        Assert.Contains("Network", loaded.IncludedModules);
    }
}
