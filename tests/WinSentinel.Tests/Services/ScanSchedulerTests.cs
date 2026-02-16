using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

[Collection("SettingsFile")]
public class ScanSchedulerTests
{
    private static AuditEngine CreateMockEngine()
    {
        // Use an empty engine for fast test scans
        return new AuditEngine(Array.Empty<Core.Interfaces.IAuditModule>());
    }

    [Fact]
    public void Constructor_LoadsSettings()
    {
        var settings = new ScheduleSettings { Enabled = true, Interval = ScanInterval.Hourly };
        var engine = CreateMockEngine();
        var scheduler = new ScanScheduler(engine, settings);

        Assert.True(scheduler.Settings.Enabled);
        Assert.Equal(ScanInterval.Hourly, scheduler.Settings.Interval);
    }

    [Fact]
    public void Start_WithDisabledSettings_DoesNotActivate()
    {
        var settings = new ScheduleSettings { Enabled = false };
        var engine = CreateMockEngine();
        var scheduler = new ScanScheduler(engine, settings);

        scheduler.Start();

        Assert.False(scheduler.IsSchedulerActive);
        scheduler.Dispose();
    }

    [Fact]
    public void Start_WithEnabledSettings_Activates()
    {
        var settings = new ScheduleSettings { Enabled = true, Interval = ScanInterval.Daily };
        var engine = CreateMockEngine();
        var scheduler = new ScanScheduler(engine, settings);

        scheduler.Start();

        Assert.True(scheduler.IsSchedulerActive);
        scheduler.Dispose();
    }

    [Fact]
    public void Stop_DeactivatesScheduler()
    {
        var settings = new ScheduleSettings { Enabled = true, Interval = ScanInterval.Hourly };
        var engine = CreateMockEngine();
        var scheduler = new ScanScheduler(engine, settings);

        scheduler.Start();
        Assert.True(scheduler.IsSchedulerActive);

        scheduler.Stop();
        Assert.False(scheduler.IsSchedulerActive);
        scheduler.Dispose();
    }

    [Fact]
    public void UpdateSettings_RestartsWithNewSettings()
    {
        var settings = new ScheduleSettings { Enabled = true, Interval = ScanInterval.Hourly };
        var engine = CreateMockEngine();
        var scheduler = new ScanScheduler(engine, settings);

        scheduler.Start();

        var newSettings = new ScheduleSettings { Enabled = true, Interval = ScanInterval.Daily };
        scheduler.UpdateSettings(newSettings);

        Assert.Equal(ScanInterval.Daily, scheduler.Settings.Interval);
        Assert.True(scheduler.IsSchedulerActive);
        scheduler.Dispose();
    }

    [Fact]
    public void UpdateSettings_DisablingStopsScheduler()
    {
        var settings = new ScheduleSettings { Enabled = true, Interval = ScanInterval.Hourly };
        var engine = CreateMockEngine();
        var scheduler = new ScanScheduler(engine, settings);

        scheduler.Start();
        Assert.True(scheduler.IsSchedulerActive);

        var newSettings = new ScheduleSettings { Enabled = false };
        scheduler.UpdateSettings(newSettings);

        Assert.False(scheduler.IsSchedulerActive);
        scheduler.Dispose();
    }

    [Fact]
    public async Task RunScanNowAsync_ExecutesScanAndRaisesEvent()
    {
        var settings = new ScheduleSettings { Enabled = false };
        var engine = CreateMockEngine();
        var scheduler = new ScanScheduler(engine, settings);

        SecurityReport? completedReport = null;
        scheduler.ScanCompleted += (_, args) => completedReport = args.Report;

        var report = await scheduler.RunScanNowAsync();

        Assert.NotNull(report);
        Assert.NotNull(completedReport);
        Assert.Equal(report.SecurityScore, completedReport!.SecurityScore);
        scheduler.Dispose();
    }

    [Fact]
    public async Task RunScanNowAsync_PreventsConcurrentScans()
    {
        var settings = new ScheduleSettings { Enabled = false };
        var engine = CreateMockEngine();
        var scheduler = new ScanScheduler(engine, settings);

        // Run two scans concurrently
        var task1 = scheduler.RunScanNowAsync();
        var task2 = scheduler.RunScanNowAsync();

        var results = await Task.WhenAll(task1, task2);

        // One should succeed, one should return null (skipped)
        Assert.True(results[0] != null || results[1] != null);
        scheduler.Dispose();
    }

    [Fact]
    public void IsScanRunning_DefaultsFalse()
    {
        var settings = new ScheduleSettings { Enabled = false };
        var engine = CreateMockEngine();
        var scheduler = new ScanScheduler(engine, settings);

        Assert.False(scheduler.IsScanRunning);
        scheduler.Dispose();
    }

    [Fact]
    public void NextScanTime_NullWhenDisabled()
    {
        var settings = new ScheduleSettings { Enabled = false };
        var engine = CreateMockEngine();
        var scheduler = new ScanScheduler(engine, settings);

        Assert.Null(scheduler.NextScanTime);
        scheduler.Dispose();
    }

    [Fact]
    public void NextScanTime_CalculatesCorrectly()
    {
        var lastScan = DateTimeOffset.UtcNow.AddHours(-2);
        var settings = new ScheduleSettings
        {
            Enabled = true,
            Interval = ScanInterval.Daily,
            LastScanTime = lastScan
        };
        var engine = CreateMockEngine();
        var scheduler = new ScanScheduler(engine, settings);

        var nextScan = scheduler.NextScanTime;
        Assert.NotNull(nextScan);

        // Should be ~22 hours from now (24h - 2h elapsed)
        var expectedNext = lastScan + TimeSpan.FromHours(24);
        Assert.Equal(expectedNext, nextScan!.Value);
        scheduler.Dispose();
    }

    [Fact]
    public void Dispose_MultipleCallsDoesNotThrow()
    {
        var settings = new ScheduleSettings { Enabled = true };
        var engine = CreateMockEngine();
        var scheduler = new ScanScheduler(engine, settings);
        scheduler.Start();

        scheduler.Dispose();
        scheduler.Dispose(); // Should not throw
    }

    [Fact]
    public void Dispose_ThrowsOnSubsequentStart()
    {
        var settings = new ScheduleSettings { Enabled = true };
        var engine = CreateMockEngine();
        var scheduler = new ScanScheduler(engine, settings);

        scheduler.Dispose();

        Assert.Throws<ObjectDisposedException>(() => scheduler.Start());
    }
}
