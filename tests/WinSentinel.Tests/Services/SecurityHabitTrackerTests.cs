using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests.Services;

public class SecurityHabitTrackerTests : IDisposable
{
    private readonly string _tempDir;
    private readonly SecurityHabitTracker _sut;

    public SecurityHabitTrackerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "WinSentinel_Tests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _sut = new SecurityHabitTracker(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    // ── AddHabit ───────────────────────────────────────────────

    [Fact]
    public void AddHabit_NewHabit_PersistsToFile()
    {
        _sut.AddHabit("Check Updates", "System", "daily");

        var data = _sut.Load();
        Assert.Single(data.Habits);
        Assert.Equal("Check Updates", data.Habits[0].Name);
        Assert.Equal("System", data.Habits[0].Category);
        Assert.Equal("daily", data.Habits[0].Frequency);
        Assert.False(string.IsNullOrEmpty(data.Habits[0].CreatedDate));
    }

    [Fact]
    public void AddHabit_DefaultCategoryAndFrequency()
    {
        _sut.AddHabit("Review Logs");

        var data = _sut.Load();
        Assert.Equal("General", data.Habits[0].Category);
        Assert.Equal("daily", data.Habits[0].Frequency);
    }

    [Fact]
    public void AddHabit_DuplicateName_Throws()
    {
        _sut.AddHabit("Check Updates");

        var ex = Assert.Throws<InvalidOperationException>(
            () => _sut.AddHabit("check updates")); // case-insensitive
        Assert.Contains("already exists", ex.Message);
    }

    [Fact]
    public void AddHabit_MultipleHabits_AllPersisted()
    {
        _sut.AddHabit("Check Updates");
        _sut.AddHabit("Review Logs");
        _sut.AddHabit("Backup Config");

        var data = _sut.Load();
        Assert.Equal(3, data.Habits.Count);
    }

    // ── RemoveHabit ────────────────────────────────────────────

    [Fact]
    public void RemoveHabit_ExistingHabit_RemovesHabitAndCompletions()
    {
        _sut.AddHabit("Check Updates");
        _sut.Complete("Check Updates");
        _sut.RemoveHabit("Check Updates");

        var data = _sut.Load();
        Assert.Empty(data.Habits);
        Assert.Empty(data.Completions);
    }

    [Fact]
    public void RemoveHabit_CaseInsensitive()
    {
        _sut.AddHabit("Check Updates");
        _sut.RemoveHabit("CHECK UPDATES");

        var data = _sut.Load();
        Assert.Empty(data.Habits);
    }

    [Fact]
    public void RemoveHabit_NonExistent_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => _sut.RemoveHabit("Nonexistent"));
        Assert.Contains("not found", ex.Message);
    }

    // ── Complete ───────────────────────────────────────────────

    [Fact]
    public void Complete_ValidHabit_RecordsCompletion()
    {
        _sut.AddHabit("Check Updates");
        _sut.Complete("Check Updates", "2026-04-17");

        var data = _sut.Load();
        Assert.Single(data.Completions);
        Assert.Equal("Check Updates", data.Completions[0].Habit);
        Assert.Equal("2026-04-17", data.Completions[0].Date);
    }

    [Fact]
    public void Complete_NonExistentHabit_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => _sut.Complete("Ghost Habit"));
        Assert.Contains("not found", ex.Message);
    }

    [Fact]
    public void Complete_DuplicateDate_Throws()
    {
        _sut.AddHabit("Check Updates");
        _sut.Complete("Check Updates", "2026-04-17");

        var ex = Assert.Throws<InvalidOperationException>(
            () => _sut.Complete("Check Updates", "2026-04-17"));
        Assert.Contains("already completed", ex.Message);
    }

    [Fact]
    public void Complete_DifferentDates_AllRecorded()
    {
        _sut.AddHabit("Check Updates");
        _sut.Complete("Check Updates", "2026-04-15");
        _sut.Complete("Check Updates", "2026-04-16");
        _sut.Complete("Check Updates", "2026-04-17");

        var data = _sut.Load();
        Assert.Equal(3, data.Completions.Count);
    }

    // ── Load / Save roundtrip ──────────────────────────────────

    [Fact]
    public void Load_NoFile_ReturnsEmptyData()
    {
        var data = _sut.Load();
        Assert.Empty(data.Habits);
        Assert.Empty(data.Completions);
    }

    [Fact]
    public void Save_And_Load_Roundtrip()
    {
        var data = new HabitData();
        data.Habits.Add(new HabitDefinition { Name = "Test", Category = "Cat", Frequency = "weekly" });
        data.Completions.Add(new HabitCompletion { Habit = "Test", Date = "2026-01-01" });
        _sut.Save(data);

        var loaded = _sut.Load();
        Assert.Single(loaded.Habits);
        Assert.Equal("Test", loaded.Habits[0].Name);
        Assert.Single(loaded.Completions);
    }

    // ── GetReport ──────────────────────────────────────────────

    [Fact]
    public void GetReport_NoHabits_ReturnsEmptyReport()
    {
        var report = _sut.GetReport();

        Assert.Equal(0, report.TotalHabits);
        Assert.Equal(0, report.CompletedToday);
        Assert.Equal(0.0, report.OverallConsistency);
        Assert.Empty(report.HabitStats);
    }

    [Fact]
    public void GetReport_HabitWithNoCompletions_ZeroConsistency()
    {
        _sut.AddHabit("Check Updates");

        var report = _sut.GetReport(days: 30);

        Assert.Single(report.HabitStats);
        Assert.Equal(0, report.HabitStats[0].CompletedDays);
        Assert.Equal(0.0, report.HabitStats[0].ConsistencyPercent);
        Assert.Equal(0, report.HabitStats[0].CurrentStreak);
        Assert.Equal(0, report.HabitStats[0].BestStreak);
        Assert.False(report.HabitStats[0].CompletedToday);
    }

    [Fact]
    public void GetReport_ConsecutiveCompletions_CorrectStreak()
    {
        _sut.AddHabit("Check Updates");
        var today = DateTime.UtcNow.Date;
        // Complete today and 2 previous days
        for (int i = 0; i < 3; i++)
            _sut.Complete("Check Updates", today.AddDays(-i).ToString("yyyy-MM-dd"));

        var report = _sut.GetReport(days: 30);
        var stats = report.HabitStats[0];

        Assert.Equal(3, stats.CurrentStreak);
        Assert.Equal(3, stats.BestStreak);
        Assert.Equal(3, stats.CompletedDays);
        Assert.True(stats.CompletedToday);
    }

    [Fact]
    public void GetReport_BrokenStreak_CurrentStreakResets()
    {
        _sut.AddHabit("Review Logs");
        var today = DateTime.UtcNow.Date;
        // Complete today and yesterday, skip day before, then 3 days before that
        _sut.Complete("Review Logs", today.ToString("yyyy-MM-dd"));
        _sut.Complete("Review Logs", today.AddDays(-1).ToString("yyyy-MM-dd"));
        // Skip -2
        _sut.Complete("Review Logs", today.AddDays(-3).ToString("yyyy-MM-dd"));
        _sut.Complete("Review Logs", today.AddDays(-4).ToString("yyyy-MM-dd"));
        _sut.Complete("Review Logs", today.AddDays(-5).ToString("yyyy-MM-dd"));

        var report = _sut.GetReport(days: 30);
        var stats = report.HabitStats[0];

        Assert.Equal(2, stats.CurrentStreak); // today + yesterday
        Assert.Equal(3, stats.BestStreak); // days -3, -4, -5
    }

    [Fact]
    public void GetReport_Last7Days_Has7Elements()
    {
        _sut.AddHabit("Check Updates");

        var report = _sut.GetReport(days: 30);

        Assert.Equal(7, report.HabitStats[0].Last7Days.Count);
    }

    [Fact]
    public void GetReport_MultipleHabits_OverallConsistency()
    {
        _sut.AddHabit("Habit A");
        _sut.AddHabit("Habit B");
        var today = DateTime.UtcNow.Date;
        // Complete Habit A for all 7 days, Habit B for none
        for (int i = 0; i < 7; i++)
            _sut.Complete("Habit A", today.AddDays(-i).ToString("yyyy-MM-dd"));

        var report = _sut.GetReport(days: 7);

        Assert.Equal(2, report.TotalHabits);
        Assert.Equal(1, report.CompletedToday);
        // Habit A = 100%, Habit B = 0% → average = 50%
        Assert.Equal(50.0, report.OverallConsistency);
    }

    [Fact]
    public void GetReport_CompletionsOutsideWindow_Excluded()
    {
        _sut.AddHabit("Check Updates");
        var today = DateTime.UtcNow.Date;
        // Complete 60 days ago — outside 30-day window
        _sut.Complete("Check Updates", today.AddDays(-60).ToString("yyyy-MM-dd"));

        var report = _sut.GetReport(days: 30);

        Assert.Equal(0, report.HabitStats[0].CompletedDays);
    }

    [Fact]
    public void GetReport_CustomDaysParameter()
    {
        _sut.AddHabit("Check Updates");
        var today = DateTime.UtcNow.Date;
        _sut.Complete("Check Updates", today.ToString("yyyy-MM-dd"));

        var report7 = _sut.GetReport(days: 7);
        var report1 = _sut.GetReport(days: 1);

        // 1 out of 7 days = ~14.3%
        Assert.True(report7.HabitStats[0].ConsistencyPercent > 14.0
                  && report7.HabitStats[0].ConsistencyPercent < 15.0);
        // 1 out of 1 day = 100%
        Assert.Equal(100.0, report1.HabitStats[0].ConsistencyPercent);
    }
}
