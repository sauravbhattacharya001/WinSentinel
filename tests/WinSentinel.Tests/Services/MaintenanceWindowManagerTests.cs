using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class MaintenanceWindowManagerTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _filePath;
    private readonly MaintenanceWindowManager _mgr;

    public MaintenanceWindowManagerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"ws-maint-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _filePath = Path.Combine(_tempDir, "maintenance-windows.json");
        _mgr = new MaintenanceWindowManager(_filePath);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private MaintenanceWindowRequest MakeRequest(
        string name = "Patch Tuesday",
        int hoursFromNow = -1,
        int durationHours = 4,
        List<string>? categories = null,
        List<Severity>? severities = null,
        List<string>? titlePatterns = null,
        bool recurring = false,
        int recurrenceDays = 0) => new()
    {
        Name = name,
        Description = $"Test window: {name}",
        StartUtc = DateTimeOffset.UtcNow.AddHours(hoursFromNow),
        EndUtc = DateTimeOffset.UtcNow.AddHours(hoursFromNow + durationHours),
        SuppressedCategories = categories,
        SuppressedSeverities = severities,
        SuppressedTitlePatterns = titlePatterns,
        Recurring = recurring,
        RecurrenceIntervalDays = recurrenceDays,
        CreatedBy = "tester"
    };

    [Fact]
    public void Create_ValidRequest_ReturnsWindow()
    {
        var w = _mgr.Create(MakeRequest());
        Assert.NotNull(w);
        Assert.Equal("Patch Tuesday", w.Name);
        Assert.Equal(12, w.Id.Length);
        Assert.Equal("tester", w.CreatedBy);
    }

    [Fact]
    public void Create_EmptyName_Throws()
    {
        Assert.Throws<ArgumentException>(() => _mgr.Create(MakeRequest(name: "")));
    }

    [Fact]
    public void Create_EndBeforeStart_Throws()
    {
        var req = MakeRequest();
        req.EndUtc = req.StartUtc.AddHours(-1);
        Assert.Throws<ArgumentException>(() => _mgr.Create(req));
    }

    [Fact]
    public void Create_NullRequest_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _mgr.Create(null!));
    }

    [Fact]
    public void GetAll_ReturnsCreatedWindows()
    {
        _mgr.Create(MakeRequest("W1"));
        _mgr.Create(MakeRequest("W2"));
        Assert.Equal(2, _mgr.GetAll().Count);
    }

    [Fact]
    public void GetById_ExistingId_ReturnsWindow()
    {
        var w = _mgr.Create(MakeRequest());
        Assert.NotNull(_mgr.GetById(w.Id));
    }

    [Fact]
    public void GetById_NonExistentId_ReturnsNull()
    {
        Assert.Null(_mgr.GetById("nonexistent"));
    }

    [Fact]
    public void Delete_ExistingId_RemovesWindow()
    {
        var w = _mgr.Create(MakeRequest());
        Assert.True(_mgr.Delete(w.Id));
        Assert.Empty(_mgr.GetAll());
    }

    [Fact]
    public void Delete_NonExistentId_ReturnsFalse()
    {
        Assert.False(_mgr.Delete("nope"));
    }

    [Fact]
    public void Cancel_SetsFlag()
    {
        var w = _mgr.Create(MakeRequest());
        Assert.True(_mgr.Cancel(w.Id));
        Assert.True(_mgr.GetById(w.Id)!.Cancelled);
    }

    [Fact]
    public void Cancel_NonExistent_ReturnsFalse()
    {
        Assert.False(_mgr.Cancel("nope"));
    }

    [Fact]
    public void Extend_AddsTime()
    {
        var w = _mgr.Create(MakeRequest());
        var origEnd = w.EndUtc;
        Assert.True(_mgr.Extend(w.Id, TimeSpan.FromHours(2)));
        var updated = _mgr.GetById(w.Id)!;
        Assert.Equal(origEnd.AddHours(2), updated.EndUtc);
    }

    [Fact]
    public void Extend_NegativeDuration_Throws()
    {
        var w = _mgr.Create(MakeRequest());
        Assert.Throws<ArgumentException>(() => _mgr.Extend(w.Id, TimeSpan.FromHours(-1)));
    }

    [Fact]
    public void Extend_NonExistent_ReturnsFalse()
    {
        Assert.False(_mgr.Extend("nope", TimeSpan.FromHours(1)));
    }

    [Fact]
    public void GetActive_ReturnsActiveWindows()
    {
        // Active window (started 1h ago, ends in 3h)
        _mgr.Create(MakeRequest("Active"));
        // Future window (starts in 5h)
        _mgr.Create(MakeRequest("Future", hoursFromNow: 5));

        var active = _mgr.GetActive();
        Assert.Single(active);
        Assert.Equal("Active", active[0].Name);
    }

    [Fact]
    public void GetActive_ExcludesCancelled()
    {
        var w = _mgr.Create(MakeRequest("Cancelled"));
        _mgr.Cancel(w.Id);
        Assert.Empty(_mgr.GetActive());
    }

    [Fact]
    public void GetActive_RecurringWindow()
    {
        var start = DateTimeOffset.UtcNow.AddDays(-7).AddHours(-1);
        var req = new MaintenanceWindowRequest
        {
            Name = "Weekly Patch",
            StartUtc = start,
            EndUtc = start.AddHours(4),
            Recurring = true,
            RecurrenceIntervalDays = 7
        };
        _mgr.Create(req);

        // Should be active now (7 days after start, within 4h window)
        var active = _mgr.GetActive();
        Assert.Single(active);
    }

    [Fact]
    public void GetUpcoming_ReturnsScheduledWindows()
    {
        _mgr.Create(MakeRequest("Soon", hoursFromNow: 2));
        _mgr.Create(MakeRequest("Far", hoursFromNow: 100));

        var upcoming = _mgr.GetUpcoming(TimeSpan.FromHours(24));
        Assert.Single(upcoming);
        Assert.Equal("Soon", upcoming[0].Name);
    }

    [Fact]
    public void IsSuppressed_NoFilters_SuppressesAll()
    {
        _mgr.Create(MakeRequest());
        var finding = Finding.Warning("Test", "Desc", "Network");
        Assert.True(_mgr.IsSuppressed(finding));
    }

    [Fact]
    public void IsSuppressed_CategoryFilter_MatchesCategory()
    {
        _mgr.Create(MakeRequest(categories: new List<string> { "Network" }));
        Assert.True(_mgr.IsSuppressed(Finding.Warning("Test", "Desc", "Network")));
        Assert.False(_mgr.IsSuppressed(Finding.Warning("Test", "Desc", "Firewall")));
    }

    [Fact]
    public void IsSuppressed_SeverityFilter_MatchesSeverity()
    {
        _mgr.Create(MakeRequest(severities: new List<Severity> { Severity.Warning }));
        Assert.True(_mgr.IsSuppressed(Finding.Warning("Test", "Desc", "Cat")));
        Assert.False(_mgr.IsSuppressed(Finding.Critical("Test", "Desc", "Cat")));
    }

    [Fact]
    public void IsSuppressed_TitlePattern_Matches()
    {
        _mgr.Create(MakeRequest(titlePatterns: new List<string> { "firewall" }));
        Assert.True(_mgr.IsSuppressed(Finding.Warning("Firewall rule issue", "Desc", "Cat")));
        Assert.False(_mgr.IsSuppressed(Finding.Warning("DNS problem", "Desc", "Cat")));
    }

    [Fact]
    public void IsSuppressed_NoActiveWindow_ReturnsFalse()
    {
        _mgr.Create(MakeRequest("Future", hoursFromNow: 5));
        Assert.False(_mgr.IsSuppressed(Finding.Warning("Test", "Desc", "Cat")));
    }

    [Fact]
    public void IsSuppressed_NullFinding_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _mgr.IsSuppressed(null!));
    }

    [Fact]
    public void ApplyWindows_SplitsFindings()
    {
        _mgr.Create(MakeRequest(categories: new List<string> { "Network" }));
        var findings = new[]
        {
            Finding.Warning("Net issue", "Desc", "Network"),
            Finding.Critical("Disk issue", "Desc", "Storage"),
            Finding.Info("Net info", "Desc", "Network")
        };

        var result = _mgr.ApplyWindows(findings);
        Assert.Equal(1, result.Kept.Count);
        Assert.Equal(2, result.SuppressedCount);
        Assert.Equal(3, result.TotalCount);
        Assert.True(result.SuppressionRate > 0.6);
    }

    [Fact]
    public void ApplyWindows_NullFindings_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _mgr.ApplyWindows(null!));
    }

    [Fact]
    public void PurgeExpired_RemovesOldWindows()
    {
        var req = MakeRequest(hoursFromNow: -48, durationHours: 2);
        _mgr.Create(req);
        _mgr.Create(MakeRequest()); // active

        var purged = _mgr.PurgeExpired(TimeSpan.FromHours(24));
        Assert.Equal(1, purged);
        Assert.Single(_mgr.GetAll());
    }

    [Fact]
    public void PurgeExpired_KeepsRecurring()
    {
        var req = MakeRequest(hoursFromNow: -48, durationHours: 2);
        req.Recurring = true;
        req.RecurrenceIntervalDays = 7;
        _mgr.Create(req);

        var purged = _mgr.PurgeExpired(TimeSpan.FromHours(24));
        Assert.Equal(0, purged);
    }

    [Fact]
    public void GenerateReport_ContainsWindowInfo()
    {
        _mgr.Create(MakeRequest("Patch Window", categories: new List<string> { "Updates" }));
        var report = _mgr.GenerateReport();
        Assert.Contains("Patch Window", report);
        Assert.Contains("Updates", report);
        Assert.Contains("ACTIVE", report);
    }

    [Fact]
    public void GenerateReport_EmptyWindows()
    {
        var report = _mgr.GenerateReport();
        Assert.Contains("No maintenance windows configured", report);
    }

    [Fact]
    public void ExportImport_RoundTrip()
    {
        _mgr.Create(MakeRequest("W1"));
        _mgr.Create(MakeRequest("W2"));
        var json = _mgr.ExportJson();

        var mgr2 = new MaintenanceWindowManager(Path.Combine(_tempDir, "import.json"));
        var imported = mgr2.ImportJson(json);
        Assert.Equal(2, imported);
        Assert.Equal(2, mgr2.GetAll().Count);
    }

    [Fact]
    public void ImportJson_SkipsDuplicateIds()
    {
        var w = _mgr.Create(MakeRequest());
        var json = _mgr.ExportJson();
        var imported = _mgr.ImportJson(json);
        Assert.Equal(0, imported);
        Assert.Single(_mgr.GetAll());
    }

    [Fact]
    public void ImportJson_EmptyJson_Throws()
    {
        Assert.Throws<ArgumentException>(() => _mgr.ImportJson(""));
    }

    [Fact]
    public void Persistence_SurvivesReload()
    {
        _mgr.Create(MakeRequest("Persistent"));
        var mgr2 = new MaintenanceWindowManager(_filePath);
        Assert.Single(mgr2.GetAll());
        Assert.Equal("Persistent", mgr2.GetAll()[0].Name);
    }

    [Fact]
    public void ApplyWindows_SuppressedFindingHasWindowInfo()
    {
        var w = _mgr.Create(MakeRequest());
        var result = _mgr.ApplyWindows(new[] { Finding.Warning("X", "Y", "Z") });
        Assert.Single(result.Suppressed);
        Assert.Equal(w.Id, result.Suppressed[0].WindowId);
        Assert.Equal(w.Name, result.Suppressed[0].WindowName);
    }

    [Fact]
    public void GetUpcoming_RecurringWindow()
    {
        var start = DateTimeOffset.UtcNow.AddDays(-6);
        _mgr.Create(new MaintenanceWindowRequest
        {
            Name = "Weekly",
            StartUtc = start,
            EndUtc = start.AddHours(2),
            Recurring = true,
            RecurrenceIntervalDays = 7
        });

        var upcoming = _mgr.GetUpcoming(TimeSpan.FromDays(3));
        Assert.Single(upcoming);
    }

    [Fact]
    public void MultipleWindows_FirstMatchWins()
    {
        _mgr.Create(MakeRequest("Broad"));
        _mgr.Create(MakeRequest("Narrow", categories: new List<string> { "Network" }));
        var result = _mgr.ApplyWindows(new[] { Finding.Warning("Test", "Desc", "Network") });
        // Should be suppressed by Broad (no filters = suppress all)
        Assert.Equal("Broad", result.Suppressed[0].WindowName);
    }

    [Fact]
    public void CategoryFilter_CaseInsensitive()
    {
        _mgr.Create(MakeRequest(categories: new List<string> { "network" }));
        Assert.True(_mgr.IsSuppressed(Finding.Warning("X", "Y", "NETWORK")));
    }

    [Fact]
    public void TitlePattern_CaseInsensitive()
    {
        _mgr.Create(MakeRequest(titlePatterns: new List<string> { "FIREWALL" }));
        Assert.True(_mgr.IsSuppressed(Finding.Warning("firewall disabled", "Y", "Cat")));
    }
}
