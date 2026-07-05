using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the UpdateAudit module.
/// Runs audit once and shares the result across all tests.
/// </summary>
public class UpdateAuditTests : IAsyncLifetime
{
    private readonly UpdateAudit _audit = new();
    private AuditResult _result = null!;

    public async Task InitializeAsync()
    {
        _result = await _audit.RunAuditAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Update Audit", _audit.Name);
        Assert.Equal("Updates", _audit.Category);
    }

    [Fact]
    public void RunAuditAsync_Succeeds()
    {
        Assert.True(_result.Success, $"Audit failed: {_result.Error}");
    }

    [Fact]
    public void RunAuditAsync_ChecksLastUpdateDate()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Update", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksAutoUpdate()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Automatic", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Auto", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Update", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ProducesFindings()
    {
        Assert.NotEmpty(_result.Findings);
    }

    [Fact]
    public void RunAuditAsync_ScoreIsValid()
    {
        Assert.InRange(_result.Score, 0, 100);
    }

    [Fact]
    public void RunAuditAsync_ChecksWindowsSupportStatus()
    {
        // The support-lifecycle check always emits exactly one finding in the
        // "Windows ... Support"/"Windows Build ..." family (Critical/Warning/Pass/Info).
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Support", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Windows Build", StringComparison.OrdinalIgnoreCase));
    }

    // ---- ClassifyWindowsSupport: pure, deterministic lifecycle classification ----

    [Fact]
    public void Classify_Windows10_22H2_AfterEos_IsCritical()
    {
        // Win10 22H2 (19045) reached end of support 2025-10-14.
        var s = UpdateAudit.ClassifyWindowsSupport(19045, new DateTime(2026, 7, 5));
        Assert.Equal(Severity.Critical, s.Level);
        Assert.Equal(new DateTime(2025, 10, 14), s.EndDate);
    }

    [Fact]
    public void Classify_Windows10_22H2_BeforeEos_IsPass()
    {
        // Well before its EOS date it should be a clean Pass with the date attached.
        var s = UpdateAudit.ClassifyWindowsSupport(19045, new DateTime(2025, 1, 1));
        Assert.Equal(Severity.Pass, s.Level);
        Assert.Equal(new DateTime(2025, 10, 14), s.EndDate);
        Assert.True(s.DaysRemaining > 60);
    }

    [Fact]
    public void Classify_WithinWarnWindow_IsWarning()
    {
        // 30 days before Win11 23H2 EOS (2026-11-10) -> Warning with days remaining.
        var s = UpdateAudit.ClassifyWindowsSupport(22631, new DateTime(2026, 10, 11));
        Assert.Equal(Severity.Warning, s.Level);
        Assert.Equal(new DateTime(2026, 11, 10), s.EndDate);
        Assert.InRange(s.DaysRemaining, 1, 60);
    }

    [Fact]
    public void Classify_OnEosDate_IsNotCriticalYet()
    {
        // On the exact EOS date the build is still (barely) supported -> Warning, not Critical.
        var s = UpdateAudit.ClassifyWindowsSupport(22631, new DateTime(2026, 11, 10));
        Assert.Equal(Severity.Warning, s.Level);
        Assert.Equal(0, s.DaysRemaining);
    }

    [Fact]
    public void Classify_DayAfterEos_IsCritical()
    {
        var s = UpdateAudit.ClassifyWindowsSupport(22631, new DateTime(2026, 11, 11));
        Assert.Equal(Severity.Critical, s.Level);
    }

    [Fact]
    public void Classify_NewerThanKnownBuild_IsPassWithNoDate()
    {
        // A build newer than anything we track is assumed current -> Pass, no date.
        var s = UpdateAudit.ClassifyWindowsSupport(27000, new DateTime(2026, 7, 5));
        Assert.Equal(Severity.Pass, s.Level);
        Assert.Null(s.EndDate);
    }

    [Fact]
    public void Classify_UnknownOldBuild_IsInfo()
    {
        // An old build with no EOS entry in the table (e.g. Win10 1507, 10240) -> Info, don't guess.
        var s = UpdateAudit.ClassifyWindowsSupport(10240, new DateTime(2026, 7, 5));
        Assert.Equal(Severity.Info, s.Level);
        Assert.Null(s.EndDate);
    }

    [Fact]
    public void Classify_Windows11_24H2_IsPass()
    {
        // Win11 24H2 (26100), EOS 2027-10-12, today -> supported.
        var s = UpdateAudit.ClassifyWindowsSupport(26100, new DateTime(2026, 7, 5));
        Assert.Equal(Severity.Pass, s.Level);
        Assert.Equal(new DateTime(2027, 10, 12), s.EndDate);
    }
}
