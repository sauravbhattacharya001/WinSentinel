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

    // ---- ParsePendingUpdateOutput: probe output -> (indicators, history-read) ----

    [Fact]
    public void ParsePendingUpdateOutput_ZeroOk_IsClean()
    {
        var s = UpdateAudit.ParsePendingUpdateOutput("0|OK");
        Assert.NotNull(s);
        Assert.Equal(0, s.Value.Indicators);
        Assert.True(s.Value.HistoryRead);
    }

    [Fact]
    public void ParsePendingUpdateOutput_CountOk_PreservesCount()
    {
        var s = UpdateAudit.ParsePendingUpdateOutput("3|OK");
        Assert.NotNull(s);
        Assert.Equal(3, s.Value.Indicators);
        Assert.True(s.Value.HistoryRead);
    }

    [Fact]
    public void ParsePendingUpdateOutput_ZeroUnknown_FlagsUnreadHistory()
    {
        // The defect case: COM failure with no reboot pending. The count is 0
        // but the history was never read — the parser must carry that fact.
        var s = UpdateAudit.ParsePendingUpdateOutput("0|UNKNOWN");
        Assert.NotNull(s);
        Assert.Equal(0, s.Value.Indicators);
        Assert.False(s.Value.HistoryRead);
    }

    [Fact]
    public void ParsePendingUpdateOutput_OneUnknown_KeepsIndicator()
    {
        // Reboot-required indicator survives even when history is unread.
        var s = UpdateAudit.ParsePendingUpdateOutput("1|UNKNOWN");
        Assert.NotNull(s);
        Assert.Equal(1, s.Value.Indicators);
        Assert.False(s.Value.HistoryRead);
    }

    [Fact]
    public void ParsePendingUpdateOutput_LowercaseFlag_IsAccepted()
    {
        var s = UpdateAudit.ParsePendingUpdateOutput("2|ok");
        Assert.NotNull(s);
        Assert.Equal(2, s.Value.Indicators);
        Assert.True(s.Value.HistoryRead);
    }

    [Fact]
    public void ParsePendingUpdateOutput_Whitespace_IsTrimmed()
    {
        var s = UpdateAudit.ParsePendingUpdateOutput(" 3|OK \r\n");
        Assert.NotNull(s);
        Assert.Equal(3, s.Value.Indicators);
        Assert.True(s.Value.HistoryRead);
    }

    [Fact]
    public void ParsePendingUpdateOutput_Empty_IsNull()
    {
        Assert.Null(UpdateAudit.ParsePendingUpdateOutput(""));
        Assert.Null(UpdateAudit.ParsePendingUpdateOutput("   "));
    }

    [Fact]
    public void ParsePendingUpdateOutput_BareInteger_IsNull()
    {
        // Legacy bare-integer output carries no history-read signal and must
        // never be treated as a clean bill of health.
        Assert.Null(UpdateAudit.ParsePendingUpdateOutput("0"));
        Assert.Null(UpdateAudit.ParsePendingUpdateOutput("5"));
    }

    [Fact]
    public void ParsePendingUpdateOutput_NonIntegerCount_IsNull()
    {
        Assert.Null(UpdateAudit.ParsePendingUpdateOutput("abc|OK"));
    }

    [Fact]
    public void ParsePendingUpdateOutput_NegativeCount_IsNull()
    {
        Assert.Null(UpdateAudit.ParsePendingUpdateOutput("-1|OK"));
    }

    [Fact]
    public void ParsePendingUpdateOutput_UnknownFlag_IsNull()
    {
        Assert.Null(UpdateAudit.ParsePendingUpdateOutput("0|MAYBE"));
        Assert.Null(UpdateAudit.ParsePendingUpdateOutput("0|OK|EXTRA"));
    }

    // ---- AddPendingUpdateFindings: verdicts for a parsed probe result ----

    private static AuditResult MakeResult() => new()
    {
        ModuleName = "Update Audit",
        Category = "Updates"
    };

    [Fact]
    public void Findings_HistoryRead_ZeroIndicators_IsPass()
    {
        var result = MakeResult();
        UpdateAudit.AddPendingUpdateFindings(
            result, new UpdateAudit.PendingUpdateStatus(0, HistoryRead: true), "Updates");
        Assert.Single(result.Findings);
        Assert.Equal("No Pending Updates", result.Findings[0].Title);
        Assert.Equal(Severity.Pass, result.Findings[0].Severity);
    }

    [Fact]
    public void Findings_HistoryRead_WithIndicators_ReportsIssues()
    {
        var result = MakeResult();
        UpdateAudit.AddPendingUpdateFindings(
            result, new UpdateAudit.PendingUpdateStatus(3, HistoryRead: true), "Updates");
        Assert.Single(result.Findings);
        Assert.Equal("3 Update Issue(s) Detected", result.Findings[0].Title);
        Assert.Equal(Severity.Info, result.Findings[0].Severity);
    }

    [Fact]
    public void Findings_HistoryRead_ManyIndicators_IsWarning()
    {
        var result = MakeResult();
        UpdateAudit.AddPendingUpdateFindings(
            result, new UpdateAudit.PendingUpdateStatus(6, HistoryRead: true), "Updates");
        Assert.Single(result.Findings);
        Assert.Equal(Severity.Warning, result.Findings[0].Severity);
    }

    [Fact]
    public void Findings_HistoryUnread_ZeroIndicators_IsInfoNotPass()
    {
        // The fixed defect: an unread history with zero indicators must NOT
        // produce a "No Pending Updates" Pass.
        var result = MakeResult();
        UpdateAudit.AddPendingUpdateFindings(
            result, new UpdateAudit.PendingUpdateStatus(0, HistoryRead: false), "Updates");
        Assert.Single(result.Findings);
        Assert.Equal("Update Status Check Incomplete", result.Findings[0].Title);
        Assert.Equal(Severity.Info, result.Findings[0].Severity);
        Assert.DoesNotContain(result.Findings, f => f.Severity == Severity.Pass);
    }

    [Fact]
    public void Findings_HistoryUnread_WithIndicators_IsStillIncomplete()
    {
        // Without the history the count is not a trustworthy pending-update
        // count, so the verdict is Incomplete; the reboot signal itself has
        // its own dedicated finding elsewhere in the audit.
        var result = MakeResult();
        UpdateAudit.AddPendingUpdateFindings(
            result, new UpdateAudit.PendingUpdateStatus(1, HistoryRead: false), "Updates");
        Assert.Single(result.Findings);
        Assert.Equal("Update Status Check Incomplete", result.Findings[0].Title);
        Assert.Equal(Severity.Info, result.Findings[0].Severity);
    }
}
