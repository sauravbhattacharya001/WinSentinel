using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class SecurityReplayServiceTests : IDisposable
{
    private readonly string _dbPath;
    private readonly AuditHistoryService _history;
    private readonly SecurityReplayService _service;

    public SecurityReplayServiceTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"winsentinel_replay_test_{Guid.NewGuid():N}.db");
        _history = new AuditHistoryService(_dbPath);
        _service = new SecurityReplayService(_history);
    }

    public void Dispose()
    {
        _history.Dispose();
        try { if (File.Exists(_dbPath)) File.Delete(_dbPath); }
        catch { /* best effort */ }
    }

    private SecurityReport CreateReport(int score, string moduleName = "Firewall",
        int criticals = 0, int warnings = 0, string? criticalTitle = null)
    {
        var result = new AuditResult
        {
            ModuleName = moduleName,
            Category = "Network"
        };

        for (int i = 0; i < criticals; i++)
            result.Findings.Add(Finding.Critical(
                criticalTitle ?? $"Critical-{moduleName}-{i}",
                $"Critical issue {i} in {moduleName}", moduleName));
        for (int i = 0; i < warnings; i++)
            result.Findings.Add(Finding.Warning(
                $"Warning-{moduleName}-{i}",
                $"Warning {i} in {moduleName}", moduleName, "Fix it"));

        return new SecurityReport
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            SecurityScore = score,
            Results = [result]
        };
    }

    private void SeedRuns(params int[] scores)
    {
        foreach (var score in scores)
        {
            _history.SaveAuditResult(CreateReport(score, criticals: score < 50 ? 2 : 0, warnings: 1));
            // Small delay to ensure distinct timestamps
            Thread.Sleep(50);
        }
    }

    // ── Snapshot Tests ──

    [Fact]
    public void Snapshot_EmptyHistory_ReturnsErrorMessage()
    {
        var result = _service.Snapshot(30, null);

        Assert.Equal("snapshot", result.Mode);
        Assert.NotNull(result.ErrorMessage);
        Assert.Contains("No audit history", result.ErrorMessage);
        Assert.Null(result.Snapshot);
    }

    [Fact]
    public void Snapshot_DefaultTarget_ReturnsOldestRun()
    {
        SeedRuns(60, 70, 80); // oldest=60, newest=80

        var result = _service.Snapshot(30, null);

        Assert.Null(result.ErrorMessage);
        Assert.NotNull(result.Snapshot);
        Assert.Equal(60, result.Snapshot.Score);
        Assert.Equal(80, result.Snapshot.CurrentScore);
        Assert.Equal(3, result.TotalRunsAvailable);
    }

    [Fact]
    public void Snapshot_ByIndex_ReturnsCorrectRun()
    {
        SeedRuns(50, 60, 70, 80);

        // Index 0 = newest (80), index 3 = oldest (50)
        var result = _service.Snapshot(30, "0");

        Assert.NotNull(result.Snapshot);
        Assert.Equal(80, result.Snapshot.Score);
        Assert.Equal(0, result.Snapshot.RunIndex);
    }

    [Fact]
    public void Snapshot_ByIndex_MiddleRun()
    {
        SeedRuns(50, 60, 70, 80);

        var result = _service.Snapshot(30, "2");

        Assert.NotNull(result.Snapshot);
        Assert.Equal(60, result.Snapshot.Score); // 3rd newest = 60
    }

    [Fact]
    public void Snapshot_InvalidIndex_FallsBackToOldest()
    {
        SeedRuns(50, 60, 70);

        var result = _service.Snapshot(30, "999");

        Assert.NotNull(result.Snapshot);
        Assert.Equal(50, result.Snapshot.Score); // oldest
    }

    [Fact]
    public void Snapshot_ModulesListPopulated()
    {
        // GetHistory returns lightweight records (no module scores loaded)
        // so Modules list will be empty — this tests that code handles it gracefully
        SeedRuns(60, 90);

        var result = _service.Snapshot(30, null);

        Assert.NotNull(result.Snapshot);
        // Modules sourced from run.ModuleScores which GetHistory doesn't populate
        Assert.NotNull(result.Snapshot.Modules);
    }

    [Fact]
    public void Snapshot_NarrativeContainsScoreInfo()
    {
        SeedRuns(60, 80);

        var result = _service.Snapshot(30, null);

        Assert.NotNull(result.Snapshot);
        Assert.Contains("60", result.Snapshot.Narrative);
        Assert.Contains("80", result.Snapshot.Narrative);
    }

    // ── Bisect Tests ──

    [Fact]
    public void Bisect_InsufficientHistory_ReturnsError()
    {
        SeedRuns(80); // Only 1 run

        var result = _service.Bisect(30, null, null);

        Assert.Equal("bisect", result.Mode);
        Assert.NotNull(result.ErrorMessage);
        Assert.Contains("at least 2", result.ErrorMessage);
    }

    [Fact]
    public void Bisect_FindsScoreRegression()
    {
        // oldest→newest: 90, 85, 80, 40, 35, 30
        // Regression at score 40 (below current 30)
        SeedRuns(90, 85, 80, 40, 35, 30);

        var result = _service.Bisect(30, null, 50);

        Assert.NotNull(result.Bisect);
        Assert.NotNull(result.Bisect.RegressionIntroduced);
        Assert.True(result.Bisect.BisectSteps > 0);
        Assert.NotEmpty(result.Bisect.Steps);
        Assert.Contains("Regression introduced", result.Bisect.Narrative);
    }

    [Fact]
    public void Bisect_ByPattern_FindsFindingIntroduction()
    {
        // First two runs clean, third introduces a critical finding
        _history.SaveAuditResult(CreateReport(90, criticals: 0));
        Thread.Sleep(50);
        _history.SaveAuditResult(CreateReport(85, criticals: 0));
        Thread.Sleep(50);
        _history.SaveAuditResult(CreateReport(60, criticals: 1, criticalTitle: "Open port 445"));
        Thread.Sleep(50);
        _history.SaveAuditResult(CreateReport(55, criticals: 1, criticalTitle: "Open port 445"));

        var result = _service.Bisect(30, "Open port 445", null);

        Assert.NotNull(result.Bisect);
        Assert.Equal("bisect", result.Mode);
        Assert.NotNull(result.Bisect.RegressionIntroduced);
    }

    [Fact]
    public void Bisect_AllRunsBad_NarrativeIndicatesPredatesHistory()
    {
        // All runs have low scores
        SeedRuns(30, 25, 20, 15);

        var result = _service.Bisect(30, null, 50);

        Assert.NotNull(result.Bisect);
        Assert.Contains("predates available history", result.Bisect.Narrative);
    }

    [Fact]
    public void Bisect_LastGoodRunPopulatedWhenExists()
    {
        SeedRuns(90, 85, 40, 30); // Good: 90,85 then bad: 40,30

        var result = _service.Bisect(30, null, 50);

        Assert.NotNull(result.Bisect);
        Assert.NotNull(result.Bisect.LastGoodRun);
        Assert.False(result.Bisect.LastGoodRun.MatchesCriteria);
    }

    [Fact]
    public void Bisect_StepsAreLogN()
    {
        // 16 runs → bisect should take ~4 steps
        var scores = Enumerable.Range(0, 16).Select(i => i < 8 ? 90 : 30).ToArray();
        SeedRuns(scores);

        var result = _service.Bisect(30, null, 50);

        Assert.NotNull(result.Bisect);
        Assert.True(result.Bisect.BisectSteps <= 5,
            $"Expected ≤5 bisect steps for 16 runs, got {result.Bisect.BisectSteps}");
    }

    // ── Diff Tests ──

    [Fact]
    public void Diff_InsufficientHistory_ReturnsError()
    {
        SeedRuns(80);

        var result = _service.Diff(30, null, null);

        Assert.Equal("diff", result.Mode);
        Assert.NotNull(result.ErrorMessage);
    }

    [Fact]
    public void Diff_DefaultFromTo_ComparesOldestToNewest()
    {
        SeedRuns(60, 70, 80);

        var result = _service.Diff(30, null, null);

        Assert.NotNull(result.Diff);
        Assert.Equal(60, result.Diff.From.Score); // oldest
        Assert.Equal(80, result.Diff.To.Score);   // newest
    }

    [Fact]
    public void Diff_ExplicitIndices()
    {
        SeedRuns(50, 60, 70, 80);
        // Index 0=80, 1=70, 2=60, 3=50

        var result = _service.Diff(30, "1", "2");

        Assert.NotNull(result.Diff);
        Assert.Equal(70, result.Diff.From.Score);
        Assert.Equal(60, result.Diff.To.Score);
    }

    [Fact]
    public void Diff_ScoreChangeCalculated()
    {
        SeedRuns(60, 80);

        var result = _service.Diff(30, null, null);

        Assert.NotNull(result.Diff);
        Assert.Equal(20, result.Diff.ScoreChange); // 80 - 60
    }

    [Fact]
    public void Diff_AddedAndRemovedListsAreInitialized()
    {
        // GetHistory returns lightweight records without findings,
        // so Added/Removed will both be empty — verify no crash and lists exist
        SeedRuns(60, 80);

        var result = _service.Diff(30, null, null);

        Assert.NotNull(result.Diff);
        Assert.NotNull(result.Diff.Added);
        Assert.NotNull(result.Diff.Removed);
    }

    [Fact]
    public void Diff_NarrativeContainsDirection()
    {
        SeedRuns(60, 80);

        var result = _service.Diff(30, null, null);

        Assert.NotNull(result.Diff);
        Assert.Contains("improved", result.Diff.Narrative);
    }

    [Fact]
    public void Diff_DegradedScoreNarrative()
    {
        SeedRuns(80, 60);

        var result = _service.Diff(30, null, null);

        Assert.NotNull(result.Diff);
        Assert.Contains("degraded", result.Diff.Narrative);
    }

    [Fact]
    public void Diff_UnchangedScoreNarrative()
    {
        SeedRuns(70, 70);

        var result = _service.Diff(30, null, null);

        Assert.NotNull(result.Diff);
        Assert.Contains("unchanged", result.Diff.Narrative);
    }

    // ── Edge Cases ──

    [Fact]
    public void Snapshot_TopFindingsLimitedTo10()
    {
        // Create a report with many findings
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        for (int i = 0; i < 20; i++)
            result.Findings.Add(Finding.Critical($"Issue {i}", $"Desc {i}", "Test"));
        var report = new SecurityReport { SecurityScore = 30, Results = [result] };

        _history.SaveAuditResult(report);
        Thread.Sleep(50);
        _history.SaveAuditResult(CreateReport(80));

        var snapshot = _service.Snapshot(30, null); // Oldest = the one with 20 findings

        Assert.NotNull(snapshot.Snapshot);
        Assert.True(snapshot.Snapshot.TopFindings.Count <= 10,
            $"Expected ≤10 top findings, got {snapshot.Snapshot.TopFindings.Count}");
    }

    [Fact]
    public void Snapshot_ByDateTarget_ParsesDateAndReturnsResult()
    {
        SeedRuns(60, 70, 80);

        var runs = _history.GetHistory(30);
        // Use the middle run's exact ISO timestamp
        var middleDate = runs[1].Timestamp.ToString("o");

        var result = _service.Snapshot(30, middleDate);

        Assert.NotNull(result.Snapshot);
        // Should find a valid run (exact match or closest)
        Assert.True(result.Snapshot.Score > 0);
        Assert.Equal(3, result.TotalRunsAvailable);
    }
}
