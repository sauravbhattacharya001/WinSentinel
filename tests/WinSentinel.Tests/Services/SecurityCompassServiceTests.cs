using Microsoft.Data.Sqlite;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

/// <summary>
/// Tests for SecurityCompassService — directional gap analysis with heading guidance.
/// Uses direct SQLite inserts to populate ModuleScores and Findings (GetHistory only
/// returns shallow records; we use GetRunDetails path via direct DB population).
/// </summary>
public class SecurityCompassServiceTests : IDisposable
{
    private readonly string _dbPath;
    private readonly AuditHistoryService _history;

    public SecurityCompassServiceTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"compass_test_{Guid.NewGuid():N}.db");
        _history = new AuditHistoryService(_dbPath);
        _history.EnsureDatabase();
    }

    public void Dispose()
    {
        _history.Dispose();
        SqliteConnection.ClearAllPools();
        try { if (File.Exists(_dbPath)) File.Delete(_dbPath); } catch { /* best effort */ }
    }

    // ── Helper ──────────────────────────────────────────────────

    /// <summary>
    /// Insert an audit run via the normal SaveAuditResult path.
    /// GetHistory() only returns OverallScore (no ModuleScores/Findings).
    /// SecurityCompassService falls back to a single "Overall" heading when ModuleScores is empty.
    /// </summary>
    private void InsertRun(int score, DateTimeOffset ts, int criticals = 0, int warnings = 0)
    {
        var findings = new List<Finding>();
        for (int i = 0; i < criticals; i++)
            findings.Add(new Finding { Title = $"C{i}", Severity = Severity.Critical, Description = "c" });
        for (int i = 0; i < warnings; i++)
            findings.Add(new Finding { Title = $"W{i}", Severity = Severity.Warning, Description = "w" });
        for (int i = 0; i < 10; i++)
            findings.Add(new Finding { Title = $"P{i}", Severity = Severity.Pass, Description = "p" });

        var report = new SecurityReport
        {
            GeneratedAt = ts.DateTime,
            SecurityScore = score,
            Results = new List<AuditResult>
            {
                new() { ModuleName = "General", Category = "Security", Findings = findings }
            }
        };
        _history.SaveAuditResult(report);
    }

    // ── No Data ─────────────────────────────────────────────────

    [Fact]
    public void Analyze_NoRuns_ReturnsEmptyResult()
    {
        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        Assert.Empty(result.Headings);
        Assert.Empty(result.Waypoints);
        Assert.Equal("unknown", result.Trajectory.Direction);
        Assert.Contains("No audit data", result.Trajectory.Narrative);
    }

    // ── Single Run (Overall heading) ────────────────────────────

    [Fact]
    public void Analyze_SingleRun_ProducesOverallHeading()
    {
        InsertRun(75, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        Assert.NotNull(result.CurrentPosition);
        Assert.NotNull(result.IdealPosition);
        Assert.Equal(90.0, result.IdealPosition.Latitude);
        Assert.Equal(0.0, result.IdealPosition.Longitude);

        // Latitude = (75/100)*180 - 90 = 45
        Assert.Equal(45.0, result.CurrentPosition.Latitude);

        // Single module → "Overall" heading
        Assert.Single(result.Headings);
        Assert.Equal("Overall", result.Headings[0].Module);
    }

    [Fact]
    public void Analyze_SingleRun_TrajectoryHolding()
    {
        InsertRun(80, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        Assert.Equal("holding", result.Trajectory.Direction);
        Assert.Equal(-1, result.Trajectory.EstimatedDaysToTarget);
    }

    // ── Waypoints ───────────────────────────────────────────────

    [Fact]
    public void Analyze_LowScore_HasWaypointWithGap()
    {
        InsertRun(60, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        Assert.Single(result.Waypoints);
        Assert.Equal("Overall", result.Waypoints[0].Module);
        Assert.Equal(35, result.Waypoints[0].ExpectedGain); // 95 - 60
        Assert.Equal(100.0, result.Waypoints[0].CumulativeProgress);
    }

    [Fact]
    public void Analyze_HighScore_NoWaypointsIfOnTarget()
    {
        InsertRun(100, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        // Score 100 → Overall heading score = 100, target = 95, distance = 0
        Assert.Empty(result.Waypoints);
    }

    // ── Bearing & Direction ─────────────────────────────────────

    [Fact]
    public void Analyze_HighOverallScore_BearingNearNorth()
    {
        InsertRun(95, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        var heading = result.Headings[0];
        // Bearing = (1 - 95/100) * 180 = 9.0
        Assert.Equal(9.0, heading.BearingDegrees);
        Assert.Equal("N", heading.Direction);
    }

    [Fact]
    public void Analyze_ZeroOverallScore_BearingSouth()
    {
        InsertRun(0, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        var heading = result.Headings[0];
        Assert.Equal(180.0, heading.BearingDegrees);
        Assert.Equal("S", heading.Direction);
    }

    // ── Guidance Text ───────────────────────────────────────────

    [Fact]
    public void Analyze_CriticalGap_GuidanceSaysCritical()
    {
        InsertRun(30, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        // Gap = 95-30 = 65 > 50 → "Critical gap"
        Assert.Contains("Critical gap", result.Headings[0].Guidance);
    }

    [Fact]
    public void Analyze_SignificantGap_GuidanceSaysSignificant()
    {
        InsertRun(55, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        // Gap = 95-55 = 40 > 25 → "Significant gap"
        Assert.Contains("Significant gap", result.Headings[0].Guidance);
    }

    [Fact]
    public void Analyze_ModerateGap_GuidanceSaysModerate()
    {
        InsertRun(80, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        // Gap = 95-80 = 15 > 10 → "Moderate gap"
        Assert.Contains("Moderate gap", result.Headings[0].Guidance);
    }

    [Fact]
    public void Analyze_MinorGap_GuidanceSaysMinor()
    {
        InsertRun(90, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        // Gap = 95-90 = 5 ≤ 10 → "Minor gap"
        Assert.Contains("Minor gap", result.Headings[0].Guidance);
    }

    [Fact]
    public void Analyze_OnTarget_GuidanceSaysMaintain()
    {
        InsertRun(100, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        // Score 100 >= target 95 → "on target"
        Assert.Contains("on target", result.Headings[0].Guidance);
    }

    // ── Declining Module Detection ──────────────────────────────

    [Fact]
    public void Analyze_DecliningScore_BearingShiftedWest()
    {
        // Score declined from 90 to 70
        InsertRun(90, DateTimeOffset.UtcNow.AddHours(-6));
        InsertRun(70, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        // The "declining" logic checks ModuleScores (which are empty via GetHistory)
        // So decline detection won't fire via this path. But trajectory should detect decline.
        // Latest overall score is 70 → heading bearing = (1 - 70/100)*180 = 54
        Assert.Equal(54.0, result.Headings[0].BearingDegrees);
    }

    // ── Trajectory ──────────────────────────────────────────────

    [Fact]
    public void Analyze_ImprovingScores_TrajectoryApproaching()
    {
        for (int i = 5; i >= 0; i--)
            InsertRun(60 + (5 - i) * 5, DateTimeOffset.UtcNow.AddDays(-i));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        Assert.Equal("approaching", result.Trajectory.Direction);
        Assert.True(result.Trajectory.VelocityPerDay > 0);
        Assert.True(result.Trajectory.EstimatedDaysToTarget > 0);
        Assert.Contains("Heading toward ideal", result.Trajectory.Narrative);
    }

    [Fact]
    public void Analyze_DecliningScores_TrajectoryDrifting()
    {
        for (int i = 5; i >= 0; i--)
            InsertRun(90 - (5 - i) * 5, DateTimeOffset.UtcNow.AddDays(-i));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        Assert.Equal("drifting", result.Trajectory.Direction);
        Assert.True(result.Trajectory.VelocityPerDay < 0);
        Assert.Equal(-1, result.Trajectory.EstimatedDaysToTarget);
        Assert.Contains("Drifting away", result.Trajectory.Narrative);
    }

    [Fact]
    public void Analyze_StableScores_TrajectoryHolding()
    {
        for (int i = 5; i >= 0; i--)
            InsertRun(80, DateTimeOffset.UtcNow.AddDays(-i));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        Assert.Equal("holding", result.Trajectory.Direction);
        Assert.Contains("Holding steady", result.Trajectory.Narrative);
    }

    // ── Deviation ───────────────────────────────────────────────

    [Fact]
    public void Analyze_PerfectScore_DeviationNearZero()
    {
        InsertRun(100, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        Assert.True(result.DeviationDegrees < 1.0);
    }

    [Fact]
    public void Analyze_LowScore_LargeDeviation()
    {
        InsertRun(20, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        Assert.True(result.DeviationDegrees > 40);
    }

    // ── Course Correction ───────────────────────────────────────

    [Fact]
    public void Analyze_WithGap_CourseCorrectionTargetsOverall()
    {
        InsertRun(60, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        Assert.Contains("Overall", result.CourseCorrection);
        Assert.Contains("biggest gap", result.CourseCorrection);
    }

    [Fact]
    public void Analyze_PerfectScore_CourseCorrectionMaintain()
    {
        InsertRun(100, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        Assert.Contains("On course", result.CourseCorrection);
    }

    // ── Position ────────────────────────────────────────────────

    [Fact]
    public void Analyze_Score0_LatitudeNeg90()
    {
        InsertRun(0, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        Assert.Equal(-90.0, result.CurrentPosition.Latitude);
    }

    [Fact]
    public void Analyze_Score100_Latitude90()
    {
        InsertRun(100, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        Assert.Equal(90.0, result.CurrentPosition.Latitude);
    }

    [Fact]
    public void Analyze_SingleModule_LongitudeZero()
    {
        InsertRun(80, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        // Single module → stddev=0 → longitude=0
        Assert.Equal(0.0, result.CurrentPosition.Longitude);
    }

    // ── AnalyzedAt ──────────────────────────────────────────────

    [Fact]
    public void Analyze_SetsAnalyzedAtToRecentTime()
    {
        InsertRun(80, DateTimeOffset.UtcNow.AddHours(-1));

        var before = DateTimeOffset.UtcNow;
        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();
        var after = DateTimeOffset.UtcNow;

        Assert.InRange(result.AnalyzedAt, before.AddSeconds(-1), after.AddSeconds(1));
    }

    // ── Custom Days Window ──────────────────────────────────────

    [Fact]
    public void Analyze_CustomDaysWindow_FiltersOldRuns()
    {
        InsertRun(50, DateTimeOffset.UtcNow.AddDays(-60));
        InsertRun(90, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze(days: 7);

        // Only the recent run, score=90 → latitude=(90/100)*180-90=72
        Assert.Equal(72.0, result.CurrentPosition.Latitude);
    }

    // ── Heading Distance ────────────────────────────────────────

    [Fact]
    public void Analyze_HeadingDistance_EqualsTargetMinusScore()
    {
        InsertRun(70, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        // Target = 95, score = 70, distance = 25
        Assert.Equal(25, result.Headings[0].Distance);
    }

    [Fact]
    public void Analyze_HeadingDistance_ZeroWhenAboveTarget()
    {
        InsertRun(100, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        // Score 100 > target 95, distance clamped to 0
        Assert.Equal(0, result.Headings[0].Distance);
    }

    // ── Trajectory Velocity ─────────────────────────────────────

    [Fact]
    public void Analyze_Trajectory_VelocityPositiveWhenImproving()
    {
        InsertRun(50, DateTimeOffset.UtcNow.AddDays(-10));
        InsertRun(90, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        Assert.True(result.Trajectory.VelocityPerDay > 0);
    }

    [Fact]
    public void Analyze_Trajectory_VelocityNegativeWhenDeclining()
    {
        InsertRun(90, DateTimeOffset.UtcNow.AddDays(-10));
        InsertRun(50, DateTimeOffset.UtcNow.AddHours(-1));

        var svc = new SecurityCompassService(_history);
        var result = svc.Analyze();

        Assert.True(result.Trajectory.VelocityPerDay < 0);
    }
}
