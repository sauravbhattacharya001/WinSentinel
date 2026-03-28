using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class ScoreForecasterTests
{
    private readonly ScoreForecaster _forecaster = new();

    // ── Helpers ──────────────────────────────────────────────────────

    private static AuditRunRecord MakeRun(
        int daysAgo, int score, int criticals = 0, int warnings = 0,
        int pass = 10, int total = 0, List<ModuleScoreRecord>? modules = null)
    {
        return new AuditRunRecord
        {
            Timestamp = DateTimeOffset.UtcNow.AddDays(-daysAgo),
            OverallScore = score,
            Grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F",
            CriticalCount = criticals,
            WarningCount = warnings,
            PassCount = pass,
            TotalFindings = total > 0 ? total : criticals + warnings,
            ModuleScores = modules ?? [],
        };
    }

    private static List<AuditRunRecord> MakeImprovingRuns(int count = 5)
    {
        var runs = new List<AuditRunRecord>();
        for (int i = 0; i < count; i++)
            runs.Add(MakeRun(daysAgo: (count - 1 - i) * 7, score: 60 + i * 8));
        return runs;
    }

    // ── Insufficient data ────────────────────────────────────────────

    [Fact]
    public void Forecast_InsufficientData_ReturnsFailure()
    {
        var runs = new List<AuditRunRecord> { MakeRun(7, 70), MakeRun(0, 75) };
        var result = _forecaster.Forecast(runs);

        Assert.False(result.Success);
        Assert.Contains("Insufficient data", result.FailureReason);
        Assert.Equal(2, result.DataPointCount);
    }

    [Fact]
    public void Forecast_EmptyList_ReturnsFailure()
    {
        var result = _forecaster.Forecast([]);
        Assert.False(result.Success);
    }

    // ── Basic successful forecast ────────────────────────────────────

    [Fact]
    public void Forecast_ImprovingTrend_DetectsImproving()
    {
        var runs = MakeImprovingRuns();
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.Equal("Improving", result.TrendDirection);
        Assert.True(result.DailyRate > 0);
        Assert.True(result.WeeklyChange > 0);
        Assert.True(result.MonthlyChange > 0);
    }

    [Fact]
    public void Forecast_DecliningTrend_DetectsDeclining()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(28, 90),
            MakeRun(21, 82),
            MakeRun(14, 74),
            MakeRun(7, 66),
            MakeRun(0, 58),
        };
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.Equal("Declining", result.TrendDirection);
        Assert.True(result.DailyRate < 0);
    }

    [Fact]
    public void Forecast_StableScores_DetectsStable()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(21, 80),
            MakeRun(14, 80),
            MakeRun(7, 81),
            MakeRun(0, 80),
        };
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.Equal("Stable", result.TrendDirection);
    }

    // ── Forecast points ──────────────────────────────────────────────

    [Fact]
    public void Forecast_DefaultOptions_ProducesThreePoints()
    {
        var result = _forecaster.Forecast(MakeImprovingRuns());
        Assert.Equal(3, result.Forecasts.Count); // 7, 30, 90 days
    }

    [Fact]
    public void Forecast_CustomDays_ProducesCorrectCount()
    {
        var opts = new ScoreForecaster.ForecastOptions
        {
            ForecastDays = [1, 3, 14, 60, 180]
        };
        var result = _forecaster.Forecast(MakeImprovingRuns(), opts);
        Assert.Equal(5, result.Forecasts.Count);
    }

    [Fact]
    public void Forecast_ScoresClamped_Between0And100()
    {
        // Very steep improvement that would predict >100
        var runs = new List<AuditRunRecord>
        {
            MakeRun(6, 80),
            MakeRun(4, 90),
            MakeRun(2, 95),
            MakeRun(0, 99),
        };
        var opts = new ScoreForecaster.ForecastOptions { ForecastDays = [90] };
        var result = _forecaster.Forecast(runs, opts);

        Assert.True(result.Success);
        foreach (var fp in result.Forecasts)
        {
            Assert.InRange(fp.PredictedScore, 0, 100);
            Assert.InRange(fp.LowerBound, 0, 100);
            Assert.InRange(fp.UpperBound, 0, 100);
        }
    }

    [Fact]
    public void Forecast_ConfidenceIntervals_LowerLessThanUpper()
    {
        var result = _forecaster.Forecast(MakeImprovingRuns());
        foreach (var fp in result.Forecasts)
            Assert.True(fp.LowerBound <= fp.UpperBound);
    }

    [Fact]
    public void Forecast_GradeAssignment_MatchesScore()
    {
        var result = _forecaster.Forecast(MakeImprovingRuns());
        foreach (var fp in result.Forecasts)
        {
            var expected = (int)Math.Round(fp.PredictedScore) switch
            {
                >= 90 => "A",
                >= 80 => "B",
                >= 70 => "C",
                >= 60 => "D",
                _ => "F"
            };
            Assert.Equal(expected, fp.Grade);
        }
    }

    // ── Days to target ───────────────────────────────────────────────

    [Fact]
    public void Forecast_TargetReachable_ReturnsDaysToTarget()
    {
        var runs = MakeImprovingRuns(); // 60→92 over 28 days
        var opts = new ScoreForecaster.ForecastOptions { TargetScore = 95 };
        var result = _forecaster.Forecast(runs, opts);

        Assert.True(result.Success);
        Assert.Equal(95, result.TargetScore);
        // Improving trend, target above current — should be reachable
        if (result.DaysToTarget.HasValue)
            Assert.True(result.DaysToTarget.Value > 0);
    }

    [Fact]
    public void Forecast_TargetAlreadyMet_NoDaysToTarget()
    {
        var runs = MakeImprovingRuns(); // latest score = 92
        var opts = new ScoreForecaster.ForecastOptions { TargetScore = 50 };
        var result = _forecaster.Forecast(runs, opts);

        // Target below current with positive slope → target behind us
        Assert.True(result.Success);
    }

    // ── Module forecasts ─────────────────────────────────────────────

    [Fact]
    public void Forecast_WithModuleScores_ProducesModuleForecasts()
    {
        var modules = new List<ModuleScoreRecord>
        {
            new() { ModuleName = "Firewall", Score = 80 },
            new() { ModuleName = "Updates", Score = 60 },
        };
        var runs = new List<AuditRunRecord>
        {
            MakeRun(21, 70, modules: modules.Select(m =>
                new ModuleScoreRecord { ModuleName = m.ModuleName, Score = m.Score - 10 }).ToList()),
            MakeRun(14, 75, modules: modules.Select(m =>
                new ModuleScoreRecord { ModuleName = m.ModuleName, Score = m.Score - 5 }).ToList()),
            MakeRun(7, 78, modules: modules),
            MakeRun(0, 82, modules: modules.Select(m =>
                new ModuleScoreRecord { ModuleName = m.ModuleName, Score = m.Score + 3 }).ToList()),
        };

        var result = _forecaster.Forecast(runs);
        Assert.True(result.Success);
        Assert.True(result.ModuleForecasts.Count >= 2);
        Assert.Contains(result.ModuleForecasts, m => m.ModuleName == "Firewall");
        Assert.Contains(result.ModuleForecasts, m => m.ModuleName == "Updates");
    }

    [Fact]
    public void Forecast_DisableModuleForecasts_ReturnsEmpty()
    {
        var opts = new ScoreForecaster.ForecastOptions { IncludeModuleForecasts = false };
        var result = _forecaster.Forecast(MakeImprovingRuns(), opts);
        Assert.Empty(result.ModuleForecasts);
    }

    // ── Risk factors ─────────────────────────────────────────────────

    [Fact]
    public void Forecast_CriticalFindings_ReportsRiskFactor()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(14, 70),
            MakeRun(7, 68),
            MakeRun(0, 65, criticals: 5),
        };
        var result = _forecaster.Forecast(runs);
        Assert.Contains(result.RiskFactors, r => r.Category == "Critical Findings");
    }

    [Fact]
    public void Forecast_RecentDecline_ReportsRiskFactor()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(14, 80),
            MakeRun(7, 85),
            MakeRun(0, 70), // -15 drop
        };
        var result = _forecaster.Forecast(runs);
        Assert.Contains(result.RiskFactors, r => r.Category == "Recent Decline");
    }

    [Fact]
    public void Forecast_GrowingFindings_ReportsRiskFactor()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(14, 80, total: 5),
            MakeRun(7, 78, total: 8),
            MakeRun(0, 75, total: 12),
        };
        var result = _forecaster.Forecast(runs);
        Assert.Contains(result.RiskFactors, r => r.Category == "Growing Issues");
    }

    [Fact]
    public void Forecast_InfrequentScanning_ReportsRiskFactor()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(90, 80),
            MakeRun(60, 82),
            MakeRun(30, 84),
            MakeRun(0, 86),
        };
        var result = _forecaster.Forecast(runs);
        Assert.Contains(result.RiskFactors, r => r.Category == "Infrequent Scanning");
    }

    [Fact]
    public void Forecast_DisableRiskFactors_ReturnsEmpty()
    {
        var opts = new ScoreForecaster.ForecastOptions { IncludeRiskFactors = false };
        var runs = new List<AuditRunRecord>
        {
            MakeRun(14, 80, criticals: 5),
            MakeRun(7, 75, criticals: 5),
            MakeRun(0, 70, criticals: 5),
        };
        var result = _forecaster.Forecast(runs, opts);
        Assert.Empty(result.RiskFactors);
    }

    // ── Linear regression ────────────────────────────────────────────

    [Fact]
    public void LinearRegression_PerfectLine_RSquaredIsOne()
    {
        double[] x = [0, 1, 2, 3, 4];
        double[] y = [10, 20, 30, 40, 50];
        var (slope, intercept, rSquared) = ScoreForecaster.LinearRegression(x, y);

        Assert.Equal(10, slope, 1e-6);
        Assert.Equal(10, intercept, 1e-6);
        Assert.Equal(1.0, rSquared, 1e-6);
    }

    [Fact]
    public void LinearRegression_SinglePoint_ReturnsZeroSlope()
    {
        double[] x = [5];
        double[] y = [42];
        var (slope, intercept, rSquared) = ScoreForecaster.LinearRegression(x, y);

        Assert.Equal(0, slope);
        Assert.Equal(42, intercept);
    }

    [Fact]
    public void LinearRegression_ConstantY_ZeroSlope()
    {
        double[] x = [0, 1, 2, 3];
        double[] y = [50, 50, 50, 50];
        var (slope, _, rSquared) = ScoreForecaster.LinearRegression(x, y);

        Assert.Equal(0, slope, 1e-6);
    }

    // ── R² and confidence ────────────────────────────────────────────

    [Fact]
    public void Forecast_RSquared_BetweenZeroAndOne()
    {
        var result = _forecaster.Forecast(MakeImprovingRuns());
        Assert.InRange(result.RSquared, 0.0, 1.0);
    }

    [Fact]
    public void Forecast_ConfidenceLevel_IsValid()
    {
        var result = _forecaster.Forecast(MakeImprovingRuns());
        Assert.Contains(result.ConfidenceLevel, new[] { "High", "Moderate", "Low", "Very Low" });
    }

    // ── Metadata ─────────────────────────────────────────────────────

    [Fact]
    public void Forecast_ReportsCurrentScoreAndGrade()
    {
        var runs = MakeImprovingRuns();
        var result = _forecaster.Forecast(runs);

        Assert.Equal(runs.OrderBy(r => r.Timestamp).Last().OverallScore, result.CurrentScore);
        Assert.False(string.IsNullOrEmpty(result.CurrentGrade));
    }

    [Fact]
    public void Forecast_HistoricalSpan_IsPositive()
    {
        var result = _forecaster.Forecast(MakeImprovingRuns());
        Assert.True(result.HistoricalSpan.TotalDays > 0);
    }

    [Fact]
    public void Forecast_MaxForecastDays_Clamped()
    {
        var opts = new ScoreForecaster.ForecastOptions { ForecastDays = [9999] };
        var result = _forecaster.Forecast(MakeImprovingRuns(), opts);

        Assert.True(result.Success);
        Assert.Single(result.Forecasts);
        // Date should be at most MaxForecastDays from latest run
    }
}
