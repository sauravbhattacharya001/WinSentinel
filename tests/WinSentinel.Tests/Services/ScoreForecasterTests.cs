using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests.Services;

public class ScoreForecasterTests
{
    private readonly ScoreForecaster _forecaster = new();

    private static List<AuditRunRecord> CreateRuns(
        params (int score, string grade, int daysAgo)[] data)
    {
        var now = DateTimeOffset.UtcNow;
        return data.Select((d, i) => new AuditRunRecord
        {
            Id = i + 1,
            Timestamp = now.AddDays(-d.daysAgo),
            OverallScore = d.score,
            Grade = d.grade,
            TotalFindings = 100 - d.score,
            CriticalCount = d.score < 50 ? 3 : d.score < 70 ? 1 : 0,
            WarningCount = d.score < 80 ? 5 : 1,
            InfoCount = 2,
            PassCount = d.score >= 70 ? 10 : 3,
        }).ToList();
    }

    private static List<AuditRunRecord> CreateRunsWithModules(
        params (int score, string grade, int daysAgo,
                (string name, int moduleScore)[] modules)[] data)
    {
        var now = DateTimeOffset.UtcNow;
        return data.Select((d, i) => new AuditRunRecord
        {
            Id = i + 1,
            Timestamp = now.AddDays(-d.daysAgo),
            OverallScore = d.score,
            Grade = d.grade,
            TotalFindings = 100 - d.score,
            CriticalCount = 0,
            WarningCount = 2,
            InfoCount = 1,
            PassCount = 5,
            ModuleScores = d.modules.Select(m => new ModuleScoreRecord
            {
                ModuleName = m.name,
                Score = m.moduleScore,
                Category = "Test",
            }).ToList(),
        }).ToList();
    }

    // ── Insufficient data ────────────────────────────────────────────

    [Fact]
    public void Forecast_EmptyRuns_ReturnsFailure()
    {
        var result = _forecaster.Forecast([]);
        Assert.False(result.Success);
        Assert.Contains("Insufficient", result.FailureReason);
        Assert.Equal(0, result.DataPointCount);
    }

    [Fact]
    public void Forecast_OneRun_ReturnsFailure()
    {
        var runs = CreateRuns((85, "A", 0));
        var result = _forecaster.Forecast(runs);
        Assert.False(result.Success);
        Assert.Equal(1, result.DataPointCount);
    }

    [Fact]
    public void Forecast_TwoRuns_ReturnsFailure()
    {
        var runs = CreateRuns((80, "B", 7), (85, "A", 0));
        var result = _forecaster.Forecast(runs);
        Assert.False(result.Success);
        Assert.Equal(2, result.DataPointCount);
    }

    // ── Successful forecast ──────────────────────────────────────────

    [Fact]
    public void Forecast_ThreeRuns_Succeeds()
    {
        var runs = CreateRuns((70, "C", 14), (75, "C", 7), (80, "B", 0));
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.Null(result.FailureReason);
        Assert.Equal(3, result.DataPointCount);
        Assert.Equal(80, result.CurrentScore);
        Assert.Equal("B", result.CurrentGrade);
    }

    [Fact]
    public void Forecast_ImprovingTrend_PositiveSlope()
    {
        var runs = CreateRuns(
            (60, "D", 30), (65, "D", 20), (70, "C", 10), (80, "B", 0));
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.True(result.DailyRate > 0, "Improving trend should have positive slope");
        Assert.Equal("Improving", result.TrendDirection);
        Assert.True(result.WeeklyChange > 0);
        Assert.True(result.MonthlyChange > 0);
    }

    [Fact]
    public void Forecast_DecliningTrend_NegativeSlope()
    {
        var runs = CreateRuns(
            (90, "A", 30), (85, "A", 20), (75, "C", 10), (65, "D", 0));
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.True(result.DailyRate < 0, "Declining trend should have negative slope");
        Assert.Equal("Declining", result.TrendDirection);
    }

    [Fact]
    public void Forecast_StableTrend_NearZeroSlope()
    {
        var runs = CreateRuns(
            (80, "B", 30), (81, "B", 20), (80, "B", 10), (80, "B", 0));
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.Equal("Stable", result.TrendDirection);
    }

    // ── Forecast points ──────────────────────────────────────────────

    [Fact]
    public void Forecast_DefaultDays_ProducesThreePoints()
    {
        var runs = CreateRuns(
            (70, "C", 21), (75, "C", 14), (80, "B", 7), (85, "A", 0));
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.Equal(3, result.Forecasts.Count);  // 7, 30, 90 days
    }

    [Fact]
    public void Forecast_CustomDays_ProducesRequestedPoints()
    {
        var runs = CreateRuns(
            (70, "C", 14), (75, "C", 7), (80, "B", 0));
        var options = new ScoreForecaster.ForecastOptions
        {
            ForecastDays = [14, 60]
        };
        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        Assert.Equal(2, result.Forecasts.Count);
    }

    [Fact]
    public void Forecast_ScoreClamped_BetweenZeroAndHundred()
    {
        // Steep upward trend — prediction could exceed 100
        var runs = CreateRuns(
            (50, "F", 10), (70, "C", 5), (90, "A", 0));
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        foreach (var fp in result.Forecasts)
        {
            Assert.True(fp.PredictedScore >= 0, "Score should not be negative");
            Assert.True(fp.PredictedScore <= 100, "Score should not exceed 100");
            Assert.True(fp.LowerBound >= 0);
            Assert.True(fp.UpperBound <= 100);
        }
    }

    [Fact]
    public void Forecast_ConfidenceBounds_LowerLessThanUpper()
    {
        var runs = CreateRuns(
            (60, "D", 21), (65, "D", 14), (70, "C", 7), (75, "C", 0));
        var result = _forecaster.Forecast(runs);

        foreach (var fp in result.Forecasts)
        {
            Assert.True(fp.LowerBound <= fp.PredictedScore,
                $"Lower bound {fp.LowerBound} > predicted {fp.PredictedScore}");
            Assert.True(fp.UpperBound >= fp.PredictedScore,
                $"Upper bound {fp.UpperBound} < predicted {fp.PredictedScore}");
        }
    }

    [Fact]
    public void Forecast_ForecastPointsHaveGrades()
    {
        var runs = CreateRuns(
            (70, "C", 14), (75, "C", 7), (80, "B", 0));
        var result = _forecaster.Forecast(runs);

        foreach (var fp in result.Forecasts)
        {
            Assert.False(string.IsNullOrEmpty(fp.Grade));
        }
    }

    // ── Days to target ───────────────────────────────────────────────

    [Fact]
    public void Forecast_TargetReachable_ReturnsDaysToTarget()
    {
        // Improving trend aiming for 95
        var runs = CreateRuns(
            (70, "C", 30), (75, "C", 20), (80, "B", 10), (85, "A", 0));
        var options = new ScoreForecaster.ForecastOptions { TargetScore = 95 };
        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        Assert.Equal(95, result.TargetScore);
        Assert.NotNull(result.DaysToTarget);
        Assert.True(result.DaysToTarget > 0);
    }

    [Fact]
    public void Forecast_TargetUnreachable_ReturnsNull()
    {
        // Declining trend trying to reach higher score
        var runs = CreateRuns(
            (90, "A", 30), (85, "A", 20), (80, "B", 10), (75, "C", 0));
        var options = new ScoreForecaster.ForecastOptions { TargetScore = 95 };
        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        Assert.Null(result.DaysToTarget);
    }

    [Fact]
    public void Forecast_NoTarget_DaysToTargetNull()
    {
        var runs = CreateRuns(
            (70, "C", 14), (75, "C", 7), (80, "B", 0));
        var result = _forecaster.Forecast(runs);

        Assert.Null(result.DaysToTarget);
        Assert.Null(result.TargetScore);
    }

    // ── R² and confidence ────────────────────────────────────────────

    [Fact]
    public void Forecast_PerfectLinear_HighRSquared()
    {
        // Perfectly linear improvement
        var runs = CreateRuns(
            (60, "D", 40), (65, "D", 30), (70, "C", 20),
            (75, "C", 10), (80, "B", 0));
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.True(result.RSquared >= 0.95, $"R²={result.RSquared} should be ≥0.95 for linear data");
        Assert.Equal("High", result.ConfidenceLevel);
    }

    [Fact]
    public void Forecast_NoisyData_LowerRSquared()
    {
        var runs = CreateRuns(
            (80, "B", 40), (60, "D", 30), (90, "A", 20),
            (50, "F", 10), (75, "C", 0));
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.True(result.RSquared < 0.8, $"R²={result.RSquared} should be <0.8 for noisy data");
    }

    [Fact]
    public void Forecast_RSquared_BetweenZeroAndOne()
    {
        var runs = CreateRuns(
            (70, "C", 21), (75, "C", 14), (80, "B", 7), (85, "A", 0));
        var result = _forecaster.Forecast(runs);

        Assert.InRange(result.RSquared, 0.0, 1.0);
    }

    // ── Module forecasts ─────────────────────────────────────────────

    [Fact]
    public void Forecast_WithModules_ProducesModuleForecasts()
    {
        var runs = CreateRunsWithModules(
            (70, "C", 14, new[] { ("Firewall", 80), ("Updates", 60) }),
            (75, "C", 7,  new[] { ("Firewall", 85), ("Updates", 65) }),
            (80, "B", 0,  new[] { ("Firewall", 90), ("Updates", 70) }));

        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.True(result.ModuleForecasts.Count >= 2);

        var fw = result.ModuleForecasts.FirstOrDefault(m => m.ModuleName == "Firewall");
        Assert.NotNull(fw);
        Assert.Equal(90, fw.CurrentScore);
        Assert.True(fw.Slope > 0);
    }

    [Fact]
    public void Forecast_DisableModules_NoModuleForecasts()
    {
        var runs = CreateRunsWithModules(
            (70, "C", 14, new[] { ("Firewall", 80) }),
            (75, "C", 7,  new[] { ("Firewall", 85) }),
            (80, "B", 0,  new[] { ("Firewall", 90) }));

        var options = new ScoreForecaster.ForecastOptions
        {
            IncludeModuleForecasts = false
        };
        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        Assert.Empty(result.ModuleForecasts);
    }

    // ── Risk factors ─────────────────────────────────────────────────

    [Fact]
    public void Forecast_CriticalFindings_IdentifiesRisk()
    {
        var runs = CreateRuns(
            (40, "F", 14), (45, "F", 7), (50, "F", 0));
        // CreateRuns gives CriticalCount=3 for score<50
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        var critRisk = result.RiskFactors
            .FirstOrDefault(r => r.Category == "Critical Findings");
        Assert.NotNull(critRisk);
    }

    [Fact]
    public void Forecast_RecentDecline_IdentifiesRisk()
    {
        var runs = CreateRuns(
            (85, "A", 14), (80, "B", 7), (65, "D", 0));
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        var declineRisk = result.RiskFactors
            .FirstOrDefault(r => r.Category == "Recent Decline");
        Assert.NotNull(declineRisk);
    }

    [Fact]
    public void Forecast_DisableRiskFactors_NoRisks()
    {
        var runs = CreateRuns(
            (40, "F", 14), (45, "F", 7), (50, "F", 0));
        var options = new ScoreForecaster.ForecastOptions
        {
            IncludeRiskFactors = false
        };
        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        Assert.Empty(result.RiskFactors);
    }

    [Fact]
    public void Forecast_GrowingFindings_IdentifiesRisk()
    {
        // TotalFindings = 100 - score, so 70→65→60 gives 30→35→40
        var runs = CreateRuns(
            (70, "C", 14), (65, "D", 7), (60, "D", 0));
        var result = _forecaster.Forecast(runs);

        var growingRisk = result.RiskFactors
            .FirstOrDefault(r => r.Category == "Growing Issues");
        Assert.NotNull(growingRisk);
    }

    // ── Volatility ───────────────────────────────────────────────────

    [Fact]
    public void Forecast_StableScores_LowVolatility()
    {
        var runs = CreateRuns(
            (80, "B", 21), (81, "B", 14), (80, "B", 7), (80, "B", 0));
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Volatility < 2);
    }

    [Fact]
    public void Forecast_VolatileScores_HighVolatility()
    {
        var runs = CreateRuns(
            (50, "F", 21), (90, "A", 14), (55, "F", 7), (85, "A", 0));
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Volatility > 10);
    }

    // ── Edge cases ───────────────────────────────────────────────────

    [Fact]
    public void Forecast_MaxForecastDaysClamped()
    {
        var runs = CreateRuns(
            (70, "C", 14), (75, "C", 7), (80, "B", 0));
        var options = new ScoreForecaster.ForecastOptions
        {
            ForecastDays = [500]  // exceeds MaxForecastDays
        };
        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        Assert.Single(result.Forecasts);
        // Date should be at most 365 days in the future
        var maxDate = DateTimeOffset.UtcNow.AddDays(ScoreForecaster.MaxForecastDays + 1);
        Assert.True(result.Forecasts[0].Date <= maxDate);
    }

    [Fact]
    public void Forecast_UnorderedInput_StillWorks()
    {
        // Runs in random order
        var runs = CreateRuns(
            (80, "B", 0), (70, "C", 14), (75, "C", 7));
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.Equal(80, result.CurrentScore);
    }

    // ── Linear regression ────────────────────────────────────────────

    [Fact]
    public void LinearRegression_PerfectLine_ReturnsExactCoefficients()
    {
        var x = new double[] { 0, 1, 2, 3, 4 };
        var y = new double[] { 10, 12, 14, 16, 18 };

        var (slope, intercept, r2) = ScoreForecaster.LinearRegression(x, y);

        Assert.Equal(2.0, slope, precision: 6);
        Assert.Equal(10.0, intercept, precision: 6);
        Assert.Equal(1.0, r2, precision: 6);
    }

    [Fact]
    public void LinearRegression_SinglePoint_ReturnsZeroSlope()
    {
        var x = new double[] { 5 };
        var y = new double[] { 80 };

        var (slope, intercept, _) = ScoreForecaster.LinearRegression(x, y);

        Assert.Equal(0.0, slope);
        Assert.Equal(80.0, intercept);
    }

    [Fact]
    public void LinearRegression_FlatData_ZeroSlope()
    {
        var x = new double[] { 0, 1, 2, 3, 4 };
        var y = new double[] { 50, 50, 50, 50, 50 };

        var (slope, _, _) = ScoreForecaster.LinearRegression(x, y);

        Assert.Equal(0.0, slope, precision: 6);
    }
}
