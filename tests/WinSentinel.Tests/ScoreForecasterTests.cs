using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

/// <summary>
/// Tests for <see cref="ScoreForecaster"/> — linear regression forecasting,
/// confidence intervals, module-level projections, and risk factor analysis.
/// </summary>
public class ScoreForecasterTests
{
    private readonly ScoreForecaster _forecaster = new();

    // ── Helper factories ─────────────────────────────────────────────

    private static AuditRunRecord MakeRun(
        DateTimeOffset timestamp,
        int score,
        int criticals = 0,
        int warnings = 2,
        int passes = 10,
        List<ModuleScoreRecord>? moduleScores = null)
    {
        return new AuditRunRecord
        {
            Timestamp = timestamp,
            OverallScore = score,
            Grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F",
            TotalFindings = criticals + warnings,
            CriticalCount = criticals,
            WarningCount = warnings,
            InfoCount = 0,
            PassCount = passes,
            ModuleScores = moduleScores ?? [],
        };
    }

    private static List<AuditRunRecord> MakeImprovingRuns(int count = 5)
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>();
        for (int i = 0; i < count; i++)
        {
            runs.Add(MakeRun(baseDate.AddDays(i * 7), 60 + i * 5));
        }
        return runs;
    }

    private static List<AuditRunRecord> MakeDecliningRuns(int count = 5)
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>();
        for (int i = 0; i < count; i++)
        {
            runs.Add(MakeRun(baseDate.AddDays(i * 7), 90 - i * 5));
        }
        return runs;
    }

    // ── Insufficient data ────────────────────────────────────────────

    [Fact]
    public void Forecast_InsufficientData_ReturnsFailure()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(DateTimeOffset.UtcNow, 75),
            MakeRun(DateTimeOffset.UtcNow.AddDays(-7), 70),
        };

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
        Assert.Equal(0, result.DataPointCount);
    }

    [Fact]
    public void Forecast_SingleRun_ReturnsFailure()
    {
        var result = _forecaster.Forecast([MakeRun(DateTimeOffset.UtcNow, 80)]);

        Assert.False(result.Success);
        Assert.Equal(1, result.DataPointCount);
    }

    // ── Successful forecasts ─────────────────────────────────────────

    [Fact]
    public void Forecast_MinimumThreeRuns_Succeeds()
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(baseDate, 60),
            MakeRun(baseDate.AddDays(7), 65),
            MakeRun(baseDate.AddDays(14), 70),
        };

        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.Null(result.FailureReason);
        Assert.Equal(3, result.DataPointCount);
        Assert.Equal(70, result.CurrentScore);
    }

    [Fact]
    public void Forecast_ImprovingTrend_PositiveSlope()
    {
        var runs = MakeImprovingRuns();
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.True(result.DailyRate > 0);
        Assert.Equal("Improving", result.TrendDirection);
        Assert.True(result.WeeklyChange > 0);
        Assert.True(result.MonthlyChange > 0);
    }

    [Fact]
    public void Forecast_DecliningTrend_NegativeSlope()
    {
        var runs = MakeDecliningRuns();
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.True(result.DailyRate < 0);
        Assert.Equal("Declining", result.TrendDirection);
        Assert.True(result.WeeklyChange < 0);
    }

    [Fact]
    public void Forecast_StableTrend_SlopeNearZero()
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(baseDate, 75),
            MakeRun(baseDate.AddDays(7), 75),
            MakeRun(baseDate.AddDays(14), 76),
            MakeRun(baseDate.AddDays(21), 75),
            MakeRun(baseDate.AddDays(28), 75),
        };

        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.Equal("Stable", result.TrendDirection);
    }

    // ── Score clamping ───────────────────────────────────────────────

    [Fact]
    public void Forecast_PredictedAbove100_ClampedTo100()
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(baseDate, 90),
            MakeRun(baseDate.AddDays(7), 95),
            MakeRun(baseDate.AddDays(14), 99),
        };

        var options = new ScoreForecaster.ForecastOptions
        {
            ForecastDays = [90],
            IncludeModuleForecasts = false,
            IncludeRiskFactors = false,
        };

        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        foreach (var fp in result.Forecasts)
        {
            Assert.True(fp.PredictedScore <= 100);
            Assert.True(fp.UpperBound <= 100);
        }
    }

    [Fact]
    public void Forecast_PredictedBelow0_ClampedTo0()
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(baseDate, 20),
            MakeRun(baseDate.AddDays(7), 10),
            MakeRun(baseDate.AddDays(14), 5),
        };

        var options = new ScoreForecaster.ForecastOptions
        {
            ForecastDays = [365],
            IncludeModuleForecasts = false,
            IncludeRiskFactors = false,
        };

        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        foreach (var fp in result.Forecasts)
        {
            Assert.True(fp.PredictedScore >= 0);
            Assert.True(fp.LowerBound >= 0);
        }
    }

    // ── Forecast days capped at MaxForecastDays ──────────────────────

    [Fact]
    public void Forecast_ExcessiveDays_CappedAtMax()
    {
        var runs = MakeImprovingRuns();
        var options = new ScoreForecaster.ForecastOptions
        {
            ForecastDays = [500],
            IncludeModuleForecasts = false,
            IncludeRiskFactors = false,
        };

        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        Assert.Single(result.Forecasts);
        var latest = runs.OrderBy(r => r.Timestamp).Last().Timestamp;
        var delta = (result.Forecasts[0].Date - latest).TotalDays;
        Assert.True(delta <= ScoreForecaster.MaxForecastDays);
    }

    // ── Confidence intervals ─────────────────────────────────────────

    [Fact]
    public void Forecast_ConfidenceIntervals_LowerLessThanUpper()
    {
        var runs = MakeImprovingRuns(10);
        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        foreach (var fp in result.Forecasts)
        {
            Assert.True(fp.LowerBound <= fp.PredictedScore);
            Assert.True(fp.PredictedScore <= fp.UpperBound);
        }
    }

    [Fact]
    public void Forecast_WiderInterval_FartherInFuture()
    {
        var runs = MakeImprovingRuns(8);
        var options = new ScoreForecaster.ForecastOptions
        {
            ForecastDays = [7, 90],
            IncludeModuleForecasts = false,
            IncludeRiskFactors = false,
        };

        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        Assert.Equal(2, result.Forecasts.Count);
        var short7 = result.Forecasts[0];
        var long90 = result.Forecasts[1];
        Assert.True(long90.UpperBound - long90.LowerBound >= short7.UpperBound - short7.LowerBound);
    }

    // ── Days to target ───────────────────────────────────────────────

    [Fact]
    public void Forecast_TargetReachable_ReturnsDays()
    {
        var runs = MakeImprovingRuns(); // 60→80 over 4 weeks
        var options = new ScoreForecaster.ForecastOptions
        {
            TargetScore = 90,
            IncludeModuleForecasts = false,
            IncludeRiskFactors = false,
        };

        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        Assert.NotNull(result.DaysToTarget);
        Assert.True(result.DaysToTarget > 0);
        Assert.Equal(90, result.TargetScore);
    }

    [Fact]
    public void Forecast_TargetUnreachable_WrongDirection_ReturnsNull()
    {
        var runs = MakeDecliningRuns(); // 90→70 declining
        var options = new ScoreForecaster.ForecastOptions
        {
            TargetScore = 95, // can't reach higher with declining slope
            IncludeModuleForecasts = false,
            IncludeRiskFactors = false,
        };

        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        Assert.Null(result.DaysToTarget);
    }

    // ── R² and confidence ────────────────────────────────────────────

    [Fact]
    public void Forecast_PerfectLinear_HighRSquared()
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>();
        for (int i = 0; i < 10; i++)
        {
            runs.Add(MakeRun(baseDate.AddDays(i * 7), 50 + i * 5));
        }

        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.True(result.RSquared > 0.99);
        Assert.Equal("High", result.ConfidenceLevel);
    }

    [Fact]
    public void Forecast_NoisyData_LowerRSquared()
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        int[] scores = [60, 80, 55, 85, 50, 75, 65, 90, 45, 70];
        var runs = scores.Select((s, i) =>
            MakeRun(baseDate.AddDays(i * 7), s)).ToList();

        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.True(result.RSquared < 0.5);
    }

    // ── Module forecasts ─────────────────────────────────────────────

    [Fact]
    public void Forecast_WithModuleScores_ReturnsModuleForecasts()
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>();
        for (int i = 0; i < 5; i++)
        {
            runs.Add(MakeRun(baseDate.AddDays(i * 7), 70 + i * 3,
                moduleScores: new List<ModuleScoreRecord>
                {
                    new() { ModuleName = "Firewall", Score = 80 + i * 2 },
                    new() { ModuleName = "Updates", Score = 60 + i * 4 },
                }));
        }

        var options = new ScoreForecaster.ForecastOptions { IncludeModuleForecasts = true };
        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        Assert.Equal(2, result.ModuleForecasts.Count);
        Assert.Contains(result.ModuleForecasts, m => m.ModuleName == "Firewall");
        Assert.Contains(result.ModuleForecasts, m => m.ModuleName == "Updates");
        Assert.All(result.ModuleForecasts, m => Assert.True(m.Slope > 0));
    }

    [Fact]
    public void Forecast_ModuleForecasts_DisabledByOption()
    {
        var runs = MakeImprovingRuns();
        var options = new ScoreForecaster.ForecastOptions { IncludeModuleForecasts = false };

        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        Assert.Empty(result.ModuleForecasts);
    }

    // ── Risk factors ─────────────────────────────────────────────────

    [Fact]
    public void Forecast_CriticalFindings_FlagsRiskFactor()
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(baseDate, 70),
            MakeRun(baseDate.AddDays(7), 65),
            MakeRun(baseDate.AddDays(14), 60, criticals: 4),
        };

        var options = new ScoreForecaster.ForecastOptions { IncludeRiskFactors = true };
        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        Assert.Contains(result.RiskFactors, f => f.Category == "Critical Findings");
    }

    [Fact]
    public void Forecast_GrowingIssues_FlagsRiskFactor()
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(baseDate, 75, warnings: 5),
            MakeRun(baseDate.AddDays(7), 72, warnings: 8),
            MakeRun(baseDate.AddDays(14), 70, warnings: 12),
        };
        runs[0].TotalFindings = 5;
        runs[1].TotalFindings = 8;
        runs[2].TotalFindings = 12;

        var options = new ScoreForecaster.ForecastOptions { IncludeRiskFactors = true };
        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        Assert.Contains(result.RiskFactors, f => f.Category == "Growing Issues");
    }

    [Fact]
    public void Forecast_InfrequentScanning_FlagsRiskFactor()
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(baseDate, 75),
            MakeRun(baseDate.AddDays(30), 73),
            MakeRun(baseDate.AddDays(60), 71),
        };

        var options = new ScoreForecaster.ForecastOptions { IncludeRiskFactors = true };
        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        Assert.Contains(result.RiskFactors, f => f.Category == "Infrequent Scanning");
    }

    [Fact]
    public void Forecast_RecentDecline_FlagsRiskFactor()
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(baseDate, 80),
            MakeRun(baseDate.AddDays(7), 82),
            MakeRun(baseDate.AddDays(14), 70), // -12 drop
        };

        var options = new ScoreForecaster.ForecastOptions { IncludeRiskFactors = true };
        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        Assert.Contains(result.RiskFactors, f => f.Category == "Recent Decline");
    }

    [Fact]
    public void Forecast_RiskFactors_DisabledByOption()
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(baseDate, 70, criticals: 5),
            MakeRun(baseDate.AddDays(7), 65, criticals: 5),
            MakeRun(baseDate.AddDays(14), 60, criticals: 5),
        };

        var options = new ScoreForecaster.ForecastOptions { IncludeRiskFactors = false };
        var result = _forecaster.Forecast(runs, options);

        Assert.True(result.Success);
        Assert.Empty(result.RiskFactors);
    }

    // ── Grade assignment ─────────────────────────────────────────────

    [Theory]
    [InlineData(95, "A")]
    [InlineData(90, "A")]
    [InlineData(85, "B")]
    [InlineData(75, "C")]
    [InlineData(65, "D")]
    [InlineData(50, "F")]
    public void Forecast_GradeAssignment_CorrectForScore(int score, string expectedGrade)
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(baseDate, score - 2),
            MakeRun(baseDate.AddDays(7), score - 1),
            MakeRun(baseDate.AddDays(14), score),
        };

        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.Equal(expectedGrade, result.CurrentGrade);
    }

    // ── Linear regression static method ──────────────────────────────

    [Fact]
    public void LinearRegression_PerfectLine_ExactValues()
    {
        double[] x = [0, 1, 2, 3, 4];
        double[] y = [10, 12, 14, 16, 18]; // y = 2x + 10

        var (slope, intercept, rSquared) = ScoreForecaster.LinearRegression(x, y);

        Assert.Equal(2.0, slope, precision: 6);
        Assert.Equal(10.0, intercept, precision: 6);
        Assert.Equal(1.0, rSquared, precision: 6);
    }

    [Fact]
    public void LinearRegression_SinglePoint_ReturnsThatPoint()
    {
        double[] x = [5];
        double[] y = [42];

        var (slope, intercept, rSquared) = ScoreForecaster.LinearRegression(x, y);

        Assert.Equal(0, slope);
        Assert.Equal(42, intercept);
        Assert.Equal(0, rSquared);
    }

    [Fact]
    public void LinearRegression_TwoPoints_ExactFit()
    {
        double[] x = [0, 10];
        double[] y = [20, 70]; // y = 5x + 20

        var (slope, intercept, rSquared) = ScoreForecaster.LinearRegression(x, y);

        Assert.Equal(5.0, slope, precision: 6);
        Assert.Equal(20.0, intercept, precision: 6);
        Assert.Equal(1.0, rSquared, precision: 6);
    }

    [Fact]
    public void LinearRegression_ConstantY_ZeroSlope()
    {
        double[] x = [0, 1, 2, 3, 4];
        double[] y = [50, 50, 50, 50, 50];

        var (slope, intercept, rSquared) = ScoreForecaster.LinearRegression(x, y);

        Assert.Equal(0.0, slope, precision: 6);
        Assert.Equal(50.0, intercept, precision: 6);
    }

    // ── Statistical properties ───────────────────────────────────────

    [Fact]
    public void Forecast_Volatility_HighForNoisyData()
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        int[] scores = [40, 90, 30, 85, 45];
        var runs = scores.Select((s, i) =>
            MakeRun(baseDate.AddDays(i * 7), s)).ToList();

        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.True(result.Volatility > 20);
    }

    [Fact]
    public void Forecast_Volatility_LowForConsistentData()
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        int[] scores = [75, 76, 75, 76, 75];
        var runs = scores.Select((s, i) =>
            MakeRun(baseDate.AddDays(i * 7), s)).ToList();

        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.True(result.Volatility < 2);
    }

    // ── Input ordering ───────────────────────────────────────────────

    [Fact]
    public void Forecast_UnorderedInput_SortsChronologically()
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(baseDate.AddDays(14), 70),
            MakeRun(baseDate, 60),
            MakeRun(baseDate.AddDays(7), 65),
        };

        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.Equal(70, result.CurrentScore); // Latest by time, not by position
    }

    // ── Historical span ──────────────────────────────────────────────

    [Fact]
    public void Forecast_HistoricalSpan_CorrectDuration()
    {
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(baseDate, 60),
            MakeRun(baseDate.AddDays(10), 65),
            MakeRun(baseDate.AddDays(20), 70),
        };

        var result = _forecaster.Forecast(runs);

        Assert.True(result.Success);
        Assert.Equal(TimeSpan.FromDays(20), result.HistoricalSpan);
    }

    // ── Custom confidence multiplier ─────────────────────────────────

    [Fact]
    public void Forecast_NarrowConfidence_SmallerInterval()
    {
        // Use noisy mid-range data so residuals are non-zero and intervals are meaningful
        var baseDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        int[] scores = [48, 53, 50, 56, 52, 59, 55, 61]; // generally improving but noisy
        var runs = scores.Select((s, i) =>
            MakeRun(baseDate.AddDays(i * 7), s)).ToList();

        var wide = _forecaster.Forecast(runs, new ScoreForecaster.ForecastOptions
        {
            ForecastDays = [7],
            ConfidenceMultiplier = 2.576, // 99%
            IncludeModuleForecasts = false,
            IncludeRiskFactors = false,
        });

        var narrow = _forecaster.Forecast(runs, new ScoreForecaster.ForecastOptions
        {
            ForecastDays = [7],
            ConfidenceMultiplier = 1.0, // ~68%
            IncludeModuleForecasts = false,
            IncludeRiskFactors = false,
        });

        Assert.True(wide.Success);
        Assert.True(narrow.Success);
        var wideRange = wide.Forecasts[0].UpperBound - wide.Forecasts[0].LowerBound;
        var narrowRange = narrow.Forecasts[0].UpperBound - narrow.Forecasts[0].LowerBound;
        Assert.True(wideRange > narrowRange,
            $"Expected wide ({wideRange}) > narrow ({narrowRange})");
    }
}
