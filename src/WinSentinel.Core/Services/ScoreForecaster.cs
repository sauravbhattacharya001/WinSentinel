using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Forecasts future security scores using linear regression on historical
/// audit data.  Provides predicted scores at future dates, confidence
/// intervals, estimated time to reach target scores, per-module
/// projections, and risk factors that could cause score decline.
///
/// <para>Requires at least 3 historical audit runs to produce a forecast.
/// Accuracy improves with more data points and more regular scan intervals.</para>
/// </summary>
public class ScoreForecaster
{
    // ── Configuration ────────────────────────────────────────────────

    /// <summary>Minimum number of audit runs required for forecasting.</summary>
    public const int MinimumRunsRequired = 3;

    /// <summary>Maximum forecast horizon in days.</summary>
    public const int MaxForecastDays = 365;

    /// <summary>Score floor (cannot go below 0).</summary>
    private const int ScoreMin = 0;

    /// <summary>Score ceiling (cannot exceed 100).</summary>
    private const int ScoreMax = 100;

    // ── Result types ─────────────────────────────────────────────────

    /// <summary>A single point forecast at a specific date.</summary>
    public record ForecastPoint(
        DateTimeOffset Date,
        double PredictedScore,
        double LowerBound,
        double UpperBound,
        string Grade);

    /// <summary>Forecast for a single audit module.</summary>
    public record ModuleForecast(
        string ModuleName,
        int CurrentScore,
        double PredictedScore,
        double Slope,
        string Trend);

    /// <summary>A risk factor that could cause score decline.</summary>
    public record RiskFactor(
        string Category,
        string Description,
        string Severity,
        double ImpactEstimate);

    /// <summary>Complete forecast result.</summary>
    public class ForecastResult
    {
        /// <summary>Whether the forecast could be generated.</summary>
        public bool Success { get; init; }

        /// <summary>Reason for failure (if Success is false).</summary>
        public string? FailureReason { get; init; }

        /// <summary>Number of historical data points used.</summary>
        public int DataPointCount { get; init; }

        /// <summary>Date range of historical data.</summary>
        public TimeSpan HistoricalSpan { get; init; }

        /// <summary>Current score (most recent audit).</summary>
        public int CurrentScore { get; init; }

        /// <summary>Current grade.</summary>
        public string CurrentGrade { get; init; } = "";

        /// <summary>Daily score change rate (slope of regression line).</summary>
        public double DailyRate { get; init; }

        /// <summary>Weekly projected change.</summary>
        public double WeeklyChange { get; init; }

        /// <summary>Monthly projected change.</summary>
        public double MonthlyChange { get; init; }

        /// <summary>Overall trend direction.</summary>
        public string TrendDirection { get; init; } = "";

        /// <summary>R² goodness-of-fit (0.0 to 1.0).</summary>
        public double RSquared { get; init; }

        /// <summary>Confidence level description based on R².</summary>
        public string ConfidenceLevel { get; init; } = "";

        /// <summary>Forecasted scores at requested future dates.</summary>
        public List<ForecastPoint> Forecasts { get; init; } = [];

        /// <summary>Estimated days to reach a target score (null if unreachable).</summary>
        public int? DaysToTarget { get; init; }

        /// <summary>The target score used for DaysToTarget.</summary>
        public int? TargetScore { get; init; }

        /// <summary>Per-module projections.</summary>
        public List<ModuleForecast> ModuleForecasts { get; init; } = [];

        /// <summary>Identified risk factors.</summary>
        public List<RiskFactor> RiskFactors { get; init; } = [];

        /// <summary>Standard error of the regression estimate.</summary>
        public double StandardError { get; init; }

        /// <summary>Residual standard deviation.</summary>
        public double ResidualStdDev { get; init; }

        /// <summary>Score volatility (standard deviation of scores).</summary>
        public double Volatility { get; init; }
    }

    /// <summary>Options for generating a forecast.</summary>
    public class ForecastOptions
    {
        /// <summary>Days into the future to forecast (default: 7, 30, 90).</summary>
        public List<int> ForecastDays { get; set; } = [7, 30, 90];

        /// <summary>Target score to estimate days-to-reach.</summary>
        public int? TargetScore { get; set; }

        /// <summary>Confidence interval width (1.96 = 95%, 1.645 = 90%).</summary>
        public double ConfidenceMultiplier { get; set; } = 1.96;

        /// <summary>Whether to include per-module forecasts.</summary>
        public bool IncludeModuleForecasts { get; set; } = true;

        /// <summary>Whether to analyze risk factors.</summary>
        public bool IncludeRiskFactors { get; set; } = true;
    }

    // ── Core forecasting ─────────────────────────────────────────────

    /// <summary>
    /// Generate a security score forecast from historical audit data.
    /// </summary>
    /// <param name="runs">Historical audit runs (any order).</param>
    /// <param name="options">Forecast configuration.</param>
    public ForecastResult Forecast(List<AuditRunRecord> runs, ForecastOptions? options = null)
    {
        options ??= new ForecastOptions();

        if (runs.Count < MinimumRunsRequired)
        {
            return new ForecastResult
            {
                Success = false,
                FailureReason = $"Insufficient data: {runs.Count} runs provided, " +
                                $"minimum {MinimumRunsRequired} required.",
                DataPointCount = runs.Count,
            };
        }

        // Sort chronologically
        var sorted = runs.OrderBy(r => r.Timestamp).ToList();
        var latest = sorted.Last();
        var oldest = sorted.First();

        // Convert timestamps to days-since-first-scan for regression
        var t0 = oldest.Timestamp;
        var xValues = sorted.Select(r => (r.Timestamp - t0).TotalDays).ToArray();
        var yValues = sorted.Select(r => (double)r.OverallScore).ToArray();

        // Linear regression: y = slope * x + intercept
        var (slope, intercept, rSquared) = LinearRegression(xValues, yValues);

        // Standard error and residual std dev
        var residuals = new double[xValues.Length];
        for (int i = 0; i < xValues.Length; i++)
            residuals[i] = yValues[i] - (slope * xValues[i] + intercept);

        var residualStdDev = xValues.Length > 2
            ? Math.Sqrt(residuals.Select(r => r * r).Sum() / (xValues.Length - 2))
            : 0.0;

        var volatility = CalculateStdDev(yValues);

        // Build forecast points
        var latestDay = xValues.Last();
        var forecasts = new List<ForecastPoint>();
        foreach (var days in options.ForecastDays)
        {
            var clampedDays = Math.Min(days, MaxForecastDays);
            var futureDay = latestDay + clampedDays;
            var predicted = slope * futureDay + intercept;
            var clamped = Math.Clamp(predicted, ScoreMin, ScoreMax);

            // Prediction interval widens with distance from mean
            var xMean = xValues.Average();
            var xSumSqDev = xValues.Select(x => (x - xMean) * (x - xMean)).Sum();
            var predictionSe = residualStdDev * Math.Sqrt(
                1.0 + 1.0 / xValues.Length +
                (futureDay - xMean) * (futureDay - xMean) / Math.Max(xSumSqDev, 1e-10));

            var margin = options.ConfidenceMultiplier * predictionSe;

            forecasts.Add(new ForecastPoint(
                Date: latest.Timestamp.AddDays(clampedDays),
                PredictedScore: Math.Round(clamped, 1),
                LowerBound: Math.Round(Math.Clamp(predicted - margin, ScoreMin, ScoreMax), 1),
                UpperBound: Math.Round(Math.Clamp(predicted + margin, ScoreMin, ScoreMax), 1),
                Grade: GetGrade((int)Math.Round(clamped))));
        }

        // Days to target
        int? daysToTarget = null;
        if (options.TargetScore.HasValue && Math.Abs(slope) > 1e-10)
        {
            var targetDay = (options.TargetScore.Value - intercept) / slope;
            var daysFromNow = targetDay - latestDay;

            if (daysFromNow > 0 && daysFromNow <= MaxForecastDays)
            {
                // Only reachable if slope is going in the right direction
                if ((options.TargetScore.Value > latest.OverallScore && slope > 0) ||
                    (options.TargetScore.Value < latest.OverallScore && slope < 0) ||
                    options.TargetScore.Value == latest.OverallScore)
                {
                    daysToTarget = (int)Math.Ceiling(daysFromNow);
                }
            }
        }

        // Module forecasts
        var moduleForecasts = new List<ModuleForecast>();
        if (options.IncludeModuleForecasts)
        {
            moduleForecasts = BuildModuleForecasts(sorted, t0, latestDay);
        }

        // Risk factors
        var riskFactors = new List<RiskFactor>();
        if (options.IncludeRiskFactors)
        {
            riskFactors = IdentifyRiskFactors(sorted);
        }

        var trendDir = slope switch
        {
            > 0.1 => "Improving",
            < -0.1 => "Declining",
            _ => "Stable"
        };

        var confidence = rSquared switch
        {
            >= 0.8 => "High",
            >= 0.5 => "Moderate",
            >= 0.2 => "Low",
            _ => "Very Low"
        };

        return new ForecastResult
        {
            Success = true,
            DataPointCount = runs.Count,
            HistoricalSpan = latest.Timestamp - oldest.Timestamp,
            CurrentScore = latest.OverallScore,
            CurrentGrade = latest.Grade,
            DailyRate = Math.Round(slope, 4),
            WeeklyChange = Math.Round(slope * 7, 2),
            MonthlyChange = Math.Round(slope * 30, 2),
            TrendDirection = trendDir,
            RSquared = Math.Round(rSquared, 4),
            ConfidenceLevel = confidence,
            StandardError = Math.Round(residualStdDev, 2),
            ResidualStdDev = Math.Round(residualStdDev, 2),
            Volatility = Math.Round(volatility, 2),
            Forecasts = forecasts,
            DaysToTarget = daysToTarget,
            TargetScore = options.TargetScore,
            ModuleForecasts = moduleForecasts,
            RiskFactors = riskFactors,
        };
    }

    // ── Module-level forecasts ───────────────────────────────────────

    private List<ModuleForecast> BuildModuleForecasts(
        List<AuditRunRecord> sorted,
        DateTimeOffset t0,
        double latestDay)
    {
        // Collect all module names across all runs
        var moduleNames = sorted
            .SelectMany(r => r.ModuleScores)
            .Select(m => m.ModuleName)
            .Distinct()
            .OrderBy(n => n)
            .ToList();

        var forecasts = new List<ModuleForecast>();

        foreach (var moduleName in moduleNames)
        {
            // Get data points for this module
            var moduleData = sorted
                .Where(r => r.ModuleScores.Any(m => m.ModuleName == moduleName))
                .Select(r => new
                {
                    Day = (r.Timestamp - t0).TotalDays,
                    Score = r.ModuleScores.First(m => m.ModuleName == moduleName).Score
                })
                .ToList();

            if (moduleData.Count < 2) continue;

            var xVals = moduleData.Select(d => d.Day).ToArray();
            var yVals = moduleData.Select(d => (double)d.Score).ToArray();

            var (modSlope, modIntercept, _) = LinearRegression(xVals, yVals);
            var predicted = modSlope * (latestDay + 30) + modIntercept;
            var clamped = Math.Clamp(predicted, ScoreMin, ScoreMax);

            var trend = modSlope switch
            {
                > 0.1 => "Improving",
                < -0.1 => "Declining",
                _ => "Stable"
            };

            forecasts.Add(new ModuleForecast(
                ModuleName: moduleName,
                CurrentScore: moduleData.Last().Score,
                PredictedScore: Math.Round(clamped, 1),
                Slope: Math.Round(modSlope, 4),
                Trend: trend));
        }

        return forecasts.OrderBy(f => f.PredictedScore).ToList();
    }

    // ── Risk factor identification ───────────────────────────────────

    private List<RiskFactor> IdentifyRiskFactors(List<AuditRunRecord> sorted)
    {
        var factors = new List<RiskFactor>();
        var latest = sorted.Last();

        // Factor 1: High critical finding count
        if (latest.CriticalCount > 0)
        {
            factors.Add(new RiskFactor(
                Category: "Critical Findings",
                Description: $"{latest.CriticalCount} critical finding(s) remain unresolved.",
                Severity: latest.CriticalCount >= 3 ? "High" : "Medium",
                ImpactEstimate: latest.CriticalCount * 5.0));
        }

        // Factor 2: Score volatility
        if (sorted.Count >= 3)
        {
            var scores = sorted.Select(r => r.OverallScore).ToArray();
            var stdDev = CalculateStdDev(scores.Select(s => (double)s).ToArray());
            if (stdDev > 10)
            {
                factors.Add(new RiskFactor(
                    Category: "Score Volatility",
                    Description: $"Score varies by ±{stdDev:F1} points — inconsistent posture.",
                    Severity: stdDev > 20 ? "High" : "Medium",
                    ImpactEstimate: stdDev));
            }
        }

        // Factor 3: Recent score decline
        if (sorted.Count >= 2)
        {
            var prev = sorted[^2];
            var delta = latest.OverallScore - prev.OverallScore;
            if (delta < -5)
            {
                factors.Add(new RiskFactor(
                    Category: "Recent Decline",
                    Description: $"Score dropped {Math.Abs(delta)} points since last scan.",
                    Severity: delta < -15 ? "High" : "Medium",
                    ImpactEstimate: Math.Abs(delta)));
            }
        }

        // Factor 4: Growing finding count
        if (sorted.Count >= 3)
        {
            var recent = sorted.TakeLast(3).ToList();
            if (recent[2].TotalFindings > recent[1].TotalFindings &&
                recent[1].TotalFindings > recent[0].TotalFindings)
            {
                factors.Add(new RiskFactor(
                    Category: "Growing Issues",
                    Description: "Finding count has increased for 3 consecutive scans.",
                    Severity: "Medium",
                    ImpactEstimate: recent[2].TotalFindings - recent[0].TotalFindings));
            }
        }

        // Factor 5: Infrequent scanning
        if (sorted.Count >= 2)
        {
            var gaps = new List<double>();
            for (int i = 1; i < sorted.Count; i++)
                gaps.Add((sorted[i].Timestamp - sorted[i - 1].Timestamp).TotalDays);

            var avgGap = gaps.Average();
            if (avgGap > 14)
            {
                factors.Add(new RiskFactor(
                    Category: "Infrequent Scanning",
                    Description: $"Average {avgGap:F0} days between scans — " +
                                 $"recommend at least weekly.",
                    Severity: avgGap > 30 ? "High" : "Low",
                    ImpactEstimate: avgGap / 7.0));
            }
        }

        // Factor 6: High warning-to-pass ratio
        if (latest.PassCount > 0)
        {
            var ratio = (double)(latest.WarningCount + latest.CriticalCount) / latest.PassCount;
            if (ratio > 0.5)
            {
                factors.Add(new RiskFactor(
                    Category: "Issue Density",
                    Description: $"Finding-to-pass ratio of {ratio:F2} — " +
                                 $"more than half of checks have issues.",
                    Severity: ratio > 1.0 ? "High" : "Medium",
                    ImpactEstimate: ratio * 10));
            }
        }

        return factors.OrderByDescending(f => f.ImpactEstimate).ToList();
    }

    // ── Math helpers ─────────────────────────────────────────────────

    /// <summary>
    /// Ordinary least-squares linear regression.
    /// Returns (slope, intercept, rSquared).
    /// </summary>
    public static (double Slope, double Intercept, double RSquared) LinearRegression(
        double[] x, double[] y)
    {
        int n = x.Length;
        if (n < 2) return (0, y.Length > 0 ? y[0] : 0, 0);

        double sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;
        for (int i = 0; i < n; i++)
        {
            sumX += x[i];
            sumY += y[i];
            sumXY += x[i] * y[i];
            sumX2 += x[i] * x[i];
        }

        double xMean = sumX / n;
        double yMean = sumY / n;
        double denom = sumX2 - sumX * sumX / n;

        if (Math.Abs(denom) < 1e-10)
            return (0, yMean, 0);

        double slope = (sumXY - sumX * sumY / n) / denom;
        double intercept = yMean - slope * xMean;

        // R² calculation
        double ssTot = 0, ssRes = 0;
        for (int i = 0; i < n; i++)
        {
            double predicted = slope * x[i] + intercept;
            ssTot += (y[i] - yMean) * (y[i] - yMean);
            ssRes += (y[i] - predicted) * (y[i] - predicted);
        }

        double rSquared = ssTot > 1e-10 ? 1.0 - ssRes / ssTot : 0;

        return (slope, intercept, Math.Max(0, rSquared));
    }

    private static double CalculateStdDev(double[] values)
    {
        if (values.Length < 2) return 0;
        double mean = values.Average();
        double sumSqDiff = values.Select(v => (v - mean) * (v - mean)).Sum();
        return Math.Sqrt(sumSqDiff / (values.Length - 1));
    }

    private static string GetGrade(int score) => score switch
    {
        >= 90 => "A",
        >= 80 => "B",
        >= 70 => "C",
        >= 60 => "D",
        _ => "F"
    };
}
