using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

/// <summary>
/// Tests for <see cref="ShadowItDetectorService"/>.
///
/// The service currently returns demo data, but the aggregation logic
/// (risk scoring, recommendation generation, category breakdown) is real
/// and should be locked down so future refactors don't silently shift
/// risk scores or drop recommendations.
/// </summary>
public class ShadowItDetectorServiceTests
{
    private static ShadowItResult RunDetect() => new ShadowItDetectorService().Detect();

    [Fact]
    public void Detect_ReturnsNonNullResult()
    {
        Assert.NotNull(RunDetect());
    }

    [Fact]
    public void Detect_PopulatesAllFourCategories()
    {
        var result = RunDetect();
        Assert.NotEmpty(result.UnknownServices);
        Assert.NotEmpty(result.SuspiciousListeningPorts);
        Assert.NotEmpty(result.UnauthorizedStartupPrograms);
        Assert.NotEmpty(result.ShadowScheduledTasks);
    }

    [Fact]
    public void Detect_TotalFindingsEqualsSumOfCategoryCounts()
    {
        var r = RunDetect();
        var expected = r.UnknownServices.Count
                     + r.SuspiciousListeningPorts.Count
                     + r.UnauthorizedStartupPrograms.Count
                     + r.ShadowScheduledTasks.Count;
        Assert.Equal(expected, r.TotalFindings);
    }

    [Fact]
    public void Detect_HighMediumLowCountsSumToTotal()
    {
        var r = RunDetect();
        Assert.Equal(r.TotalFindings, r.HighRiskCount + r.MediumRiskCount + r.LowRiskCount);
    }

    [Fact]
    public void Detect_RiskScoreIsClampedToHundred()
    {
        var r = RunDetect();
        Assert.InRange(r.OverallRiskScore, 0, 100);
    }

    [Fact]
    public void Detect_RiskScoreMatchesWeightedFormula()
    {
        // Score = min(100, High*20 + Medium*8 + Low*2). If this changes
        // intentionally, update the assertion deliberately.
        var r = RunDetect();
        var expected = Math.Min(100, r.HighRiskCount * 20 + r.MediumRiskCount * 8 + r.LowRiskCount * 2);
        Assert.Equal(expected, r.OverallRiskScore);
    }

    [Fact]
    public void Detect_CategoryBreakdownHasAllFourKeysWithCorrectCounts()
    {
        var r = RunDetect();
        Assert.Equal(r.UnknownServices.Count,             r.CategoryBreakdown["Unknown Services"]);
        Assert.Equal(r.SuspiciousListeningPorts.Count,    r.CategoryBreakdown["Suspicious Ports"]);
        Assert.Equal(r.UnauthorizedStartupPrograms.Count, r.CategoryBreakdown["Unauthorized Startup"]);
        Assert.Equal(r.ShadowScheduledTasks.Count,        r.CategoryBreakdown["Shadow Tasks"]);
    }

    [Fact]
    public void Detect_ProducesRecommendationsForPopulatedCategories()
    {
        var r = RunDetect();
        // With demo data every category is populated, so each per-category
        // recommendation message must appear.
        Assert.Contains(r.Recommendations, msg => msg.Contains("unknown service"));
        Assert.Contains(r.Recommendations, msg => msg.Contains("suspicious listening port"));
        Assert.Contains(r.Recommendations, msg => msg.Contains("startup program"));
        Assert.Contains(r.Recommendations, msg => msg.Contains("scheduled task"));
    }

    [Fact]
    public void Detect_RecommendsHighRiskActionWhenHighFindingsExist()
    {
        var r = RunDetect();
        if (r.HighRiskCount > 0)
        {
            Assert.Contains(r.Recommendations,
                msg => msg.Contains("Immediately investigate high-risk findings"));
        }
    }

    [Fact]
    public void Detect_RecommendsAppLockerWhenScoreIsHigh()
    {
        var r = RunDetect();
        if (r.OverallRiskScore > 50)
        {
            Assert.Contains(r.Recommendations,
                msg => msg.Contains("AppLocker") || msg.Contains("WDAC"));
        }
    }

    [Fact]
    public void Detect_DoesNotRecommendBothHighAndLowGuidanceSimultaneously()
    {
        // The "low footprint" advice and the AppLocker advice are
        // mutually exclusive by construction (riskScore > 50 vs <= 20).
        var r = RunDetect();
        bool hasLow  = r.Recommendations.Any(m => m.Contains("Low shadow IT footprint"));
        bool hasHigh = r.Recommendations.Any(m => m.Contains("AppLocker") || m.Contains("WDAC"));
        Assert.False(hasLow && hasHigh,
            "Recommendation set should not advertise both 'low footprint' and 'apply application whitelisting'.");
    }

    [Fact]
    public void Detect_ScanTimestampIsUtcAndRecent()
    {
        var before = DateTime.UtcNow.AddSeconds(-5);
        var r = RunDetect();
        var after  = DateTime.UtcNow.AddSeconds(5);
        Assert.InRange(r.ScanTimestamp, before, after);
        Assert.Equal(DateTimeKind.Utc, r.ScanTimestamp.Kind);
    }

    [Fact]
    public void Detect_EveryFindingHasARiskLevel()
    {
        var r = RunDetect();
        Assert.All(r.UnknownServices,             s => Assert.False(string.IsNullOrEmpty(s.RiskLevel)));
        Assert.All(r.SuspiciousListeningPorts,    p => Assert.False(string.IsNullOrEmpty(p.RiskLevel)));
        Assert.All(r.UnauthorizedStartupPrograms, s => Assert.False(string.IsNullOrEmpty(s.RiskLevel)));
        Assert.All(r.ShadowScheduledTasks,        t => Assert.False(string.IsNullOrEmpty(t.RiskLevel)));
    }

    [Fact]
    public void Detect_RiskLevelsUseExpectedVocabulary()
    {
        var allowed = new HashSet<string> { "High", "Medium", "Low" };
        var r = RunDetect();
        var all = r.UnknownServices.Select(x => x.RiskLevel)
            .Concat(r.SuspiciousListeningPorts.Select(x => x.RiskLevel))
            .Concat(r.UnauthorizedStartupPrograms.Select(x => x.RiskLevel))
            .Concat(r.ShadowScheduledTasks.Select(x => x.RiskLevel));
        Assert.All(all, level => Assert.Contains(level, allowed));
    }

    [Fact]
    public void Detect_IsDeterministicAcrossCalls()
    {
        // Demo data is hard-coded, so two consecutive calls must agree on
        // counts and overall score. Guards against future state leakage.
        var a = RunDetect();
        var b = RunDetect();
        Assert.Equal(a.TotalFindings,     b.TotalFindings);
        Assert.Equal(a.HighRiskCount,     b.HighRiskCount);
        Assert.Equal(a.MediumRiskCount,   b.MediumRiskCount);
        Assert.Equal(a.LowRiskCount,      b.LowRiskCount);
        Assert.Equal(a.OverallRiskScore,  b.OverallRiskScore);
    }
}
