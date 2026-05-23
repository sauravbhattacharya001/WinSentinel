using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

/// <summary>
/// Tests for <see cref="AnomalyWatchdogService"/>.
/// Covers stats computation, score-drop detection, finding-spike detection,
/// module regression classification, status escalation, recommendations,
/// and the new <see cref="WatchdogConfig"/> threshold knobs.
/// </summary>
public class AnomalyWatchdogServiceTests
{
    private static AuditRunRecord Run(
        DateTimeOffset ts,
        int score,
        int totalFindings = 0,
        int criticals = 0,
        params (string Module, int Score)[] modules)
    {
        return new AuditRunRecord
        {
            Timestamp = ts,
            OverallScore = score,
            TotalFindings = totalFindings,
            CriticalCount = criticals,
            ModuleScores = modules.Select(m => new ModuleScoreRecord
            {
                ModuleName = m.Module,
                Score = m.Score
            }).ToList()
        };
    }

    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // ── Guard clauses ────────────────────────────────────────────────

    [Fact]
    public void Analyze_NullRuns_Throws()
    {
        var svc = new AnomalyWatchdogService();
        Assert.Throws<ArgumentNullException>(() => svc.Analyze(null!, days: 30));
    }

    [Fact]
    public void Constructor_NullConfig_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new AnomalyWatchdogService((WatchdogConfig)null!));
    }

    [Fact]
    public void Analyze_EmptyRuns_ReturnsRecommendationAndOkStatus()
    {
        var svc = new AnomalyWatchdogService();
        var report = svc.Analyze(new List<AuditRunRecord>(), days: 7);

        Assert.Equal(0, report.RunsAnalyzed);
        Assert.Equal(7, report.DaysAnalyzed);
        Assert.Equal("OK", report.OverallStatus);
        Assert.Empty(report.ScoreAnomalies);
        Assert.Empty(report.FindingSpikes);
        Assert.Empty(report.ModuleRegressions);
        Assert.Contains(report.Recommendations, r => r.Contains("at least 2"));
    }

    [Fact]
    public void Analyze_SingleRun_ReturnsRecommendationAndOkStatus()
    {
        var svc = new AnomalyWatchdogService();
        var report = svc.Analyze(new List<AuditRunRecord> { Run(T0, 90) }, days: 30);

        Assert.Equal(1, report.RunsAnalyzed);
        Assert.Equal("OK", report.OverallStatus);
        Assert.Contains(report.Recommendations, r => r.Contains("at least 2"));
    }

    // ── Stats ────────────────────────────────────────────────────────

    [Fact]
    public void Analyze_TwoRuns_ComputesMeanStdDevAndLatest()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,               80, totalFindings: 4),
            Run(T0.AddHours(1),   90, totalFindings: 6),
        };

        var report = svc.Analyze(runs, days: 1);

        Assert.Equal(2, report.RunsAnalyzed);
        Assert.Equal(85.0, report.Stats.MeanScore);
        Assert.Equal(5.0, report.Stats.MeanFindings);
        Assert.True(report.Stats.StdDevScore > 0);
        Assert.True(report.Stats.StdDevFindings > 0);
        Assert.Equal(90, report.Stats.LatestScore);
        Assert.Equal(6, report.Stats.LatestFindings);
    }

    [Fact]
    public void Analyze_IdenticalScores_StdDevAndZScoresAreZero()
    {
        var svc = new AnomalyWatchdogService();
        var runs = Enumerable.Range(0, 5)
            .Select(i => Run(T0.AddHours(i), 80, totalFindings: 3))
            .ToList();

        var report = svc.Analyze(runs, days: 1);

        Assert.Equal(0, report.Stats.StdDevScore);
        Assert.Equal(0, report.Stats.StdDevFindings);
        Assert.Equal(0, report.Stats.ScoreZScore);
        Assert.Equal(0, report.Stats.FindingsZScore);
        Assert.Empty(report.ScoreAnomalies);
        Assert.Empty(report.FindingSpikes);
        Assert.Equal("OK", report.OverallStatus);
    }

    [Fact]
    public void Analyze_OrdersRunsByTimestamp_RegardlessOfInputOrder()
    {
        var svc = new AnomalyWatchdogService();
        // Provide newest first to make sure the service sorts.
        var runs = new List<AuditRunRecord>
        {
            Run(T0.AddHours(2), 70),
            Run(T0,             90),
            Run(T0.AddHours(1), 80),
        };

        var report = svc.Analyze(runs, days: 1);

        Assert.Equal(70, report.Stats.LatestScore);
    }

    // ── Score anomalies ─────────────────────────────────────────────

    [Fact]
    public void Analyze_AbsoluteScoreDropOf10_FlaggedAsWarning()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90),
            Run(T0.AddHours(1), 80), // drop = 10, exact warn threshold
        };

        var report = svc.Analyze(runs, days: 1);

        Assert.Single(report.ScoreAnomalies);
        var a = report.ScoreAnomalies[0];
        Assert.Equal(10, a.Drop);
        Assert.Equal(80, a.Score);
        Assert.Equal(90, a.PreviousScore);
        // 10pt drop alone is not "Major" (<20) so severity comes from Warning bucket
        Assert.Equal("Warning", a.Severity);
        Assert.Equal("WARN", report.OverallStatus);
    }

    [Fact]
    public void Analyze_AbsoluteScoreDropOf20_EscalatedToCritical()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90),
            Run(T0.AddHours(1), 70), // drop = 20, major
        };

        var report = svc.Analyze(runs, days: 1);

        var a = Assert.Single(report.ScoreAnomalies);
        Assert.Equal("Critical", a.Severity);
        Assert.Equal("Major score collapse", a.Reason);
        Assert.Equal("ALERT", report.OverallStatus);
    }

    [Fact]
    public void Analyze_ScoreImprovement_DoesNotProduceAnomaly()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             70),
            Run(T0.AddHours(1), 90),
        };

        var report = svc.Analyze(runs, days: 1);

        Assert.Empty(report.ScoreAnomalies);
        Assert.Equal("OK", report.OverallStatus);
    }

    [Fact]
    public void Analyze_SmallDropBelowThreshold_NotFlagged()
    {
        // Raise warn z so that small absolute drops in a noisy series do not trip
        // the z-score path (real config behaviour is z=1.5).
        var cfg = new WatchdogConfig { ZThresholdWarn = 10, ZThresholdCrit = 20 };
        var svc = new AnomalyWatchdogService(cfg);
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90),
            Run(T0.AddHours(1), 89),
            Run(T0.AddHours(2), 90),
            Run(T0.AddHours(3), 88), // drop=2 vs prev; <MinorScoreDrop(10), z above warn ignored
        };

        var report = svc.Analyze(runs, days: 1);
        Assert.Empty(report.ScoreAnomalies);
    }

    [Fact]
    public void Analyze_ZScoreAtCritThreshold_EscalatesEvenWithoutAbsoluteCollapse()
    {
        // Custom config: tiny absolute thresholds disabled (set high), so only z-score path fires.
        var cfg = new WatchdogConfig
        {
            MinorScoreDrop = 1000,
            MajorScoreDrop = 1000,
            ZThresholdWarn = 1.0,
            ZThresholdCrit = 2.0,
        };
        var svc = new AnomalyWatchdogService(cfg);

        var runs = new List<AuditRunRecord>
        {
            Run(T0,                100),
            Run(T0.AddHours(1),    100),
            Run(T0.AddHours(2),    100),
            Run(T0.AddHours(3),    40), // drop=60; mean=85, stdDev=30, z=2.0 → Critical
        };

        var report = svc.Analyze(runs, days: 1);

        var a = Assert.Single(report.ScoreAnomalies);
        Assert.Equal("Critical", a.Severity);
        Assert.Equal("Statistically significant drop", a.Reason);
    }

    // ── Finding spikes ──────────────────────────────────────────────

    [Fact]
    public void Analyze_AbsoluteFindingSpikeOf5_FlaggedAsWarning()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90, totalFindings: 2, criticals: 0),
            Run(T0.AddHours(1), 90, totalFindings: 7, criticals: 0), // +5
        };

        var report = svc.Analyze(runs, days: 1);

        var spike = Assert.Single(report.FindingSpikes);
        Assert.Equal(5, spike.Increase);
        Assert.Equal(7, spike.TotalFindings);
        Assert.Equal(2, spike.PreviousFindings);
        Assert.Equal("Warning", spike.Severity);
    }

    [Fact]
    public void Analyze_CriticalCountJump_EscalatesSpikeToCritical()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90, totalFindings: 2, criticals: 0),
            Run(T0.AddHours(1), 90, totalFindings: 8, criticals: 3), // +6 findings, +3 crits (>2)
        };

        var report = svc.Analyze(runs, days: 1);

        var spike = Assert.Single(report.FindingSpikes);
        Assert.Equal("Critical", spike.Severity);
        Assert.Equal(3, spike.CriticalCount);
        Assert.Equal("ALERT", report.OverallStatus);
    }

    [Fact]
    public void Analyze_FindingsDecrease_NoSpike()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90, totalFindings: 10),
            Run(T0.AddHours(1), 92, totalFindings: 4),
        };

        var report = svc.Analyze(runs, days: 1);
        Assert.Empty(report.FindingSpikes);
    }

    // ── Module regressions ──────────────────────────────────────────

    [Fact]
    public void Analyze_ModuleScoreDrop5_Flagged()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90, modules: new[] { ("Firewall", 90) }),
            Run(T0.AddHours(1), 90, modules: new[] { ("Firewall", 85) }), // drop = 5
        };

        var report = svc.Analyze(runs, days: 1);

        var reg = Assert.Single(report.ModuleRegressions);
        Assert.Equal("Firewall", reg.ModuleName);
        Assert.Equal(85, reg.CurrentScore);
        Assert.Equal(90, reg.PreviousScore);
        Assert.Equal(5, reg.ScoreDrop);
        Assert.Equal("Volatile", reg.Trend); // single drop, not below collapse threshold, no streak
    }

    [Fact]
    public void Analyze_ModuleCollapsedToZero_TrendIsCollapsedAndStatusAlert()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90, modules: new[] { ("Defender", 80) }),
            Run(T0.AddHours(1), 90, modules: new[] { ("Defender", 5)  }), // collapsed
        };

        var report = svc.Analyze(runs, days: 1);

        var reg = Assert.Single(report.ModuleRegressions);
        Assert.Equal("Collapsed", reg.Trend);
        Assert.Equal("ALERT", report.OverallStatus);
    }

    [Fact]
    public void Analyze_ModuleConsecutiveDrops_ClassifiedAsDeclining()
    {
        var svc = new AnomalyWatchdogService();
        // 90 → 85 → 80 → 75 → 70 (four backward steps; latest run is 70 vs prev 75 → drop=5,
        // walking back: 75>70 (drop1), 80>75 (drop2), 85>80 (drop3), 90>85 (drop4) → 4 consecutive)
        var runs = new List<AuditRunRecord>
        {
            Run(T0,                90, modules: new[] { ("Updates", 90) }),
            Run(T0.AddHours(1),    90, modules: new[] { ("Updates", 85) }),
            Run(T0.AddHours(2),    90, modules: new[] { ("Updates", 80) }),
            Run(T0.AddHours(3),    90, modules: new[] { ("Updates", 75) }),
            Run(T0.AddHours(4),    90, modules: new[] { ("Updates", 70) }),
        };

        var report = svc.Analyze(runs, days: 1);

        var reg = Assert.Single(report.ModuleRegressions);
        Assert.Equal("Declining", reg.Trend);
        Assert.True(reg.ConsecutiveDrops >= 3);
        Assert.Contains(report.Recommendations, r => r.Contains("Sustained module regression"));
    }

    [Fact]
    public void Analyze_ModuleSmallDropWithoutStreak_NotFlagged()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90, modules: new[] { ("Network", 90) }),
            Run(T0.AddHours(1), 90, modules: new[] { ("Network", 88) }), // drop=2, <5, no streak
        };

        var report = svc.Analyze(runs, days: 1);
        Assert.Empty(report.ModuleRegressions);
    }

    [Fact]
    public void Analyze_ModuleImprovement_NotFlagged()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90, modules: new[] { ("Backup", 60) }),
            Run(T0.AddHours(1), 90, modules: new[] { ("Backup", 95) }),
        };

        var report = svc.Analyze(runs, days: 1);
        Assert.Empty(report.ModuleRegressions);
    }

    [Fact]
    public void Analyze_ModuleMissingInPrevious_Ignored()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90, modules: new[] { ("Old", 80) }),
            Run(T0.AddHours(1), 90, modules: new[] { ("Old", 70), ("Brand New", 40) }),
        };

        var report = svc.Analyze(runs, days: 1);

        // "Brand New" has no previous score → not a regression. Only "Old" should appear.
        Assert.Single(report.ModuleRegressions);
        Assert.Equal("Old", report.ModuleRegressions[0].ModuleName);
    }

    [Fact]
    public void Analyze_NoModuleData_RegressionDetectorSilent()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90),
            Run(T0.AddHours(1), 92),
        };

        var report = svc.Analyze(runs, days: 1);
        Assert.Empty(report.ModuleRegressions);
    }

    [Fact]
    public void Analyze_OnlyOneRunHasModuleData_RegressionDetectorSilent()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90),                                       // no modules
            Run(T0.AddHours(1), 90, modules: new[] { ("Firewall", 80) }),  // only 1 run with modules
        };

        var report = svc.Analyze(runs, days: 1);
        Assert.Empty(report.ModuleRegressions);
    }

    // ── Recommendations & status ────────────────────────────────────

    [Fact]
    public void Analyze_NoAnomalies_EmitsStableRecommendation()
    {
        var svc = new AnomalyWatchdogService();
        // Perfectly stable: zero variance → no z-driven anomalies, no absolute drops.
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90, totalFindings: 3),
            Run(T0.AddHours(1), 90, totalFindings: 3),
            Run(T0.AddHours(2), 90, totalFindings: 3),
        };

        var report = svc.Analyze(runs, days: 1);
        Assert.Equal("OK", report.OverallStatus);
        Assert.Contains(report.Recommendations, r => r.Contains("No anomalies"));
    }

    [Fact]
    public void Analyze_LowLatestScore_EmitsFixAllRecommendation()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             45),
            Run(T0.AddHours(1), 40),
        };

        var report = svc.Analyze(runs, days: 1);
        Assert.Contains(report.Recommendations, r => r.Contains("below 50"));
    }

    [Fact]
    public void Analyze_ManyCriticalsInSpike_TriggersCriticalRemediationRecommendation()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90, totalFindings: 2, criticals: 0),
            Run(T0.AddHours(1), 90, totalFindings: 10, criticals: 5), // CriticalCount>3
        };

        var report = svc.Analyze(runs, days: 1);
        Assert.Contains(report.Recommendations, r => r.Contains("critical items"));
    }

    [Fact]
    public void Analyze_CollapsedModule_TriggersCollapsedRecommendation()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90, modules: new[] { ("Defender", 70) }),
            Run(T0.AddHours(1), 90, modules: new[] { ("Defender", 0)  }),
        };

        var report = svc.Analyze(runs, days: 1);
        Assert.Contains(report.Recommendations, r => r.Contains("collapsed"));
    }

    [Fact]
    public void Analyze_CriticalScoreDrop_TriggersScoreDropRecommendation()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             95),
            Run(T0.AddHours(1), 70), // drop=25, major
        };

        var report = svc.Analyze(runs, days: 1);
        Assert.Contains(report.Recommendations, r => r.Contains("Critical score drops"));
    }

    [Fact]
    public void Analyze_TotalAnomaliesAggregatesAllThreeCategories()
    {
        var svc = new AnomalyWatchdogService();
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             95, totalFindings: 2, criticals: 0,
                modules: new[] { ("Firewall", 90) }),
            Run(T0.AddHours(1), 70, totalFindings: 12, criticals: 4,        // score drop + finding spike
                modules: new[] { ("Firewall", 80) }),                       // + module regression
        };

        var report = svc.Analyze(runs, days: 1);

        Assert.True(report.ScoreAnomalies.Count >= 1);
        Assert.True(report.FindingSpikes.Count >= 1);
        Assert.True(report.ModuleRegressions.Count >= 1);
        Assert.Equal(
            report.ScoreAnomalies.Count + report.FindingSpikes.Count + report.ModuleRegressions.Count,
            report.TotalAnomalies);
        Assert.Equal("ALERT", report.OverallStatus);
    }

    // ── Config / threshold knobs ────────────────────────────────────

    [Fact]
    public void Analyze_CustomConfig_LowerThresholds_FlagSmallerChanges()
    {
        var cfg = new WatchdogConfig
        {
            MinorScoreDrop = 3,
            MajorScoreDrop = 6,
            FindingSpikeAbsolute = 1,
            ModuleScoreDrop = 1,
            ModuleVolatileStreak = 2,
        };
        var svc = new AnomalyWatchdogService(cfg);

        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90, totalFindings: 0,
                modules: new[] { ("Firewall", 90) }),
            Run(T0.AddHours(1), 87, totalFindings: 1,
                modules: new[] { ("Firewall", 89) }),  // small score drop & finding spike & module dip
        };

        var report = svc.Analyze(runs, days: 1);

        Assert.NotEmpty(report.ScoreAnomalies);
        Assert.NotEmpty(report.FindingSpikes);
        Assert.NotEmpty(report.ModuleRegressions);
    }

    [Fact]
    public void Analyze_LegacyConstructor_PreservesBehaviourWithCustomZThresholds()
    {
        // The two-arg constructor stays for backward compatibility; tighten z thresholds and confirm
        // a z-driven anomaly fires even when absolute drop is too small.
        var svc = new AnomalyWatchdogService(zThresholdWarn: 0.5, zThresholdCrit: 100); // never Critical via z
        var runs = new List<AuditRunRecord>
        {
            Run(T0,             90),
            Run(T0.AddHours(1), 91),
            Run(T0.AddHours(2), 90),
            Run(T0.AddHours(3), 88), // drop=2 vs prev, but z high enough to trigger Warning
        };

        var report = svc.Analyze(runs, days: 1);

        Assert.NotEmpty(report.ScoreAnomalies);
        Assert.All(report.ScoreAnomalies, a => Assert.Equal("Warning", a.Severity));
    }

    [Fact]
    public void Analyze_RecentModuleRunWindow_HonouredByConfig()
    {
        // Window=2 means only the last 2 runs with modules are considered;
        // an older streak should not influence consecutiveDrops.
        var cfg = new WatchdogConfig { RecentModuleRunWindow = 2 };
        var svc = new AnomalyWatchdogService(cfg);

        var runs = new List<AuditRunRecord>
        {
            Run(T0,                90, modules: new[] { ("Backup", 95) }),
            Run(T0.AddHours(1),    90, modules: new[] { ("Backup", 90) }),
            Run(T0.AddHours(2),    90, modules: new[] { ("Backup", 85) }),
            Run(T0.AddHours(3),    90, modules: new[] { ("Backup", 78) }), // drop=7 from 85
        };

        var report = svc.Analyze(runs, days: 1);

        var reg = Assert.Single(report.ModuleRegressions);
        // With window=2 the walk-back only inspects the one prior run, so
        // consecutive-drops caps at 1 (regardless of older runs in the input).
        Assert.Equal(1, reg.ConsecutiveDrops);
        Assert.Equal("Volatile", reg.Trend);
    }

    [Fact]
    public void Analyze_RunsAnalyzedReflectsInput()
    {
        var svc = new AnomalyWatchdogService();
        var runs = Enumerable.Range(0, 4)
            .Select(i => Run(T0.AddHours(i), 90))
            .ToList();
        var report = svc.Analyze(runs, days: 14);

        Assert.Equal(4, report.RunsAnalyzed);
        Assert.Equal(14, report.DaysAnalyzed);
    }
}
