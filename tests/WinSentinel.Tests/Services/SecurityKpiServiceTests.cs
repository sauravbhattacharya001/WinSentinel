using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

/// <summary>
/// Tests for SecurityKpiService — computes KPI metrics (MTTD, MTTR, recurrence,
/// security debt, health scoring, scan cadence, module trends) from audit history.
/// </summary>
public class SecurityKpiServiceTests
{
    private readonly SecurityKpiService _svc = new();

    // ─── Helper Methods ──────────────────────────────────────────

    private static AuditRunRecord MakeRun(
        DateTimeOffset timestamp,
        int score,
        int critical = 0,
        int warnings = 0,
        int info = 0,
        int pass = 0,
        List<FindingRecord>? findings = null,
        List<ModuleScoreRecord>? moduleScores = null)
    {
        var totalFindings = critical + warnings + info + pass;
        return new AuditRunRecord
        {
            Timestamp = timestamp,
            OverallScore = score,
            CriticalCount = critical,
            WarningCount = warnings,
            InfoCount = info,
            PassCount = pass,
            TotalFindings = totalFindings,
            Findings = findings ?? [],
            ModuleScores = moduleScores ?? [],
        };
    }

    private static FindingRecord MakeFinding(string module, string title, string severity = "Warning")
        => new() { ModuleName = module, Title = title, Severity = severity };

    private static ModuleScoreRecord MakeModuleScore(string name, int score)
        => new() { ModuleName = name, Score = score };

    private static DateTimeOffset Day(int offset)
        => new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero).AddDays(offset);

    // ─── Empty / Single-Run Input ────────────────────────────────

    [Fact]
    public void Compute_EmptyRuns_ReturnsDefaultReport()
    {
        var report = _svc.Compute([], 30);

        Assert.Equal(0, report.RunsAnalyzed);
        Assert.Equal(0, report.HealthScore);
        Assert.Equal(0, report.TotalScans);
    }

    [Fact]
    public void Compute_SingleRun_SetsBasicMetrics()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 80, critical: 1, warnings: 3, info: 2, pass: 10)
        };

        var report = _svc.Compute(runs, 30);

        Assert.Equal(1, report.RunsAnalyzed);
        Assert.Equal(80, report.CurrentScore);
        Assert.Equal(80, report.AverageScore);
        Assert.Equal(16, report.CurrentFindings);
        Assert.Equal(1, report.CurrentCritical);
        Assert.Equal(3, report.CurrentWarnings);
    }

    [Fact]
    public void Compute_SingleRun_ScoreChangeIsZero()
    {
        var runs = new List<AuditRunRecord> { MakeRun(Day(0), score: 75) };
        var report = _svc.Compute(runs, 30);

        Assert.Equal(0, report.ScoreChange);
        Assert.Equal("Stable", report.ScoreTrend);
    }

    [Fact]
    public void Compute_SingleRun_NoDaysBetweenScans()
    {
        var runs = new List<AuditRunRecord> { MakeRun(Day(0), score: 80) };
        var report = _svc.Compute(runs, 7);

        Assert.Equal(0, report.AvgDaysBetweenScans);
        Assert.Equal(0, report.MaxScanGap);
    }

    // ─── Score KPIs ──────────────────────────────────────────────

    [Fact]
    public void Compute_ImprovingScore_TrendIsImproving()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 50),
            MakeRun(Day(7), score: 65),
            MakeRun(Day(14), score: 80),
        };

        var report = _svc.Compute(runs, 14);

        Assert.Equal(30, report.ScoreChange); // 80 - 50
        Assert.Equal("Improving", report.ScoreTrend);
    }

    [Fact]
    public void Compute_DecliningScore_TrendIsDeclining()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 90),
            MakeRun(Day(7), score: 75),
            MakeRun(Day(14), score: 60),
        };

        var report = _svc.Compute(runs, 14);

        Assert.Equal(-30, report.ScoreChange);
        Assert.Equal("Declining", report.ScoreTrend);
    }

    [Fact]
    public void Compute_StableScore_TrendIsStable()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 80),
            MakeRun(Day(7), score: 82),
        };

        var report = _svc.Compute(runs, 7);

        Assert.Equal(2, report.ScoreChange);
        Assert.Equal("Stable", report.ScoreTrend);
    }

    [Fact]
    public void Compute_TwoRuns_CalculatesScoreVolatility()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 60),
            MakeRun(Day(7), score: 90),
        };

        var report = _svc.Compute(runs, 7);

        // Mean = 75, variance = ((60-75)^2 + (90-75)^2)/2 = 225, std = 15.0
        Assert.Equal(15.0, report.ScoreVolatility);
    }

    [Fact]
    public void Compute_IdenticalScores_VolatilityIsZero()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 80),
            MakeRun(Day(7), score: 80),
            MakeRun(Day(14), score: 80),
        };

        var report = _svc.Compute(runs, 14);

        Assert.Equal(0, report.ScoreVolatility);
    }

    [Fact]
    public void Compute_AverageScore_IsCorrect()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 60),
            MakeRun(Day(7), score: 80),
            MakeRun(Day(14), score: 100),
        };

        var report = _svc.Compute(runs, 14);

        Assert.Equal(80, report.AverageScore);
    }

    // ─── Finding KPIs ────────────────────────────────────────────

    [Fact]
    public void Compute_NewFindings_DetectedAfterFirstRun()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 80, findings: new List<FindingRecord>
            {
                MakeFinding("Firewall", "Firewall disabled"),
            }),
            MakeRun(Day(7), score: 70, findings: new List<FindingRecord>
            {
                MakeFinding("Firewall", "Firewall disabled"),
                MakeFinding("Accounts", "Stale admin account"), // new
            }),
        };

        var report = _svc.Compute(runs, 7);

        Assert.Equal(1, report.NewFindings);
    }

    [Fact]
    public void Compute_ResolvedFindings_PresentInEarlierButNotLast()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 60, findings: new List<FindingRecord>
            {
                MakeFinding("Firewall", "Firewall disabled"),
                MakeFinding("RDP", "RDP exposed"),
            }),
            MakeRun(Day(7), score: 80, findings: new List<FindingRecord>
            {
                MakeFinding("Firewall", "Firewall disabled"),
                // RDP exposed is now resolved
            }),
        };

        var report = _svc.Compute(runs, 7);

        Assert.Equal(1, report.ResolvedFindings);
    }

    [Fact]
    public void Compute_RecurringFindings_DetectedCorrectly()
    {
        // Finding appears in run 0, disappears in run 1, reappears in run 2
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 70, findings: new List<FindingRecord>
            {
                MakeFinding("Firewall", "Firewall disabled"),
            }),
            MakeRun(Day(7), score: 85, findings: new List<FindingRecord>()),
            MakeRun(Day(14), score: 70, findings: new List<FindingRecord>
            {
                MakeFinding("Firewall", "Firewall disabled"),
            }),
        };

        var report = _svc.Compute(runs, 14);

        Assert.Equal(1, report.RecurringFindings);
        Assert.True(report.RecurrenceRate > 0);
    }

    [Fact]
    public void Compute_NoRecurrence_RateIsZero()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 70, findings: new List<FindingRecord>
            {
                MakeFinding("Firewall", "Firewall disabled"),
            }),
            MakeRun(Day(7), score: 70, findings: new List<FindingRecord>
            {
                MakeFinding("Firewall", "Firewall disabled"),
            }),
        };

        var report = _svc.Compute(runs, 7);

        Assert.Equal(0, report.RecurringFindings);
        Assert.Equal(0, report.RecurrenceRate);
    }

    [Fact]
    public void Compute_FindingNetChange_TracksCorrectly()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 60, critical: 2, warnings: 3),
            MakeRun(Day(7), score: 80, critical: 0, warnings: 1),
        };

        var report = _svc.Compute(runs, 7);

        Assert.Equal(-4, report.FindingNetChange); // 1 - 5 = -4
    }

    [Fact]
    public void Compute_AverageFindingsPerScan_Calculated()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 60, critical: 2, warnings: 4), // 6
            MakeRun(Day(7), score: 80, critical: 0, warnings: 2), // 2
        };

        var report = _svc.Compute(runs, 7);

        Assert.Equal(4.0, report.AverageFindingsPerScan); // (6+2)/2
    }

    // ─── Severity KPIs ───────────────────────────────────────────

    [Fact]
    public void Compute_PeakCritical_IsMaxAcrossRuns()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 50, critical: 3),
            MakeRun(Day(7), score: 60, critical: 5),
            MakeRun(Day(14), score: 80, critical: 1),
        };

        var report = _svc.Compute(runs, 14);

        Assert.Equal(5, report.PeakCritical);
        Assert.Equal(1, report.CurrentCritical);
    }

    [Fact]
    public void Compute_AvgCriticalPerScan_Calculated()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 50, critical: 0),
            MakeRun(Day(7), score: 60, critical: 3),
            MakeRun(Day(14), score: 80, critical: 6),
        };

        var report = _svc.Compute(runs, 14);

        Assert.Equal(3.0, report.AvgCriticalPerScan); // (0+3+6)/3
    }

    // ─── MTTR (Mean Time to Remediate) ───────────────────────────

    [Fact]
    public void Compute_MTTR_CalculatedForResolvedCriticals()
    {
        // Critical finding appears in run 0 and 1, resolved by run 2
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 50, findings: new List<FindingRecord>
            {
                MakeFinding("Firewall", "Port exposed", "Critical"),
            }),
            MakeRun(Day(7), score: 60, findings: new List<FindingRecord>
            {
                MakeFinding("Firewall", "Port exposed", "Critical"),
            }),
            MakeRun(Day(14), score: 90, findings: new List<FindingRecord>()),
        };

        var report = _svc.Compute(runs, 14);

        Assert.NotNull(report.MeanTimeToRemediateCritical);
        Assert.True(report.MeanTimeToRemediateCritical > 0);
    }

    [Fact]
    public void Compute_MTTR_NullWhenNoResolvedFindings()
    {
        // Finding persists through all runs — never resolved
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 50, findings: new List<FindingRecord>
            {
                MakeFinding("Firewall", "Port exposed", "Critical"),
            }),
            MakeRun(Day(7), score: 55, findings: new List<FindingRecord>
            {
                MakeFinding("Firewall", "Port exposed", "Critical"),
            }),
        };

        var report = _svc.Compute(runs, 7);

        Assert.Null(report.MeanTimeToRemediateCritical);
    }

    [Fact]
    public void Compute_MTTR_CalculatedForWarnings()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 70, findings: new List<FindingRecord>
            {
                MakeFinding("Accounts", "Stale admin", "Warning"),
            }),
            MakeRun(Day(10), score: 90, findings: new List<FindingRecord>()),
        };

        var report = _svc.Compute(runs, 10);

        Assert.NotNull(report.MeanTimeToRemediateWarning);
    }

    // ─── Security Debt ───────────────────────────────────────────

    [Fact]
    public void Compute_SecurityDebt_WeightedBySeverity()
    {
        // Debt = criticals*10 + warnings*3 + info*0.5
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 50, critical: 2, warnings: 4, info: 6), // 20+12+3 = 35
        };

        var report = _svc.Compute(runs, 7);

        Assert.Equal(35.0, report.SecurityDebt);
    }

    [Fact]
    public void Compute_DebtDecreasing_TrendCorrect()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 50, critical: 5, warnings: 10, info: 10),  // 50+30+5 = 85
            MakeRun(Day(14), score: 90, critical: 0, warnings: 1, info: 2),   // 0+3+1 = 4
        };

        var report = _svc.Compute(runs, 14);

        Assert.Equal(4.0, report.SecurityDebt);
        Assert.True(report.DebtChange < 0);
        Assert.Equal("Decreasing", report.DebtTrend);
    }

    [Fact]
    public void Compute_DebtIncreasing_TrendCorrect()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 90, critical: 0, warnings: 1, info: 2),    // 0+3+1 = 4
            MakeRun(Day(14), score: 50, critical: 5, warnings: 10, info: 10), // 50+30+5 = 85
        };

        var report = _svc.Compute(runs, 14);

        Assert.Equal(85.0, report.SecurityDebt);
        Assert.True(report.DebtChange > 0);
        Assert.Equal("Increasing", report.DebtTrend);
    }

    [Fact]
    public void Compute_DebtStable_WhenSmallChange()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 80, critical: 1, warnings: 3, info: 4),   // 10+9+2 = 21
            MakeRun(Day(7), score: 82, critical: 1, warnings: 3, info: 2),   // 10+9+1 = 20
        };

        var report = _svc.Compute(runs, 7);

        Assert.Equal("Stable", report.DebtTrend);
    }

    // ─── Scan Cadence ────────────────────────────────────────────

    [Fact]
    public void Compute_ScanCadence_DailyScans()
    {
        var runs = Enumerable.Range(0, 7)
            .Select(i => MakeRun(Day(i), score: 80))
            .ToList();

        var report = _svc.Compute(runs, 7);

        Assert.Equal(1.0, report.AvgDaysBetweenScans);
        Assert.Equal(1.0, report.MaxScanGap);
        Assert.True(report.ScansPerWeek >= 7);
    }

    [Fact]
    public void Compute_ScanCadence_WeeklyScans()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 80),
            MakeRun(Day(7), score: 82),
            MakeRun(Day(14), score: 85),
        };

        var report = _svc.Compute(runs, 14);

        Assert.Equal(7.0, report.AvgDaysBetweenScans);
        Assert.Equal(7.0, report.MaxScanGap);
    }

    [Fact]
    public void Compute_MaxScanGap_DetectsLargestGap()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 80),
            MakeRun(Day(1), score: 82),
            MakeRun(Day(15), score: 85), // 14-day gap
        };

        var report = _svc.Compute(runs, 15);

        Assert.Equal(14.0, report.MaxScanGap);
    }

    [Fact]
    public void Compute_ScansPerWeek_CalculatedFromSpan()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 80),
            MakeRun(Day(14), score: 85),
        };

        var report = _svc.Compute(runs, 14);

        // 2 scans over 14 days = 1.0 scan/week
        Assert.Equal(1.0, report.ScansPerWeek);
    }

    // ─── Module KPIs ─────────────────────────────────────────────

    [Fact]
    public void Compute_WeakestModule_IdentifiedCorrectly()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 70, moduleScores: new List<ModuleScoreRecord>
            {
                MakeModuleScore("Firewall", 90),
                MakeModuleScore("Accounts", 40),
                MakeModuleScore("Defender", 80),
            }),
        };

        var report = _svc.Compute(runs, 7);

        Assert.Equal("Accounts", report.WeakestModule);
        Assert.Equal(40, report.WeakestModuleScore);
    }

    [Fact]
    public void Compute_MostImprovedModule_TrackedOverTime()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 60, moduleScores: new List<ModuleScoreRecord>
            {
                MakeModuleScore("Firewall", 50),
                MakeModuleScore("Accounts", 70),
                MakeModuleScore("Defender", 60),
            }),
            MakeRun(Day(14), score: 85, moduleScores: new List<ModuleScoreRecord>
            {
                MakeModuleScore("Firewall", 90), // +40
                MakeModuleScore("Accounts", 75), // +5
                MakeModuleScore("Defender", 80), // +20
            }),
        };

        var report = _svc.Compute(runs, 14);

        Assert.Equal("Firewall", report.MostImprovedModule);
        Assert.Equal(40, report.MostImprovedChange);
    }

    [Fact]
    public void Compute_MostRegressedModule_TrackedOverTime()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 80, moduleScores: new List<ModuleScoreRecord>
            {
                MakeModuleScore("Firewall", 90),
                MakeModuleScore("Accounts", 80),
                MakeModuleScore("Defender", 70),
            }),
            MakeRun(Day(14), score: 60, moduleScores: new List<ModuleScoreRecord>
            {
                MakeModuleScore("Firewall", 85),  // -5
                MakeModuleScore("Accounts", 50),  // -30
                MakeModuleScore("Defender", 65),   // -5
            }),
        };

        var report = _svc.Compute(runs, 14);

        Assert.Equal("Accounts", report.MostRegressedModule);
        Assert.Equal(-30, report.MostRegressedChange);
    }

    [Fact]
    public void Compute_NoModuleScores_WeakestIsNull()
    {
        var runs = new List<AuditRunRecord> { MakeRun(Day(0), score: 80) };

        var report = _svc.Compute(runs, 7);

        Assert.Null(report.WeakestModule);
        Assert.Null(report.WeakestModuleScore);
    }

    [Fact]
    public void Compute_SingleRunWithModules_NoImprovement()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 70, moduleScores: new List<ModuleScoreRecord>
            {
                MakeModuleScore("Firewall", 90),
                MakeModuleScore("Accounts", 40),
            }),
        };

        var report = _svc.Compute(runs, 7);

        Assert.Null(report.MostImprovedModule);
        Assert.Null(report.MostRegressedModule);
    }

    // ─── Health Score ────────────────────────────────────────────

    [Fact]
    public void Compute_HighHealth_ExcellentRating()
    {
        // High score, improving, no criticals, low recurrence, frequent scans
        var runs = Enumerable.Range(0, 14)
            .Select(i => MakeRun(Day(i), score: 90 + (i > 7 ? 5 : 0)))
            .ToList();

        var report = _svc.Compute(runs, 14);

        Assert.True(report.HealthScore >= 85);
        Assert.Contains(report.HealthRating, new[] { "Excellent", "Good" });
    }

    [Fact]
    public void Compute_LowHealth_PoorOrCriticalRating()
    {
        // Low score, declining, high criticals, infrequent scans
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 40, critical: 5, warnings: 10),
            MakeRun(Day(30), score: 25, critical: 8, warnings: 15),
        };

        var report = _svc.Compute(runs, 30);

        Assert.True(report.HealthScore < 50);
        Assert.Contains(report.HealthRating, new[] { "Poor", "Critical" });
    }

    [Fact]
    public void Compute_HealthScore_ClampedTo0And100()
    {
        // Even extreme values shouldn't exceed bounds
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 0, critical: 20, warnings: 50),
        };

        var report = _svc.Compute(runs, 1);

        Assert.InRange(report.HealthScore, 0, 100);
    }

    [Fact]
    public void Compute_HealthRating_ExcellentAt90Plus()
    {
        // Perfect scenario: high score, improving, no criticals, daily scans
        var runs = Enumerable.Range(0, 14)
            .Select(i => MakeRun(Day(i), score: 95))
            .ToList();

        var report = _svc.Compute(runs, 14);

        Assert.True(report.HealthScore >= 90);
        Assert.Equal("Excellent", report.HealthRating);
    }

    // ─── Recommendations ─────────────────────────────────────────

    [Fact]
    public void Compute_CriticalFindings_GeneratesRecommendation()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 50, critical: 3),
        };

        var report = _svc.Compute(runs, 7);

        Assert.Contains(report.Recommendations,
            r => r.Contains("critical", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Compute_HighRecurrence_GeneratesRecommendation()
    {
        // Create a scenario with high recurrence
        var finding = MakeFinding("Firewall", "Firewall disabled");
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 70, findings: new List<FindingRecord> { finding }),
            MakeRun(Day(1), score: 85, findings: new List<FindingRecord>()),
            MakeRun(Day(2), score: 70, findings: new List<FindingRecord> { finding }),
            MakeRun(Day(3), score: 85, findings: new List<FindingRecord>()),
            MakeRun(Day(4), score: 70, findings: new List<FindingRecord> { finding }),
        };

        var report = _svc.Compute(runs, 4);

        // Recurrence rate = 100% (1 finding, 1 recurring) > 20%
        Assert.Contains(report.Recommendations,
            r => r.Contains("recurrence", StringComparison.OrdinalIgnoreCase) ||
                 r.Contains("recurring", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Compute_LowScanCadence_GeneratesRecommendation()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 80),
            MakeRun(Day(30), score: 82),
        };

        var report = _svc.Compute(runs, 30);

        // 2 scans over 30 days < 1/week
        Assert.Contains(report.Recommendations,
            r => r.Contains("cadence", StringComparison.OrdinalIgnoreCase) ||
                 r.Contains("scan", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Compute_HighVolatility_GeneratesRecommendation()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 30),
            MakeRun(Day(1), score: 90),
            MakeRun(Day(2), score: 30),
            MakeRun(Day(3), score: 90),
        };

        var report = _svc.Compute(runs, 3);

        Assert.True(report.ScoreVolatility > 10);
        Assert.Contains(report.Recommendations,
            r => r.Contains("volatility", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Compute_LongCriticalMTTR_GeneratesRecommendation()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 50, findings: new List<FindingRecord>
            {
                MakeFinding("Firewall", "Critical gap", "Critical"),
            }),
            MakeRun(Day(10), score: 55, findings: new List<FindingRecord>
            {
                MakeFinding("Firewall", "Critical gap", "Critical"),
            }),
            MakeRun(Day(20), score: 90, findings: new List<FindingRecord>()),
        };

        var report = _svc.Compute(runs, 20);

        if (report.MeanTimeToRemediateCritical > 7)
        {
            Assert.Contains(report.Recommendations,
                r => r.Contains("MTTR", StringComparison.OrdinalIgnoreCase) ||
                     r.Contains("remediate", StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public void Compute_IncreasingDebt_GeneratesRecommendation()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 90, critical: 0, warnings: 1, info: 2),
            MakeRun(Day(14), score: 50, critical: 5, warnings: 10, info: 10),
        };

        var report = _svc.Compute(runs, 14);

        Assert.Equal("Increasing", report.DebtTrend);
        Assert.Contains(report.Recommendations,
            r => r.Contains("debt", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Compute_WeakModule_GeneratesRecommendation()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 60, moduleScores: new List<ModuleScoreRecord>
            {
                MakeModuleScore("Firewall", 30),
                MakeModuleScore("Defender", 90),
            }),
        };

        var report = _svc.Compute(runs, 7);

        Assert.Contains(report.Recommendations,
            r => r.Contains("Firewall", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Compute_HealthyPosture_DefaultRecommendation()
    {
        // Scenario with no issues: good score, no criticals, frequent scans, low recurrence
        var runs = Enumerable.Range(0, 14)
            .Select(i => MakeRun(Day(i), score: 95,
                moduleScores: new List<ModuleScoreRecord>
                {
                    MakeModuleScore("Firewall", 95),
                    MakeModuleScore("Defender", 98),
                }))
            .ToList();

        var report = _svc.Compute(runs, 14);

        Assert.Contains(report.Recommendations,
            r => r.Contains("healthy", StringComparison.OrdinalIgnoreCase) ||
                 r.Contains("maintain", StringComparison.OrdinalIgnoreCase));
    }

    // ─── Period Metadata ─────────────────────────────────────────

    [Fact]
    public void Compute_PeriodStartEnd_MatchFirstLastRun()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 60),
            MakeRun(Day(7), score: 70),
            MakeRun(Day(14), score: 80),
        };

        var report = _svc.Compute(runs, 14);

        Assert.Equal(Day(0), report.PeriodStart);
        Assert.Equal(Day(14), report.PeriodEnd);
    }

    [Fact]
    public void Compute_DaysSpan_AtLeastOne()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 80),
            MakeRun(Day(0).AddHours(1), score: 82),
        };

        var report = _svc.Compute(runs, 1);

        Assert.True(report.DaysSpan >= 1);
    }

    [Fact]
    public void Compute_TotalScans_EqualsRunCount()
    {
        var runs = Enumerable.Range(0, 5)
            .Select(i => MakeRun(Day(i), score: 80))
            .ToList();

        var report = _svc.Compute(runs, 5);

        Assert.Equal(5, report.TotalScans);
    }

    // ─── Ordering Robustness ─────────────────────────────────────

    [Fact]
    public void Compute_UnorderedRuns_SortedCorrectly()
    {
        // Pass runs out of order — service should sort them ascending
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(14), score: 90),
            MakeRun(Day(0), score: 50),
            MakeRun(Day(7), score: 70),
        };

        var report = _svc.Compute(runs, 14);

        Assert.Equal(90, report.CurrentScore); // Last run score
        Assert.Equal(40, report.ScoreChange);  // 90 - 50
        Assert.Equal("Improving", report.ScoreTrend);
    }

    // ─── Edge Cases ──────────────────────────────────────────────

    [Fact]
    public void Compute_AllZeroScores_HandledGracefully()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 0, critical: 10, warnings: 20),
            MakeRun(Day(7), score: 0, critical: 12, warnings: 25),
        };

        var report = _svc.Compute(runs, 7);

        Assert.Equal(0, report.CurrentScore);
        Assert.Equal(0, report.AverageScore);
        Assert.Equal("Stable", report.ScoreTrend);
        Assert.InRange(report.HealthScore, 0, 100);
    }

    [Fact]
    public void Compute_PerfectScores_HighHealth()
    {
        var runs = Enumerable.Range(0, 7)
            .Select(i => MakeRun(Day(i), score: 100))
            .ToList();

        var report = _svc.Compute(runs, 7);

        Assert.Equal(100, report.CurrentScore);
        Assert.True(report.HealthScore >= 80);
    }

    [Fact]
    public void Compute_ManyFindings_AllTracked()
    {
        var findings = Enumerable.Range(1, 20)
            .Select(i => MakeFinding("Module" + i, "Finding" + i))
            .ToList();

        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 30, findings: findings),
            MakeRun(Day(7), score: 40, findings: findings.Take(10).ToList()),
        };

        var report = _svc.Compute(runs, 7);

        Assert.Equal(10, report.ResolvedFindings); // 10 findings dropped
    }

    [Fact]
    public void Compute_MultipleRecurring_CountedSeparately()
    {
        var f1 = MakeFinding("Mod1", "Finding1");
        var f2 = MakeFinding("Mod2", "Finding2");

        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 60, findings: new List<FindingRecord> { f1, f2 }),
            MakeRun(Day(1), score: 80, findings: new List<FindingRecord>()),
            MakeRun(Day(2), score: 60, findings: new List<FindingRecord> { f1, f2 }),
        };

        var report = _svc.Compute(runs, 2);

        Assert.Equal(2, report.RecurringFindings);
        Assert.Equal(100.0, report.RecurrenceRate); // Both recurring out of 2 total
    }

    [Fact]
    public void Compute_LargeDataset_PerformsReasonably()
    {
        // 365 daily runs over a year
        var runs = Enumerable.Range(0, 365)
            .Select(i => MakeRun(Day(i), score: 60 + (i % 30),
                critical: Math.Max(0, 3 - i / 100),
                warnings: 5,
                findings: new List<FindingRecord>
                {
                    MakeFinding("Firewall", "Issue" + (i % 5)),
                }))
            .ToList();

        var report = _svc.Compute(runs, 365);

        Assert.Equal(365, report.RunsAnalyzed);
        Assert.InRange(report.HealthScore, 0, 100);
        Assert.NotEmpty(report.Recommendations);
    }

    [Fact]
    public void Compute_NewModulesAppearLater_WeakestUsesLatestRun()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), score: 70, moduleScores: new List<ModuleScoreRecord>
            {
                MakeModuleScore("Firewall", 80),
            }),
            MakeRun(Day(7), score: 65, moduleScores: new List<ModuleScoreRecord>
            {
                MakeModuleScore("Firewall", 80),
                MakeModuleScore("NewModule", 30), // New, weak module
            }),
        };

        var report = _svc.Compute(runs, 7);

        Assert.Equal("NewModule", report.WeakestModule);
        Assert.Equal(30, report.WeakestModuleScore);
    }
}
