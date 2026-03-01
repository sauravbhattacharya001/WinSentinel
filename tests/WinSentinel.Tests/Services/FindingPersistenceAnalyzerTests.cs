using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests.Services;

public class FindingPersistenceAnalyzerTests
{
    private readonly FindingPersistenceAnalyzer _analyzer = new();

    // ── Helper methods ───────────────────────────────────────────────

    private static AuditRunRecord MakeRun(
        DateTimeOffset timestamp,
        params (string module, string title, string severity)[] findings)
    {
        return new AuditRunRecord
        {
            Id = timestamp.ToUnixTimeSeconds(),
            Timestamp = timestamp,
            OverallScore = 80,
            Grade = "B",
            TotalFindings = findings.Length,
            Findings = findings.Select(f => new FindingRecord
            {
                ModuleName = f.module,
                Title = f.title,
                Severity = f.severity,
                Description = $"Description for {f.title}"
            }).ToList()
        };
    }

    private static DateTimeOffset Day(int day) =>
        new(2026, 1, day, 12, 0, 0, TimeSpan.Zero);

    // ── Insufficient data ────────────────────────────────────────────

    [Fact]
    public void Analyze_NullRuns_ThrowsArgumentNull()
    {
        Assert.Throws<ArgumentNullException>(() => _analyzer.Analyze(null!));
    }

    [Fact]
    public void Analyze_EmptyRuns_ReturnInsufficientData()
    {
        var report = _analyzer.Analyze([]);
        Assert.False(report.HasSufficientData);
        Assert.Equal(0, report.TotalRunsAnalyzed);
        Assert.NotNull(report.Message);
    }

    [Fact]
    public void Analyze_SingleRun_ReturnInsufficientData()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(1), ("Firewall", "Firewall Disabled", "Critical"))
        };
        var report = _analyzer.Analyze(runs);
        Assert.False(report.HasSufficientData);
        Assert.Equal(1, report.TotalRunsAnalyzed);
    }

    // ── Chronic classification ───────────────────────────────────────

    [Fact]
    public void Analyze_FindingInAllRuns_ClassifiedAsChronic()
    {
        var runs = Enumerable.Range(1, 10).Select(d =>
            MakeRun(Day(d), ("Firewall", "Firewall Disabled", "Critical"))
        ).ToList();

        var report = _analyzer.Analyze(runs);

        Assert.True(report.HasSufficientData);
        Assert.Equal(10, report.TotalRunsAnalyzed);
        Assert.Single(report.Entries);
        Assert.Equal(PersistenceClass.Chronic, report.Entries[0].Classification);
        Assert.Equal(10, report.Entries[0].AppearanceCount);
        Assert.Equal(1.0, report.Entries[0].PresenceRatio);
        Assert.True(report.Entries[0].PresentInLatest);
        Assert.Equal(10, report.Entries[0].ConsecutiveFromLatest);
    }

    [Fact]
    public void Analyze_FindingIn90PercentOfRuns_ClassifiedAsChronic()
    {
        // 9 out of 10 runs have the finding (90%)
        var runs = new List<AuditRunRecord>();
        for (int d = 1; d <= 10; d++)
        {
            runs.Add(d == 5
                ? MakeRun(Day(d)) // Missing in run 5
                : MakeRun(Day(d), ("Defender", "Defender Off", "Warning")));
        }

        var report = _analyzer.Analyze(runs);
        var entry = Assert.Single(report.Entries);
        Assert.Equal(PersistenceClass.Chronic, entry.Classification);
        Assert.Equal(9, entry.AppearanceCount);
        Assert.Equal(0.9, entry.PresenceRatio);
    }

    [Fact]
    public void Analyze_ChronicCount()
    {
        var runs = Enumerable.Range(1, 5).Select(d =>
            MakeRun(Day(d),
                ("Firewall", "Firewall Disabled", "Critical"),
                ("Defender", "Defender Off", "Warning"))
        ).ToList();

        var report = _analyzer.Analyze(runs);
        Assert.Equal(2, report.ChronicCount);
        Assert.Equal(0, report.RecurringCount);
        Assert.Equal(0, report.TransientCount);
        Assert.Equal(0, report.ResolvedCount);
    }

    // ── Recurring classification ─────────────────────────────────────

    [Fact]
    public void Analyze_FindingIn50PercentOfRuns_ClassifiedAsRecurring()
    {
        var runs = new List<AuditRunRecord>();
        for (int d = 1; d <= 10; d++)
        {
            runs.Add(d % 2 == 0
                ? MakeRun(Day(d), ("Network", "Open Port", "Warning"))
                : MakeRun(Day(d)));
        }

        var report = _analyzer.Analyze(runs);
        var entry = Assert.Single(report.Entries);
        Assert.Equal(PersistenceClass.Recurring, entry.Classification);
        Assert.Equal(5, entry.AppearanceCount);
        Assert.Equal(0.5, entry.PresenceRatio);
    }

    [Fact]
    public void Analyze_FindingIn30PercentOfRuns_ClassifiedAsRecurring()
    {
        var runs = new List<AuditRunRecord>();
        for (int d = 1; d <= 10; d++)
        {
            runs.Add(d <= 3
                ? MakeRun(Day(d), ("System", "Weak Config", "Warning"))
                : MakeRun(Day(d)));
        }
        // Present in 3/10 = 30%, but not in latest → Resolved
        // To test Recurring, keep it in latest too
        runs[9] = MakeRun(Day(10), ("System", "Weak Config", "Warning"));
        // Now 4/10 = 40%, present in latest

        var report = _analyzer.Analyze(runs);
        var entry = Assert.Single(report.Entries);
        Assert.Equal(PersistenceClass.Recurring, entry.Classification);
    }

    [Fact]
    public void Analyze_RecurringCount()
    {
        // Two findings each appearing 5/10 times, interleaved
        var runs = new List<AuditRunRecord>();
        for (int d = 1; d <= 10; d++)
        {
            var findings = new List<(string, string, string)>();
            if (d % 2 == 0) findings.Add(("A", "FindingA", "Warning"));
            if (d % 2 == 1) findings.Add(("B", "FindingB", "Warning"));
            runs.Add(MakeRun(Day(d), findings.ToArray()));
        }

        var report = _analyzer.Analyze(runs);
        Assert.Equal(0, report.ChronicCount);
        // FindingA: 5/10 present in latest (d=10) → Recurring
        // FindingB: 5/10 NOT present in latest → Resolved
        Assert.Equal(1, report.RecurringCount);
        Assert.Equal(1, report.ResolvedCount);
    }

    // ── Transient classification ─────────────────────────────────────

    [Fact]
    public void Analyze_FindingInOneOfManyRuns_ClassifiedAsTransient()
    {
        var runs = new List<AuditRunRecord>();
        for (int d = 1; d <= 10; d++)
        {
            runs.Add(d == 10
                ? MakeRun(Day(d), ("Process", "Suspicious Process", "Warning"))
                : MakeRun(Day(d)));
        }

        var report = _analyzer.Analyze(runs);
        var entry = Assert.Single(report.Entries);
        Assert.Equal(PersistenceClass.Transient, entry.Classification);
        Assert.Equal(1, entry.AppearanceCount);
        Assert.Equal(0.1, entry.PresenceRatio);
    }

    [Fact]
    public void Analyze_TransientCount()
    {
        // 2 findings each appearing once, both in latest
        var runs = Enumerable.Range(1, 10).Select(d =>
        {
            if (d == 10) return MakeRun(Day(d),
                ("A", "FindA", "Info"), ("B", "FindB", "Info"));
            return MakeRun(Day(d));
        }).ToList();

        var report = _analyzer.Analyze(runs);
        Assert.Equal(2, report.TransientCount);
    }

    // ── Resolved classification ──────────────────────────────────────

    [Fact]
    public void Analyze_FindingNotInLatestRun_ClassifiedAsResolved()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(1), ("Firewall", "Firewall Disabled", "Critical")),
            MakeRun(Day(2), ("Firewall", "Firewall Disabled", "Critical")),
            MakeRun(Day(3)) // Fixed!
        };

        var report = _analyzer.Analyze(runs);
        var entry = Assert.Single(report.Entries);
        Assert.Equal(PersistenceClass.Resolved, entry.Classification);
        Assert.False(entry.PresentInLatest);
        Assert.Equal(0, entry.ConsecutiveFromLatest);
    }

    [Fact]
    public void Analyze_ResolvedEvenIfWasHighPresence()
    {
        // Present in 9/10 runs but not the last one → Resolved
        var runs = new List<AuditRunRecord>();
        for (int d = 1; d <= 10; d++)
        {
            runs.Add(d < 10
                ? MakeRun(Day(d), ("Defender", "Defender Off", "Critical"))
                : MakeRun(Day(d)));
        }

        var report = _analyzer.Analyze(runs);
        var entry = Assert.Single(report.Entries);
        Assert.Equal(PersistenceClass.Resolved, entry.Classification);
        Assert.Equal(9, entry.AppearanceCount);
    }

    // ── Consecutive count ────────────────────────────────────────────

    [Fact]
    public void Analyze_ConsecutiveFromLatest_Correct()
    {
        // Gap in the middle, then present for last 3 runs
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(1), ("A", "Finding", "Warning")),
            MakeRun(Day(2)), // gap
            MakeRun(Day(3), ("A", "Finding", "Warning")),
            MakeRun(Day(4), ("A", "Finding", "Warning")),
            MakeRun(Day(5), ("A", "Finding", "Warning")),
        };

        var report = _analyzer.Analyze(runs);
        var entry = Assert.Single(report.Entries);
        Assert.Equal(3, entry.ConsecutiveFromLatest);
        Assert.Equal(4, entry.AppearanceCount);
    }

    [Fact]
    public void Analyze_ConsecutiveFromLatest_AllRuns()
    {
        var runs = Enumerable.Range(1, 5).Select(d =>
            MakeRun(Day(d), ("A", "F", "Warning"))
        ).ToList();

        var report = _analyzer.Analyze(runs);
        Assert.Equal(5, report.Entries[0].ConsecutiveFromLatest);
    }

    // ── First/last seen timestamps ───────────────────────────────────

    [Fact]
    public void Analyze_FirstAndLastSeen_Correct()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(1)),
            MakeRun(Day(3), ("A", "Finding", "Warning")),
            MakeRun(Day(5), ("A", "Finding", "Warning")),
            MakeRun(Day(7)),
        };

        var report = _analyzer.Analyze(runs);
        var entry = Assert.Single(report.Entries);
        Assert.Equal(Day(3), entry.FirstSeen);
        Assert.Equal(Day(5), entry.LastSeen);
    }

    // ── Multiple findings ────────────────────────────────────────────

    [Fact]
    public void Analyze_MixedClassifications()
    {
        // 10 runs:
        // FindingA: all 10 → Chronic
        // FindingB: 5/10, present in latest → Recurring
        // FindingC: 1/10, in latest → Transient
        // FindingD: 5/10, NOT in latest → Resolved
        var runs = new List<AuditRunRecord>();
        for (int d = 1; d <= 10; d++)
        {
            var findings = new List<(string, string, string)>
            {
                ("Mod", "FindingA", "Critical")
            };
            if (d % 2 == 0) findings.Add(("Mod", "FindingB", "Warning"));
            if (d == 10) findings.Add(("Mod", "FindingC", "Info"));
            if (d % 2 == 1 && d < 10) findings.Add(("Mod", "FindingD", "Warning"));

            runs.Add(MakeRun(Day(d), findings.ToArray()));
        }

        var report = _analyzer.Analyze(runs);
        Assert.Equal(10, report.TotalRunsAnalyzed);
        Assert.Equal(4, report.TotalUniqueFindings);
        Assert.Equal(1, report.ChronicCount);
        Assert.Equal(1, report.RecurringCount);
        Assert.Equal(1, report.TransientCount);
        Assert.Equal(1, report.ResolvedCount);
    }

    [Fact]
    public void Analyze_SortOrder_ChronicFirst_ThenBySeverity()
    {
        // Chronic critical, Chronic warning, Recurring critical
        var runs = new List<AuditRunRecord>();
        for (int d = 1; d <= 5; d++)
        {
            var findings = new List<(string, string, string)>
            {
                ("A", "ChronicCrit", "Critical"),
                ("B", "ChronicWarn", "Warning"),
            };
            if (d % 2 == 0) findings.Add(("C", "RecurCrit", "Critical"));
            runs.Add(MakeRun(Day(d), findings.ToArray()));
        }
        // RecurCrit in 2/5 = 40%, present in latest? d=5 is odd, so no → Resolved
        // Let's adjust: make RecurCrit present in latest
        runs[4] = MakeRun(Day(5),
            ("A", "ChronicCrit", "Critical"),
            ("B", "ChronicWarn", "Warning"),
            ("C", "RecurCrit", "Critical"));

        var report = _analyzer.Analyze(runs);
        // ChronicCrit: 5/5 = Chronic
        // ChronicWarn: 5/5 = Chronic
        // RecurCrit: 3/5 = 60% → Recurring, present in latest
        Assert.Equal(PersistenceClass.Chronic, report.Entries[0].Classification);
        Assert.Equal("Critical", report.Entries[0].Severity.ToString());
        Assert.Equal(PersistenceClass.Chronic, report.Entries[1].Classification);
        Assert.Equal("Warning", report.Entries[1].Severity.ToString());
        Assert.Equal(PersistenceClass.Recurring, report.Entries[2].Classification);
    }

    // ── Custom thresholds ────────────────────────────────────────────

    [Fact]
    public void Analyze_CustomChronicThreshold()
    {
        var analyzer = new FindingPersistenceAnalyzer { ChronicThreshold = 0.5 };

        var runs = new List<AuditRunRecord>();
        for (int d = 1; d <= 10; d++)
        {
            runs.Add(d <= 5
                ? MakeRun(Day(d), ("A", "Finding", "Warning"))
                : MakeRun(Day(d), ("A", "Finding", "Warning"))); // All 10
        }

        // With 50% threshold, all-runs finding is definitely chronic
        var report = analyzer.Analyze(runs);
        Assert.Equal(PersistenceClass.Chronic, report.Entries[0].Classification);
        Assert.Equal(0.5, report.ChronicThresholdUsed);
    }

    [Fact]
    public void Analyze_CustomRecurringThreshold()
    {
        var analyzer = new FindingPersistenceAnalyzer
        {
            ChronicThreshold = 0.9,
            RecurringThreshold = 0.1
        };

        // Finding in 2/10 = 20%, present in latest
        var runs = new List<AuditRunRecord>();
        for (int d = 1; d <= 10; d++)
        {
            runs.Add(d >= 9
                ? MakeRun(Day(d), ("A", "Finding", "Warning"))
                : MakeRun(Day(d)));
        }

        var report = analyzer.Analyze(runs);
        Assert.Equal(PersistenceClass.Recurring, report.Entries[0].Classification);
        Assert.Equal(0.1, report.RecurringThresholdUsed);
    }

    // ── Case insensitivity ───────────────────────────────────────────

    [Fact]
    public void Analyze_FindingKeysAreCaseInsensitive()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(1), ("Firewall", "Open Port", "Warning")),
            MakeRun(Day(2), ("FIREWALL", "OPEN PORT", "Warning")),
            MakeRun(Day(3), ("firewall", "open port", "Warning")),
        };

        var report = _analyzer.Analyze(runs);
        Assert.Single(report.Entries);
        Assert.Equal(3, report.Entries[0].AppearanceCount);
    }

    // ── Duplicate findings in same run ───────────────────────────────

    [Fact]
    public void Analyze_DuplicatesInSameRun_CountedOnce()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(1),
                ("A", "Same Finding", "Warning"),
                ("A", "Same Finding", "Warning")),
            MakeRun(Day(2), ("A", "Same Finding", "Warning")),
        };

        var report = _analyzer.Analyze(runs);
        Assert.Single(report.Entries);
        Assert.Equal(2, report.Entries[0].AppearanceCount); // Once per run, not twice
    }

    // ── Analysis window ──────────────────────────────────────────────

    [Fact]
    public void Analyze_AnalysisWindow_Correct()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(1)),
            MakeRun(Day(15)),
        };

        var report = _analyzer.Analyze(runs);
        Assert.Equal(14, report.AnalysisWindow.Days);
        Assert.Equal(Day(1), report.FirstRunDate);
        Assert.Equal(Day(15), report.LastRunDate);
    }

    [Fact]
    public void Analyze_UnsortedRuns_SortedInternally()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(5), ("A", "Finding", "Warning")),
            MakeRun(Day(1)),
            MakeRun(Day(3), ("A", "Finding", "Warning")),
        };

        var report = _analyzer.Analyze(runs);
        Assert.Equal(Day(1), report.FirstRunDate);
        Assert.Equal(Day(5), report.LastRunDate);
        Assert.True(report.Entries[0].PresentInLatest); // Day 5 is latest
    }

    // ── Empty findings ───────────────────────────────────────────────

    [Fact]
    public void Analyze_AllRunsEmpty_IsClean()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(1)),
            MakeRun(Day(2)),
            MakeRun(Day(3)),
        };

        var report = _analyzer.Analyze(runs);
        Assert.True(report.HasSufficientData);
        Assert.True(report.IsClean);
        Assert.Equal(0, report.TotalUniqueFindings);
        Assert.Empty(report.Entries);
    }

    // ── Severity tracking ────────────────────────────────────────────

    [Fact]
    public void Analyze_SeverityParsedCorrectly()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(1),
                ("A", "Crit", "Critical"),
                ("B", "Warn", "Warning"),
                ("C", "Inf", "Info"),
                ("D", "Ps", "Pass")),
            MakeRun(Day(2),
                ("A", "Crit", "Critical"),
                ("B", "Warn", "Warning"),
                ("C", "Inf", "Info"),
                ("D", "Ps", "Pass")),
        };

        var report = _analyzer.Analyze(runs);
        Assert.Equal(4, report.Entries.Count);
        Assert.Contains(report.Entries, e => e.Severity == Severity.Critical);
        Assert.Contains(report.Entries, e => e.Severity == Severity.Warning);
        Assert.Contains(report.Entries, e => e.Severity == Severity.Info);
        Assert.Contains(report.Entries, e => e.Severity == Severity.Pass);
    }

    [Fact]
    public void Analyze_UnknownSeverity_DefaultsToInfo()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(1), ("A", "F", "Unknown")),
            MakeRun(Day(2), ("A", "F", "Unknown")),
        };

        var report = _analyzer.Analyze(runs);
        Assert.Equal(Severity.Info, report.Entries[0].Severity);
    }

    // ── Classification labels ────────────────────────────────────────

    [Fact]
    public void PersistenceEntry_ClassificationLabel()
    {
        Assert.Equal("● Chronic", new PersistenceEntry
            { Classification = PersistenceClass.Chronic }.ClassificationLabel);
        Assert.Equal("◐ Recurring", new PersistenceEntry
            { Classification = PersistenceClass.Recurring }.ClassificationLabel);
        Assert.Equal("○ Transient", new PersistenceEntry
            { Classification = PersistenceClass.Transient }.ClassificationLabel);
        Assert.Equal("✓ Resolved", new PersistenceEntry
            { Classification = PersistenceClass.Resolved }.ClassificationLabel);
    }

    // ── FormatSummary ────────────────────────────────────────────────

    [Fact]
    public void FormatSummary_InsufficientData()
    {
        var report = new PersistenceReport
        {
            HasSufficientData = false,
            Message = "Need more runs."
        };
        var text = FindingPersistenceAnalyzer.FormatSummary(report);
        Assert.Equal("Need more runs.", text);
    }

    [Fact]
    public void FormatSummary_WithData_ContainsKeySections()
    {
        // Build a small report
        var runs = Enumerable.Range(1, 5).Select(d =>
            MakeRun(Day(d), ("Firewall", "Firewall Disabled", "Critical"))
        ).ToList();
        // Add a resolved finding in early runs
        runs[0] = MakeRun(Day(1),
            ("Firewall", "Firewall Disabled", "Critical"),
            ("Update", "Updates Pending", "Warning"));

        var report = _analyzer.Analyze(runs);
        var summary = FindingPersistenceAnalyzer.FormatSummary(report);

        Assert.Contains("FINDING PERSISTENCE ANALYSIS", summary);
        Assert.Contains("Chronic", summary);
        Assert.Contains("Firewall Disabled", summary);
        Assert.Contains("RECENTLY RESOLVED", summary);
    }

    [Fact]
    public void FormatSummary_NoMessage_DefaultFallback()
    {
        var report = new PersistenceReport { HasSufficientData = false };
        var text = FindingPersistenceAnalyzer.FormatSummary(report);
        Assert.Contains("Insufficient data", text);
    }

    // ── MaxRunsToAnalyze cap ─────────────────────────────────────────

    [Fact]
    public void Analyze_MoreThanMaxRuns_TakesLatest()
    {
        // Create 510 runs (over the 500 limit)
        var runs = Enumerable.Range(1, 510).Select(i =>
        {
            var ts = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero)
                .AddHours(i);
            return MakeRun(ts, ("A", "F", "Warning"));
        }).ToList();

        var report = _analyzer.Analyze(runs);
        Assert.Equal(FindingPersistenceAnalyzer.MaxRunsToAnalyze, report.TotalRunsAnalyzed);
    }

    // ── Multi-module same title ──────────────────────────────────────

    [Fact]
    public void Analyze_SameTitleDifferentModules_TrackedSeparately()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(1),
                ("ModuleA", "Weak Config", "Warning"),
                ("ModuleB", "Weak Config", "Warning")),
            MakeRun(Day(2),
                ("ModuleA", "Weak Config", "Warning"),
                ("ModuleB", "Weak Config", "Warning")),
        };

        var report = _analyzer.Analyze(runs);
        Assert.Equal(2, report.Entries.Count);
        Assert.Contains(report.Entries, e => e.Module == "ModuleA");
        Assert.Contains(report.Entries, e => e.Module == "ModuleB");
    }

    // ── Edge: exactly at threshold boundaries ────────────────────────

    [Fact]
    public void Analyze_ExactlyAtChronicThreshold_IsChronic()
    {
        // 90% threshold: 9/10 = exactly 0.9
        var runs = new List<AuditRunRecord>();
        for (int d = 1; d <= 10; d++)
        {
            runs.Add(d == 3
                ? MakeRun(Day(d))
                : MakeRun(Day(d), ("A", "F", "Warning")));
        }

        var report = _analyzer.Analyze(runs);
        Assert.Equal(PersistenceClass.Chronic, report.Entries[0].Classification);
    }

    [Fact]
    public void Analyze_JustBelowChronicThreshold_IsRecurring()
    {
        // 8/10 = 0.8, below 0.9 → Recurring
        var runs = new List<AuditRunRecord>();
        for (int d = 1; d <= 10; d++)
        {
            runs.Add(d <= 2
                ? MakeRun(Day(d))
                : MakeRun(Day(d), ("A", "F", "Warning")));
        }

        var report = _analyzer.Analyze(runs);
        Assert.Equal(PersistenceClass.Recurring, report.Entries[0].Classification);
    }

    [Fact]
    public void Analyze_ExactlyAtRecurringThreshold_IsRecurring()
    {
        // 3/10 = 0.3 exactly, present in latest
        var runs = new List<AuditRunRecord>();
        for (int d = 1; d <= 10; d++)
        {
            runs.Add(d >= 8
                ? MakeRun(Day(d), ("A", "F", "Warning"))
                : MakeRun(Day(d)));
        }

        var report = _analyzer.Analyze(runs);
        Assert.Equal(PersistenceClass.Recurring, report.Entries[0].Classification);
    }

    [Fact]
    public void Analyze_JustBelowRecurringThreshold_IsTransient()
    {
        // 2/10 = 0.2, below 0.3, present in latest → Transient
        var runs = new List<AuditRunRecord>();
        for (int d = 1; d <= 10; d++)
        {
            runs.Add(d >= 9
                ? MakeRun(Day(d), ("A", "F", "Warning"))
                : MakeRun(Day(d)));
        }

        var report = _analyzer.Analyze(runs);
        Assert.Equal(PersistenceClass.Transient, report.Entries[0].Classification);
    }

    // ── Remediation field preserved ──────────────────────────────────

    [Fact]
    public void Analyze_RemediationFieldPreserved()
    {
        var run1 = MakeRun(Day(1), ("A", "Finding", "Warning"));
        run1.Findings[0].Remediation = "Enable firewall via Settings > Network";
        var run2 = MakeRun(Day(2), ("A", "Finding", "Warning"));
        run2.Findings[0].Remediation = "Enable firewall via Settings > Network";

        var report = _analyzer.Analyze([run1, run2]);
        Assert.Equal("Enable firewall via Settings > Network",
            report.Entries[0].Remediation);
    }

    // ── Two runs minimum ─────────────────────────────────────────────

    [Fact]
    public void Analyze_ExactlyTwoRuns_Works()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(1), ("A", "F1", "Critical")),
            MakeRun(Day(2), ("A", "F1", "Critical"), ("B", "F2", "Warning")),
        };

        var report = _analyzer.Analyze(runs);
        Assert.True(report.HasSufficientData);
        Assert.Equal(2, report.TotalUniqueFindings);

        var f1 = report.Entries.First(e => e.Title == "F1");
        Assert.Equal(PersistenceClass.Chronic, f1.Classification); // 2/2 = 100%
        Assert.True(f1.PresentInLatest);

        var f2 = report.Entries.First(e => e.Title == "F2");
        Assert.Equal(PersistenceClass.Recurring, f2.Classification); // 1/2 = 50%, above 30% recurring threshold
        Assert.True(f2.PresentInLatest);
    }
}
