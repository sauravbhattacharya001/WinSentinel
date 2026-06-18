using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class CalendarHeatmapServiceTests
{
    private readonly CalendarHeatmapService _service = new();

    private static AuditRunRecord MakeRun(DateTimeOffset timestamp, int score, int findings = 5, int critical = 0)
        => new()
        {
            Timestamp = timestamp,
            OverallScore = score,
            TotalFindings = findings,
            CriticalCount = critical,
            Grade = score >= 90 ? "A" : score >= 80 ? "B" : "C"
        };

    [Fact]
    public void Analyze_EmptyRuns_ReturnsZeroStats()
    {
        var result = _service.Analyze([], weeks: 4);

        Assert.Equal(4, result.Weeks);
        Assert.Equal(0, result.TotalAudits);
        Assert.Equal(0, result.ActiveDays);
        Assert.Equal(0, result.MaxAuditsInDay);
        Assert.Equal(0, result.BestScore);
        Assert.Equal(0, result.WorstScore);
        Assert.Equal(0, result.CurrentStreak);
        Assert.Equal(0, result.LongestStreak);
    }

    [Fact]
    public void Analyze_EmptyRuns_StillCreatesDayCells()
    {
        var result = _service.Analyze([], weeks: 4);

        // 4 weeks = 28 days of cells
        Assert.Equal(28, result.Days.Count);
    }

    [Fact]
    public void Analyze_SingleRun_CountsOneAuditOneActiveDay()
    {
        var today = DateTimeOffset.Now;
        var runs = new List<AuditRunRecord> { MakeRun(today, 85) };

        var result = _service.Analyze(runs, weeks: 4);

        Assert.Equal(1, result.TotalAudits);
        Assert.Equal(1, result.ActiveDays);
        Assert.Equal(1, result.MaxAuditsInDay);
        Assert.Equal(85, result.BestScore);
        Assert.Equal(85, result.WorstScore);
    }

    [Fact]
    public void Analyze_MultipleRunsSameDay_AggregatesCorrectly()
    {
        // Anchor to an explicit "now" so the calendar window is deterministic
        // regardless of the machine's timezone or the wall-clock time of the run.
        var now = new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, 80, findings: 10, critical: 2),
            MakeRun(now.AddHours(-3), 90, findings: 5, critical: 0),
            MakeRun(now.AddHours(-2), 70, findings: 15, critical: 3),
        };

        var result = _service.Analyze(runs, now, weeks: 4);

        Assert.Equal(3, result.TotalAudits);
        Assert.Equal(1, result.ActiveDays);
        Assert.Equal(3, result.MaxAuditsInDay);
        Assert.Equal(90, result.BestScore);
        Assert.Equal(70, result.WorstScore);

        // Find today's cell (same offset as `now`)
        var todayDate = DateOnly.FromDateTime(now.DateTime);
        var todayCell = result.Days.FirstOrDefault(d => d.Date == todayDate);
        Assert.NotNull(todayCell);
        Assert.Equal(3, todayCell.AuditCount);
        Assert.Equal(80, todayCell.AvgScore); // avg(80,90,70) = 80
        Assert.Equal(30, todayCell.TotalFindings); // 10+5+15
        Assert.Equal(5, todayCell.CriticalCount); // 2+0+3
        Assert.Equal(90, todayCell.BestScore);
    }

    [Fact]
    public void Analyze_ConsecutiveDays_TracksCurrentStreak()
    {
        var now = DateTimeOffset.Now;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, 90),
            MakeRun(now.AddDays(-1), 85),
            MakeRun(now.AddDays(-2), 80),
        };

        var result = _service.Analyze(runs, weeks: 4);

        Assert.True(result.CurrentStreak >= 3, $"CurrentStreak should be >= 3 but was {result.CurrentStreak}");
    }

    [Fact]
    public void Analyze_GapInDays_BreaksCurrentStreak()
    {
        var now = DateTimeOffset.Now;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, 90),
            // gap: no run yesterday
            MakeRun(now.AddDays(-2), 85),
            MakeRun(now.AddDays(-3), 80),
        };

        var result = _service.Analyze(runs, weeks: 4);

        // Current streak should be 1 (today only) since yesterday is missing
        Assert.Equal(1, result.CurrentStreak);
    }

    [Fact]
    public void Analyze_LongestStreak_ComputedAcrossEntireRange()
    {
        var now = DateTimeOffset.Now;
        var runs = new List<AuditRunRecord>
        {
            // Current streak: 1 day
            MakeRun(now, 90),
            // Gap
            // Old streak: 5 consecutive days
            MakeRun(now.AddDays(-10), 85),
            MakeRun(now.AddDays(-11), 80),
            MakeRun(now.AddDays(-12), 82),
            MakeRun(now.AddDays(-13), 88),
            MakeRun(now.AddDays(-14), 91),
        };

        var result = _service.Analyze(runs, weeks: 4);

        Assert.Equal(5, result.LongestStreak);
    }

    [Fact]
    public void Analyze_DaysCells_AreChronological()
    {
        var runs = new List<AuditRunRecord> { MakeRun(DateTimeOffset.Now, 90) };
        var result = _service.Analyze(runs, weeks: 4);

        for (int i = 1; i < result.Days.Count; i++)
        {
            Assert.True(result.Days[i].Date >= result.Days[i - 1].Date,
                $"Days should be chronological: {result.Days[i - 1].Date} should come before {result.Days[i].Date}");
        }
    }

    [Fact]
    public void Analyze_WeeksParameter_ControlsDayCount()
    {
        var result1 = _service.Analyze([], weeks: 1);
        var result52 = _service.Analyze([], weeks: 52);

        Assert.Equal(7, result1.Days.Count);
        Assert.Equal(364, result52.Days.Count);
    }

    [Fact]
    public void Analyze_RunsOutsideWindow_AreExcluded()
    {
        var now = DateTimeOffset.Now;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, 90),
            MakeRun(now.AddDays(-200), 50), // way outside 4-week window
        };

        var result = _service.Analyze(runs, weeks: 4);

        // Only the recent run should be counted in active days
        // The old run may appear in TotalAudits from runsByDate grouping
        // but the cell won't be in the heatmap range
        Assert.Equal(1, result.ActiveDays);
    }

    [Fact]
    public void Analyze_DayCells_HaveCorrectDayOfWeek()
    {
        var result = _service.Analyze([], weeks: 2);

        foreach (var day in result.Days)
        {
            var expected = day.Date.DayOfWeek;
            Assert.Equal(expected, day.DayOfWeek);
        }
    }

    [Fact]
    public void Analyze_EmptyDayCells_HaveZeroValues()
    {
        var result = _service.Analyze([], weeks: 1);

        foreach (var day in result.Days)
        {
            Assert.Equal(0, day.AuditCount);
            Assert.Equal(0, day.AvgScore);
            Assert.Equal(0, day.TotalFindings);
            Assert.Equal(0, day.CriticalCount);
            Assert.Equal(0, day.BestScore);
        }
    }

    [Fact]
    public void Analyze_DefaultWeeks_Is26()
    {
        var result = _service.Analyze([]);

        Assert.Equal(26, result.Weeks);
        Assert.Equal(182, result.Days.Count);
    }

    [Fact]
    public void Analyze_MultipleRunsDifferentDays_TracksActiveDays()
    {
        var now = DateTimeOffset.Now;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, 95),
            MakeRun(now.AddDays(-3), 85),
            MakeRun(now.AddDays(-7), 75),
        };

        var result = _service.Analyze(runs, weeks: 4);

        Assert.Equal(3, result.TotalAudits);
        Assert.Equal(3, result.ActiveDays);
        Assert.Equal(1, result.MaxAuditsInDay);
    }

    [Fact]
    public void Analyze_ScoreExtremes_TrackedCorrectly()
    {
        var now = DateTimeOffset.Now;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, 100),
            MakeRun(now.AddDays(-1), 0),
        };

        var result = _service.Analyze(runs, weeks: 4);

        Assert.Equal(100, result.BestScore);
        Assert.Equal(0, result.WorstScore);
    }

    // ── Deterministic clock injection / cross-timezone correctness ──────────
    // Regression coverage for the bug where the window end (DateTime.Now, local)
    // and run bucketing (Timestamp.LocalDateTime) could disagree with a caller
    // reasoning in UTC, silently dropping "today" runs whenever the local and UTC
    // day boundaries diverged. The injected-now overload frames both in one offset.

    [Fact]
    public void Analyze_InjectedNow_WindowEndsOnGivenInstant()
    {
        // Wednesday 2026-06-10; end-of-week Sunday is 2026-06-14.
        var now = new DateTimeOffset(2026, 6, 10, 9, 0, 0, TimeSpan.Zero);

        var result = _service.Analyze([], now, weeks: 4);

        Assert.Equal(28, result.Days.Count);
        // Last cell is the aligned end-of-week Sunday, independent of wall clock.
        Assert.Equal(new DateOnly(2026, 6, 14), result.Days[^1].Date);
        // First cell is (weeks*7 - 1) = 27 days before that Sunday.
        Assert.Equal(new DateOnly(2026, 5, 18), result.Days[0].Date);
    }

    [Fact]
    public void Analyze_InjectedNow_IsDeterministicAcrossCalls()
    {
        var now = new DateTimeOffset(2026, 3, 1, 17, 30, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord> { MakeRun(now, 88) };

        var a = _service.Analyze(runs, now, weeks: 6);
        var b = _service.Analyze(runs, now, weeks: 6);

        Assert.Equal(a.Days.Count, b.Days.Count);
        Assert.Equal(a.Days[0].Date, b.Days[0].Date);
        Assert.Equal(a.Days[^1].Date, b.Days[^1].Date);
        Assert.Equal(a.TotalAudits, b.TotalAudits);
        Assert.Equal(a.CurrentStreak, b.CurrentStreak);
    }

    [Fact]
    public void Analyze_LateEveningRun_LandsOnLocalDayNotUtcDay()
    {
        // 2026-06-15 22:00 in UTC-07:00 is already 2026-06-16 05:00 UTC.
        // Bucketing must follow the caller's offset (the run's local day = the 15th),
        // not the UTC day, so the run shows up on the day the user actually ran it.
        var offset = TimeSpan.FromHours(-7);
        var now = new DateTimeOffset(2026, 6, 15, 22, 0, 0, offset);
        var runs = new List<AuditRunRecord> { MakeRun(now, 77) };

        var result = _service.Analyze(runs, now, weeks: 4);

        var localToday = new DateOnly(2026, 6, 15);
        var utcToday = new DateOnly(2026, 6, 16);
        var localCell = result.Days.FirstOrDefault(d => d.Date == localToday);
        Assert.NotNull(localCell);
        Assert.Equal(1, localCell.AuditCount);
        Assert.Equal(77, localCell.BestScore);
        // The UTC "tomorrow" cell must not exist / must be empty.
        var utcCell = result.Days.FirstOrDefault(d => d.Date == utcToday);
        Assert.True(utcCell is null || utcCell.AuditCount == 0);
        Assert.Equal(1, result.ActiveDays);
        Assert.Equal(1, result.CurrentStreak);
    }

    [Fact]
    public void Analyze_RunStoredInDifferentOffset_BucketsByNowOffset()
    {
        // A run timestamped in UTC, evaluated by a UTC-07:00 caller anchored to the
        // same wall instant, must aggregate onto a single local day (no double cell).
        var localNow = new DateTimeOffset(2026, 6, 15, 23, 30, 0, TimeSpan.FromHours(-7));
        var sameInstantUtc = localNow.ToUniversalTime(); // 2026-06-16 06:30Z
        var runs = new List<AuditRunRecord>
        {
            MakeRun(localNow, 80, findings: 4),
            MakeRun(sameInstantUtc, 90, findings: 6),
        };

        var result = _service.Analyze(runs, localNow, weeks: 4);

        Assert.Equal(2, result.TotalAudits);
        Assert.Equal(1, result.ActiveDays); // both land on the same local day
        Assert.Equal(2, result.MaxAuditsInDay);

        var localCell = result.Days.FirstOrDefault(d => d.Date == new DateOnly(2026, 6, 15));
        Assert.NotNull(localCell);
        Assert.Equal(2, localCell.AuditCount);
        Assert.Equal(10, localCell.TotalFindings); // 4 + 6
        Assert.Equal(85, localCell.AvgScore); // avg(80, 90)
        Assert.Equal(90, localCell.BestScore);
    }

    [Fact]
    public void Analyze_InjectedNow_ConsecutiveDaysStreakDeterministic()
    {
        // Three consecutive local days ending on the anchor → current streak 3,
        // with no dependence on the machine's actual clock or timezone.
        var now = new DateTimeOffset(2026, 2, 18, 8, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, 90),
            MakeRun(now.AddDays(-1), 85),
            MakeRun(now.AddDays(-2), 80),
        };

        var result = _service.Analyze(runs, now, weeks: 4);

        Assert.Equal(3, result.CurrentStreak);
        Assert.Equal(3, result.ActiveDays);
    }

    [Fact]
    public void Analyze_DefaultOverload_DelegatesToInjectedNow()
    {
        // The parameterless overload must behave like the injected one at "now";
        // a run at the current instant is always today's cell.
        var now = DateTimeOffset.Now;
        var runs = new List<AuditRunRecord> { MakeRun(now, 73) };

        var viaDefault = _service.Analyze(runs, weeks: 4);
        var viaInjected = _service.Analyze(runs, now, weeks: 4);

        Assert.Equal(viaInjected.Days.Count, viaDefault.Days.Count);
        Assert.Equal(viaInjected.TotalAudits, viaDefault.TotalAudits);
        Assert.Equal(viaInjected.ActiveDays, viaDefault.ActiveDays);
        Assert.Equal(viaInjected.Days[^1].Date, viaDefault.Days[^1].Date);
    }

    // ── Current-streak correctness (future days & not-yet-audited "today") ──────
    // Regression coverage for the bug where the streak walk started at the
    // padded end-of-week Sunday with a single `streakActive` flag, so:
    //   (a) a future-dated run (clock skew / a node ahead) was *counted* into the
    //       current streak even with zero recent activity, and
    //   (b) a daily streak that ran through yesterday collapsed to 0 the instant
    //       midnight passed before the user ran "today's" audit.
    // The fix anchors the streak at today-or-yesterday and ignores future days.

    [Fact]
    public void Analyze_TodayNotYetAudited_KeepsYesterdayAnchoredStreak()
    {
        // Audited every day through yesterday, but not yet today (e.g. it's
        // 00:20 and the daily scan hasn't run). The streak must survive — a
        // calendar day hasn't fully lapsed without an audit.
        var now = new DateTimeOffset(2026, 6, 18, 0, 20, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now.AddDays(-1), 90), // yesterday
            MakeRun(now.AddDays(-2), 88),
            MakeRun(now.AddDays(-3), 91),
        };

        var result = _service.Analyze(runs, now, weeks: 4);

        // 3 consecutive days through yesterday; today (no run yet) is grace, not a break.
        Assert.Equal(3, result.CurrentStreak);
    }

    [Fact]
    public void Analyze_TwoDayGapBeforeToday_ResetsCurrentStreak()
    {
        // Neither today nor yesterday was audited (a full day lapsed) → streak is 0,
        // even though there is an older run. Guards the grace window from over-reaching.
        var now = new DateTimeOffset(2026, 6, 18, 9, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now.AddDays(-2), 90),
            MakeRun(now.AddDays(-3), 88),
        };

        var result = _service.Analyze(runs, now, weeks: 4);

        Assert.Equal(0, result.CurrentStreak);
    }

    [Fact]
    public void Analyze_FutureDatedRun_DoesNotInflateCurrentStreak()
    {
        // A single run dated *tomorrow* (clock skew between fleet nodes) with no
        // recent activity must not register as a current streak. Previously the
        // backward walk from the end-of-week Sunday counted it.
        var now = new DateTimeOffset(2026, 6, 17, 12, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now.AddDays(1), 95), // tomorrow — future relative to `now`
        };

        var result = _service.Analyze(runs, now, weeks: 4);

        Assert.Equal(0, result.CurrentStreak);
    }

    [Fact]
    public void Analyze_FutureRunWithTodayStreak_CountsOnlyRealDays()
    {
        // Today + yesterday audited (real 2-day streak), plus a stray future-dated
        // run. The future run must neither extend nor inflate the streak.
        var now = new DateTimeOffset(2026, 6, 17, 12, 0, 0, TimeSpan.Zero);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now.AddDays(2), 99),  // future noise
            MakeRun(now, 90),             // today
            MakeRun(now.AddDays(-1), 85), // yesterday
        };

        var result = _service.Analyze(runs, now, weeks: 4);

        Assert.Equal(2, result.CurrentStreak);
    }
}
