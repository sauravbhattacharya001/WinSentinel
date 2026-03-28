using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests.Services;

public class GamificationServiceTests
{
    private readonly GamificationService _sut = new();

    private static AuditRunRecord MakeRun(int score, int criticals = 0, int daysAgo = 0) => new()
    {
        Timestamp = DateTimeOffset.UtcNow.AddDays(-daysAgo),
        OverallScore = score,
        CriticalCount = criticals,
        TotalFindings = criticals + 5,
        WarningCount = 3,
        InfoCount = 2,
        PassCount = 10
    };

    [Fact]
    public void Analyze_EmptyRuns_ReturnsDefaultProfile()
    {
        var result = _sut.Analyze([]);

        Assert.Equal(1, result.Level);
        Assert.Equal(0, result.TotalXp);
        Assert.Equal(0, result.TotalAudits);
        Assert.Empty(result.Achievements);
    }

    [Fact]
    public void Analyze_SingleRun_CalculatesBasicStats()
    {
        var runs = new List<AuditRunRecord> { MakeRun(80) };

        var result = _sut.Analyze(runs);

        Assert.Equal(1, result.TotalAudits);
        Assert.Equal(80, result.HighestScore);
        Assert.Equal(80, result.AverageScore);
        Assert.Equal(80, result.LatestScore);
        Assert.Equal(80, result.TotalXp);
    }

    [Theory]
    [InlineData(100, 1)]   // 100 XP → Level 1
    [InlineData(500, 2)]   // 500 XP → Level 2
    [InlineData(1500, 3)]
    [InlineData(3000, 4)]
    [InlineData(5000, 5)]
    [InlineData(8000, 6)]
    [InlineData(12000, 7)]
    [InlineData(17000, 8)]
    [InlineData(23000, 9)]
    [InlineData(30000, 10)]
    public void Analyze_LevelThresholds_CorrectLevel(int totalScore, int expectedLevel)
    {
        // Create enough runs to hit the total XP
        var runs = new List<AuditRunRecord>();
        int remaining = totalScore;
        while (remaining > 0)
        {
            int score = Math.Min(remaining, 100);
            runs.Add(MakeRun(score));
            remaining -= score;
        }

        var result = _sut.Analyze(runs);

        Assert.Equal(expectedLevel, result.Level);
    }

    [Fact]
    public void Analyze_XpToNextLevel_CalculatedCorrectly()
    {
        // 400 XP → Level 1, need 500 to reach Level 2, so 100 to go
        var runs = Enumerable.Range(0, 4).Select(_ => MakeRun(100)).ToList();

        var result = _sut.Analyze(runs);

        Assert.Equal(1, result.Level);
        Assert.Equal(100, result.XpToNextLevel); // 500 - 400
    }

    [Fact]
    public void Analyze_MaxLevel_XpToNextLevelIsZero()
    {
        // 300 runs of 100 = 30000 XP → Level 10
        var runs = Enumerable.Range(0, 300).Select(_ => MakeRun(100)).ToList();

        var result = _sut.Analyze(runs);

        Assert.Equal(10, result.Level);
        Assert.Equal(0, result.XpToNextLevel);
    }

    [Fact]
    public void Analyze_ImprovementStreak_TrackedCorrectly()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(50, daysAgo: 5),
            MakeRun(60, daysAgo: 4), // +1
            MakeRun(70, daysAgo: 3), // +2
            MakeRun(65, daysAgo: 2), // reset
            MakeRun(80, daysAgo: 1), // +1
            MakeRun(90, daysAgo: 0), // +2 (current)
        };

        var result = _sut.Analyze(runs);

        Assert.Equal(2, result.CurrentImprovementStreak);
        Assert.Equal(2, result.BestImprovementStreak);
    }

    [Fact]
    public void Analyze_EqualScores_CountAsImprovement()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(70, daysAgo: 3),
            MakeRun(70, daysAgo: 2), // equal counts as improvement
            MakeRun(70, daysAgo: 1),
            MakeRun(70, daysAgo: 0),
        };

        var result = _sut.Analyze(runs);

        Assert.Equal(3, result.CurrentImprovementStreak);
        Assert.Equal(3, result.BestImprovementStreak);
    }

    [Fact]
    public void Analyze_PerfectStreak_TracksConsecutive90Plus()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(85, daysAgo: 5),
            MakeRun(92, daysAgo: 4),
            MakeRun(95, daysAgo: 3),
            MakeRun(91, daysAgo: 2),
            MakeRun(80, daysAgo: 1), // breaks streak
            MakeRun(93, daysAgo: 0),
        };

        var result = _sut.Analyze(runs);

        Assert.Equal(1, result.CurrentPerfectStreak);
        Assert.Equal(3, result.BestPerfectStreak);
    }

    [Fact]
    public void Analyze_CriticalsFixed_CountsReductions()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(50, criticals: 10, daysAgo: 3),
            MakeRun(60, criticals: 5, daysAgo: 2),  // fixed 5
            MakeRun(65, criticals: 8, daysAgo: 1),   // increased, no fix
            MakeRun(80, criticals: 2, daysAgo: 0),   // fixed 6
        };

        var result = _sut.Analyze(runs);

        Assert.Equal(11, result.TotalCriticalFixed); // 5 + 6
    }

    [Fact]
    public void Analyze_CriticalsNeverFixed_ReturnsZero()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(50, criticals: 3, daysAgo: 2),
            MakeRun(55, criticals: 5, daysAgo: 1),
            MakeRun(60, criticals: 7, daysAgo: 0),
        };

        var result = _sut.Analyze(runs);

        Assert.Equal(0, result.TotalCriticalFixed);
    }

    [Fact]
    public void Analyze_FirstStepsAchievement_AlwaysUnlocked()
    {
        var result = _sut.Analyze([MakeRun(10)]);

        Assert.Contains(result.Achievements, a => a.Name == "First Steps" && a.Unlocked);
    }

    [Theory]
    [InlineData(50, "Half Way There")]
    [InlineData(75, "Security Enthusiast")]
    [InlineData(90, "Hardened")]
    [InlineData(95, "Fort Knox")]
    [InlineData(100, "Perfection")]
    public void Analyze_ScoreAchievements_UnlockedAtThreshold(int score, string achievementName)
    {
        var result = _sut.Analyze([MakeRun(score)]);

        Assert.Contains(result.Achievements, a => a.Name == achievementName && a.Unlocked);
    }

    [Fact]
    public void Analyze_Score49_DoesNotUnlockHalfWayThere()
    {
        var result = _sut.Analyze([MakeRun(49)]);

        Assert.DoesNotContain(result.Achievements, a => a.Name == "Half Way There");
    }

    [Fact]
    public void Analyze_VeteranAchievement_At10Audits()
    {
        var runs = Enumerable.Range(0, 10).Select(i => MakeRun(50, daysAgo: i)).ToList();

        var result = _sut.Analyze(runs);

        Assert.Contains(result.Achievements, a => a.Name == "Veteran" && a.Unlocked);
    }

    [Fact]
    public void Analyze_9Audits_NoVeteranAchievement()
    {
        var runs = Enumerable.Range(0, 9).Select(i => MakeRun(50, daysAgo: i)).ToList();

        var result = _sut.Analyze(runs);

        Assert.DoesNotContain(result.Achievements, a => a.Name == "Veteran");
    }

    [Fact]
    public void Analyze_StreakAchievement_OnARollAt3()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(50, daysAgo: 3),
            MakeRun(60, daysAgo: 2),
            MakeRun(70, daysAgo: 1),
            MakeRun(80, daysAgo: 0),
        };

        var result = _sut.Analyze(runs);

        Assert.Contains(result.Achievements, a => a.Name == "On a Roll" && a.Unlocked);
    }

    [Fact]
    public void Analyze_CleanSlate_ZeroCriticalsOnLatest()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(50, criticals: 5, daysAgo: 1),
            MakeRun(80, criticals: 0, daysAgo: 0),
        };

        var result = _sut.Analyze(runs);

        Assert.Contains(result.Achievements, a => a.Name == "Clean Slate" && a.Unlocked);
    }

    [Fact]
    public void Analyze_NoCleanSlate_WhenCriticalsExist()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(80, criticals: 1, daysAgo: 0),
        };

        var result = _sut.Analyze(runs);

        Assert.DoesNotContain(result.Achievements, a => a.Name == "Clean Slate");
    }

    [Fact]
    public void Analyze_BugSquasher_FirstCriticalFixed()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(60, criticals: 3, daysAgo: 1),
            MakeRun(70, criticals: 1, daysAgo: 0),
        };

        var result = _sut.Analyze(runs);

        Assert.Contains(result.Achievements, a => a.Name == "Bug Squasher" && a.Unlocked);
    }

    [Fact]
    public void Analyze_RunsAreOrderedChronologically()
    {
        // Pass runs in reverse order — service should sort them
        var runs = new List<AuditRunRecord>
        {
            MakeRun(90, daysAgo: 0),  // most recent first
            MakeRun(50, daysAgo: 2),
            MakeRun(70, daysAgo: 1),
        };

        var result = _sut.Analyze(runs);

        Assert.Equal(90, result.LatestScore); // latest by timestamp
    }
}
