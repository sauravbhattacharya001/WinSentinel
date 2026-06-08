using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

/// <summary>
/// Comprehensive tests for SecurityMentorService.
/// Tests skill assessment, learning paths, challenges, levels, streaks, and encouragement.
/// </summary>
public class SecurityMentorServiceTests : IDisposable
{
    private readonly string _dbPath;
    private readonly AuditHistoryService _history;
    private readonly SecurityMentorService _service;

    public SecurityMentorServiceTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"winsentinel_mentor_test_{Guid.NewGuid():N}.db");
        _history = new AuditHistoryService(_dbPath);
        _service = new SecurityMentorService(_history);
    }

    public void Dispose()
    {
        _history.Dispose();
        if (File.Exists(_dbPath)) { try { File.Delete(_dbPath); } catch { } }
    }

    // ── Helpers ──────────────────────────────────────────────────

    private static SecurityReport MakeReport(int score, params (string module, string category, int pass, int warn, int crit)[] modules)
    {
        var report = new SecurityReport { SecurityScore = score };
        foreach (var (module, category, pass, warn, crit) in modules)
        {
            var findings = new List<Finding>();
            for (int i = 0; i < pass; i++)
                findings.Add(Finding.Pass($"Pass {i}", "OK", category));
            for (int i = 0; i < warn; i++)
                findings.Add(new Finding { Title = $"Warning {i}", Description = "Issue", Category = category, Severity = Severity.Warning });
            for (int i = 0; i < crit; i++)
                findings.Add(new Finding { Title = $"Critical {i}", Description = "Severe", Category = category, Severity = Severity.Critical });

            report.Results.Add(new AuditResult
            {
                ModuleName = module,
                Category = category,
                Findings = findings,
                StartTime = DateTimeOffset.UtcNow,
                EndTime = DateTimeOffset.UtcNow.AddSeconds(1),
            });
        }
        return report;
    }

    private void SeedHistory(params SecurityReport[] reports)
    {
        foreach (var report in reports)
            _history.SaveAuditResult(report);
    }

    // ──────────────────────────────────────────────────────────────────
    // Basic contract
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Analyze_EmptyReport_ReturnsValidResult()
    {
        var report = new SecurityReport();
        var result = _service.Analyze(report);

        Assert.NotNull(result);
        Assert.Empty(result.Skills);
        Assert.Empty(result.LearningPaths);
        Assert.Empty(result.Challenges);
        Assert.Equal(0, result.OverallScore);
        Assert.Equal("Novice", result.OverallLevel);
        Assert.NotEmpty(result.Encouragement);
    }

    [Fact]
    public void Analyze_ReportWithFindings_ProducesSkills()
    {
        var report = MakeReport(75,
            ("NetworkAudit", "Network", 8, 2, 0),
            ("FirewallAudit", "Firewall", 5, 3, 1));

        var result = _service.Analyze(report);

        Assert.True(result.Skills.Count >= 2);
        Assert.All(result.Skills, s =>
        {
            Assert.NotEmpty(s.Domain);
            Assert.InRange(s.Score, 0, 100);
            Assert.NotEmpty(s.Level);
        });
    }

    // ──────────────────────────────────────────────────────────────────
    // Skill scoring
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void SkillScore_AllPass_Returns100()
    {
        var report = MakeReport(100, ("NetworkAudit", "Network", 10, 0, 0));
        var result = _service.Analyze(report);

        var network = result.Skills.First(s => s.Domain == "Network");
        Assert.Equal(100, network.Score);
    }

    [Fact]
    public void SkillScore_AllWarnings_Returns0()
    {
        var report = MakeReport(0, ("NetworkAudit", "Network", 0, 10, 0));
        var result = _service.Analyze(report);

        var network = result.Skills.First(s => s.Domain == "Network");
        Assert.Equal(0, network.Score);
    }

    [Fact]
    public void SkillScore_MixedPassAndWarning_ReflectsPassRate()
    {
        // 6 pass + 4 warning = 60% pass rate = score 60
        var report = MakeReport(60, ("NetworkAudit", "Network", 6, 4, 0));
        var result = _service.Analyze(report);

        var network = result.Skills.First(s => s.Domain == "Network");
        Assert.Equal(60, network.Score);
    }

    [Fact]
    public void SkillScore_CriticalFindingsPenalize()
    {
        // 8 pass + 2 critical = 80% pass rate, then -5 per critical = 80 - 10 = 70
        var report = MakeReport(70, ("NetworkAudit", "Network", 8, 0, 2));
        var result = _service.Analyze(report);

        var network = result.Skills.First(s => s.Domain == "Network");
        Assert.Equal(70, network.Score);
    }

    [Fact]
    public void SkillScore_ManyCriticals_ClampedAtZero()
    {
        // 2 pass + 8 critical = 20% pass rate, then -5*8 = -40 → clamped to 0
        var report = MakeReport(0, ("NetworkAudit", "Network", 2, 0, 8));
        var result = _service.Analyze(report);

        var network = result.Skills.First(s => s.Domain == "Network");
        Assert.Equal(0, network.Score);
    }

    [Fact]
    public void SkillScore_OrderedByScoreAscending()
    {
        var report = MakeReport(50,
            ("NetworkAudit", "Network", 9, 1, 0),   // 90%
            ("FirewallAudit", "Firewall", 3, 7, 0), // 30%
            ("ServiceAudit", "Services", 6, 4, 0)); // 60%

        var result = _service.Analyze(report);

        for (int i = 1; i < result.Skills.Count; i++)
            Assert.True(result.Skills[i].Score >= result.Skills[i - 1].Score);
    }

    // ──────────────────────────────────────────────────────────────────
    // Level mapping
    // ──────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(0, "Novice")]
    [InlineData(15, "Novice")]
    [InlineData(20, "Beginner")]
    [InlineData(39, "Beginner")]
    [InlineData(40, "Intermediate")]
    [InlineData(59, "Intermediate")]
    [InlineData(60, "Advanced")]
    [InlineData(79, "Advanced")]
    [InlineData(80, "Expert")]
    [InlineData(100, "Expert")]
    public void OverallLevel_MapsCorrectly(int score, string expected)
    {
        // Create a report that produces the desired overall score
        // With one module: pass count = score, total = 100
        var report = MakeReport(score, ("NetworkAudit", "Network", score, 100 - score, 0));
        var result = _service.Analyze(report);

        Assert.Equal(expected, result.OverallLevel);
    }

    // ──────────────────────────────────────────────────────────────────
    // Trend tracking
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Trend_NoHistory_ReturnsNeutral()
    {
        var report = MakeReport(75, ("NetworkAudit", "Network", 7, 3, 0));
        var result = _service.Analyze(report);

        Assert.All(result.Skills, s => Assert.Equal("→", s.Trend));
    }

    [Fact]
    public void Trend_WithHistory_ReturnsNeutral_WhenModuleScoresNotLoaded()
    {
        // GetHistory() doesn't load ModuleScores, so trends always show neutral
        // This is by design — GetHistory is the lightweight query
        SeedHistory(MakeReport(40, ("NetworkAudit", "Network", 4, 6, 0)));
        SeedHistory(MakeReport(60, ("NetworkAudit", "Network", 6, 4, 0)));

        var currentReport = MakeReport(80, ("NetworkAudit", "Network", 8, 2, 0));
        var result = _service.Analyze(currentReport);

        // Since GetHistory doesn't populate ModuleScores, all trends are neutral
        Assert.All(result.Skills, s => Assert.Equal("→", s.Trend));
    }

    // ──────────────────────────────────────────────────────────────────
    // Learning paths
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void LearningPaths_GeneratedForSkillsBelow80()
    {
        var report = MakeReport(50,
            ("NetworkAudit", "Network", 3, 7, 0),     // 30 → learning path
            ("FirewallAudit", "Firewall", 9, 1, 0));  // 90 → no learning path

        var result = _service.Analyze(report);

        Assert.Contains(result.LearningPaths, lp => lp.Domain == "Network");
        Assert.DoesNotContain(result.LearningPaths, lp => lp.Domain == "Firewall");
    }

    [Fact]
    public void LearningPaths_HighPriority_WhenScoreBelow40()
    {
        var report = MakeReport(20, ("NetworkAudit", "Network", 2, 8, 0)); // 20%

        var result = _service.Analyze(report);

        var path = result.LearningPaths.First(lp => lp.Domain == "Network");
        Assert.Equal("High", path.Priority);
    }

    [Fact]
    public void LearningPaths_MediumPriority_WhenScoreBetween40And60()
    {
        var report = MakeReport(50, ("NetworkAudit", "Network", 5, 5, 0)); // 50%

        var result = _service.Analyze(report);

        var path = result.LearningPaths.First(lp => lp.Domain == "Network");
        Assert.Equal("Medium", path.Priority);
    }

    [Fact]
    public void LearningPaths_LowPriority_WhenScoreBetween60And80()
    {
        var report = MakeReport(65, ("NetworkAudit", "Network", 7, 3, 0)); // 70%

        var result = _service.Analyze(report);

        var path = result.LearningPaths.First(lp => lp.Domain == "Network");
        Assert.Equal("Low", path.Priority);
    }

    [Fact]
    public void LearningPaths_ContainRelevantTopics()
    {
        var report = MakeReport(30, ("NetworkAudit", "Network", 3, 7, 0));

        var result = _service.Analyze(report);

        var path = result.LearningPaths.First(lp => lp.Domain == "Network");
        Assert.NotEmpty(path.Topics);
        Assert.All(path.Topics, t => Assert.NotEmpty(t));
    }

    [Fact]
    public void LearningPaths_MoreTopicsForLowerScores()
    {
        var lowReport = MakeReport(20, ("NetworkAudit", "Network", 2, 8, 0));  // 20% → 5 topics
        var midReport = MakeReport(65, ("NetworkAudit", "Network", 7, 3, 0));  // 70% → 2 topics

        var lowResult = _service.Analyze(lowReport);
        var midResult = _service.Analyze(midReport);

        var lowPath = lowResult.LearningPaths.First(lp => lp.Domain == "Network");
        var midPath = midResult.LearningPaths.First(lp => lp.Domain == "Network");

        Assert.True(lowPath.Topics.Count > midPath.Topics.Count);
    }

    // ──────────────────────────────────────────────────────────────────
    // Challenges
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Challenges_GeneratedForWeakDomains()
    {
        var report = MakeReport(40,
            ("NetworkAudit", "Network", 3, 7, 0),     // 30 → challenge
            ("FirewallAudit", "Firewall", 9, 1, 0));  // 90 → no challenge

        var result = _service.Analyze(report);

        Assert.Contains(result.Challenges, c => c.Domain == "Network");
        Assert.DoesNotContain(result.Challenges, c => c.Domain == "Firewall");
    }

    [Fact]
    public void Challenges_MaximumOf5()
    {
        var report = MakeReport(20,
            ("NetworkAudit", "Network", 1, 9, 0),
            ("FirewallAudit", "Firewall", 1, 9, 0),
            ("ServiceAudit", "Services", 1, 9, 0),
            ("RegistryAudit", "Registry", 1, 9, 0),
            ("IdentityAudit", "Identity", 1, 9, 0),
            ("EncryptionAudit", "Encryption", 1, 9, 0),
            ("UpdateAudit", "Updates", 1, 9, 0));

        var result = _service.Analyze(report);

        Assert.True(result.Challenges.Count <= 5);
    }

    [Fact]
    public void Challenges_HavePointsReward()
    {
        var report = MakeReport(30, ("NetworkAudit", "Network", 3, 7, 0));

        var result = _service.Analyze(report);

        Assert.All(result.Challenges, c =>
        {
            Assert.True(c.PointsReward > 0);
            Assert.NotEmpty(c.Title);
            Assert.NotEmpty(c.Description);
            Assert.NotEmpty(c.Difficulty);
        });
    }

    [Fact]
    public void Challenges_HarderForLowerScores()
    {
        var lowReport = MakeReport(10, ("NetworkAudit", "Network", 1, 9, 0));  // <30 → Hard
        var midReport = MakeReport(50, ("NetworkAudit", "Network", 5, 5, 0));  // >=30 → Medium

        var lowResult = _service.Analyze(lowReport);
        var midResult = _service.Analyze(midReport);

        var lowChallenge = lowResult.Challenges.First(c => c.Domain == "Network");
        var midChallenge = midResult.Challenges.First(c => c.Domain == "Network");

        Assert.Equal("Hard", lowChallenge.Difficulty);
        Assert.Equal("Medium", midChallenge.Difficulty);
    }

    // ──────────────────────────────────────────────────────────────────
    // Streak calculation
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Streak_NoHistory_ReturnsZero()
    {
        var report = MakeReport(75, ("NetworkAudit", "Network", 7, 3, 0));
        var result = _service.Analyze(report);

        Assert.Equal(0, result.StreakDays);
    }

    [Fact]
    public void Streak_ConsistentImprovement_CountsUp()
    {
        // Seed 4 improving runs
        SeedHistory(MakeReport(40, ("NetworkAudit", "Network", 4, 6, 0)));
        SeedHistory(MakeReport(50, ("NetworkAudit", "Network", 5, 5, 0)));
        SeedHistory(MakeReport(60, ("NetworkAudit", "Network", 6, 4, 0)));
        SeedHistory(MakeReport(70, ("NetworkAudit", "Network", 7, 3, 0)));

        var report = MakeReport(80, ("NetworkAudit", "Network", 8, 2, 0));
        var result = _service.Analyze(report);

        Assert.True(result.StreakDays >= 2);
    }

    [Fact]
    public void Streak_ScoreDrop_ResetsStreak()
    {
        SeedHistory(MakeReport(80, ("NetworkAudit", "Network", 8, 2, 0)));
        SeedHistory(MakeReport(70, ("NetworkAudit", "Network", 7, 3, 0))); // drop
        SeedHistory(MakeReport(60, ("NetworkAudit", "Network", 6, 4, 0))); // drop again

        var report = MakeReport(50, ("NetworkAudit", "Network", 5, 5, 0));
        var result = _service.Analyze(report);

        // Streak should be 0 since scores are declining
        Assert.Equal(0, result.StreakDays);
    }

    // ──────────────────────────────────────────────────────────────────
    // Encouragement messages
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Encouragement_ExpertLevel_CelebratesExcellence()
    {
        var report = MakeReport(95, ("NetworkAudit", "Network", 10, 0, 0));
        var result = _service.Analyze(report);

        Assert.Contains("🏆", result.Encouragement);
    }

    [Fact]
    public void Encouragement_HighScore_EncouragesProgress()
    {
        var report = MakeReport(78, ("NetworkAudit", "Network", 8, 2, 0));
        var result = _service.Analyze(report);

        Assert.Contains("💪", result.Encouragement);
    }

    [Fact]
    public void Encouragement_LowScore_MotivatesBeginner()
    {
        var report = MakeReport(15, ("NetworkAudit", "Network", 1, 8, 1));
        var result = _service.Analyze(report);

        Assert.Contains("🚀", result.Encouragement);
    }

    // ──────────────────────────────────────────────────────────────────
    // Domain normalization
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void DomainNormalization_CapitalizesCategory()
    {
        var report = MakeReport(50, ("NetworkAudit", "network", 5, 5, 0));
        var result = _service.Analyze(report);

        Assert.Contains(result.Skills, s => s.Domain == "Network");
    }

    [Fact]
    public void DomainNormalization_MultipleSameCategory_Aggregates()
    {
        var report = MakeReport(60,
            ("NetworkAudit", "Network", 5, 5, 0),
            ("DnsAudit", "Network", 3, 7, 0));

        var result = _service.Analyze(report);

        // Both should merge into one "Network" domain
        var networkSkills = result.Skills.Where(s => s.Domain == "Network").ToList();
        Assert.Single(networkSkills);
        Assert.Equal(20, networkSkills[0].FindingsCount); // 10 + 10
    }

    // ──────────────────────────────────────────────────────────────────
    // WeakestDomain / StrongestDomain
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void WeakestAndStrongest_Identified()
    {
        var report = MakeReport(50,
            ("NetworkAudit", "Network", 9, 1, 0),     // 90
            ("FirewallAudit", "Firewall", 2, 8, 0));  // 20

        var result = _service.Analyze(report);

        Assert.Equal("Firewall", result.WeakestDomain);
        Assert.Equal("Network", result.StrongestDomain);
    }

    [Fact]
    public void WeakestDomain_NA_WhenNoSkills()
    {
        var report = new SecurityReport();
        var result = _service.Analyze(report);

        Assert.Equal("N/A", result.WeakestDomain);
    }

    // ──────────────────────────────────────────────────────────────────
    // Full integration scenario
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void FullScenario_MultiDomain_ProducesComprehensiveReport()
    {
        // Seed some history
        SeedHistory(MakeReport(40,
            ("NetworkAudit", "Network", 4, 6, 0),
            ("FirewallAudit", "Firewall", 3, 7, 0)));
        SeedHistory(MakeReport(50,
            ("NetworkAudit", "Network", 5, 5, 0),
            ("FirewallAudit", "Firewall", 4, 6, 0)));

        // Current report is better
        var report = MakeReport(65,
            ("NetworkAudit", "Network", 7, 3, 0),
            ("FirewallAudit", "Firewall", 5, 5, 0),
            ("ServiceAudit", "Services", 8, 2, 0));

        var result = _service.Analyze(report);

        // Skills
        Assert.True(result.Skills.Count >= 3);
        // Learning paths only for < 80
        Assert.All(result.LearningPaths, lp =>
        {
            var skill = result.Skills.First(s => s.Domain == lp.Domain);
            Assert.True(skill.Score < 80);
        });
        // Overall level
        Assert.NotEmpty(result.OverallLevel);
        // Encouragement
        Assert.NotEmpty(result.Encouragement);
        // Strongest vs weakest
        Assert.NotEqual(result.WeakestDomain, result.StrongestDomain);
    }
}
