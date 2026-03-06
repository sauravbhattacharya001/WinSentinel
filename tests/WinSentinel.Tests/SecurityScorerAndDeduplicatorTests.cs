using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

/// <summary>
/// Tests for SecurityScorer — score calculation, grading, and color assignment.
/// </summary>
public class SecurityScorerTests
{
    // ── Helper ──

    private static AuditResult MakeResult(params Severity[] severities)
    {
        var result = new AuditResult
        {
            ModuleName = "TestModule",
            Category = "Test"
        };
        foreach (var sev in severities)
        {
            result.Findings.Add(new Finding
            {
                Title = $"Finding-{sev}",
                Description = "desc",
                Severity = sev,
                Category = "Test"
            });
        }
        return result;
    }

    private static SecurityReport MakeReport(params AuditResult[] results)
    {
        return new SecurityReport
        {
            Results = results.ToList()
        };
    }

    // ── CalculateCategoryScore ─────────────────────────────────────

    [Fact]
    public void CategoryScore_NoFindings_Returns100()
    {
        var result = MakeResult();
        Assert.Equal(100, SecurityScorer.CalculateCategoryScore(result));
    }

    [Fact]
    public void CategoryScore_OneCritical_Returns80()
    {
        var result = MakeResult(Severity.Critical);
        Assert.Equal(80, SecurityScorer.CalculateCategoryScore(result));
    }

    [Fact]
    public void CategoryScore_OneWarning_Returns95()
    {
        var result = MakeResult(Severity.Warning);
        Assert.Equal(95, SecurityScorer.CalculateCategoryScore(result));
    }

    [Fact]
    public void CategoryScore_InfoOnly_Returns100()
    {
        var result = MakeResult(Severity.Info, Severity.Info, Severity.Info);
        Assert.Equal(100, SecurityScorer.CalculateCategoryScore(result));
    }

    [Fact]
    public void CategoryScore_PassOnly_Returns100()
    {
        var result = MakeResult(Severity.Pass, Severity.Pass);
        Assert.Equal(100, SecurityScorer.CalculateCategoryScore(result));
    }

    [Fact]
    public void CategoryScore_MultipleCritical_Cumulative()
    {
        // 3 criticals = 3 * 20 = 60 deducted → 40
        var result = MakeResult(Severity.Critical, Severity.Critical, Severity.Critical);
        Assert.Equal(40, SecurityScorer.CalculateCategoryScore(result));
    }

    [Fact]
    public void CategoryScore_FloorAtZero()
    {
        // 6 criticals = 120 deducted → clamped to 0
        var result = MakeResult(
            Severity.Critical, Severity.Critical, Severity.Critical,
            Severity.Critical, Severity.Critical, Severity.Critical);
        Assert.Equal(0, SecurityScorer.CalculateCategoryScore(result));
    }

    [Fact]
    public void CategoryScore_MixedSeverities()
    {
        // 1 Critical (20) + 2 Warnings (10) + 1 Info (0) + 1 Pass (0) = 30 deducted → 70
        var result = MakeResult(
            Severity.Critical, Severity.Warning, Severity.Warning,
            Severity.Info, Severity.Pass);
        Assert.Equal(70, SecurityScorer.CalculateCategoryScore(result));
    }

    [Fact]
    public void CategoryScore_ManyWarnings()
    {
        // 20 warnings = 20 * 5 = 100 deducted → 0
        var severities = Enumerable.Repeat(Severity.Warning, 20).ToArray();
        var result = MakeResult(severities);
        Assert.Equal(0, SecurityScorer.CalculateCategoryScore(result));
    }

    // ── CalculateScore (overall) ──────────────────────────────────

    [Fact]
    public void OverallScore_EmptyReport_Returns100()
    {
        var report = MakeReport();
        Assert.Equal(100, SecurityScorer.CalculateScore(report));
    }

    [Fact]
    public void OverallScore_SingleModule_EqualsCategoryScore()
    {
        var result = MakeResult(Severity.Critical);
        var report = MakeReport(result);
        Assert.Equal(80, SecurityScorer.CalculateScore(report));
    }

    [Fact]
    public void OverallScore_MultipleModules_AveragesScores()
    {
        // Module A: 100, Module B: 80, Module C: 60 → average = 80
        var a = MakeResult(); // 100
        var b = MakeResult(Severity.Critical); // 80
        var c = MakeResult(Severity.Critical, Severity.Critical); // 60
        var report = MakeReport(a, b, c);
        Assert.Equal(80, SecurityScorer.CalculateScore(report));
    }

    [Fact]
    public void OverallScore_AllPerfect_Returns100()
    {
        var a = MakeResult(Severity.Pass);
        var b = MakeResult(Severity.Info);
        var c = MakeResult();
        var report = MakeReport(a, b, c);
        Assert.Equal(100, SecurityScorer.CalculateScore(report));
    }

    [Fact]
    public void OverallScore_Rounded()
    {
        // Module A: 95 (1 warning), Module B: 100 → average = 97.5 → rounds to 98
        var a = MakeResult(Severity.Warning);
        var b = MakeResult();
        var report = MakeReport(a, b);
        Assert.Equal(98, SecurityScorer.CalculateScore(report));
    }

    // ── GetGrade ──────────────────────────────────────────────────

    [Theory]
    [InlineData(100, "A")]
    [InlineData(95, "A")]
    [InlineData(90, "A")]
    [InlineData(89, "B")]
    [InlineData(80, "B")]
    [InlineData(79, "C")]
    [InlineData(70, "C")]
    [InlineData(69, "D")]
    [InlineData(60, "D")]
    [InlineData(59, "F")]
    [InlineData(0, "F")]
    public void GetGrade_Boundaries(int score, string expected)
    {
        Assert.Equal(expected, SecurityScorer.GetGrade(score));
    }

    // ── GetScoreColor ─────────────────────────────────────────────

    [Theory]
    [InlineData(100, "#4CAF50")]
    [InlineData(80, "#4CAF50")]
    [InlineData(79, "#FFC107")]
    [InlineData(60, "#FFC107")]
    [InlineData(59, "#FF9800")]
    [InlineData(40, "#FF9800")]
    [InlineData(39, "#F44336")]
    [InlineData(0, "#F44336")]
    public void GetScoreColor_Boundaries(int score, string expected)
    {
        Assert.Equal(expected, SecurityScorer.GetScoreColor(score));
    }
}

/// <summary>
/// Tests for FindingDeduplicator — similarity scoring, deduplication,
/// n-gram matching, and edge cases.
/// </summary>
public class FindingDeduplicatorTests
{
    // ── Helper ──

    private static Finding MakeFinding(
        string title,
        string description = "desc",
        Severity severity = Severity.Warning,
        string category = "Network",
        string? fixCommand = null)
    {
        return new Finding
        {
            Title = title,
            Description = description,
            Severity = severity,
            Category = category,
            FixCommand = fixCommand
        };
    }

    // ── Constructor validation ────────────────────────────────────

    [Theory]
    [InlineData(-0.1)]
    [InlineData(1.1)]
    public void Constructor_InvalidThreshold_Throws(double threshold)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new FindingDeduplicator(threshold));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(11)]
    public void Constructor_InvalidNgramSize_Throws(int ngramSize)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new FindingDeduplicator(ngramSize: ngramSize));
    }

    [Fact]
    public void Constructor_ValidBoundary_Succeeds()
    {
        var d1 = new FindingDeduplicator(0.0, 2);
        var d2 = new FindingDeduplicator(1.0, 10);
        Assert.NotNull(d1);
        Assert.NotNull(d2);
    }

    // ── NgramSimilarity ──────────────────────────────────────────

    [Fact]
    public void NgramSimilarity_IdenticalStrings_Returns1()
    {
        var dedup = new FindingDeduplicator();
        Assert.Equal(1.0, dedup.NgramSimilarity("hello world", "hello world"));
    }

    [Fact]
    public void NgramSimilarity_EmptyStrings_Returns0()
    {
        var dedup = new FindingDeduplicator();
        Assert.Equal(0.0, dedup.NgramSimilarity("", "hello"));
        Assert.Equal(0.0, dedup.NgramSimilarity("hello", ""));
        Assert.Equal(0.0, dedup.NgramSimilarity("", ""));
    }

    [Fact]
    public void NgramSimilarity_NullStrings_Returns0()
    {
        var dedup = new FindingDeduplicator();
        Assert.Equal(0.0, dedup.NgramSimilarity(null!, "hello"));
        Assert.Equal(0.0, dedup.NgramSimilarity("hello", null!));
    }

    [Fact]
    public void NgramSimilarity_SimilarStrings_HighScore()
    {
        var dedup = new FindingDeduplicator();
        double sim = dedup.NgramSimilarity("firewall disabled", "firewall is disabled");
        Assert.True(sim > 0.5, $"Expected > 0.5, got {sim}");
    }

    [Fact]
    public void NgramSimilarity_DifferentStrings_LowScore()
    {
        var dedup = new FindingDeduplicator();
        double sim = dedup.NgramSimilarity("firewall disabled", "bluetooth vulnerability");
        Assert.True(sim < 0.3, $"Expected < 0.3, got {sim}");
    }

    [Fact]
    public void NgramSimilarity_ShortStrings_BelowNgramSize()
    {
        // Strings shorter than n-gram size (5) produce empty n-gram sets,
        // so non-identical short strings should score 0.
        var dedup = new FindingDeduplicator(ngramSize: 5);
        double sim = dedup.NgramSimilarity("abc", "abd");
        Assert.Equal(0.0, sim);
    }

    // ── ComputeSimilarity ────────────────────────────────────────

    [Fact]
    public void ComputeSimilarity_IdenticalFindings_HighScore()
    {
        var dedup = new FindingDeduplicator();
        var a = MakeFinding("Firewall disabled", "Windows Firewall is off",
            Severity.Critical, "Network", "netsh advfirewall set allprofiles state on");
        var b = MakeFinding("Firewall disabled", "Windows Firewall is off",
            Severity.Critical, "Network", "netsh advfirewall set allprofiles state on");

        var (score, reason) = dedup.ComputeSimilarity(a, b);
        Assert.True(score >= 0.85, $"Expected >= 0.85, got {score}");
        Assert.Contains("exact title", reason);
    }

    [Fact]
    public void ComputeSimilarity_DifferentFindings_LowScore()
    {
        var dedup = new FindingDeduplicator();
        var a = MakeFinding("Firewall disabled", "Firewall is off",
            Severity.Critical, "Network");
        var b = MakeFinding("Weak password policy", "Passwords too short",
            Severity.Warning, "Account");

        var (score, _) = dedup.ComputeSimilarity(a, b);
        Assert.True(score < 0.5, $"Expected < 0.5, got {score}");
    }

    [Fact]
    public void ComputeSimilarity_SameCategory_BoostsScore()
    {
        var dedup = new FindingDeduplicator();
        var a = MakeFinding("Issue A", "desc", Severity.Warning, "Network");
        var b = MakeFinding("Issue B", "desc", Severity.Warning, "Network");

        var (withCat, _) = dedup.ComputeSimilarity(a, b);

        var c = MakeFinding("Issue A", "desc", Severity.Warning, "Network");
        var d = MakeFinding("Issue B", "desc", Severity.Warning, "Account");

        var (withoutCat, _) = dedup.ComputeSimilarity(c, d);

        Assert.True(withCat > withoutCat,
            $"Same category ({withCat}) should score higher than different ({withoutCat})");
    }

    [Fact]
    public void ComputeSimilarity_SameFixCommand_BoostsScore()
    {
        var dedup = new FindingDeduplicator();
        var a = MakeFinding("Issue A", "desc", Severity.Warning, "Network",
            "netsh advfirewall set allprofiles state on");
        var b = MakeFinding("Issue B", "desc", Severity.Warning, "Network",
            "netsh advfirewall set allprofiles state on");

        var (score, reason) = dedup.ComputeSimilarity(a, b);
        Assert.Contains("same fix", reason);
    }

    [Fact]
    public void ComputeSimilarity_CaseInsensitiveTitle()
    {
        var dedup = new FindingDeduplicator();
        var a = MakeFinding("Firewall Disabled");
        var b = MakeFinding("firewall disabled");

        var (score, reason) = dedup.ComputeSimilarity(a, b);
        Assert.Contains("exact title", reason);
    }

    [Fact]
    public void ComputeSimilarity_ScoreCappedAt1()
    {
        var dedup = new FindingDeduplicator();
        var a = MakeFinding("Same Title", "Same Description",
            Severity.Critical, "Same", "Same Fix");
        var b = MakeFinding("Same Title", "Same Description",
            Severity.Critical, "Same", "Same Fix");

        var (score, _) = dedup.ComputeSimilarity(a, b);
        Assert.True(score <= 1.0, $"Score should be <= 1.0, got {score}");
    }

    // ── Deduplicate ──────────────────────────────────────────────

    [Fact]
    public void Deduplicate_NullInput_Throws()
    {
        var dedup = new FindingDeduplicator();
        Assert.Throws<ArgumentNullException>(() => dedup.Deduplicate(null!));
    }

    [Fact]
    public void Deduplicate_EmptyList_ReturnsEmpty()
    {
        var dedup = new FindingDeduplicator();
        var result = dedup.Deduplicate(Array.Empty<Finding>());
        Assert.Empty(result.Deduplicated);
        Assert.Equal(0, result.OriginalCount);
        Assert.Equal(0, result.DuplicatesRemoved);
        Assert.Equal(0.0, result.ReductionPercent);
    }

    [Fact]
    public void Deduplicate_SingleFinding_NoDuplicates()
    {
        var dedup = new FindingDeduplicator();
        var findings = new[] { MakeFinding("Only one") };
        var result = dedup.Deduplicate(findings);
        Assert.Single(result.Deduplicated);
        Assert.Empty(result.Groups);
        Assert.Equal(0, result.DuplicatesRemoved);
    }

    [Fact]
    public void Deduplicate_ExactDuplicates_Grouped()
    {
        var dedup = new FindingDeduplicator();
        var findings = new[]
        {
            MakeFinding("Firewall disabled", "Firewall is off", Severity.Critical, "Network"),
            MakeFinding("Firewall disabled", "Firewall is off", Severity.Warning, "Network"),
        };
        var result = dedup.Deduplicate(findings);
        Assert.Single(result.Deduplicated);
        Assert.Equal(1, result.DuplicatesRemoved);
        Assert.Single(result.Groups);
    }

    [Fact]
    public void Deduplicate_KeepsHigherSeverity()
    {
        var dedup = new FindingDeduplicator();
        var findings = new[]
        {
            MakeFinding("Firewall disabled", "Firewall is off", Severity.Warning, "Network"),
            MakeFinding("Firewall disabled", "Firewall is off", Severity.Critical, "Network"),
        };
        var result = dedup.Deduplicate(findings);
        Assert.Single(result.Deduplicated);
        Assert.Equal(Severity.Critical, result.Deduplicated[0].Severity);
    }

    [Fact]
    public void Deduplicate_DifferentFindings_NoDedup()
    {
        var dedup = new FindingDeduplicator();
        var findings = new[]
        {
            MakeFinding("Firewall disabled", "Firewall off", Severity.Critical, "Network"),
            MakeFinding("Weak password policy", "Short passwords", Severity.Warning, "Account"),
            MakeFinding("Outdated antivirus", "Signatures stale", Severity.Warning, "Defender"),
        };
        var result = dedup.Deduplicate(findings);
        Assert.Equal(3, result.DeduplicatedCount);
        Assert.Equal(0, result.DuplicatesRemoved);
    }

    [Fact]
    public void Deduplicate_ThreeDuplicates_OneGroup()
    {
        var dedup = new FindingDeduplicator();
        var findings = new[]
        {
            MakeFinding("Firewall disabled", "fw off", Severity.Warning, "Network"),
            MakeFinding("Firewall disabled", "fw off", Severity.Critical, "Network"),
            MakeFinding("Firewall disabled", "fw off", Severity.Info, "Network"),
        };
        var result = dedup.Deduplicate(findings);
        Assert.Single(result.Deduplicated);
        Assert.Equal(2, result.DuplicatesRemoved);
        Assert.Single(result.Groups);
        Assert.Equal(2, result.Groups[0].Duplicates.Count);
    }

    [Fact]
    public void Deduplicate_ReductionPercent_Correct()
    {
        var dedup = new FindingDeduplicator();
        var findings = new[]
        {
            MakeFinding("Same", "d", Severity.Warning, "A"),
            MakeFinding("Same", "d", Severity.Warning, "A"),
            MakeFinding("Different", "d", Severity.Warning, "B"),
            MakeFinding("Another", "d", Severity.Warning, "C"),
        };
        var result = dedup.Deduplicate(findings);
        Assert.Equal(4, result.OriginalCount);
        Assert.Equal(3, result.DeduplicatedCount);
        Assert.Equal(1, result.DuplicatesRemoved);
        Assert.Equal(25.0, result.ReductionPercent);
    }

    [Fact]
    public void Deduplicate_HighThreshold_NoDuplicates()
    {
        // With threshold = 1.0, only perfectly identical findings match
        var dedup = new FindingDeduplicator(threshold: 1.0);
        var findings = new[]
        {
            MakeFinding("Firewall disabled", "Firewall is off", Severity.Warning, "Network"),
            MakeFinding("Firewall disabled", "Firewall is off", Severity.Critical, "Network"),
        };
        var result = dedup.Deduplicate(findings);
        // Different severity → score < 1.0 → no dedup
        Assert.Equal(2, result.DeduplicatedCount);
    }

    [Fact]
    public void Deduplicate_LowThreshold_AggressiveDedup()
    {
        var dedup = new FindingDeduplicator(threshold: 0.1);
        var findings = new[]
        {
            MakeFinding("Issue A", "desc", Severity.Warning, "Network"),
            MakeFinding("Issue B", "desc", Severity.Warning, "Network"),
        };
        var result = dedup.Deduplicate(findings);
        // Same category (0.15) + same severity (0.05) = 0.20 >= 0.1 threshold
        Assert.True(result.DuplicatesRemoved > 0,
            "Low threshold should catch more duplicates");
    }

    // ── DeduplicateAcrossModules ─────────────────────────────────

    [Fact]
    public void DeduplicateAcrossModules_NullInput_Throws()
    {
        var dedup = new FindingDeduplicator();
        Assert.Throws<ArgumentNullException>(() =>
            dedup.DeduplicateAcrossModules(null!));
    }

    [Fact]
    public void DeduplicateAcrossModules_SkipsPassFindings()
    {
        var dedup = new FindingDeduplicator();
        var results = new[]
        {
            new AuditResult
            {
                ModuleName = "A", Category = "Network",
                Findings = new List<Finding>
                {
                    MakeFinding("Pass finding", "ok", Severity.Pass, "Network"),
                    MakeFinding("Real issue", "bad", Severity.Critical, "Network"),
                }
            }
        };
        var result = dedup.DeduplicateAcrossModules(results);
        // Pass findings are excluded from deduplication
        Assert.Single(result.Deduplicated);
        Assert.Equal("Real issue", result.Deduplicated[0].Title);
    }

    [Fact]
    public void DeduplicateAcrossModules_CrossModuleDuplicates()
    {
        var dedup = new FindingDeduplicator();
        var results = new[]
        {
            new AuditResult
            {
                ModuleName = "Firewall", Category = "Network",
                Findings = new List<Finding>
                {
                    MakeFinding("Firewall disabled", "fw off", Severity.Critical, "Network"),
                }
            },
            new AuditResult
            {
                ModuleName = "Network", Category = "Network",
                Findings = new List<Finding>
                {
                    MakeFinding("Firewall disabled", "fw off", Severity.Warning, "Network"),
                }
            }
        };
        var result = dedup.DeduplicateAcrossModules(results);
        Assert.Single(result.Deduplicated);
        Assert.Equal(Severity.Critical, result.Deduplicated[0].Severity);
    }

    [Fact]
    public void Deduplicate_AverageSimilarity_InRange()
    {
        var dedup = new FindingDeduplicator();
        var findings = new[]
        {
            MakeFinding("Firewall disabled", "fw off", Severity.Critical, "Network"),
            MakeFinding("Firewall disabled", "fw off", Severity.Warning, "Network"),
        };
        var result = dedup.Deduplicate(findings);
        Assert.Single(result.Groups);
        Assert.InRange(result.Groups[0].AverageSimilarity, 0.0, 1.0);
    }

    // ── Edge cases ───────────────────────────────────────────────

    [Fact]
    public void Deduplicate_LargeInput_Handles()
    {
        // Verify deduplicator handles large input without errors.
        // Use a high threshold so nothing gets grouped — we're testing performance, not grouping.
        var dedup = new FindingDeduplicator(threshold: 0.99);
        var findings = Enumerable.Range(0, 100)
            .Select(i => MakeFinding($"Finding {i}", $"Description {i}",
                i % 2 == 0 ? Severity.Warning : Severity.Critical, "Test"))
            .ToList();
        var result = dedup.Deduplicate(findings);
        Assert.Equal(100, result.OriginalCount);
        // With threshold 0.99, similar-but-not-identical findings should not group
        Assert.True(result.DeduplicatedCount >= 50,
            $"High threshold should limit dedup; got {result.DeduplicatedCount}/100");
    }

    [Fact]
    public void Deduplicate_EmptyDescriptions()
    {
        var dedup = new FindingDeduplicator();
        var a = new Finding
        {
            Title = "Issue",
            Description = "",
            Severity = Severity.Warning,
            Category = "Test"
        };
        var b = new Finding
        {
            Title = "Issue",
            Description = "",
            Severity = Severity.Warning,
            Category = "Test"
        };
        var result = dedup.Deduplicate(new[] { a, b });
        Assert.Single(result.Deduplicated);
    }
}
