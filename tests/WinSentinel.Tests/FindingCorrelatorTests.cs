using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

/// <summary>
/// Tests for <see cref="FindingCorrelator"/> — rule management, correlation
/// analysis, pattern matching, and severity amplification.
/// </summary>
public class FindingCorrelatorTests
{
    // ── Helpers ──────────────────────────────────────────────────

    private static SecurityReport MakeReport(params Finding[] findings)
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        result.Findings.AddRange(findings);
        return new SecurityReport { Results = [result] };
    }

    private static Finding MakeFinding(string title, Severity severity,
        string category = "General", string description = "desc") => new()
    {
        Title = title,
        Description = description,
        Severity = severity,
        Category = category
    };

    private static FindingCorrelator.CorrelationRule MakeRule(
        string id, string[] patterns, string[] categories,
        Severity amplified = Severity.Critical) => new(
        id, $"Rule {id}", "Test rule", patterns, categories,
        amplified, "Fix it");

    // ── Constructor / Built-in rules ────────────────────────────

    [Fact]
    public void Constructor_LoadsBuiltInRules()
    {
        var correlator = new FindingCorrelator();
        Assert.True(correlator.RuleCount >= 8, "Should load at least 8 built-in rules");
    }

    [Fact]
    public void GetRules_ReturnsReadOnlyCopy()
    {
        var correlator = new FindingCorrelator();
        var rules = correlator.GetRules();
        Assert.True(rules.Count > 0);
        // Verify it's read-only
        Assert.IsAssignableFrom<IReadOnlyList<FindingCorrelator.CorrelationRule>>(rules);
    }

    // ── AddRule ─────────────────────────────────────────────────

    [Fact]
    public void AddRule_ValidRule_IncreasesCount()
    {
        var correlator = new FindingCorrelator();
        var before = correlator.RuleCount;
        correlator.AddRule(MakeRule("CUSTOM-1", ["test"], []));
        Assert.Equal(before + 1, correlator.RuleCount);
    }

    [Fact]
    public void AddRule_NullRule_Throws()
    {
        var correlator = new FindingCorrelator();
        Assert.Throws<ArgumentNullException>(() => correlator.AddRule(null!));
    }

    [Fact]
    public void AddRule_EmptyId_Throws()
    {
        var correlator = new FindingCorrelator();
        var rule = new FindingCorrelator.CorrelationRule(
            "", "Name", "Desc", ["p"], [], Severity.Warning, "rec");
        Assert.Throws<ArgumentException>(() => correlator.AddRule(rule));
    }

    [Fact]
    public void AddRule_EmptyName_Throws()
    {
        var correlator = new FindingCorrelator();
        var rule = new FindingCorrelator.CorrelationRule(
            "X", " ", "Desc", ["p"], [], Severity.Warning, "rec");
        Assert.Throws<ArgumentException>(() => correlator.AddRule(rule));
    }

    [Fact]
    public void AddRule_NoPatternsOrCategories_Throws()
    {
        var correlator = new FindingCorrelator();
        var rule = new FindingCorrelator.CorrelationRule(
            "X", "Name", "Desc", [], [], Severity.Warning, "rec");
        Assert.Throws<ArgumentException>(() => correlator.AddRule(rule));
    }

    [Fact]
    public void AddRule_DuplicateId_Throws()
    {
        var correlator = new FindingCorrelator();
        correlator.AddRule(MakeRule("DUP-1", ["a"], []));
        Assert.Throws<ArgumentException>(() =>
            correlator.AddRule(MakeRule("DUP-1", ["b"], [])));
    }

    [Fact]
    public void AddRule_ExceedsMaxRules_Throws()
    {
        var correlator = new FindingCorrelator();
        // Fill up to max (some already loaded as built-ins)
        var current = correlator.RuleCount;
        for (int i = current; i < FindingCorrelator.MaxRules; i++)
            correlator.AddRule(MakeRule($"FILL-{i}", ["x"], []));

        Assert.Equal(FindingCorrelator.MaxRules, correlator.RuleCount);
        Assert.Throws<InvalidOperationException>(() =>
            correlator.AddRule(MakeRule("OVERFLOW", ["y"], [])));
    }

    // ── RemoveRule ──────────────────────────────────────────────

    [Fact]
    public void RemoveRule_ExistingRule_ReturnsTrue()
    {
        var correlator = new FindingCorrelator();
        correlator.AddRule(MakeRule("REM-1", ["x"], []));
        Assert.True(correlator.RemoveRule("REM-1"));
    }

    [Fact]
    public void RemoveRule_NonExistent_ReturnsFalse()
    {
        var correlator = new FindingCorrelator();
        Assert.False(correlator.RemoveRule("NOPE"));
    }

    // ── Analyze: basic behavior ─────────────────────────────────

    [Fact]
    public void Analyze_NullReport_Throws()
    {
        var correlator = new FindingCorrelator();
        Assert.Throws<ArgumentNullException>(() => correlator.Analyze(null!));
    }

    [Fact]
    public void Analyze_EmptyReport_NoCorrelations()
    {
        var correlator = new FindingCorrelator();
        var report = new SecurityReport();
        var result = correlator.Analyze(report);

        Assert.Equal(0, result.TotalFindings);
        Assert.Equal(0, result.CorrelationsFound);
        Assert.Empty(result.Matches);
        Assert.Equal(0, result.RiskAmplification);
    }

    [Fact]
    public void Analyze_PassFindingsOnly_Excluded()
    {
        var correlator = new FindingCorrelator();
        var report = MakeReport(
            MakeFinding("Defender enabled", Severity.Pass),
            MakeFinding("Firewall enabled", Severity.Pass));
        var result = correlator.Analyze(report);

        Assert.Equal(0, result.TotalFindings);
        Assert.Equal(0, result.CorrelationsFound);
    }

    // ── Analyze: pattern matching ───────────────────────────────

    [Fact]
    public void Analyze_MatchesBuiltInCORR001_DefenderAndFirewall()
    {
        var correlator = new FindingCorrelator();
        var report = MakeReport(
            MakeFinding("Windows Defender disabled", Severity.Warning),
            MakeFinding("Windows Firewall off", Severity.Warning));

        var result = correlator.Analyze(report);

        var corr001 = result.Matches.FirstOrDefault(m => m.Rule.Id == "CORR-001");
        Assert.NotNull(corr001);
        Assert.Equal(Severity.Critical, corr001.AmplifiedSeverity);
        Assert.Equal(Severity.Warning, corr001.OriginalMaxSeverity);
        Assert.Equal(2, corr001.MatchedFindings.Count);
    }

    [Fact]
    public void Analyze_SinglePatternMatch_NoCorrelation()
    {
        var correlator = new FindingCorrelator();
        // Only Defender finding, no Firewall — CORR-001 shouldn't match
        var report = MakeReport(
            MakeFinding("Windows Defender disabled", Severity.Warning));

        var result = correlator.Analyze(report);
        var corr001 = result.Matches.FirstOrDefault(m => m.Rule.Id == "CORR-001");
        Assert.Null(corr001);
    }

    [Fact]
    public void Analyze_PatternMatchIsCase_Insensitive()
    {
        var correlator = new FindingCorrelator();
        var report = MakeReport(
            MakeFinding("WINDOWS DEFENDER ISSUE", Severity.Warning),
            MakeFinding("windows firewall problem", Severity.Warning));

        var result = correlator.Analyze(report);
        var corr001 = result.Matches.FirstOrDefault(m => m.Rule.Id == "CORR-001");
        Assert.NotNull(corr001);
    }

    [Fact]
    public void Analyze_PatternMatchInDescription_AlsoWorks()
    {
        var correlator = new FindingCorrelator();
        var report = MakeReport(
            MakeFinding("AV Issue", Severity.Warning,
                description: "Windows Defender is turned off"),
            MakeFinding("Network Issue", Severity.Warning,
                description: "Firewall rules too permissive"));

        var result = correlator.Analyze(report);
        var corr001 = result.Matches.FirstOrDefault(m => m.Rule.Id == "CORR-001");
        Assert.NotNull(corr001);
    }

    // ── Distinct finding per pattern ────────────────────────────

    [Fact]
    public void Analyze_SingleFindingWithBothPatterns_DoesNotMatch()
    {
        // A single finding containing both "Defender" and "Firewall" should NOT
        // satisfy CORR-001 because each pattern requires a distinct finding.
        var correlator = new FindingCorrelator();
        var report = MakeReport(
            MakeFinding("Windows Defender Firewall disabled", Severity.Warning));

        var result = correlator.Analyze(report);
        var corr001 = result.Matches.FirstOrDefault(m => m.Rule.Id == "CORR-001");
        Assert.Null(corr001);
    }

    // ── Category matching ───────────────────────────────────────

    [Fact]
    public void Analyze_CustomRule_RequiresCategories()
    {
        var correlator = new FindingCorrelator();
        correlator.AddRule(MakeRule("CAT-1",
            patterns: ["weak"],
            categories: ["Network"],
            amplified: Severity.Critical));

        // Finding matches pattern but wrong category
        var report = MakeReport(
            MakeFinding("weak config", Severity.Warning, category: "Privacy"));
        var result = correlator.Analyze(report);
        var cat1 = result.Matches.FirstOrDefault(m => m.Rule.Id == "CAT-1");
        Assert.Null(cat1);

        // Now with correct category
        var report2 = MakeReport(
            MakeFinding("weak config", Severity.Warning, category: "Network"));
        var result2 = correlator.Analyze(report2);
        var cat1b = result2.Matches.FirstOrDefault(m => m.Rule.Id == "CAT-1");
        Assert.NotNull(cat1b);
    }

    // ── Severity amplification ──────────────────────────────────

    [Fact]
    public void Analyze_AmplificationCount_CorrectWhenAmplified()
    {
        var correlator = new FindingCorrelator();
        var report = MakeReport(
            MakeFinding("Defender disabled", Severity.Warning),
            MakeFinding("Firewall disabled", Severity.Warning));

        var result = correlator.Analyze(report);

        // CORR-001 amplifies Warning → Critical, so RiskAmplification ≥ 1
        Assert.True(result.RiskAmplification >= 1);
    }

    [Fact]
    public void Analyze_NoAmplification_WhenAlreadyCritical()
    {
        var correlator = new FindingCorrelator();
        // Custom rule that amplifies to Warning — but findings are already Critical
        correlator.AddRule(MakeRule("NOAMP-1", ["testA"], [],
            amplified: Severity.Warning));

        var report = MakeReport(
            MakeFinding("testA issue", Severity.Critical));
        var result = correlator.Analyze(report);

        var match = result.Matches.FirstOrDefault(m => m.Rule.Id == "NOAMP-1");
        Assert.NotNull(match);
        // OriginalMax (Critical) > AmplifiedSeverity (Warning), so not counted as amplification
        Assert.Equal(0, result.Matches.Count(m =>
            m.Rule.Id == "NOAMP-1" && m.AmplifiedSeverity > m.OriginalMaxSeverity));
    }

    // ── Recommendations ─────────────────────────────────────────

    [Fact]
    public void Analyze_Recommendations_ContainsMatchedRuleRecommendations()
    {
        var correlator = new FindingCorrelator();
        var report = MakeReport(
            MakeFinding("Defender disabled", Severity.Warning),
            MakeFinding("Firewall disabled", Severity.Warning));

        var result = correlator.Analyze(report);

        Assert.Contains(result.Recommendations,
            r => r.Contains("Defender") && r.Contains("Firewall"));
    }

    [Fact]
    public void Analyze_Recommendations_Deduplicated()
    {
        var correlator = new FindingCorrelator();
        // Add two rules with the same recommendation
        correlator.AddRule(new FindingCorrelator.CorrelationRule(
            "DEDUP-1", "Rule A", "desc", ["testdup"], [],
            Severity.Warning, "Same recommendation"));
        correlator.AddRule(new FindingCorrelator.CorrelationRule(
            "DEDUP-2", "Rule B", "desc", ["testdup"], [],
            Severity.Warning, "Same recommendation"));

        var report = MakeReport(
            MakeFinding("testdup a", Severity.Warning),
            MakeFinding("testdup b", Severity.Info));
        var result = correlator.Analyze(report);

        // Ensure no duplicate recommendations
        var matching = result.Recommendations.Count(r => r == "Same recommendation");
        Assert.True(matching <= 1);
    }

    // ── Sorting: critical first ─────────────────────────────────

    [Fact]
    public void Analyze_Matches_SortedBySeverityDescending()
    {
        var correlator = new FindingCorrelator();
        correlator.AddRule(new FindingCorrelator.CorrelationRule(
            "SORT-LO", "Low", "desc", ["sortlo"], [],
            Severity.Info, "Low priority"));
        correlator.AddRule(new FindingCorrelator.CorrelationRule(
            "SORT-HI", "High", "desc", ["sorthi"], [],
            Severity.Critical, "High priority"));

        var report = MakeReport(
            MakeFinding("sortlo issue", Severity.Warning),
            MakeFinding("sorthi issue", Severity.Warning));
        var result = correlator.Analyze(report);

        if (result.Matches.Count >= 2)
        {
            // First match should be Critical-amplified
            Assert.True(result.Matches[0].AmplifiedSeverity >=
                         result.Matches[1].AmplifiedSeverity);
        }
    }

    // ── Multi-module report ─────────────────────────────────────

    [Fact]
    public void Analyze_FindingsAcrossModules_AreCorrelated()
    {
        var correlator = new FindingCorrelator();
        var report = new SecurityReport
        {
            Results =
            [
                new AuditResult
                {
                    ModuleName = "Antivirus", Category = "Security",
                    Findings = [MakeFinding("Defender disabled", Severity.Warning)]
                },
                new AuditResult
                {
                    ModuleName = "Network", Category = "Network",
                    Findings = [MakeFinding("Firewall off", Severity.Warning)]
                }
            ]
        };

        var result = correlator.Analyze(report);
        var corr001 = result.Matches.FirstOrDefault(m => m.Rule.Id == "CORR-001");
        Assert.NotNull(corr001);
    }

    // ── TotalFindings excludes Pass ─────────────────────────────

    [Fact]
    public void Analyze_TotalFindings_ExcludesPassSeverity()
    {
        var correlator = new FindingCorrelator();
        var report = MakeReport(
            MakeFinding("OK check", Severity.Pass),
            MakeFinding("Some warning", Severity.Warning),
            MakeFinding("Info note", Severity.Info));

        var result = correlator.Analyze(report);
        Assert.Equal(2, result.TotalFindings);
    }
}
