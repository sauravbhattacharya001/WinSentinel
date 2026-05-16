using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests;

/// <summary>
/// Tests for <see cref="FindingCorrelator"/>.
///
/// Covers built-in rule registration, custom rule lifecycle, validation,
/// match semantics (distinct-per-pattern, case-insensitive, description
/// fallback), category requirements, severity amplification accounting,
/// match sorting, and the Pass-finding exclusion contract.
/// </summary>
public class FindingCorrelatorTests
{
    private readonly FindingCorrelator _correlator = new();

    // ---------- Helpers ----------

    private static SecurityReport ReportWith(params Finding[] findings) => new()
    {
        Results = new List<AuditResult>
        {
            new()
            {
                ModuleName = "Test",
                Category = "Test",
                Findings = findings.ToList(),
            }
        }
    };

    private static FindingCorrelator.CorrelationRule MakeRule(
        string id = "TEST-1",
        string name = "Test Rule",
        string[]? patterns = null,
        string[]? categories = null,
        Severity amplified = Severity.Critical) => new(
            id,
            name,
            "test description",
            patterns ?? Array.Empty<string>(),
            categories ?? Array.Empty<string>(),
            amplified,
            "test remediation");

    // ---------- Construction / built-in rules ----------

    [Fact]
    public void Constructor_LoadsAllBuiltInRules()
    {
        // 8 built-in rules (CORR-001 .. CORR-008) per LoadBuiltInRules().
        Assert.Equal(8, _correlator.RuleCount);
        var ids = _correlator.GetRules().Select(r => r.Id).ToList();
        for (int i = 1; i <= 8; i++)
            Assert.Contains($"CORR-00{i}", ids);
    }

    [Fact]
    public void GetRules_ReturnsReadOnlyView()
    {
        var rules = _correlator.GetRules();
        Assert.IsAssignableFrom<IReadOnlyList<FindingCorrelator.CorrelationRule>>(rules);
    }

    // ---------- AddRule validation ----------

    [Fact]
    public void AddRule_NullRule_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _correlator.AddRule(null!));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void AddRule_EmptyId_Throws(string id)
    {
        var rule = MakeRule(id: id, patterns: new[] { "x" });
        Assert.Throws<ArgumentException>(() => _correlator.AddRule(rule));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void AddRule_EmptyName_Throws(string name)
    {
        var rule = MakeRule(name: name, patterns: new[] { "x" });
        Assert.Throws<ArgumentException>(() => _correlator.AddRule(rule));
    }

    [Fact]
    public void AddRule_NoPatternsNoCategories_Throws()
    {
        var rule = MakeRule(); // both empty
        Assert.Throws<ArgumentException>(() => _correlator.AddRule(rule));
    }

    [Fact]
    public void AddRule_DuplicateId_Throws()
    {
        // CORR-001 is already a built-in.
        var dup = MakeRule(id: "CORR-001", patterns: new[] { "x" });
        Assert.Throws<ArgumentException>(() => _correlator.AddRule(dup));
    }

    [Fact]
    public void AddRule_BeyondMaxRules_Throws()
    {
        var fresh = new FindingCorrelator();
        // Replace built-ins with predictable count up to MaxRules.
        foreach (var r in fresh.GetRules().ToList())
            fresh.RemoveRule(r.Id);
        Assert.Equal(0, fresh.RuleCount);

        for (int i = 0; i < FindingCorrelator.MaxRules; i++)
            fresh.AddRule(MakeRule(id: $"R-{i}", patterns: new[] { "x" }));

        Assert.Equal(FindingCorrelator.MaxRules, fresh.RuleCount);
        Assert.Throws<InvalidOperationException>(() =>
            fresh.AddRule(MakeRule(id: "R-overflow", patterns: new[] { "x" })));
    }

    [Fact]
    public void AddRule_CategoryOnly_IsAccepted()
    {
        _correlator.AddRule(MakeRule(id: "CAT-ONLY", categories: new[] { "Network" }));
        Assert.Contains(_correlator.GetRules(), r => r.Id == "CAT-ONLY");
    }

    // ---------- RemoveRule ----------

    [Fact]
    public void RemoveRule_ExistingId_ReturnsTrueAndRemoves()
    {
        Assert.True(_correlator.RemoveRule("CORR-001"));
        Assert.DoesNotContain(_correlator.GetRules(), r => r.Id == "CORR-001");
        Assert.Equal(7, _correlator.RuleCount);
    }

    [Fact]
    public void RemoveRule_UnknownId_ReturnsFalse()
    {
        Assert.False(_correlator.RemoveRule("NO-SUCH-RULE"));
        Assert.Equal(8, _correlator.RuleCount);
    }

    // ---------- Analyze: argument validation ----------

    [Fact]
    public void Analyze_NullReport_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _correlator.Analyze(null!));
    }

    // ---------- Analyze: built-in behavior ----------

    [Fact]
    public void Analyze_EmptyReport_NoMatches()
    {
        var result = _correlator.Analyze(new SecurityReport());
        Assert.Equal(0, result.TotalFindings);
        Assert.Equal(0, result.CorrelationsFound);
        Assert.Empty(result.Matches);
        Assert.Empty(result.Recommendations);
        Assert.Equal(0, result.RiskAmplification);
    }

    [Fact]
    public void Analyze_ExcludesPassFindingsFromTotals()
    {
        // Two real findings, three passing — only the two real ones should count.
        var report = ReportWith(
            Finding.Pass("All good A", "ok", "Network"),
            Finding.Pass("All good B", "ok", "System"),
            Finding.Pass("All good C", "ok", "System"),
            Finding.Warning("Some issue", "issue", "Network"),
            Finding.Critical("Another issue", "issue", "System"));

        var result = _correlator.Analyze(report);
        Assert.Equal(2, result.TotalFindings);
    }

    [Fact]
    public void Analyze_DefenderAndFirewallDown_TriggersCORR001()
    {
        var report = ReportWith(
            Finding.Critical("Windows Defender disabled", "AV is off", "Antivirus"),
            Finding.Critical("Windows Firewall disabled", "FW is off", "Network"));

        var result = _correlator.Analyze(report);
        var corr1 = result.Matches.SingleOrDefault(m => m.Rule.Id == "CORR-001");
        Assert.NotNull(corr1);
        Assert.Equal(2, corr1!.MatchedFindings.Count);
        Assert.Equal(Severity.Critical, corr1.OriginalMaxSeverity);
        Assert.Equal(Severity.Critical, corr1.AmplifiedSeverity);
    }

    [Fact]
    public void Analyze_SingleFindingMentioningBothKeywords_DoesNotSatisfyTwoPatterns()
    {
        // The "distinct finding per pattern" rule: this single finding mentions
        // both "Defender" and "Firewall" but must NOT satisfy CORR-001 alone.
        var report = ReportWith(
            Finding.Critical(
                "Windows Defender Firewall disabled",
                "The integrated Defender Firewall feature is off",
                "Network"));

        var result = _correlator.Analyze(report);
        Assert.DoesNotContain(result.Matches, m => m.Rule.Id == "CORR-001");
    }

    [Fact]
    public void Analyze_PatternMatchingIsCaseInsensitive()
    {
        var report = ReportWith(
            Finding.Warning("event log access denied", "perm issue", "Logging"),
            Finding.Warning("Audit policy missing", "no policy", "Audit"));

        var result = _correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "CORR-004");
    }

    [Fact]
    public void Analyze_PatternMatchesInDescription_WhenNotInTitle()
    {
        var report = ReportWith(
            Finding.Critical("AV inactive", "Microsoft Defender service is stopped", "Antivirus"),
            Finding.Critical("Perimeter open", "Windows Firewall profile is off", "Network"));

        var result = _correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "CORR-001");
    }

    [Fact]
    public void Analyze_MissingOnePattern_DoesNotMatch()
    {
        // Only Defender mentioned — CORR-001 needs Firewall too.
        var report = ReportWith(
            Finding.Critical("Windows Defender disabled", "AV off", "Antivirus"));

        var result = _correlator.Analyze(report);
        Assert.DoesNotContain(result.Matches, m => m.Rule.Id == "CORR-001");
    }

    // ---------- Severity amplification ----------

    [Fact]
    public void Analyze_AmplificationCount_IncrementsWhenAmplifiedExceedsOriginal()
    {
        // Two warnings amplify to Critical under CORR-001.
        var report = ReportWith(
            Finding.Warning("Defender weak config", "AV reduced protection", "Antivirus"),
            Finding.Warning("Firewall loose rules", "FW allow-all", "Network"));

        var result = _correlator.Analyze(report);
        var corr1 = result.Matches.Single(m => m.Rule.Id == "CORR-001");
        Assert.Equal(Severity.Warning, corr1.OriginalMaxSeverity);
        Assert.Equal(Severity.Critical, corr1.AmplifiedSeverity);
        Assert.True(result.RiskAmplification >= 1);
    }

    [Fact]
    public void Analyze_NoAmplification_WhenOriginalAlreadyMatchesAmplified()
    {
        var report = ReportWith(
            Finding.Critical("Defender off", "AV down", "Antivirus"),
            Finding.Critical("Firewall off", "FW down", "Network"));

        var result = _correlator.Analyze(report);
        var corr1 = result.Matches.Single(m => m.Rule.Id == "CORR-001");
        // Both already Critical => no amplification credit for this match.
        Assert.False(corr1.AmplifiedSeverity > corr1.OriginalMaxSeverity);
    }

    // ---------- Sorting ----------

    [Fact]
    public void Analyze_MatchesSortedBySeverityThenMatchCountDescending()
    {
        // Trigger multiple rules with different amplified severities.
        var report = ReportWith(
            Finding.Critical("Defender off", "AV off", "Antivirus"),     // CORR-001 (Critical) + CORR-002 (Critical)
            Finding.Critical("Firewall off", "FW off", "Network"),       // CORR-001
            Finding.Critical("Update missing", "patches old", "System"), // CORR-002, CORR-006
            Finding.Warning("Browser stale", "browser issue", "Browser") // CORR-006 (Warning)
        );

        var result = _correlator.Analyze(report);
        Assert.True(result.Matches.Count >= 2);

        // Severity must be non-increasing.
        for (int i = 1; i < result.Matches.Count; i++)
        {
            var prev = result.Matches[i - 1].AmplifiedSeverity;
            var cur = result.Matches[i].AmplifiedSeverity;
            Assert.True(prev >= cur, $"Match #{i - 1} severity {prev} must be >= #{i} {cur}");
        }
    }

    // ---------- Categories ----------

    [Fact]
    public void Analyze_RequiredCategoryAbsent_RuleDoesNotMatch()
    {
        var fresh = new FindingCorrelator();
        foreach (var r in fresh.GetRules().ToList()) fresh.RemoveRule(r.Id);

        fresh.AddRule(MakeRule(
            id: "CAT-RULE",
            patterns: new[] { "leak" },
            categories: new[] { "Network" },
            amplified: Severity.Warning));

        // Finding has the pattern but wrong category.
        var report = ReportWith(
            Finding.Warning("Data leak suspected", "leak detected", "Application"));

        var result = fresh.Analyze(report);
        Assert.Empty(result.Matches);
    }

    [Fact]
    public void Analyze_CategorySatisfiedBySamePatternFinding_IsAllowed()
    {
        var fresh = new FindingCorrelator();
        foreach (var r in fresh.GetRules().ToList()) fresh.RemoveRule(r.Id);

        fresh.AddRule(MakeRule(
            id: "CAT-OVERLAP",
            patterns: new[] { "leak" },
            categories: new[] { "Network" },
            amplified: Severity.Warning));

        // One finding satisfies both the pattern *and* the category.
        var report = ReportWith(
            Finding.Warning("Data leak suspected", "leak detected", "Network"));

        var result = fresh.Analyze(report);
        var m = Assert.Single(result.Matches);
        Assert.Equal("CAT-OVERLAP", m.Rule.Id);
        Assert.Single(m.MatchedFindings);
    }

    [Fact]
    public void Analyze_CategoryMatchingIsCaseInsensitive()
    {
        var fresh = new FindingCorrelator();
        foreach (var r in fresh.GetRules().ToList()) fresh.RemoveRule(r.Id);

        fresh.AddRule(MakeRule(
            id: "CAT-ONLY",
            categories: new[] { "Network" },
            amplified: Severity.Info));

        var report = ReportWith(
            Finding.Info("Note", "trivial", "network")); // lowercase category

        var result = fresh.Analyze(report);
        Assert.Single(result.Matches);
    }

    // ---------- Recommendations ----------

    [Fact]
    public void Analyze_Recommendations_AreDistinct()
    {
        var fresh = new FindingCorrelator();
        foreach (var r in fresh.GetRules().ToList()) fresh.RemoveRule(r.Id);

        // Two rules with the SAME recommendation, both will fire.
        const string sharedRec = "Same remediation text";
        fresh.AddRule(new FindingCorrelator.CorrelationRule(
            "R-A", "A", "d", new[] { "alpha" }, Array.Empty<string>(),
            Severity.Warning, sharedRec));
        fresh.AddRule(new FindingCorrelator.CorrelationRule(
            "R-B", "B", "d", new[] { "beta" }, Array.Empty<string>(),
            Severity.Warning, sharedRec));

        var report = ReportWith(
            Finding.Warning("alpha issue", "x", "Cat"),
            Finding.Warning("beta issue", "x", "Cat"));

        var result = fresh.Analyze(report);
        Assert.Equal(2, result.CorrelationsFound);
        Assert.Single(result.Recommendations);
        Assert.Equal(sharedRec, result.Recommendations[0]);
    }

    // ---------- Totals ----------

    [Fact]
    public void Analyze_TotalFindings_AggregatesAcrossModulesAndExcludesPass()
    {
        var report = new SecurityReport
        {
            Results = new List<AuditResult>
            {
                new()
                {
                    ModuleName = "M1", Category = "A",
                    Findings = new List<Finding>
                    {
                        Finding.Critical("c1", "d", "A"),
                        Finding.Pass("p1", "d", "A"),
                    }
                },
                new()
                {
                    ModuleName = "M2", Category = "B",
                    Findings = new List<Finding>
                    {
                        Finding.Warning("w1", "d", "B"),
                        Finding.Warning("w2", "d", "B"),
                        Finding.Pass("p2", "d", "B"),
                    }
                },
            }
        };

        var result = _correlator.Analyze(report);
        Assert.Equal(3, result.TotalFindings);
    }
}
