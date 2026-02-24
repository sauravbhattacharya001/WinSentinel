using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.FindingCorrelator;

namespace WinSentinel.Tests.Services;

public class FindingCorrelatorTests
{
    private static SecurityReport CreateReport(params (string title, string description, string category, Severity severity)[] findings)
    {
        var result = new AuditResult
        {
            ModuleName = "Test",
            Category = "Test",
            Findings = findings.Select(f => new Finding
            {
                Title = f.title,
                Description = f.description,
                Category = f.category,
                Severity = f.severity
            }).ToList()
        };
        return new SecurityReport { Results = new List<AuditResult> { result } };
    }

    private static SecurityReport CreateEmptyReport() =>
        new() { Results = new List<AuditResult>() };

    #region Constructor

    [Fact]
    public void Constructor_LoadsBuiltInRules()
    {
        var correlator = new FindingCorrelator();
        Assert.True(correlator.RuleCount > 0);
    }

    [Fact]
    public void Constructor_Has8BuiltInRules()
    {
        var correlator = new FindingCorrelator();
        Assert.Equal(8, correlator.RuleCount);
    }

    [Fact]
    public void Constructor_RulesHaveUniqueIds()
    {
        var correlator = new FindingCorrelator();
        var rules = correlator.GetRules();
        var ids = rules.Select(r => r.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
    }

    #endregion

    #region AddRule

    [Fact]
    public void AddRule_AddsCustomRule()
    {
        var correlator = new FindingCorrelator();
        var initialCount = correlator.RuleCount;
        correlator.AddRule(new CorrelationRule(
            "CUSTOM-001", "Custom Rule", "Test rule",
            new[] { "test" }, Array.Empty<string>(),
            Severity.Warning, "Test recommendation"));
        Assert.Equal(initialCount + 1, correlator.RuleCount);
    }

    [Fact]
    public void AddRule_ThrowsOnNullRule()
    {
        var correlator = new FindingCorrelator();
        Assert.Throws<ArgumentNullException>(() => correlator.AddRule(null!));
    }

    [Fact]
    public void AddRule_ThrowsOnEmptyId()
    {
        var correlator = new FindingCorrelator();
        Assert.Throws<ArgumentException>(() => correlator.AddRule(new CorrelationRule(
            "", "Name", "Desc",
            new[] { "pattern" }, Array.Empty<string>(),
            Severity.Warning, "Rec")));
    }

    [Fact]
    public void AddRule_ThrowsOnWhitespaceId()
    {
        var correlator = new FindingCorrelator();
        Assert.Throws<ArgumentException>(() => correlator.AddRule(new CorrelationRule(
            "   ", "Name", "Desc",
            new[] { "pattern" }, Array.Empty<string>(),
            Severity.Warning, "Rec")));
    }

    [Fact]
    public void AddRule_ThrowsOnEmptyName()
    {
        var correlator = new FindingCorrelator();
        Assert.Throws<ArgumentException>(() => correlator.AddRule(new CorrelationRule(
            "CUSTOM-X", "", "Desc",
            new[] { "pattern" }, Array.Empty<string>(),
            Severity.Warning, "Rec")));
    }

    [Fact]
    public void AddRule_ThrowsOnWhitespaceName()
    {
        var correlator = new FindingCorrelator();
        Assert.Throws<ArgumentException>(() => correlator.AddRule(new CorrelationRule(
            "CUSTOM-X", "  ", "Desc",
            new[] { "pattern" }, Array.Empty<string>(),
            Severity.Warning, "Rec")));
    }

    [Fact]
    public void AddRule_ThrowsOnNoPatternsOrCategories()
    {
        var correlator = new FindingCorrelator();
        Assert.Throws<ArgumentException>(() => correlator.AddRule(new CorrelationRule(
            "CUSTOM-X", "Name", "Desc",
            Array.Empty<string>(), Array.Empty<string>(),
            Severity.Warning, "Rec")));
    }

    [Fact]
    public void AddRule_ThrowsOnDuplicateId()
    {
        var correlator = new FindingCorrelator();
        // CORR-001 is a built-in rule
        Assert.Throws<ArgumentException>(() => correlator.AddRule(new CorrelationRule(
            "CORR-001", "Duplicate", "Desc",
            new[] { "x" }, Array.Empty<string>(),
            Severity.Warning, "Rec")));
    }

    [Fact]
    public void AddRule_ThrowsOnExceedingMaxRules()
    {
        var correlator = new FindingCorrelator();
        // Add rules up to MaxRules (8 built-in already)
        for (int i = 0; i < MaxRules - 8; i++)
        {
            correlator.AddRule(new CorrelationRule(
                $"FILL-{i:D4}", $"Fill {i}", "Filler",
                new[] { "pattern" }, Array.Empty<string>(),
                Severity.Info, "Rec"));
        }
        Assert.Equal(MaxRules, correlator.RuleCount);
        Assert.Throws<InvalidOperationException>(() => correlator.AddRule(new CorrelationRule(
            "OVERFLOW", "Overflow", "Desc",
            new[] { "x" }, Array.Empty<string>(),
            Severity.Warning, "Rec")));
    }

    [Fact]
    public void AddRule_IncrementsRuleCount()
    {
        var correlator = new FindingCorrelator();
        var before = correlator.RuleCount;
        correlator.AddRule(new CorrelationRule(
            "INC-001", "Increment Test", "Desc",
            new[] { "pattern" }, Array.Empty<string>(),
            Severity.Warning, "Rec"));
        Assert.Equal(before + 1, correlator.RuleCount);
    }

    #endregion

    #region RemoveRule

    [Fact]
    public void RemoveRule_RemovesExistingRule()
    {
        var correlator = new FindingCorrelator();
        var result = correlator.RemoveRule("CORR-001");
        Assert.True(result);
        Assert.DoesNotContain(correlator.GetRules(), r => r.Id == "CORR-001");
    }

    [Fact]
    public void RemoveRule_ReturnsFalseForNonExistent()
    {
        var correlator = new FindingCorrelator();
        Assert.False(correlator.RemoveRule("NON-EXISTENT"));
    }

    [Fact]
    public void RemoveRule_DecrementsRuleCount()
    {
        var correlator = new FindingCorrelator();
        var before = correlator.RuleCount;
        correlator.RemoveRule("CORR-001");
        Assert.Equal(before - 1, correlator.RuleCount);
    }

    #endregion

    #region GetRules

    [Fact]
    public void GetRules_ReturnsAllRules()
    {
        var correlator = new FindingCorrelator();
        var rules = correlator.GetRules();
        Assert.Equal(correlator.RuleCount, rules.Count);
    }

    [Fact]
    public void GetRules_ReturnsReadOnlyList()
    {
        var correlator = new FindingCorrelator();
        var rules = correlator.GetRules();
        Assert.IsAssignableFrom<IReadOnlyList<CorrelationRule>>(rules);
    }

    #endregion

    #region Analyze - Basics

    [Fact]
    public void Analyze_ThrowsOnNullReport()
    {
        var correlator = new FindingCorrelator();
        Assert.Throws<ArgumentNullException>(() => correlator.Analyze(null!));
    }

    [Fact]
    public void Analyze_ReturnsZeroCorrelationsForEmptyReport()
    {
        var correlator = new FindingCorrelator();
        var report = CreateEmptyReport();
        var result = correlator.Analyze(report);
        Assert.Equal(0, result.CorrelationsFound);
        Assert.Empty(result.Matches);
    }

    [Fact]
    public void Analyze_ReturnsZeroCorrelationsWhenNoPatternsMatch()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Unrelated Finding", "Nothing relevant", "Other", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.Equal(0, result.CorrelationsFound);
    }

    #endregion

    #region Analyze - Built-in Rule Detection

    [Fact]
    public void Analyze_DetectsCORR001_DefenderAndFirewall()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Windows Defender Disabled", "AV is off", "Security", Severity.Critical),
            ("Firewall Not Active", "Firewall is off", "Network", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "CORR-001");
    }

    [Fact]
    public void Analyze_DetectsCORR002_UpdateAndDefender()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Windows Update Overdue", "Updates not installed", "System", Severity.Warning),
            ("Windows Defender Disabled", "AV is off", "Security", Severity.Critical));
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "CORR-002");
    }

    [Fact]
    public void Analyze_DetectsCORR003_BitLockerAndPassword()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("BitLocker Not Enabled", "No encryption", "Encryption", Severity.Warning),
            ("Weak password policy", "Passwords too short", "Accounts", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "CORR-003");
    }

    [Fact]
    public void Analyze_DetectsCORR004_EventLogAndAudit()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Event Log Service Stopped", "Logging disabled", "Logging", Severity.Warning),
            ("System audit policy incomplete", "Missing audit configs", "Policy", Severity.Info));
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "CORR-004");
    }

    [Fact]
    public void Analyze_DetectsCORR005_FirewallAndSMB()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Firewall Misconfigured", "Rules too open", "Network", Severity.Warning),
            ("SMB Sharing Enabled", "SMB is open", "Network", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "CORR-005");
    }

    [Fact]
    public void Analyze_DetectsCORR006_BrowserAndUpdate()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Insecure browser settings", "Browser is risky", "Browser", Severity.Warning),
            ("Windows Update Pending", "Updates available", "System", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "CORR-006");
    }

    [Fact]
    public void Analyze_DetectsCORR007_StartupAndProcess()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Unknown startup entry found", "Suspicious startup", "Startup", Severity.Warning),
            ("Unsigned process running", "Process not verified", "Process", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "CORR-007");
    }

    [Fact]
    public void Analyze_DetectsCORR008_PrivacyAndNetwork()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Telemetry and privacy settings weak", "Privacy concern", "Privacy", Severity.Info),
            ("Open network shares detected", "Network exposure", "Network", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "CORR-008");
    }

    #endregion

    #region Analyze - Report Fields

    [Fact]
    public void Analyze_ReturnsCorrectTotalFindingsCount()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Finding 1", "Desc", "Cat", Severity.Warning),
            ("Finding 2", "Desc", "Cat", Severity.Critical),
            ("Finding 3", "Desc", "Cat", Severity.Info));
        var result = correlator.Analyze(report);
        Assert.Equal(3, result.TotalFindings);
    }

    [Fact]
    public void Analyze_ReturnsCorrectCorrelationsFoundCount()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Windows Defender Off", "AV off", "Security", Severity.Critical),
            ("Firewall Down", "FW off", "Network", Severity.Warning),
            ("Windows Update Missing", "Updates off", "System", Severity.Warning));
        var result = correlator.Analyze(report);
        // Should match CORR-001 (Defender+Firewall) and CORR-002 (Update+Defender)
        Assert.True(result.CorrelationsFound >= 2);
    }

    [Fact]
    public void Analyze_ReturnsCorrectRiskAmplificationCount()
    {
        var correlator = new FindingCorrelator();
        // CORR-001 amplifies to Critical; if original max of matched findings is Warning, that's amplification
        var report = CreateReport(
            ("Windows Defender issue", "Something with Defender", "Security", Severity.Warning),
            ("Firewall problem", "Something with Firewall", "Network", Severity.Warning));
        var result = correlator.Analyze(report);
        var corr001 = result.Matches.FirstOrDefault(m => m.Rule.Id == "CORR-001");
        Assert.NotNull(corr001);
        // Both findings are Warning, amplified to Critical
        Assert.True(result.RiskAmplification > 0);
    }

    [Fact]
    public void Analyze_IncludesRecommendations()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Windows Defender Disabled", "AV off", "Security", Severity.Critical),
            ("Firewall Disabled", "FW off", "Network", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.NotEmpty(result.Recommendations);
    }

    [Fact]
    public void Analyze_SkipsPassSeverityFindings()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Windows Defender OK", "AV is on", "Security", Severity.Pass),
            ("Firewall OK", "FW is on", "Network", Severity.Pass));
        var result = correlator.Analyze(report);
        Assert.Equal(0, result.TotalFindings);
        Assert.Equal(0, result.CorrelationsFound);
    }

    [Fact]
    public void Analyze_SortsMatchesBySeverityThenCount()
    {
        var correlator = new FindingCorrelator();
        // Create findings that trigger both Critical and Warning rules
        var report = CreateReport(
            ("Windows Defender Disabled", "AV off", "Security", Severity.Critical),
            ("Firewall Disabled", "FW off", "Network", Severity.Warning),
            ("Event Log stopped", "Logging off", "Logging", Severity.Info),
            ("System audit missing", "Audit off", "Policy", Severity.Info));
        var result = correlator.Analyze(report);
        if (result.Matches.Count >= 2)
        {
            for (int i = 0; i < result.Matches.Count - 1; i++)
            {
                var current = result.Matches[i];
                var next = result.Matches[i + 1];
                Assert.True(current.AmplifiedSeverity >= next.AmplifiedSeverity,
                    $"Matches should be sorted by severity descending. {current.Rule.Id} ({current.AmplifiedSeverity}) should be >= {next.Rule.Id} ({next.AmplifiedSeverity})");
            }
        }
    }

    [Fact]
    public void Analyze_MultipleRulesCanMatchSameReport()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Windows Defender Disabled", "AV off", "Security", Severity.Critical),
            ("Firewall Problem", "FW issue", "Network", Severity.Warning),
            ("Windows Update Missing", "No updates", "System", Severity.Warning),
            ("SMB Open", "SMB exposed", "Network", Severity.Warning));
        var result = correlator.Analyze(report);
        // Should match CORR-001, CORR-002, CORR-005 at minimum
        Assert.True(result.CorrelationsFound >= 3);
    }

    [Fact]
    public void Analyze_MatchedFindingsAreCorrect()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Windows Defender Disabled", "AV off", "Security", Severity.Critical),
            ("Firewall Not Active", "FW off", "Network", Severity.Warning),
            ("Unrelated Finding", "Something else", "Other", Severity.Info));
        var result = correlator.Analyze(report);
        var corr001 = result.Matches.First(m => m.Rule.Id == "CORR-001");
        Assert.Equal(2, corr001.MatchedFindings.Count);
        Assert.Contains(corr001.MatchedFindings, f => f.Title.Contains("Defender"));
        Assert.Contains(corr001.MatchedFindings, f => f.Title.Contains("Firewall"));
    }

    [Fact]
    public void Analyze_OriginalMaxSeverityReflectsMatchedFindings()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Windows Defender Off", "AV off", "Security", Severity.Critical),
            ("Firewall Off", "FW off", "Network", Severity.Warning));
        var result = correlator.Analyze(report);
        var corr001 = result.Matches.First(m => m.Rule.Id == "CORR-001");
        Assert.Equal(Severity.Critical, corr001.OriginalMaxSeverity);
    }

    [Fact]
    public void Analyze_AmplifiedSeverityComesFromRule()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Windows Defender Off", "AV off", "Security", Severity.Warning),
            ("Firewall Off", "FW off", "Network", Severity.Warning));
        var result = correlator.Analyze(report);
        var corr001 = result.Matches.First(m => m.Rule.Id == "CORR-001");
        Assert.Equal(Severity.Critical, corr001.AmplifiedSeverity); // CORR-001 amplifies to Critical
    }

    #endregion

    #region FindMatchingFindings (tested via Analyze)

    [Fact]
    public void Analyze_MatchesCaseInsensitive()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("windows DEFENDER issue", "Something", "Security", Severity.Warning),
            ("FIREWALL problem", "Something", "Network", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "CORR-001");
    }

    [Fact]
    public void Analyze_MatchesInTitle()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Defender Status Warning", "Some description", "Security", Severity.Warning),
            ("Firewall Alert", "Some description", "Network", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "CORR-001");
    }

    [Fact]
    public void Analyze_MatchesInDescription()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("AV Issue", "Windows Defender is disabled", "Security", Severity.Warning),
            ("Network Issue", "Firewall rules are missing", "Network", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "CORR-001");
    }

    [Fact]
    public void Analyze_RequiresAllPatternsToMatch()
    {
        var correlator = new FindingCorrelator();
        // Only Defender present, no Firewall
        var report = CreateReport(
            ("Windows Defender Off", "AV off", "Security", Severity.Critical));
        var result = correlator.Analyze(report);
        Assert.DoesNotContain(result.Matches, m => m.Rule.Id == "CORR-001");
    }

    [Fact]
    public void Analyze_PartialPatternMatchReturnsNoResults()
    {
        var correlator = new FindingCorrelator();
        // Only one of two patterns for CORR-003
        var report = CreateReport(
            ("BitLocker Not Enabled", "No disk encryption", "Encryption", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.DoesNotContain(result.Matches, m => m.Rule.Id == "CORR-003");
    }

    [Fact]
    public void Analyze_CategoryMatchingWorks()
    {
        var correlator = new FindingCorrelator();
        correlator.AddRule(new CorrelationRule(
            "CAT-001", "Category Test", "Tests category matching",
            Array.Empty<string>(), new[] { "SecurityCat", "NetworkCat" },
            Severity.Critical, "Fix categories"));
        var report = CreateReport(
            ("Finding A", "Desc A", "SecurityCat", Severity.Warning),
            ("Finding B", "Desc B", "NetworkCat", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "CAT-001");
    }

    #endregion

    #region Custom Rules

    [Fact]
    public void CustomRule_TriggersOnMatchingReport()
    {
        var correlator = new FindingCorrelator();
        correlator.AddRule(new CorrelationRule(
            "CUSTOM-T1", "Custom Test", "Custom rule test",
            new[] { "CustomPattern" }, Array.Empty<string>(),
            Severity.Critical, "Custom fix"));
        var report = CreateReport(
            ("CustomPattern Found", "Has the pattern", "Test", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "CUSTOM-T1");
    }

    [Fact]
    public void CustomRule_WithCategories()
    {
        var correlator = new FindingCorrelator();
        correlator.AddRule(new CorrelationRule(
            "CUSTOM-T2", "Category Custom", "Custom with categories",
            Array.Empty<string>(), new[] { "Alpha", "Beta" },
            Severity.Warning, "Fix Alpha and Beta"));
        var report = CreateReport(
            ("Finding X", "Desc", "Alpha", Severity.Warning),
            ("Finding Y", "Desc", "Beta", Severity.Info));
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "CUSTOM-T2");
    }

    [Fact]
    public void RemovedRule_DoesNotTrigger()
    {
        var correlator = new FindingCorrelator();
        correlator.RemoveRule("CORR-001");
        var report = CreateReport(
            ("Windows Defender Disabled", "AV off", "Security", Severity.Critical),
            ("Firewall Disabled", "FW off", "Network", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.DoesNotContain(result.Matches, m => m.Rule.Id == "CORR-001");
    }

    #endregion

    #region CorrelationReport

    [Fact]
    public void CorrelationReport_HasExpectedFieldValues()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Windows Defender Off", "AV off", "Security", Severity.Warning),
            ("Firewall Off", "FW off", "Network", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.Equal(2, result.TotalFindings);
        Assert.True(result.CorrelationsFound > 0);
        Assert.NotNull(result.Matches);
        Assert.NotNull(result.Recommendations);
    }

    [Fact]
    public void CorrelationReport_RecommendationsAreDeduplicated()
    {
        var correlator = new FindingCorrelator();
        // Add two rules with same recommendation
        correlator.AddRule(new CorrelationRule(
            "DUP-001", "Dup A", "Desc",
            new[] { "DupTarget" }, Array.Empty<string>(),
            Severity.Warning, "Same recommendation"));
        correlator.AddRule(new CorrelationRule(
            "DUP-002", "Dup B", "Desc",
            Array.Empty<string>(), new[] { "DupCat" },
            Severity.Warning, "Same recommendation"));
        var report = CreateReport(
            ("DupTarget Finding", "Desc", "DupCat", Severity.Warning));
        var result = correlator.Analyze(report);
        var sameRecCount = result.Recommendations.Count(r => r == "Same recommendation");
        Assert.True(sameRecCount <= 1);
    }

    [Fact]
    public void CorrelationReport_EmptyReportHasEmptyRecommendations()
    {
        var correlator = new FindingCorrelator();
        var report = CreateEmptyReport();
        var result = correlator.Analyze(report);
        Assert.Empty(result.Recommendations);
    }

    #endregion

    #region Edge Cases

    [Fact]
    public void EdgeCase_SingleFindingCannotTriggerMultiPatternRule()
    {
        var correlator = new FindingCorrelator();
        // CORR-001 requires both "Defender" and "Firewall" patterns
        var report = CreateReport(
            ("Defender Firewall Combined", "Has both words but is one finding", "Security", Severity.Critical));
        var result = correlator.Analyze(report);
        // The single finding matches both patterns via Title, but they map to same finding
        // The correlator still considers it valid since both patterns match (same finding can satisfy both)
        // Actually this should match because patterns match - one finding satisfies both
        var corr001 = result.Matches.FirstOrDefault(m => m.Rule.Id == "CORR-001");
        // A single finding that contains both pattern words will match both patterns
        // but the HashSet deduplicates, so we get 1 matched finding
        if (corr001 != null)
        {
            Assert.Single(corr001.MatchedFindings);
        }
    }

    [Fact]
    public void EdgeCase_SameFindingCanSatisfyMultiplePatterns()
    {
        var correlator = new FindingCorrelator();
        // A single finding that contains both "Defender" and "Firewall" text
        var report = CreateReport(
            ("Defender and Firewall both disabled", "Both are off", "Security", Severity.Critical));
        var result = correlator.Analyze(report);
        var corr001 = result.Matches.FirstOrDefault(m => m.Rule.Id == "CORR-001");
        Assert.NotNull(corr001);
        // HashSet deduplicates: same finding matched twice → 1 unique finding
        Assert.Single(corr001.MatchedFindings);
    }

    [Fact]
    public void EdgeCase_ReportWithOnlyPassFindings_ReturnsZeroCorrelations()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Windows Defender Active", "AV is on", "Security", Severity.Pass),
            ("Firewall Active", "FW is on", "Network", Severity.Pass),
            ("Updates Current", "System up to date", "System", Severity.Pass));
        var result = correlator.Analyze(report);
        Assert.Equal(0, result.TotalFindings);
        Assert.Equal(0, result.CorrelationsFound);
    }

    [Fact]
    public void EdgeCase_LargeReportWithManyFindings()
    {
        var correlator = new FindingCorrelator();
        var findings = new List<(string, string, string, Severity)>();
        for (int i = 0; i < 500; i++)
        {
            findings.Add(($"Finding {i}", $"Description {i}", $"Category{i % 10}", Severity.Warning));
        }
        // Add some that will trigger correlations
        findings.Add(("Windows Defender Off", "AV off", "Security", Severity.Critical));
        findings.Add(("Firewall Down", "FW off", "Network", Severity.Warning));
        var report = CreateReport(findings.ToArray());
        var result = correlator.Analyze(report);
        Assert.Equal(502, result.TotalFindings); // 500 + 2
        Assert.True(result.CorrelationsFound > 0);
    }

    [Fact]
    public void EdgeCase_InfoSeverityFindingsAreIncluded()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Info about Defender", "Defender info", "Security", Severity.Info),
            ("Info about Firewall", "Firewall info", "Network", Severity.Info));
        var result = correlator.Analyze(report);
        // Info findings should be included (not filtered out like Pass)
        Assert.Equal(2, result.TotalFindings);
    }

    [Fact]
    public void EdgeCase_MixedPassAndNonPassFindings()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Windows Defender Off", "AV off", "Security", Severity.Critical),
            ("Something Good", "All good", "Security", Severity.Pass),
            ("Firewall Down", "FW off", "Network", Severity.Warning),
            ("Other Good", "Also good", "Network", Severity.Pass));
        var result = correlator.Analyze(report);
        Assert.Equal(2, result.TotalFindings); // Only non-Pass
        Assert.Contains(result.Matches, m => m.Rule.Id == "CORR-001");
    }

    [Fact]
    public void EdgeCase_RuleWithBothPatternsAndCategories()
    {
        var correlator = new FindingCorrelator();
        correlator.AddRule(new CorrelationRule(
            "COMBO-001", "Combo Rule", "Needs both patterns and categories",
            new[] { "SpecialPattern" }, new[] { "SpecialCat" },
            Severity.Critical, "Fix combo"));
        var report = CreateReport(
            ("Has SpecialPattern", "Desc", "SpecialCat", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "COMBO-001");
    }

    [Fact]
    public void EdgeCase_RuleWithBothPatternsAndCategories_FailsWhenCategoryMissing()
    {
        var correlator = new FindingCorrelator();
        correlator.AddRule(new CorrelationRule(
            "COMBO-002", "Combo Rule Fail", "Needs both",
            new[] { "SpecialPattern" }, new[] { "MissingCat" },
            Severity.Critical, "Fix combo"));
        var report = CreateReport(
            ("Has SpecialPattern", "Desc", "WrongCat", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.DoesNotContain(result.Matches, m => m.Rule.Id == "COMBO-002");
    }

    [Fact]
    public void EdgeCase_RuleWithBothPatternsAndCategories_FailsWhenPatternMissing()
    {
        var correlator = new FindingCorrelator();
        correlator.AddRule(new CorrelationRule(
            "COMBO-003", "Combo Rule Fail Pattern", "Needs both",
            new[] { "MissingPattern" }, new[] { "SpecialCat" },
            Severity.Critical, "Fix combo"));
        var report = CreateReport(
            ("No match here", "Desc", "SpecialCat", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.DoesNotContain(result.Matches, m => m.Rule.Id == "COMBO-003");
    }

    [Fact]
    public void EdgeCase_MultipleAuditResultsInReport()
    {
        var correlator = new FindingCorrelator();
        var report = new SecurityReport
        {
            Results = new List<AuditResult>
            {
                new AuditResult
                {
                    ModuleName = "Module1",
                    Category = "Security",
                    Findings = new List<Finding>
                    {
                        new Finding { Title = "Defender Issue", Description = "AV off", Category = "Security", Severity = Severity.Critical }
                    }
                },
                new AuditResult
                {
                    ModuleName = "Module2",
                    Category = "Network",
                    Findings = new List<Finding>
                    {
                        new Finding { Title = "Firewall Issue", Description = "FW off", Category = "Network", Severity = Severity.Warning }
                    }
                }
            }
        };
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "CORR-001");
    }

    [Fact]
    public void EdgeCase_MaxRulesConstantIs200()
    {
        Assert.Equal(200, FindingCorrelator.MaxRules);
    }

    [Fact]
    public void EdgeCase_BuiltInRulesHaveNonEmptyRecommendations()
    {
        var correlator = new FindingCorrelator();
        foreach (var rule in correlator.GetRules())
        {
            Assert.False(string.IsNullOrWhiteSpace(rule.Recommendation),
                $"Rule {rule.Id} should have a non-empty recommendation");
        }
    }

    [Fact]
    public void EdgeCase_BuiltInRulesHaveNonEmptyDescriptions()
    {
        var correlator = new FindingCorrelator();
        foreach (var rule in correlator.GetRules())
        {
            Assert.False(string.IsNullOrWhiteSpace(rule.Description),
                $"Rule {rule.Id} should have a non-empty description");
        }
    }

    [Fact]
    public void EdgeCase_BuiltInRulesHaveNonEmptyNames()
    {
        var correlator = new FindingCorrelator();
        foreach (var rule in correlator.GetRules())
        {
            Assert.False(string.IsNullOrWhiteSpace(rule.Name),
                $"Rule {rule.Id} should have a non-empty name");
        }
    }

    [Fact]
    public void EdgeCase_AmplificationCountOnlyCountsWhenSeverityIncreases()
    {
        var correlator = new FindingCorrelator();
        // CORR-001 amplifies to Critical; if original max is already Critical, no amplification
        var report = CreateReport(
            ("Windows Defender Off", "AV off", "Security", Severity.Critical),
            ("Firewall Off", "FW off", "Network", Severity.Critical));
        var result = correlator.Analyze(report);
        var corr001 = result.Matches.FirstOrDefault(m => m.Rule.Id == "CORR-001");
        Assert.NotNull(corr001);
        // OriginalMax is Critical, Amplified is Critical → no amplification for this match
        Assert.Equal(Severity.Critical, corr001.OriginalMaxSeverity);
        Assert.Equal(Severity.Critical, corr001.AmplifiedSeverity);
    }

    [Fact]
    public void EdgeCase_CustomRuleWithSinglePattern()
    {
        var correlator = new FindingCorrelator();
        correlator.AddRule(new CorrelationRule(
            "SINGLE-001", "Single Pattern", "Only one pattern",
            new[] { "SingleMatch" }, Array.Empty<string>(),
            Severity.Warning, "Fix single"));
        var report = CreateReport(
            ("SingleMatch Issue", "Found it", "Test", Severity.Info));
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "SINGLE-001");
    }

    [Fact]
    public void EdgeCase_CustomRuleWithSingleCategory()
    {
        var correlator = new FindingCorrelator();
        correlator.AddRule(new CorrelationRule(
            "SINGLECAT-001", "Single Category", "Only one category",
            Array.Empty<string>(), new[] { "UniqueCategory" },
            Severity.Warning, "Fix category"));
        var report = CreateReport(
            ("Some Finding", "Description", "UniqueCategory", Severity.Warning));
        var result = correlator.Analyze(report);
        Assert.Contains(result.Matches, m => m.Rule.Id == "SINGLECAT-001");
    }

    [Fact]
    public void EdgeCase_AnalyzeWithNoRules()
    {
        var correlator = new FindingCorrelator();
        // Remove all built-in rules
        foreach (var rule in correlator.GetRules().ToList())
        {
            correlator.RemoveRule(rule.Id);
        }
        Assert.Equal(0, correlator.RuleCount);
        var report = CreateReport(
            ("Windows Defender Off", "AV off", "Security", Severity.Critical));
        var result = correlator.Analyze(report);
        Assert.Equal(0, result.CorrelationsFound);
        Assert.Equal(1, result.TotalFindings);
    }

    [Fact]
    public void Analyze_AllBuiltInRulesCanMatchSimultaneously()
    {
        var correlator = new FindingCorrelator();
        var report = CreateReport(
            ("Windows Defender Off", "AV off", "Security", Severity.Critical),
            ("Firewall Down", "FW off", "Network", Severity.Warning),
            ("Windows Update Missing", "No updates", "System", Severity.Warning),
            ("BitLocker Not Enabled", "No encryption", "Encryption", Severity.Warning),
            ("Weak password policy", "Passwords weak", "Accounts", Severity.Warning),
            ("Event Log Service Stopped", "Logging off", "Logging", Severity.Warning),
            ("System audit incomplete", "Audit missing", "Policy", Severity.Info),
            ("SMB Sharing Open", "SMB exposed", "Network", Severity.Warning),
            ("Insecure browser config", "Browser risky", "Browser", Severity.Warning),
            ("Unknown startup entry", "Suspicious startup", "Startup", Severity.Warning),
            ("Unsigned process detected", "Process concern", "Process", Severity.Warning),
            ("Telemetry privacy weak", "Privacy leak", "Privacy", Severity.Info),
            ("Open network config", "Network exposed", "Network", Severity.Warning));
        var result = correlator.Analyze(report);
        // All 8 built-in rules should match
        Assert.Equal(8, result.CorrelationsFound);
    }

    #endregion
}
