using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.RiskAssessmentService;

namespace WinSentinel.Tests.Services;

public class RiskAssessmentServiceTests
{
    private readonly RiskAssessmentService _sut = new();

    private static Finding MakeFinding(Severity severity, string category,
        string title = "Test Finding", string? remediation = null,
        DateTimeOffset? timestamp = null) => new()
    {
        Title = title,
        Description = $"Test finding: {title}",
        Severity = severity,
        Category = category,
        Remediation = remediation,
        Timestamp = timestamp ?? DateTimeOffset.UtcNow
    };

    private static AuditResult MakeResult(string module, string category, params Finding[] findings) => new()
    {
        ModuleName = module,
        Category = category,
        Findings = findings.ToList(),
        StartTime = DateTimeOffset.UtcNow.AddSeconds(-1),
        EndTime = DateTimeOffset.UtcNow
    };

    private static SecurityReport MakeReport(params AuditResult[] results) => new()
    {
        Results = results.ToList(),
        SecurityScore = 50
    };

    // ── AssessFindings ──

    [Fact]
    public void AssessFindings_EmptyReport_ReturnsEmpty()
    {
        var report = MakeReport();
        var result = _sut.AssessFindings(report);
        Assert.Empty(result);
    }

    [Fact]
    public void AssessFindings_SkipsPassFindings()
    {
        var report = MakeReport(MakeResult("SystemAudit", "System",
            Finding.Pass("OK", "All good", "System")));
        var result = _sut.AssessFindings(report);
        Assert.Empty(result);
    }

    [Fact]
    public void AssessFindings_IncludesInfoWarningCritical()
    {
        var report = MakeReport(MakeResult("Test", "Network",
            Finding.Info("Info", "desc", "Network"),
            Finding.Warning("Warn", "desc", "Network"),
            Finding.Critical("Crit", "desc", "Network")));
        var result = _sut.AssessFindings(report);
        Assert.Equal(3, result.Count);
    }

    [Fact]
    public void AssessFindings_SortedByCompositeScoreDescending()
    {
        var report = MakeReport(
            MakeResult("Net", "Network",
                Finding.Info("Low risk", "desc", "Network")),
            MakeResult("Enc", "Encryption",
                Finding.Critical("High risk", "desc", "Encryption")));
        var result = _sut.AssessFindings(report);
        Assert.True(result[0].CompositeScore >= result[1].CompositeScore);
        Assert.Equal("High risk", result[0].Finding.Title);
    }

    [Fact]
    public void AssessFindings_AssignsPriorityRanks()
    {
        var report = MakeReport(MakeResult("Test", "Network",
            Finding.Warning("A", "d", "Network"),
            Finding.Critical("B", "d", "Network")));
        var result = _sut.AssessFindings(report);
        Assert.Equal(1, result[0].PriorityRank);
        Assert.Equal(2, result[1].PriorityRank);
    }

    [Fact]
    public void AssessFindings_NullReport_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _sut.AssessFindings(null!));
    }

    // ── AssessSingleFinding ──

    [Fact]
    public void AssessSingleFinding_CriticalNetworkScoresHighest()
    {
        var finding = Finding.Critical("Open port", "Port 22 exposed", "Network");
        var assessed = _sut.AssessSingleFinding(finding, "Network", "NetworkAudit");

        Assert.Equal(10.0, assessed.SeverityScore);
        Assert.Equal(9.0, assessed.ExploitabilityScore);
        Assert.True(assessed.CompositeScore >= 70);
        Assert.True(assessed.Level >= RiskLevel.High);
    }

    [Fact]
    public void AssessSingleFinding_InfoSystemScoresLowest()
    {
        var finding = Finding.Info("Config note", "Non-default setting", "System");
        var assessed = _sut.AssessSingleFinding(finding, "System", "SystemAudit");

        Assert.Equal(3.0, assessed.SeverityScore);
        Assert.True(assessed.CompositeScore < 50);
    }

    [Fact]
    public void AssessSingleFinding_WarningScoresBetween()
    {
        var finding = Finding.Warning("Weak password policy", "desc", "Account");
        var assessed = _sut.AssessSingleFinding(finding, "Account", "AccountAudit");

        Assert.Equal(6.0, assessed.SeverityScore);
        Assert.True(assessed.CompositeScore > 30);
        Assert.True(assessed.CompositeScore < 90);
    }

    [Fact]
    public void AssessSingleFinding_UnknownCategoryGetsDefaults()
    {
        var finding = Finding.Warning("Unknown", "desc", "CustomCategory");
        var assessed = _sut.AssessSingleFinding(finding, "CustomCategory", "Custom");

        Assert.Equal(5.0, assessed.ExploitabilityScore); // Default
        Assert.Equal(5.0, assessed.ImpactScore);
        Assert.Equal(5.0, assessed.EnvironmentalScore);
    }

    [Fact]
    public void AssessSingleFinding_SetsModuleName()
    {
        var finding = Finding.Warning("Test", "desc", "Network");
        var assessed = _sut.AssessSingleFinding(finding, "Network", "NetworkAudit");
        Assert.Equal("NetworkAudit", assessed.Module);
    }

    [Fact]
    public void AssessSingleFinding_CompositeScoreRounded()
    {
        var finding = Finding.Critical("Test", "desc", "Firewall");
        var assessed = _sut.AssessSingleFinding(finding, "Firewall", "FirewallAudit");

        // Composite should be rounded to 1 decimal place
        Assert.Equal(assessed.CompositeScore, Math.Round(assessed.CompositeScore, 1));
    }

    // ── Persistence Scoring ──

    [Fact]
    public void AssessSingleFinding_FreshFindingLowPersistence()
    {
        var finding = MakeFinding(Severity.Warning, "Network", timestamp: DateTimeOffset.UtcNow);
        var assessed = _sut.AssessSingleFinding(finding, "Network", "Net");
        Assert.Equal(1.0, assessed.PersistenceScore);
    }

    [Fact]
    public void AssessSingleFinding_OldFindingHighPersistence()
    {
        var finding = MakeFinding(Severity.Warning, "Network",
            timestamp: DateTimeOffset.UtcNow.AddDays(-100));
        var assessed = _sut.AssessSingleFinding(finding, "Network", "Net");
        Assert.Equal(10.0, assessed.PersistenceScore);
    }

    [Fact]
    public void AssessSingleFinding_WeekOldFindingMidPersistence()
    {
        var finding = MakeFinding(Severity.Warning, "Network",
            timestamp: DateTimeOffset.UtcNow.AddDays(-10));
        var assessed = _sut.AssessSingleFinding(finding, "Network", "Net");
        Assert.Equal(4.0, assessed.PersistenceScore);
    }

    [Fact]
    public void AssessSingleFinding_MonthOldFinding()
    {
        var finding = MakeFinding(Severity.Warning, "Network",
            timestamp: DateTimeOffset.UtcNow.AddDays(-45));
        var assessed = _sut.AssessSingleFinding(finding, "Network", "Net");
        Assert.Equal(7.0, assessed.PersistenceScore);
    }

    [Fact]
    public void AssessSingleFinding_TwoDayOldFinding()
    {
        var finding = MakeFinding(Severity.Warning, "Network",
            timestamp: DateTimeOffset.UtcNow.AddDays(-3));
        var assessed = _sut.AssessSingleFinding(finding, "Network", "Net");
        Assert.Equal(2.0, assessed.PersistenceScore);
    }

    // ── Risk Level Classification ──

    [Theory]
    [InlineData(80.0, RiskLevel.Critical)]
    [InlineData(75.0, RiskLevel.Critical)]
    [InlineData(60.0, RiskLevel.High)]
    [InlineData(50.0, RiskLevel.High)]
    [InlineData(30.0, RiskLevel.Medium)]
    [InlineData(25.0, RiskLevel.Medium)]
    [InlineData(20.0, RiskLevel.Low)]
    [InlineData(0.0, RiskLevel.Low)]
    public void ClassifyRiskLevel_CorrectBuckets(double score, RiskLevel expected)
    {
        Assert.Equal(expected, RiskAssessmentService.ClassifyRiskLevel(score));
    }

    // ── GenerateMatrix ──

    [Fact]
    public void GenerateMatrix_EmptyList_ReturnsZeroMatrix()
    {
        var matrix = _sut.GenerateMatrix(new List<RiskAssessedFinding>());
        Assert.Equal(0, matrix.TotalFindings);
        Assert.Equal(0, matrix.CriticalRisk);
        Assert.Equal(RiskLevel.Low, matrix.OverallRisk);
        Assert.Empty(matrix.CategoryBreakdown);
        Assert.Empty(matrix.TopPriorities);
    }

    [Fact]
    public void GenerateMatrix_CountsRiskLevels()
    {
        var report = MakeReport(
            MakeResult("Net", "Network",
                Finding.Critical("C1", "d", "Network"),
                Finding.Critical("C2", "d", "Network")),
            MakeResult("Sys", "System",
                Finding.Info("I1", "d", "System")));
        var assessed = _sut.AssessFindings(report);
        var matrix = _sut.GenerateMatrix(assessed);

        Assert.Equal(3, matrix.TotalFindings);
        Assert.True(matrix.CriticalRisk + matrix.HighRisk + matrix.MediumRisk + matrix.LowRisk == 3);
    }

    [Fact]
    public void GenerateMatrix_CategoryBreakdownSortedByAvgScore()
    {
        var report = MakeReport(
            MakeResult("Net", "Network", Finding.Critical("Net crit", "d", "Network")),
            MakeResult("Sys", "System", Finding.Info("Sys info", "d", "System")));
        var assessed = _sut.AssessFindings(report);
        var matrix = _sut.GenerateMatrix(assessed);

        Assert.True(matrix.CategoryBreakdown.Count >= 2);
        Assert.True(matrix.CategoryBreakdown[0].AverageScore >= matrix.CategoryBreakdown[1].AverageScore);
    }

    [Fact]
    public void GenerateMatrix_TopPrioritiesMaxFive()
    {
        var findings = Enumerable.Range(0, 10)
            .Select(i => Finding.Warning($"Warning {i}", "d", "Network"))
            .ToArray();
        var report = MakeReport(MakeResult("Net", "Network", findings));
        var assessed = _sut.AssessFindings(report);
        var matrix = _sut.GenerateMatrix(assessed);

        Assert.True(matrix.TopPriorities.Count <= 5);
    }

    [Fact]
    public void GenerateMatrix_AverageRiskScoreCalculated()
    {
        var report = MakeReport(MakeResult("Net", "Network",
            Finding.Critical("C", "d", "Network"),
            Finding.Info("I", "d", "Network")));
        var assessed = _sut.AssessFindings(report);
        var matrix = _sut.GenerateMatrix(assessed);

        Assert.True(matrix.AverageRiskScore > 0);
    }

    [Fact]
    public void GenerateMatrix_NullInput_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _sut.GenerateMatrix(null!));
    }

    // ── Analyze (end-to-end) ──

    [Fact]
    public void Analyze_ProducesCompleteMatrix()
    {
        var report = MakeReport(
            MakeResult("Net", "Network",
                Finding.Critical("Open RDP", "RDP port open", "Network", "Disable RDP")),
            MakeResult("Enc", "Encryption",
                Finding.Warning("Weak TLS", "TLS 1.0 enabled", "Encryption")),
            MakeResult("Sys", "System",
                Finding.Info("Old version", "Not latest", "System")));

        var matrix = _sut.Analyze(report);

        Assert.Equal(3, matrix.TotalFindings);
        Assert.True(matrix.AverageRiskScore > 0);
        Assert.True(matrix.CategoryBreakdown.Count >= 2);
        Assert.True(matrix.TopPriorities.Count <= 5);
    }

    // ── FormatSummary ──

    [Fact]
    public void FormatSummary_ContainsAllSections()
    {
        var report = MakeReport(MakeResult("Net", "Network",
            Finding.Critical("Open port", "desc", "Network")));
        var matrix = _sut.Analyze(report);
        var summary = FormatSummary(matrix);

        Assert.Contains("Risk Assessment Summary", summary);
        Assert.Contains("Overall Risk Level", summary);
        Assert.Contains("Risk Distribution", summary);
        Assert.Contains("Category Risk Ranking", summary);
        Assert.Contains("Top Priority Findings", summary);
    }

    [Fact]
    public void FormatSummary_EmptyMatrix_NoCategories()
    {
        var matrix = _sut.GenerateMatrix(new List<RiskAssessedFinding>());
        var summary = FormatSummary(matrix);

        Assert.Contains("Total Findings: 0", summary);
        Assert.DoesNotContain("Category Risk Ranking", summary);
        Assert.DoesNotContain("Top Priority", summary);
    }

    [Fact]
    public void FormatSummary_NullInput_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => FormatSummary(null!));
    }

    // ── Justification ──

    [Fact]
    public void Justification_CriticalNetwork_MentionsHighExploitability()
    {
        var finding = Finding.Critical("Open port", "desc", "Network");
        var assessed = _sut.AssessSingleFinding(finding, "Network", "Net");
        Assert.Contains("high exploitability", assessed.Justification);
    }

    [Fact]
    public void Justification_WithRemediation_Mentioned()
    {
        var finding = Finding.Warning("Weak", "d", "Account", "Fix it");
        var assessed = _sut.AssessSingleFinding(finding, "Account", "Acc");
        Assert.Contains("remediation available", assessed.Justification);
    }

    [Fact]
    public void Justification_WithoutRemediation_NoRemediationNote()
    {
        var finding = Finding.Warning("Weak", "d", "Account");
        var assessed = _sut.AssessSingleFinding(finding, "Account", "Acc");
        Assert.Contains("no known remediation", assessed.Justification);
    }

    [Fact]
    public void Justification_OldFinding_MentionsPersistence()
    {
        var finding = MakeFinding(Severity.Warning, "Network",
            timestamp: DateTimeOffset.UtcNow.AddDays(-100));
        var assessed = _sut.AssessSingleFinding(finding, "Network", "Net");
        Assert.Contains("long-standing issue", assessed.Justification);
    }

    // ── Category-specific Scoring Consistency ──

    [Theory]
    [InlineData("Network")]
    [InlineData("Firewall")]
    [InlineData("Encryption")]
    [InlineData("Account")]
    [InlineData("Update")]
    [InlineData("Browser")]
    [InlineData("Defender")]
    [InlineData("Privacy")]
    [InlineData("EventLog")]
    [InlineData("Process")]
    [InlineData("AppSecurity")]
    [InlineData("Startup")]
    [InlineData("System")]
    public void AllCategories_ProduceValidScores(string category)
    {
        var finding = Finding.Critical("Test", "desc", category);
        var assessed = _sut.AssessSingleFinding(finding, category, "Mod");

        Assert.InRange(assessed.CompositeScore, 0, 100);
        Assert.InRange(assessed.ExploitabilityScore, 0, 10);
        Assert.InRange(assessed.ImpactScore, 0, 10);
        Assert.InRange(assessed.EnvironmentalScore, 0, 10);
    }

    [Fact]
    public void NetworkCategory_HigherRiskThanSystem_ForSameSeverity()
    {
        var netFinding = Finding.Warning("Net issue", "d", "Network");
        var sysFinding = Finding.Warning("Sys issue", "d", "System");

        var net = _sut.AssessSingleFinding(netFinding, "Network", "Net");
        var sys = _sut.AssessSingleFinding(sysFinding, "System", "Sys");

        Assert.True(net.CompositeScore > sys.CompositeScore,
            $"Network ({net.CompositeScore}) should score higher than System ({sys.CompositeScore})");
    }

    [Fact]
    public void CriticalSeverity_HigherThanWarning_SameCategory()
    {
        var crit = _sut.AssessSingleFinding(
            Finding.Critical("C", "d", "Network"), "Network", "Net");
        var warn = _sut.AssessSingleFinding(
            Finding.Warning("W", "d", "Network"), "Network", "Net");

        Assert.True(crit.CompositeScore > warn.CompositeScore);
    }

    // ── Edge Cases ──

    [Fact]
    public void AssessFindings_MixedPassAndNonPass()
    {
        var report = MakeReport(MakeResult("Test", "Network",
            Finding.Pass("OK", "pass", "Network"),
            Finding.Warning("Warn", "warn", "Network"),
            Finding.Pass("OK2", "pass", "Network")));
        var result = _sut.AssessFindings(report);
        Assert.Single(result); // Only the warning
    }

    [Fact]
    public void AssessFindings_MultipleModules()
    {
        var report = MakeReport(
            MakeResult("Mod1", "Network", Finding.Warning("N1", "d", "Network")),
            MakeResult("Mod2", "Account", Finding.Warning("A1", "d", "Account")),
            MakeResult("Mod3", "System", Finding.Warning("S1", "d", "System")));
        var result = _sut.AssessFindings(report);

        Assert.Equal(3, result.Count);
        Assert.Contains(result, r => r.Module == "Mod1");
        Assert.Contains(result, r => r.Module == "Mod2");
        Assert.Contains(result, r => r.Module == "Mod3");
    }

    [Fact]
    public void EmptyCategoryString_GetsDefaultScores()
    {
        var finding = Finding.Warning("Test", "d", "");
        var assessed = _sut.AssessSingleFinding(finding, "", "Mod");
        Assert.Equal(5.0, assessed.ExploitabilityScore);
    }
}
