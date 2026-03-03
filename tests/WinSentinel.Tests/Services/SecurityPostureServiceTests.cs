using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class SecurityPostureServiceTests
{
    private readonly SecurityPostureService _service = new();

    // ── Helper builders ──────────────────────────────────────────────

    private static SecurityReport MakeReport(int score, params AuditResult[] results)
    {
        return new SecurityReport
        {
            SecurityScore = score,
            Results = results.ToList()
        };
    }

    private static AuditResult MakeAudit(string category, int _score, params Finding[] findings)
    {
        // Note: Score is computed from findings via SecurityScorer.
        // The _score param is unused; the actual score comes from findings.
        return new AuditResult
        {
            ModuleName = category,
            Category = category,
            Findings = findings.ToList()
        };
    }

    private static Finding MakeFinding(string title, Severity severity,
        string? fixCommand = null, string? remediation = null, string? description = null)
    {
        return new Finding
        {
            Title = title,
            Severity = severity,
            FixCommand = fixCommand,
            Remediation = remediation,
            Description = description ?? $"Description for {title}"
        };
    }

    // ── Basic generation ─────────────────────────────────────────────

    [Fact]
    public void Generate_EmptyReport_ReturnsValidPosture()
    {
        var report = MakeReport(100);
        var posture = _service.Generate(report);

        Assert.Equal(100, posture.OverallScore);
        Assert.Equal(PostureLevel.Excellent, posture.PostureLevel);
        Assert.Equal(0, posture.TotalFindings);
        Assert.Equal(0, posture.CriticalCount);
        Assert.False(string.IsNullOrWhiteSpace(posture.ExecutiveSummary));
    }

    [Fact]
    public void Generate_WithFindings_CountsCorrectly()
    {
        var report = MakeReport(65,
            MakeAudit("Firewall", 50,
                MakeFinding("FW Off", Severity.Critical, fixCommand: "netsh advfirewall set allprofiles state on"),
                MakeFinding("FW Rule", Severity.Warning)),
            MakeAudit("Updates", 80,
                MakeFinding("Updates OK", Severity.Pass),
                MakeFinding("Optional Update", Severity.Info))
        );

        var posture = _service.Generate(report);

        Assert.Equal(4, posture.TotalFindings);
        Assert.Equal(1, posture.CriticalCount);
        Assert.Equal(1, posture.WarningCount);
        Assert.Equal(1, posture.InfoCount);
        Assert.Equal(1, posture.PassCount);
        Assert.Equal(1, posture.AutoFixableCount);
    }

    // ── Posture level classification ─────────────────────────────────

    [Theory]
    [InlineData(95, PostureLevel.Excellent)]
    [InlineData(90, PostureLevel.Excellent)]
    [InlineData(89, PostureLevel.Good)]
    [InlineData(70, PostureLevel.Good)]
    [InlineData(69, PostureLevel.Fair)]
    [InlineData(50, PostureLevel.Fair)]
    [InlineData(49, PostureLevel.Poor)]
    [InlineData(30, PostureLevel.Poor)]
    [InlineData(29, PostureLevel.Critical)]
    [InlineData(0, PostureLevel.Critical)]
    public void ClassifyPosture_CorrectLevel(int score, PostureLevel expected)
    {
        Assert.Equal(expected, SecurityPostureService.ClassifyPosture(score));
    }

    // ── Module health ────────────────────────────────────────────────

    [Fact]
    public void ClassifyModuleHealth_HealthyNoIssues()
    {
        var findings = new List<Finding> { MakeFinding("OK", Severity.Pass) };
        Assert.Equal(ModuleHealth.Healthy,
            SecurityPostureService.ClassifyModuleHealth(95, findings));
    }

    [Fact]
    public void ClassifyModuleHealth_CriticalLowScore()
    {
        var findings = new List<Finding> { MakeFinding("Bad", Severity.Critical) };
        Assert.Equal(ModuleHealth.Critical,
            SecurityPostureService.ClassifyModuleHealth(40, findings));
    }

    [Fact]
    public void ClassifyModuleHealth_AtRiskCriticalHighScore()
    {
        var findings = new List<Finding> { MakeFinding("Risk", Severity.Critical) };
        Assert.Equal(ModuleHealth.AtRisk,
            SecurityPostureService.ClassifyModuleHealth(75, findings));
    }

    [Fact]
    public void ClassifyModuleHealth_ModerateNoCritical()
    {
        var findings = new List<Finding> { MakeFinding("Warn", Severity.Warning) };
        Assert.Equal(ModuleHealth.Moderate,
            SecurityPostureService.ClassifyModuleHealth(80, findings));
    }

    [Fact]
    public void ClassifyModuleHealth_NeedsAttentionLowScoreNoCritical()
    {
        var findings = new List<Finding> { MakeFinding("Warn", Severity.Warning) };
        Assert.Equal(ModuleHealth.NeedsAttention,
            SecurityPostureService.ClassifyModuleHealth(60, findings));
    }

    // ── Score delta / trend ──────────────────────────────────────────

    [Fact]
    public void Generate_WithPreviousScore_ComputesDelta()
    {
        var report = MakeReport(75);
        var posture = _service.Generate(report, previousScore: 70);

        Assert.Equal(5, posture.ScoreDelta);
        Assert.Equal(TrendDirection.Improving, posture.TrendDirection);
    }

    [Fact]
    public void Generate_ScoreDeclined_DecliningTrend()
    {
        var report = MakeReport(60);
        var posture = _service.Generate(report, previousScore: 70);

        Assert.Equal(-10, posture.ScoreDelta);
        Assert.Equal(TrendDirection.Declining, posture.TrendDirection);
    }

    [Fact]
    public void Generate_ScoreUnchanged_StableTrend()
    {
        var report = MakeReport(75);
        var posture = _service.Generate(report, previousScore: 74);

        Assert.Equal(1, posture.ScoreDelta);
        Assert.Equal(TrendDirection.Stable, posture.TrendDirection);
    }

    [Fact]
    public void Generate_NoPreviousScore_NoDelta()
    {
        var report = MakeReport(80);
        var posture = _service.Generate(report);

        Assert.Null(posture.ScoreDelta);
        Assert.Null(posture.TrendDirection);
    }

    // ── Module breakdown ─────────────────────────────────────────────

    [Fact]
    public void Generate_ModulesOrderedByScore()
    {
        var report = MakeReport(70,
            MakeAudit("Updates", 100), // no findings = 100
            MakeAudit("Firewall", 60,  // 2 critical = 60
                MakeFinding("FW Off", Severity.Critical),
                MakeFinding("FW Weak", Severity.Critical)),
            MakeAudit("Privacy", 80,   // 1 critical = 80
                MakeFinding("Privacy Issue", Severity.Critical))
        );

        var posture = _service.Generate(report);

        Assert.Equal(3, posture.ModuleBreakdown.Count);
        Assert.Equal("Firewall", posture.ModuleBreakdown[0].ModuleName);
        Assert.Equal("Privacy", posture.ModuleBreakdown[1].ModuleName);
        Assert.Equal("Updates", posture.ModuleBreakdown[2].ModuleName);
    }

    // ── Top risks ────────────────────────────────────────────────────

    [Fact]
    public void Generate_TopRisksCriticalFirst()
    {
        var report = MakeReport(50,
            MakeAudit("Test", 50,
                MakeFinding("Minor Issue", Severity.Warning),
                MakeFinding("Major Issue", Severity.Critical),
                MakeFinding("Info", Severity.Info))
        );

        var posture = _service.Generate(report);

        Assert.Equal(2, posture.TopRisks.Count);
        Assert.Equal(Severity.Critical, posture.TopRisks[0].Severity);
        Assert.Equal(Severity.Warning, posture.TopRisks[1].Severity);
    }

    [Fact]
    public void Generate_TopRisksMax10()
    {
        var findings = Enumerable.Range(1, 15)
            .Select(i => MakeFinding($"Finding {i}", Severity.Warning))
            .ToArray();

        var report = MakeReport(30, MakeAudit("Test", 30, findings));
        var posture = _service.Generate(report);

        Assert.Equal(10, posture.TopRisks.Count);
    }

    // ── Quick wins ───────────────────────────────────────────────────

    [Fact]
    public void Generate_QuickWinsOnlyAutoFixable()
    {
        var report = MakeReport(50,
            MakeAudit("Test", 50,
                MakeFinding("Auto Fix", Severity.Critical, fixCommand: "fix-it"),
                MakeFinding("Manual Fix", Severity.Critical, remediation: "Do it manually"),
                MakeFinding("Info", Severity.Info, fixCommand: "some-cmd"))
        );

        var posture = _service.Generate(report);

        Assert.Single(posture.QuickWins);
        Assert.Equal("Auto Fix", posture.QuickWins[0].Title);
        Assert.Equal("fix-it", posture.QuickWins[0].FixCommand);
    }

    // ── Executive summary ────────────────────────────────────────────

    [Fact]
    public void ExecutiveSummary_ContainsScore()
    {
        var report = MakeReport(75);
        var posture = _service.Generate(report);

        Assert.Contains("75/100", posture.ExecutiveSummary);
    }

    [Fact]
    public void ExecutiveSummary_ContainsCriticalCount()
    {
        var report = MakeReport(40,
            MakeAudit("Test", 40,
                MakeFinding("Crit1", Severity.Critical),
                MakeFinding("Crit2", Severity.Critical))
        );

        var posture = _service.Generate(report);
        Assert.Contains("2 critical findings", posture.ExecutiveSummary);
    }

    [Fact]
    public void ExecutiveSummary_MentionsTrendWhenDeclining()
    {
        var report = MakeReport(50);
        var posture = _service.Generate(report, previousScore: 70);

        Assert.Contains("down", posture.ExecutiveSummary);
    }

    // ── Recommendations ──────────────────────────────────────────────

    [Fact]
    public void Recommendations_CriticalFindingsFirst()
    {
        var report = MakeReport(40,
            MakeAudit("Test", 40,
                MakeFinding("Crit", Severity.Critical))
        );

        var posture = _service.Generate(report);

        Assert.NotEmpty(posture.Recommendations);
        Assert.Equal("Critical Findings", posture.Recommendations[0].Category);
    }

    [Fact]
    public void Recommendations_IncludesQuickWins()
    {
        var report = MakeReport(50,
            MakeAudit("Test", 50,
                MakeFinding("Auto", Severity.Warning, fixCommand: "fix"))
        );

        var posture = _service.Generate(report);
        Assert.Contains(posture.Recommendations, r => r.Category == "Quick Wins");
    }

    [Fact]
    public void Recommendations_IncludesWeakModule()
    {
        // 2 critical + 2 warning = 100-40-10 = 50 (below 70 threshold)
        var report = MakeReport(50,
            MakeAudit("WeakModule", 50,
                MakeFinding("Issue1", Severity.Critical),
                MakeFinding("Issue2", Severity.Critical),
                MakeFinding("Issue3", Severity.Warning),
                MakeFinding("Issue4", Severity.Warning))
        );

        var posture = _service.Generate(report);
        Assert.Contains(posture.Recommendations, r =>
            r.Category == "Module Focus" && r.Action.Contains("WeakModule"));
    }

    [Fact]
    public void Recommendations_DecliningTrendAlert()
    {
        var report = MakeReport(50);
        var posture = _service.Generate(report, previousScore: 70);

        Assert.Contains(posture.Recommendations, r => r.Category == "Trend Alert");
    }

    [Fact]
    public void Recommendations_ExcellentScoreGetsMaintenance()
    {
        var report = MakeReport(95);
        var posture = _service.Generate(report);

        Assert.Single(posture.Recommendations);
        Assert.Equal("Maintenance", posture.Recommendations[0].Category);
    }

    // ── Persistence data ─────────────────────────────────────────────

    [Fact]
    public void Generate_NoPersistenceDataByDefault()
    {
        var report = MakeReport(80);
        var posture = _service.Generate(report);

        Assert.False(posture.HasPersistenceData);
    }

    // ── Format report ────────────────────────────────────────────────

    [Fact]
    public void FormatReport_ContainsSections()
    {
        var report = MakeReport(65,
            MakeAudit("Firewall", 40,
                MakeFinding("FW Off", Severity.Critical, fixCommand: "netsh advfirewall set allprofiles state on")),
            MakeAudit("Updates", 90,
                MakeFinding("All Good", Severity.Pass))
        );

        var posture = _service.Generate(report, previousScore: 70);
        var text = SecurityPostureService.FormatReport(posture);

        Assert.Contains("SECURITY POSTURE REPORT", text);
        Assert.Contains("Executive Summary", text);
        Assert.Contains("Score Card", text);
        Assert.Contains("Findings", text);
        Assert.Contains("Module Health", text);
        Assert.Contains("Top Risks", text);
        Assert.Contains("Quick Wins", text);
        Assert.Contains("Recommendations", text);
    }

    [Fact]
    public void FormatReport_ModuleBarChart()
    {
        // 1 warning = score 95, so bar has some filled and some empty
        var report = MakeReport(95,
            MakeAudit("TestModule", 95,
                MakeFinding("Minor", Severity.Warning))
        );

        var posture = _service.Generate(report);
        var text = SecurityPostureService.FormatReport(posture);

        Assert.Contains("█", text);
        Assert.Contains("░", text);
        Assert.Contains("TestModule", text);
    }

    [Fact]
    public void FormatReport_ShowsTrendArrow()
    {
        var report = MakeReport(80);
        var posture = _service.Generate(report, previousScore: 70);
        var text = SecurityPostureService.FormatReport(posture);

        Assert.Contains("↑", text);
        Assert.Contains("Improving", text);
    }

    [Fact]
    public void FormatReport_DownArrowOnDecline()
    {
        var report = MakeReport(50);
        var posture = _service.Generate(report, previousScore: 80);
        var text = SecurityPostureService.FormatReport(posture);

        Assert.Contains("↓", text);
    }

    [Fact]
    public void FormatReport_ContainsTimestamp()
    {
        var report = MakeReport(80);
        var posture = _service.Generate(report);
        var text = SecurityPostureService.FormatReport(posture);

        Assert.Contains("Generated:", text);
    }

    // ── Edge cases ───────────────────────────────────────────────────

    [Fact]
    public void Generate_AllPassFindings_ExcellentPosture()
    {
        var report = MakeReport(100,
            MakeAudit("All Good", 100,
                MakeFinding("Check 1", Severity.Pass),
                MakeFinding("Check 2", Severity.Pass))
        );

        var posture = _service.Generate(report);

        Assert.Equal(PostureLevel.Excellent, posture.PostureLevel);
        Assert.Equal(0, posture.CriticalCount);
        Assert.Equal(0, posture.WarningCount);
        Assert.Equal(2, posture.PassCount);
        Assert.Empty(posture.TopRisks);
        Assert.Empty(posture.QuickWins);
    }

    [Fact]
    public void Generate_AllCritical_CriticalPosture()
    {
        var findings = Enumerable.Range(1, 5)
            .Select(i => MakeFinding($"Critical {i}", Severity.Critical))
            .ToArray();

        var report = MakeReport(10, MakeAudit("Disaster", 10, findings));
        var posture = _service.Generate(report);

        Assert.Equal(PostureLevel.Critical, posture.PostureLevel);
        Assert.Equal(5, posture.CriticalCount);
        Assert.Equal(5, posture.TopRisks.Count);
    }

    [Fact]
    public void Generate_ZeroScore_HandledGracefully()
    {
        var report = MakeReport(0);
        var posture = _service.Generate(report);

        Assert.Equal(PostureLevel.Critical, posture.PostureLevel);
        Assert.Equal("F", posture.Grade);
    }

    // ── Executive summary: singular forms ────────────────────────────

    [Fact]
    public void ExecutiveSummary_SingleCritical_SingularForm()
    {
        var report = MakeReport(40,
            MakeAudit("Test", 40,
                MakeFinding("One Critical", Severity.Critical))
        );

        var posture = _service.Generate(report);
        Assert.Contains("1 critical finding ", posture.ExecutiveSummary);
        Assert.DoesNotContain("findings ", posture.ExecutiveSummary.Replace("1 critical finding require", ""));
    }

    [Fact]
    public void ExecutiveSummary_SingleQuickWin_SingularForm()
    {
        var report = MakeReport(50,
            MakeAudit("Test", 50,
                MakeFinding("Fix Me", Severity.Warning, fixCommand: "fix"))
        );

        var posture = _service.Generate(report);
        Assert.Contains("1 issue ", posture.ExecutiveSummary);
    }

    [Fact]
    public void ExecutiveSummary_MultipleQuickWins_PluralForm()
    {
        var report = MakeReport(40,
            MakeAudit("Test", 40,
                MakeFinding("Fix1", Severity.Warning, fixCommand: "fix1"),
                MakeFinding("Fix2", Severity.Critical, fixCommand: "fix2"))
        );

        var posture = _service.Generate(report);
        Assert.Contains("2 issues", posture.ExecutiveSummary);
    }

    [Fact]
    public void ExecutiveSummary_UnchangedScore_MentionsUnchanged()
    {
        var report = MakeReport(75);
        var posture = _service.Generate(report, previousScore: 75);

        Assert.Contains("unchanged", posture.ExecutiveSummary);
    }

    [Fact]
    public void ExecutiveSummary_ImprovingScore_MentionsUp()
    {
        var report = MakeReport(80);
        var posture = _service.Generate(report, previousScore: 70);

        Assert.Contains("up", posture.ExecutiveSummary);
        Assert.Contains("10 point", posture.ExecutiveSummary);
    }

    [Fact]
    public void ExecutiveSummary_SinglePointDelta_SingularPoint()
    {
        var report = MakeReport(74);
        var posture = _service.Generate(report, previousScore: 71);

        // Delta = 3, Improving (>2)
        Assert.Contains("3 points", posture.ExecutiveSummary);
    }

    // ── Recommendations: priority ordering ───────────────────────────

    [Fact]
    public void Recommendations_PrioritiesAreSequential()
    {
        var report = MakeReport(35,
            MakeAudit("Weak", 30,
                MakeFinding("Crit", Severity.Critical, fixCommand: "fix"),
                MakeFinding("Warn", Severity.Warning, fixCommand: "fix2"))
        );

        var posture = _service.Generate(report, previousScore: 60);
        for (int i = 0; i < posture.Recommendations.Count; i++)
        {
            Assert.Equal(i + 1, posture.Recommendations[i].Priority);
        }
    }

    [Fact]
    public void Recommendations_DecliningTrend_ContainsTrendAlert()
    {
        var report = MakeReport(50);
        var posture = _service.Generate(report, previousScore: 65);

        Assert.Contains(posture.Recommendations, r => r.Category == "Trend Alert");
        var trend = posture.Recommendations.First(r => r.Category == "Trend Alert");
        Assert.Equal("Medium", trend.Impact);
        Assert.Contains("15 points", trend.Action);
    }

    // ── Recommendations: quick win effort label ──────────────────────

    [Fact]
    public void Recommendations_QuickWinsCriticalAutoFix_EffortLowMedium()
    {
        // When critical findings have auto-fix, effort should be Low-Medium
        var report = MakeReport(40,
            MakeAudit("Test", 40,
                MakeFinding("Crit with fix", Severity.Critical, fixCommand: "fix-cmd"))
        );

        var posture = _service.Generate(report);
        var critRec = posture.Recommendations.FirstOrDefault(r => r.Category == "Critical Findings");
        Assert.NotNull(critRec);
        Assert.Equal("Low-Medium", critRec.Effort);
    }

    [Fact]
    public void Recommendations_CriticalNoAutoFix_EffortMediumHigh()
    {
        // When critical findings have NO auto-fix, effort should be Medium-High
        var report = MakeReport(40,
            MakeAudit("Test", 40,
                MakeFinding("Crit no fix", Severity.Critical),
                MakeFinding("Crit no fix 2", Severity.Critical))
        );

        var posture = _service.Generate(report);
        var critRec = posture.Recommendations.FirstOrDefault(r => r.Category == "Critical Findings");
        Assert.NotNull(critRec);
        Assert.Equal("Medium-High", critRec.Effort);
    }

    // ── FormatReport: persistence section ────────────────────────────

    [Fact]
    public void FormatReport_WithPersistenceData_ShowsChronicCounts()
    {
        var report = MakeReport(70);
        var posture = _service.Generate(report);
        posture.HasPersistenceData = true;
        posture.NewCount = 3;
        posture.PersistentCount = 2;
        posture.ResolvedCount = 1;

        var text = SecurityPostureService.FormatReport(posture);

        Assert.Contains("New:", text);
        Assert.Contains("Chronic:", text);
        Assert.Contains("Resolved:", text);
    }

    [Fact]
    public void FormatReport_WithoutPersistenceData_NoChronic()
    {
        var report = MakeReport(70);
        var posture = _service.Generate(report);
        posture.HasPersistenceData = false;

        var text = SecurityPostureService.FormatReport(posture);

        Assert.DoesNotContain("Chronic:", text);
        Assert.DoesNotContain("Resolved:", text);
    }

    // ── FormatReport: compliance section ─────────────────────────────

    [Fact]
    public void FormatReport_WithCompliance_ShowsComplianceSection()
    {
        var report = MakeReport(75);
        var posture = _service.Generate(report);
        posture.ComplianceProfile = "NIST-800-53";
        posture.ComplianceScore = 72;
        posture.ComplianceStatus = "Partially Compliant";

        var text = SecurityPostureService.FormatReport(posture);

        Assert.Contains("Compliance", text);
        Assert.Contains("NIST-800-53", text);
        Assert.Contains("72/100", text);
        Assert.Contains("Partially Compliant", text);
    }

    [Fact]
    public void FormatReport_NoCompliance_NoComplianceSection()
    {
        var report = MakeReport(80);
        var posture = _service.Generate(report);

        var text = SecurityPostureService.FormatReport(posture);

        // Should NOT have the compliance section header between dividers
        var lines = text.Split('\n');
        Assert.DoesNotContain(lines, l => l.Trim() == "── Compliance ──");
    }

    // ── FormatReport: stable trend arrow ─────────────────────────────

    [Fact]
    public void FormatReport_StableTrend_RightArrow()
    {
        // ScoreDelta = 0 → arrow = "→"
        var report = MakeReport(75);
        var posture = _service.Generate(report, previousScore: 75);

        var text = SecurityPostureService.FormatReport(posture);

        Assert.Contains("Stable", text);
    }

    // ── FormatReport: no trend (no previous) ─────────────────────────

    [Fact]
    public void FormatReport_NoPreviousScore_NoTrendLine()
    {
        var report = MakeReport(80);
        var posture = _service.Generate(report);

        var text = SecurityPostureService.FormatReport(posture);

        Assert.DoesNotContain("↑", text);
        Assert.DoesNotContain("↓", text);
        Assert.DoesNotContain("→", text);
    }

    // ── Module health boundary tests ─────────────────────────────────

    [Theory]
    [InlineData(90, false, ModuleHealth.Healthy)]
    [InlineData(89, false, ModuleHealth.Moderate)]
    [InlineData(70, false, ModuleHealth.Moderate)]
    [InlineData(69, false, ModuleHealth.NeedsAttention)]
    [InlineData(50, true, ModuleHealth.AtRisk)]
    [InlineData(49, true, ModuleHealth.Critical)]
    [InlineData(100, false, ModuleHealth.Healthy)]
    [InlineData(0, false, ModuleHealth.NeedsAttention)]
    [InlineData(0, true, ModuleHealth.Critical)]
    public void ClassifyModuleHealth_BoundaryValues(int score, bool hasCritical, ModuleHealth expected)
    {
        var findings = new List<Finding>();
        if (hasCritical)
            findings.Add(MakeFinding("Crit", Severity.Critical));
        else
            findings.Add(MakeFinding("Warn", Severity.Warning));

        Assert.Equal(expected,
            SecurityPostureService.ClassifyModuleHealth(score, findings));
    }

    // ── Quick wins: estimated impact ─────────────────────────────────

    [Fact]
    public void QuickWins_CriticalSeverity_HighImpact()
    {
        var report = MakeReport(40,
            MakeAudit("Test", 40,
                MakeFinding("Critical Fix", Severity.Critical, fixCommand: "fix"))
        );

        var posture = _service.Generate(report);

        Assert.Single(posture.QuickWins);
        Assert.Equal("High", posture.QuickWins[0].EstimatedImpact);
    }

    [Fact]
    public void QuickWins_WarningSeverity_MediumImpact()
    {
        var report = MakeReport(60,
            MakeAudit("Test", 60,
                MakeFinding("Warning Fix", Severity.Warning, fixCommand: "fix"))
        );

        var posture = _service.Generate(report);

        Assert.Single(posture.QuickWins);
        Assert.Equal("Medium", posture.QuickWins[0].EstimatedImpact);
    }

    [Fact]
    public void QuickWins_InfoWithFixCommand_NotIncluded()
    {
        var report = MakeReport(80,
            MakeAudit("Test", 80,
                MakeFinding("Info Item", Severity.Info, fixCommand: "some-cmd"))
        );

        var posture = _service.Generate(report);

        // Info-level findings with fix commands should NOT be quick wins
        Assert.Empty(posture.QuickWins);
    }

    // ── Module breakdown: module names and counts ─────────────────────

    [Fact]
    public void ModuleBreakdown_CapturesCorrectCounts()
    {
        var report = MakeReport(60,
            MakeAudit("Network", 60,
                MakeFinding("Net1", Severity.Critical),
                MakeFinding("Net2", Severity.Warning),
                MakeFinding("Net3", Severity.Info))
        );

        var posture = _service.Generate(report);

        Assert.Single(posture.ModuleBreakdown);
        var module = posture.ModuleBreakdown[0];
        Assert.Equal("Network", module.ModuleName);
        Assert.Equal(3, module.FindingCount);
        Assert.Equal(1, module.CriticalCount);
        Assert.Equal(1, module.WarningCount);
    }

    // ── Top risks: module association ─────────────────────────────────

    [Fact]
    public void TopRisks_IncludesCorrectModuleName()
    {
        var report = MakeReport(50,
            MakeAudit("Firewall", 50,
                MakeFinding("FW Issue", Severity.Critical))
        );

        var posture = _service.Generate(report);

        Assert.Single(posture.TopRisks);
        Assert.Equal("Firewall", posture.TopRisks[0].Module);
    }

    [Fact]
    public void TopRisks_HasAutoFix_Correct()
    {
        var report = MakeReport(50,
            MakeAudit("Test", 50,
                MakeFinding("WithFix", Severity.Warning, fixCommand: "cmd"),
                MakeFinding("NoFix", Severity.Warning))
        );

        var posture = _service.Generate(report);

        var withFix = posture.TopRisks.First(r => r.Title == "WithFix");
        var noFix = posture.TopRisks.First(r => r.Title == "NoFix");

        Assert.True(withFix.HasAutoFix);
        Assert.False(noFix.HasAutoFix);
    }

    // ── PostureReport defaults ───────────────────────────────────────

    [Fact]
    public void PostureReport_DefaultValues()
    {
        var p = new PostureReport();

        Assert.Equal("", p.Grade);
        Assert.Equal("", p.ExecutiveSummary);
        Assert.Null(p.ScoreDelta);
        Assert.Null(p.TrendDirection);
        Assert.False(p.HasPersistenceData);
        Assert.Null(p.ComplianceProfile);
        Assert.Null(p.ComplianceScore);
        Assert.Null(p.ComplianceStatus);
        Assert.Empty(p.ModuleBreakdown);
        Assert.Empty(p.TopRisks);
        Assert.Empty(p.QuickWins);
        Assert.Empty(p.Recommendations);
    }

    // ── FormatReport: empty sections ─────────────────────────────────

    [Fact]
    public void FormatReport_NoModules_SkipsModuleSection()
    {
        var posture = new PostureReport
        {
            OverallScore = 80,
            Grade = "B",
            PostureLevel = PostureLevel.Good,
            ExecutiveSummary = "Test summary.",
        };

        var text = SecurityPostureService.FormatReport(posture);

        Assert.DoesNotContain("Module Health", text);
    }

    [Fact]
    public void FormatReport_NoRisks_SkipsRiskSection()
    {
        var posture = new PostureReport
        {
            OverallScore = 95,
            Grade = "A",
            PostureLevel = PostureLevel.Excellent,
            ExecutiveSummary = "All clear.",
        };

        var text = SecurityPostureService.FormatReport(posture);

        Assert.DoesNotContain("Top Risks", text);
    }

    [Fact]
    public void FormatReport_NoQuickWins_SkipsQuickWinSection()
    {
        var posture = new PostureReport
        {
            OverallScore = 90,
            Grade = "A",
            PostureLevel = PostureLevel.Excellent,
            ExecutiveSummary = "Good.",
        };

        var text = SecurityPostureService.FormatReport(posture);

        Assert.DoesNotContain("Quick Wins", text);
    }
}
