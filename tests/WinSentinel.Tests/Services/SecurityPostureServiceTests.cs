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
}
