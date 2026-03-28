using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class ExecutiveSummaryGeneratorTests
{
    private static SecurityReport CreateReport(int score, params AuditResult[] results)
    {
        return new SecurityReport
        {
            SecurityScore = score,
            Results = results.ToList()
        };
    }

    private static AuditResult CreateAuditResult(string module, string category, params Finding[] findings)
    {
        return new AuditResult
        {
            ModuleName = module,
            Category = category,
            Findings = findings.ToList()
        };
    }

    private static Finding Critical(string title, string? remediation = null) =>
        new() { Title = title, Description = "desc", Severity = Severity.Critical, Remediation = remediation };

    private static Finding Warning(string title, string? remediation = null) =>
        new() { Title = title, Description = "desc", Severity = Severity.Warning, Remediation = remediation };

    private static Finding Info(string title) =>
        new() { Title = title, Description = "desc", Severity = Severity.Info };

    private static Finding Pass(string title) =>
        new() { Title = title, Description = "desc", Severity = Severity.Pass };

    // ── Generate ────────────────────────────────────────────

    [Fact]
    public void Generate_EmptyReport_ReturnsValidSummary()
    {
        var gen = new ExecutiveSummaryGenerator();
        var report = CreateReport(100);

        var summary = gen.Generate(report);

        Assert.Equal(100, summary.Score);
        Assert.Equal(0, summary.TotalFindings);
        Assert.Empty(summary.TopRisks);
        Assert.Empty(summary.PriorityActions);
        Assert.Empty(summary.Categories);
    }

    [Theory]
    [InlineData(95, "well-secured")]
    [InlineData(80, "reasonable")]
    [InlineData(55, "Several significant")]
    [InlineData(30, "critically weak")]
    public void Generate_PostureNarrative_MatchesScoreRange(int score, string expectedFragment)
    {
        var gen = new ExecutiveSummaryGenerator();
        var report = CreateReport(score);

        var summary = gen.Generate(report);

        Assert.Contains(expectedFragment, summary.PostureNarrative);
    }

    [Fact]
    public void Generate_CategoriesGroupedAndSortedByScore()
    {
        var gen = new ExecutiveSummaryGenerator();
        var report = CreateReport(50,
            CreateAuditResult("Firewall", "Network", Critical("Open ports", "Close ports")),
            CreateAuditResult("DNS", "Network", Pass("DNS secured")),
            CreateAuditResult("Defender", "System", Warning("Outdated sigs")));

        var summary = gen.Generate(report);

        Assert.Equal(2, summary.Categories.Count);
        // Sorted by score ascending — worst first
        Assert.True(summary.Categories[0].Score <= summary.Categories[1].Score);
    }

    [Fact]
    public void Generate_TopRisks_LimitedToFive()
    {
        var gen = new ExecutiveSummaryGenerator();
        var findings = Enumerable.Range(1, 8)
            .Select(i => Critical($"Issue {i}", $"Fix {i}"))
            .ToArray();
        var report = CreateReport(20,
            CreateAuditResult("TestModule", "Security", findings));

        var summary = gen.Generate(report);

        Assert.True(summary.TopRisks.Count <= 5);
    }

    [Fact]
    public void Generate_TopRisks_CriticalBeforeWarning()
    {
        var gen = new ExecutiveSummaryGenerator();
        var report = CreateReport(50,
            CreateAuditResult("Mod", "Cat",
                Warning("Warn1"),
                Critical("Crit1"),
                Warning("Warn2")));

        var summary = gen.Generate(report);

        Assert.True(summary.TopRisks.Count >= 2);
        Assert.Equal(Severity.Critical, summary.TopRisks[0].Severity);
    }

    [Fact]
    public void Generate_PriorityActions_FromCriticalFindings()
    {
        var gen = new ExecutiveSummaryGenerator();
        var report = CreateReport(30,
            CreateAuditResult("Mod", "Cat",
                Critical("Issue A", "Fix A"),
                Critical("Issue B", "Fix B"),
                Warning("Warn C", "Fix C")));

        var summary = gen.Generate(report);

        Assert.Contains("Fix A", summary.PriorityActions);
        Assert.Contains("Fix B", summary.PriorityActions);
    }

    [Fact]
    public void Generate_PriorityActions_FallsBackToWarnings_WhenFewCritical()
    {
        var gen = new ExecutiveSummaryGenerator();
        var report = CreateReport(60,
            CreateAuditResult("Mod", "Cat",
                Critical("Only crit", "Critical fix"),
                Warning("Warn1", "Warning fix 1"),
                Warning("Warn2", "Warning fix 2")));

        var summary = gen.Generate(report);

        // Should have critical fix + warning fixes since < 3 critical actions
        Assert.True(summary.PriorityActions.Count >= 2);
    }

    [Fact]
    public void Generate_PriorityActions_DeduplicatesRemediation()
    {
        var gen = new ExecutiveSummaryGenerator();
        var report = CreateReport(30,
            CreateAuditResult("Mod", "Cat",
                Critical("Issue A", "Same fix"),
                Critical("Issue B", "Same fix")));

        var summary = gen.Generate(report);

        Assert.Single(summary.PriorityActions.Where(a => a == "Same fix"));
    }

    [Fact]
    public void Generate_CountsMatchReport()
    {
        var gen = new ExecutiveSummaryGenerator();
        var report = CreateReport(50,
            CreateAuditResult("Mod1", "Cat1",
                Critical("C1"), Warning("W1"), Info("I1"), Pass("P1")),
            CreateAuditResult("Mod2", "Cat2",
                Warning("W2"), Pass("P2")));

        var summary = gen.Generate(report);

        Assert.Equal(6, summary.TotalFindings);
        Assert.Equal(1, summary.CriticalCount);
        Assert.Equal(2, summary.WarningCount);
        Assert.Equal(1, summary.InfoCount);
        Assert.Equal(2, summary.PassCount);
        Assert.Equal(2, summary.ModulesScanned);
    }

    [Fact]
    public void Generate_NoHistory_TrendNoteIsNull()
    {
        var gen = new ExecutiveSummaryGenerator(historyService: null);
        var report = CreateReport(80);

        var summary = gen.Generate(report);

        Assert.Null(summary.TrendNote);
    }

    // ── RenderText ──────────────────────────────────────────

    [Fact]
    public void RenderText_ContainsGradeAndScore()
    {
        var summary = new ExecutiveSummary
        {
            Machine = "TEST-PC",
            Score = 85,
            Grade = "B",
            PostureNarrative = "Reasonable posture.",
            Categories = new(),
            TopRisks = new(),
            PriorityActions = new()
        };

        var text = ExecutiveSummaryGenerator.RenderText(summary);

        Assert.Contains("SECURITY GRADE: B", text);
        Assert.Contains("85/100", text);
        Assert.Contains("TEST-PC", text);
    }

    [Fact]
    public void RenderText_IncludesTopRisks()
    {
        var summary = new ExecutiveSummary
        {
            Machine = "PC",
            Grade = "D",
            Score = 30,
            PostureNarrative = "Bad",
            Categories = new(),
            TopRisks = new()
            {
                new SummaryRiskItem { Title = "Open SSH", Module = "Network", Severity = Severity.Critical, Remediation = "Close port 22" }
            },
            PriorityActions = new()
        };

        var text = ExecutiveSummaryGenerator.RenderText(summary);

        Assert.Contains("Open SSH", text);
        Assert.Contains("Close port 22", text);
    }

    // ── RenderMarkdown ──────────────────────────────────────

    [Fact]
    public void RenderMarkdown_ContainsHeaders()
    {
        var summary = new ExecutiveSummary
        {
            Machine = "PC",
            Grade = "A",
            Score = 95,
            PostureNarrative = "Excellent.",
            Categories = new(),
            TopRisks = new(),
            PriorityActions = new() { "Keep monitoring" }
        };

        var md = ExecutiveSummaryGenerator.RenderMarkdown(summary);

        Assert.Contains("# Executive Security Summary", md);
        Assert.Contains("## Recommended Actions", md);
        Assert.Contains("Keep monitoring", md);
    }

    [Fact]
    public void RenderMarkdown_IncludesCategoryTable()
    {
        var summary = new ExecutiveSummary
        {
            Machine = "PC",
            Grade = "C",
            Score = 60,
            PostureNarrative = "OK.",
            Categories = new()
            {
                new CategoryBrief { Category = "Network", Score = 50, Critical = 2, Warnings = 1, ModuleCount = 3 }
            },
            TopRisks = new(),
            PriorityActions = new()
        };

        var md = ExecutiveSummaryGenerator.RenderMarkdown(summary);

        Assert.Contains("## Category Breakdown", md);
        Assert.Contains("Network", md);
    }

    // ── RenderJson ──────────────────────────────────────────

    [Fact]
    public void RenderJson_IsValidJson()
    {
        var summary = new ExecutiveSummary
        {
            Machine = "PC",
            Grade = "A",
            Score = 95,
            PostureNarrative = "Great.",
            Categories = new(),
            TopRisks = new(),
            PriorityActions = new()
        };

        var json = ExecutiveSummaryGenerator.RenderJson(summary);

        Assert.Contains("\"Score\": 95", json);
        Assert.Contains("\"Grade\": \"A\"", json);
        // Should parse without error
        System.Text.Json.JsonDocument.Parse(json);
    }
}
