using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

/// <summary>
/// Tests for ReportCardService — GPA calculation, grading, trends, and formatting.
/// </summary>
public class ReportCardServiceTests
{
    private readonly ReportCardService _service = new();

    private static SecurityReport MakeReport(params (string module, string category, Severity[] findings)[] modules)
    {
        var report = new SecurityReport();
        foreach (var (module, category, findings) in modules)
        {
            var result = new AuditResult { ModuleName = module, Category = category };
            int i = 0;
            foreach (var sev in findings)
            {
                result.Findings.Add(new Finding
                {
                    Title = $"{module}-finding-{i++}",
                    Category = category,
                    Severity = sev,
                    Description = "",
                });
            }
            report.Results.Add(result);
        }
        report.SecurityScore = SecurityScorer.CalculateScore(report);
        return report;
    }

    [Fact]
    public void Generate_NoModules_ReturnsDefaultCard()
    {
        var report = new SecurityReport { SecurityScore = 100 };
        var card = _service.Generate(report);

        Assert.Equal(100, card.OverallScore);
        Assert.Equal("A", card.OverallGrade);
        Assert.Equal(4.0, card.Gpa);
        Assert.Empty(card.Modules);
        Assert.Empty(card.Improvements);
        Assert.Empty(card.Regressions);
    }

    [Fact]
    public void Generate_SingleModule_CorrectGrade()
    {
        // 1 critical = -20 => score 80 => B
        var report = MakeReport(("Firewall", "Network", new[] { Severity.Critical }));
        var card = _service.Generate(report);

        Assert.Single(card.Modules);
        Assert.Equal("B", card.Modules[0].Grade);
        Assert.Equal(80, card.Modules[0].Score);
        Assert.Equal(3.0, card.Gpa);
    }

    [Fact]
    public void Generate_MultipleModules_GpaIsAverage()
    {
        // Module A: score 100 (A=4.0), Module B: score 80 (B=3.0)
        var report = MakeReport(
            ("ModA", "CatA", Array.Empty<Severity>()),
            ("ModB", "CatB", new[] { Severity.Critical }));

        var card = _service.Generate(report);

        Assert.Equal(2, card.TotalModules);
        Assert.Equal(3.5, card.Gpa);
    }

    [Fact]
    public void Generate_FGradeModule_Gpa0()
    {
        // 3 criticals = -60 => score 40 => F
        var report = MakeReport(("Bad", "Security", new[] { Severity.Critical, Severity.Critical, Severity.Critical }));
        var card = _service.Generate(report);

        Assert.Equal("F", card.Modules[0].Grade);
        Assert.Equal(0.0, card.Gpa);
    }

    [Fact]
    public void Generate_WithPreviousScores_ShowsImprovement()
    {
        // Current: score 90 (A)
        var report = MakeReport(("Firewall", "Network", new[] { Severity.Warning, Severity.Warning }));
        // Previous: score 60 (D)
        var prev = new List<ModuleScoreRecord>
        {
            new() { ModuleName = "Firewall", Category = "Network", Score = 60 }
        };

        var card = _service.Generate(report, prev, 60);

        Assert.Single(card.Improvements);
        Assert.Empty(card.Regressions);
        Assert.Equal("↑", card.Modules[0].Trend);
        Assert.Equal("↑", card.GpaTrend);
    }

    [Fact]
    public void Generate_WithPreviousScores_ShowsRegression()
    {
        // Current: score 40 (F) — 3 criticals
        var report = MakeReport(("Accounts", "Auth", new[] { Severity.Critical, Severity.Critical, Severity.Critical }));
        // Previous: score 90 (A)
        var prev = new List<ModuleScoreRecord>
        {
            new() { ModuleName = "Accounts", Category = "Auth", Score = 90 }
        };

        var card = _service.Generate(report, prev, 90);

        Assert.Empty(card.Improvements);
        Assert.Single(card.Regressions);
        Assert.Equal("↓", card.Modules[0].Trend);
        Assert.Equal("↓", card.GpaTrend);
    }

    [Fact]
    public void Generate_GradeDistribution_Correct()
    {
        var report = MakeReport(
            ("M1", "C1", Array.Empty<Severity>()),                          // 100 = A
            ("M2", "C2", new[] { Severity.Warning }),                       // 95 = A
            ("M3", "C3", new[] { Severity.Critical }),                      // 80 = B
            ("M4", "C4", new[] { Severity.Critical, Severity.Critical }),   // 60 = D
            ("M5", "C5", new[] { Severity.Critical, Severity.Critical, Severity.Critical })); // 40 = F

        var card = _service.Generate(report);

        Assert.Equal(2, card.GradeDistribution["A"]);
        Assert.Equal(1, card.GradeDistribution["B"]);
        Assert.Equal(0, card.GradeDistribution["C"]);
        Assert.Equal(1, card.GradeDistribution["D"]);
        Assert.Equal(1, card.GradeDistribution["F"]);
    }

    [Fact]
    public void Generate_ModulesSortedWorstFirst()
    {
        var report = MakeReport(
            ("Good", "CatA", Array.Empty<Severity>()),
            ("Bad", "CatB", new[] { Severity.Critical, Severity.Critical, Severity.Critical }));

        var card = _service.Generate(report);

        Assert.Equal("Bad", card.Modules[0].ModuleName);
        Assert.Equal("Good", card.Modules[1].ModuleName);
    }

    [Fact]
    public void Generate_NextSteps_IncludesFailingModules()
    {
        var report = MakeReport(
            ("Bad", "Security", new[] { Severity.Critical, Severity.Critical, Severity.Critical }));

        var card = _service.Generate(report);

        Assert.Contains(card.NextSteps, s => s.Contains("URGENT") && s.Contains("Security"));
    }

    [Fact]
    public void GradeToPoints_AllGrades()
    {
        Assert.Equal(4.0, ReportCardService.GradeToPoints("A"));
        Assert.Equal(3.0, ReportCardService.GradeToPoints("B"));
        Assert.Equal(2.0, ReportCardService.GradeToPoints("C"));
        Assert.Equal(1.0, ReportCardService.GradeToPoints("D"));
        Assert.Equal(0.0, ReportCardService.GradeToPoints("F"));
    }

    [Fact]
    public void FormatText_ContainsKeyElements()
    {
        var report = MakeReport(
            ("Firewall", "Network", new[] { Severity.Warning }),
            ("Accounts", "Auth", new[] { Severity.Critical }));
        var card = _service.Generate(report);

        var text = ReportCardService.FormatText(card);

        Assert.Contains("Report Card", text);
        Assert.Contains("GPA", text);
        Assert.Contains("Module Grades", text);
        Assert.Contains("Network", text);
        Assert.Contains("Auth", text);
    }

    [Fact]
    public void FormatHtml_ContainsHtmlStructure()
    {
        var report = MakeReport(("M1", "Cat", Array.Empty<Severity>()));
        var card = _service.Generate(report);

        var html = ReportCardService.FormatHtml(card);

        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains("Report Card", html);
        Assert.Contains("4.00", html);
    }

    [Fact]
    public void GenerateFromHistory_ProducesValidCard()
    {
        var currentRun = new AuditRunRecord
        {
            Id = 2,
            OverallScore = 85,
            ModuleScores = new()
            {
                new() { ModuleName = "Firewall", Category = "Network", Score = 85, CriticalCount = 0, WarningCount = 3 },
                new() { ModuleName = "Accounts", Category = "Auth", Score = 80, CriticalCount = 1, WarningCount = 0 },
            }
        };
        var previousRun = new AuditRunRecord
        {
            Id = 1,
            OverallScore = 70,
            ModuleScores = new()
            {
                new() { ModuleName = "Firewall", Category = "Network", Score = 70, CriticalCount = 1, WarningCount = 2 },
                new() { ModuleName = "Accounts", Category = "Auth", Score = 60, CriticalCount = 2, WarningCount = 0 },
            }
        };

        var card = _service.GenerateFromHistory(currentRun, previousRun);

        Assert.Equal(85, card.OverallScore);
        Assert.Equal(2, card.TotalModules);
        Assert.NotEmpty(card.Improvements);
        Assert.Equal("↑", card.GpaTrend);
    }
}
