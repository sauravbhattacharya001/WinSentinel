using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

/// <summary>
/// Tests for the SecurityScorer calculations.
/// </summary>
public class SecurityScorerTests
{
    [Fact]
    public void CalculateScore_PerfectWithNoResults()
    {
        var report = new SecurityReport();
        Assert.Equal(100, SecurityScorer.CalculateScore(report));
    }

    [Fact]
    public void CalculateScore_PerfectWithOnlyPassFindings()
    {
        var report = new SecurityReport();
        report.Results.Add(new AuditResult
        {
            ModuleName = "Test",
            Category = "Test",
            Findings = { Finding.Pass("P1", "D", "C"), Finding.Pass("P2", "D", "C") }
        });

        Assert.Equal(100, SecurityScorer.CalculateScore(report));
    }

    [Fact]
    public void CalculateScore_DeductsAcrossModules()
    {
        var report = new SecurityReport();
        report.Results.Add(new AuditResult
        {
            ModuleName = "Mod1",
            Category = "Cat1",
            Findings = { Finding.Critical("C1", "D", "C") } // -15
        });
        report.Results.Add(new AuditResult
        {
            ModuleName = "Mod2",
            Category = "Cat2",
            Findings = { Finding.Warning("W1", "D", "C") } // -5
        });

        Assert.Equal(80, SecurityScorer.CalculateScore(report));
    }

    [Fact]
    public void CalculateScore_FlooredAtZero()
    {
        var report = new SecurityReport();
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        for (int i = 0; i < 20; i++)
            result.Findings.Add(Finding.Critical($"C{i}", "D", "C"));
        report.Results.Add(result);

        Assert.Equal(0, SecurityScorer.CalculateScore(report));
    }

    [Fact]
    public void CalculateCategoryScore_SingleModule()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        result.Findings.Add(Finding.Warning("W1", "D", "C")); // -5
        result.Findings.Add(Finding.Info("I1", "D", "C"));    // -1

        Assert.Equal(94, SecurityScorer.CalculateCategoryScore(result));
    }

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
    public void GetGrade_ReturnsCorrectGrade(int score, string expected)
    {
        Assert.Equal(expected, SecurityScorer.GetGrade(score));
    }

    [Theory]
    [InlineData(90, "#4CAF50")]  // Green
    [InlineData(80, "#4CAF50")]  // Green
    [InlineData(79, "#FFC107")]  // Yellow
    [InlineData(60, "#FFC107")]  // Yellow
    [InlineData(59, "#FF9800")]  // Orange
    [InlineData(40, "#FF9800")]  // Orange
    [InlineData(39, "#F44336")]  // Red
    [InlineData(0, "#F44336")]   // Red
    public void GetScoreColor_ReturnsCorrectColor(int score, string expected)
    {
        Assert.Equal(expected, SecurityScorer.GetScoreColor(score));
    }

    [Fact]
    public void SecurityReport_AggregatesCorrectly()
    {
        var report = new SecurityReport();
        report.Results.Add(new AuditResult
        {
            ModuleName = "M1", Category = "C1",
            Findings =
            {
                Finding.Critical("C1", "D", "C"),
                Finding.Warning("W1", "D", "C"),
            }
        });
        report.Results.Add(new AuditResult
        {
            ModuleName = "M2", Category = "C2",
            Findings =
            {
                Finding.Info("I1", "D", "C"),
                Finding.Pass("P1", "D", "C"),
            }
        });

        Assert.Equal(4, report.TotalFindings);
        Assert.Equal(1, report.TotalCritical);
        Assert.Equal(1, report.TotalWarnings);
        Assert.Equal(1, report.TotalInfo);
        Assert.Equal(1, report.TotalPass);
    }
}
