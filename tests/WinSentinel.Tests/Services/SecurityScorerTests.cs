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
            Findings = { Finding.Critical("C1", "D", "C") } // Score: 80
        });
        report.Results.Add(new AuditResult
        {
            ModuleName = "Mod2",
            Category = "Cat2",
            Findings = { Finding.Warning("W1", "D", "C") } // Score: 95
        });

        // Average of 80 and 95 = 87.5, rounded to 88
        Assert.Equal(88, SecurityScorer.CalculateScore(report));
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
        result.Findings.Add(Finding.Info("I1", "D", "C"));    // -0 (Info doesn't deduct)

        Assert.Equal(95, SecurityScorer.CalculateCategoryScore(result));
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

    // ── CalculateCategoryScore edge cases ──

    [Fact]
    public void CalculateCategoryScore_EmptyFindings_Returns100()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        Assert.Equal(100, SecurityScorer.CalculateCategoryScore(result));
    }

    [Fact]
    public void CalculateCategoryScore_OnlyInfoFindings_Returns100()
    {
        var result = new AuditResult
        {
            ModuleName = "Test", Category = "Test",
            Findings =
            {
                Finding.Info("I1", "D", "C"),
                Finding.Info("I2", "D", "C"),
                Finding.Info("I3", "D", "C"),
            }
        };
        Assert.Equal(100, SecurityScorer.CalculateCategoryScore(result));
    }

    [Fact]
    public void CalculateCategoryScore_OnlyPassFindings_Returns100()
    {
        var result = new AuditResult
        {
            ModuleName = "Test", Category = "Test",
            Findings =
            {
                Finding.Pass("P1", "D", "C"),
                Finding.Pass("P2", "D", "C"),
            }
        };
        Assert.Equal(100, SecurityScorer.CalculateCategoryScore(result));
    }

    [Fact]
    public void CalculateCategoryScore_MultipleWarnings_DeductsCorrectly()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        for (int i = 0; i < 4; i++)
            result.Findings.Add(Finding.Warning($"W{i}", "D", "C"));
        // 4 warnings * 5 = 20 deducted → 80
        Assert.Equal(80, SecurityScorer.CalculateCategoryScore(result));
    }

    [Fact]
    public void CalculateCategoryScore_MixedCriticalAndWarning()
    {
        var result = new AuditResult
        {
            ModuleName = "Test", Category = "Test",
            Findings =
            {
                Finding.Critical("C1", "D", "C"),  // -20
                Finding.Warning("W1", "D", "C"),   // -5
                Finding.Warning("W2", "D", "C"),   // -5
                Finding.Info("I1", "D", "C"),       // -0
            }
        };
        // 100 - 20 - 5 - 5 = 70
        Assert.Equal(70, SecurityScorer.CalculateCategoryScore(result));
    }

    [Fact]
    public void CalculateCategoryScore_ManyWarnings_FloorsAtZero()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        for (int i = 0; i < 25; i++)
            result.Findings.Add(Finding.Warning($"W{i}", "D", "C"));
        // 25 * 5 = 125 deduction, but floored at 0
        Assert.Equal(0, SecurityScorer.CalculateCategoryScore(result));
    }

    [Fact]
    public void CalculateCategoryScore_ExactlyOneWarning_Returns95()
    {
        var result = new AuditResult
        {
            ModuleName = "Test", Category = "Test",
            Findings = { Finding.Warning("W1", "D", "C") }
        };
        Assert.Equal(95, SecurityScorer.CalculateCategoryScore(result));
    }

    [Fact]
    public void CalculateCategoryScore_ExactlyOneCritical_Returns80()
    {
        var result = new AuditResult
        {
            ModuleName = "Test", Category = "Test",
            Findings = { Finding.Critical("C1", "D", "C") }
        };
        Assert.Equal(80, SecurityScorer.CalculateCategoryScore(result));
    }

    [Fact]
    public void CalculateCategoryScore_FiveCriticals_ReturnsZero()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        for (int i = 0; i < 5; i++)
            result.Findings.Add(Finding.Critical($"C{i}", "D", "C"));
        // 5 * 20 = 100 deduction → exactly 0
        Assert.Equal(0, SecurityScorer.CalculateCategoryScore(result));
    }

    // ── AuditResult.Score property (delegates to CalculateCategoryScore) ──

    [Fact]
    public void AuditResult_Score_MatchesCategoryScore()
    {
        var result = new AuditResult
        {
            ModuleName = "Test", Category = "Test",
            Findings =
            {
                Finding.Critical("C1", "D", "C"),
                Finding.Warning("W1", "D", "C"),
                Finding.Info("I1", "D", "C"),
            }
        };
        // Score property should delegate to CalculateCategoryScore
        Assert.Equal(
            SecurityScorer.CalculateCategoryScore(result),
            result.Score);
    }

    [Fact]
    public void AuditResult_Score_EmptyFindings_Returns100()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        Assert.Equal(100, result.Score);
    }

    [Fact]
    public void AuditResult_Score_FlooredAtZero()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        for (int i = 0; i < 10; i++)
            result.Findings.Add(Finding.Critical($"C{i}", "D", "C"));
        Assert.Equal(0, result.Score);
    }

    // ── CalculateScore (overall) edge cases ──

    [Fact]
    public void CalculateScore_ManyModules_AveragesCorrectly()
    {
        var report = new SecurityReport();
        // Module 1: 1 critical → score 80
        report.Results.Add(new AuditResult
        {
            ModuleName = "Mod1", Category = "Cat1",
            Findings = { Finding.Critical("C1", "D", "C") }
        });
        // Module 2: 0 findings → score 100
        report.Results.Add(new AuditResult
        {
            ModuleName = "Mod2", Category = "Cat2"
        });
        // Module 3: 2 warnings → score 90
        report.Results.Add(new AuditResult
        {
            ModuleName = "Mod3", Category = "Cat3",
            Findings = {
                Finding.Warning("W1", "D", "C"),
                Finding.Warning("W2", "D", "C"),
            }
        });
        // Average: (80 + 100 + 90) / 3 = 90
        Assert.Equal(90, SecurityScorer.CalculateScore(report));
    }

    [Fact]
    public void CalculateScore_RoundingUp()
    {
        var report = new SecurityReport();
        // Module 1: score 100
        report.Results.Add(new AuditResult
        {
            ModuleName = "M1", Category = "C1",
        });
        // Module 2: score 95
        report.Results.Add(new AuditResult
        {
            ModuleName = "M2", Category = "C2",
            Findings = { Finding.Warning("W1", "D", "C") }
        });
        // Module 3: score 95
        report.Results.Add(new AuditResult
        {
            ModuleName = "M3", Category = "C3",
            Findings = { Finding.Warning("W1", "D", "C") }
        });
        // Average: (100 + 95 + 95) / 3 = 96.666... → rounds to 97
        Assert.Equal(97, SecurityScorer.CalculateScore(report));
    }

    [Fact]
    public void CalculateScore_AllModulesZero_ReturnsZero()
    {
        var report = new SecurityReport();
        for (int m = 0; m < 3; m++)
        {
            var result = new AuditResult
            {
                ModuleName = $"Mod{m}", Category = $"Cat{m}"
            };
            for (int i = 0; i < 6; i++)
                result.Findings.Add(Finding.Critical($"C{i}", "D", "C"));
            report.Results.Add(result);
        }
        Assert.Equal(0, SecurityScorer.CalculateScore(report));
    }

    [Fact]
    public void CalculateScore_SingleModule_EqualsModuleScore()
    {
        var report = new SecurityReport();
        var result = new AuditResult
        {
            ModuleName = "M1", Category = "C1",
            Findings =
            {
                Finding.Warning("W1", "D", "C"),
                Finding.Warning("W2", "D", "C"),
            }
        };
        report.Results.Add(result);
        Assert.Equal(90, SecurityScorer.CalculateScore(report));
        Assert.Equal(SecurityScorer.CalculateCategoryScore(result),
                     SecurityScorer.CalculateScore(report));
    }

    // ── GetGrade boundary tests ──

    [Theory]
    [InlineData(91, "A")]
    [InlineData(90, "A")]  // exact boundary
    [InlineData(89, "B")]
    [InlineData(81, "B")]
    [InlineData(80, "B")]  // exact boundary
    [InlineData(79, "C")]
    [InlineData(71, "C")]
    [InlineData(70, "C")]  // exact boundary
    [InlineData(69, "D")]
    [InlineData(61, "D")]
    [InlineData(60, "D")]  // exact boundary
    [InlineData(59, "F")]
    [InlineData(1, "F")]
    [InlineData(0, "F")]
    public void GetGrade_BoundaryValues(int score, string expected)
    {
        Assert.Equal(expected, SecurityScorer.GetGrade(score));
    }

    // ── GetScoreColor boundary tests ──

    [Theory]
    [InlineData(100, "#4CAF50")]
    [InlineData(80, "#4CAF50")]  // exact boundary
    [InlineData(79, "#FFC107")]
    [InlineData(60, "#FFC107")]  // exact boundary
    [InlineData(59, "#FF9800")]
    [InlineData(40, "#FF9800")]  // exact boundary
    [InlineData(39, "#F44336")]
    [InlineData(0, "#F44336")]
    public void GetScoreColor_BoundaryValues(int score, string expected)
    {
        Assert.Equal(expected, SecurityScorer.GetScoreColor(score));
    }
}
