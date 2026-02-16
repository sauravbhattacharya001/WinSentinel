using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Models;

/// <summary>
/// Tests for AuditResult scoring and severity calculations.
/// </summary>
public class AuditResultTests
{
    [Fact]
    public void Score_PerfectWhenNoFindings()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        Assert.Equal(100, result.Score);
    }

    [Fact]
    public void Score_DeductsCritical20Points()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        result.Findings.Add(Finding.Critical("C1", "Desc", "Cat"));

        Assert.Equal(80, result.Score);
    }

    [Fact]
    public void Score_DeductsWarning5Points()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        result.Findings.Add(Finding.Warning("W1", "Desc", "Cat"));

        Assert.Equal(95, result.Score);
    }

    [Fact]
    public void Score_InfoDoesNotDeduct()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        result.Findings.Add(Finding.Info("I1", "Desc", "Cat"));

        Assert.Equal(100, result.Score);
    }

    [Fact]
    public void Score_PassDoesNotDeduct()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        result.Findings.Add(Finding.Pass("P1", "Desc", "Cat"));

        Assert.Equal(100, result.Score);
    }

    [Fact]
    public void Score_NeverBelowZero()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        // 10 critical findings = 150 points deduction
        for (int i = 0; i < 10; i++)
            result.Findings.Add(Finding.Critical($"C{i}", "Desc", "Cat"));

        Assert.Equal(0, result.Score);
    }

    [Fact]
    public void Score_MixedFindings()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        result.Findings.Add(Finding.Critical("C1", "Desc", "Cat"));  // -20
        result.Findings.Add(Finding.Warning("W1", "Desc", "Cat"));   // -5
        result.Findings.Add(Finding.Info("I1", "Desc", "Cat"));      // -0
        result.Findings.Add(Finding.Pass("P1", "Desc", "Cat"));      // -0

        Assert.Equal(75, result.Score);
    }

    [Fact]
    public void Counts_CorrectlyTallied()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        result.Findings.Add(Finding.Critical("C1", "Desc", "Cat"));
        result.Findings.Add(Finding.Critical("C2", "Desc", "Cat"));
        result.Findings.Add(Finding.Warning("W1", "Desc", "Cat"));
        result.Findings.Add(Finding.Info("I1", "Desc", "Cat"));
        result.Findings.Add(Finding.Info("I2", "Desc", "Cat"));
        result.Findings.Add(Finding.Info("I3", "Desc", "Cat"));
        result.Findings.Add(Finding.Pass("P1", "Desc", "Cat"));

        Assert.Equal(2, result.CriticalCount);
        Assert.Equal(1, result.WarningCount);
        Assert.Equal(3, result.InfoCount);
        Assert.Equal(1, result.PassCount);
    }

    [Fact]
    public void OverallSeverity_CriticalWhenHasCritical()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        result.Findings.Add(Finding.Pass("P1", "Desc", "Cat"));
        result.Findings.Add(Finding.Critical("C1", "Desc", "Cat"));

        Assert.Equal(Severity.Critical, result.OverallSeverity);
    }

    [Fact]
    public void OverallSeverity_WarningWhenNoHigher()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        result.Findings.Add(Finding.Warning("W1", "Desc", "Cat"));
        result.Findings.Add(Finding.Info("I1", "Desc", "Cat"));

        Assert.Equal(Severity.Warning, result.OverallSeverity);
    }

    [Fact]
    public void OverallSeverity_PassWhenAllPass()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        result.Findings.Add(Finding.Pass("P1", "Desc", "Cat"));

        Assert.Equal(Severity.Pass, result.OverallSeverity);
    }

    [Fact]
    public void OverallSeverity_PassWhenEmpty()
    {
        var result = new AuditResult { ModuleName = "Test", Category = "Test" };
        Assert.Equal(Severity.Pass, result.OverallSeverity);
    }

    [Fact]
    public void Duration_CalculatedFromStartAndEnd()
    {
        var start = DateTimeOffset.UtcNow;
        var end = start.AddSeconds(5);
        var result = new AuditResult
        {
            ModuleName = "Test",
            Category = "Test",
            StartTime = start,
            EndTime = end
        };

        Assert.Equal(TimeSpan.FromSeconds(5), result.Duration);
    }
}
