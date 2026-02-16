using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Models;

/// <summary>
/// Tests for the Finding model and its factory methods.
/// </summary>
public class FindingTests
{
    [Fact]
    public void Pass_CreatesPassSeverityFinding()
    {
        var finding = Finding.Pass("Test Title", "Test Description", "TestCategory");

        Assert.Equal("Test Title", finding.Title);
        Assert.Equal("Test Description", finding.Description);
        Assert.Equal("TestCategory", finding.Category);
        Assert.Equal(Severity.Pass, finding.Severity);
        Assert.Null(finding.Remediation);
        Assert.Null(finding.FixCommand);
    }

    [Fact]
    public void Info_CreatesInfoSeverityFinding()
    {
        var finding = Finding.Info("Info Title", "Info Desc", "Cat", "Fix it", "fix-cmd");

        Assert.Equal(Severity.Info, finding.Severity);
        Assert.Equal("Fix it", finding.Remediation);
        Assert.Equal("fix-cmd", finding.FixCommand);
    }

    [Fact]
    public void Warning_CreatesWarningSeverityFinding()
    {
        var finding = Finding.Warning("Warn", "Warn Desc", "Cat");
        Assert.Equal(Severity.Warning, finding.Severity);
    }

    [Fact]
    public void Critical_CreatesCriticalSeverityFinding()
    {
        var finding = Finding.Critical("Crit", "Crit Desc", "Cat", "Do this", "run this");

        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Equal("Do this", finding.Remediation);
        Assert.Equal("run this", finding.FixCommand);
    }

    [Fact]
    public void Finding_HasTimestamp()
    {
        var before = DateTimeOffset.UtcNow;
        var finding = Finding.Pass("Test", "Desc", "Cat");
        var after = DateTimeOffset.UtcNow;

        Assert.InRange(finding.Timestamp, before, after);
    }
}
