using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Models;

/// <summary>
/// Tests for <see cref="SeverityExtensions"/> ensuring the centralised
/// severity helpers stay stable. These weights are used by aggregate
/// scoring across the codebase, so accidental drift here would silently
/// shift risk scores.
/// </summary>
public class SeverityExtensionsTests
{
    [Theory]
    [InlineData(Severity.Critical, 10)]
    [InlineData(Severity.Warning, 5)]
    [InlineData(Severity.Info, 1)]
    [InlineData(Severity.Pass, 0)]
    public void RiskWeight_ReturnsExpectedWeight(Severity severity, int expected)
    {
        Assert.Equal(expected, severity.RiskWeight());
    }

    [Fact]
    public void RiskWeight_UnknownEnumValue_ReturnsZero()
    {
        // Defensive: future-added enum value should not blow up scoring;
        // it must fall through to the default branch and return 0.
        var bogus = (Severity)999;
        Assert.Equal(0, bogus.RiskWeight());
    }

    [Theory]
    [InlineData(Severity.Critical, "CRITICAL")]
    [InlineData(Severity.Warning, "WARNING")]
    [InlineData(Severity.Info, "INFO")]
    [InlineData(Severity.Pass, "PASS")]
    public void ShortLabel_ReturnsExpectedLabel(Severity severity, string expected)
    {
        Assert.Equal(expected, severity.ShortLabel());
    }

    [Fact]
    public void ShortLabel_UnknownEnumValue_ReturnsUnknown()
    {
        var bogus = (Severity)999;
        Assert.Equal("UNKNOWN", bogus.ShortLabel());
    }

    [Fact]
    public void ShortLabel_IsAllUppercaseForKnownValues()
    {
        // Reports and log formatters depend on these labels being
        // upper-cased (no localisation, no lower-case fallthrough).
        foreach (Severity s in Enum.GetValues(typeof(Severity)))
        {
            var label = s.ShortLabel();
            Assert.Equal(label, label.ToUpperInvariant());
        }
    }

    [Fact]
    public void RiskWeight_OrderingMatchesSeverityOrdering()
    {
        // Critical must outweigh Warning must outweigh Info must outweigh Pass.
        Assert.True(Severity.Critical.RiskWeight() > Severity.Warning.RiskWeight());
        Assert.True(Severity.Warning.RiskWeight()  > Severity.Info.RiskWeight());
        Assert.True(Severity.Info.RiskWeight()     > Severity.Pass.RiskWeight());
    }
}
