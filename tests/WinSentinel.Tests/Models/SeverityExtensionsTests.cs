using WinSentinel.Core.Models;
using System.Globalization;

namespace WinSentinel.Tests.Models;

/// <summary>
/// Tests for <see cref="SeverityExtensions"/> ensuring the centralised
/// severity helpers stay stable. These weights are used by aggregate
/// scoring across the codebase, so accidental drift here would silently
/// shift risk scores.
/// </summary>
[Trait("Category", "BVT")]
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

    [Theory]
    [InlineData(Severity.Critical, "Critical")]
    [InlineData(Severity.Warning, "Warning")]
    [InlineData(Severity.Info, "Info")]
    [InlineData(Severity.Pass, "Pass")]
    public void DisplayName_DefaultCulture_ReturnsEnglishLabel(Severity severity, string expected)
    {
        // Explicit invariant culture so the assertion is deterministic regardless
        // of the host machine's UI culture.
        Assert.Equal(expected, severity.DisplayName(CultureInfo.InvariantCulture));
    }

    [Theory]
    [InlineData(Severity.Critical, "Cr\u00edtico")]
    [InlineData(Severity.Warning, "Advertencia")]
    [InlineData(Severity.Info, "Informaci\u00f3n")]
    [InlineData(Severity.Pass, "Correcto")]
    public void DisplayName_SpanishCulture_ReturnsTranslatedLabel(Severity severity, string expected)
    {
        // Proves the es satellite assembly is embedded and resolved at runtime.
        Assert.Equal(expected, severity.DisplayName(new CultureInfo("es")));
    }

    [Fact]
    public void DisplayName_IsTitleCase_NotShortLabel()
    {
        // DisplayName is user-facing title case; ShortLabel is the invariant
        // upper-case log token. They must not be the same string.
        Assert.NotEqual(Severity.Critical.ShortLabel(), Severity.Critical.DisplayName(CultureInfo.InvariantCulture));
        Assert.Equal("Critical", Severity.Critical.DisplayName(CultureInfo.InvariantCulture));
    }

    [Fact]
    public void DisplayName_UnknownEnumValue_FallsBackToInfo()
    {
        // Defensive: an out-of-range value must not throw; it maps to the Info key.
        var bogus = (Severity)999;
        Assert.Equal("Info", bogus.DisplayName(CultureInfo.InvariantCulture));
    }
}
