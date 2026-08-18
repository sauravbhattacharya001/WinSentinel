using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.DeliveryOptimizationAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="DeliveryOptimizationAnalyzer"/> -
/// the single-machine Windows Delivery Optimization download-source check. Every rule
/// is exercised directly against a synthetic <see cref="DeliveryOptimizationState"/>;
/// no registry or I/O is touched. The behaviour under test: Internet peering (mode 3)
/// warns, group peering (2) / LAN peering (1) are informational, HTTP-only (0) and
/// bypass (99/100) pass, policy overrides config, and absence of both maps to the
/// Windows default of LAN peering.
/// </summary>
public class DeliveryOptimizationAnalyzerTests
{
    private static Finding Only(DeliveryOptimizationState state)
    {
        var findings = Analyze(state);
        Assert.Single(findings);
        return findings[0];
    }

    [Fact]
    public void Analyze_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Analyze(null!));
    }

    [Fact]
    public void AnalyzeDownloadMode_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => AnalyzeDownloadMode(null!));
    }

    [Fact]
    public void Analyze_ReturnsSingleFinding_InCategory()
    {
        var finding = Only(new DeliveryOptimizationState { ConfigDownloadMode = 0 });
        Assert.Equal("Delivery Optimization", finding.Category);
    }

    [Fact]
    public void InternetPeering_Warns()
    {
        var finding = Only(new DeliveryOptimizationState { ConfigDownloadMode = 3 });
        Assert.Equal(Severity.Warning, finding.Severity);
        Assert.Contains("Internet peering", finding.Title);
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
    }

    [Fact]
    public void InternetPeering_ViaPolicy_ReportsPolicySource()
    {
        var finding = Only(new DeliveryOptimizationState { PolicyDownloadMode = 3 });
        Assert.Equal(Severity.Warning, finding.Severity);
        Assert.Contains("policy", finding.Description);
    }

    [Fact]
    public void GroupPeering_IsInfo()
    {
        var finding = Only(new DeliveryOptimizationState { ConfigDownloadMode = 2 });
        Assert.Equal(Severity.Info, finding.Severity);
        Assert.Contains("group peering", finding.Title);
    }

    [Fact]
    public void LanPeering_IsInfo()
    {
        var finding = Only(new DeliveryOptimizationState { ConfigDownloadMode = 1 });
        Assert.Equal(Severity.Info, finding.Severity);
        Assert.Contains("LAN peering", finding.Title);
    }

    [Fact]
    public void HttpOnly_Passes()
    {
        var finding = Only(new DeliveryOptimizationState { ConfigDownloadMode = 0 });
        Assert.Equal(Severity.Pass, finding.Severity);
        Assert.Contains("HTTP-only", finding.Title);
    }

    [Theory]
    [InlineData(99)]
    [InlineData(100)]
    public void BypassModes_Pass(int mode)
    {
        var finding = Only(new DeliveryOptimizationState { ConfigDownloadMode = mode });
        Assert.Equal(Severity.Pass, finding.Severity);
        Assert.Contains("peering is disabled", finding.Title);
    }

    [Fact]
    public void UnrecognizedMode_IsInfo()
    {
        var finding = Only(new DeliveryOptimizationState { ConfigDownloadMode = 42 });
        Assert.Equal(Severity.Info, finding.Severity);
        Assert.Contains("unrecognized", finding.Title);
    }

    [Fact]
    public void NoValues_DefaultsToLanPeering()
    {
        var finding = Only(new DeliveryOptimizationState());
        Assert.Equal(Severity.Info, finding.Severity);
        Assert.Contains("LAN peering", finding.Title);
        Assert.Contains("Windows default", finding.Description);
    }

    [Fact]
    public void Policy_OverridesConfig()
    {
        // Config would pass (HTTP only) but policy forces Internet peering => must warn.
        var finding = Only(new DeliveryOptimizationState { PolicyDownloadMode = 3, ConfigDownloadMode = 0 });
        Assert.Equal(Severity.Warning, finding.Severity);
        Assert.Contains("policy", finding.Description);
    }

    [Fact]
    public void Config_UsedWhenNoPolicy()
    {
        var finding = Only(new DeliveryOptimizationState { ConfigDownloadMode = 3 });
        Assert.Contains("config", finding.Description);
    }

    [Fact]
    public void DefaultDownloadMode_IsLanPeering()
    {
        Assert.Equal(1, DefaultDownloadMode);
    }

    [Fact]
    public void NonPassFindings_CarryRemediationAndFix()
    {
        foreach (var mode in new[] { 1, 2, 3, 42 })
        {
            var finding = Only(new DeliveryOptimizationState { ConfigDownloadMode = mode });
            Assert.False(string.IsNullOrWhiteSpace(finding.Remediation), $"mode {mode} missing remediation");
            Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand), $"mode {mode} missing fix command");
        }
    }
}
