using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.NetworkProtectionAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="NetworkProtectionAnalyzer"/> - the single-machine
/// Microsoft Defender Network Protection checks: Defender real-time protection active, Network
/// Protection mode (Disabled / Block / Audit), and cloud-delivered reputation backing. Every rule is
/// exercised directly against a synthetic <see cref="NetworkProtectionState"/>; no Get-MpPreference,
/// registry, or shell I/O is touched.
/// </summary>
public class NetworkProtectionAnalyzerTests
{
    private static NetworkProtectionState SecureState() => new()
    {
        DefenderRealTimeProtectionEnabled = true,
        Mode = ModeBlock,
        CloudProtectionEnabled = true,
    };

    [Fact]
    public void Analyze_Throws_On_Null_State()
    {
        Assert.Throws<ArgumentNullException>(() => NetworkProtectionAnalyzer.Analyze(null!));
    }

    [Fact]
    public void Analyze_Secure_State_Is_All_Pass()
    {
        var findings = NetworkProtectionAnalyzer.Analyze(SecureState());
        Assert.Equal(3, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal(Category, f.Category));
    }

    [Fact]
    public void Analyze_Is_Deterministic_And_Ordered()
    {
        var a = NetworkProtectionAnalyzer.Analyze(SecureState());
        var b = NetworkProtectionAnalyzer.Analyze(SecureState());
        Assert.Equal(a.Select(f => f.Title), b.Select(f => f.Title));
    }

    // --- Real-time protection ---

    [Fact]
    public void RealTimeProtection_Off_Is_Warning_With_Fix()
    {
        var f = AnalyzeRealTimeProtection(SecureState() with { DefenderRealTimeProtectionEnabled = false });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Equal(Category, f.Category);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void RealTimeProtection_On_Is_Pass()
    {
        var f = AnalyzeRealTimeProtection(SecureState());
        Assert.Equal(Severity.Pass, f.Severity);
    }

    // --- Mode ---

    [Fact]
    public void Mode_Block_Is_Pass()
    {
        var f = AnalyzeMode(SecureState() with { Mode = ModeBlock });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Mode_Disabled_Is_Warning_With_Fix()
    {
        var f = AnalyzeMode(SecureState() with { Mode = ModeDisabled });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void Mode_Audit_Is_Info_With_Fix()
    {
        var f = AnalyzeMode(SecureState() with { Mode = ModeAudit });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void Mode_Unrecognized_Is_Info()
    {
        var f = AnalyzeMode(SecureState() with { Mode = 99 });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Equal(Category, f.Category);
    }

    // --- Cloud reputation ---

    [Fact]
    public void CloudOff_While_Blocking_Is_Info()
    {
        var f = AnalyzeCloudReputation(SecureState() with { Mode = ModeBlock, CloudProtectionEnabled = false });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void CloudOff_While_Auditing_Is_Info()
    {
        var f = AnalyzeCloudReputation(SecureState() with { Mode = ModeAudit, CloudProtectionEnabled = false });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void CloudOff_While_Disabled_Is_Pass()
    {
        // When NP isn't enforcing, the cloud-reputation caveat is not relevant.
        var f = AnalyzeCloudReputation(SecureState() with { Mode = ModeDisabled, CloudProtectionEnabled = false });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void CloudOn_While_Blocking_Is_Pass()
    {
        var f = AnalyzeCloudReputation(SecureState() with { Mode = ModeBlock, CloudProtectionEnabled = true });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    // --- Collector parse helpers ---

    [Theory]
    [InlineData("True", false)]
    [InlineData("true", false)]
    [InlineData("False", true)]
    [InlineData("", true)]
    [InlineData(null, true)]
    public void ParseRealTimeEnabled_Maps_DisableFlag(string? raw, bool expectedEnabled)
    {
        Assert.Equal(expectedEnabled, NetworkProtectionAudit.ParseRealTimeEnabled(raw));
    }

    [Theory]
    [InlineData("0", ModeDisabled)]
    [InlineData("1", ModeBlock)]
    [InlineData("2", ModeAudit)]
    [InlineData(" 1 ", ModeBlock)]
    [InlineData("", ModeBlock)]      // unreadable => secure default
    [InlineData("garbage", ModeBlock)]
    [InlineData("7", ModeBlock)]     // out-of-range => secure default
    public void ParseMode_Maps_Value(string raw, int expected)
    {
        Assert.Equal(expected, NetworkProtectionAudit.ParseMode(raw));
    }

    [Theory]
    [InlineData("0", false)]
    [InlineData("1", true)]
    [InlineData("2", true)]
    [InlineData("", true)]           // unreadable => secure default
    [InlineData(null, true)]
    public void ParseCloudEnabled_Maps_MapsReporting(string? raw, bool expected)
    {
        Assert.Equal(expected, NetworkProtectionAudit.ParseCloudEnabled(raw));
    }
}
