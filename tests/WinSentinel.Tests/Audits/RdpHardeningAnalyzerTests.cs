using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.RdpHardeningAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="RdpHardeningAnalyzer"/> - the
/// single-machine Remote Desktop (RDP) hardening checks: whether RDP is enabled, whether
/// Network Level Authentication is required (UserAuthentication), the minimum encryption
/// level (MinEncryptionLevel), the TLS security layer (SecurityLayer), and whether RDP
/// listens on the default port 3389. Every rule is exercised directly against a synthetic
/// <see cref="RdpHardeningState"/>; no registry I/O is touched.
/// </summary>
public class RdpHardeningAnalyzerTests
{
    private static RdpHardeningState SecureState() => new()
    {
        RdpEnabled = false,
        NlaRequired = true,
        MinEncryptionLevel = 3,
        SecurityLayer = 2,
        PortNumber = 3389,
    };

    [Fact]
    public void Analyze_Throws_On_Null_State()
    {
        Assert.Throws<ArgumentNullException>(() => RdpHardeningAnalyzer.Analyze(null!));
    }

    [Fact]
    public void Analyze_Returns_Five_Findings_In_Category()
    {
        var findings = RdpHardeningAnalyzer.Analyze(SecureState());
        Assert.Equal(5, findings.Count);
        Assert.All(findings, f => Assert.Equal(Category, f.Category));
    }

    [Fact]
    public void Analyze_Is_Deterministic_And_Ordered()
    {
        var a = RdpHardeningAnalyzer.Analyze(SecureState());
        var b = RdpHardeningAnalyzer.Analyze(SecureState());
        Assert.Equal(a.Select(f => f.Title), b.Select(f => f.Title));
    }

    [Fact]
    public void RdpDisabled_Is_Pass()
    {
        var f = AnalyzeRdpEnabled(SecureState() with { RdpEnabled = false });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void RdpEnabled_Is_Info()
    {
        var f = AnalyzeRdpEnabled(SecureState() with { RdpEnabled = true });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void Nla_Required_Is_Pass()
    {
        var f = AnalyzeNla(SecureState() with { NlaRequired = true });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Nla_Off_Is_Warning_With_Fix()
    {
        var f = AnalyzeNla(SecureState() with { NlaRequired = false });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Theory]
    [InlineData(3)]
    [InlineData(4)]
    public void EncryptionLevel_High_Or_Fips_Is_Pass(int level)
    {
        var f = AnalyzeEncryptionLevel(SecureState() with { MinEncryptionLevel = level });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void EncryptionLevel_Weak_Is_Warning_With_Fix(int level)
    {
        var f = AnalyzeEncryptionLevel(SecureState() with { MinEncryptionLevel = level });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void SecurityLayer_Tls_Is_Pass()
    {
        var f = AnalyzeSecurityLayer(SecureState() with { SecurityLayer = 2 });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void SecurityLayer_NonTls_Is_Warning_With_Fix(int layer)
    {
        var f = AnalyzeSecurityLayer(SecureState() with { SecurityLayer = layer });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void Port_Default_Is_Info()
    {
        var f = AnalyzePort(SecureState() with { PortNumber = 3389 });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void Port_NonDefault_Is_Pass()
    {
        var f = AnalyzePort(SecureState() with { PortNumber = 3390 });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Fully_Insecure_State_Has_Warnings()
    {
        var insecure = new RdpHardeningState
        {
            RdpEnabled = true,
            NlaRequired = false,
            MinEncryptionLevel = 1,
            SecurityLayer = 0,
            PortNumber = 3389,
        };
        var findings = RdpHardeningAnalyzer.Analyze(insecure);
        Assert.Contains(findings, f => f.Severity == Severity.Warning);
    }
}
