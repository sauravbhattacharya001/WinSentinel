using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.LsaHardeningAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="LsaHardeningAnalyzer"/> - the
/// single-machine LSA / credential-protection registry checks (RunAsPPL, WDigest
/// plaintext caching, NoLMHash, LmCompatibilityLevel, cached-logon count,
/// cleartext autologon). Every rule is exercised directly against a synthetic
/// <see cref="LsaHardeningState"/>; no registry or I/O is touched.
/// </summary>
public class LsaHardeningAnalyzerTests
{
    private static LsaHardeningState HardenedState() => new()
    {
        RunAsPpl = 1,
        WDigestUseLogonCredential = 0,
        NoLmHash = 1,
        LmCompatibilityLevel = 5,
        CachedLogonsCount = 10,
        AutoAdminLogon = false,
        DefaultPassword = null,
    };

    [Fact]
    public void Analyze_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Analyze(null!));
    }

    [Fact]
    public void Analyze_HardenedState_IsAllPass()
    {
        var findings = Analyze(HardenedState());
        Assert.Equal(6, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal("Credentials", f.Category));
    }

    [Fact]
    public void RunAsPpl_Off_Warns_WithFix()
    {
        var f = AnalyzeRunAsPpl(HardenedState() with { RunAsPpl = 0 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("RunAsPPL", f.FixCommand);
    }

    [Fact]
    public void RunAsPpl_Null_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeRunAsPpl(HardenedState() with { RunAsPpl = null }).Severity);
    }

    [Fact]
    public void WDigest_PlaintextCaching_IsCritical()
    {
        var f = AnalyzeWDigest(HardenedState() with { WDigestUseLogonCredential = 1 });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("UseLogonCredential", f.FixCommand);
    }

    [Fact]
    public void WDigest_AbsentOrZero_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeWDigest(HardenedState() with { WDigestUseLogonCredential = 0 }).Severity);
        Assert.Equal(Severity.Pass, AnalyzeWDigest(HardenedState() with { WDigestUseLogonCredential = null }).Severity);
    }

    [Fact]
    public void NoLmHash_Off_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeNoLmHash(HardenedState() with { NoLmHash = 0 }).Severity);
        Assert.Equal(Severity.Pass, AnalyzeNoLmHash(HardenedState() with { NoLmHash = 1 }).Severity);
    }

    [Theory]
    [InlineData(5, Severity.Pass)]
    [InlineData(6, Severity.Pass)]
    [InlineData(4, Severity.Warning)]
    [InlineData(3, Severity.Warning)]
    [InlineData(2, Severity.Critical)]
    [InlineData(0, Severity.Critical)]
    public void LmCompatibilityLevel_Threshold(int level, Severity expected)
    {
        var f = AnalyzeLmCompatibilityLevel(HardenedState() with { LmCompatibilityLevel = level });
        Assert.Equal(expected, f.Severity);
        if (expected != Severity.Pass)
        {
            Assert.Contains("LmCompatibilityLevel", f.FixCommand);
        }
    }

    [Fact]
    public void LmCompatibilityLevel_Null_TreatedAsDefault3_Warns()
    {
        // Unset -> modern OS default of 3, which still accepts inbound LM/NTLMv1.
        Assert.Equal(Severity.Warning, AnalyzeLmCompatibilityLevel(HardenedState() with { LmCompatibilityLevel = null }).Severity);
    }

    [Theory]
    [InlineData(10, Severity.Pass)]
    [InlineData(0, Severity.Pass)]
    [InlineData(11, Severity.Warning)]
    [InlineData(50, Severity.Warning)]
    public void CachedLogons_Threshold(int count, Severity expected)
    {
        Assert.Equal(expected, AnalyzeCachedLogons(HardenedState() with { CachedLogonsCount = count }).Severity);
    }

    [Fact]
    public void CachedLogons_Null_TreatedAsDefault_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeCachedLogons(HardenedState() with { CachedLogonsCount = null }).Severity);
    }

    [Fact]
    public void AutoLogon_Disabled_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeAutoLogon(HardenedState() with { AutoAdminLogon = false }).Severity);
    }

    [Fact]
    public void AutoLogon_WithCleartextPassword_IsCritical()
    {
        var f = AnalyzeAutoLogon(HardenedState() with { AutoAdminLogon = true, DefaultPassword = "hunter2" });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("DefaultPassword", f.FixCommand);
    }

    [Fact]
    public void AutoLogon_WithoutStoredPassword_Warns()
    {
        var f = AnalyzeAutoLogon(HardenedState() with { AutoAdminLogon = true, DefaultPassword = null });
        Assert.Equal(Severity.Warning, f.Severity);
    }

    [Fact]
    public void Analyze_WorstCase_ProducesCriticals()
    {
        var findings = Analyze(new LsaHardeningState
        {
            RunAsPpl = 0,
            WDigestUseLogonCredential = 1,
            NoLmHash = 0,
            LmCompatibilityLevel = 0,
            CachedLogonsCount = 25,
            AutoAdminLogon = true,
            DefaultPassword = "P@ssw0rd",
        });
        Assert.Equal(6, findings.Count);
        Assert.Contains(findings, f => f.Severity == Severity.Critical);
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Pass);
    }
}
