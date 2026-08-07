using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.CredentialGuardAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="CredentialGuardAnalyzer"/> - the
/// single-machine LSASS credential-theft defenses (LSA Protection / RunAsPPL, Credential Guard /
/// LsaCfgFlags, and WDigest cleartext caching / UseLogonCredential). Every rule is exercised
/// directly against a synthetic <see cref="CredentialGuardState"/>; no registry I/O is touched.
/// </summary>
public class CredentialGuardAnalyzerTests
{
    /// <summary>Hardened posture: both protections UEFI-locked, WDigest not caching cleartext.</summary>
    private static CredentialGuardState SecureState() => new()
    {
        RunAsPPL = EnabledWithUefiLock,
        LsaCfgFlags = EnabledWithUefiLock,
        WDigestUseLogonCredential = 0,
    };

    [Fact]
    public void Analyze_Throws_On_Null_State()
    {
        Assert.Throws<ArgumentNullException>(() => CredentialGuardAnalyzer.Analyze(null!));
    }

    [Fact]
    public void Analyze_Returns_Three_Findings_In_Category()
    {
        var findings = CredentialGuardAnalyzer.Analyze(SecureState());
        Assert.Equal(3, findings.Count);
        Assert.All(findings, f => Assert.Equal(Category, f.Category));
    }

    [Fact]
    public void Analyze_Is_Deterministic_And_Ordered()
    {
        var a = CredentialGuardAnalyzer.Analyze(SecureState());
        var b = CredentialGuardAnalyzer.Analyze(SecureState());
        Assert.Equal(a.Select(f => f.Title), b.Select(f => f.Title));
    }

    [Fact]
    public void SecureState_Is_All_Pass()
    {
        var findings = CredentialGuardAnalyzer.Analyze(SecureState());
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
    }

    // ── AnalyzeLsaProtection ───────────────────────────────────────────

    [Fact]
    public void LsaProtection_UefiLocked_Is_Pass()
    {
        var f = AnalyzeLsaProtection(new CredentialGuardState { RunAsPPL = EnabledWithUefiLock });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void LsaProtection_Unlocked_Is_Info_With_Fix()
    {
        var f = AnalyzeLsaProtection(new CredentialGuardState { RunAsPPL = EnabledWithoutLock });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0)]
    public void LsaProtection_Absent_Or_Zero_Is_Warning_With_Fix(int? value)
    {
        var f = AnalyzeLsaProtection(new CredentialGuardState { RunAsPPL = value });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    // ── AnalyzeCredentialGuard ─────────────────────────────────────────

    [Fact]
    public void CredentialGuard_UefiLocked_Is_Pass()
    {
        var f = AnalyzeCredentialGuard(new CredentialGuardState { LsaCfgFlags = EnabledWithUefiLock });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void CredentialGuard_Unlocked_Is_Info_With_Fix()
    {
        var f = AnalyzeCredentialGuard(new CredentialGuardState { LsaCfgFlags = EnabledWithoutLock });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0)]
    public void CredentialGuard_Absent_Or_Zero_Is_Warning_With_Fix(int? value)
    {
        var f = AnalyzeCredentialGuard(new CredentialGuardState { LsaCfgFlags = value });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    // ── AnalyzeWDigest ─────────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData(0)]
    public void WDigest_Absent_Or_Zero_Is_Pass(int? value)
    {
        var f = AnalyzeWDigest(new CredentialGuardState { WDigestUseLogonCredential = value });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void WDigest_Cleartext_Is_Warning_With_Fix()
    {
        var f = AnalyzeWDigest(new CredentialGuardState { WDigestUseLogonCredential = 1 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    // ── Constants sanity ───────────────────────────────────────────────

    [Fact]
    public void Enabled_Values_Are_1_And_2()
    {
        Assert.Equal(1, EnabledWithUefiLock);
        Assert.Equal(2, EnabledWithoutLock);
    }
}
