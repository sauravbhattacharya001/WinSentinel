using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.KerberosHardeningAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="KerberosHardeningAnalyzer"/> - the
/// single-machine Kerberos client encryption-type hardening checks driven by the
/// <c>SupportedEncryptionTypes</c> bitmask: whether the value is explicitly configured, whether
/// the broken DES suites are offered, whether the weak RC4 suite is offered, and whether a strong
/// AES suite is offered. Every rule is exercised directly against a synthetic
/// <see cref="KerberosHardeningState"/>; no registry I/O is touched.
/// </summary>
public class KerberosHardeningAnalyzerTests
{
    /// <summary>Hardened posture: only the two AES suites (0x18), no DES, no RC4.</summary>
    private static KerberosHardeningState SecureState() => new()
    {
        SupportedEncryptionTypes = AesMask,
    };

    [Fact]
    public void Analyze_Throws_On_Null_State()
    {
        Assert.Throws<ArgumentNullException>(() => KerberosHardeningAnalyzer.Analyze(null!));
    }

    [Fact]
    public void Analyze_Returns_Four_Findings_In_Category()
    {
        var findings = KerberosHardeningAnalyzer.Analyze(SecureState());
        Assert.Equal(4, findings.Count);
        Assert.All(findings, f => Assert.Equal(Category, f.Category));
    }

    [Fact]
    public void Analyze_Is_Deterministic_And_Ordered()
    {
        var a = KerberosHardeningAnalyzer.Analyze(SecureState());
        var b = KerberosHardeningAnalyzer.Analyze(SecureState());
        Assert.Equal(a.Select(f => f.Title), b.Select(f => f.Title));
    }

    // ── AnalyzeConfigured ──────────────────────────────────────────────

    [Fact]
    public void Configured_Explicit_Value_Is_Pass()
    {
        var f = AnalyzeConfigured(SecureState());
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Configured_Absent_Is_Info_With_Fix()
    {
        var f = AnalyzeConfigured(new KerberosHardeningState { SupportedEncryptionTypes = null });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    // ── AnalyzeDes ─────────────────────────────────────────────────────

    [Fact]
    public void Des_Not_Offered_Is_Pass()
    {
        var f = AnalyzeDes(SecureState());
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Des_Absent_Is_Pass()
    {
        // Unconfigured => modern Windows does not offer DES => Pass.
        var f = AnalyzeDes(new KerberosHardeningState { SupportedEncryptionTypes = null });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Theory]
    [InlineData(DesCbcCrc)]
    [InlineData(DesCbcMd5)]
    [InlineData(DesMask | AesMask)]
    public void Des_Offered_Is_Warning_With_Fix(int etypes)
    {
        var f = AnalyzeDes(new KerberosHardeningState { SupportedEncryptionTypes = etypes });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    // ── AnalyzeRc4 ─────────────────────────────────────────────────────

    [Fact]
    public void Rc4_Not_Offered_Is_Pass()
    {
        var f = AnalyzeRc4(SecureState());
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Rc4_Absent_Is_Info()
    {
        var f = AnalyzeRc4(new KerberosHardeningState { SupportedEncryptionTypes = null });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Theory]
    [InlineData(Rc4Hmac)]
    [InlineData(Rc4Hmac | AesMask)]
    public void Rc4_Offered_Is_Warning_With_Fix(int etypes)
    {
        var f = AnalyzeRc4(new KerberosHardeningState { SupportedEncryptionTypes = etypes });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    // ── AnalyzeAes ─────────────────────────────────────────────────────

    [Theory]
    [InlineData(Aes128)]
    [InlineData(Aes256)]
    [InlineData(AesMask)]
    [InlineData(Rc4Hmac | Aes256)]
    public void Aes_Offered_Is_Pass(int etypes)
    {
        var f = AnalyzeAes(new KerberosHardeningState { SupportedEncryptionTypes = etypes });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Aes_Absent_Is_Pass()
    {
        // Unconfigured => modern Windows offers AES by default => Pass.
        var f = AnalyzeAes(new KerberosHardeningState { SupportedEncryptionTypes = null });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Theory]
    [InlineData(Rc4Hmac)]
    [InlineData(DesMask)]
    [InlineData(DesMask | Rc4Hmac)]
    public void Aes_Missing_Is_Warning_With_Fix(int etypes)
    {
        var f = AnalyzeAes(new KerberosHardeningState { SupportedEncryptionTypes = etypes });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    // ── Constants sanity ───────────────────────────────────────────────

    [Fact]
    public void AesMask_Is_0x18()
    {
        Assert.Equal(0x18, AesMask);
        Assert.Equal(Aes128 | Aes256, AesMask);
    }

    [Fact]
    public void DesMask_Combines_Both_Des_Suites()
    {
        Assert.Equal(DesCbcCrc | DesCbcMd5, DesMask);
    }
}
