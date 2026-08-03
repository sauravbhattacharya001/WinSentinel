using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.WerExposureAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="WerExposureAnalyzer"/> - the
/// single-machine Windows Error Reporting (WER) / crash-dump exposure checks: whether WER
/// may upload the additional in-memory data slice (DontSendAdditionalData), whether it
/// auto-sends all crash data (Consent\DefaultConsent), whether full user-mode crash dumps
/// are written to local disk (LocalDumps / DumpType), and whether WER is disabled entirely.
/// Every rule is exercised directly against a synthetic <see cref="WerState"/>; no registry
/// I/O is touched.
/// </summary>
public class WerExposureAnalyzerTests
{
    private static WerState SecureState() => new()
    {
        DontSendAdditionalData = true,
        DefaultConsent = 1,
        LocalDumpsEnabled = false,
        LocalDumpsFullType = false,
        WerDisabled = false,
    };

    [Fact]
    public void Analyze_Throws_On_Null_State()
    {
        Assert.Throws<ArgumentNullException>(() => WerExposureAnalyzer.Analyze(null!));
    }

    [Fact]
    public void Analyze_Secure_State_Is_All_Pass()
    {
        var findings = WerExposureAnalyzer.Analyze(SecureState());
        Assert.Equal(4, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal(Category, f.Category));
    }

    [Fact]
    public void Analyze_Is_Deterministic_And_Ordered()
    {
        var a = WerExposureAnalyzer.Analyze(SecureState());
        var b = WerExposureAnalyzer.Analyze(SecureState());
        Assert.Equal(a.Select(f => f.Title), b.Select(f => f.Title));
    }

    [Fact]
    public void DontSendAdditionalData_Off_Is_Warning()
    {
        var f = AnalyzeDontSendAdditionalData(SecureState() with { DontSendAdditionalData = false });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Equal(Category, f.Category);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void DontSendAdditionalData_On_Is_Pass()
    {
        var f = AnalyzeDontSendAdditionalData(SecureState() with { DontSendAdditionalData = true });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void DefaultConsent_AutoSendAll_Is_Warning()
    {
        var f = AnalyzeDefaultConsent(SecureState() with { DefaultConsent = 4 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void DefaultConsent_NonAuto_Is_Pass(int consent)
    {
        var f = AnalyzeDefaultConsent(SecureState() with { DefaultConsent = consent });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void LocalDumps_Disabled_Is_Pass()
    {
        var f = AnalyzeLocalDumps(SecureState() with { LocalDumpsEnabled = false, LocalDumpsFullType = false });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void LocalDumps_FullDump_Is_Warning()
    {
        var f = AnalyzeLocalDumps(SecureState() with { LocalDumpsEnabled = true, LocalDumpsFullType = true });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void LocalDumps_MiniDump_Is_Info()
    {
        var f = AnalyzeLocalDumps(SecureState() with { LocalDumpsEnabled = true, LocalDumpsFullType = false });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void WerDisabled_Is_Info()
    {
        var f = AnalyzeWerDisabled(SecureState() with { WerDisabled = true });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void WerEnabled_Is_Pass()
    {
        var f = AnalyzeWerDisabled(SecureState() with { WerDisabled = false });
        Assert.Equal(Severity.Pass, f.Severity);
    }
}
