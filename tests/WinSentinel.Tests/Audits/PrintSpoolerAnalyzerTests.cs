using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.PrintSpoolerAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="PrintSpoolerAnalyzer"/> - the
/// single-machine Print Spooler / PrintNightmare hardening checks: whether the spooler is
/// running, whether printer-driver installation is restricted to administrators
/// (RestrictDriverInstallationToAdministrators), and whether Point-and-Print suppresses the
/// install (NoWarningNoElevationOnInstall) and update (UpdatePromptSettings) elevation prompts.
/// Every rule is exercised directly against a synthetic <see cref="PrintSpoolerState"/>; no
/// service or registry I/O is touched.
/// </summary>
public class PrintSpoolerAnalyzerTests
{
    private static PrintSpoolerState SecureState() => new()
    {
        SpoolerRunning = false,
        RestrictDriverInstallationToAdministrators = true,
        NoWarningNoElevationOnInstall = false,
        UpdatePromptSettings = 0,
    };

    [Fact]
    public void Analyze_Throws_On_Null_State()
    {
        Assert.Throws<ArgumentNullException>(() => PrintSpoolerAnalyzer.Analyze(null!));
    }

    [Fact]
    public void Analyze_Returns_Four_Findings_In_Category()
    {
        var findings = PrintSpoolerAnalyzer.Analyze(SecureState());
        Assert.Equal(4, findings.Count);
        Assert.All(findings, f => Assert.Equal(Category, f.Category));
    }

    [Fact]
    public void Analyze_Is_Deterministic_And_Ordered()
    {
        var a = PrintSpoolerAnalyzer.Analyze(SecureState());
        var b = PrintSpoolerAnalyzer.Analyze(SecureState());
        Assert.Equal(a.Select(f => f.Title), b.Select(f => f.Title));
    }

    [Fact]
    public void SpoolerStopped_Is_Pass()
    {
        var f = AnalyzeSpoolerRunning(SecureState() with { SpoolerRunning = false });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void SpoolerRunning_Is_Info()
    {
        var f = AnalyzeSpoolerRunning(SecureState() with { SpoolerRunning = true });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void RestrictDriverInstall_On_Is_Pass()
    {
        var f = AnalyzeRestrictDriverInstall(SecureState() with { RestrictDriverInstallationToAdministrators = true });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void RestrictDriverInstall_Off_Is_Warning_With_Fix()
    {
        var f = AnalyzeRestrictDriverInstall(SecureState() with { RestrictDriverInstallationToAdministrators = false });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void NoWarningNoElevation_Off_Is_Pass()
    {
        var f = AnalyzeNoWarningNoElevation(SecureState() with { NoWarningNoElevationOnInstall = false });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void NoWarningNoElevation_On_Is_Warning_With_Fix()
    {
        var f = AnalyzeNoWarningNoElevation(SecureState() with { NoWarningNoElevationOnInstall = true });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void UpdatePrompt_Zero_Is_Pass()
    {
        var f = AnalyzeUpdatePrompt(SecureState() with { UpdatePromptSettings = 0 });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void UpdatePrompt_NonZero_Is_Warning_With_Fix(int value)
    {
        var f = AnalyzeUpdatePrompt(SecureState() with { UpdatePromptSettings = value });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void Fully_Insecure_State_Has_Warnings()
    {
        var insecure = new PrintSpoolerState
        {
            SpoolerRunning = true,
            RestrictDriverInstallationToAdministrators = false,
            NoWarningNoElevationOnInstall = true,
            UpdatePromptSettings = 2,
        };
        var findings = PrintSpoolerAnalyzer.Analyze(insecure);
        Assert.Contains(findings, f => f.Severity == Severity.Warning);
    }
}
