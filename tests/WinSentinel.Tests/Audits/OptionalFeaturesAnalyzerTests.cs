using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.OptionalFeaturesAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="OptionalFeaturesAnalyzer"/> - the
/// single-machine risky-optional-features checks: SMB 1.0/CIFS, the legacy PowerShell 2.0
/// engine, and cleartext legacy clients (Telnet, TFTP). Every rule is exercised directly
/// against a synthetic <see cref="OptionalFeaturesState"/>; no DISM / PowerShell I/O is
/// touched.
/// </summary>
public class OptionalFeaturesAnalyzerTests
{
    private static OptionalFeaturesState CleanState() => new()
    {
        EnumerationSucceeded = true,
        EnabledFeatures = Array.Empty<string>(),
    };

    private static OptionalFeaturesState Enabled(params string[] features) => new()
    {
        EnumerationSucceeded = true,
        EnabledFeatures = features,
    };

    [Fact]
    public void Analyze_Throws_On_Null_State()
    {
        Assert.Throws<ArgumentNullException>(() => OptionalFeaturesAnalyzer.Analyze(null!));
    }

    [Fact]
    public void Analyze_Clean_State_Is_All_Pass()
    {
        var findings = OptionalFeaturesAnalyzer.Analyze(CleanState());

        Assert.Equal(KnownRiskyFeatures.Count, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal(Category, f.Category));
    }

    [Fact]
    public void Analyze_Enumeration_Failure_Yields_Single_Info()
    {
        var state = new OptionalFeaturesState { EnumerationSucceeded = false };

        var findings = OptionalFeaturesAnalyzer.Analyze(state);

        var only = Assert.Single(findings);
        Assert.Equal(Severity.Info, only.Severity);
        Assert.Equal(Category, only.Category);
        Assert.Contains("could not", only.Title, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Analyze_Is_Deterministic_And_Ordered()
    {
        var a = OptionalFeaturesAnalyzer.Analyze(CleanState()).Select(f => f.Title).ToArray();
        var b = OptionalFeaturesAnalyzer.Analyze(CleanState()).Select(f => f.Title).ToArray();
        Assert.Equal(a, b);
    }

    [Fact]
    public void Smb1_Enabled_Is_Critical_With_Remediation()
    {
        var findings = OptionalFeaturesAnalyzer.Analyze(Enabled("SMB1Protocol"));

        var smb = Assert.Single(findings, f => f.Title.Contains("SMB 1.0", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(Severity.Critical, smb.Severity);
        Assert.False(string.IsNullOrWhiteSpace(smb.Remediation));
        Assert.Contains("SMB1Protocol", smb.FixCommand);
    }

    [Fact]
    public void PowerShellV2_Enabled_Is_Warning()
    {
        var findings = OptionalFeaturesAnalyzer.Analyze(Enabled("MicrosoftWindowsPowerShellV2"));

        var ps2 = Assert.Single(findings, f => f.Title.Contains("PowerShell 2.0", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(Severity.Warning, ps2.Severity);
    }

    [Fact]
    public void Telnet_And_Tftp_Enabled_Are_Warning()
    {
        var findings = OptionalFeaturesAnalyzer.Analyze(Enabled("TelnetClient", "TFTP"));

        var telnet = Assert.Single(findings, f => f.Title.Contains("Telnet", StringComparison.OrdinalIgnoreCase));
        var tftp = Assert.Single(findings, f => f.Title.Contains("TFTP", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(Severity.Warning, telnet.Severity);
        Assert.Equal(Severity.Warning, tftp.Severity);
    }

    [Fact]
    public void Feature_Matching_Is_Case_Insensitive()
    {
        var findings = OptionalFeaturesAnalyzer.Analyze(Enabled("smb1protocol"));

        var smb = Assert.Single(findings, f => f.Title.Contains("SMB 1.0", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(Severity.Critical, smb.Severity);
    }

    [Fact]
    public void Unknown_Enabled_Feature_Does_Not_Add_Findings()
    {
        var findings = OptionalFeaturesAnalyzer.Analyze(Enabled("SomeHarmlessFeature"));

        Assert.Equal(KnownRiskyFeatures.Count, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
    }

    [Fact]
    public void AnalyzeFeature_Throws_On_Null_Arguments()
    {
        var feature = KnownRiskyFeatures[0];
        Assert.Throws<ArgumentNullException>(() => OptionalFeaturesAnalyzer.AnalyzeFeature(null!, CleanState()));
        Assert.Throws<ArgumentNullException>(() => OptionalFeaturesAnalyzer.AnalyzeFeature(feature, null!));
    }
}
