using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.PrintSpoolerAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="PrintSpoolerAnalyzer"/> - the
/// single-machine Print Spooler / Point-and-Print (PrintNightmare) hardening
/// checks. Every rule is exercised directly against a synthetic
/// <see cref="PrintSpoolerState"/>; no registry, service, or I/O is touched.
/// </summary>
public class PrintSpoolerAnalyzerTests
{
    private static PrintSpoolerState HardenedState() => new()
    {
        SpoolerRunning = false,
        SharesPrinters = false,
        RestrictDriverInstallationToAdministrators = 1,
        NoWarningNoElevationOnInstall = 0,
        UpdatePromptSettings = 0,
        RegisterSpoolerRemoteRpcEndPoint = 2,
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
        Assert.Equal(5, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal("Print Spooler", f.Category));
    }

    [Fact]
    public void Spooler_Stopped_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeSpoolerService(HardenedState() with { SpoolerRunning = false }).Severity);
    }

    [Fact]
    public void Spooler_RunningAndSharing_Passes()
    {
        var f = AnalyzeSpoolerService(HardenedState() with { SpoolerRunning = true, SharesPrinters = true });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Spooler_RunningNotSharing_IsInfo_WithFix()
    {
        var f = AnalyzeSpoolerService(HardenedState() with { SpoolerRunning = true, SharesPrinters = false });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Spooler", f.FixCommand);
    }

    [Theory]
    [InlineData(1, Severity.Pass)]
    [InlineData(0, Severity.Critical)]
    [InlineData(null, Severity.Critical)]
    public void RestrictDriverInstallation_Threshold(int? value, Severity expected)
    {
        var f = AnalyzeRestrictDriverInstallation(HardenedState() with { RestrictDriverInstallationToAdministrators = value });
        Assert.Equal(expected, f.Severity);
    }

    [Fact]
    public void RestrictDriverInstallation_Off_HasPrintNightmareFix()
    {
        var f = AnalyzeRestrictDriverInstallation(HardenedState() with { RestrictDriverInstallationToAdministrators = 0 });
        Assert.Contains("RestrictDriverInstallationToAdministrators", f.FixCommand);
    }

    [Theory]
    [InlineData(1, Severity.Critical)]
    [InlineData(0, Severity.Pass)]
    [InlineData(null, Severity.Pass)]
    public void NoWarningNoElevation_Threshold(int? value, Severity expected)
    {
        Assert.Equal(expected, AnalyzeNoWarningNoElevation(HardenedState() with { NoWarningNoElevationOnInstall = value }).Severity);
    }

    [Theory]
    [InlineData(0, Severity.Pass)]
    [InlineData(null, Severity.Pass)]
    [InlineData(1, Severity.Warning)]
    [InlineData(2, Severity.Warning)]
    public void UpdatePromptSettings_Threshold(int? value, Severity expected)
    {
        Assert.Equal(expected, AnalyzeUpdatePromptSettings(HardenedState() with { UpdatePromptSettings = value }).Severity);
    }

    [Fact]
    public void RemoteRpc_Restricted_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeRemoteRpcEndpoint(HardenedState() with { RegisterSpoolerRemoteRpcEndPoint = 2 }).Severity);
    }

    [Fact]
    public void RemoteRpc_EnabledOnPrintServer_Passes()
    {
        var f = AnalyzeRemoteRpcEndpoint(HardenedState() with { RegisterSpoolerRemoteRpcEndPoint = 1, SharesPrinters = true });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void RemoteRpc_EnabledNotSharing_IsInfo()
    {
        var f = AnalyzeRemoteRpcEndpoint(HardenedState() with { RegisterSpoolerRemoteRpcEndPoint = 1, SharesPrinters = false });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("RegisterSpoolerRemoteRpcEndPoint", f.FixCommand);
    }

    [Fact]
    public void Analyze_WorstCase_ProducesCriticals()
    {
        var findings = Analyze(new PrintSpoolerState
        {
            SpoolerRunning = true,
            SharesPrinters = false,
            RestrictDriverInstallationToAdministrators = 0,
            NoWarningNoElevationOnInstall = 1,
            UpdatePromptSettings = 2,
            RegisterSpoolerRemoteRpcEndPoint = 1,
        });
        Assert.Equal(5, findings.Count);
        Assert.Contains(findings, f => f.Severity == Severity.Critical);
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Pass);
    }
}
