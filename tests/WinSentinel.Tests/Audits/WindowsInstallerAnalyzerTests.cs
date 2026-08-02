using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.WindowsInstallerAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="WindowsInstallerAnalyzer"/> -
/// the single-machine Windows Installer (msiexec) hardening checks. Every rule is
/// exercised directly against a synthetic <see cref="WindowsInstallerState"/>; no
/// registry or I/O is touched.
/// </summary>
public class WindowsInstallerAnalyzerTests
{
    private static WindowsInstallerState HardenedState() => new()
    {
        MachineAlwaysInstallElevated = 0,
        UserAlwaysInstallElevated = 0,
        DisableMsi = 1,
        EnableUserControl = 0,
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
        Assert.Equal(3, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal("Windows Installer", f.Category));
    }

    [Fact]
    public void Analyze_DefaultState_IsInfoForDisableMsiOnly()
    {
        // All-null = Windows default: no elevation, all installs allowed, no user control.
        // AlwaysInstallElevated absent = Pass; DisableMsi absent = Info; EnableUserControl absent = Pass.
        var findings = Analyze(new WindowsInstallerState());
        Assert.Equal(3, findings.Count);
        Assert.Equal(1, findings.Count(f => f.Severity == Severity.Info));
        Assert.Equal(2, findings.Count(f => f.Severity == Severity.Pass));
    }

    // ---- AlwaysInstallElevated ---------------------------------------------

    [Fact]
    public void AlwaysInstallElevated_BothHives_IsCritical()
    {
        var f = AnalyzeAlwaysInstallElevated(HardenedState() with
        {
            MachineAlwaysInstallElevated = 1,
            UserAlwaysInstallElevated = 1,
        });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void AlwaysInstallElevated_MachineOnly_IsInfo()
    {
        var f = AnalyzeAlwaysInstallElevated(HardenedState() with
        {
            MachineAlwaysInstallElevated = 1,
            UserAlwaysInstallElevated = 0,
        });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void AlwaysInstallElevated_UserOnly_IsInfo()
    {
        var f = AnalyzeAlwaysInstallElevated(HardenedState() with
        {
            MachineAlwaysInstallElevated = null,
            UserAlwaysInstallElevated = 1,
        });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void AlwaysInstallElevated_BothZero_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeAlwaysInstallElevated(HardenedState()).Severity);
    }

    [Fact]
    public void AlwaysInstallElevated_BothAbsent_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeAlwaysInstallElevated(new WindowsInstallerState()).Severity);
    }

    // ---- DisableMSI --------------------------------------------------------

    [Fact]
    public void DisableMsi_Two_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeDisableMsi(HardenedState() with { DisableMsi = 2 }).Severity);
    }

    [Fact]
    public void DisableMsi_One_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeDisableMsi(HardenedState() with { DisableMsi = 1 }).Severity);
    }

    [Fact]
    public void DisableMsi_Zero_IsInfo()
    {
        var f = AnalyzeDisableMsi(HardenedState() with { DisableMsi = 0 });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void DisableMsi_Absent_IsInfo()
    {
        Assert.Equal(Severity.Info, AnalyzeDisableMsi(HardenedState() with { DisableMsi = null }).Severity);
    }

    // ---- EnableUserControl -------------------------------------------------

    [Fact]
    public void EnableUserControl_One_IsWarning()
    {
        var f = AnalyzeEnableUserControl(HardenedState() with { EnableUserControl = 1 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void EnableUserControl_Zero_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeEnableUserControl(HardenedState() with { EnableUserControl = 0 }).Severity);
    }

    [Fact]
    public void EnableUserControl_Absent_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeEnableUserControl(HardenedState() with { EnableUserControl = null }).Severity);
    }
}
