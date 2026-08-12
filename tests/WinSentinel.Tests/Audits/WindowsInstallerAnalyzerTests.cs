using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.WindowsInstallerAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="WindowsInstallerAnalyzer"/> -
/// the single-machine Windows Installer (MSI) hardening checks: the classic
/// AlwaysInstallElevated local-privilege-escalation flaw (exploitable only when
/// BOTH HKLM and HKCU are 1), DisableMSI install-surface restriction, and
/// EnableUserControl property override. Every rule is exercised directly against a
/// synthetic <see cref="WindowsInstallerState"/>; no registry or I/O is touched.
/// </summary>
public class WindowsInstallerAnalyzerTests
{
    /// <summary>A safe default machine: no elevation, installs allowed, no user control.</summary>
    private static WindowsInstallerState SafeState() => new()
    {
        MachineAlwaysInstallElevated = 0,
        UserAlwaysInstallElevated = 0,
        DisableMsi = null,
        EnableUserControl = 0,
    };

    [Fact]
    public void Analyze_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Analyze(null!));
    }

    [Fact]
    public void Analyze_ReturnsThreeFindings_AllInCategory()
    {
        var findings = Analyze(SafeState());
        Assert.Equal(3, findings.Count);
        Assert.All(findings, f => Assert.Equal("Windows Installer", f.Category));
    }

    // --- AlwaysInstallElevated (the headline check) ---

    [Fact]
    public void AlwaysInstallElevated_BothHives_Critical_WithFix()
    {
        var f = AnalyzeAlwaysInstallElevated(SafeState() with
        {
            MachineAlwaysInstallElevated = 1,
            UserAlwaysInstallElevated = 1,
        });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("AlwaysInstallElevated", f.FixCommand);
    }

    [Fact]
    public void AlwaysInstallElevated_MachineOnly_Info_NotExploitable()
    {
        var f = AnalyzeAlwaysInstallElevated(SafeState() with { MachineAlwaysInstallElevated = 1 });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void AlwaysInstallElevated_UserOnly_Info_NotExploitable()
    {
        var f = AnalyzeAlwaysInstallElevated(SafeState() with { UserAlwaysInstallElevated = 1 });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void AlwaysInstallElevated_NeitherHive_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeAlwaysInstallElevated(SafeState()).Severity);
        Assert.Equal(Severity.Pass, AnalyzeAlwaysInstallElevated(new WindowsInstallerState()).Severity);
    }

    // --- DisableMSI ---

    [Fact]
    public void DisableMsi_Two_InstallerDisabled_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeDisableMsi(SafeState() with { DisableMsi = 2 }).Severity);
    }

    [Fact]
    public void DisableMsi_One_ManagedOnly_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeDisableMsi(SafeState() with { DisableMsi = 1 }).Severity);
    }

    [Fact]
    public void DisableMsi_ZeroOrAbsent_Info_WithFix()
    {
        var f = AnalyzeDisableMsi(SafeState() with { DisableMsi = 0 });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("DisableMSI", f.FixCommand);
        Assert.Equal(Severity.Info, AnalyzeDisableMsi(SafeState() with { DisableMsi = null }).Severity);
    }

    // --- EnableUserControl ---

    [Fact]
    public void EnableUserControl_One_Warns_WithFix()
    {
        var f = AnalyzeEnableUserControl(SafeState() with { EnableUserControl = 1 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("EnableUserControl", f.FixCommand);
    }

    [Fact]
    public void EnableUserControl_ZeroOrAbsent_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeEnableUserControl(SafeState() with { EnableUserControl = 0 }).Severity);
        Assert.Equal(Severity.Pass, AnalyzeEnableUserControl(SafeState() with { EnableUserControl = null }).Severity);
    }

    [Fact]
    public void Analyze_WorstCase_ProducesCriticalAndWarning()
    {
        var findings = Analyze(new WindowsInstallerState
        {
            MachineAlwaysInstallElevated = 1,
            UserAlwaysInstallElevated = 1,
            DisableMsi = 0,
            EnableUserControl = 1,
        });
        Assert.Equal(3, findings.Count);
        Assert.Contains(findings, f => f.Severity == Severity.Critical);
        Assert.Contains(findings, f => f.Severity == Severity.Warning);
    }
}
