using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.WindowsScriptHostAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="WindowsScriptHostAnalyzer"/> -
/// the single-machine Windows Script Host (wscript/cscript) hardening checks.
/// Every rule is exercised directly against a synthetic
/// <see cref="WindowsScriptHostState"/>; no registry or I/O is touched.
/// </summary>
public class WindowsScriptHostAnalyzerTests
{
    private static WindowsScriptHostState HardenedState() => new()
    {
        Enabled = 0,
        Remote = 0,
        TrustPolicy = 2,
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
        Assert.Equal(4, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal("Windows Script Host", f.Category));
    }

    [Fact]
    public void Analyze_DefaultInsecureState_FlagsEnabledAndTrustPolicy()
    {
        // All-null state = Windows default: WSH enabled, no remote flag, no signing.
        // Enabled + TrustPolicy are flagged Info; Remote-absent is safe (local only) = Pass.
        var findings = Analyze(new WindowsScriptHostState());
        Assert.Equal(4, findings.Count);
        Assert.Equal(2, findings.Count(f => f.Severity == Severity.Info));
        Assert.Equal(2, findings.Count(f => f.Severity == Severity.Pass));
    }

    // ---- Enabled -----------------------------------------------------------

    [Fact]
    public void Enabled_Zero_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeEnabled(HardenedState() with { Enabled = 0 }).Severity);
    }

    [Fact]
    public void Enabled_One_IsInfo()
    {
        var f = AnalyzeEnabled(HardenedState() with { Enabled = 1 });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void Enabled_Absent_IsInfo()
    {
        // Absent (null) is the default = enabled = flagged.
        Assert.Equal(Severity.Info, AnalyzeEnabled(HardenedState() with { Enabled = null }).Severity);
    }

    // ---- Remote ------------------------------------------------------------

    [Fact]
    public void Remote_One_IsWarning()
    {
        var f = AnalyzeRemote(HardenedState() with { Remote = 1 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void Remote_Zero_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeRemote(HardenedState() with { Remote = 0 }).Severity);
    }

    [Fact]
    public void Remote_Absent_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeRemote(HardenedState() with { Remote = null }).Severity);
    }

    // ---- TrustPolicy -------------------------------------------------------

    [Fact]
    public void TrustPolicy_Two_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeTrustPolicy(HardenedState() with { TrustPolicy = 2 }).Severity);
    }

    [Fact]
    public void TrustPolicy_One_IsInfo()
    {
        Assert.Equal(Severity.Info, AnalyzeTrustPolicy(HardenedState() with { TrustPolicy = 1 }).Severity);
    }

    [Fact]
    public void TrustPolicy_Zero_IsInfo()
    {
        var f = AnalyzeTrustPolicy(HardenedState() with { TrustPolicy = 0 });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void TrustPolicy_Absent_IsInfo()
    {
        Assert.Equal(Severity.Info, AnalyzeTrustPolicy(HardenedState() with { TrustPolicy = null }).Severity);
    }

    // ---- Per-user override -------------------------------------------------

    [Fact]
    public void UserOverride_MachineDisabled_UserReEnabled_IsWarning()
    {
        // HKLM Enabled=0 (machine disabled) but HKCU Enabled=1 re-enables it.
        var f = AnalyzeUserOverride(HardenedState() with { Enabled = 0, UserEnabled = 1 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void UserOverride_MachineDisabled_NoUserValue_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeUserOverride(HardenedState() with { Enabled = 0, UserEnabled = null }).Severity);
    }

    [Fact]
    public void UserOverride_MachineEnabled_UserValueIrrelevant_Passes()
    {
        // When the machine is not disabled, the per-user value is not an override worth flagging.
        Assert.Equal(Severity.Pass, AnalyzeUserOverride(HardenedState() with { Enabled = 1, UserEnabled = 1 }).Severity);
        Assert.Equal(Severity.Pass, AnalyzeUserOverride(HardenedState() with { Enabled = null, UserEnabled = 1 }).Severity);
    }
}
