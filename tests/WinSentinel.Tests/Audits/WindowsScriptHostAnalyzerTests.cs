using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.WindowsScriptHostAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="WindowsScriptHostAnalyzer"/> -
/// the single-machine Windows Script Host (WSH) hardening checks (WSH Enabled kill
/// switch, per-user override that bypasses a machine-wide disable, remote script
/// execution, and Authenticode TrustPolicy). Every rule is exercised directly
/// against a synthetic <see cref="WindowsScriptHostState"/>; no registry or I/O is
/// touched.
/// </summary>
public class WindowsScriptHostAnalyzerTests
{
    /// <summary>A fully-hardened machine: WSH disabled, no per-user override, no remote, signed-only.</summary>
    private static WindowsScriptHostState HardenedState() => new()
    {
        Enabled = 0,
        UserEnabled = null,
        Remote = 0,
        TrustPolicy = 2,
    };

    [Fact]
    public void Analyze_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Analyze(null!));
    }

    [Fact]
    public void Analyze_ReturnsFourFindings_AllInCategory()
    {
        var findings = Analyze(HardenedState());
        Assert.Equal(4, findings.Count);
        Assert.All(findings, f => Assert.Equal("Windows Script Host", f.Category));
    }

    [Fact]
    public void Analyze_HardenedState_HasNoWarnings()
    {
        var findings = Analyze(HardenedState());
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Warning);
    }

    // --- WSH Enabled ---

    [Fact]
    public void Enabled_Zero_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeEnabled(HardenedState() with { Enabled = 0 }).Severity);
    }

    [Fact]
    public void Enabled_Absent_TreatedAsDefaultEnabled_Info_WithFix()
    {
        var f = AnalyzeEnabled(HardenedState() with { Enabled = null });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Enabled", f.FixCommand);
    }

    [Fact]
    public void Enabled_One_Info()
    {
        Assert.Equal(Severity.Info, AnalyzeEnabled(HardenedState() with { Enabled = 1 }).Severity);
    }

    // --- Per-user override ---

    [Fact]
    public void UserOverride_MachineDisabledButUserReenables_Warns_WithFix()
    {
        var f = AnalyzeUserOverride(HardenedState() with { Enabled = 0, UserEnabled = 1 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("HKCU", f.FixCommand);
    }

    [Fact]
    public void UserOverride_NoOverride_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeUserOverride(HardenedState() with { Enabled = 0, UserEnabled = null }).Severity);
    }

    [Fact]
    public void UserOverride_MachineEnabled_UserValueIrrelevant_Passes()
    {
        // If the machine did not disable WSH, a per-user Enabled=1 changes nothing worth flagging here.
        Assert.Equal(Severity.Pass, AnalyzeUserOverride(HardenedState() with { Enabled = 1, UserEnabled = 1 }).Severity);
    }

    // --- Remote ---

    [Fact]
    public void Remote_One_Warns_WithFix()
    {
        var f = AnalyzeRemote(HardenedState() with { Remote = 1 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("Remote", f.FixCommand);
    }

    [Fact]
    public void Remote_ZeroOrAbsent_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeRemote(HardenedState() with { Remote = 0 }).Severity);
        Assert.Equal(Severity.Pass, AnalyzeRemote(HardenedState() with { Remote = null }).Severity);
    }

    // --- TrustPolicy ---

    [Fact]
    public void TrustPolicy_Two_SignedOnly_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeTrustPolicy(HardenedState() with { TrustPolicy = 2 }).Severity);
    }

    [Fact]
    public void TrustPolicy_One_Prompt_Info()
    {
        Assert.Equal(Severity.Info, AnalyzeTrustPolicy(HardenedState() with { TrustPolicy = 1 }).Severity);
    }

    [Fact]
    public void TrustPolicy_ZeroOrAbsent_Info_WithFix()
    {
        var zero = AnalyzeTrustPolicy(HardenedState() with { TrustPolicy = 0 });
        Assert.Equal(Severity.Info, zero.Severity);
        Assert.Contains("TrustPolicy", zero.FixCommand);
        Assert.Equal(Severity.Info, AnalyzeTrustPolicy(HardenedState() with { TrustPolicy = null }).Severity);
    }

    [Fact]
    public void Analyze_WorstCase_ProducesExpectedSeverities()
    {
        // Machine disabled + user re-enable + remote on + unsigned allowed.
        var findings = Analyze(new WindowsScriptHostState
        {
            Enabled = 0,
            UserEnabled = 1,
            Remote = 1,
            TrustPolicy = 0,
        });
        Assert.Equal(4, findings.Count);
        // Two warnings (user override bypass, remote), plus the Enabled=0 pass and the unsigned Info.
        Assert.Equal(2, findings.Count(f => f.Severity == Severity.Warning));
    }
}
