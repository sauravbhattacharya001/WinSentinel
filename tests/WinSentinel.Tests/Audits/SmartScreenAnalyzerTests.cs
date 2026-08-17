using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.SmartScreenAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="SmartScreenAnalyzer"/> - the
/// single-machine Windows SmartScreen reputation checks (App &amp; File shell
/// SmartScreen enable + block level, Edge SmartScreen, Edge PUA blocking, and
/// Store/App-Installer web-content evaluation). Every rule is exercised directly
/// against a synthetic <see cref="SmartScreenState"/>; no registry or I/O is touched.
/// </summary>
public class SmartScreenAnalyzerTests
{
    /// <summary>A fully-hardened machine: shell SmartScreen on+Block, Edge on, PUA blocking on, web eval on.</summary>
    private static SmartScreenState HardenedState() => new()
    {
        EnableSmartScreen = 1,
        ShellSmartScreenLevel = "Block",
        EdgeSmartScreenEnabled = 1,
        EdgeSmartScreenPuaEnabled = 1,
        EnableWebContentEvaluation = 1,
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
        Assert.All(findings, f => Assert.Equal("SmartScreen", f.Category));
    }

    [Fact]
    public void Analyze_HardenedState_HasNoWarnings()
    {
        var findings = Analyze(HardenedState());
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_HardenedState_AllPass()
    {
        var findings = Analyze(HardenedState());
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
    }

    // --- App & File (shell) SmartScreen ---

    [Fact]
    public void Shell_Disabled_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeShellSmartScreen(HardenedState() with { EnableSmartScreen = 0 }).Severity);
    }

    [Fact]
    public void Shell_EnabledBlock_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeShellSmartScreen(HardenedState() with { EnableSmartScreen = 1, ShellSmartScreenLevel = "Block" }).Severity);
    }

    [Fact]
    public void Shell_BlockLevel_IsCaseInsensitive()
    {
        Assert.Equal(Severity.Pass, AnalyzeShellSmartScreen(HardenedState() with { ShellSmartScreenLevel = "block" }).Severity);
    }

    [Fact]
    public void Shell_EnabledWarnLevel_IsInfo()
    {
        Assert.Equal(Severity.Info, AnalyzeShellSmartScreen(HardenedState() with { EnableSmartScreen = 1, ShellSmartScreenLevel = "Warn" }).Severity);
    }

    [Fact]
    public void Shell_EnabledNoLevelPinned_IsInfo()
    {
        Assert.Equal(Severity.Info, AnalyzeShellSmartScreen(HardenedState() with { EnableSmartScreen = 1, ShellSmartScreenLevel = null }).Severity);
    }

    [Fact]
    public void Shell_AbsentEnable_TreatedAsOn_NotWarning()
    {
        // Absent EnableSmartScreen => Windows default on; without a pinned level this is Info, not Warning.
        Assert.Equal(Severity.Info, AnalyzeShellSmartScreen(HardenedState() with { EnableSmartScreen = null, ShellSmartScreenLevel = null }).Severity);
    }

    // --- Edge SmartScreen ---

    [Fact]
    public void Edge_Disabled_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeEdgeSmartScreen(HardenedState() with { EdgeSmartScreenEnabled = 0 }).Severity);
    }

    [Fact]
    public void Edge_Enabled_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeEdgeSmartScreen(HardenedState() with { EdgeSmartScreenEnabled = 1 }).Severity);
    }

    [Fact]
    public void Edge_Absent_TreatedAsOn_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeEdgeSmartScreen(HardenedState() with { EdgeSmartScreenEnabled = null }).Severity);
    }

    // --- Edge PUA ---

    [Fact]
    public void EdgePua_Enabled_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeEdgePua(HardenedState() with { EdgeSmartScreenPuaEnabled = 1 }).Severity);
    }

    [Fact]
    public void EdgePua_Absent_IsInfo()
    {
        Assert.Equal(Severity.Info, AnalyzeEdgePua(HardenedState() with { EdgeSmartScreenPuaEnabled = null }).Severity);
    }

    [Fact]
    public void EdgePua_Disabled_IsInfo()
    {
        Assert.Equal(Severity.Info, AnalyzeEdgePua(HardenedState() with { EdgeSmartScreenPuaEnabled = 0 }).Severity);
    }

    // --- Store / App Installer web content ---

    [Fact]
    public void StoreApp_Disabled_IsInfo()
    {
        Assert.Equal(Severity.Info, AnalyzeStoreAppReputation(HardenedState() with { EnableWebContentEvaluation = 0 }).Severity);
    }

    [Fact]
    public void StoreApp_Enabled_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeStoreAppReputation(HardenedState() with { EnableWebContentEvaluation = 1 }).Severity);
    }

    [Fact]
    public void StoreApp_Absent_TreatedAsOn_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeStoreAppReputation(HardenedState() with { EnableWebContentEvaluation = null }).Severity);
    }

    // --- remediation/fix presence on non-pass findings ---

    [Fact]
    public void NonPassFindings_CarryFixCommand()
    {
        var weak = new SmartScreenState
        {
            EnableSmartScreen = 0,
            ShellSmartScreenLevel = null,
            EdgeSmartScreenEnabled = 0,
            EdgeSmartScreenPuaEnabled = 0,
            EnableWebContentEvaluation = 0,
        };
        foreach (var f in Analyze(weak))
        {
            Assert.NotEqual(Severity.Pass, f.Severity);
            Assert.False(string.IsNullOrWhiteSpace(f.FixCommand), $"expected FixCommand on '{f.Title}'");
        }
    }
}
