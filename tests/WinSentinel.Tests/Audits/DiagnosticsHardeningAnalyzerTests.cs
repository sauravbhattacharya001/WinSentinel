using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.DiagnosticsHardeningAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="DiagnosticsHardeningAnalyzer"/> -
/// the single-machine Windows diagnostics / troubleshooting hardening checks
/// (scripted-diagnostics MSDT engine, the ms-msdt: URL protocol handler behind
/// Follina/CVE-2022-30190, built-in MSDT troubleshooter policy, and the diagnostic
/// data floor). Every rule is exercised directly against a synthetic
/// <see cref="DiagnosticsHardeningState"/>; no registry or I/O is touched.
/// </summary>
public class DiagnosticsHardeningAnalyzerTests
{
    private static DiagnosticsHardeningState HardenedState() => new()
    {
        ScriptedDiagnosticsEnabled = 0,
        MsdtProtocolHandlerRegistered = false,
        AllowBuiltInTroubleshooting = 0,
        AllowTelemetry = 1,
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
    }

    [Fact]
    public void Analyze_EveryFinding_UsesTheDiagnosticsCategory()
    {
        var findings = Analyze(HardenedState());
        Assert.All(findings, f => Assert.Equal(Category, f.Category));
    }

    // --- Scripted diagnostics (MSDT engine / Follina) --------------------------

    [Fact]
    public void ScriptedDiagnostics_Disabled_Passes()
    {
        var f = AnalyzeScriptedDiagnostics(HardenedState() with { ScriptedDiagnosticsEnabled = 0 });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(null)]
    public void ScriptedDiagnostics_EnabledOrUnset_Warns(int? value)
    {
        var f = AnalyzeScriptedDiagnostics(HardenedState() with { ScriptedDiagnosticsEnabled = value });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("CVE-2022-30190", f.Description);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    // --- ms-msdt: URL protocol handler -----------------------------------------

    [Fact]
    public void MsdtProtocol_NotRegistered_Passes()
    {
        var f = AnalyzeMsdtProtocolHandler(HardenedState() with { MsdtProtocolHandlerRegistered = false });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void MsdtProtocol_Registered_Warns()
    {
        var f = AnalyzeMsdtProtocolHandler(HardenedState() with { MsdtProtocolHandlerRegistered = true });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("ms-msdt", f.Description);
        Assert.False(string.IsNullOrWhiteSpace(f.Remediation));
    }

    // --- Built-in troubleshooting policy ---------------------------------------

    [Fact]
    public void Troubleshooting_Restricted_Passes()
    {
        var f = AnalyzeTroubleshootingPolicy(HardenedState() with { AllowBuiltInTroubleshooting = 0 });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(null)]
    public void Troubleshooting_AllowedOrUnset_Warns(int? value)
    {
        var f = AnalyzeTroubleshootingPolicy(HardenedState() with { AllowBuiltInTroubleshooting = value });
        Assert.Equal(Severity.Warning, f.Severity);
    }

    // --- Diagnostic data floor -------------------------------------------------

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void DiagnosticData_AtFloor_Passes(int level)
    {
        var f = AnalyzeDiagnosticDataFloor(HardenedState() with { AllowTelemetry = level });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(null)]
    public void DiagnosticData_AboveFloorOrUnset_Warns(int? level)
    {
        var f = AnalyzeDiagnosticDataFloor(HardenedState() with { AllowTelemetry = level });
        Assert.Equal(Severity.Warning, f.Severity);
    }

    [Fact]
    public void DiagnosticData_Unset_MentionsDefault()
    {
        var f = AnalyzeDiagnosticDataFloor(HardenedState() with { AllowTelemetry = null });
        Assert.Contains("unset", f.Description);
    }
}
