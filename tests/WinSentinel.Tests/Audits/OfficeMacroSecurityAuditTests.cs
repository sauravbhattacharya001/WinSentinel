using WinSentinel.Core.Audits;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Tests for the <see cref="OfficeMacroSecurityAudit"/> I/O module that wires the
/// pure <see cref="OfficeMacroSecurityAnalyzer"/> into a live <c>--audit</c> run.
/// The analyzer's decision logic is covered exhaustively in
/// <see cref="OfficeMacroSecurityAnalyzerTests"/>; these tests pin the module's
/// identity/wiring: category matches the analyzer, the collector reads real local
/// per-app Office policy state without throwing, and running the module surfaces
/// exactly the analyzer's finding set for the collected state (1 finding when
/// Office is not detected, 3 when it is).
/// </summary>
public class OfficeMacroSecurityAuditTests
{
    private readonly OfficeMacroSecurityAudit _audit = new();

    [Fact]
    public void Category_MatchesAnalyzer()
    {
        Assert.Equal(OfficeMacroSecurityAnalyzer.Category, _audit.Category);
        Assert.Equal("Application Security", _audit.Category);
    }

    [Fact]
    public void Name_And_Description_AreProvided()
    {
        Assert.False(string.IsNullOrWhiteSpace(_audit.Name));
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    [Fact]
    public void CollectState_DoesNotThrow_AndReturnsState()
    {
        var state = OfficeMacroSecurityAudit.CollectState();
        Assert.NotNull(state);
    }

    [Fact]
    public void OfficeInstalled_DoesNotThrow()
    {
        // Best-effort registry probe - result depends on the host, must never throw.
        var ex = Record.Exception(() => OfficeMacroSecurityAudit.OfficeInstalled());
        Assert.Null(ex);
    }

    [Fact]
    public async Task RunAudit_SurfacesEveryAnalyzerFindingForCollectedState()
    {
        var state = OfficeMacroSecurityAudit.CollectState();
        var expected = OfficeMacroSecurityAnalyzer.Analyze(state);

        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, result.Error);
        // The module surfaces exactly the analyzer's finding set for whatever state
        // the collector read on this host: 1 when Office is absent, 3 when present.
        Assert.Equal(expected.Count, result.Findings.Count);
        Assert.Contains(result.Findings.Count, new[] { 1, 3 });
        Assert.All(result.Findings, f => Assert.Equal(OfficeMacroSecurityAnalyzer.Category, f.Category));
    }
}
