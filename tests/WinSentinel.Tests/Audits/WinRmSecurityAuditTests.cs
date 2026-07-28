using WinSentinel.Core.Audits;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Tests for the <see cref="WinRmSecurityAudit"/> I/O module that wires the pure
/// <see cref="WinRmSecurityAnalyzer"/> into a live <c>--audit</c> run. The analyzer's
/// decision logic is covered exhaustively in <see cref="WinRmSecurityAnalyzerTests"/>;
/// these tests pin the module's identity/wiring: category matches the analyzer, the
/// collector reads real local service/registry state without throwing, and running
/// the module surfaces exactly the analyzer's finding set for the collected state
/// (which varies with whether the WinRM service is running on the test host).
/// </summary>
public class WinRmSecurityAuditTests
{
    private readonly WinRmSecurityAudit _audit = new();

    [Fact]
    public void Category_MatchesAnalyzer()
    {
        Assert.Equal(WinRmSecurityAnalyzer.Category, _audit.Category);
        Assert.Equal("Remote Management", _audit.Category);
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
        var state = WinRmSecurityAudit.CollectState();
        Assert.NotNull(state);
    }

    [Fact]
    public async Task RunAudit_SurfacesEveryAnalyzerFindingForCollectedState()
    {
        var state = WinRmSecurityAudit.CollectState();
        var expected = WinRmSecurityAnalyzer.Analyze(state).Count;

        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, result.Error);
        // The module surfaces exactly one finding per analyzer check for whatever
        // state the collector read: 8 when the WinRM service is running (4 service
        // + 4 client), or 5 when it is stopped (1 info + 4 client). Either way it
        // must match the analyzer's own output for that same collected state.
        Assert.Equal(expected, result.Findings.Count);
        Assert.All(result.Findings, f => Assert.Equal(WinRmSecurityAnalyzer.Category, f.Category));
    }
}
