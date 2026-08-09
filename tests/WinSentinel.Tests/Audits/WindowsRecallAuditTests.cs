using WinSentinel.Core.Audits;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Tests for the <see cref="WindowsRecallAudit"/> I/O module that wires the pure
/// <see cref="WindowsRecallAnalyzer"/> into a live <c>--audit</c> run. The
/// analyzer's decision logic is covered exhaustively in
/// <see cref="WindowsRecallAnalyzerTests"/>; these tests pin the module's
/// identity/wiring: category matches the analyzer, the collector reads real local
/// policy/registry state and probes for a snapshot store without throwing, and
/// running the module surfaces exactly the analyzer's finding set for the
/// collected state (which varies with the host's Recall policy).
/// </summary>
public class WindowsRecallAuditTests
{
    private readonly WindowsRecallAudit _audit = new();

    [Fact]
    public void Category_MatchesAnalyzer()
    {
        Assert.Equal(WindowsRecallAnalyzer.Category, _audit.Category);
        Assert.Equal("Privacy", _audit.Category);
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
        var state = WindowsRecallAudit.CollectState();
        Assert.NotNull(state);
    }

    [Fact]
    public async Task RunAudit_SurfacesEveryAnalyzerFindingForCollectedState()
    {
        var state = WindowsRecallAudit.CollectState();
        var expected = WindowsRecallAnalyzer.Analyze(state).Count;

        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, result.Error);
        // The module surfaces exactly one finding per analyzer check (3) for
        // whatever state the collector read on this host.
        Assert.Equal(expected, result.Findings.Count);
        Assert.Equal(3, result.Findings.Count);
        Assert.All(result.Findings, f => Assert.Equal(WindowsRecallAnalyzer.Category, f.Category));
    }
}
