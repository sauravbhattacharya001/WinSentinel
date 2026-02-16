using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the ProcessAudit module.
/// Runs audit once and shares the result across all tests.
/// </summary>
public class ProcessAuditTests : IAsyncLifetime
{
    private readonly ProcessAudit _audit = new();
    private AuditResult _result = null!;

    public async Task InitializeAsync()
    {
        _result = await _audit.RunAuditAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Process Audit", _audit.Name);
        Assert.Equal("Processes", _audit.Category);
    }

    [Fact]
    public void RunAuditAsync_Succeeds()
    {
        Assert.True(_result.Success, $"Audit failed: {_result.Error}");
    }

    [Fact]
    public void RunAuditAsync_ChecksProcessCount()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Process Count", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksTempProcesses()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Temp", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksSignatures()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Signed", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Unsigned", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ProducesMultipleFindings()
    {
        Assert.True(_result.Findings.Count >= 2,
            $"Expected at least 2 findings, got {_result.Findings.Count}");
    }

    [Fact]
    public void RunAuditAsync_ScoreIsValid()
    {
        Assert.InRange(_result.Score, 0, 100);
    }
}
