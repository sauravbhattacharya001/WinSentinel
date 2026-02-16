using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the ProcessAudit module.
/// Runs against the actual Windows machine.
/// </summary>
public class ProcessAuditTests
{
    private readonly ProcessAudit _audit = new();

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Process Audit", _audit.Name);
        Assert.Equal("Processes", _audit.Category);
    }

    [Fact]
    public async Task RunAuditAsync_Succeeds()
    {
        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, $"Audit failed: {result.Error}");
    }

    [Fact]
    public async Task RunAuditAsync_ChecksProcessCount()
    {
        var result = await _audit.RunAuditAsync();

        Assert.Contains(result.Findings,
            f => f.Title.Contains("Process Count", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_ChecksTempProcesses()
    {
        var result = await _audit.RunAuditAsync();

        // Should have a finding about temp directory processes (pass or warning)
        Assert.Contains(result.Findings,
            f => f.Title.Contains("Temp", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_ChecksSignatures()
    {
        var result = await _audit.RunAuditAsync();

        // Should check process signatures
        Assert.Contains(result.Findings,
            f => f.Title.Contains("Signed", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Unsigned", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_ProducesMultipleFindings()
    {
        var result = await _audit.RunAuditAsync();

        Assert.True(result.Findings.Count >= 2,
            $"Expected at least 2 findings, got {result.Findings.Count}");
    }

    [Fact]
    public async Task RunAuditAsync_ScoreIsValid()
    {
        var result = await _audit.RunAuditAsync();
        Assert.InRange(result.Score, 0, 100);
    }
}
