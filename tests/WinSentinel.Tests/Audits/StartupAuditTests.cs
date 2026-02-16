using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the StartupAudit module.
/// Runs against the actual Windows machine.
/// </summary>
public class StartupAuditTests
{
    private readonly StartupAudit _audit = new();

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Startup Audit", _audit.Name);
        Assert.Equal("Startup", _audit.Category);
    }

    [Fact]
    public async Task RunAuditAsync_Succeeds()
    {
        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, $"Audit failed: {result.Error}");
    }

    [Fact]
    public async Task RunAuditAsync_ChecksRegistryRunKeys()
    {
        var result = await _audit.RunAuditAsync();

        Assert.Contains(result.Findings,
            f => f.Title.Contains("Registry Run", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_ChecksScheduledTasks()
    {
        var result = await _audit.RunAuditAsync();

        Assert.Contains(result.Findings,
            f => f.Title.Contains("Scheduled Task", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Tasks", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_ChecksServices()
    {
        var result = await _audit.RunAuditAsync();

        Assert.Contains(result.Findings,
            f => f.Title.Contains("Service", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_ProducesMultipleFindings()
    {
        var result = await _audit.RunAuditAsync();

        Assert.True(result.Findings.Count >= 3,
            $"Expected at least 3 findings, got {result.Findings.Count}");
    }

    [Fact]
    public async Task RunAuditAsync_ScoreIsValid()
    {
        var result = await _audit.RunAuditAsync();
        Assert.InRange(result.Score, 0, 100);
    }
}
