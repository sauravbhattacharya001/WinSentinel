using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the StartupAudit module.
/// Runs audit once and shares the result across all tests.
/// </summary>
public class StartupAuditTests : IAsyncLifetime
{
    private readonly StartupAudit _audit = new();
    private AuditResult _result = null!;

    public async Task InitializeAsync()
    {
        _result = await _audit.RunAuditAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Startup Audit", _audit.Name);
        Assert.Equal("Startup", _audit.Category);
    }

    [Fact]
    public void RunAuditAsync_Succeeds()
    {
        Assert.True(_result.Success, $"Audit failed: {_result.Error}");
    }

    [Fact]
    public void RunAuditAsync_ChecksRegistryRunKeys()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Registry Run", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksScheduledTasks()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Scheduled Task", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Tasks", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksServices()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Service", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ProducesMultipleFindings()
    {
        Assert.True(_result.Findings.Count >= 3,
            $"Expected at least 3 findings, got {_result.Findings.Count}");
    }

    [Fact]
    public void RunAuditAsync_ScoreIsValid()
    {
        Assert.InRange(_result.Score, 0, 100);
    }
}
