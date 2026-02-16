using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the UpdateAudit module.
/// Runs audit once and shares the result across all tests.
/// </summary>
public class UpdateAuditTests : IAsyncLifetime
{
    private readonly UpdateAudit _audit = new();
    private AuditResult _result = null!;

    public async Task InitializeAsync()
    {
        _result = await _audit.RunAuditAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Update Audit", _audit.Name);
        Assert.Equal("Updates", _audit.Category);
    }

    [Fact]
    public void RunAuditAsync_Succeeds()
    {
        Assert.True(_result.Success, $"Audit failed: {_result.Error}");
    }

    [Fact]
    public void RunAuditAsync_ChecksLastUpdateDate()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Update", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksAutoUpdate()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Automatic", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Auto", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Update", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ProducesFindings()
    {
        Assert.NotEmpty(_result.Findings);
    }

    [Fact]
    public void RunAuditAsync_ScoreIsValid()
    {
        Assert.InRange(_result.Score, 0, 100);
    }
}
