using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the UpdateAudit module.
/// Runs against the actual Windows machine.
/// </summary>
public class UpdateAuditTests
{
    private readonly UpdateAudit _audit = new();

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Update Audit", _audit.Name);
        Assert.Equal("Updates", _audit.Category);
    }

    [Fact]
    public async Task RunAuditAsync_Succeeds()
    {
        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, $"Audit failed: {result.Error}");
    }

    [Fact]
    public async Task RunAuditAsync_ChecksLastUpdateDate()
    {
        var result = await _audit.RunAuditAsync();

        Assert.Contains(result.Findings,
            f => f.Title.Contains("Update", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_ChecksAutoUpdate()
    {
        var result = await _audit.RunAuditAsync();

        Assert.Contains(result.Findings,
            f => f.Title.Contains("Automatic", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Auto", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Update", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_ProducesFindings()
    {
        var result = await _audit.RunAuditAsync();

        Assert.NotEmpty(result.Findings);
    }

    [Fact]
    public async Task RunAuditAsync_ScoreIsValid()
    {
        var result = await _audit.RunAuditAsync();
        Assert.InRange(result.Score, 0, 100);
    }
}
