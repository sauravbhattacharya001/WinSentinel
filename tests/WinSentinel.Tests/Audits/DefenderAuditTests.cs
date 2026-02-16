using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the DefenderAudit module.
/// Runs audit once and shares the result across all tests.
/// </summary>
public class DefenderAuditTests : IAsyncLifetime
{
    private readonly DefenderAudit _audit = new();
    private AuditResult _result = null!;

    public async Task InitializeAsync()
    {
        _result = await _audit.RunAuditAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Defender Audit", _audit.Name);
        Assert.Equal("Defender", _audit.Category);
    }

    [Fact]
    public void RunAuditAsync_Succeeds()
    {
        Assert.True(_result.Success, $"Audit failed: {_result.Error}");
        Assert.Equal("Defender Audit", _result.ModuleName);
    }

    [Fact]
    public void RunAuditAsync_ChecksRealTimeProtection()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Real-Time Protection", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksDefinitions()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Definitions", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Definition", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_AllFindingsHaveCategory()
    {
        foreach (var finding in _result.Findings)
        {
            Assert.Equal("Defender", finding.Category);
        }
    }

    [Fact]
    public void RunAuditAsync_ScoreIsValid()
    {
        Assert.InRange(_result.Score, 0, 100);
    }
}
