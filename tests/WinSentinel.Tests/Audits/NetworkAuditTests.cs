using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the NetworkAudit module.
/// Runs audit once and shares the result across all tests.
/// </summary>
public class NetworkAuditTests : IAsyncLifetime
{
    private readonly NetworkAudit _audit = new();
    private AuditResult _result = null!;

    public async Task InitializeAsync()
    {
        _result = await _audit.RunAuditAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Network Audit", _audit.Name);
        Assert.Equal("Network", _audit.Category);
    }

    [Fact]
    public void RunAuditAsync_Succeeds()
    {
        Assert.True(_result.Success, $"Audit failed: {_result.Error}");
    }

    [Fact]
    public void RunAuditAsync_ChecksListeningPorts()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Port", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Listening", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksSmbOrRdp()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("SMB", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("RDP", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksDns()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("DNS", StringComparison.OrdinalIgnoreCase));
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
