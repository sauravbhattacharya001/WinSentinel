using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the NetworkAudit module.
/// Runs against the actual Windows machine.
/// </summary>
public class NetworkAuditTests
{
    private readonly NetworkAudit _audit = new();

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Network Audit", _audit.Name);
        Assert.Equal("Network", _audit.Category);
    }

    [Fact]
    public async Task RunAuditAsync_Succeeds()
    {
        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, $"Audit failed: {result.Error}");
    }

    [Fact]
    public async Task RunAuditAsync_ChecksListeningPorts()
    {
        var result = await _audit.RunAuditAsync();

        // Should report on listening ports (either pass or findings)
        Assert.Contains(result.Findings,
            f => f.Title.Contains("Port", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Listening", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_ChecksSmbOrRdp()
    {
        var result = await _audit.RunAuditAsync();

        // Should check at least SMB or RDP
        Assert.Contains(result.Findings,
            f => f.Title.Contains("SMB", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("RDP", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_ChecksDns()
    {
        var result = await _audit.RunAuditAsync();

        Assert.Contains(result.Findings,
            f => f.Title.Contains("DNS", StringComparison.OrdinalIgnoreCase));
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
