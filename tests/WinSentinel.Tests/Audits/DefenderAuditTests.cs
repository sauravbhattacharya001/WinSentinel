using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the DefenderAudit module.
/// Runs against the actual Windows machine.
/// </summary>
public class DefenderAuditTests
{
    private readonly DefenderAudit _audit = new();

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Defender Audit", _audit.Name);
        Assert.Equal("Defender", _audit.Category);
    }

    [Fact]
    public async Task RunAuditAsync_Succeeds()
    {
        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, $"Audit failed: {result.Error}");
        Assert.Equal("Defender Audit", result.ModuleName);
    }

    [Fact]
    public async Task RunAuditAsync_ChecksRealTimeProtection()
    {
        var result = await _audit.RunAuditAsync();

        // Should have at least one finding about real-time protection
        Assert.Contains(result.Findings,
            f => f.Title.Contains("Real-Time Protection", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_ChecksDefinitions()
    {
        var result = await _audit.RunAuditAsync();

        // Should have a finding about antivirus definitions
        Assert.Contains(result.Findings,
            f => f.Title.Contains("Definitions", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Definition", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_AllFindingsHaveCategory()
    {
        var result = await _audit.RunAuditAsync();

        foreach (var finding in result.Findings)
        {
            Assert.Equal("Defender", finding.Category);
        }
    }

    [Fact]
    public async Task RunAuditAsync_ScoreIsValid()
    {
        var result = await _audit.RunAuditAsync();
        Assert.InRange(result.Score, 0, 100);
    }
}
