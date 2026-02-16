using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the SystemAudit module.
/// Runs against the actual Windows machine.
/// </summary>
public class SystemAuditTests
{
    private readonly SystemAudit _audit = new();

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("System Audit", _audit.Name);
        Assert.Equal("System", _audit.Category);
    }

    [Fact]
    public async Task RunAuditAsync_Succeeds()
    {
        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, $"Audit failed: {result.Error}");
    }

    [Fact]
    public async Task RunAuditAsync_DetectsOsVersion()
    {
        var result = await _audit.RunAuditAsync();

        Assert.Contains(result.Findings,
            f => f.Title.Contains("OS", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Windows", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_ChecksUac()
    {
        var result = await _audit.RunAuditAsync();

        Assert.Contains(result.Findings,
            f => f.Title.Contains("UAC", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_ChecksSecureBoot()
    {
        var result = await _audit.RunAuditAsync();

        Assert.Contains(result.Findings,
            f => f.Title.Contains("Secure Boot", StringComparison.OrdinalIgnoreCase));
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
