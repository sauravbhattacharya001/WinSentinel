using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the SystemAudit module.
/// Runs audit once and shares the result across all tests.
/// </summary>
public class SystemAuditTests : IAsyncLifetime
{
    private readonly SystemAudit _audit = new();
    private AuditResult _result = null!;

    public async Task InitializeAsync()
    {
        _result = await _audit.RunAuditAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("System Audit", _audit.Name);
        Assert.Equal("System", _audit.Category);
    }

    [Fact]
    public void RunAuditAsync_Succeeds()
    {
        Assert.True(_result.Success, $"Audit failed: {_result.Error}");
    }

    [Fact]
    public void RunAuditAsync_DetectsOsVersion()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("OS", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Windows", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksUac()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("UAC", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksSecureBoot()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Secure Boot", StringComparison.OrdinalIgnoreCase));
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
