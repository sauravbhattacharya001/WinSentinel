using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the AccountAudit module.
/// Runs audit once and shares the result across all tests.
/// </summary>
public class AccountAuditTests : IAsyncLifetime
{
    private readonly AccountAudit _audit = new();
    private AuditResult _result = null!;

    public async Task InitializeAsync()
    {
        _result = await _audit.RunAuditAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Account Audit", _audit.Name);
        Assert.Equal("Accounts", _audit.Category);
    }

    [Fact]
    public void RunAuditAsync_Succeeds()
    {
        Assert.True(_result.Success, $"Audit failed: {_result.Error}");
    }

    [Fact]
    public void RunAuditAsync_ChecksGuestAccount()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Guest", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksAdminAccounts()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Admin", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksPasswordPolicy()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Password", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Lockout", StringComparison.OrdinalIgnoreCase));
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
