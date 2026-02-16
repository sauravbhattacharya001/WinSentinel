using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the AccountAudit module.
/// Runs against the actual Windows machine.
/// </summary>
public class AccountAuditTests
{
    private readonly AccountAudit _audit = new();

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Account Audit", _audit.Name);
        Assert.Equal("Accounts", _audit.Category);
    }

    [Fact]
    public async Task RunAuditAsync_Succeeds()
    {
        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, $"Audit failed: {result.Error}");
    }

    [Fact]
    public async Task RunAuditAsync_ChecksGuestAccount()
    {
        var result = await _audit.RunAuditAsync();

        Assert.Contains(result.Findings,
            f => f.Title.Contains("Guest", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_ChecksAdminAccounts()
    {
        var result = await _audit.RunAuditAsync();

        Assert.Contains(result.Findings,
            f => f.Title.Contains("Admin", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_ChecksPasswordPolicy()
    {
        var result = await _audit.RunAuditAsync();

        Assert.Contains(result.Findings,
            f => f.Title.Contains("Password", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Lockout", StringComparison.OrdinalIgnoreCase));
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
