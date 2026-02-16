using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the FirewallAudit module.
/// Uses IAsyncLifetime to run the audit once and share the result across all tests.
/// </summary>
public class FirewallAuditTests : IAsyncLifetime
{
    private readonly FirewallAudit _audit = new();
    private AuditResult _result = null!;

    public async Task InitializeAsync()
    {
        _result = await _audit.RunAuditAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Firewall Audit", _audit.Name);
        Assert.Equal("Firewall", _audit.Category);
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    [Fact]
    public void RunAuditAsync_Succeeds()
    {
        Assert.True(_result.Success, $"Audit failed: {_result.Error}");
        Assert.Equal("Firewall Audit", _result.ModuleName);
        Assert.Equal("Firewall", _result.Category);
    }

    [Fact]
    public void RunAuditAsync_ProducesFindings()
    {
        Assert.NotEmpty(_result.Findings);
        // Should at least have findings for the 3 firewall profiles
        Assert.True(_result.Findings.Count >= 3,
            $"Expected at least 3 findings (one per profile), got {_result.Findings.Count}");
    }

    [Fact]
    public void RunAuditAsync_FindingsHaveRequiredFields()
    {
        foreach (var finding in _result.Findings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Title),
                "Finding title must not be empty");
            Assert.False(string.IsNullOrWhiteSpace(finding.Description),
                "Finding description must not be empty");
            Assert.True(Enum.IsDefined(finding.Severity),
                $"Invalid severity: {finding.Severity}");
        }
    }

    [Fact]
    public void RunAuditAsync_HasValidTimestamps()
    {
        Assert.True(_result.StartTime > DateTimeOffset.MinValue);
        Assert.True(_result.EndTime >= _result.StartTime);
        Assert.True(_result.Duration >= TimeSpan.Zero);
    }

    [Fact]
    public void RunAuditAsync_CriticalFindingsHaveRemediation()
    {
        foreach (var finding in _result.Findings.Where(f => f.Severity == Severity.Critical))
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Remediation),
                $"Critical finding '{finding.Title}' must have remediation");
            Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand),
                $"Critical finding '{finding.Title}' must have a fix command");
        }
    }

    [Fact]
    public void RunAuditAsync_ScoreIsValid()
    {
        Assert.InRange(_result.Score, 0, 100);
    }
}
