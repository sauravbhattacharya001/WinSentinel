using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the FirewallAudit module.
/// Runs against the actual Windows machine to verify real results.
/// </summary>
public class FirewallAuditTests
{
    private readonly FirewallAudit _audit = new();

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Firewall Audit", _audit.Name);
        Assert.Equal("Firewall", _audit.Category);
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    [Fact]
    public async Task RunAuditAsync_Succeeds()
    {
        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, $"Audit failed: {result.Error}");
        Assert.Equal("Firewall Audit", result.ModuleName);
        Assert.Equal("Firewall", result.Category);
    }

    [Fact]
    public async Task RunAuditAsync_ProducesFindings()
    {
        var result = await _audit.RunAuditAsync();

        Assert.NotEmpty(result.Findings);
        // Should at least have findings for the 3 firewall profiles
        Assert.True(result.Findings.Count >= 3,
            $"Expected at least 3 findings (one per profile), got {result.Findings.Count}");
    }

    [Fact]
    public async Task RunAuditAsync_FindingsHaveRequiredFields()
    {
        var result = await _audit.RunAuditAsync();

        foreach (var finding in result.Findings)
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
    public async Task RunAuditAsync_HasValidTimestamps()
    {
        var before = DateTimeOffset.UtcNow;
        var result = await _audit.RunAuditAsync();
        var after = DateTimeOffset.UtcNow;

        Assert.InRange(result.StartTime, before, after);
        Assert.InRange(result.EndTime, before, after);
        Assert.True(result.Duration >= TimeSpan.Zero);
    }

    [Fact]
    public async Task RunAuditAsync_CriticalFindingsHaveRemediation()
    {
        var result = await _audit.RunAuditAsync();

        foreach (var finding in result.Findings.Where(f => f.Severity == Severity.Critical))
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Remediation),
                $"Critical finding '{finding.Title}' must have remediation");
            Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand),
                $"Critical finding '{finding.Title}' must have a fix command");
        }
    }

    [Fact]
    public async Task RunAuditAsync_SupportsCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // Should throw OperationCanceledException or return gracefully
        try
        {
            await _audit.RunAuditAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            // Expected
        }
    }

    [Fact]
    public async Task RunAuditAsync_ScoreIsValid()
    {
        var result = await _audit.RunAuditAsync();
        Assert.InRange(result.Score, 0, 100);
    }
}
