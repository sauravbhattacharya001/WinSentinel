using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the IdentityCredentialAudit module.
/// Validates all seven audit checks: password-never-expires, stale accounts,
/// local admin sprawl, LAPS posture, cached credentials, LSA protection,
/// and Credential Guard status.
/// </summary>
public class IdentityCredentialAuditTests : IAsyncLifetime
{
    private readonly IdentityCredentialAudit _audit = new();
    private AuditResult _result = null!;

    public async Task InitializeAsync()
    {
        _result = await _audit.RunAuditAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void Properties_NameIsCorrect()
    {
        Assert.Equal("Identity & Credential Audit", _audit.Name);
    }

    [Fact]
    public void Properties_CategoryIsIdentity()
    {
        Assert.Equal("Identity", _audit.Category);
    }

    [Fact]
    public void Properties_DescriptionContainsKeyTerms()
    {
        Assert.Contains("admin sprawl", _audit.Description);
        Assert.Contains("stale accounts", _audit.Description);
        Assert.Contains("LAPS", _audit.Description);
        Assert.Contains("cached credential", _audit.Description);
    }

    [Fact]
    public void RunAuditAsync_Succeeds()
    {
        Assert.True(_result.Success, $"Audit failed: {_result.Error}");
    }

    [Fact]
    public void RunAuditAsync_ProducesFindings()
    {
        Assert.NotEmpty(_result.Findings);
    }

    [Fact]
    public void RunAuditAsync_ProducesMultipleFindings()
    {
        // The module has 7 checks; even with some skipped, we expect several findings
        Assert.True(_result.Findings.Count >= 3,
            $"Expected at least 3 findings, got {_result.Findings.Count}");
    }

    [Fact]
    public void RunAuditAsync_AllFindingsHaveCategory()
    {
        foreach (var finding in _result.Findings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Category),
                $"Finding '{finding.Title}' has no category");
        }
    }

    [Fact]
    public void RunAuditAsync_AllFindingsHaveTitle()
    {
        foreach (var finding in _result.Findings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Title),
                "A finding has an empty title");
        }
    }

    [Fact]
    public void RunAuditAsync_AllFindingsHaveDescription()
    {
        foreach (var finding in _result.Findings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Description),
                $"Finding '{finding.Title}' has no description");
        }
    }

    [Fact]
    public void RunAuditAsync_FindingsHaveValidSeverity()
    {
        var validSeverities = new[] { Severity.Critical, Severity.Warning, Severity.Info, Severity.Pass };
        foreach (var finding in _result.Findings)
        {
            Assert.Contains(finding.Severity, validSeverities);
        }
    }

    [Fact]
    public void RunAuditAsync_ChecksPasswordExpiry()
    {
        // Should always produce a finding about password-never-expires (pass or warning)
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Password", StringComparison.OrdinalIgnoreCase) &&
                 (f.Title.Contains("Expires", StringComparison.OrdinalIgnoreCase) ||
                  f.Title.Contains("Expiry", StringComparison.OrdinalIgnoreCase) ||
                  f.Title.Contains("Skipped", StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public void RunAuditAsync_ChecksStaleAccounts()
    {
        // Should always produce a finding about stale accounts (pass, warning, or skipped)
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Stale", StringComparison.OrdinalIgnoreCase) ||
                 (f.Title.Contains("Account", StringComparison.OrdinalIgnoreCase) &&
                  f.Description.Contains("90", StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public void RunAuditAsync_ChecksCachedCredentialsOrLsa()
    {
        // Should always produce findings about cached creds, LSA, or Credential Guard
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Cached", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("LSA", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Credential Guard", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksLsaProtection()
    {
        // LSA Protection check always runs (reads registry directly)
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("LSA", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("LSASS", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Protected Process", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksCredentialGuard()
    {
        // Credential Guard check always runs (reads registry directly)
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Credential Guard", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("VBS", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Device Guard", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksLapsPosture()
    {
        // LAPS check should produce a finding (pass, warning, or info for non-domain machines)
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("LAPS", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_WarningFindingsHaveRemediation()
    {
        var warnings = _result.Findings.Where(f => f.Severity == Severity.Warning).ToList();
        foreach (var warning in warnings)
        {
            Assert.True(
                !string.IsNullOrWhiteSpace(warning.Remediation) ||
                !string.IsNullOrWhiteSpace(warning.FixCommand),
                $"Warning finding '{warning.Title}' has no remediation guidance");
        }
    }

    [Fact]
    public void RunAuditAsync_ScoreIsValid()
    {
        Assert.InRange(_result.Score, 0, 100);
    }

    [Fact]
    public void RunAuditAsync_FindingsAreInIdentityCategory()
    {
        // All findings from this module should be in the Identity category
        foreach (var finding in _result.Findings)
        {
            Assert.Equal("Identity", finding.Category);
        }
    }

    [Fact]
    public async Task RunAuditAsync_CompletesWithinTimeout()
    {
        // Validate audit doesn't hang — it should complete within 30 seconds
        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var result = await new IdentityCredentialAudit().RunAuditAsync(cts.Token);
        Assert.NotNull(result);
    }

    [Fact]
    public async Task RunAuditAsync_SupportsIdempotentExecution()
    {
        // Running twice should produce consistent results
        var result2 = await new IdentityCredentialAudit().RunAuditAsync();
        Assert.Equal(_result.Findings.Count, result2.Findings.Count);
        Assert.Equal(_result.Success, result2.Success);
    }

    [Fact]
    public async Task RunAuditAsync_SupportsCancellation()
    {
        // Should handle cancellation gracefully (not throw unhandled)
        var cts = new CancellationTokenSource();
        cts.Cancel();

        // Should either complete with what it has or throw OperationCanceledException
        try
        {
            var result = await new IdentityCredentialAudit().RunAuditAsync(cts.Token);
            // If it completes despite cancellation, that's acceptable (some checks are non-async)
            Assert.NotNull(result);
        }
        catch (OperationCanceledException)
        {
            // Expected behavior when cancellation is respected
        }
    }
}
