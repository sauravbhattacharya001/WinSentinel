using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Comprehensive tests for the BrowserAudit module.
/// Runs against the actual Windows machine to verify real results.
/// </summary>
public class BrowserAuditTests
{
    private readonly BrowserAudit _audit = new();

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Browser Audit", _audit.Name);
        Assert.Equal("Browser", _audit.Category);
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
        Assert.Contains("Chrome", _audit.Description);
        Assert.Contains("Edge", _audit.Description);
        Assert.Contains("Firefox", _audit.Description);
    }

    [Fact]
    public async Task RunAuditAsync_Succeeds()
    {
        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, $"Audit failed: {result.Error}");
        Assert.Equal("Browser Audit", result.ModuleName);
        Assert.Equal("Browser", result.Category);
    }

    [Fact]
    public async Task RunAuditAsync_ProducesFindings()
    {
        var result = await _audit.RunAuditAsync();

        Assert.NotEmpty(result.Findings);
        // Should have findings for at least browser version checks + safe browsing + saved passwords + popup blocker
        Assert.True(result.Findings.Count >= 3,
            $"Expected at least 3 findings, got {result.Findings.Count}");
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
            Assert.Equal("Browser", finding.Category);
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
    public async Task RunAuditAsync_WarningFindingsHaveRemediation()
    {
        var result = await _audit.RunAuditAsync();

        foreach (var finding in result.Findings.Where(f => f.Severity == Severity.Warning))
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Remediation),
                $"Warning finding '{finding.Title}' must have remediation");
        }
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
    public async Task RunAuditAsync_ChecksEdgeOrChrome()
    {
        var result = await _audit.RunAuditAsync();

        // At least one of Chrome or Edge should be detected (Edge is pre-installed on Win 10/11)
        var browserFindings = result.Findings
            .Where(f => f.Title.Contains("Chrome", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("Edge", StringComparison.OrdinalIgnoreCase))
            .ToList();
        Assert.NotEmpty(browserFindings);
    }

    [Fact]
    public async Task RunAuditAsync_ChecksSafeBrowsingOrSmartScreen()
    {
        var result = await _audit.RunAuditAsync();

        var safeBrowsingFindings = result.Findings
            .Where(f => f.Title.Contains("Safe Browsing", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("SmartScreen", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("Safe Browsing / SmartScreen", StringComparison.OrdinalIgnoreCase))
            .ToList();
        Assert.NotEmpty(safeBrowsingFindings);
    }

    [Fact]
    public async Task RunAuditAsync_ChecksSavedPasswords()
    {
        var result = await _audit.RunAuditAsync();

        var passwordFindings = result.Findings
            .Where(f => f.Title.Contains("Password", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("Saved Password", StringComparison.OrdinalIgnoreCase))
            .ToList();
        Assert.NotEmpty(passwordFindings);
    }

    [Fact]
    public async Task RunAuditAsync_ChecksAutoUpdate()
    {
        var result = await _audit.RunAuditAsync();

        var updateFindings = result.Findings
            .Where(f => f.Title.Contains("Auto-Update", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("Update", StringComparison.OrdinalIgnoreCase))
            .ToList();
        Assert.NotEmpty(updateFindings);
    }

    [Fact]
    public async Task RunAuditAsync_ChecksPopupBlocker()
    {
        var result = await _audit.RunAuditAsync();

        var popupFindings = result.Findings
            .Where(f => f.Title.Contains("Popup", StringComparison.OrdinalIgnoreCase))
            .ToList();
        Assert.NotEmpty(popupFindings);
    }

    [Fact]
    public async Task RunAuditAsync_ChecksTrackingProtection()
    {
        var result = await _audit.RunAuditAsync();

        var trackingFindings = result.Findings
            .Where(f => f.Title.Contains("Track", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("Tracking", StringComparison.OrdinalIgnoreCase))
            .ToList();
        Assert.NotEmpty(trackingFindings);
    }

    [Fact]
    public async Task RunAuditAsync_SupportsCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // BrowserAudit is synchronous internally so it should complete even with a cancelled token,
        // but shouldn't throw unexpected exceptions
        try
        {
            var result = await _audit.RunAuditAsync(cts.Token);
            // If it completes, that's fine — it's synchronous work
            Assert.NotNull(result);
        }
        catch (OperationCanceledException)
        {
            // Also acceptable
        }
    }

    [Fact]
    public async Task RunAuditAsync_ScoreIsValid()
    {
        var result = await _audit.RunAuditAsync();
        Assert.InRange(result.Score, 0, 100);
    }

    [Fact]
    public async Task RunAuditAsync_AllFindingsHaveCategory()
    {
        var result = await _audit.RunAuditAsync();

        foreach (var finding in result.Findings)
        {
            Assert.Equal("Browser", finding.Category);
        }
    }

    [Fact]
    public async Task RunAuditAsync_DurationIsReasonable()
    {
        var result = await _audit.RunAuditAsync();

        // Browser audit reads registry and filesystem — should complete in under 10 seconds
        Assert.True(result.Duration < TimeSpan.FromSeconds(10),
            $"Audit took too long: {result.Duration}");
    }

    [Fact]
    public async Task RunAuditAsync_MultipleRunsAreConsistent()
    {
        var result1 = await _audit.RunAuditAsync();
        var result2 = await _audit.RunAuditAsync();

        // Both should succeed
        Assert.True(result1.Success);
        Assert.True(result2.Success);

        // Finding counts should be the same (nothing changed between runs)
        Assert.Equal(result1.Findings.Count, result2.Findings.Count);

        // Same finding titles
        var titles1 = result1.Findings.Select(f => f.Title).OrderBy(t => t).ToList();
        var titles2 = result2.Findings.Select(f => f.Title).OrderBy(t => t).ToList();
        Assert.Equal(titles1, titles2);
    }
}
